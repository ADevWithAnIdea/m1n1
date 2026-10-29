/* SPDX-License-Identifier: GPL-2.0-only
 * Caller-only compute fixture. This file supplies opaque BO/command bytes;
 * the driver neither imports it nor knows the shader's expected outputs.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include "asahi_drm.h"
#include "g17g_bridge.h"

#ifdef G17G_FIXTURE_LIBC
#include <limits.h>
#include <sys/ioctl.h>
static int
caller_ioctl(uint64_t file, unsigned long request, void *arg)
{
    if (file > INT_MAX)
        return -EBADF;
    int ret = ioctl((int)file, request, arg);
    return ret < 0 ? -errno : ret;
}

static int64_t
caller_mmap_offset(uint64_t file, uint64_t offset, size_t size)
{
    (void)file;
    (void)size;
    /* GEM_MMAP_OFFSET supplied this token. The real mmap entrypoint below
     * performs all mapping validation through the interposed DRM fd. */
    return offset > INT64_MAX ? -EINVAL : (int64_t)offset;
}
#define g17g_drm_ioctl caller_ioctl
#define g17g_drm_mmap_offset caller_mmap_offset
#endif

#define PAGE_SIZE 0x4000
#define MAX_CALLER_PAGES 32768
#define VM_END ((1ull << 42) - 2 * PAGE_SIZE)
#define VM_KERNEL_SIZE 0x20000000

struct caller_page {
    uint64_t dva;
    uint32_t flags, handle;
    uint64_t mmap_offset;
    void *mapping;
};

struct caller {
    uint64_t file;
    uint32_t vm, queues[2], binary, timeline, count;
    struct caller_page *pages;
    uint64_t completed;
    struct drm_asahi_params_global params;
    uint64_t time_before, time_after;
    uint64_t *job_times;
    uint32_t timestamp_handle, timestamp_object, timestamp_count;
    uint64_t timestamp_offset;
    void *timestamp_mapping;
};

_Static_assert(sizeof(struct drm_asahi_submit) == 40, "pinned submit ABI");
_Static_assert(sizeof(struct drm_asahi_cmd_compute) == 64, "pinned compute ABI");
_Static_assert(sizeof(struct drm_asahi_gem_bind_op) == 32, "pinned bind ABI");
_Static_assert(sizeof(struct drm_asahi_params_global) == 592, "pinned device params ABI");

/* Caller operations only: install a page, update its shared bytes, or replace
 * its binding while retaining the old BO for independent after-work checks. */
static int
caller_page_operation(struct caller *caller, int backing_fd, const uint8_t *input)
{
    uint64_t dva;
    uint32_t flags, mode;
    memcpy(&dva, input, 8);
    memcpy(&flags, input + 8, 4);
    memcpy(&mode, input + 12, 4);
    struct caller_page *old = NULL;
    for (uint32_t i = caller->count; i; --i) {
        if (caller->pages[i - 1].dva == dva) {
            old = &caller->pages[i - 1];
            break;
        }
    }
    if (mode > 3 || (mode == 0 && old) || (mode != 0 && !old))
        return -EINVAL;
    if ((mode == 1 || mode == 3) && (!old->mapping || old->flags != flags))
        return -EINVAL;
    if (mode == 1) {
        memcpy(old->mapping, input + 16, PAGE_SIZE);
        return 0;
    }
    if (caller->count == MAX_CALLER_PAGES)
        return -E2BIG;
    int ret;
#define PAGE_IOCTL(request, arg) do { \
    ret = g17g_drm_ioctl(caller->file, request, arg); \
    if (ret) return ret; \
} while (0)
    if (mode == 2 || mode == 3) {
        struct drm_asahi_gem_bind_op unmap = {
            .flags = DRM_ASAHI_BIND_UNBIND, .addr = dva, .range = PAGE_SIZE,
        };
        struct drm_asahi_vm_bind bind = {
            .vm_id = caller->vm, .num_binds = 1, .stride = sizeof(unmap),
            .userptr = (uintptr_t)&unmap,
        };
        PAGE_IOCTL(DRM_IOCTL_ASAHI_VM_BIND, &bind);
    }
    if (mode == 3) {
        /* Caller diagnostic: break/reinstall the binding while retaining the
         * same BO, physical backing and shared mapping. No driver extension. */
        struct drm_asahi_gem_bind_op operation = {
            .flags = flags, .handle = old->handle, .range = PAGE_SIZE, .addr = dva,
        };
        struct drm_asahi_vm_bind bind = {
            .vm_id = caller->vm, .num_binds = 1, .stride = sizeof(operation),
            .userptr = (uintptr_t)&operation,
        };
        PAGE_IOCTL(DRM_IOCTL_ASAHI_VM_BIND, &bind);
        memcpy(old->mapping, input + 16, PAGE_SIZE);
        return 0;
    }
    struct caller_page *page = &caller->pages[caller->count];
    page->dva = dva;
    page->flags = flags;
    struct drm_asahi_gem_create bo = {.size = PAGE_SIZE};
    PAGE_IOCTL(DRM_IOCTL_ASAHI_GEM_CREATE, &bo);
    page->handle = bo.handle;
    caller->count++;
    struct drm_asahi_gem_mmap_offset map = {.handle = bo.handle};
    PAGE_IOCTL(DRM_IOCTL_ASAHI_GEM_MMAP_OFFSET, &map);
    int64_t offset = g17g_drm_mmap_offset(caller->file, map.offset, PAGE_SIZE);
    if (offset < 0)
        return (int)offset;
    page->mmap_offset = offset;
    page->mapping = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                         backing_fd, offset);
    if (page->mapping == MAP_FAILED) {
        page->mapping = NULL;
        return -errno;
    }
    memcpy(page->mapping, input + 16, PAGE_SIZE);
    struct drm_asahi_gem_bind_op operation = {
        .flags = flags, .handle = bo.handle, .range = PAGE_SIZE, .addr = dva,
    };
    struct drm_asahi_vm_bind bind = {
        .vm_id = caller->vm, .num_binds = 1, .stride = sizeof(operation),
        .userptr = (uintptr_t)&operation,
    };
    PAGE_IOCTL(DRM_IOCTL_ASAHI_VM_BIND, &bind);
    return 0;
#undef PAGE_IOCTL
}

/* Input is a caller-defined fixture file, never a firmware capture:
 * u32 page_count, command_count, followed by page_count (u64 dva,u32 flags,
 * u32 reserved,16KiB payload) and command_count (u32 size,command bytes).
 * With command_count's high bit set, each command is preceded by u32 update
 * count and that many page records; their third word is operation mode0/1/2/3.
 * Mode3 unbinds/rebinds the same BO before updating it; mode2 creates a new BO.
 * Bit30 adds an expected fence errno before each command size. The observing
 * harness checks the fence; DRM waits report completion, including errors.
 * A command after an expected error has no failed input sync.
 * Bit29 adds two public u32 queue priorities immediately after the header.
 */
int
g17g_compute_fixture(uint64_t file, int backing_fd, const uint8_t *input,
                     size_t size, int timestamps, struct caller **out)
{
    if (size < 8)
        return -EINVAL;
    uint32_t page_count, command_count;
    memcpy(&page_count, input, 4);
    memcpy(&command_count, input + 4, 4);
    int updates = !!(command_count & 0x80000000u);
    int expected_errors = !!(command_count & 0x40000000u);
    int priorities = !!(command_count & 0x20000000u);
    command_count &= 0x1fffffffu;
    input += 8;
    size -= 8;
    uint32_t queue_priorities[2] = {1, 1};
    if (priorities) {
        if (size < sizeof(queue_priorities))
            return -EINVAL;
        memcpy(queue_priorities, input, sizeof(queue_priorities));
        input += sizeof(queue_priorities);
        size -= sizeof(queue_priorities);
        if (queue_priorities[0] > 1 || queue_priorities[1] > 1)
            return -EINVAL;
    }
    if (!page_count || page_count > MAX_CALLER_PAGES || !command_count || command_count > 1000)
        return -EINVAL;
    struct caller *caller = calloc(1, sizeof(*caller));
    if (!caller)
        return -ENOMEM;
    caller->file = file;
    caller->pages = calloc(MAX_CALLER_PAGES, sizeof(*caller->pages));
    *out = caller; /* Keep all acquired handles available after any failure. */
    if (!caller->pages)
        return -ENOMEM;
    caller->job_times = calloc(command_count * 2, sizeof(uint64_t));
    if (!caller->job_times)
        return -ENOMEM;
    int ret;
#define IOCTL(request, arg) do { \
    ret = g17g_drm_ioctl(file, request, arg); \
    if (ret) return ret; \
} while (0)
    struct drm_asahi_get_params get = {
        .pointer = (uintptr_t)&caller->params, .size = sizeof(caller->params),
    };
    IOCTL(DRM_IOCTL_ASAHI_GET_PARAMS, &get);
    if (caller->params.chip_id != 0x8142 || caller->params.gpu_generation != 17 ||
        caller->params.gpu_variant != 'G' || caller->params.vm_end != VM_END ||
        caller->params.vm_kernel_min_size != VM_KERNEL_SIZE)
        return -ENODEV;
    struct drm_asahi_get_time timestamp = {0};
    IOCTL(DRM_IOCTL_ASAHI_GET_TIME, &timestamp);
    caller->time_before = timestamp.gpu_timestamp;
    struct drm_asahi_vm_create vm = {
        .kernel_start = caller->params.vm_end - caller->params.vm_kernel_min_size,
        .kernel_end = caller->params.vm_end,
    };
    IOCTL(DRM_IOCTL_ASAHI_VM_CREATE, &vm);
    caller->vm = vm.vm_id;
    if (timestamps) {
        struct drm_asahi_gem_create bo = {.size = 2 * PAGE_SIZE};
        IOCTL(DRM_IOCTL_ASAHI_GEM_CREATE, &bo);
        caller->timestamp_handle = bo.handle;
        struct drm_asahi_gem_mmap_offset map = {.handle = bo.handle};
        IOCTL(DRM_IOCTL_ASAHI_GEM_MMAP_OFFSET, &map);
        int64_t offset = g17g_drm_mmap_offset(file, map.offset, 2 * PAGE_SIZE);
        if (offset < 0)
            return (int)offset;
        caller->timestamp_offset = offset;
        caller->timestamp_mapping = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
                                          MAP_SHARED, backing_fd, offset);
        if (caller->timestamp_mapping == MAP_FAILED) {
            caller->timestamp_mapping = NULL;
            return -errno;
        }
        /* Nonzero guards catch writes outside the specially bound second page. */
        memset(caller->timestamp_mapping, 0x5a, 2 * PAGE_SIZE);
        struct drm_asahi_gem_bind_object object = {
            .op = DRM_ASAHI_BIND_OBJECT_OP_BIND,
            .flags = DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
            .handle = bo.handle, .offset = PAGE_SIZE, .range = PAGE_SIZE,
        };
        IOCTL(DRM_IOCTL_ASAHI_GEM_BIND_OBJECT, &object);
        caller->timestamp_object = object.object_handle;
    }
    for (uint32_t i = 0; i < page_count; ++i) {
        if (size < 16 + PAGE_SIZE)
            return -EINVAL;
        ret = caller_page_operation(caller, backing_fd, input);
        if (ret)
            return ret;
        input += 16 + PAGE_SIZE;
        size -= 16 + PAGE_SIZE;
    }
    for (unsigned i = 0; i < 2; ++i) {
        struct drm_asahi_queue_create queue = {
            .vm_id = vm.vm_id, .priority = queue_priorities[i],
            .usc_exec_base = 0x10000000000ULL,
        };
        IOCTL(DRM_IOCTL_ASAHI_QUEUE_CREATE, &queue);
        caller->queues[i] = queue.queue_id;
    }
    struct drm_syncobj_create binary = {0}, timeline = {0};
    IOCTL(DRM_IOCTL_SYNCOBJ_CREATE, &binary);
    caller->binary = binary.handle;
    IOCTL(DRM_IOCTL_SYNCOBJ_CREATE, &timeline);
    caller->timeline = timeline.handle;
    int clock_unavailable = 0;
    int predecessor_failed = 0;
    unsigned timestamp_stride = 0;
    for (uint32_t i = 0; i < command_count; ++i) {
        if (updates) {
            uint32_t count;
            if (size < 4)
                return -EINVAL;
            memcpy(&count, input, 4);
            input += 4;
            size -= 4;
            if (count > MAX_CALLER_PAGES || size < (size_t)count * (16 + PAGE_SIZE))
                return -EINVAL;
            for (uint32_t j = 0; j < count; ++j) {
                ret = caller_page_operation(caller, backing_fd, input);
                if (ret)
                    return ret;
                input += 16 + PAGE_SIZE;
                size -= 16 + PAGE_SIZE;
            }
        }
        int32_t expected_error = 0;
        if (expected_errors) {
            if (size < 4)
                return -EINVAL;
            memcpy(&expected_error, input, 4);
            input += 4;
            size -= 4;
            if (expected_error != 0 && expected_error != -ENOMEM)
                return -EINVAL;
        }
        uint32_t bytes;
        if (size < 4)
            return -EINVAL;
        memcpy(&bytes, input, 4);
        input += 4;
        size -= 4;
        if (size < bytes)
            return -EINVAL;
        uint8_t *command = NULL;
        if (timestamps) {
            command = malloc(bytes);
            if (!command)
                return -ENOMEM;
            memcpy(command, input, bytes);
            size_t offset = 0;
            while (offset < bytes) {
                struct drm_asahi_cmd_header header;
                if (bytes - offset < sizeof(header)) {
                    free(command);
                    return -EINVAL;
                }
                memcpy(&header, command + offset, sizeof(header));
                offset += sizeof(header);
                if (header.size > bytes - offset) {
                    free(command);
                    return -EINVAL;
                }
                if (header.cmd_type >= DRM_ASAHI_SET_VERTEX_ATTACHMENTS &&
                    header.cmd_type <= DRM_ASAHI_SET_COMPUTE_ATTACHMENTS) {
                    /* Attachment state is opaque caller data, not a work
                     * command with timestamp destinations. */
                    offset += header.size;
                    continue;
                }
                unsigned timestamp_bytes = header.cmd_type == DRM_ASAHI_CMD_RENDER ? 32 : 16;
                /* Mixed caller mode reserves one four-word slot for either
                 * engine; compute leaves its two padding words untouched. */
                if (timestamps == 2)
                    timestamp_bytes = 32;
                if (timestamp_stride && timestamp_stride != timestamp_bytes) {
                    free(command);
                    return -EINVAL;
                }
                timestamp_stride = timestamp_bytes;
                unsigned timestamp_offset = 8 + caller->timestamp_count * timestamp_stride;
                if (timestamp_offset + timestamp_bytes > PAGE_SIZE) {
                    free(command);
                    return -EINVAL;
                }
                if (header.cmd_type == DRM_ASAHI_CMD_COMPUTE &&
                    header.size >= sizeof(struct drm_asahi_cmd_compute) &&
                    timestamp_offset + timestamp_bytes <= PAGE_SIZE) {
                    struct drm_asahi_cmd_compute compute;
                    memcpy(&compute, command + offset, sizeof(compute));
                    compute.ts.start.handle = compute.ts.end.handle = caller->timestamp_object;
                    compute.ts.start.offset = timestamp_offset;
                    compute.ts.end.offset = timestamp_offset + 8;
                    memcpy(command + offset, &compute, sizeof(compute));
                } else if (header.cmd_type == DRM_ASAHI_CMD_RENDER &&
                           header.size >= sizeof(struct drm_asahi_cmd_render)) {
                    struct drm_asahi_cmd_render render;
                    memcpy(&render, command + offset, sizeof(render));
                    render.ts_vtx.start.handle = render.ts_vtx.end.handle = caller->timestamp_object;
                    render.ts_frag.start.handle = render.ts_frag.end.handle = caller->timestamp_object;
                    render.ts_vtx.start.offset = timestamp_offset;
                    render.ts_vtx.end.offset = timestamp_offset + 8;
                    render.ts_frag.start.offset = timestamp_offset + 16;
                    render.ts_frag.end.offset = timestamp_offset + 24;
                    memcpy(command + offset, &render, sizeof(render));
                } else {
                    free(command);
                    return -EINVAL;
                }
                memset((uint8_t *)caller->timestamp_mapping + PAGE_SIZE + timestamp_offset,
                       0, timestamp_bytes);
                caller->timestamp_count++;
                offset += header.size;
            }
        }
        struct drm_asahi_sync syncs[4] = {
            {.sync_type = DRM_ASAHI_SYNC_SYNCOBJ, .handle = caller->binary},
            {.sync_type = DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ,
             .handle = caller->timeline, .timeline_value = i},
            {.sync_type = DRM_ASAHI_SYNC_SYNCOBJ, .handle = caller->binary},
            {.sync_type = DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ,
             .handle = caller->timeline, .timeline_value = i + 1},
        };
        int has_dependency = i && !predecessor_failed;
        struct drm_asahi_submit submit = {
            .syncs = (uintptr_t)(has_dependency ? syncs : syncs + 2),
            .cmdbuf = (uintptr_t)(command ? command : input), .queue_id = caller->queues[i % 2],
            .in_sync_count = has_dependency ? 2 : 0, .out_sync_count = 2, .cmdbuf_size = bytes,
        };
        if (!clock_unavailable) {
            ret = g17g_drm_ioctl(file, DRM_IOCTL_ASAHI_GET_TIME, &timestamp);
            if (ret == -ENODEV)
                clock_unavailable = 1;
            else if (ret)
                return ret;
            else
                caller->job_times[i * 2] = timestamp.gpu_timestamp;
        }
        ret = g17g_drm_ioctl(file, DRM_IOCTL_ASAHI_SUBMIT, &submit);
        free(command);
        if (ret)
            return ret;
        uint64_t point = i + 1;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        struct drm_syncobj_timeline_wait wait = {
            .handles = (uintptr_t)&caller->timeline, .points = (uintptr_t)&point,
            .timeout_nsec = (int64_t)now.tv_sec * 1000000000 + now.tv_nsec + 1000000000,
            .count_handles = 1, .flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL,
        };
        IOCTL(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &wait);
        predecessor_failed = expected_error != 0;
        uint64_t queried = 0;
        struct drm_syncobj_timeline_array query = {
            .handles = (uintptr_t)&caller->timeline, .points = (uintptr_t)&queried,
            .count_handles = 1,
        };
        IOCTL(DRM_IOCTL_SYNCOBJ_QUERY, &query);
        if (queried != point)
            return -EIO;
        if (!clock_unavailable) {
            ret = g17g_drm_ioctl(file, DRM_IOCTL_ASAHI_GET_TIME, &timestamp);
            if (ret == -ENODEV)
                clock_unavailable = 1;
            else if (ret)
                return ret;
            else
                caller->job_times[i * 2 + 1] = timestamp.gpu_timestamp;
        }
        caller->completed = point;
        input += bytes;
        size -= bytes;
    }
    if (clock_unavailable)
        return -ENODEV;
    IOCTL(DRM_IOCTL_ASAHI_GET_TIME, &timestamp);
    caller->time_after = timestamp.gpu_timestamp;
    if (caller->time_after <= caller->time_before)
        return -EIO;
    return size ? -EINVAL : 0;
#undef IOCTL
}

int
g17g_compute_fixture_cleanup(struct caller *caller)
{
    int first_error = 0;
    if (!caller)
        return 0;
#define CLOSE(request, arg) do { \
    int ret = g17g_drm_ioctl(caller->file, request, arg); \
    if (ret && !first_error) first_error = ret; \
} while (0)
    for (unsigned i = 0; i < 2; ++i) {
        if (caller->queues[i]) {
            struct drm_asahi_queue_destroy queue = {.queue_id = caller->queues[i]};
            CLOSE(DRM_IOCTL_ASAHI_QUEUE_DESTROY, &queue);
        }
    }
    if (caller->count) {
        uint64_t start = UINT64_MAX, end = 0;
        for (unsigned i = 0; i < caller->count; ++i) {
            uint64_t dva = caller->pages[i].dva;
            if (dva < start) start = dva;
            if (dva + PAGE_SIZE > end) end = dva + PAGE_SIZE;
        }
        /* One ordinary range-unbind batches page-table maintenance. It only
         * removes this VM's caller bindings, including the holes between BOs.
         */
        struct drm_asahi_gem_bind_op operation = {
            .flags = DRM_ASAHI_BIND_UNBIND, .addr = start, .range = end - start,
        };
        struct drm_asahi_vm_bind bind = {
            .vm_id = caller->vm, .num_binds = 1, .stride = sizeof(operation),
            .userptr = (uintptr_t)&operation,
        };
        CLOSE(DRM_IOCTL_ASAHI_VM_BIND, &bind);
    }
    for (unsigned i = 0; i < caller->count; ++i) {
        struct caller_page *page = &caller->pages[i];
        struct drm_gem_close close = {.handle = page->handle};
        CLOSE(DRM_IOCTL_GEM_CLOSE, &close);
        if (page->mapping)
            munmap(page->mapping, PAGE_SIZE);
    }
    if (caller->timestamp_object) {
        struct drm_asahi_gem_bind_object object = {
            .op = DRM_ASAHI_BIND_OBJECT_OP_UNBIND,
            .object_handle = caller->timestamp_object,
        };
        CLOSE(DRM_IOCTL_ASAHI_GEM_BIND_OBJECT, &object);
    }
    if (caller->timestamp_handle) {
        struct drm_gem_close close = {.handle = caller->timestamp_handle};
        CLOSE(DRM_IOCTL_GEM_CLOSE, &close);
        if (caller->timestamp_mapping)
            munmap(caller->timestamp_mapping, 2 * PAGE_SIZE);
    }
    uint32_t syncs[] = {caller->binary, caller->timeline};
    for (unsigned i = 0; i < 2; ++i) {
        if (syncs[i]) {
            struct drm_syncobj_destroy destroy = {.handle = syncs[i]};
            CLOSE(DRM_IOCTL_SYNCOBJ_DESTROY, &destroy);
        }
    }
    if (caller->vm) {
        struct drm_asahi_vm_destroy vm = {.vm_id = caller->vm};
        CLOSE(DRM_IOCTL_ASAHI_VM_DESTROY, &vm);
    }
    free(caller->pages);
    free(caller->job_times);
    free(caller);
    return first_error;
#undef CLOSE
}
