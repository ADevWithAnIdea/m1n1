/*
 * Copyright 2022 Alyssa Rosenzweig
 * Copyright 2018 Broadcom
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include "drm-shim/drm_shim.h"
#include "drm-uapi/asahi_drm.h"

bool drm_shim_driver_prefers_first_render_node = true;

static const struct drm_asahi_params_global params = {
   .gpu_generation = 13,
   .gpu_variant = 'G',
   .gpu_revision = 0,
   .vm_start = 0x4000,
   .vm_end = 0x7fffff8000ull,
   .command_timestamp_frequency_hz = 1000000000,
};

struct asahi_bo {
   struct shim_bo base;
   uint32_t offset;
   uint64_t gpu_addr;
   uint64_t gpu_offset;
   uint64_t gpu_range;
   uint32_t bind_flags;
};

static struct asahi_bo *
asahi_bo(struct shim_bo *bo)
{
   return (struct asahi_bo *)bo;
}

struct asahi_device {
   uint64_t next_offset;
};

static struct asahi_device asahi = {
   .next_offset = 0x1000,
};

static int
asahi_ioctl_noop(int fd, unsigned long request, void *arg)
{
   return 0;
}

static int
asahi_ioctl_vm_bind(int fd, unsigned long request, void *arg)
{
   struct shim_fd *shim_fd = drm_shim_fd_lookup(fd);
   const struct drm_asahi_vm_bind *bind = arg;

   for (uint32_t i = 0; i < bind->num_binds; ++i) {
      const struct drm_asahi_gem_bind_op *op =
         (const void *)((const uint8_t *)(uintptr_t)bind->userptr +
                        (i * bind->stride));
      if (!op->handle)
         continue;

      struct shim_bo *base = drm_shim_bo_lookup(shim_fd, op->handle);
      if (!base)
         return -ENOENT;

      struct asahi_bo *bo = asahi_bo(base);
      bo->gpu_addr = op->addr;
      bo->gpu_offset = op->offset;
      bo->gpu_range = op->range;
      bo->bind_flags = op->flags;
      drm_shim_bo_put(base);
   }

   return 0;
}

static int
dump_bo(const char *dir, uint32_t handle, const struct asahi_bo *bo,
        FILE *manifest)
{
   char path[1024];
   snprintf(path, sizeof(path), "%s/bo_%u_%016" PRIx64 ".bin",
            dir, handle, bo->gpu_addr);

   FILE *fp = fopen(path, "wb");
   if (!fp)
      return -errno;

   uint8_t buffer[65536];
   size_t done = 0;
   while (done < bo->base.size) {
      size_t length = MIN2(sizeof(buffer), bo->base.size - done);
      ssize_t ret = pread(shim_device.mem_fd, buffer, length,
                          bo->base.mem_addr + done);
      if (ret <= 0) {
         fclose(fp);
         return ret ? -errno : -EIO;
      }
      if (fwrite(buffer, 1, ret, fp) != (size_t)ret) {
         fclose(fp);
         return -EIO;
      }
      done += ret;
   }
   fclose(fp);

   fprintf(manifest,
           "handle=%u va=0x%016" PRIx64 " bo_offset=0x%" PRIx64
           " range=0x%" PRIx64 " size=0x%x flags=0x%x file=%s\n",
           handle, bo->gpu_addr, bo->gpu_offset, bo->gpu_range,
           bo->base.size, bo->bind_flags, path);
   return 0;
}

static int
dump_submit(int fd, const struct drm_asahi_submit *submit)
{
   const char *dir = getenv("ASAHI_SHIM_CAPTURE_DIR");
   if (!dir || !*dir)
      return 0;
   if (mkdir(dir, 0777) && errno != EEXIST)
      return -errno;

   char path[1024];
   snprintf(path, sizeof(path), "%s/cmdbuf.bin", dir);
   FILE *fp = fopen(path, "wb");
   if (!fp)
      return -errno;
   fwrite((const void *)(uintptr_t)submit->cmdbuf, 1,
          submit->cmdbuf_size, fp);
   fclose(fp);

   snprintf(path, sizeof(path), "%s/manifest.txt", dir);
   FILE *manifest = fopen(path, "w");
   if (!manifest)
      return -errno;
   fprintf(manifest, "cmdbuf_size=0x%x queue_id=%u\n",
           submit->cmdbuf_size, submit->queue_id);

   struct shim_fd *shim_fd = drm_shim_fd_lookup(fd);
   hash_table_foreach(shim_fd->handles, entry) {
      uint32_t handle = (uintptr_t)entry->key;
      dump_bo(dir, handle, asahi_bo(entry->data), manifest);
   }
   fclose(manifest);
   return 0;
}

static int
asahi_ioctl_gem_create(int fd, unsigned long request, void *arg)
{
   struct shim_fd *shim_fd = drm_shim_fd_lookup(fd);
   struct drm_asahi_gem_create *create = arg;
   struct asahi_bo *bo = calloc(1, sizeof(*bo));

   drm_shim_bo_init(&bo->base, create->size);

   assert(UINT64_MAX - asahi.next_offset > create->size);
   bo->offset = asahi.next_offset;
   asahi.next_offset += create->size;

   create->handle = drm_shim_bo_get_handle(shim_fd, &bo->base);

   drm_shim_bo_put(&bo->base);

   return 0;
}

static int
asahi_ioctl_gem_mmap_offset(int fd, unsigned long request, void *arg)
{
   struct shim_fd *shim_fd = drm_shim_fd_lookup(fd);
   struct drm_asahi_gem_mmap_offset *map = arg;
   struct shim_bo *bo = drm_shim_bo_lookup(shim_fd, map->handle);

   map->offset = drm_shim_bo_get_mmap_offset(shim_fd, bo);

   drm_shim_bo_put(bo);

   return 0;
}

static int
asahi_ioctl_get_param(int fd, unsigned long request, void *arg)
{
   struct drm_asahi_get_params *gp = arg;

   switch (gp->param_group) {
   case 0:
      assert(gp->size == sizeof(struct drm_asahi_params_global));
      memcpy((void *)gp->pointer, &params, gp->size);
      return 0;

   default:
      fprintf(stderr, "Unknown DRM_IOCTL_ASAHI_GET_PARAMS %d\n",
              gp->param_group);
      return -1;
   }
}

static int
asahi_ioctl_submit(int fd, unsigned long request, void *arg)
{
   const struct drm_asahi_submit *submit = arg;
   int ret = dump_submit(fd, submit);
   return ret < 0 ? ret : 0;
}

static ioctl_fn_t driver_ioctls[] = {
   [DRM_ASAHI_GET_PARAMS] = asahi_ioctl_get_param,
   [DRM_ASAHI_VM_CREATE] = asahi_ioctl_noop,
   [DRM_ASAHI_VM_DESTROY] = asahi_ioctl_noop,
   [DRM_ASAHI_VM_BIND] = asahi_ioctl_vm_bind,
   [DRM_ASAHI_GEM_CREATE] = asahi_ioctl_gem_create,
   [DRM_ASAHI_GEM_MMAP_OFFSET] = asahi_ioctl_gem_mmap_offset,
   [DRM_ASAHI_QUEUE_CREATE] = asahi_ioctl_noop,
   [DRM_ASAHI_QUEUE_DESTROY] = asahi_ioctl_noop,
   [DRM_ASAHI_GEM_BIND_OBJECT] = asahi_ioctl_noop,
   [DRM_ASAHI_SUBMIT] = asahi_ioctl_submit,
};

void
drm_shim_driver_init(void)
{
   shim_device.bus_type = DRM_BUS_PLATFORM;
   shim_device.driver_name = "asahi";
   shim_device.driver_ioctls = driver_ioctls;
   shim_device.driver_ioctl_count = ARRAY_SIZE(driver_ioctls);

   drm_shim_override_file("DRIVER=asahi\n"
                          "OF_FULLNAME=/soc/agx\n"
                          "OF_COMPATIBLE_0=apple,gpu-g13g\n"
                          "OF_COMPATIBLE_N=1\n",
                          "/sys/dev/char/%d:%d/device/uevent", DRM_MAJOR,
                          render_node_minor);
}
