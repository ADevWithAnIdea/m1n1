/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

#include "adt.h"
#include "xnuboot.h"

#define SPTM_AUX_SIZE              (64 * SZ_1M)
#define SPTM_CPU_STACK_WINDOW_SIZE SZ_1M
#define SPTM_BOOT_MAX_TABLES       1024
#define SPTM_BOOTSTRAP_SIZE        0x340
#define SPTM_FRAME_ENTRY_SIZE      16
#define SPTM_FRAME_PARAM_SIZE      0x90
#define SPTM_VM_MAX_KERNEL_ADDRESS 0xfffffecfffffffffULL

#define SPTM_TCR_BOOT   0x10800336511a511ULL
#define SPTM_MAIR_BOOT  0x0c0d00ff01a040ffULL
#define SPTM_SCTLR_BOOT 0x100010103414593dULL

#define SPTM_LEAF_CODE       0x603
#define SPTM_LEAF_DATA       0x60000000000703ULL
#define SPTM_LEAF_DATA_OUTER 0x60000000000603ULL
#define SPTM_LEAF_DATA_NC    0x60000000000407ULL
#define SPTM_TABLE_DESC      3

#define SPTM_FRAME_KERNEL_CODE  6
#define SPTM_FRAME_KERNEL_ROOT  8
#define SPTM_FRAME_PAGE_TABLE   9
#define SPTM_FRAME_DEFAULT      11
#define SPTM_FRAME_RO           12
#define SPTM_FRAME_USER_ROOT    18
#define SPTM_FRAME_SHARED_ROOT  19
#define SPTM_FRAME_XNU_ROOT     20
#define SPTM_FRAME_SHARED_PT    21
#define SPTM_FRAME_ROZONE_PT    22
#define SPTM_FRAME_COMMPAGE_PT  23
#define SPTM_FRAME_XNU_IOMMU    24
#define SPTM_FRAME_STAGE2_ROOT  33
#define SPTM_FRAME_STAGE2_PT    34
#define SPTM_FRAME_SUBPAGE_ROOT 40

#define MACHO_MAGIC_64      0xfeedfacf
#define MACHO_LC_SEGMENT_64 0x19
#define MACHO_LC_UNIXTHREAD 0x05
#define MACHO_VM_PROT_WRITE 2
#define MACHO_VM_PROT_EXEC  4

struct macho_header_64 {
    u32 magic;
    u32 cpu_type;
    u32 cpu_subtype;
    u32 file_type;
    u32 command_count;
    u32 command_size;
    u32 flags;
    u32 reserved;
} PACKED;

struct macho_command {
    u32 type;
    u32 size;
} PACKED;

struct macho_segment_64 {
    struct macho_command command;
    char name[16];
    u64 vm_address;
    u64 vm_size;
    u64 file_offset;
    u64 file_size;
    u32 maximum_protection;
    u32 initial_protection;
    u32 section_count;
    u32 flags;
} PACKED;

struct macho_thread_64 {
    struct macho_command command;
    u32 flavor;
    u32 count;
    u64 x[29];
    u64 fp;
    u64 lr;
    u64 sp;
    u64 pc;
    u32 cpsr;
    u32 flags;
} PACKED;

struct sptm_boot_allocator {
    u64 next;
    u64 end;
};

struct sptm_boot_pt_page {
    u64 pa;
    u8 level;
};

struct sptm_boot_io_range {
    u64 address;
    u64 size;
    u32 flags;
    u32 signature;
} PACKED;

struct sptm_boot_io_filter {
    u32 signature;
    u16 offset;
    u16 length;
} PACKED;

struct sptm_boot_papt {
    u64 pa;
    u64 va;
    u32 count;
    u32 reserved;
} PACKED;

struct sptm_boot_context {
    struct sptm_boot_allocator allocator;
    u64 managed_start;
    u64 managed_end;
    u64 physmap_base;
    u64 physmap_end;
    u64 kernel_pa;
    u64 kernel_vmin;
    u64 kernel_vmax;
    u64 kernel_entry;
    u64 ttbr0_pa;
    u64 ttbr1_pa;
    u64 bootstrap_pa;
    u64 panic_state_pa;
    u64 scratch_pa;
    u64 cpu_map_pa;
    u64 frame_table_pa;
    u64 uat_global_state_pa;
    u64 uat_global_root_pa;
    u64 uat_gpu_region_pa;
    u64 uat_l2_pa;
    u64 uat_l2_va;
    u64 txm_info_va;
    u8 *frame_table;
    u8 *frame_priority;
};

static struct {
    bool ready;
    u64 entry;
    u64 bootargs_va;
    u64 bootstrap_va;
    u64 panic_state_pa;
    struct sptm_boot_pt_page pages[SPTM_BOOT_MAX_TABLES];
    u32 page_count;
} sptm_boot;

static void *sptm_boot_alloc(struct sptm_boot_allocator *allocator, size_t size, size_t alignment)
{
    u64 address = ALIGN_UP(allocator->next, alignment);
    assert(address + size <= allocator->end);
    allocator->next = address + size;
    return (void *)address;
}

static void *sptm_boot_alloc_zero(struct sptm_boot_allocator *allocator, size_t size,
                                  size_t alignment)
{
    void *result = sptm_boot_alloc(allocator, size, alignment);
    memset(result, 0, size);
    return result;
}

static u64 sptm_boot_adt_integer(int node, const char *name, u64 fallback)
{
    u32 size;
    const void *value = adt_getprop(adt, node, name, &size);
    if (!value)
        return fallback;
    u64 result = 0;
    memcpy(&result, value, min(size, (u32)sizeof(result)));
    return result;
}

static bool sptm_boot_adt_bool(int node, const char *name, bool fallback)
{
    u32 size;
    const void *value = adt_getprop(adt, node, name, &size);
    if (!value)
        return fallback;
    if (!size)
        return true;
    u64 result = 0;
    memcpy(&result, value, min(size, (u32)sizeof(result)));
    return result != 0;
}

static void sptm_boot_adt_region(int node, const char *name, u64 *address, u64 *size)
{
    const u64 *region = adt_getprop(adt, node, name, NULL);
    *address = region[0];
    *size = region[1];
}

static u64 sptm_boot_property(const int *nodes, size_t count, const char *name, u64 fallback)
{
    for (size_t index = 0; index < count; index++) {
        if (adt_get_property(adt, nodes[index], name))
            return sptm_boot_adt_integer(nodes[index], name, fallback);
    }
    return fallback;
}

static bool sptm_boot_bool_property(const int *nodes, size_t count, const char *name, bool fallback)
{
    for (size_t index = 0; index < count; index++) {
        if (adt_get_property(adt, nodes[index], name))
            return sptm_boot_adt_bool(nodes[index], name, fallback);
    }
    return fallback;
}

static u64 sptm_boot_va(const struct sptm_boot_context *context, u64 pa)
{
    return context->physmap_base + pa - context->managed_start;
}

static u64 sptm_boot_alloc_table(struct sptm_boot_context *context, u8 level)
{
    u64 pa = (u64)sptm_boot_alloc_zero(&context->allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    assert(sptm_boot.page_count < ARRAY_SIZE(sptm_boot.pages));
    sptm_boot.pages[sptm_boot.page_count++] = (struct sptm_boot_pt_page){pa, level};
    return pa;
}

static u64 sptm_boot_ensure_l3(struct sptm_boot_context *context, u64 root, u64 va)
{
    u64 table = root;
    for (u32 level = 1, shift = 36; level <= 2; level++, shift -= 11) {
        u64 *slot = (u64 *)table + ((va >> shift) & 0x7ff);
        if (!(*slot & 1))
            *slot = sptm_boot_alloc_table(context, level + 1) | SPTM_TABLE_DESC;
        table = *slot & SPTM_DESC_PA_MASK_16K;
    }
    return table;
}

static void sptm_boot_map_page(struct sptm_boot_context *context, u64 root, u64 va, u64 pa,
                               u64 attributes)
{
    u64 table = sptm_boot_ensure_l3(context, root, va);
    ((u64 *)table)[(va >> SPTM_PAGE_SHIFT) & 0x7ff] = (pa & SPTM_DESC_PA_MASK_16K) | attributes;
}

static void sptm_boot_map_range(struct sptm_boot_context *context, u64 root, u64 va, u64 pa,
                                u64 size, u64 attributes)
{
    for (u64 offset = 0; offset < size; offset += SPTM_PAGE_SIZE)
        sptm_boot_map_page(context, root, va + offset, pa + offset, attributes);
}

static void sptm_boot_retype_page(struct sptm_boot_context *context, u64 root, u64 va, u64 pa,
                                  u64 attributes)
{
    u64 table = sptm_boot_ensure_l3(context, root, va);
    ((u64 *)table)[(va >> SPTM_PAGE_SHIFT) & 0x7ff] = (pa & SPTM_DESC_PA_MASK_16K) | attributes;
}

static void sptm_boot_preallocate_l3(struct sptm_boot_context *context, u64 root, u64 start,
                                     u64 end)
{
    for (u64 va = ALIGN_DOWN(start, SZ_32M); va < ALIGN_UP(end, SZ_32M); va += SZ_32M)
        sptm_boot_ensure_l3(context, root, va);
}

static u16 sptm_boot_valid_count(u64 table)
{
    u16 count = 0;
    for (size_t index = 0; index < SPTM_PAGE_SIZE / sizeof(u64); index++)
        count += (((u64 *)table)[index] & 1) != 0;
    return count;
}

static bool sptm_boot_table_frame(u8 type)
{
    switch (type) {
        case SPTM_FRAME_KERNEL_ROOT:
        case SPTM_FRAME_PAGE_TABLE:
        case SPTM_FRAME_USER_ROOT:
        case SPTM_FRAME_SHARED_ROOT:
        case SPTM_FRAME_XNU_ROOT:
        case SPTM_FRAME_SHARED_PT:
        case SPTM_FRAME_ROZONE_PT:
        case SPTM_FRAME_COMMPAGE_PT:
        case SPTM_FRAME_STAGE2_ROOT:
        case SPTM_FRAME_STAGE2_PT:
        case SPTM_FRAME_SUBPAGE_ROOT:
            return true;
        default:
            return false;
    }
}

static void sptm_boot_set_frame(struct sptm_boot_context *context, u64 pa, u8 type, u32 ro, u32 wx,
                                u8 level, u16 valid, u16 iommu_refs)
{
    if (pa < context->managed_start || pa >= context->managed_end)
        return;
    u8 *entry = context->frame_table +
                ((pa - context->managed_start) >> SPTM_PAGE_SHIFT) * SPTM_FRAME_ENTRY_SIZE;
    entry[2] = type;
    if (sptm_boot_table_frame(type)) {
        entry[4] = level;
        write16((u64)entry + 8, valid);
    } else if (type == SPTM_FRAME_XNU_IOMMU) {
        write16((u64)entry + 4, iommu_refs);
    } else {
        if (ro)
            write32((u64)entry + 8, ro);
        write32((u64)entry + 12, wx);
    }
}

static void sptm_boot_macho_info(struct sptm_boot_context *context)
{
    const struct macho_header_64 *header = (void *)context->kernel_pa;
    assert(header->magic == MACHO_MAGIC_64);
    const struct macho_command *command = (const void *)(header + 1);
    context->kernel_vmin = UINT64_MAX;
    for (u32 index = 0; index < header->command_count; index++) {
        if (command->type == MACHO_LC_SEGMENT_64) {
            const struct macho_segment_64 *segment = (const void *)command;
            context->kernel_vmin = min(context->kernel_vmin, segment->vm_address);
            context->kernel_vmax =
                max(context->kernel_vmax, segment->vm_address + segment->vm_size);
        } else if (command->type == MACHO_LC_UNIXTHREAD) {
            context->kernel_entry = ((const struct macho_thread_64 *)command)->pc;
        }
        command = (const void *)command + command->size;
    }
}

static void sptm_boot_type_kernel_frames(struct sptm_boot_context *context)
{
    const struct macho_header_64 *header = (void *)context->kernel_pa;
    const struct macho_command *command = (const void *)(header + 1);
    for (u32 index = 0; index < header->command_count; index++) {
        if (command->type == MACHO_LC_SEGMENT_64) {
            const struct macho_segment_64 *segment = (const void *)command;
            u8 priority = 1;
            u8 type = SPTM_FRAME_RO;
            if (segment->initial_protection & MACHO_VM_PROT_EXEC) {
                priority = 3;
                type = SPTM_FRAME_KERNEL_CODE;
            } else if (segment->initial_protection & MACHO_VM_PROT_WRITE) {
                priority = 2;
                type = SPTM_FRAME_DEFAULT;
            }
            u64 start = ALIGN_DOWN(segment->vm_address, SPTM_PAGE_SIZE);
            u64 end = ALIGN_UP(segment->vm_address + segment->vm_size, SPTM_PAGE_SIZE);
            for (u64 va = start; va < end; va += SPTM_PAGE_SIZE) {
                u64 pa = context->kernel_pa + va - context->kernel_vmin;
                if (pa < context->managed_start || pa >= context->managed_end)
                    continue;
                size_t frame = (pa - context->managed_start) >> SPTM_PAGE_SHIFT;
                if (priority > context->frame_priority[frame]) {
                    context->frame_priority[frame] = priority;
                    sptm_boot_set_frame(context, pa, type, 1, 0, 0, 0, 0);
                }
            }
        }
        command = (const void *)command + command->size;
    }
}

static void sptm_boot_sort_io_ranges(struct sptm_boot_io_range *ranges, u32 count)
{
    for (u32 index = 1; index < count; index++) {
        struct sptm_boot_io_range value = ranges[index];
        u32 position = index;
        while (position && (ranges[position - 1].address > value.address ||
                            (ranges[position - 1].address == value.address &&
                             ranges[position - 1].size > value.size))) {
            ranges[position] = ranges[position - 1];
            position--;
        }
        ranges[position] = value;
    }
}

static void sptm_boot_sort_io_filters(struct sptm_boot_io_filter *filters, u32 count)
{
    for (u32 index = 1; index < count; index++) {
        struct sptm_boot_io_filter value = filters[index];
        u32 position = index;
        while (position && (filters[position - 1].signature > value.signature ||
                            (filters[position - 1].signature == value.signature &&
                             filters[position - 1].offset > value.offset))) {
            filters[position] = filters[position - 1];
            position--;
        }
        filters[position] = value;
    }
}

u64 sptm_boot_init(u64 guest_adt, u64 cons_ops, u64 page_shift_const, u64 xnu_text)
{
    memset(&sptm_boot, 0, sizeof(sptm_boot));
    void *firmware_adt = adt;
    adt = (void *)guest_adt;

    int memory_map = adt_path_offset(adt, "/chosen/memory-map");
    u64 bootargs_pa, bootargs_size, kernel_size;
    struct sptm_boot_context context = {0};
    sptm_boot_adt_region(memory_map, "BootArgs", &bootargs_pa, &bootargs_size);
    sptm_boot_adt_region(memory_map, "Kernel-mach_header", &context.kernel_pa, &kernel_size);
    struct boot_args *bootargs = (void *)bootargs_pa;

    context.managed_start = bootargs->phys_base;
    context.managed_end = bootargs->phys_base + bootargs->mem_size;
    context.physmap_base = bootargs->virt_base;
    context.physmap_end = bootargs->virt_base + bootargs->mem_size;
    u64 aux_start = ALIGN_UP(bootargs->top_of_kernel_data, SPTM_PAGE_SIZE);
    u64 aux_end = aux_start + SPTM_AUX_SIZE;
    context.allocator = (struct sptm_boot_allocator){aux_start, aux_end};
    // Keep every handoff object below the RAM XNU is allowed to allocate.
    bootargs->top_of_kernel_data = aux_end;

    sptm_boot_macho_info(&context);

    int cpus = adt_path_offset(adt, "/cpus");
    u32 cpu_count = 0;
    int cpu = cpus;
    ADT_FOREACH_CHILD(adt, cpu)
    cpu_count = max(cpu_count, (u32)sptm_boot_adt_integer(cpu, "cpu-id", 0) + 1);

    int sgx = adt_path_offset(adt, "/arm-io/sgx");
    int defaults = adt_path_offset(adt, "/defaults");
    int chosen = adt_path_offset(adt, "/chosen");
    int uat_nodes[] = {sgx, defaults, chosen};
    u8 uat_mode =
        sptm_boot_property(uat_nodes, ARRAY_SIZE(uat_nodes), "agx-address-space-mgmt-mode", 0);
    u8 uat_va_width = sptm_boot_property(uat_nodes, ARRAY_SIZE(uat_nodes), "uat-vaddr-size", 40);
    u16 uat_segment_limit =
        sptm_boot_property(uat_nodes, ARRAY_SIZE(uat_nodes), "uat-segment-limit", 64);
    u16 uat_mapping_limit =
        sptm_boot_property(uat_nodes, ARRAY_SIZE(uat_nodes), "uat-mapping-limit", 256);
    bool uat_tlbi_at_retype = sptm_boot_bool_property(uat_nodes, ARRAY_SIZE(uat_nodes),
                                                      "issue-gmmu-tlbis-at-retype", false);
    context.uat_gpu_region_pa = sptm_boot_adt_integer(sgx, "gpu-region-base", 0);

    size_t managed_pages = (context.managed_end - context.managed_start) / SPTM_PAGE_SIZE;
    size_t frame_table_size = managed_pages * SPTM_FRAME_ENTRY_SIZE;
    size_t external_ref_table_size = managed_pages * 8;

    context.bootstrap_pa = (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_BOOTSTRAP_SIZE, 16);
    u64 debug_header_pa = (u64)sptm_boot_alloc_zero(&context.allocator, 0x100, 16);
    context.panic_state_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    u64 papt_count_pa = (u64)sptm_boot_alloc_zero(&context.allocator, sizeof(u32), 4);
    u64 papt_ranges_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, 3 * sizeof(struct sptm_boot_papt), 8);
    u64 trace_buffer_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    u64 dispatch_states_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    u64 saved_states_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    u64 event_counters_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    context.scratch_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, cpu_count * SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    context.cpu_map_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, (cpu_count + 1) * sizeof(u32), 4);
    u64 txm_stack_array_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, cpu_count * sizeof(u64), 8);
    u64 txm_stacks_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, cpu_count * SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    u64 txm_info_pa = (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    context.txm_info_va = sptm_boot_va(&context, txm_info_pa);
    context.uat_global_state_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    context.uat_global_root_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);
    u64 kernel_stacks_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_CPU_STACK_WINDOW_SIZE, SPTM_PAGE_SIZE);
    // Keep EL2-only RO/WX reservations after the ABI-visible frame table.
    context.frame_table_pa = (u64)sptm_boot_alloc_zero(
        &context.allocator, frame_table_size + external_ref_table_size, SPTM_PAGE_SIZE);
    context.frame_table = (void *)context.frame_table_pa;
    u64 frame_params_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, 256 * SPTM_FRAME_PARAM_SIZE, SPTM_PAGE_SIZE);
    u64 pt_attrs_pa = (u64)sptm_boot_alloc_zero(&context.allocator, 6 * sizeof(u64), 8);
    u64 ttbr0_zero_page_pa =
        (u64)sptm_boot_alloc_zero(&context.allocator, SPTM_PAGE_SIZE, SPTM_PAGE_SIZE);

    u32 io_ranges_bytes, io_filters_bytes;
    const void *raw_io_ranges = adt_getprop(adt, defaults, "pmap-io-ranges", &io_ranges_bytes);
    const void *raw_io_filters = adt_getprop(adt, defaults, "pmap-io-filters", &io_filters_bytes);
    if (!raw_io_ranges)
        io_ranges_bytes = 0;
    if (!raw_io_filters)
        io_filters_bytes = 0;
    size_t io_ranges_size = ALIGN_UP(max(io_ranges_bytes, 1U), SPTM_PAGE_SIZE);
    size_t io_filters_size = ALIGN_UP(max(io_filters_bytes, 1U), SPTM_PAGE_SIZE);
    struct sptm_boot_io_range *io_ranges =
        sptm_boot_alloc_zero(&context.allocator, io_ranges_size, SPTM_PAGE_SIZE);
    struct sptm_boot_io_filter *io_filters =
        sptm_boot_alloc_zero(&context.allocator, io_filters_size, SPTM_PAGE_SIZE);
    memcpy(io_ranges, raw_io_ranges, io_ranges_bytes);
    memcpy(io_filters, raw_io_filters, io_filters_bytes);
    u32 io_range_count = io_ranges_bytes / sizeof(*io_ranges);
    u32 io_filter_count = io_filters_bytes / sizeof(*io_filters);
    sptm_boot_sort_io_ranges(io_ranges, io_range_count);
    sptm_boot_sort_io_filters(io_filters, io_filter_count);

    context.ttbr1_pa = sptm_boot_alloc_table(&context, 1);
    context.ttbr0_pa = sptm_boot_alloc_table(&context, 1);
    // Locked platforms need Outer-shareable aliases for cross-cluster stability.
    u64 data_leaf =
        !cpu_features->apple_sysregs_unlocked ? SPTM_LEAF_DATA_OUTER : SPTM_LEAF_DATA;
    sptm_boot_map_page(&context, context.ttbr0_pa, 0, ttbr0_zero_page_pa, data_leaf);
    sptm_boot_map_range(&context, context.ttbr1_pa, context.kernel_vmin, context.kernel_pa,
                        ALIGN_UP(context.kernel_vmax - context.kernel_vmin, SPTM_PAGE_SIZE),
                        SPTM_LEAF_CODE);
    sptm_boot_map_range(&context, context.ttbr1_pa, context.physmap_base, context.managed_start,
                        context.managed_end - context.managed_start, data_leaf);
    sptm_boot_retype_page(&context, context.ttbr1_pa,
                          sptm_boot_va(&context, context.uat_global_root_pa),
                          context.uat_global_root_pa, SPTM_LEAF_DATA_NC);

    // XNU expects the locked ADT and TrustCache as EXTRADATA just below the kernelcache.
    u64 trustcache_pa, trustcache_size;
    sptm_boot_adt_region(memory_map, "TrustCache", &trustcache_pa, &trustcache_size);
    u64 adt_pa = ALIGN_DOWN(guest_adt, SPTM_PAGE_SIZE);
    u64 adt_offset = guest_adt - adt_pa;
    u64 adt_size = ALIGN_UP(adt_offset + bootargs->devtree_size, SPTM_PAGE_SIZE);
    u64 extradata_pa = min(adt_pa, ALIGN_DOWN(trustcache_pa, SPTM_PAGE_SIZE));
    u64 extradata_end =
        max(adt_pa + adt_size, ALIGN_UP(trustcache_pa + trustcache_size, SPTM_PAGE_SIZE));
    u64 extradata_size = extradata_end - extradata_pa;
    u64 extradata_va = ALIGN_DOWN(context.kernel_vmin - extradata_size, SPTM_PAGE_SIZE);
    sptm_boot_map_range(&context, context.ttbr1_pa, extradata_va, extradata_pa, extradata_size,
                        data_leaf);
    bootargs->devtree = (void *)(extradata_va + guest_adt - extradata_pa);

    context.uat_l2_pa = sptm_boot_adt_integer(sgx, "gfx-shared-l2-region-base", 0);
    u64 uat_l2_size = sptm_boot_adt_integer(sgx, "gfx-shared-l2-region-size", 0);
    // XNU adopts these empty L3s before normal pmap allocation is operational.
    // The fixed 64 MiB term stands in for the boot framebuffer size.
    u64 memory_segments = ALIGN_UP(bootargs->mem_size, BIT(28)) >> 28;
    u64 dynamic_l3_start = ALIGN_UP(context.physmap_end, SZ_32M);
    u64 dynamic_budget = (2 + memory_segments * 10) * SZ_1M;
    u64 dynamic_l3_end = ALIGN_UP(dynamic_l3_start + dynamic_budget + 64 * SZ_1M, 8 * SZ_1M);
    sptm_boot_preallocate_l3(&context, context.ttbr1_pa, dynamic_l3_start, dynamic_l3_end);
    // Keep the firmware-owned selector-9 page outside the physmap and empty-table range.
    context.uat_l2_va = ALIGN_UP(dynamic_l3_end, SZ_32M);
    sptm_boot_map_page(&context, context.ttbr1_pa, context.uat_l2_va, context.uat_l2_pa,
                       SPTM_LEAF_DATA_NC);
    // The topmost L3 backs early debug data and per-CPU copy windows.
    u64 high_l3_end = SPTM_VM_MAX_KERNEL_ADDRESS + 1;
    sptm_boot_preallocate_l3(&context, context.ttbr1_pa, high_l3_end - SZ_32M, high_l3_end);

    // Seed frames already live at handoff; XNU types the remaining RAM as it claims it.
    for (size_t frame = 0; frame < managed_pages; frame++)
        context.frame_table[frame * SPTM_FRAME_ENTRY_SIZE + 2] = SPTM_FRAME_DEFAULT;
    context.frame_priority =
        sptm_boot_alloc_zero(&context.allocator, managed_pages, SPTM_CACHE_LINE_SIZE);
    sptm_boot_type_kernel_frames(&context);
    // INIT_STATE never sees these objects; the root also owns its shared-L2 link.
    sptm_boot_set_frame(&context, context.uat_global_root_pa, SPTM_FRAME_XNU_IOMMU, 0, 0, 0, 0, 2);
    sptm_boot_set_frame(&context, context.uat_global_state_pa, SPTM_FRAME_XNU_IOMMU, 0, 0, 0, 0, 1);
    for (u32 index = 0; index < sptm_boot.page_count; index++) {
        const struct sptm_boot_pt_page *page = &sptm_boot.pages[index];
        u8 type = page->pa == context.ttbr1_pa   ? SPTM_FRAME_KERNEL_ROOT
                  : page->pa == context.ttbr0_pa ? SPTM_FRAME_USER_ROOT
                                                 : SPTM_FRAME_PAGE_TABLE;
        sptm_boot_set_frame(&context, page->pa, type, 0, 0, page->level,
                            sptm_boot_valid_count(page->pa), 0);
    }
    sptm_boot_set_frame(&context, ttbr0_zero_page_pa, SPTM_FRAME_DEFAULT, 0, 1, 0, 0, 0);

    // libsptm interprets kind 2 as a table body and kind 5 as a data body.
    for (u32 type = 0; type < 256; type++)
        ((u8 *)frame_params_pa)[type * SPTM_FRAME_PARAM_SIZE + 1] =
            sptm_boot_table_frame(type) ? 2 : 5;
    // Recover stripped pt-attr globals from stable anchors, in XNU's ABI order:
    // 16K, 4K, 16K kernel, then 16K, 16K-36b, and 4K stage 2.
    u64 *pt_attrs = (void *)pt_attrs_pa;
    pt_attrs[0] = cons_ops + 0x338;
    pt_attrs[1] = cons_ops + 0x248;
    pt_attrs[2] = cons_ops + 0x2c0;
    pt_attrs[3] = page_shift_const - 0xd18;
    pt_attrs[4] = page_shift_const - 0xca0;
    pt_attrs[5] = page_shift_const - 0xc28;

    // Put specific aliases before the catch-all physmap so overlaps resolve to them.
    struct sptm_boot_papt *papt = (void *)papt_ranges_pa;
    papt[0] =
        (struct sptm_boot_papt){extradata_pa, extradata_va, extradata_size / SPTM_PAGE_SIZE, 0};
    papt[1] = (struct sptm_boot_papt){context.uat_l2_pa, context.uat_l2_va, 1, 0};
    papt[2] =
        (struct sptm_boot_papt){context.managed_start, context.physmap_base,
                                (context.managed_end - context.managed_start) / SPTM_PAGE_SIZE, 0};
    write32(papt_count_pa, 3);

    // Cold boot dereferences all three image slots; reuse XNU without SPTM/TXM symbols.
    write32(debug_header_pa, 0x47424544);
    write32(debug_header_pa + 4, 2);
    write32(debug_header_pa + 8, 3);
    write64(debug_header_pa + 0x10, xnu_text);
    write64(debug_header_pa + 0x18, xnu_text);
    write64(debug_header_pa + 0x20, xnu_text);

    write32(context.cpu_map_pa, cpu_count);
    cpu = cpus;
    ADT_FOREACH_CHILD(adt, cpu)
    {
        u32 logical = sptm_boot_adt_integer(cpu, "cpu-id", 0);
        write32(context.cpu_map_pa + (logical + 1) * sizeof(u32),
                sptm_boot_adt_integer(cpu, "reg", 0));
    }
    for (u32 index = 0; index < cpu_count; index++)
        write64(txm_stack_array_pa + index * sizeof(u64),
                sptm_boot_va(&context, txm_stacks_pa + index * SPTM_PAGE_SIZE));
    // TXM uses this zeroed policy page to disable monitor signing and enable developer mode.
    write64(txm_info_pa + 0x190, context.txm_info_va);
    write8(txm_info_pa + 0x318, 1);

    // This boot-created global UAT state never passes through INIT_STATE.
    write8(context.uat_global_state_pa, uat_mode == 0 ? 2 : 8);
    write64(context.uat_global_state_pa + 8, 0xffffffff);
    write64(context.uat_global_state_pa + 0x10, context.uat_global_root_pa);
    write16(context.uat_global_state_pa + 0x18, 0xffff);
    write8(context.uat_global_state_pa + 0x1a, 2);
    // G15+ UAT exposes the firmware-shared L2 through top-level slot 2.
    write64(context.uat_global_root_pa + 2 * sizeof(u64), context.uat_l2_pa | SPTM_TABLE_DESC);

    // arm_init copies this one-shot cold-entry record before using its pointers.
    u8 *bootstrap = (void *)context.bootstrap_pa;
    write64((u64)bootstrap + 0x00, sptm_boot_va(&context, context.scratch_pa));
    write64((u64)bootstrap + 0x08, context.physmap_base);
    write64((u64)bootstrap + 0x10, context.physmap_end);
    write64((u64)bootstrap + 0x18, aux_end);
    write64((u64)bootstrap + 0x30, sptm_boot_va(&context, txm_stack_array_pa));
    write32((u64)bootstrap + 0x38, cpu_count);
    write64((u64)bootstrap + 0x40, sptm_boot_va(&context, kernel_stacks_pa));
    write64((u64)bootstrap + 0x48,
            sptm_boot_va(&context, kernel_stacks_pa + SPTM_CPU_STACK_WINDOW_SIZE));
    write64((u64)bootstrap + 0x50, context.kernel_vmin);
    write64((u64)bootstrap + 0x58, context.kernel_vmax);
    write64((u64)bootstrap + 0x60, sptm_boot_va(&context, debug_header_pa));
    write32((u64)bootstrap + 0x68, sptm_boot_adt_integer(defaults, "pmap-max-asids", 256));
    memcpy(bootstrap + 0x6c, "randseed", 8);
    memcpy(bootstrap + 0x74, adt_getprop(adt, chosen, "random-seed", NULL), 256);
    write64((u64)bootstrap + 0x178, 0x108);
    write64((u64)bootstrap + 0x198, sptm_boot_va(&context, context.panic_state_pa));

    // The nested libsptm state becomes XNU's persistent SPTM client state.
    u64 libsptm = (u64)bootstrap + 0x1a0;
    write64(libsptm + 0x00, 10);
    write64(libsptm + 0x08, sptm_boot_va(&context, papt_count_pa));
    write64(libsptm + 0x10, sptm_boot_va(&context, papt_ranges_pa));
    write64(libsptm + 0x18, context.managed_start);
    write64(libsptm + 0x20, context.managed_end);
    write64(libsptm + 0x28, context.physmap_base);
    write64(libsptm + 0x30, context.physmap_end);
    write64(libsptm + 0x38, context.ttbr1_pa);
    write64(libsptm + 0x40, sptm_boot_va(&context, context.frame_table_pa));
    write64(libsptm + 0x48, sptm_boot_va(&context, frame_params_pa));
    write64(libsptm + 0x50, sptm_boot_va(&context, pt_attrs_pa));
    write64(libsptm + 0x80, sptm_boot_va(&context, context.panic_state_pa + 8));
    write64(libsptm + 0x88, sptm_boot_va(&context, trace_buffer_pa));
    write64(libsptm + 0x90, sptm_boot_va(&context, dispatch_states_pa));
    write64(libsptm + 0x98, cpu_count);
    write64(libsptm + 0xa0, sptm_boot_va(&context, saved_states_pa));
    write64(libsptm + 0xa8, 8);
    // Early boot and persistent libsptm state each need their own I/O-range copy.
    write64(libsptm + 0xc0, sptm_boot_va(&context, (u64)io_ranges));
    write64(libsptm + 0xc8, io_range_count);
    write64(libsptm + 0xd0, sptm_boot_va(&context, context.panic_state_pa + 12));
    write64(libsptm + 0xd8, sptm_boot_va(&context, event_counters_pa));
    // With no AuxKC, XNU still needs this value to derive the kernelcache bounds.
    write64((u64)bootstrap + 0x2e8, context.kernel_vmax);
    write64((u64)bootstrap + 0x318, sptm_boot_va(&context, (u64)io_ranges));
    write32((u64)bootstrap + 0x320, io_range_count);
    write64((u64)bootstrap + 0x328, sptm_boot_va(&context, (u64)io_filters));
    write32((u64)bootstrap + 0x330, io_filter_count);
    write64((u64)bootstrap + 0x338, 0x10);

    // Start with no panicking CPU/domain and the cold-boot dispatch states XNU expects.
    write16(context.panic_state_pa + 8, 0xffff);
    write32(context.panic_state_pa + 12, 0xff);
    write32(dispatch_states_pa + 0xa30, 5);
    write32(dispatch_states_pa + 0xa60, 5);

    msr(TTBR0_EL12, context.ttbr0_pa);
    msr(TTBR1_EL12, context.ttbr1_pa);
    msr(TCR_EL12, SPTM_TCR_BOOT);
    msr(MAIR_EL12, SPTM_MAIR_BOOT);
    msr(AMAIR_EL12, 0);
    msr(CONTEXTIDR_EL12, 0);
    msr(VBAR_EL12, 0);
    msr(SCTLR_EL12, SPTM_SCTLR_BOOT);

    hv_sptm_configure(context.managed_start, context.managed_end, context.physmap_base,
                      context.scratch_pa, context.ttbr1_pa, context.cpu_map_pa);
    hv_sptm_configure_frames(context.frame_table_pa);
    u64 uat_info = uat_mode | (u64)uat_va_width << 8 | (u64)uat_segment_limit << 16 |
                   (u64)uat_mapping_limit << 32 | (u64)uat_tlbi_at_retype << 48;
    hv_sptm_configure_uat(context.uat_l2_pa, uat_l2_size, uat_info, context.uat_global_state_pa,
                          context.uat_gpu_region_pa, context.uat_l2_va);
    hv_sptm_configure_uat_handoff(sptm_boot_adt_integer(sgx, "gfx-handoff-base", 0),
                                  sptm_boot_adt_integer(sgx, "gfx-handoff-size", 0));
    hv_sptm_configure_txm(context.txm_info_va);
    sptm_init_platform(guest_adt, context.allocator.next, context.allocator.end);

    sptm_boot.entry = context.kernel_entry;
    sptm_boot.bootargs_va = sptm_boot_va(&context, bootargs_pa);
    sptm_boot.bootstrap_va = sptm_boot_va(&context, context.bootstrap_pa);
    sptm_boot.panic_state_pa = context.panic_state_pa;
    sptm_boot.ready = true;
    adt = firmware_adt;
    return sptm_boot.panic_state_pa;
}

void sptm_boot_prepare_start(void **entry, u64 regs[4], bool secondary)
{
    if (!sptm_boot.ready)
        return;
    *entry = (void *)sptm_boot.entry;
    regs[0] = secondary;
    regs[1] = sptm_boot.bootargs_va;
    regs[2] = sptm_boot.bootstrap_va;
    regs[3] = 0;
}
