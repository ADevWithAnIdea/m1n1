/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

static bool sptm_uat_valid_table(u64 pa)
{
    if (pa & SPTM_PAGE_MASK)
        return false;
    if (sptm_valid_pa(pa, SPTM_PAGE_SIZE))
        return true;
    return pa == sptm.uat_shared_l2_pa && sptm.uat_shared_l2_size == SPTM_PAGE_SIZE;
}

static bool sptm_uat_sentinel(u64 root)
{
    return root == UINT32_MAX || root == UINT64_MAX;
}

static u64 sptm_uat_state_pa(u64 handle)
{
    if (!sptm.uat_configured)
        return 0;
    if ((handle & SPTM_PAGE_MASK) || !sptm_valid_pa(handle, SPTM_PAGE_SIZE))
        return 0;
    return handle;
}

static void sptm_uat_handoff_acquire(u64 address, size_t size)
{
    if (!size)
        return;
    u64 start = ALIGN_DOWN(address, SPTM_CACHE_LINE_SIZE);
    size = ALIGN_UP(address - start + size, SPTM_CACHE_LINE_SIZE);
    sysop("dsb osh");
    dc_ivac_range((void *)start, size);
    sysop("dsb osh");
}

static u64 sptm_uat_handoff_slot_addr(u32 slot)
{
    return sptm.uat_handoff_pa + UAT_HANDOFF_SLOT_BASE + slot * UAT_HANDOFF_SLOT_STRIDE;
}

static bool sptm_uat_handoff_slot_for_state(u64 state_pa, u32 *slot)
{
    u8 state_type = read8(state_pa);
    if (state_type == UAT_STATE_GLOBAL_MODE0 || state_type == UAT_STATE_GLOBAL_MODE1) {
        *slot = UAT_HANDOFF_SHARED_SLOT;
        return true;
    }
    if (state_type != UAT_STATE_SINGLE_ROOT && state_type != UAT_STATE_DUAL_ROOT)
        return false;

    u16 context_id = read16(state_pa + UAT_STATE_CONTEXT_ID);
    if (context_id >= UAT_HANDOFF_SHARED_SLOT)
        return false;
    *slot = context_id;
    return true;
}

static bool sptm_uat_handoff_slot_available(u32 slot)
{
    if (!sptm.uat_handoff_pa || slot >= UAT_HANDOFF_SLOT_COUNT || sptm.uat_handoff_pending[slot])
        return false;
    u64 state = sptm_uat_handoff_slot_addr(slot) + UAT_HANDOFF_SLOT_STATE;
    sptm_uat_handoff_acquire(state, sizeof(u32));
    return read32(state) == 0;
}

static bool sptm_uat_handoff_post(u64 state_pa, u32 slot, u64 va, u64 count, u64 *result)
{
    if (!count) {
        *result = 0;
        return true;
    }

    if (!sptm_uat_handoff_slot_available(slot)) {
        printf("HV: SPTM UAT handoff slot %u unavailable for state 0x%lx "
               "(slot-state=0x%x pending=%u)\n",
               slot, state_pa,
               sptm.uat_handoff_pa
                   ? read32(sptm_uat_handoff_slot_addr(slot) + UAT_HANDOFF_SLOT_STATE)
                   : UINT32_MAX,
               slot < UAT_HANDOFF_SLOT_COUNT ? sptm.uat_handoff_pending[slot] : false);
        return false;
    }

    u64 handoff = sptm.uat_handoff_pa;
    sptm_uat_handoff_acquire(handoff, UAT_HANDOFF_SLOT_BASE);
    bool firmware_accepting = read64(handoff + UAT_HANDOFF_MAGIC_FW) == UAT_HANDOFF_MAGIC;
    bool could_be_cached =
        slot == UAT_HANDOFF_SHARED_SLOT || read32(handoff + UAT_HANDOFF_CURRENT_CTX) == slot;
    bool request_flush = firmware_accepting && could_be_cached;
    u64 slot_addr = sptm_uat_handoff_slot_addr(slot);
    u64 address = request_flush ? va : UAT_HANDOFF_UNMAP_TAG | (va & UAT_HANDOFF_ADDR_MASK);

    write64(slot_addr + UAT_HANDOFF_SLOT_ADDR, address);
    write64(slot_addr + UAT_HANDOFF_SLOT_SIZE, count * SPTM_PAGE_SIZE);
    sysop("dsb osh");
    write64(slot_addr + UAT_HANDOFF_SLOT_STATE, request_flush ? 1 : 2);
    sysop("dsb osh");

    sptm.uat_handoff_pending[slot] = true;
    sptm.uat_handoff_owner[slot] = state_pa;
    *result = request_flush ? 2 : 0;
    return true;
}

static bool sptm_uat_handoff_complete(u64 state_pa)
{
    u64 owner = state_pa;
    for (u32 slot = 0; slot < UAT_HANDOFF_SLOT_COUNT; slot++) {
        if (!sptm.uat_handoff_pending[slot] || sptm.uat_handoff_owner[slot] != owner)
            continue;

        u64 state_addr = sptm_uat_handoff_slot_addr(slot) + UAT_HANDOFF_SLOT_STATE;
        sptm_uat_handoff_acquire(state_addr, sizeof(u32));
        u32 state = read32(state_addr);
        if (!state) {
            printf("HV: SPTM UAT handoff slot %u was cleared before "
                   "unmap completion for state 0x%lx\n",
                   slot, owner);
            return false;
        }
        write32(state_addr, 0);
        sysop("dsb osh");
        sptm.uat_handoff_pending[slot] = false;
        sptm.uat_handoff_owner[slot] = 0;
    }
    return true;
}

static void sptm_uat_publish_guard(u64 state_pa, u8 guard)
{
    sysop("dsb osh");
    write8(state_pa + UAT_STATE_GUARD, guard);
    sysop("dsb osh");
}

static bool sptm_uat_acquire_guard(u64 state_pa, u8 expected)
{
    if (read8(state_pa + UAT_STATE_GUARD) != expected)
        return false;
    write8(state_pa + UAT_STATE_GUARD, UAT_GUARD_BUSY);
    sysop("dsb osh");
    return true;
}

static bool sptm_uat_acquire_begin(u64 state_pa, u8 operation)
{
    // Both guarded boot objects and idle contexts are valid at BEGIN.
    u8 guard = read8(state_pa + UAT_STATE_GUARD);
    if (guard != UAT_GUARD_IDLE && guard != operation)
        return false;
    write8(state_pa + UAT_STATE_GUARD, UAT_GUARD_BUSY);
    sysop("dsb osh");
    return true;
}

static void sptm_uat_write_descriptor(u64 slot, u64 descriptor)
{
    // this is where we would use the coprocessor flush op
    write64(slot, descriptor);
    sysop("dsb oshst");
}

static bool sptm_uat_ref_table(u64 pa, int delta)
{
    pa &= SPTM_DESC_PA_MASK_16K;
    u8 *entry = sptm_frame_entry(pa);
    if (!entry || entry[2] != SPTM_FRAME_XNU_IOMMU)
        return false;

    u16 refcount = read16((u64)entry + 4);
    if ((delta < 0 && refcount < (u16)-delta) || (delta > 0 && refcount > UINT16_MAX - (u16)delta))
        return false;
    write16((u64)entry + 4, refcount + delta);
    return true;
}

static bool sptm_uat_ref_parent(u64 pa, int delta)
{
    pa &= SPTM_DESC_PA_MASK_16K;
    if (pa == sptm.uat_shared_l2_pa && sptm.uat_shared_l2_size == SPTM_PAGE_SIZE)
        return true;
    return sptm_uat_ref_table(pa, delta);
}

static bool sptm_uat_table_refs_can_release(u64 child_pa, u64 parent_pa)
{
    child_pa &= SPTM_DESC_PA_MASK_16K;
    parent_pa &= SPTM_DESC_PA_MASK_16K;

    u8 *child = sptm_frame_entry(child_pa);
    if (!child || child[2] != SPTM_FRAME_XNU_IOMMU)
        return false;

    u16 child_refs = read16((u64)child + 4);
    if (child_pa == parent_pa)
        return child_refs >= 2;
    if (!child_refs)
        return false;

    if (parent_pa == sptm.uat_shared_l2_pa && sptm.uat_shared_l2_size == SPTM_PAGE_SIZE)
        return true;

    u8 *parent = sptm_frame_entry(parent_pa);
    return parent && parent[2] == SPTM_FRAME_XNU_IOMMU && read16((u64)parent + 4);
}

static bool sptm_uat_ref_page(u64 descriptor, int delta)
{
    // Track UAT leaves through the frame header's common in_use count.
    return sptm_adjust_iommu_use(descriptor & SPTM_DESC_PA_MASK_16K, delta);
}

static u64 sptm_uat_normalize_va(u64 va)
{
    return va & (BIT(sptm.uat_va_width) - 1);
}

void sptm_uat_tlbi_all(void)
{
    // Match VMALLE1OS's outer-shareable domain.
    sysop("dsb oshst");
    __asm__ volatile("sys #0, c8, c1, #0, xzr" ::: "memory");
    sysop("dsb osh");
    sysop("isb");
}

static bool sptm_uat_root(u64 state_pa, u64 va, u64 *root)
{
    va = sptm_uat_normalize_va(va);
    u64 root_offset;
    switch (read8(state_pa)) {
        case UAT_STATE_SINGLE_ROOT:
            root_offset = UAT_STATE_ROOT0;
            break;
        case UAT_STATE_GLOBAL_MODE0:
        case UAT_STATE_GLOBAL_MODE1:
            /* Boot-seeded shared-TTBR1 objects intentionally have no root0. */
            root_offset = UAT_STATE_ROOT1;
            break;
        case UAT_STATE_DUAL_ROOT:
            root_offset = ((va >> (sptm.uat_va_width - 1)) & 1) ? UAT_STATE_ROOT1 : UAT_STATE_ROOT0;
            break;
        default:
            return false;
    }

    u64 table = read64(state_pa + root_offset);
    if (sptm_uat_sentinel(table))
        return false;
    table &= SPTM_DESC_PA_MASK_16K;
    if (!sptm_uat_valid_table(table))
        return false;
    *root = table;
    return true;
}

static u64 sptm_uat_slot(u64 state_pa, u64 va, u32 level)
{
    u64 table;
    if (!sptm_uat_root(state_pa, va, &table))
        return 0;
    va = sptm_uat_normalize_va(va);

    // The L1 index uses the VA bits above the 16 KiB three-level walk.
    u64 l1_mask = BIT(max((int)sptm.uat_va_width - 37, 0)) - 1;
    u64 indices[] = {
        (va >> 36) & l1_mask,
        (va >> 25) & 0x7ff,
        (va >> SPTM_PAGE_SHIFT) & 0x7ff,
    };

    for (u32 current_level = 1;; current_level++) {
        // Access type-24 tables only through their Normal-NC alias.
        u64 slot = sptm_iommu_table_va(table) + indices[current_level - 1] * sizeof(u64);
        if (current_level == level)
            return slot;

        u64 descriptor = read64(slot);
        if ((descriptor & 3) != UAT_DESC_TABLE)
            return 0;
        table = descriptor & SPTM_DESC_PA_MASK_16K;
        if (!sptm_uat_valid_table(table))
            return 0;
    }
}

static bool sptm_uat_init_state(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    u64 root0 = ctx->regs[1];
    u64 root1 = ctx->regs[2];
    bool dual = !sptm_uat_sentinel(root1);
    if (!state_pa || sptm_uat_sentinel(root0) ||
        read8(state_pa + UAT_STATE_GUARD) != UAT_GUARD_UNINITIALIZED)
        return false;

    u64 roots[] = {state_pa, root0, root1};
    size_t root_count = dual ? ARRAY_SIZE(roots) : ARRAY_SIZE(roots) - 1;
    size_t pinned = 0;
    for (; pinned < root_count; pinned++) {
        if (!sptm_uat_ref_table(roots[pinned], 1))
            break;
    }
    if (pinned != root_count) {
        while (pinned)
            sptm_uat_ref_table(roots[--pinned], -1);
        return false;
    }

    memset((void *)state_pa, 0, SPTM_PAGE_SIZE);
    write8(state_pa, dual ? UAT_STATE_DUAL_ROOT : UAT_STATE_SINGLE_ROOT);
    write64(state_pa + UAT_STATE_ROOT0, root0);
    write64(state_pa + UAT_STATE_ROOT1, root1);
    write16(state_pa + UAT_STATE_CONTEXT_ID, UINT16_MAX);
    sptm_uat_publish_guard(state_pa, UAT_GUARD_IDLE);
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static bool sptm_uat_destroy_state(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    if (!state_pa || read16(state_pa + UAT_STATE_CONTEXT_ID) != UINT16_MAX ||
        !sptm_uat_acquire_guard(state_pa, UAT_GUARD_IDLE))
        return false;

    u64 root0 = read64(state_pa + UAT_STATE_ROOT0);
    u64 root1 = read64(state_pa + UAT_STATE_ROOT1);
    u64 roots[] = {state_pa, root0, root1};
    size_t root_count = sptm_uat_sentinel(root1) ? 2 : ARRAY_SIZE(roots);
    for (size_t index = 0; index < root_count; index++)
        sptm_uat_ref_table(roots[index], -1);

    memset((void *)state_pa, 0, SPTM_PAGE_SIZE);
    write64(state_pa + UAT_STATE_ROOT0, UINT32_MAX);
    write64(state_pa + UAT_STATE_ROOT1, UINT32_MAX);
    write16(state_pa + UAT_STATE_CONTEXT_ID, UINT16_MAX);
    sysop("dsb osh");
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static bool sptm_uat_map_table(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    u32 level = ctx->regs[2];
    u64 table_pa = ctx->regs[3] & SPTM_DESC_PA_MASK_16K;

    if (!state_pa || level < 1 || level > 2 || (ctx->regs[3] & SPTM_PAGE_MASK) ||
        !sptm_valid_pa(table_pa, SPTM_PAGE_SIZE))
        return false;

    u8 *table_entry = sptm_frame_entry(table_pa);
    if (!table_entry || table_entry[2] != SPTM_FRAME_XNU_IOMMU)
        return false;

    u64 slot = sptm_uat_slot(state_pa, ctx->regs[1], level);
    if (!slot)
        return false;
    u64 descriptor = table_pa | UAT_DESC_TABLE;
    if (read64(slot))
        return false;

    u64 parent_pa = slot & ~(REGION_NORMAL_NC | SPTM_PAGE_MASK);

    if (!sptm_uat_ref_table(table_pa, 1))
        return false;
    if (!sptm_uat_ref_parent(parent_pa, 1)) {
        sptm_uat_ref_table(table_pa, -1);
        return false;
    }

    sptm_uat_write_descriptor(slot, descriptor);
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static bool sptm_uat_unmap_table(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    u32 level = ctx->regs[2];
    if (!state_pa || level < 1 || level > 2)
        return false;

    u64 slot = sptm_uat_slot(state_pa, ctx->regs[1], level);
    if (!slot)
        return false;
    u64 descriptor = read64(slot);
    if ((descriptor & 3) != UAT_DESC_TABLE)
        return false;
    u64 table_pa = descriptor & SPTM_DESC_PA_MASK_16K;
    u64 parent_pa = slot & ~(REGION_NORMAL_NC | SPTM_PAGE_MASK);

    // The firmware-owned shared L2 cannot be removed or recreated.
    if (table_pa == sptm.uat_shared_l2_pa && sptm.uat_shared_l2_size == SPTM_PAGE_SIZE)
        return false;
    if (!sptm_uat_table_refs_can_release(table_pa, parent_pa))
        return false;

    sptm_uat_write_descriptor(slot, 0);
    sptm_uat_tlbi_all();
    sptm_uat_ref_table(table_pa, -1);
    sptm_uat_ref_parent(parent_pa, -1);
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static bool sptm_uat_validate_map_segments(u64 segments_pa, u64 count, u64 start_va)
{
    if (start_va >= BIT(sptm.uat_va_width))
        return false;
    u64 pages = 0;
    for (u64 index = 0; index < count; index++) {
        struct sptm_uat_segment *segment = (void *)(segments_pa + index * sizeof(*segment));
        if ((segment->first & SPTM_PAGE_MASK) ||
            segment->count > (UINT64_MAX - segment->first) / SPTM_PAGE_SIZE ||
            pages > UINT64_MAX - segment->count)
            return false;
        pages += segment->count;
    }
    return pages <= (BIT(sptm.uat_va_width) - start_va) / SPTM_PAGE_SIZE;
}

static bool sptm_uat_validate_unmap_segments(u64 segments_pa, u64 count)
{
    for (u64 index = 0; index < count; index++) {
        struct sptm_uat_segment *segment = (void *)(segments_pa + index * sizeof(*segment));
        u64 first = sptm_uat_normalize_va(segment->first);
        if ((segment->first & SPTM_PAGE_MASK) ||
            segment->count > (BIT(sptm.uat_va_width) - first) / SPTM_PAGE_SIZE)
            return false;

        u64 end = first + segment->count * SPTM_PAGE_SIZE;
        for (u64 previous = 0; previous < index; previous++) {
            struct sptm_uat_segment *other = (void *)(segments_pa + previous * sizeof(*other));
            u64 other_first = sptm_uat_normalize_va(other->first);
            u64 other_end = other_first + other->count * SPTM_PAGE_SIZE;
            if (segment->count && other->count && first < other_end && other_first < end)
                return false;
        }
    }
    return true;
}

static bool sptm_uat_leaf_descriptor(u64 state_pa, u64 target, u32 options, u64 *descriptor)
{
    // Preserve per-context memory types and permissions from the map options.
    static const u8 permissions[4][4] = {
        {0, 2, 2 | BIT(2), 2 | BIT(3)},
        {1, BIT(2), UINT8_MAX, UINT8_MAX},
        {1 | BIT(2), UINT8_MAX, BIT(3), UINT8_MAX},
        {1 | BIT(3), 1 | BIT(2) | BIT(3), UINT8_MAX, BIT(2) | BIT(3)},
    };

    if (options & ~UAT_MAP_OPTIONS_MASK)
        return false;

    u8 permission = permissions[options & 3][(options >> 8) & 3];
    if (permission == UINT8_MAX)
        return false;

    u8 state_type = read8(state_pa);
    bool non_global;
    switch (state_type) {
        case UAT_STATE_SINGLE_ROOT:
        case UAT_STATE_DUAL_ROOT:
            non_global = true;
            break;
        case UAT_STATE_GLOBAL_MODE0:
        case UAT_STATE_GLOBAL_MODE1:
            non_global = false;
            break;
        default:
            return false;
    }

    u64 attr = options & BIT(2) ? 1 : options & BIT(3) ? 2 : 0;
    u64 flags = UAT_DESC_OS | UAT_DESC_AF | UAT_DESC_VALID | BIT(1) |
                (attr << UAT_DESC_ATTR_SHIFT) | ((u64)(permission & 3) << UAT_DESC_AP_SHIFT);
    if (non_global)
        flags |= UAT_DESC_NG;
    if (permission & BIT(2))
        flags |= UAT_DESC_PXN;
    if (permission & BIT(3))
        flags |= UAT_DESC_UXN;

    *descriptor = (target & SPTM_DESC_PA_MASK_16K) | flags;
    return true;
}

static bool sptm_uat_map_continue(struct exc_info *ctx, u64 state_pa)
{
    u64 va = read64(state_pa + UAT_STATE_CURSOR0);
    u64 segment_count = read64(state_pa + UAT_STATE_CURSOR1);
    u64 segment_index = read64(state_pa + UAT_STATE_CURSOR2);
    u64 page_index = read64(state_pa + UAT_STATE_CURSOR3);
    u32 options = read32(state_pa + UAT_STATE_OPTIONS);
    u32 budget = min(sptm.uat_mapping_limit, SPTM_UAT_BATCH_PAGES);
    bool failed = false;

    while (budget && segment_index < segment_count) {
        struct sptm_uat_segment *segment =
            (void *)(state_pa + UAT_STATE_MAP_SEGMENTS + segment_index * sizeof(*segment));
        if (page_index >= segment->count) {
            segment_index++;
            page_index = 0;
            continue;
        }

        u64 slot = sptm_uat_slot(state_pa, va, 3);
        if (!slot) {
            printf("HV: SPTM UAT MAP_PAGE rejected missing leaf state=0x%lx "
                   "va=0x%lx segment=%lu/%lu page=%lu\n",
                   state_pa, va, segment_index, segment_count, page_index);
            failed = true;
            break;
        }
        u64 target = segment->first + page_index * SPTM_PAGE_SIZE;
        u64 descriptor;
        if (!sptm_uat_leaf_descriptor(state_pa, target, options, &descriptor)) {
            printf("HV: SPTM UAT MAP_PAGE rejected options state=0x%lx "
                   "type=%u options=0x%x va=0x%lx target=0x%lx\n",
                   state_pa, read8(state_pa), options, va, target);
            failed = true;
            break;
        }
        u64 old_descriptor = read64(slot);
        if (old_descriptor != descriptor) {
            bool old_valid = old_descriptor & UAT_DESC_VALID;
            bool changes_frame = !old_valid || (old_descriptor & SPTM_DESC_PA_MASK_16K) !=
                                                   (descriptor & SPTM_DESC_PA_MASK_16K);
            if (changes_frame && !sptm_uat_ref_page(descriptor, 1)) {
                failed = true;
                break;
            }

            if (old_valid) {
                // Keep the old target pinned until the replacement is invalidated.
                sptm_uat_write_descriptor(slot, descriptor);
                sptm_uat_tlbi_all();
                if (changes_frame)
                    sptm_uat_ref_page(old_descriptor, -1);
            } else {
                sptm_uat_write_descriptor(slot, descriptor);
            }
        }
        va += SPTM_PAGE_SIZE;
        page_index++;
        budget--;
    }

    if (failed)
        return false;

    write64(state_pa + UAT_STATE_CURSOR0, va);
    write64(state_pa + UAT_STATE_CURSOR2, segment_index);
    write64(state_pa + UAT_STATE_CURSOR3, page_index);
    bool done = segment_index >= segment_count;
    sptm_uat_publish_guard(state_pa, done ? UAT_GUARD_IDLE : UAT_GUARD_MAP);
    ctx->regs[0] = done ? 0 : 1;
    return true;
}

static bool sptm_uat_map_begin(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    u64 segment_count = ctx->regs[3];
    u64 start_va = sptm_uat_normalize_va(ctx->regs[1]);
    u64 ignored_descriptor;
    if (!state_pa || segment_count > sptm.uat_segment_limit) {
        printf("HV: SPTM UAT MAP_PAGE rejected header state=0x%lx "
               "segments=%lu limit=%u\n",
               state_pa, segment_count, sptm.uat_segment_limit);
        return false;
    }
    if ((ctx->regs[4] & ~UINT32_MAX) ||
        !sptm_uat_leaf_descriptor(state_pa, 0, (u32)ctx->regs[4], &ignored_descriptor)) {
        printf("HV: SPTM UAT MAP_PAGE rejected options state=0x%lx "
               "type=%u options=0x%lx\n",
               state_pa, state_pa ? read8(state_pa) : 0, ctx->regs[4]);
        return false;
    }

    size_t size = segment_count * sizeof(struct sptm_uat_segment);
    u64 segments_pa = 0;
    if (size) {
        segments_pa = ctx->regs[2];
        if (!sptm_valid_pa(segments_pa, size)) {
            printf("HV: SPTM UAT MAP_PAGE rejected segment pointer "
                   "0x%lx+0x%lx managed=0x%lx..0x%lx\n",
                   segments_pa, size, sptm.managed_start, sptm.managed_end);
            return false;
        }
        if (!sptm_uat_validate_map_segments(segments_pa, segment_count, start_va)) {
            struct sptm_uat_segment *first = (void *)segments_pa;
            printf("HV: SPTM UAT MAP_PAGE rejected segments va=0x%lx "
                   "first=0x%lx count=%lu entries=%lu\n",
                   start_va, first->first, first->count, segment_count);
            return false;
        }
    }
    if (!sptm_uat_acquire_begin(state_pa, UAT_GUARD_MAP)) {
        printf("HV: SPTM UAT MAP_PAGE rejected guard state=0x%lx "
               "type=%u guard=%u\n",
               state_pa, read8(state_pa), read8(state_pa + UAT_STATE_GUARD));
        return false;
    }

    if (size)
        memcpy((void *)(state_pa + UAT_STATE_MAP_SEGMENTS), (void *)segments_pa, size);
    write64(state_pa + UAT_STATE_CURSOR0, start_va);
    write64(state_pa + UAT_STATE_CURSOR1, segment_count);
    write64(state_pa + UAT_STATE_CURSOR2, 0);
    write64(state_pa + UAT_STATE_CURSOR3, 0);
    write32(state_pa + UAT_STATE_OPTIONS, ctx->regs[4]);
    write8(state_pa + UAT_STATE_FLUSH_LEVEL, 0);
    sptm_uat_publish_guard(state_pa, UAT_GUARD_MAP);
    return sptm_uat_map_continue(ctx, state_pa);
}

static bool sptm_uat_map_resume(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    if (!state_pa || !sptm_uat_acquire_guard(state_pa, UAT_GUARD_MAP))
        return false;
    return sptm_uat_map_continue(ctx, state_pa);
}

static bool sptm_uat_prepare_unmap_continue(struct exc_info *ctx, u64 state_pa)
{
    u64 va = read64(state_pa + UAT_STATE_CURSOR0);
    u64 count = read64(state_pa + UAT_STATE_CURSOR1);
    u64 processed = read64(state_pa + UAT_STATE_CURSOR2);
    u32 budget = sptm.uat_mapping_limit;

    while (budget && processed < count) {
        u64 slot = sptm_uat_slot(state_pa, va + processed * SPTM_PAGE_SIZE, 3);
        if (!slot)
            return false;
        u64 descriptor = read64(slot);
        if (descriptor & UAT_DESC_VALID) {
            u32 attr = (descriptor >> UAT_DESC_ATTR_SHIFT) & 7;
            u32 ap = (descriptor >> UAT_DESC_AP_SHIFT) & 3;
            bool firmware_candidate =
                !attr && ((!ap && (descriptor & UAT_DESC_UXN)) ||
                          (ap == 1 && (descriptor & (UAT_DESC_PXN | UAT_DESC_UXN))));
            if (firmware_candidate) {
                sptm_uat_write_descriptor(slot, descriptor | UAT_DESC_FIRMWARE_OWNED);
            }
        }
        processed++;
        budget--;
    }

    write64(state_pa + UAT_STATE_CURSOR2, processed);
    bool done = processed >= count;
    u64 result = done ? 0 : 1;
    if (done && count) {
        u64 slot_cookie = read64(state_pa + UAT_STATE_CURSOR3);
        if (!slot_cookie || slot_cookie > UAT_HANDOFF_SLOT_COUNT) {
            printf("HV: SPTM UAT missing handoff slot for completed "
                   "prepare-unmap state 0x%lx\n",
                   state_pa);
            return false;
        }
        if (!sptm_uat_handoff_post(state_pa, slot_cookie - 1, va, count, &result))
            return false;
    }
    sptm_uat_publish_guard(state_pa, done ? UAT_GUARD_IDLE : UAT_GUARD_PREPARE_UNMAP);
    ctx->regs[0] = result;
    return true;
}

static bool sptm_uat_prepare_unmap_begin(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    u64 va = sptm_uat_normalize_va(ctx->regs[1]);
    u64 count = ctx->regs[2];
    u32 handoff_slot = 0;
    if (!state_pa || (va & SPTM_PAGE_MASK) ||
        count > (BIT(sptm.uat_va_width) - va) / SPTM_PAGE_SIZE ||
        (count && (!sptm_uat_handoff_slot_for_state(state_pa, &handoff_slot) ||
                   !sptm_uat_handoff_slot_available(handoff_slot))) ||
        !sptm_uat_acquire_begin(state_pa, UAT_GUARD_PREPARE_UNMAP))
        return false;

    write64(state_pa + UAT_STATE_CURSOR0, va);
    write64(state_pa + UAT_STATE_CURSOR1, count);
    write64(state_pa + UAT_STATE_CURSOR2, 0);
    write64(state_pa + UAT_STATE_CURSOR3, count ? handoff_slot + 1 : 0);
    sptm_uat_publish_guard(state_pa, UAT_GUARD_PREPARE_UNMAP);
    return sptm_uat_prepare_unmap_continue(ctx, state_pa);
}

static bool sptm_uat_prepare_unmap_resume(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    if (!state_pa || !sptm_uat_acquire_guard(state_pa, UAT_GUARD_PREPARE_UNMAP))
        return false;
    return sptm_uat_prepare_unmap_continue(ctx, state_pa);
}

static bool sptm_uat_unmap_continue(struct exc_info *ctx, u64 state_pa)
{
    u64 segment_count = read64(state_pa + UAT_STATE_CURSOR0);
    u64 segment_index = read64(state_pa + UAT_STATE_CURSOR1);
    u64 page_index = read64(state_pa + UAT_STATE_CURSOR2);
    u64 phase = read64(state_pa + UAT_STATE_CURSOR3);
    u32 budget = min(sptm.uat_mapping_limit, SPTM_UAT_BATCH_PAGES);
    bool cleared = false;
    bool failed = false;

    if (phase > UAT_UNMAP_PHASE_RELEASE)
        return false;

    if (!segment_count) {
        sptm_uat_publish_guard(state_pa, UAT_GUARD_IDLE);
        ctx->regs[0] = 0;
        return true;
    }

    while (budget && segment_index < segment_count) {
        struct sptm_uat_segment *segment =
            (void *)(state_pa + UAT_STATE_UNMAP_SEGMENTS + segment_index * sizeof(*segment));
        if (page_index >= segment->count) {
            segment_index++;
            page_index = 0;
            continue;
        }

        u64 slot = sptm_uat_slot(state_pa, segment->first + page_index * SPTM_PAGE_SIZE, 3);
        if (!slot) {
            failed = true;
            break;
        }
        // Clear VALID/TYPE while retaining the leaf payload for handoff.
        u64 va = segment->first + page_index * SPTM_PAGE_SIZE;
        u64 descriptor = read64(slot);
        if (phase != UAT_UNMAP_PHASE_RELEASE && (descriptor & 3) != (UAT_DESC_VALID | BIT(1))) {
            printf("HV: SPTM UAT UNMAP_PAGE rejected leaf during phase %lu "
                   "state=0x%lx va=0x%lx descriptor=0x%lx\n",
                   phase, state_pa, va, descriptor);
            failed = true;
            break;
        }

        if (phase == UAT_UNMAP_PHASE_CLEAR) {
            sptm_uat_write_descriptor(slot, descriptor & ~3ULL);
            cleared = true;
        } else if (phase == UAT_UNMAP_PHASE_RELEASE) {
            sptm_uat_ref_page(descriptor | 3, -1);
        }
        page_index++;
        budget--;
    }

    // Invalidate each cleared chunk before releasing target references.
    if (cleared)
        sptm_uat_tlbi_all();

    if (failed)
        return false;

    write64(state_pa + UAT_STATE_CURSOR1, segment_index);
    write64(state_pa + UAT_STATE_CURSOR2, page_index);
    if (segment_index < segment_count) {
        sptm_uat_publish_guard(state_pa, UAT_GUARD_UNMAP);
        ctx->regs[0] = 1;
        return true;
    }

    if (phase == UAT_UNMAP_PHASE_VALIDATE) {
        phase = UAT_UNMAP_PHASE_CLEAR;
    } else if (phase == UAT_UNMAP_PHASE_CLEAR) {
        if (!sptm_uat_handoff_complete(state_pa))
            return false;
        phase = UAT_UNMAP_PHASE_RELEASE;
    } else {
        sptm_uat_publish_guard(state_pa, UAT_GUARD_IDLE);
        ctx->regs[0] = 0;
        return true;
    }

    write64(state_pa + UAT_STATE_CURSOR1, 0);
    write64(state_pa + UAT_STATE_CURSOR2, 0);
    write64(state_pa + UAT_STATE_CURSOR3, phase);
    sptm_uat_publish_guard(state_pa, UAT_GUARD_UNMAP);
    ctx->regs[0] = 1;
    return true;
}

static bool sptm_uat_unmap_begin(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    u64 segment_count = ctx->regs[2];
    if (!state_pa || segment_count > sptm.uat_segment_limit)
        return false;

    size_t size = segment_count * sizeof(struct sptm_uat_segment);
    u64 segments_pa = 0;
    if (size) {
        segments_pa = ctx->regs[1];
        if (!sptm_valid_pa(segments_pa, size) ||
            !sptm_uat_validate_unmap_segments(segments_pa, segment_count))
            return false;
    }
    if (!sptm_uat_acquire_begin(state_pa, UAT_GUARD_UNMAP))
        return false;

    if (size)
        memcpy((void *)(state_pa + UAT_STATE_UNMAP_SEGMENTS), (void *)segments_pa, size);
    write64(state_pa + UAT_STATE_CURSOR0, segment_count);
    write64(state_pa + UAT_STATE_CURSOR1, 0);
    write64(state_pa + UAT_STATE_CURSOR2, 0);
    write64(state_pa + UAT_STATE_CURSOR3, UAT_UNMAP_PHASE_VALIDATE);
    write64(state_pa + UAT_STATE_UNMAP_FLUSH_COUNT, 0);
    sptm_uat_publish_guard(state_pa, UAT_GUARD_UNMAP);
    return sptm_uat_unmap_continue(ctx, state_pa);
}

static bool sptm_uat_unmap_resume(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    if (!state_pa || !sptm_uat_acquire_guard(state_pa, UAT_GUARD_UNMAP))
        return false;
    return sptm_uat_unmap_continue(ctx, state_pa);
}

static bool sptm_uat_ttbr(u64 root, u16 context_id, u64 *ttbr)
{
    if (sptm_uat_sentinel(root)) {
        *ttbr = 0;
        return true;
    }
    root &= SPTM_DESC_PA_MASK_16K;
    if (!sptm_uat_valid_table(root))
        return false;
    *ttbr = root | ((u64)context_id << 48) | 1;
    return true;
}

static bool sptm_uat_set_context(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    u64 context_id = ctx->regs[1];
    if (!state_pa || context_id >= 64 || read16(state_pa + UAT_STATE_CONTEXT_ID) != UINT16_MAX)
        return false;

    u64 context = sptm.uat_gpu_contexts + context_id * 16;
    if ((read64(context) & 1) || (read64(context + 8) & 1))
        return false;

    u64 root0 = read64(state_pa + UAT_STATE_ROOT0);
    u64 root1 = read64(state_pa + UAT_STATE_ROOT1);
    u8 state_type = read8(state_pa);
    if (state_type == UAT_STATE_SINGLE_ROOT) {
        u64 global_state = sptm.uat_global_state;
        if (sptm.uat_mode != 0 || read8(global_state) != UAT_STATE_GLOBAL_MODE0)
            return false;
        root1 = read64(global_state + UAT_STATE_ROOT1);
    } else if (state_type != UAT_STATE_DUAL_ROOT) {
        return false;
    }

    u64 ttbr0, ttbr1;
    if (!sptm_uat_ttbr(root0, context_id, &ttbr0) || !sptm_uat_ttbr(root1, context_id, &ttbr1) ||
        !sptm_uat_acquire_guard(state_pa, UAT_GUARD_IDLE))
        return false;

    write64(context, ttbr0);
    write64(context + 8, ttbr1);
    sysop("dsb osh");
    write16(state_pa + UAT_STATE_CONTEXT_ID, context_id);
    sptm_uat_publish_guard(state_pa, UAT_GUARD_IDLE);
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static bool sptm_uat_remove_context(struct exc_info *ctx)
{
    u64 state_pa = sptm_uat_state_pa(ctx->regs[0]);
    if (!state_pa || !sptm_uat_acquire_guard(state_pa, UAT_GUARD_IDLE))
        return false;

    u16 context_id = read16(state_pa + UAT_STATE_CONTEXT_ID);
    if (context_id != UINT16_MAX) {
        if (context_id >= 64) {
            sptm_uat_publish_guard(state_pa, UAT_GUARD_IDLE);
            return false;
        }
        u64 context = sptm.uat_gpu_contexts + context_id * 16;
        write64(context, read64(context) & ~1ULL);
        write64(context + 8, read64(context + 8) & ~1ULL);
        sysop("dsb osh");
        u64 asid = (u64)context_id << 48;
        __asm__ volatile("sys #0, c8, c1, #2, %0" : : "r"(asid) : "memory");
        sysop("dsb osh");
        sysop("isb");
    }
    write16(state_pa + UAT_STATE_CONTEXT_ID, UINT16_MAX);
    sptm_uat_publish_guard(state_pa, UAT_GUARD_IDLE);
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static bool sptm_uat_get_info(struct exc_info *ctx)
{
    u64 selector = ctx->regs[0];
    u64 value = UINT64_MAX;
    switch (selector) {
        case 0:
            value = sptm.uat_mode;
            break;
        case 1:
            if (sptm.uat_mode == 0)
                value = sptm.uat_global_state;
            break;
        case 2:
            if (sptm.uat_mode == 1)
                value = sptm.uat_global_state;
            break;
        case 3:
            value = sptm.uat_va_width - 1;
            break;
        case 4:
            // Return the L1 bits in their original VA positions.
            value = (BIT(max((int)sptm.uat_va_width - 37, 0)) - 1) << 36;
            break;
        case 5:
            value = sptm.uat_segment_limit;
            break;
        case 6:
            value = 0;
            break;
        case 7:
            value = BIT(sptm.uat_va_width);
            break;
        case 8:
            value = sptm.uat_state_size;
            break;
        case 9:
            value = sptm.uat_shared_l2_va;
            break;
    }
    ctx->regs[0] = value;
    return true;
}

bool sptm_handle_uat(struct exc_info *ctx, u32 endpoint)
{
    bool handled = false;
    spin_lock(&sptm.service_lock);
    switch (endpoint) {
        case 0:
            handled = sptm_uat_init_state(ctx);
            break;
        case 1:
            handled = sptm_uat_destroy_state(ctx);
            break;
        case 2:
            handled = sptm_uat_map_table(ctx);
            break;
        case 3:
            handled = sptm_uat_unmap_table(ctx);
            break;
        case 4:
            handled = sptm_uat_map_begin(ctx);
            break;
        case 5:
            handled = sptm_uat_map_resume(ctx);
            break;
        case 6:
            handled = sptm_uat_prepare_unmap_begin(ctx);
            break;
        case 7:
            handled = sptm_uat_prepare_unmap_resume(ctx);
            break;
        case 8:
            handled = sptm_uat_unmap_begin(ctx);
            break;
        case 9:
            handled = sptm_uat_unmap_resume(ctx);
            break;
        case 10:
            handled = sptm_uat_set_context(ctx);
            break;
        case 11:
            handled = sptm_uat_remove_context(ctx);
            break;
        case 12:
            handled = sptm_uat_get_info(ctx);
            break;
    }
    spin_unlock(&sptm.service_lock);
    return handled;
}

void hv_sptm_configure_uat(u64 shared_l2_pa, u64 shared_l2_size, u64 info, u64 global_state,
                           u64 gpu_contexts, u64 shared_l2_va)
{
    u32 mode = info & 0xff;
    u32 va_width = (info >> 8) & 0xff;
    u32 segment_limit = (info >> 16) & 0xffff;
    u32 mapping_limit = (info >> 32) & 0xffff;
    bool tlbi_at_retype = info & BIT(48);
    u64 state_size = UAT_STATE_UNMAP_SEGMENTS + segment_limit * sizeof(struct sptm_uat_segment);
    u64 global_state_pa = sptm_pointer_pa(global_state, SPTM_PAGE_SIZE);
    u64 global_root_pa = global_state_pa
                             ? read64(global_state_pa + UAT_STATE_ROOT1) & SPTM_DESC_PA_MASK_16K
                             : 0;
    u8 *global_root_entry = sptm_frame_entry(global_root_pa);
    u64 global_root_va = global_root_pa
                             ? sptm.physmap_base + global_root_pa - sptm.managed_start
                             : 0;
    u64 global_root_slot = global_root_pa
                               ? sptm_walk(sptm.kernel_root, global_root_va, 3, NULL)
                               : 0;
    u64 global_root_descriptor = global_root_slot ? read64(global_root_slot) : 0;
    u64 shared_l2_slot = sptm_walk(sptm.kernel_root, shared_l2_va, 3, NULL);
    u64 shared_l2_descriptor = shared_l2_slot ? read64(shared_l2_slot) : 0;
    if (!sptm.enabled || (shared_l2_pa & SPTM_PAGE_MASK) || shared_l2_size != SPTM_PAGE_SIZE ||
        !sptm_valid_platform_pa(shared_l2_pa, shared_l2_size) || va_width < 37 || va_width > 48 ||
        mode > 1 || !segment_limit || !mapping_limit || info >> 49 || state_size > SPTM_PAGE_SIZE ||
        !global_state_pa || (gpu_contexts & (2 * sizeof(u64) - 1)) ||
        !sptm_valid_platform_pa(gpu_contexts, 64 * 2 * sizeof(u64)) ||
        read8(global_state_pa) != (mode ? UAT_STATE_GLOBAL_MODE1 : UAT_STATE_GLOBAL_MODE0) ||
        !sptm_valid_pa(global_root_pa, SPTM_PAGE_SIZE) || !global_root_entry ||
        global_root_entry[2] != SPTM_FRAME_XNU_IOMMU || !(global_root_descriptor & 1) ||
        (global_root_descriptor & SPTM_DESC_PA_MASK_16K) != global_root_pa ||
        (global_root_descriptor & ((7ULL << 2) | (3ULL << 8))) != PTE_MAIR_IDX(1) ||
        (shared_l2_va & SPTM_PAGE_MASK) || !(shared_l2_descriptor & 1) ||
        (shared_l2_descriptor & SPTM_DESC_PA_MASK_16K) != shared_l2_pa ||
        (shared_l2_descriptor & ((7ULL << 2) | (3ULL << 8))) != PTE_MAIR_IDX(1)) {
        printf("HV: refusing invalid SPTM UAT configuration\n");
        return;
    }

    // Boot-seeded UAT tables bypass RETYPE, so retire their WB aliases here.
    u64 host_pages[] = {global_root_pa, shared_l2_pa};
    mmu_map_ram_pages_nc(host_pages, ARRAY_SIZE(host_pages), true);

    sptm.uat_global_state = global_state_pa;
    sptm.uat_gpu_contexts = gpu_contexts;
    sptm.uat_shared_l2_pa = shared_l2_pa;
    sptm.uat_shared_l2_size = shared_l2_size;
    sptm.uat_shared_l2_va = shared_l2_va;
    sptm.uat_segment_limit = segment_limit;
    sptm.uat_mapping_limit = mapping_limit;
    sptm.uat_state_size = state_size;
    sptm.uat_va_width = va_width;
    sptm.uat_mode = mode;
    sptm.uat_tlbi_at_retype = tlbi_at_retype;
    sptm.uat_configured = true;
}

void hv_sptm_configure_uat_handoff(u64 handoff_pa, u64 handoff_size)
{
    if (!sptm.uat_configured || !handoff_pa || (handoff_pa & SPTM_PAGE_MASK) ||
        handoff_size < UAT_HANDOFF_MIN_SIZE || (handoff_size & SPTM_PAGE_MASK) ||
        !sptm_valid_platform_pa(handoff_pa, handoff_size)) {
        printf("HV: refusing invalid SPTM UAT handoff configuration "
               "0x%lx+0x%lx\n",
               handoff_pa, handoff_size);
        return;
    }

    sptm.uat_handoff_pa = handoff_pa;

    u64 handoff = sptm.uat_handoff_pa;
    // GFXHandoff still exposes CUR_CTX under its historical UNK name.
    write64(handoff + UAT_HANDOFF_MAGIC_AP, 0);
    write64(handoff + UAT_HANDOFF_MAGIC_FW, 0);
    write8(handoff + UAT_HANDOFF_LOCK_AP, 0);
    write8(handoff + UAT_HANDOFF_LOCK_FW, 0);
    write32(handoff + UAT_HANDOFF_TURN, 0);
    write32(handoff + UAT_HANDOFF_CURRENT_CTX, UINT32_MAX);
    memset(sptm.uat_handoff_pending, 0, sizeof(sptm.uat_handoff_pending));
    memset(sptm.uat_handoff_owner, 0, sizeof(sptm.uat_handoff_owner));
    for (u32 slot = 0; slot < UAT_HANDOFF_SLOT_COUNT; slot++) {
        u64 slot_addr = sptm_uat_handoff_slot_addr(slot);
        write64(slot_addr + UAT_HANDOFF_SLOT_STATE, 0);
        write64(slot_addr + UAT_HANDOFF_SLOT_ADDR, 0);
        write64(slot_addr + UAT_HANDOFF_SLOT_SIZE, 0);
    }
    write64(handoff + UAT_HANDOFF_UNK3, 0);
    sysop("dsb osh");
    write64(handoff + UAT_HANDOFF_MAGIC_AP, UAT_HANDOFF_MAGIC);
    sysop("dsb osh");
}
