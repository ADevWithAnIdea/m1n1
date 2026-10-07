/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

struct sptm_dart *sptm_find_dart(u32 id)
{
    for (size_t index = 0; index < sptm.dart_count; index++) {
        if (sptm.darts[index].valid && sptm.darts[index].id == id)
            return &sptm.darts[index];
    }

    return NULL;
}

static bool sptm_dart_flush_sid(struct sptm_dart *dart, u32 sid)
{
    // TLB registers are inaccessible while the DART is powered down.
    if (!dart->powered) {
        return true;
    }

    sysop("dsb sy");
    for (size_t index = 0; index < dart->instance_count; index++) {
        u64 base = dart->instances[index];
        write32(base + DART_TLB_OP, DART_TLB_FLUSH_SID | sid);
        for (size_t retry = 0; retry < 10000; retry++) {
            if (!(read32(base + DART_TLB_OP) & DART_TLB_BUSY))
                break;
            if (retry == 9999) {
                printf("HV: SPTM DART %u SID %u TLB flush timed out at 0x%lx\n", dart->id, sid,
                       base);
                return false;
            }
        }
    }
    sysop("dsb sy");
    return true;
}

static bool sptm_dart_flush_range(struct sptm_dart *dart, u32 sid, u64 start, u64 end)
{
    if (!dart->powered) {
        return true;
    }

    if (!(dart->flags & SPTM_DART_FLUSH_BY_DVA) || !dart->hardware_flush_supported || start >= end)
        return sptm_dart_flush_sid(dart, sid);

    sysop("dsb sy");
    for (size_t index = 0; index < dart->instance_count; index++) {
        u64 base = dart->instances[index];
        write32(base + DART_TLB_START_DVA, start >> SPTM_PAGE_SHIFT);
        write32(base + DART_TLB_END_DVA, (end - 1) >> SPTM_PAGE_SHIFT);
        write32(base + DART_TLB_OP,
                DART_TLB_HARDWARE_FLUSH | DART_TLB_FLUSH_DVA | DART_TLB_FLUSH_SID | sid);
        for (size_t retry = 0; retry < 10000; retry++) {
            if (!(read32(base + DART_TLB_OP) & DART_TLB_BUSY))
                break;
            if (retry == 9999) {
                printf("HV: SPTM DART %u SID %u DVA flush timed out at 0x%lx\n", dart->id, sid,
                       base);
                return false;
            }
        }
    }
    sysop("dsb sy");
    return true;
}

bool sptm_dart_flush_all(struct sptm_dart *dart)
{
    if (!dart->powered) {
        return true;
    }

    sysop("dsb sy");
    for (size_t index = 0; index < dart->instance_count; index++) {
        u64 base = dart->instances[index];
        write32(base + DART_TLB_OP, DART_TLB_FLUSH_ALL);
        for (size_t retry = 0; retry < 10000; retry++) {
            if (!(read32(base + DART_TLB_OP) & DART_TLB_BUSY))
                break;
            if (retry == 9999)
                return false;
        }
    }
    sysop("dsb sy");
    return true;
}

struct sptm_dart_sid *sptm_dart_sid(const struct sptm_dart *dart, u32 sid)
{
    if (!dart->sid_states || sid >= dart->sid_count)
        return NULL;
    return (struct sptm_dart_sid *)(dart->sid_states + sid * sizeof(struct sptm_dart_sid));
}

bool sptm_dart_valid_table(const struct sptm_dart_sid *state, u64 pa, size_t size)
{
    if (sptm_valid_pa(pa, size)) {
        u64 start = pa & ~SPTM_PAGE_MASK;
        u64 end = ALIGN_UP(pa + size, SPTM_PAGE_SIZE);

        for (u64 page = start; page < end; page += SPTM_PAGE_SIZE) {
            u8 *entry = sptm_frame_entry(page);
            if (!entry || entry[2] != SPTM_FRAME_XNU_IOMMU)
                return false;
        }
        return true;
    }
    return state && state->pt_start < state->pt_end && pa >= state->pt_start &&
           pa < state->pt_end && size <= state->pt_end - pa;
}

static bool sptm_dart_validate_dva(const struct sptm_dart_sid *state, u64 dva, u64 size)
{
    if (!state)
        return false;
    if (!state->dva_size)
        return true;
    if (dva < state->dva_base)
        return false;

    u64 offset = dva - state->dva_base;
    return offset <= state->dva_size && size <= state->dva_size - offset;
}

/* Return 1 for a translating SID, 0 for an unused SID, and -1 for policy state. */
static int sptm_dart_root(const struct sptm_dart *dart, u32 sid, u64 *root, u32 *root_level)
{
    struct sptm_dart_sid *state = sptm_dart_sid(dart, sid);
    if (!state)
        return -1;
    if (!(state->flags & SPTM_DART_SID_KNOWN))
        return 0;
    if ((state->flags & (SPTM_DART_SID_POLICY | SPTM_DART_SID_EXCLAVE)) ||
        !(state->tcr & DART_TCR_TRANSLATE))
        return -1;

    *root_level = state->root_level;
    if (!state->root)
        return 0;
    if (!sptm_dart_valid_table(state, state->root, SPTM_PAGE_SIZE))
        return -1;
    *root = state->root;
    return 1;
}

// Access live DART tables only through the Normal-NC alias.
static u64 sptm_dart_desc_pa(u64 descriptor)
{
    return ((descriptor >> 10) & DART_PTE_OFFSET_MASK) << SPTM_PAGE_SHIFT;
}

static u64 sptm_dart_leaf(const struct sptm_dart_sid *state, u64 root, u32 root_level, u64 dva)
{
    static const u32 shifts[] = {36, 25};
    u64 table = root;

    for (u32 level = root_level; level < 2; level++) {
        u64 slot = table + (((dva >> shifts[level]) & 0x7ff) * sizeof(u64));
        if (!sptm_dart_valid_table(state, slot, sizeof(u64)))
            return 0;

        u64 descriptor = read64(sptm_iommu_table_va(slot));
        if (!(descriptor & DART_PTE_VALID))
            return 0;

        table = sptm_dart_desc_pa(descriptor);
        if (!sptm_dart_valid_table(state, table, SPTM_PAGE_SIZE))
            return 0;
    }

    return table;
}

static bool sptm_dart_map_table(struct exc_info *ctx)
{
    struct sptm_dart *dart = sptm_find_dart(ctx->regs[0]);
    u32 sid = ctx->regs[1];
    u64 dva = ctx->regs[2];
    u32 level = ctx->regs[3];
    u64 table_pa = ctx->regs[4];
    struct sptm_dart_sid *state;

    if (!dart || sid >= dart->sid_count || level > 2 || (table_pa & SPTM_PAGE_MASK))
        return false;
    state = sptm_dart_sid(dart, sid);
    if (!state || !(state->flags & SPTM_DART_SID_KNOWN) ||
        (state->flags & (SPTM_DART_SID_POLICY | SPTM_DART_SID_EXCLAVE)) ||
        !(state->tcr & DART_TCR_TRANSLATE) ||
        !sptm_dart_valid_table(state, table_pa, SPTM_PAGE_SIZE) || level < state->root_level ||
        !sptm_dart_validate_dva(state, dva, 1))
        return false;

    if (level == state->root_level) {
        if (state->root && state->root != table_pa)
            return false;

        u32 ttbr = ((table_pa >> 12) & 0xfffffffcULL) | DART_TTBR_VALID;
        if (dart->powered) {
            for (size_t index = 0; index < dart->instance_count; index++) {
                u64 base = dart->instances[index];
                if (read32(base + DART_REG_PROTECT) & BIT(0)) {
                    if (read32(base + DART_TTBR + sid * sizeof(u32)) != ttbr)
                        return false;
                } else {
                    write32(base + DART_TTBR + sid * sizeof(u32), ttbr);
                }
            }
        }
        state->root = table_pa;
        if (!sptm_dart_flush_sid(dart, sid))
            return false;
        ctx->regs[0] = SPTM_STATUS_SUCCESS;
        return true;
    }

    u64 root = 0;
    u32 root_level = 0;
    if (sptm_dart_root(dart, sid, &root, &root_level) != 1)
        return false;

    u64 parent = root;
    static const u32 shifts[] = {36, 25};
    for (u32 parent_level = root_level; parent_level < level; parent_level++) {
        u64 slot = parent + (((dva >> shifts[parent_level]) & 0x7ff) * sizeof(u64));
        if (!sptm_dart_valid_table(state, slot, sizeof(u64)))
            return false;

        if (parent_level == level - 1) {
            u64 old = read64(sptm_iommu_table_va(slot));
            u64 replacement =
                (((table_pa >> SPTM_PAGE_SHIFT) & DART_PTE_OFFSET_MASK) << 10) | DART_PTE_VALID;
            if ((old & DART_PTE_VALID) && old != replacement)
                return false;

            write64(sptm_iommu_table_va(slot), replacement);
            u64 span = BIT(shifts[parent_level]);
            u64 start = dva & ~(span - 1);
            if (!sptm_dart_flush_range(dart, sid, start, start + span))
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }

        u64 descriptor = read64(sptm_iommu_table_va(slot));
        if (!(descriptor & DART_PTE_VALID))
            return false;
        parent = sptm_dart_desc_pa(descriptor);
        if (!sptm_dart_valid_table(state, parent, SPTM_PAGE_SIZE))
            return false;
    }

    return false;
}

static bool sptm_dart_unmap_table(struct exc_info *ctx)
{
    struct sptm_dart *dart = sptm_find_dart(ctx->regs[0]);
    u32 sid = ctx->regs[1];
    u64 dva = ctx->regs[2];
    u32 level = ctx->regs[3];
    u64 root = 0;
    u32 root_level = 0;

    if (!dart || level > 2)
        return false;

    struct sptm_dart_sid *state = sptm_dart_sid(dart, sid);
    if (!state || !(state->flags & SPTM_DART_SID_KNOWN) ||
        (state->flags & (SPTM_DART_SID_POLICY | SPTM_DART_SID_EXCLAVE)) ||
        !(state->tcr & DART_TCR_TRANSLATE))
        return false;
    root_level = state->root_level;
    if (level < root_level || !state->root ||
        !sptm_dart_valid_table(state, state->root, SPTM_PAGE_SIZE) ||
        !sptm_dart_validate_dva(state, dva, 1))
        return false;
    root = state->root;

    if (level == root_level) {
        if (dart->powered) {
            for (size_t index = 0; index < dart->instance_count; index++) {
                u64 base = dart->instances[index];
                if (read32(base + DART_REG_PROTECT) & BIT(0)) {
                    if (read32(base + DART_TTBR + sid * sizeof(u32)))
                        return false;
                } else {
                    write32(base + DART_TTBR + sid * sizeof(u32), 0);
                }
            }
        }
        state->root = 0;
        if (!sptm_dart_flush_sid(dart, sid))
            return false;
        ctx->regs[0] = SPTM_STATUS_SUCCESS;
        return true;
    }

    static const u32 shifts[] = {36, 25};
    u64 parent = root;
    for (u32 parent_level = root_level; parent_level < level; parent_level++) {
        u64 slot = parent + (((dva >> shifts[parent_level]) & 0x7ff) * sizeof(u64));
        if (!sptm_dart_valid_table(state, slot, sizeof(u64)))
            return false;
        if (parent_level == level - 1) {
            if (!(read64(sptm_iommu_table_va(slot)) & DART_PTE_VALID))
                return false;
            write64(sptm_iommu_table_va(slot), 0);
            u64 span = BIT(shifts[parent_level]);
            u64 start = dva & ~(span - 1);
            if (!sptm_dart_flush_range(dart, sid, start, start + span))
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        u64 descriptor = read64(sptm_iommu_table_va(slot));
        if (!(descriptor & DART_PTE_VALID))
            return false;
        parent = sptm_dart_desc_pa(descriptor);
        if (!sptm_dart_valid_table(state, parent, SPTM_PAGE_SIZE))
            return false;
    }

    return false;
}

static bool sptm_dart_page_range(u64 dva, u64 size, u64 *start, u64 *end, size_t *count)
{
    if (!size) {
        *start = dva & ~SPTM_PAGE_MASK;
        *end = *start;
        *count = 0;
        return true;
    }

    if (dva > UINT64_MAX - size || dva + size > UINT64_MAX - SPTM_PAGE_MASK)
        return false;

    *start = dva & ~SPTM_PAGE_MASK;
    *end = (dva + size + SPTM_PAGE_MASK) & ~SPTM_PAGE_MASK;
    *count = (*end - *start) >> SPTM_PAGE_SHIFT;
    return *count <= SPTM_MAX_DART_PAGES;
}

static bool sptm_dart_map_pages(struct exc_info *ctx)
{
    struct sptm_dart *dart = sptm_find_dart(ctx->regs[0]);
    u32 sid = ctx->regs[1];
    u64 dva = ctx->regs[2];
    u64 size = ctx->regs[4];
    u64 options = ctx->regs[5];
    u64 root = 0, start, end;
    u32 root_level = 0;
    size_t count;
    struct sptm_dart_sid *state;

    if (!dart || (options & ~0xfULL) || !(state = sptm_dart_sid(dart, sid)) ||
        sptm_dart_root(dart, sid, &root, &root_level) != 1 ||
        !sptm_dart_validate_dva(state, dva, size) ||
        !sptm_dart_page_range(dva, size, &start, &end, &count))
        return false;

    if (!count) {
        ctx->regs[0] = SPTM_STATUS_SUCCESS;
        return true;
    }

    u64 targets = sptm_pointer_pa(ctx->regs[3], count * sizeof(u64));
    if (!targets)
        return false;

    bool changed = false;
    bool all_fresh = true;
    for (size_t index = 0; index < count; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 target = read64(targets + index * sizeof(u64));
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        if ((target & SPTM_PAGE_MASK) || !leaf)
            return false;

        u64 valid_start = max(dva, page_dva) - page_dva;
        u64 valid_end = min(dva + size, page_dva + SPTM_PAGE_SIZE) - page_dva;
        u64 sp_start = valid_start >> 2;
        u64 sp_end = (valid_end - 1) >> 2;
        bool force_wrprot = false;
        u8 *frame = sptm_frame_entry(target);
        if (frame && (dart->flags & SPTM_DART_RELAXED_RW)) {
            switch (frame[2]) {
                case 14:
                case 15:
                case 16:
                case SPTM_FRAME_COPROCESSOR_RO_IO:
                    force_wrprot = true;
                    break;
            }
        }
        u64 pte = ((sp_start & 0xfff) << 52) | ((sp_end & 0xfff) << 40) |
                  (((target >> SPTM_PAGE_SHIFT) & DART_PTE_OFFSET_MASK) << 10) |
                  (options & BIT(0) ? DART_PTE_RDPROT : 0) |
                  ((options & BIT(1)) || force_wrprot ? DART_PTE_WRPROT : 0) |
                  (options & BIT(2) ? DART_PTE_UNCACHABLE : 0) | DART_PTE_VALID;
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        u64 old = read64(sptm_iommu_table_va(slot));
        if (old & DART_PTE_VALID)
            all_fresh = false;
        if ((old & DART_PTE_VALID) && sptm_dart_desc_pa(old) != target) {
            if (!(options & BIT(3)) || !(old & DART_PTE_WRPROT))
                return false;
        }
        changed |= old != pte;
    }

    // Pin every replacement target before publishing the batch.
    size_t refs_prepared = 0;
    for (size_t index = 0; index < count; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 target = read64(targets + index * sizeof(u64));
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        u64 old = read64(sptm_iommu_table_va(slot));
        u64 old_target = (old & DART_PTE_VALID) ? sptm_dart_desc_pa(old) : 0;

        if (old_target == target) {
            refs_prepared = index + 1;
            continue;
        }
        if (!sptm_adjust_iommu_use(target, 1))
            goto rollback_dart_map_refs;
        if (old_target && !sptm_adjust_iommu_use(old_target, -1)) {
            sptm_adjust_iommu_use(target, -1);
            goto rollback_dart_map_refs;
        }
        refs_prepared = index + 1;
    }

    for (size_t index = 0; index < count; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 target = read64(targets + index * sizeof(u64));
        u64 valid_start = max(dva, page_dva) - page_dva;
        u64 valid_end = min(dva + size, page_dva + SPTM_PAGE_SIZE) - page_dva;
        u64 sp_start = valid_start >> 2;
        u64 sp_end = (valid_end - 1) >> 2;
        bool force_wrprot = false;
        u8 *frame = sptm_frame_entry(target);
        if (frame && (dart->flags & SPTM_DART_RELAXED_RW)) {
            u8 type = frame[2];
            force_wrprot |=
                type == 14 || type == 15 || type == 16 || type == SPTM_FRAME_COPROCESSOR_RO_IO;
        }
        u64 pte = ((sp_start & 0xfff) << 52) | ((sp_end & 0xfff) << 40) |
                  (((target >> SPTM_PAGE_SHIFT) & DART_PTE_OFFSET_MASK) << 10) |
                  (options & BIT(0) ? DART_PTE_RDPROT : 0) |
                  ((options & BIT(1)) || force_wrprot ? DART_PTE_WRPROT : 0) |
                  (options & BIT(2) ? DART_PTE_UNCACHABLE : 0) | DART_PTE_VALID;
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        write64(sptm_iommu_table_va(slot), pte);
    }
    sysop("dsb sy");
    bool skip_fresh = (dart->flags & SPTM_DART_AVOID_MAP_TLBI) && all_fresh;
    if (changed && !(options & BIT(3)) && !skip_fresh &&
        !sptm_dart_flush_range(dart, sid, start, end))
        return false;
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;

rollback_dart_map_refs:
    for (size_t index = 0; index < refs_prepared; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 target = read64(targets + index * sizeof(u64));
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        u64 old = read64(sptm_iommu_table_va(slot));
        u64 old_target = (old & DART_PTE_VALID) ? sptm_dart_desc_pa(old) : 0;
        if (old_target == target)
            continue;
        if (old_target)
            sptm_adjust_iommu_use(old_target, 1);
        sptm_adjust_iommu_use(target, -1);
    }
    return false;
}

static bool sptm_dart_unmap_pages(struct exc_info *ctx)
{
    struct sptm_dart *dart = sptm_find_dart(ctx->regs[0]);
    u32 sid = ctx->regs[1];
    u64 root = 0, start, end;
    u32 root_level = 0;
    size_t count;
    struct sptm_dart_sid *state;
    u64 dva = ctx->regs[2];
    u64 size = ctx->regs[3];
    u64 options = ctx->regs[4];

    if (!dart || (options & ~3ULL) ||
        ((options & BIT(0)) && !(dart->flags & SPTM_DART_ALLOW_PTE_REMAP)) ||
        !(state = sptm_dart_sid(dart, sid)) || sptm_dart_root(dart, sid, &root, &root_level) != 1 ||
        !sptm_dart_validate_dva(state, dva, size) ||
        !sptm_dart_page_range(dva, size, &start, &end, &count))
        return false;

    bool changed = false;
    for (size_t index = 0; index < count; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        if (!leaf)
            return false;
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        u64 old = read64(sptm_iommu_table_va(slot));
        if (!(old & DART_PTE_VALID)) {
            if (!(options & BIT(1)))
                return false;
            continue;
        }
        u8 *frame = sptm_frame_entry(sptm_dart_desc_pa(old));
        if (frame && frame[2] == SPTM_FRAME_TXM_SECURE_CHANNEL)
            return false;
        changed = true;
    }

    size_t refs_released = 0;
    for (size_t index = 0; index < count; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        u64 old = read64(sptm_iommu_table_va(slot));
        if (!(old & DART_PTE_VALID)) {
            refs_released = index + 1;
            continue;
        }
        u64 target = sptm_dart_desc_pa(old);
        if (!target || !sptm_adjust_iommu_use(target, -1))
            goto rollback_dart_unmap_refs;
        refs_released = index + 1;
    }

    for (size_t index = 0; index < count; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        write64(sptm_iommu_table_va(slot), 0);
    }
    sysop("dsb sy");
    if (changed && !sptm_dart_flush_range(dart, sid, start, end))
        return false;
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;

rollback_dart_unmap_refs:
    for (size_t index = 0; index < refs_released; index++) {
        u64 page_dva = start + index * SPTM_PAGE_SIZE;
        u64 leaf = sptm_dart_leaf(state, root, root_level, page_dva);
        u64 slot = leaf + (((page_dva >> SPTM_PAGE_SHIFT) & 0x7ff) * sizeof(u64));
        u64 old = read64(sptm_iommu_table_va(slot));
        if (!(old & DART_PTE_VALID))
            continue;
        u64 target = sptm_dart_desc_pa(old);
        if (target)
            sptm_adjust_iommu_use(target, 1);
    }
    return false;
}

static bool sptm_dart_set_stream(struct exc_info *ctx, bool enable)
{
    struct sptm_dart *dart = sptm_find_dart(ctx->regs[0]);
    u32 sid = ctx->regs[1];
    struct sptm_dart_sid *state;
    if (!dart || sid >= dart->sid_count)
        return false;
    state = sptm_dart_sid(dart, sid);
    if (!state || !(state->flags & SPTM_DART_SID_KNOWN) || (state->flags & SPTM_DART_SID_EXCLAVE))
        return false;
    if (!(state->tcr & DART_TCR_TRANSLATE)) {
        ctx->regs[0] = SPTM_STATUS_SUCCESS;
        return true;
    }

    if (!enable && (dart->flags & SPTM_DART_RETENTION)) {
        ctx->regs[0] = SPTM_STATUS_SUCCESS;
        return true;
    }

    u32 word = sid / 32;
    u32 bit = BIT(sid % 32);
    if (dart->powered) {
        u64 register_offset = enable ? DART_ENABLE_STREAMS : DART_DISABLE_STREAMS;
        for (size_t index = 0; index < dart->instance_count; index++) {
            u64 base = dart->instances[index];
            write32(base + register_offset + word * sizeof(u32), bit);
            if (enable)
                dart->active_streams[index][word] |= bit;
            else
                dart->active_streams[index][word] &= ~bit;
        }
    } else {
        /* Endpoint 5 will restore the deferred stream state after power-up. */
        if (dart->saved_valid) {
            for (size_t index = 0; index < dart->instance_count; index++) {
                if (enable)
                    dart->saved_streams[index][word] |= bit;
                else
                    dart->saved_streams[index][word] &= ~bit;
            }
        }
    }

    sysop("dsb sy");
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_handle_dart(struct exc_info *ctx, u32 endpoint)
{
    bool handled;
    spin_lock(&sptm.service_lock);
    switch (endpoint) {
        case 0: /* MAP_TABLE */
            handled = sptm_dart_map_table(ctx);
            break;
        case 1: /* UNMAP_TABLE */
            handled = sptm_dart_unmap_table(ctx);
            break;
        case 2: /* MAP_PAGE */
            handled = sptm_dart_map_pages(ctx);
            break;
        case 3: /* UNMAP_PAGE */
            handled = sptm_dart_unmap_pages(ctx);
            break;
        case 4: /* POWERDOWN */
            handled = sptm_dart_power(ctx, false);
            break;
        case 5: /* POWERUP */
            handled = sptm_dart_power(ctx, true);
            break;
        case 6: /* INIT */
            handled = sptm_dart_init(ctx);
            break;
        case 7: /* DISABLE_TRANSLATION */
            handled = sptm_dart_set_stream(ctx, false);
            break;
        case 8: /* ENABLE_TRANSLATION */
            handled = sptm_dart_set_stream(ctx, true);
            break;
        default:
            handled = sptm_dart_error_endpoint(ctx);
            break;
    }
    spin_unlock(&sptm.service_lock);
    return handled;
}

void hv_sptm_configure_dart(u64 info, u64 config, u64 instance0, u64 instance1, u64 instance2,
                            u64 instance3)
{
    u32 id = info;
    u32 sid_count = (info >> 32) & 0xffff;
    u32 instance_count = (info >> 48) & 0xff;
    u64 instances[] = {instance0, instance1, instance2, instance3};
    u64 config_pa = sptm_pointer_pa(config, sizeof(struct sptm_dart_config));
    struct sptm_dart_config dart_config;
    if (config_pa)
        memcpy(&dart_config, (void *)config_pa, sizeof(dart_config));
    else
        memset(&dart_config, 0, sizeof(dart_config));

    if (!sptm.enabled || !sid_count || sid_count > SPTM_MAX_DART_SIDS || !config_pa ||
        !sptm_pointer_pa(dart_config.sid_states, sid_count * sizeof(struct sptm_dart_sid)) ||
        dart_config.dapf_count > SPTM_MAX_DART_DAPF ||
        dart_config.clock_count > SPTM_MAX_DART_CLOCKS ||
        dart_config.tunable_count > SPTM_MAX_DART_TUNABLES ||
        (dart_config.dapf_count &&
         !sptm_pointer_pa(dart_config.dapf_entries,
                          dart_config.dapf_count * sizeof(struct sptm_dart_dapf))) ||
        (dart_config.clock_count &&
         !sptm_pointer_pa(dart_config.clock_entries, dart_config.clock_count * sizeof(u64))) ||
        (dart_config.tunable_count &&
         !sptm_pointer_pa(dart_config.tunable_entries,
                          dart_config.tunable_count * sizeof(struct sptm_dart_tunable))) ||
        !instance_count || instance_count > SPTM_MAX_DART_INSTANCES) {
        printf("HV: refusing invalid SPTM DART configuration 0x%lx\n", info);
        return;
    }

    for (size_t index = 0; index < instance_count; index++) {
        if (!instances[index] || (instances[index] & 3)) {
            printf("HV: refusing invalid SPTM DART %u instance 0x%lx\n", id, instances[index]);
            return;
        }
    }

    struct sptm_dart *dart = sptm_find_dart(id);
    if (!dart) {
        if (sptm.dart_count >= ARRAY_SIZE(sptm.darts)) {
            printf("HV: refusing excess SPTM DART %u\n", id);
            return;
        }
        dart = &sptm.darts[sptm.dart_count++];
    }

    memset(dart, 0, sizeof(*dart));
    dart->id = id;
    dart->sid_count = sid_count;
    dart->instance_count = instance_count;
    dart->sid_states =
        sptm_pointer_pa(dart_config.sid_states, sid_count * sizeof(struct sptm_dart_sid));
    dart->dapf_entries = dart_config.dapf_entries;
    dart->clock_entries = dart_config.clock_entries;
    dart->tunable_entries = dart_config.tunable_entries;
    dart->dapf_count = dart_config.dapf_count;
    dart->clock_count = dart_config.clock_count;
    dart->tunable_count = dart_config.tunable_count;
    dart->flags = dart_config.flags;
    if (dart->flags & ~(SPTM_DART_FLUSH_BY_DVA | SPTM_DART_AVOID_MAP_TLBI | SPTM_DART_RELAXED_RW |
                        SPTM_DART_RETENTION | SPTM_DART_ALLOW_PTE_REMAP | SPTM_DART_CLAMP_TLIMITS |
                        SPTM_DART_IGNORE_SECONDARY | SPTM_DART_UNGANG_SHARED_PS)) {
        printf("HV: refusing invalid SPTM DART %u flags 0x%x\n", id, dart->flags);
        memset(dart, 0, sizeof(*dart));
        return;
    }
    if (dart->clock_count) {
        u64 clocks_pa = sptm_pointer_pa(dart->clock_entries, dart->clock_count * sizeof(u64));
        for (size_t index = 0; index < dart->clock_count; index++) {
            u64 entry = read64(clocks_pa + index * sizeof(u64));
            if (entry & SPTM_DART_CLOCK_FLAGS || !sptm_dart_clock_address(entry)) {
                printf("HV: refusing inconsistent SPTM DART %u clock state\n", id);
                memset(dart, 0, sizeof(*dart));
                return;
            }
        }
    }
    for (u32 sid = 0; sid < sid_count; sid++) {
        struct sptm_dart_sid *state = sptm_dart_sid(dart, sid);
        if (state && (state->pt_start || state->pt_end)) {
            u64 size = state->pt_end - state->pt_start;
            if ((state->pt_start & SPTM_PAGE_MASK) ||
                (state->pt_end & SPTM_PAGE_MASK) || state->pt_end <= state->pt_start ||
                !sptm_valid_platform_pa(state->pt_start, size) ||
                (state->pt_start < sptm.managed_end &&
                 sptm.managed_start < state->pt_end) ||
                (state->root &&
                 (state->root < state->pt_start || state->root >= state->pt_end))) {
                printf("HV: refusing invalid SPTM DART %u SID %u page-table region "
                       "0x%lx..0x%lx root=0x%lx\n",
                       id, sid, state->pt_start, state->pt_end, state->root);
                memset(dart, 0, sizeof(*dart));
                return;
            }

            // Firmware tables bypass RETYPE, so retire their WB aliases here.
            for (u64 page = state->pt_start; page < state->pt_end;
                 page += SPTM_PAGE_SIZE) {
                u64 host_page = page;
                mmu_map_ram_pages_nc(&host_page, 1, true);
            }
        }
        if (state && (state->flags & SPTM_DART_SID_ENABLED))
            dart->boot_streams[sid / 32] |= BIT(sid % 32);
    }
    for (size_t index = 0; index < instance_count; index++)
        memcpy(dart->active_streams[index], dart->boot_streams, sizeof(dart->boot_streams));
    dart->valid = true;
    memcpy(dart->instances, instances, instance_count * sizeof(u64));
}
