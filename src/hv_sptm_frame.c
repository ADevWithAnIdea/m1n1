/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

bool sptm_is_table_type(u8 type)
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
        case SPTM_FRAME_SUBPAGE:
            return true;
        default:
            return false;
    }
}

bool sptm_is_root_type(u8 type)
{
    switch (type) {
        case SPTM_FRAME_KERNEL_ROOT:
        case SPTM_FRAME_USER_ROOT:
        case SPTM_FRAME_SHARED_ROOT:
        case SPTM_FRAME_XNU_ROOT:
        case SPTM_FRAME_STAGE2_ROOT:
        case SPTM_FRAME_SUBPAGE:
            return true;
        default:
            return false;
    }
}

u8 *sptm_frame_entry(u64 pa)
{
    if (!sptm.frame_table_pa || (pa & SPTM_PAGE_MASK) || !sptm_valid_pa(pa, SPTM_PAGE_SIZE))
        return NULL;

    u64 index = (pa - sptm.managed_start) >> SPTM_PAGE_SHIFT;
    return (u8 *)(sptm.frame_table_pa + index * 16);
}

u32 *sptm_external_ref_entry(u64 pa)
{
    if (!sptm.external_ref_table_pa || (pa & SPTM_PAGE_MASK) || !sptm_valid_pa(pa, SPTM_PAGE_SIZE))
        return NULL;

    u64 index = (pa - sptm.managed_start) >> SPTM_PAGE_SHIFT;
    return (u32 *)(sptm.external_ref_table_pa + index * (2 * sizeof(u32)));
}

static bool sptm_adjust_frame_u16(u8 *entry, size_t offset, int delta)
{
    if (!entry)
        return false;

    spin_lock(&sptm.frame_lock);
    u16 value = read16((u64)entry + offset);
    if ((delta < 0 && value < (u16)-delta) || (delta > 0 && value > UINT16_MAX - (u16)delta)) {
        spin_unlock(&sptm.frame_lock);
        return false;
    }
    write16((u64)entry + offset, value + delta);
    spin_unlock(&sptm.frame_lock);
    return true;
}

bool sptm_adjust_data_ref(u64 pa, bool writable, int delta)
{
    u8 *entry = sptm_frame_entry(pa & ~SPTM_PAGE_MASK);
    if (!entry)
        return true; /* MMIO and unmanaged carveouts have no frame entry. */
    u32 *external = sptm_external_ref_entry(pa & ~SPTM_PAGE_MASK);

    // Data refcounts are only valid in ordinary frame bodies.
    spin_lock(&sptm.frame_lock);
    if (sptm_is_table_type(entry[2]) || entry[2] == SPTM_FRAME_XNU_IOMMU ||
        (delta > 0 && entry[2] == SPTM_FRAME_KERNEL_RESTRICTED)) {
        spin_unlock(&sptm.frame_lock);
        return false;
    }

    size_t offset = writable ? 12 : 8;
    size_t external_index = writable ? 1 : 0;
    u32 value = read32((u64)entry + offset);
    u32 reserved = external[external_index];
    if (value < reserved || (delta < 0 && value < (u32)-delta) ||
        (delta < 0 && reserved < (u32)-delta) || (delta > 0 && value > UINT32_MAX - (u32)delta) ||
        (delta > 0 && reserved > UINT32_MAX - (u32)delta)) {
        spin_unlock(&sptm.frame_lock);
        return false;
    }
    write32((u64)entry + offset, value + delta);
    external[external_index] = reserved + delta;
    spin_unlock(&sptm.frame_lock);
    return true;
}

static bool sptm_data_ref_can_release(u64 pa, bool writable)
{
    u8 *entry = sptm_frame_entry(pa & ~SPTM_PAGE_MASK);
    if (!entry)
        return true;
    u32 *external = sptm_external_ref_entry(pa & ~SPTM_PAGE_MASK);

    spin_lock(&sptm.frame_lock);
    size_t offset = writable ? 12 : 8;
    size_t external_index = writable ? 1 : 0;
    bool allowed = !sptm_is_table_type(entry[2]) && entry[2] != SPTM_FRAME_XNU_IOMMU &&
                   read32((u64)entry + offset) >= external[external_index] &&
                   read32((u64)entry + offset) >= 1 && external[external_index] >= 1;
    spin_unlock(&sptm.frame_lock);
    return allowed;
}

bool sptm_data_range_can_release(u64 pa, u64 size, bool writable)
{
    if (!size || pa > UINT64_MAX - size || pa + size > UINT64_MAX - SPTM_PAGE_MASK)
        return false;

    u64 start = pa & ~SPTM_PAGE_MASK;
    u64 end = ALIGN_UP(pa + size, SPTM_PAGE_SIZE);
    for (u64 frame = start; frame < end; frame += SPTM_PAGE_SIZE) {
        if (!sptm_data_ref_can_release(frame, writable))
            return false;
    }
    return true;
}

bool sptm_adjust_data_range(u64 pa, u64 size, bool writable, int delta)
{
    if (!size || pa > UINT64_MAX - size || pa + size > UINT64_MAX - SPTM_PAGE_MASK)
        return false;

    u64 start = pa & ~SPTM_PAGE_MASK;
    u64 end = ALIGN_UP(pa + size, SPTM_PAGE_SIZE);
    u64 frame = start;
    for (; frame < end; frame += SPTM_PAGE_SIZE) {
        if (sptm_adjust_data_ref(frame, writable, delta))
            continue;
        for (u64 rollback = start; rollback < frame; rollback += SPTM_PAGE_SIZE)
            sptm_adjust_data_ref(rollback, writable, -delta);
        return false;
    }
    return true;
}

bool sptm_adjust_iommu_use(u64 pa, int delta)
{
    u8 *entry = sptm_frame_entry(pa & ~SPTM_PAGE_MASK);
    if (!entry)
        return true; /* MMIO and unmanaged carveouts have no frame entry. */

    if (delta > 0 && entry[2] == SPTM_FRAME_KERNEL_RESTRICTED)
        return false;
    return sptm_adjust_frame_u16(entry, 0, delta);
}

bool sptm_adjust_table_valid(u64 slot, int delta)
{
    u8 *entry = sptm_frame_entry(slot & ~SPTM_PAGE_MASK);
    if (!entry || !sptm_is_table_type(entry[2]))
        return false;
    return sptm_adjust_frame_u16(entry, 8, delta);
}

bool sptm_adjust_parent_links(u64 child, int delta)
{
    u8 *entry = sptm_frame_entry(child & ~SPTM_PAGE_MASK);
    if (!entry || !sptm_is_table_type(entry[2]))
        return false;
    return sptm_adjust_frame_u16(entry, 6, delta);
}

bool sptm_adjust_mapping_ref(u64 pte, u64 descriptor_mask, int delta)
{
    if (!(pte & 1))
        return true;

    u64 pa = (pte & descriptor_mask) & ~SPTM_PAGE_MASK;
    u8 *entry = sptm_frame_entry(pa);
    if (!entry)
        return true; /* MMIO and unmanaged carveouts have no frame entry. */

    u32 *external = sptm_external_ref_entry(pa);

    // Track all CPU mappings in ro_refcount; DMA reservations remain external.
    spin_lock(&sptm.frame_lock);
    u32 value = read32((u64)entry + 8);
    u32 total_ro = read32((u64)entry + 8);
    u32 total_wx = read32((u64)entry + 12);
    if (total_ro < external[0] || total_wx < external[1]) {
        spin_unlock(&sptm.frame_lock);
        return false;
    }

    if ((delta < 0 && value - external[0] < (u32)-delta) ||
        (delta > 0 && value > UINT32_MAX - (u32)delta)) {
        spin_unlock(&sptm.frame_lock);
        return false;
    }
    write32((u64)entry + 8, value + delta);
    spin_unlock(&sptm.frame_lock);
    return true;
}

void hv_sptm_configure_frames(u64 frame_table_pa)
{
    u64 managed_pages = (sptm.managed_end - sptm.managed_start) >> SPTM_PAGE_SHIFT;
    if (!sptm.enabled) {
        printf("HV: refusing invalid SPTM frame-table configuration\n");
        return;
    }

    size_t frame_table_size = managed_pages * 16;
    size_t external_ref_table_size = managed_pages * 2 * sizeof(u32);
    size_t combined_size = frame_table_size + external_ref_table_size;
    if (!sptm_valid_pa(frame_table_pa, combined_size)) {
        printf("HV: refusing invalid SPTM frame/reference tables "
               "0x%lx+0x%lx\n",
               frame_table_pa, combined_size);
        return;
    }

    sptm.frame_table_pa = frame_table_pa;
    sptm.external_ref_table_pa = frame_table_pa + frame_table_size;
    memset((void *)sptm.external_ref_table_pa, 0, external_ref_table_size);
    sysop("dsb ishst");
}
