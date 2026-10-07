/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

static void sptm_sart_read_entry(size_t index, u32 *flags, u64 *pa, u64 *size)
{
    *flags = read32(sptm.sart_base + index * sizeof(u32)) & 0xff;
    *pa = (u64)read32(sptm.sart_base + 0x40 + index * sizeof(u32)) << SPTM_SART_PAGE_SHIFT;
    u64 pages = read32(sptm.sart_base + 0x80 + index * sizeof(u32)) & 0x3fffffff;
    if (*flags && !sptm.sart_exclusive_bounds)
        pages++;
    *size = pages << SPTM_SART_PAGE_SHIFT;
}

static bool sptm_sart_map(struct exc_info *ctx)
{
    u64 pa = ctx->regs[0];
    u64 size = ctx->regs[1];
    u32 permission = ctx->regs[2];
    bool guard = ctx->regs[3];

    if (permission > 1 || !size || ((pa | size) & (SPTM_SART_PAGE_SIZE - 1)))
        return false;

    u64 pages = size >> SPTM_SART_PAGE_SHIFT;
    u64 encoded_pages = sptm.sart_exclusive_bounds ? pages : pages - 1;
    if (encoded_pages > 0x3fffffff || (pa >> SPTM_SART_PAGE_SHIFT) > UINT32_MAX)
        return false;

    spin_lock(&sptm.service_lock);
    size_t free_index = SPTM_SART_ENTRIES;
    for (size_t index = 0; index < SPTM_SART_ENTRIES; index++) {
        if ((sptm.sart_protected_mask & BIT(index)) ||
            (read32(sptm.sart_base + index * sizeof(u32)) & 0xff))
            continue;
        free_index = index;
        break;
    }

    if (free_index == SPTM_SART_ENTRIES) {
        printf("HV: SPTM SART has no free hardware entry "
               "(protected=0x%x guarded=0x%x)\n",
               sptm.sart_protected_mask, sptm.sart_guarded_mask);
        spin_unlock(&sptm.service_lock);
        return false;
    }

    if (!sptm_adjust_data_range(pa, size, permission != 0, 1)) {
        spin_unlock(&sptm.service_lock);
        return false;
    }

    if (guard) {
        if (!sptm.sart_guard_count && sptm.sart_canary)
            write32(sptm.sart_canary, 0xabfedeed);
        sptm.sart_guard_count++;
        sptm.sart_guarded_mask |= BIT(free_index);
    }

    write32(sptm.sart_base + 0x40 + free_index * sizeof(u32), pa >> SPTM_SART_PAGE_SHIFT);
    write32(sptm.sart_base + 0x80 + free_index * sizeof(u32), encoded_pages);
    write32(sptm.sart_base + free_index * sizeof(u32), permission ? 0xff : 0xea);
    sysop("dsb sy");
    spin_unlock(&sptm.service_lock);

    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static bool sptm_sart_unmap(struct exc_info *ctx)
{
    u64 pa = ctx->regs[0];
    u64 size = ctx->regs[1];

    spin_lock(&sptm.service_lock);
    size_t found = SPTM_SART_ENTRIES;
    u32 found_flags = 0;
    for (size_t index = 0; index < SPTM_SART_ENTRIES; index++) {
        u32 entry_flags;
        u64 entry_pa, entry_size;
        if (sptm.sart_protected_mask & BIT(index))
            continue;
        sptm_sart_read_entry(index, &entry_flags, &entry_pa, &entry_size);
        if (entry_flags && entry_pa == pa && entry_size == size) {
            found = index;
            found_flags = entry_flags;
            break;
        }
    }

    if (found == SPTM_SART_ENTRIES) {
        printf("HV: SPTM SART cannot unmap missing region 0x%lx+0x%lx\n", pa, size);
        spin_unlock(&sptm.service_lock);
        return false;
    }

    bool writable = found_flags == 0xff;
    if (!sptm_data_range_can_release(pa, size, writable)) {
        spin_unlock(&sptm.service_lock);
        return false;
    }

    if (sptm.sart_guarded_mask & BIT(found)) {
        if (!sptm.sart_guard_count ||
            (sptm.sart_canary && read32(sptm.sart_canary) != 0xabfedeed)) {
            spin_unlock(&sptm.service_lock);
            return false;
        }
        sptm.sart_guard_count--;
        sptm.sart_guarded_mask &= ~BIT(found);
    }

    write32(sptm.sart_base + found * sizeof(u32), 0);
    write32(sptm.sart_base + 0x80 + found * sizeof(u32), 0);
    write32(sptm.sart_base + 0x40 + found * sizeof(u32), 0);
    sysop("dsb sy");
    sptm_adjust_data_range(pa, size, writable, -1);
    sysop("dsb ishst");
    spin_unlock(&sptm.service_lock);

    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_handle_sart(struct exc_info *ctx, u32 endpoint)
{
    if (!sptm.sart_configured)
        return false;

    switch (endpoint) {
        case 0:
            if (ctx->regs[0] > 1)
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        case 1:
            return sptm_sart_map(ctx);
        case 2:
            return sptm_sart_unmap(ctx);
        default:
            __builtin_unreachable();
    }
}

void hv_sptm_configure_sart(u64 base, u64 canary, u64 info)
{
    if (!sptm.enabled || !base || (base & 3) || (canary & 3) || (info & ~0x1ffffULL)) {
        printf("HV: refusing invalid SPTM SART configuration\n");
        return;
    }

    sptm.sart_base = base;
    sptm.sart_canary = canary;
    sptm.sart_protected_mask = info;
    sptm.sart_exclusive_bounds = info & BIT(16);
    sptm.sart_configured = true;
}
