/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

struct sptm_surt_root *sptm_find_surt_root(u64 root)
{
    for (size_t index = 0; index < ARRAY_SIZE(sptm.surt_roots); index++) {
        struct sptm_surt_root *candidate = &sptm.surt_roots[index];
        if (candidate->valid && candidate->root == root)
            return candidate;
    }

    return NULL;
}

static void sptm_set_geometry(u8 attr_index, struct sptm_geometry *geometry)
{
    if (attr_index == 1 || attr_index == 5) {
        geometry->descriptor_mask = 0x0000fffffffff000ULL;
        geometry->entries_mask = 0x1ff;
        geometry->page_shift = 12;
        geometry->start_level = 0;
        geometry->page_ratio = SPTM_PAGE_SIZE >> 12;
    } else {
        geometry->descriptor_mask = SPTM_DESC_PA_MASK_16K;
        geometry->entries_mask = 0x7ff;
        geometry->page_shift = 14;
        geometry->start_level = 1;
        geometry->page_ratio = 1;
    }
}

static bool sptm_root_geometry(u64 root, struct sptm_geometry *geometry)
{
    struct sptm_surt_root *surt = sptm_find_surt_root(root);
    if (surt) {
        sptm_set_geometry(surt->attr_index, geometry);
        return true;
    }

    if (root & SPTM_PAGE_MASK)
        return false;

    u8 *entry = sptm_frame_entry(root);
    if (!entry || !sptm_is_root_type(entry[2]))
        return false;

    sptm_set_geometry(entry[12], geometry);
    return true;
}

u64 sptm_walk(u64 root, u64 va, unsigned int target_level, struct sptm_geometry *geometry_out)
{
    static const unsigned int shifts_16k[] = {0, 36, 25, 14};
    static const unsigned int shifts_4k[] = {39, 30, 21, 12};
    struct sptm_geometry geometry;
    u64 table = root;

    if (!sptm_root_geometry(root, &geometry) || target_level < geometry.start_level ||
        target_level > 3)
        return 0;

    const unsigned int *shifts = geometry.page_shift == 12 ? shifts_4k : shifts_16k;

    for (unsigned int level = geometry.start_level; level < target_level; level++) {
        u64 slot = table + (((va >> shifts[level]) & geometry.entries_mask) * sizeof(u64));
        if (!sptm_valid_pa(slot, sizeof(u64)))
            return 0;

        u64 descriptor = read64(slot);
        // Do not descend into a condemned table.
        if (!(descriptor & 1) || (descriptor & BIT(2)))
            return 0;
        table = descriptor & geometry.descriptor_mask;
    }

    u64 slot = table + (((va >> shifts[target_level]) & geometry.entries_mask) * sizeof(u64));
    if (!sptm_valid_pa(slot, sizeof(u64)))
        return 0;

    if (geometry_out)
        *geometry_out = geometry;
    return slot;
}

static void sptm_cancel_host_rt_restore(u64 pa)
{
    for (size_t index = 0; index < sptm.host_rt_restore_count; index++) {
        if (sptm.host_rt_restore_pages[index] != pa)
            continue;

        sptm.host_rt_restore_count--;
        sptm.host_rt_restore_pages[index] =
            sptm.host_rt_restore_pages[sptm.host_rt_restore_count];
        return;
    }
}

static void sptm_queue_host_rt_restore(u64 pa)
{
    for (size_t index = 0; index < sptm.host_rt_restore_count; index++) {
        if (sptm.host_rt_restore_pages[index] == pa)
            return;
    }

    // Queue overflow leaves the page safely protected.
    if (sptm.host_rt_restore_count < ARRAY_SIZE(sptm.host_rt_restore_pages))
        sptm.host_rt_restore_pages[sptm.host_rt_restore_count++] = pa;
}

static void sptm_flush_stage1_tlb(void)
{
    // Publish page-table writes before invalidating guest translations.
    sysop("dsb sy");
    sysop("tlbi vmalle1is");
    sysop("dsb ish");
    sysop("isb");
}

void sptm_publish_stage1(void)
{
    sptm_flush_stage1_tlb();

    // Restore WB aliases only after stale RT translations are gone.
    if (sptm.host_rt_restore_count) {
        mmu_restore_ram_pages_wb(sptm.host_rt_restore_pages,
                                 sptm.host_rt_restore_count, false);
        sptm.host_rt_restore_count = 0;
    }
}

static void sptm_write_stage1_descriptor(u64 slot, u64 value)
{
    write64(slot, value);
}

void sptm_publish_commpage_policy(void)
{
    if (sptm.commpage_policy_published)
        return;

    if (sptm.amx_version_pa && sptm.cpu_capabilities_pa) {
        u64 version = read64(sptm.amx_version_pa);
        u64 capabilities = read64(sptm.cpu_capabilities_pa);
        u64 replacement = capabilities & ~SPTM_HW_CAP_AMX_VERSION_MASK;

        write64(sptm.amx_version_pa, 0);
        write64(sptm.cpu_capabilities_pa, replacement);
        printf("HV: SPTM disabled XNU AMX policy (version 0x%lx -> 0, "
               "caps 0x%lx -> 0x%lx)\n",
               version, capabilities, replacement);
    }

    for (size_t index = 0; index < sptm.commpage_rw_count; index++) {
        u64 pa = sptm.commpage_rw[index];
        u64 caps = read64(pa + SPTM_COMMPAGE_CPU_CAPS64_OFFSET);
        u64 replacement = caps & SPTM_CPU_CAP_PRE_AMX_MASK;
        write64(pa + SPTM_COMMPAGE_CPU_CAPS64_OFFSET, replacement);
        write8(pa + SPTM_COMMPAGE_USER_TIMEBASE_OFFSET, 0);
        write8(pa + SPTM_COMMPAGE_CONT_HWCLOCK_OFFSET, 0);
        write8(pa + SPTM_COMMPAGE_HW_TPRO_OFFSET, 0);
        printf("HV: SPTM hid XNU AMX commpage policy at PA 0x%lx "
               "(caps 0x%lx -> 0x%lx)\n",
               pa, caps, replacement);
    }
    sysop("dsb sy");
    sptm.commpage_policy_published = true;
}

bool sptm_retype_frame(struct exc_info *ctx)
{
    u64 pa = ctx->regs[0] & ~SPTM_PAGE_MASK;
    u8 new_type = ctx->regs[2];

    u8 *entry = sptm_frame_entry(pa);
    if (!entry)
        return false;

    spin_lock(&sptm.frame_lock);
    u8 old_type = entry[2];
    u16 in_use = read16((u64)entry);
    u32 ro_refcount = read32((u64)entry + 8);
    u32 wx_refcount = read32((u64)entry + 12);
    u32 *external = sptm_external_ref_entry(pa);
    u32 external_ro = external[0];
    u32 external_wx = external[1];
    if (new_type != old_type && (in_use || external_ro || external_wx)) {
        printf("HV: SPTM refusing RETYPE of externally referenced frame "
               "pa=0x%lx %u->%u in-use=%u ro=%u/%u wx=%u/%u\n",
               pa, old_type, new_type, in_use, ro_refcount, external_ro, wx_refcount, external_wx);
        spin_unlock(&sptm.frame_lock);
        return false;
    }
    if (old_type == SPTM_FRAME_XNU_IOMMU && new_type != SPTM_FRAME_XNU_IOMMU &&
        read16((u64)entry + 4)) {
        printf("HV: SPTM refusing RETYPE of pinned UAT frame "
               "pa=0x%lx refs=%u new-type=%u\n",
               pa, read16((u64)entry + 4), new_type);
        spin_unlock(&sptm.frame_lock);
        return false;
    }
    bool entering_iommu = old_type != SPTM_FRAME_XNU_IOMMU &&
                          new_type == SPTM_FRAME_XNU_IOMMU;
    bool leaving_iommu = old_type == SPTM_FRAME_XNU_IOMMU &&
                         new_type != SPTM_FRAME_XNU_IOMMU;
    bool iommu_transition = entering_iommu || leaving_iommu;
    u64 physmap_slot = 0;
    u64 physmap_replacement = 0;

    if (iommu_transition) {
        u64 physmap_va = sptm.physmap_base + pa - sptm.managed_start;
        physmap_slot = sptm_walk(sptm.kernel_root, physmap_va, 3, NULL);
        u64 descriptor = physmap_slot ? read64(physmap_slot) : 0;
        u64 type_mask = (7ULL << 2) | (3ULL << 8);
        u64 expected = entering_iommu ? PTE_MAIR_IDX(MAIR_IDX_NORMAL) | PTE_SH_OS
                                     : PTE_MAIR_IDX(MAIR_IDX_NORMAL_NC) | PTE_SH_NS;
        u64 replacement = entering_iommu ? PTE_MAIR_IDX(MAIR_IDX_NORMAL_NC) | PTE_SH_NS
                                         : PTE_MAIR_IDX(MAIR_IDX_NORMAL) | PTE_SH_OS;

        if (!physmap_slot || !(descriptor & 1) ||
            (descriptor & SPTM_DESC_PA_MASK_16K) != pa ||
            (descriptor & type_mask) != expected) {
            printf("HV: SPTM refusing IOMMU RETYPE with unexpected physmap alias "
                   "pa=0x%lx descriptor=0x%lx expected-type=0x%lx\n",
                   pa, descriptor, expected);
            spin_unlock(&sptm.frame_lock);
            return false;
        }
        physmap_replacement = (descriptor & ~type_mask) | replacement;
    }

    if (iommu_transition) {
        // Keep the physmap leaf invalid during the host memory-type transition.
        sptm_write_stage1_descriptor(physmap_slot, 0);
        sptm_flush_stage1_tlb();
    }

    // Remove WB aliases to avoid speculative accesses to them
    if (entering_iommu) {
        u64 host_page = pa;
        mmu_map_ram_pages_nc(&host_page, 1, true);
    }

    if (sptm_is_table_type(old_type))
        write16((u64)entry + 8, 0);
    entry[2] = new_type;

    if (sptm_is_table_type(new_type) || new_type == SPTM_FRAME_XNU_IOMMU) {
        void *table_va;
        if (new_type == SPTM_FRAME_XNU_IOMMU) {
            // Zero IOMMU tables through their NC alias.
            table_va = (void *)sptm_iommu_table_va(pa);
        } else {
            table_va = (void *)pa;
        }
        memset(table_va, 0, SPTM_PAGE_SIZE);
        if (new_type == SPTM_FRAME_XNU_IOMMU)
            sysop("dsb sy");
        write16((u64)entry + 6, 0);
        write16((u64)entry + 8, 0);
        if (new_type == SPTM_FRAME_XNU_IOMMU)
            write16((u64)entry + 4, 0);

        if (sptm_is_root_type(new_type)) {
            write16((u64)entry + 10, (ctx->regs[3] >> 32) & 0xffff);
            entry[12] = ctx->regs[3] & 0xff;
        }
    }

    // Defer commpage policy changes until the shared region is configured.
    if (new_type == SPTM_FRAME_XNU_COMMPAGE_RW &&
        sptm.commpage_rw_count < ARRAY_SIZE(sptm.commpage_rw)) {
        sptm.commpage_rw[sptm.commpage_rw_count++] = pa;
    }

    spin_unlock(&sptm.frame_lock);
    if (sptm_is_table_type(old_type) || sptm_is_table_type(new_type) || iommu_transition ||
        new_type == SPTM_FRAME_XNU_IOMMU || new_type == SPTM_FRAME_XNU_IO ||
        new_type == SPTM_FRAME_PROTECTED_IO || new_type == SPTM_FRAME_COPROCESSOR_RO_IO ||
        new_type == SPTM_FRAME_RESTRICTED_IO || new_type == SPTM_FRAME_RESTRICTED_IO_TELEMETRY ||
        new_type == SPTM_FRAME_SK_IO)
        sptm_publish_stage1();
    else
        sysop("dsb ishst");
    if (iommu_transition && sptm.uat_configured && sptm.uat_tlbi_at_retype)
        sptm_uat_tlbi_all();

    // Restore WB aliases only after guest and IOMMU invalidation.
    if (leaving_iommu) {
        u64 host_page = pa;
        mmu_restore_ram_pages_wb(&host_page, 1, true);
    }
    if (iommu_transition) {
        sptm_write_stage1_descriptor(physmap_slot, physmap_replacement);
        sptm_publish_stage1();
    }
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_configure_shared_region(struct exc_info *ctx)
{
    u64 pa = ctx->regs[0] & ~SPTM_PAGE_MASK;
    u8 *entry = sptm_frame_entry(pa);
    if (!entry)
        return false;

    entry[2] = SPTM_FRAME_SHARED_ROOT;
    write16((u64)entry + 10, 0);
    entry[12] = 0;
    sysop("dsb ishst");
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_map_page(struct exc_info *ctx)
{
    u64 root = ctx->regs[0];
    u64 va = ctx->regs[1];
    u64 pte = ctx->regs[2];
    struct sptm_geometry geometry;
    if (!sptm_root_geometry(root, &geometry))
        return false;
    u64 slot = sptm_walk(root, va, 3, NULL);
    if (!slot) {
        ctx->regs[0] = SPTM_STATUS_TABLE_NOT_PRESENT;
        return true;
    }

    u64 old = read64(slot);
    u64 scratch = sptm_scratch_pa(ctx);
    if (!sptm_valid_pa(scratch, 2 * sizeof(u64)))
        return false;

    write64(scratch, old);
    write64(scratch + sizeof(u64), sptm.physmap_base + slot - sptm.managed_start);

    if ((old & 1) && ((old & geometry.descriptor_mask) != (pte & geometry.descriptor_mask))) {
        sysop("dsb sy");
        ctx->regs[0] = SPTM_STATUS_MAP_PADDR_CONFLICT;
        return true;
    }

    bool fresh = !(old & 1) && (pte & 1);
    if (fresh) {
        if (!sptm_adjust_mapping_ref(pte, geometry.descriptor_mask, 1))
            return false;
        if (!sptm_adjust_table_valid(slot, 1)) {
            sptm_adjust_mapping_ref(pte, geometry.descriptor_mask, -1);
            return false;
        }
    }

    ctx->regs[0] = old & 1 ? SPTM_STATUS_MAP_VALID : SPTM_STATUS_SUCCESS;
    sptm_write_stage1_descriptor(slot, pte);

    if ((old & 1) && old != pte)
        sptm_publish_stage1();
    else
        sysop("dsb sy");

    return true;
}

bool sptm_map_table(struct exc_info *ctx)
{
    u64 root = ctx->regs[0];
    u64 va = ctx->regs[1];
    unsigned int target_level = ctx->regs[2];
    u64 tte = ctx->regs[3];

    struct sptm_geometry geometry;
    if (!sptm_root_geometry(root, &geometry))
        return false;

    u64 slot = sptm_walk(root, va, target_level, NULL);
    if (!slot) {
        ctx->regs[0] = SPTM_STATUS_TABLE_NOT_PRESENT;
        return true;
    }

    slot &= ~(geometry.page_ratio * sizeof(u64) - 1);
    for (size_t index = 0; index < geometry.page_ratio; index++) {
        if (read64(slot + index * sizeof(u64)) & 1) {
            ctx->regs[0] = SPTM_STATUS_TABLE_PRESENT;
            return true;
        }
    }

    u64 child = tte & geometry.descriptor_mask;
    u64 attrs = tte & ~geometry.descriptor_mask;
    if (!sptm_adjust_parent_links(child, 1))
        return false;
    for (size_t index = 0; index < geometry.page_ratio; index++) {
        u64 entry = slot + index * sizeof(u64);
        u64 replacement =
            ((child + index * BIT(geometry.page_shift)) & geometry.descriptor_mask) | attrs;
        sptm_write_stage1_descriptor(entry, replacement);
    }
    sysop("dsb sy");
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_unmap_table(struct exc_info *ctx)
{
    u64 root = ctx->regs[0];
    u64 va = ctx->regs[1];
    unsigned int target_level = ctx->regs[2];

    struct sptm_geometry geometry;
    u64 slot = sptm_walk(root, va, target_level, &geometry);
    if (!slot)
        return false;

    slot &= ~(geometry.page_ratio * sizeof(u64) - 1);
    for (size_t index = 0; index < geometry.page_ratio; index++) {
        u64 entry = slot + index * sizeof(u64);
        if (!(read64(entry) & 1)) {
            printf("HV: SPTM UNMAP_TABLE missing root=0x%lx va=0x%lx "
                   "level=%u slot=0x%lx descriptor=0x%lx cpu=%u "
                   "caller=0x%lx\n",
                   root, va, target_level, entry, read64(entry), (unsigned int)ctx->cpu_id,
                   ctx->elr);
            return false;
        }
    }

    u64 child = read64(slot) & geometry.descriptor_mask;
    if (!sptm_adjust_parent_links(child, -1))
        return false;
    for (size_t index = 0; index < geometry.page_ratio; index++) {
        u64 entry = slot + index * sizeof(u64);
        sptm_write_stage1_descriptor(entry, 0);
    }
    sptm_publish_stage1();
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

static u64 sptm_update_mask(u64 flags)
{
    u64 mask = 0;

    if (flags & BIT(0))
        mask |= BIT(58);
    if (flags & BIT(1))
        mask |= (3ULL << 6) | BIT(53) | BIT(54) | BIT(59);
    if (flags & BIT(2))
        mask |= BIT(11);
    if (flags & BIT(3))
        mask |= BIT(10);
    if (flags & BIT(4))
        mask |= 3ULL << 8;
    if (flags & BIT(5))
        mask |= 7ULL << 2;

    return mask;
}

bool sptm_update_region(struct exc_info *ctx)
{
    u64 root = ctx->regs[0];
    u64 start = ctx->regs[1];
    size_t count = ctx->regs[2];
    u64 flags = ctx->regs[4];

    struct sptm_geometry geometry;
    if (!sptm_root_geometry(root, &geometry) || count > SPTM_MAX_SCRATCH_ENTRIES)
        return false;
    u64 page_size = BIT(geometry.page_shift);
    if (count > (UINT64_MAX - start) / page_size)
        return false;

    u64 templates = sptm_pointer_pa(ctx->regs[3], count * sizeof(u64));
    if (count && !templates)
        return false;

    u64 scratch = sptm_scratch_pa(ctx);
    if (!sptm_valid_pa(scratch, count * sizeof(u64)))
        return false;

    u64 mask = sptm_update_mask(flags);
    if (!mask)
        return false;

    for (size_t index = 0; index < count; index++) {
        if (!sptm_walk(root, start + index * page_size, 3, NULL))
            return false;
    }
    bool changed = false;

    for (size_t index = 0; index < count; index++) {
        u64 slot = sptm_walk(root, start + index * page_size, 3, NULL);

        u64 old = read64(slot);
        u64 template = read64(templates + index * sizeof(u64));
        write64(scratch + index * sizeof(u64), old);
        sptm_write_stage1_descriptor(slot, (old & ~mask) | (template & mask));
        changed = true;
    }

    // Do not invalidate a partial deferred alias batch.
    if (changed && !(flags & BIT(8)))
        sptm_publish_stage1();
    else
        sysop("dsb sy");

    ctx->regs[0] = flags & BIT(8) ? 5 : SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_update_disjoint(struct exc_info *ctx)
{
    size_t count = ctx->regs[2];
    u64 flags = ctx->regs[3];

    if (count > SPTM_MAX_SCRATCH_ENTRIES)
        return false;

    u64 ops = sptm_pointer_pa(ctx->regs[1], count * 24);
    if (count && !ops)
        return false;

    for (size_t index = 0; index < count; index++) {
        struct sptm_geometry geometry;
        if (!sptm_root_geometry(read64(ops + index * 24), &geometry))
            return false;
    }

    u64 scratch = sptm_scratch_pa(ctx);
    if (!sptm_valid_pa(scratch, count * sizeof(u64)))
        return false;

    u64 mask = sptm_update_mask(flags);
    if (!mask)
        return false;
    bool changed = false;

    for (size_t index = 0; index < count; index++) {
        u64 op = ops + index * 24;
        if (!sptm_walk(read64(op), read64(op + 8), 3, NULL))
            return false;
    }

    for (size_t index = 0; index < count; index++) {
        u64 op = ops + index * 24;
        u64 slot = sptm_walk(read64(op), read64(op + 8), 3, NULL);

        u64 old = read64(slot);
        u64 template = read64(op + 16);
        write64(scratch + index * sizeof(u64), old);
        sptm_write_stage1_descriptor(slot, (old & ~mask) | (template & mask));
        changed = true;
    }

    if (changed && !(flags & BIT(8)))
        sptm_publish_stage1();
    else
        sysop("dsb sy");

    ctx->regs[0] = flags & BIT(8) ? 5 : SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_update_disjoint_multipage(struct exc_info *ctx)
{
    size_t slots = ctx->regs[1];

    if (slots > SPTM_MAX_SCRATCH_ENTRIES)
        return false;

    u64 stream = sptm_pointer_pa(ctx->regs[0], slots * 24);
    if (slots && !stream)
        return false;

    // Validate the entire stream before modifying mappings.
    size_t used = 0;
    while (used < slots) {
        u64 header = stream + used * 24;
        u64 paddr = read64(header);
        size_t inner_count = read32(header + 16);
        u64 options = read32(header + 20);
        used++;

        if (inner_count > slots - used || !sptm_update_mask(options))
            return false;

        if (!(options & BIT(9)) && paddr >= sptm.managed_start && paddr < sptm.managed_end) {
            u64 physmap_va = sptm.physmap_base + paddr - sptm.managed_start;
            if (!sptm_walk(sptm.kernel_root, physmap_va, 3, NULL))
                return false;
        }

        for (size_t index = 0; index < inner_count; index++) {
            struct sptm_geometry geometry;
            u64 op = stream + (used + index) * 24;
            if (!sptm_root_geometry(read64(op), &geometry) ||
                !sptm_walk(read64(op), read64(op + 8), 3, NULL))
                return false;
        }
        used += inner_count;
    }

    u64 scratch = sptm_scratch_pa(ctx);
    if (!sptm_valid_pa(scratch, slots * sizeof(u64)))
        return false;

    if (!cpu_features->apple_sysregs_unlocked) {
        const u64 restore_tag = BIT(63);
        size_t page_count = 0;

        // Mirror RT/WCOMB memory types in m1n1, restoring WB only after TLBI.
        // SKIP_PAPT continuations reuse the per-CPU scratch page.
        used = 0;
        while (used < slots) {
            u64 header = stream + used * 24;
            u64 paddr = read64(header);
            u64 papt_template = read64(header + 8);
            size_t inner_count = read32(header + 16);
            u64 options = read32(header + 20);

            if (!(options & BIT(9)) && !(paddr & SPTM_PAGE_MASK) &&
                sptm_valid_pa(paddr, SPTM_PAGE_SIZE)) {
                u64 tagged = paddr;
                if ((papt_template & (7ULL << 2)) != PTE_MAIR_IDX(1))
                    tagged |= restore_tag;

                size_t index = 0;
                for (; index < page_count; index++) {
                    if ((read64(scratch + index * sizeof(u64)) & ~restore_tag) == paddr) {
                        /* Last transition in the stream wins. */
                        write64(scratch + index * sizeof(u64), tagged);
                        break;
                    }
                }
                if (index == page_count)
                    write64(scratch + page_count++ * sizeof(u64), tagged);
            }

            used += 1 + inner_count;
        }

        /* Partition in place: protections first, queued restorations second. */
        size_t protect_count = 0;
        for (size_t index = 0; index < page_count; index++) {
            u64 value = read64(scratch + index * sizeof(u64));
            if (value & restore_tag)
                continue;

            if (index != protect_count) {
                u64 other = read64(scratch + protect_count * sizeof(u64));
                write64(scratch + index * sizeof(u64), other);
                write64(scratch + protect_count * sizeof(u64), value);
            }
            protect_count++;
        }

        for (size_t index = 0; index < protect_count; index++)
            sptm_cancel_host_rt_restore(read64(scratch + index * sizeof(u64)));

        if (protect_count)
            mmu_map_ram_pages_nc((u64 *)scratch, protect_count, false);

        size_t restore_count = page_count - protect_count;
        for (size_t index = 0; index < restore_count; index++) {
            u64 paddr = read64(scratch + (protect_count + index) * sizeof(u64)) &
                        ~restore_tag;
            sptm_queue_host_rt_restore(paddr);
        }
    }

    bool changed = false;
    bool deferred = false;
    size_t scratch_index = 0;
    used = 0;

    while (used < slots) {
        u64 header = stream + used * 24;
        u64 paddr = read64(header);
        u64 papt_template = read64(header + 8);
        size_t inner_count = read32(header + 16);
        u64 options = read32(header + 20);
        u64 mask = sptm_update_mask(options);
        used++;

        deferred |= options & BIT(8);

        // Keep the physmap memory type in sync unless SKIP_PAPT is set.
        if (!(options & BIT(9)) && paddr >= sptm.managed_start && paddr < sptm.managed_end) {
            u64 physmap_va = sptm.physmap_base + paddr - sptm.managed_start;
            u64 physmap_slot = sptm_walk(sptm.kernel_root, physmap_va, 3, NULL);
            u64 old = read64(physmap_slot);
            u64 physmap_mask = (3ULL << 8) | (7ULL << 2);
            u64 replacement = (old & ~physmap_mask) | (papt_template & physmap_mask);
            sptm_write_stage1_descriptor(physmap_slot, replacement);
            changed = true;
        }

        for (size_t index = 0; index < inner_count; index++, scratch_index++) {
            u64 op = stream + (used + index) * 24;
            u64 slot = sptm_walk(read64(op), read64(op + 8), 3, NULL);
            u64 old = slot ? read64(slot) : 0;

            write64(scratch + scratch_index * sizeof(u64), old);
            u64 template = read64(op + 16);
            sptm_write_stage1_descriptor(slot, (old & ~mask) | (template & mask));
            changed = true;
        }
        used += inner_count;
    }

    if (changed && !deferred)
        sptm_publish_stage1();
    else
        sysop("dsb sy");

    ctx->regs[0] = deferred ? 5 : SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_unmap_region(struct exc_info *ctx)
{
    u64 root = ctx->regs[0];
    u64 start = ctx->regs[1];
    size_t count = ctx->regs[2];
    u64 options = ctx->regs[3];

    struct sptm_geometry geometry;
    if (!sptm_root_geometry(root, &geometry) || count > SPTM_MAX_SCRATCH_ENTRIES)
        return false;
    u64 page_size = BIT(geometry.page_shift);
    if (count > (UINT64_MAX - start) / page_size)
        return false;

    u64 scratch = sptm_scratch_pa(ctx);
    if (!sptm_valid_pa(scratch, count * sizeof(u64)))
        return false;

    bool changed = false;
    for (size_t index = 0; index < count; index++) {
        u64 slot = sptm_walk(root, start + index * page_size, 3, NULL);
        u64 old = slot ? read64(slot) : 0;
        write64(scratch + index * sizeof(u64), old);
        if (slot && (old & 1)) {
            if (!sptm_adjust_mapping_ref(old, geometry.descriptor_mask, -1))
                return false;
            if (!sptm_adjust_table_valid(slot, -1)) {
                sptm_adjust_mapping_ref(old, geometry.descriptor_mask, 1);
                return false;
            }
            sptm_write_stage1_descriptor(slot, 0);
            changed = true;
        }
    }

    bool deferred = changed && (options & BIT(8));
    if (changed && !deferred)
        sptm_publish_stage1();
    else
        sysop("dsb sy");

    ctx->regs[0] = deferred ? 5 : SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_unmap_disjoint(struct exc_info *ctx)
{
    size_t count = ctx->regs[2];

    if (count > SPTM_MAX_SCRATCH_ENTRIES)
        return false;

    u64 ops = sptm_pointer_pa(ctx->regs[1], count * 24);
    if (count && !ops)
        return false;

    for (size_t index = 0; index < count; index++) {
        struct sptm_geometry geometry;
        if (!sptm_root_geometry(read64(ops + index * 24), &geometry))
            return false;
    }

    u64 scratch = sptm_scratch_pa(ctx);
    if (!sptm_valid_pa(scratch, count * sizeof(u64)))
        return false;

    bool changed = false;
    for (size_t index = 0; index < count; index++) {
        u64 op = ops + index * 24;
        struct sptm_geometry geometry;
        u64 slot = sptm_walk(read64(op), read64(op + 8), 3, &geometry);
        u64 old = slot ? read64(slot) : 0;
        write64(scratch + index * sizeof(u64), old);
        if (slot && (old & 1)) {
            if (!sptm_adjust_mapping_ref(old, geometry.descriptor_mask, -1))
                return false;
            if (!sptm_adjust_table_valid(slot, -1)) {
                sptm_adjust_mapping_ref(old, geometry.descriptor_mask, 1);
                return false;
            }
            sptm_write_stage1_descriptor(slot, 0);
            changed = true;
        }
    }

    if (changed)
        sptm_publish_stage1();
    else
        sysop("dsb sy");

    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_nest_region(struct exc_info *ctx, bool nest)
{
    u64 user_root = ctx->regs[0];
    u64 shared_root = ctx->regs[1];
    u64 start = ctx->regs[2];
    u64 count = ctx->regs[3];
    struct sptm_geometry user_geometry;
    struct sptm_geometry shared_geometry;

    if (!sptm_root_geometry(user_root, &user_geometry) ||
        (nest && !sptm_root_geometry(shared_root, &shared_geometry)))
        return false;
    if (nest && (user_geometry.page_shift != shared_geometry.page_shift ||
                 user_geometry.start_level != shared_geometry.start_level ||
                 user_geometry.entries_mask != shared_geometry.entries_mask ||
                 user_geometry.descriptor_mask != shared_geometry.descriptor_mask))
        return false;

    u64 page_size = BIT(user_geometry.page_shift);
    if (count > (UINT64_MAX - start) / page_size)
        return false;

    u64 bytes = count * page_size;
    u8 l2_shift = user_geometry.page_shift == 12 ? 21 : 25;
    u64 first_block = start >> l2_shift;
    u64 iterations = bytes ? ((start + bytes - 1) >> l2_shift) - first_block + 1 : 0;

    for (u64 index = 0; index < iterations; index++) {
        u64 va = (first_block + index) << l2_shift;
        if (!sptm_walk(user_root, va, 2, NULL) || (nest && !sptm_walk(shared_root, va, 2, NULL)))
            return false;
    }

    bool changed = false;

    for (u64 index = 0; index < iterations; index++) {
        u64 va = (first_block + index) << l2_shift;
        u64 user_slot = sptm_walk(user_root, va, 2, NULL);

        u64 value = 0;
        if (nest) {
            u64 shared_slot = sptm_walk(shared_root, va, 2, NULL);
            value = read64(shared_slot);
        }

        u64 old = read64(user_slot);
        if (old != value) {
            sptm_write_stage1_descriptor(user_slot, value);
            changed = true;
        }
    }

    if (changed)
        sptm_publish_stage1();
    else
        sysop("dsb sy");

    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_surt_update(struct exc_info *ctx, bool allocate)
{
    u64 frame = ctx->regs[0] & ~SPTM_PAGE_MASK;
    size_t slot_index = ctx->regs[1];
    if (slot_index >= SPTM_PAGE_SIZE / 128 || !sptm_valid_pa(frame, SPTM_PAGE_SIZE))
        return false;

    u8 *frame_entry = sptm_frame_entry(frame);
    if (!frame_entry || frame_entry[2] != SPTM_FRAME_SUBPAGE)
        return false;

    u64 root = frame + slot_index * 128;
    struct sptm_surt_root *surt = sptm_find_surt_root(root);

    if (allocate) {
        if (!surt) {
            for (size_t index = 0; index < ARRAY_SIZE(sptm.surt_roots); index++) {
                if (!sptm.surt_roots[index].valid) {
                    surt = &sptm.surt_roots[index];
                    break;
                }
            }
        }
        if (!surt)
            return false;

        surt->root = root;
        surt->attr_index = ctx->regs[2];
        surt->asid = ctx->regs[4];
        surt->valid = true;
    } else if (surt) {
        memset(surt, 0, sizeof(*surt));
    }

    memset((void *)root, 0, 128);
    sysop("dsb sy");
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_condemn_leaf_table(struct exc_info *ctx, bool condemn)
{
    struct sptm_geometry geometry;
    u64 slot = sptm_walk(ctx->regs[0], ctx->regs[1], 2, &geometry);
    if (!slot) {
        ctx->regs[0] = SPTM_STATUS_TABLE_NOT_PRESENT;
        return true;
    }

    u64 value = read64(slot);
    if (!(value & 1)) {
        ctx->regs[0] = SPTM_STATUS_TABLE_NOT_PRESENT;
        return true;
    }

    if (condemn) {
        // Only one caller may condemn a table.
        if (value & BIT(2)) {
            ctx->regs[0] = SPTM_STATUS_TABLE_NOT_PRESENT;
            return true;
        }

        u64 child = value & geometry.descriptor_mask;
        u8 *entry = sptm_frame_entry(child & ~SPTM_PAGE_MASK);
        if (!entry || !sptm_is_table_type(entry[2]))
            return false;

        sptm_write_stage1_descriptor(slot, value | BIT(2));
    } else {
        if (!(value & BIT(2))) {
            /* Endpoint 44 is an idempotent clear operation. */
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        sptm_write_stage1_descriptor(slot, value & ~BIT(2));
    }
    sptm_publish_stage1();
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}
