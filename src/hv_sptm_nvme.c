/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

static bool sptm_nvme_xnu_default_range(u64 pa, size_t size)
{
    if (!size || !sptm_valid_pa(pa, size))
        return false;

    u64 first = pa & ~SPTM_PAGE_MASK;
    u64 last = (pa + size - 1) & ~SPTM_PAGE_MASK;
    for (u64 frame = first;; frame += SPTM_PAGE_SIZE) {
        u8 *entry = sptm_frame_entry(frame);
        if (!entry || entry[2] != SPTM_FRAME_DEFAULT)
            return false;
        if (frame == last)
            return true;
    }
}

static bool sptm_nvme_range_allowed(u64 pa, size_t size)
{
    return (pa >= sptm.nvme.trusted_start && pa < sptm.nvme.trusted_end &&
            size <= sptm.nvme.trusted_end - pa) ||
           (pa >= sptm.nvme.xnu_managed_start && pa < sptm.nvme.xnu_managed_end &&
            size <= sptm.nvme.xnu_managed_end - pa) ||
           // Static kernelcache frames before top_of_kernel_data may back late I/O.
           sptm_nvme_xnu_default_range(pa, size);
}

static bool sptm_nvme_queue_allowed(u64 pa, size_t size)
{
    return !(pa & SPTM_NVME_PRP_PAGE_MASK) && sptm_nvme_range_allowed(pa, size);
}

static struct sptm_nvme_command *sptm_nvme_command(u32 cid)
{
    if (cid >= sptm.nvme.queue_entries)
        return NULL;
    return (struct sptm_nvme_command *)(sptm.nvme.command_state + cid * SPTM_NVME_COMMAND_SIZE);
}

static u64 sptm_nvme_tcb(u32 qid, u32 cid)
{
    u64 base;

    if (qid == 0)
        base = sptm.nvme.admin_tcbs;
    else if (qid == 1)
        base = sptm.nvme.io_tcbs;
    else
        return 0;

    return base + cid * SPTM_NVME_TCB_SIZE;
}

static bool sptm_nvme_map_pages(struct exc_info *ctx)
{
    u32 qid = ctx->regs[0];
    u32 cid = ctx->regs[1];
    u64 template_pointer = ctx->regs[2];
    u64 segment_pointer = ctx->regs[3];
    size_t count = ctx->regs[4];
    u8 template[SPTM_NVME_TCB_SIZE];
    struct sptm_nvme_command *command = sptm_nvme_command(cid);
    u64 tcb_pa = sptm_nvme_tcb(qid, cid);
    bool handled = false;

    if (!sptm.nvme.coastguard_enabled || !command || !tcb_pa || count > SPTM_NVME_MAX_PRPS)
        return false;

    u64 template_pa = sptm_pointer_pa(template_pointer, sizeof(template));
    if (!template_pa)
        return false;

    spin_lock(&sptm.service_lock);
    if (command->state)
        goto out;

    memcpy(template, (void *)template_pa, sizeof(template));
    u32 length = read32((u64)template + 0x04);
    u8 dma_flags = template[0x01];
    u64 template_prp1 = read64((u64)template + 0x18);
    u64 template_prp2 = read64((u64)template + 0x20);
    write64((u64)template + 0x18, 0);
    write64((u64)template + 0x20, 0);
    template[0x02] = cid;

    u64 segment_pa = 0;
    u64 first = 0;
    if (count) {
        if (!segment_pointer)
            goto out;
        size_t segment_size = count * sizeof(u64);
        segment_pa = sptm_pointer_pa(segment_pointer, segment_size);
        if (!segment_pa || (segment_pa & SPTM_PAGE_MASK) + segment_size > SPTM_PAGE_SIZE)
            goto out;

        first = read64(segment_pa);
        if (count == 1 && (first & SPTM_NVME_PRP_PAGE_MASK))
            goto out;

        u32 expected_length = (first & SPTM_NVME_PRP_PAGE_MASK) ? count - 2 : count - 1;
        if (length != expected_length || (template_prp1 && template_prp1 != first))
            goto out;
        if (count == 2) {
            u64 second = read64(segment_pa + sizeof(u64));
            if (template_prp2 && template_prp2 != second)
                goto out;
        }

        for (size_t index = 0; index < count; index++) {
            u64 target = read64(segment_pa + index * sizeof(u64));
            u64 page = target & ~SPTM_NVME_PRP_PAGE_MASK;
            if ((index && target != page) ||
                !sptm_nvme_range_allowed(page, SPTM_NVME_PRP_PAGE_SIZE))
                goto out;
        }
    } else if (length) {
        goto out;
    }

    bool writable = dma_flags & BIT(0);
    size_t acquired = 0;
    for (; acquired < count; acquired++) {
        u64 target = read64(segment_pa + acquired * sizeof(u64));
        if (sptm_adjust_data_ref(target, writable, 1))
            continue;
        for (size_t rollback = 0; rollback < acquired; rollback++) {
            u64 rollback_target = read64(segment_pa + rollback * sizeof(u64));
            sptm_adjust_data_ref(rollback_target, writable, -1);
        }
        goto out;
    }

    u64 prp_list_pa = 0;
    u64 second = 0;
    if (count)
        write64((u64)template + 0x18, first);
    if (count == 2) {
        second = read64(segment_pa + sizeof(u64));
        write64((u64)template + 0x20, second);
    } else if (count > 2) {
        prp_list_pa = sptm.nvme.prp_scratch + cid * SPTM_NVME_PRP_SLOT_SIZE;
        for (size_t index = 1; index < count; index++)
            write64(prp_list_pa + (index - 1) * sizeof(u64),
                    read64(segment_pa + index * sizeof(u64)));

        if (sptm.nvme.prp_flush_wa && count > 0x10) {
            size_t flush_size =
                count < 0x100 ? (count * sizeof(u64) + 0x7f) & 0x1f80 : SPTM_NVME_PRP_PAGE_SIZE;
            sysop("dsb sy");
            dc_civac_range((void *)prp_list_pa, flush_size);
        }
        write64((u64)template + 0x20, prp_list_pa);
    }

    memset(command, 0, sizeof(*command));
    command->prp_aux = count == 2 ? second : prp_list_pa;
    command->count = count;
    command->qid = qid;
    command->dma_flags = dma_flags;
    command->state = 1;
    command->first = first;

    memcpy((void *)tcb_pa, template, sizeof(template));
    sysop("dsb sy");

    handled = true;

out:
    spin_unlock(&sptm.service_lock);
    if (handled)
        ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return handled;
}

static bool sptm_nvme_tl_idle(struct sptm_nvme_command *command, bool retry)
{
    u32 directions = command->dma_flags & 3;
    if (!sptm.nvme.tl_wa || !directions)
        return true;

    if (!retry) {
        u32 mask = ((directions & 1) ? 0x800000 : 0) | ((directions & 2) ? 0x80 : 0);
        u32 control = ((directions & 1) ? 0x400000 : 0) | ((directions & 2) ? 0x40 : 0);
        write32(sptm.nvme.tl_mask + 0x4, mask);
        write32(sptm.nvme.tl_mask + 0xc, mask);
        write32(sptm.nvme.tl_control + 0x4, control);
        command->drained_slots = 0;
        sysop("dsb sy");
    }

    u64 all_slots = BIT(sptm.nvme.tl_slots) - 1;
    for (size_t poll = 0; poll < 250; poll++) {
        for (u32 slot = 0; slot < sptm.nvme.tl_slots; slot++) {
            if (command->drained_slots & BIT(slot))
                continue;
            u32 status = read32(sptm.nvme.tl_status + slot * 0x10000);
            bool writes_done = !(directions & 1) || (status & 0xff) == 0xff;
            bool reads_done = !(directions & 2) || (status & 0x7f0000) == 0x7f0000;
            if (writes_done && reads_done)
                command->drained_slots |= BIT(slot);
        }
        if (command->drained_slots == all_slots) {
            write32(sptm.nvme.tl_mask + 0x4, 0x800080);
            write32(sptm.nvme.tl_mask + 0xc, 0x800080);
            write32(sptm.nvme.tl_control + 0x4, 0x400040);
            command->drained_slots = 0;
            sysop("dsb sy");
            return true;
        }
        udelay(1);
    }

    return false;
}

static u64 sptm_nvme_command_target(const struct sptm_nvme_command *command, size_t index)
{
    if (!index)
        return command->first;
    if (command->count == 2)
        return command->prp_aux;
    return read64(command->prp_aux + (index - 1) * sizeof(u64));
}

static bool sptm_nvme_unmap_pages(struct exc_info *ctx)
{
    u32 qid = ctx->regs[0];
    u32 cid = ctx->regs[1];
    bool retry = ctx->regs[2];
    struct sptm_nvme_command *command = sptm_nvme_command(cid);
    u64 tcb_pa = sptm_nvme_tcb(qid, cid);
    bool handled = false;

    if (ctx->regs[2] > 1 || !command || !tcb_pa)
        return false;

    spin_lock(&sptm.service_lock);
    if (!command->state || command->qid != qid ||
        (retry && (!sptm.nvme.tl_wa || command->state != 2)) || (!retry && command->state != 1))
        goto out;

    if (!retry) {
        if (sptm.nvme.vdma_wa) {
            u32 status = read32(sptm.nvme.vdma_status + 0x20000 + cid * 0x20);
            if (status & 0x300)
                goto out;
        }
        memset((void *)tcb_pa, 0, SPTM_NVME_TCB_SIZE);
        sysop("dsb sy");
        write32(sptm.nvme.nvmmu + NVMMU_TCB_INVALIDATE, cid);
        sysop("dsb sy");
        u32 packed_status = read32(sptm.nvme.nvmmu + NVMMU_TCB_STATUS + (cid / 4) * sizeof(u32));
        u32 cid_status = (packed_status >> ((cid % 4) * 5)) & 0xf;
        if (cid_status)
            goto out;
    }

    if (!sptm_nvme_tl_idle(command, retry)) {
        command->state = 2;
        ctx->regs[0] = 0;
        handled = true;
        goto out;
    }

    bool writable = command->dma_flags & BIT(0);
    size_t released = 0;
    for (; released < command->count; released++) {
        u64 target = sptm_nvme_command_target(command, released);
        if (sptm_adjust_data_ref(target, writable, -1))
            continue;
        for (size_t rollback = 0; rollback < released; rollback++) {
            u64 rollback_target = sptm_nvme_command_target(command, rollback);
            sptm_adjust_data_ref(rollback_target, writable, 1);
        }
        goto out;
    }

    if (command->count > 2) {
        memset((void *)command->prp_aux, 0, SPTM_NVME_PRP_SLOT_SIZE);
        // Seems weird but the documentation says so...
        if (sptm.nvme.prp_flush_wa && command->count > 0xff) {
            sysop("dsb sy");
            dc_civac_range((void *)(command->prp_aux + SPTM_NVME_PRP_SLOT_SIZE),
                           SPTM_NVME_PRP_SLOT_SIZE);
        }
    }
    sysop("dsb sy");
    memset(command, 0, sizeof(*command));
    ctx->regs[0] = 1;
    handled = true;

out:
    spin_unlock(&sptm.service_lock);
    return handled;
}

static bool sptm_nvme_cache_values(bool *valid, u64 *cache, const u64 *values, size_t count)
{
    if (*valid) {
        for (size_t index = 0; index < count; index++) {
            if (cache[index] != values[index])
                return false;
        }
        return true;
    }

    memcpy(cache, values, count * sizeof(u64));
    *valid = true;
    return true;
}

static void sptm_nvme_mmio_write32(u64 address, u32 value)
{
    write32(address, value);
    sysop("dsb sy");
}

static void sptm_nvme_mmio_write64_lo_hi(u64 address, u64 value)
{
    sptm_nvme_mmio_write32(address, value);
    sptm_nvme_mmio_write32(address + sizeof(u32), value >> 32);
}

bool sptm_handle_nvme(struct exc_info *ctx, u32 endpoint)
{
    if (!sptm.nvme.configured)
        return false;

    switch (endpoint) {
        case 0:
            spin_lock(&sptm.service_lock);
            sysop("dsb sy");
            sptm_nvme_mmio_write64_lo_hi(sptm.nvme.nvmmu + NVMMU_ADMIN_TCB_BASE,
                                         sptm.nvme.admin_tcbs);
            sptm_nvme_mmio_write64_lo_hi(sptm.nvme.nvmmu + NVMMU_IO_TCB_BASE, sptm.nvme.io_tcbs);
            sptm_nvme_mmio_write32(sptm.nvme.nvmmu + NVMMU_QUEUE_COUNT,
                                   sptm.nvme.queue_entries - 1);
            sptm.nvme.coastguard_enabled = true;
            spin_unlock(&sptm.service_lock);
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        case 1:
            return sptm_nvme_map_pages(ctx);
        case 2:
            return sptm_nvme_unmap_pages(ctx);
        case 3:
            if (ctx->regs[0] != sptm.nvme.queue_entries || ctx->regs[1] != sptm.nvme.protocol)
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        case 4: {
            u64 values[] = {ctx->regs[0], ctx->regs[1], ctx->regs[2], ctx->regs[3]};
            if (!values[1] || values[1] > sptm.nvme.queue_entries || !values[3] ||
                values[3] > sptm.nvme.queue_entries ||
                !sptm_nvme_queue_allowed(values[0], values[1] * 0x40) ||
                !sptm_nvme_queue_allowed(values[2], values[3] * 0x10))
                return false;
            spin_lock(&sptm.service_lock);
            bool valid = sptm_nvme_cache_values(&sptm.nvme.admin_queues_valid,
                                                sptm.nvme.admin_queues, values, ARRAY_SIZE(values));
            if (valid) {
                sptm_nvme_mmio_write32(sptm.nvme.queue_bar + NVME_AQA,
                                       values[1] | (values[3] << 16));
                sptm_nvme_mmio_write64_lo_hi(sptm.nvme.queue_bar + NVME_ASQ, values[0]);
                sptm_nvme_mmio_write64_lo_hi(sptm.nvme.queue_bar + NVME_ACQ, values[2]);
            }
            spin_unlock(&sptm.service_lock);
            if (!valid)
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        case 5: {
            u64 values[] = {ctx->regs[0], ctx->regs[1]};
            if (!values[0] || values[0] > sptm.nvme.queue_entries || !values[1] ||
                values[1] > sptm.nvme.queue_entries)
                return false;
            spin_lock(&sptm.service_lock);
            bool valid = sptm_nvme_cache_values(&sptm.nvme.io_sizes_valid, sptm.nvme.io_sizes,
                                                values, ARRAY_SIZE(values));
            if (valid) {
                sptm_nvme_mmio_write32(sptm.nvme.queue_bar + NVME_IOQA,
                                       values[0] | (values[1] << 16));
            }
            spin_unlock(&sptm.service_lock);
            if (!valid)
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        case 6: {
            u64 value = ctx->regs[0];
            u64 size = sptm.nvme.io_sizes_valid ? sptm.nvme.io_sizes[0] : sptm.nvme.queue_entries;
            if (!sptm_nvme_queue_allowed(value, size * 0x40))
                return false;
            spin_lock(&sptm.service_lock);
            bool valid =
                sptm_nvme_cache_values(&sptm.nvme.io_sq_valid, &sptm.nvme.io_sq, &value, 1);
            if (valid) {
                sptm_nvme_mmio_write64_lo_hi(sptm.nvme.queue_bar + NVME_IOSQ, value);
            }
            spin_unlock(&sptm.service_lock);
            if (!valid)
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        case 7: {
            u64 value = ctx->regs[0];
            u64 size = sptm.nvme.io_sizes_valid ? sptm.nvme.io_sizes[1] : sptm.nvme.queue_entries;
            if (!sptm_nvme_queue_allowed(value, size * 0x10))
                return false;
            spin_lock(&sptm.service_lock);
            bool valid =
                sptm_nvme_cache_values(&sptm.nvme.io_cq_valid, &sptm.nvme.io_cq, &value, 1);
            if (valid) {
                sptm_nvme_mmio_write64_lo_hi(sptm.nvme.queue_bar + NVME_IOCQ, value);
            }
            spin_unlock(&sptm.service_lock);
            if (!valid)
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        case 8: {
            u64 values[] = {ctx->regs[0], ctx->regs[1], ctx->regs[2]};
            if (!sptm.nvme.sha_present || (values[0] & SPTM_PAGE_MASK) ||
                values[1] != SPTM_PAGE_SIZE || (values[2] & ~3ULL) ||
                !sptm_nvme_range_allowed(values[0], values[1]))
                return false;
            spin_lock(&sptm.service_lock);
            bool valid = sptm_nvme_cache_values(&sptm.nvme.sha_valid, sptm.nvme.sha, values,
                                                ARRAY_SIZE(values));
            if (valid) {
                write32(sptm.nvme.sha_base, values[0] >> SPTM_PAGE_SHIFT);
                write32(sptm.nvme.sha_base + 4, values[2]);
                sysop("dsb sy");
            }
            spin_unlock(&sptm.service_lock);
            if (!valid)
                return false;
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        default:
            __builtin_unreachable();
    }
}

void hv_sptm_configure_nvme(u64 config)
{
    u64 config_pa = sptm_pointer_pa(config, SPTM_NVME_CONFIG_WORDS * sizeof(u64));
    if (!sptm.enabled || !config_pa) {
        printf("HV: refusing invalid SPTM NVMe configuration pointer 0x%lx\n", config);
        return;
    }

    u64 words[SPTM_NVME_CONFIG_WORDS];
    memcpy(words, (void *)config_pa, sizeof(words));
    u64 packed = words[10];
    u32 queue_entries = packed;
    u8 protocol = packed >> 32;
    u8 flags = packed >> 40;
    u8 tl_slots = packed >> 48;
    u64 tcb_bytes = ALIGN_UP((u64)queue_entries * SPTM_NVME_TCB_SIZE, SPTM_NVME_TCB_ALIGNMENT);
    u64 prp_bytes = ALIGN_UP((u64)queue_entries * SPTM_NVME_PRP_SLOT_SIZE, SPTM_PAGE_SIZE);
    u64 command_bytes = (u64)queue_entries * SPTM_NVME_COMMAND_SIZE;

    if (!words[0] || !words[1] || !queue_entries || (protocol != 1 && protocol != 2) ||
        (packed >> 56) ||
        (flags & ~(SPTM_NVME_FLAG_PRP_FLUSH_WA | SPTM_NVME_FLAG_TL_WA | SPTM_NVME_FLAG_VDMA_WA |
                   SPTM_NVME_FLAG_SHA_PRESENT)) ||
        words[3] <= words[2] || words[6] != tcb_bytes || words[9] < sptm.managed_start ||
        words[16] <= words[9] || words[16] > sptm.managed_end ||
        !sptm_valid_pa(words[4], tcb_bytes) || !sptm_valid_pa(words[5], tcb_bytes) ||
        !sptm_valid_pa(words[7], prp_bytes) || !sptm_valid_pa(words[8], command_bytes) ||
        ((flags & SPTM_NVME_FLAG_TL_WA) &&
         (!words[11] || !words[12] || !words[13] || !tl_slots || tl_slots > 16)) ||
        ((flags & SPTM_NVME_FLAG_VDMA_WA) && !words[14]) ||
        ((flags & SPTM_NVME_FLAG_SHA_PRESENT) && !words[15])) {
        printf("HV: refusing inconsistent SPTM NVMe configuration\n");
        return;
    }

    memset(&sptm.nvme, 0, sizeof(sptm.nvme));
    sptm.nvme.queue_bar = words[0];
    sptm.nvme.nvmmu = words[1];
    sptm.nvme.trusted_start = words[2];
    sptm.nvme.trusted_end = words[3];
    sptm.nvme.admin_tcbs = words[4];
    sptm.nvme.io_tcbs = words[5];
    sptm.nvme.prp_scratch = words[7];
    sptm.nvme.command_state = words[8];
    sptm.nvme.xnu_managed_start = words[9];
    sptm.nvme.xnu_managed_end = words[16];
    sptm.nvme.queue_entries = queue_entries;
    sptm.nvme.protocol = protocol;
    sptm.nvme.prp_flush_wa = flags & SPTM_NVME_FLAG_PRP_FLUSH_WA;
    sptm.nvme.tl_wa = flags & SPTM_NVME_FLAG_TL_WA;
    sptm.nvme.vdma_wa = flags & SPTM_NVME_FLAG_VDMA_WA;
    sptm.nvme.sha_present = flags & SPTM_NVME_FLAG_SHA_PRESENT;
    sptm.nvme.tl_slots = tl_slots;
    sptm.nvme.tl_mask = words[11];
    sptm.nvme.tl_control = words[12];
    sptm.nvme.tl_status = words[13];
    sptm.nvme.vdma_status = words[14];
    sptm.nvme.sha_base = words[15];
    sptm.nvme.configured = true;
}
