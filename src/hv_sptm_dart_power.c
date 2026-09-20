/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

static bool sptm_dart_clear_errors(const struct sptm_dart *dart)
{
    for (size_t index = 0; index < dart->instance_count; index++) {
        u64 base = dart->instances[index];

        if (dart->version_major > 2 || (dart->version_major == 2 && dart->version_minor >= 2)) {
            // DART 2.2 uses write-one-to-clear per-SID exception words.
            for (size_t word = 0; word < dart->sid_words; word++) {
                u64 address = base + DART_SID_EXCEPTIONS + word * sizeof(u32);
                u32 pending = read32(address);
                if (pending && pending != DART_UNAVAILABLE && pending != UINT32_MAX)
                    write32(address, pending);
            }
        } else {
            u32 error = read32(base + DART_ERROR);
            if (error == DART_UNAVAILABLE || error == UINT32_MAX)
                return false;
            if (error & DART_ERROR_SECONDARY) {
                if (!(dart->flags & SPTM_DART_IGNORE_SECONDARY))
                    return false;
                u32 secondary = read32(base + 0x1c0);
                if (secondary && secondary != DART_UNAVAILABLE && secondary != UINT32_MAX)
                    write32(base + 0x1c0, secondary);
            }
            if (error)
                write32(base + DART_ERROR, error);
        }

        write32(base + dart->interrupt_status_offset, UINT32_MAX);
    }

    sysop("dsb sy");
    return true;
}

u64 sptm_dart_clock_address(u64 entry)
{
    return entry & ~(u64)SPTM_DART_CLOCK_FLAGS;
}

static struct sptm_dart_clock_ref *sptm_dart_clock_ref(u64 address, bool create)
{
    struct sptm_dart_clock_ref *empty = NULL;

    for (size_t index = 0; index < ARRAY_SIZE(sptm.dart_clock_refs); index++) {
        struct sptm_dart_clock_ref *ref = &sptm.dart_clock_refs[index];
        if (ref->valid && ref->address == address)
            return ref;
        if (!ref->valid && !empty)
            empty = ref;
    }

    if (!create || !empty)
        return NULL;
    empty->address = address;
    empty->valid = true;
    return empty;
}

static bool sptm_dart_shared_clock_acquire(u64 address)
{
    struct sptm_dart_clock_ref *ref = sptm_dart_clock_ref(address, true);
    if (!ref || ref->refs == UINT16_MAX)
        return false;

    if (!ref->refs) {
        u32 value = read32(address);
        if (value == DART_UNAVAILABLE || value == UINT32_MAX)
            return false;
        ref->original = value & FPAG_CLOCK_PROTECTION;
        if (!ref->original)
            write32(address, value | FPAG_CLOCK_PROTECTION);
    }
    ref->refs++;
    return true;
}

static void sptm_dart_shared_clock_release(u64 address)
{
    struct sptm_dart_clock_ref *ref = sptm_dart_clock_ref(address, false);
    if (!ref || !ref->refs)
        return;

    ref->refs--;
    if (ref->refs)
        return;

    if (!ref->original) {
        u32 value = read32(address);
        if (value != DART_UNAVAILABLE && value != UINT32_MAX)
            write32(address, value & ~FPAG_CLOCK_PROTECTION);
    }
    memset(ref, 0, sizeof(*ref));
}

static bool sptm_dart_powerup_sidebands(struct sptm_dart *dart)
{
    if (dart->clock_count) {
        u64 clocks_pa = sptm_pointer_pa(dart->clock_entries, dart->clock_count * sizeof(u64));
        if (!clocks_pa)
            return false;

        if (dart->flags & SPTM_DART_UNGANG_SHARED_PS) {
            // apcie0 and apcie2 share this FPAG slice on T8132.
            if (dart->clock_active)
                return true;

            size_t acquired = 0;
            for (; acquired < dart->clock_count; acquired++) {
                u64 address = sptm_dart_clock_address(read64(clocks_pa + acquired * sizeof(u64)));
                if (!sptm_dart_shared_clock_acquire(address))
                    break;
            }
            if (acquired != dart->clock_count) {
                while (acquired) {
                    u64 address =
                        sptm_dart_clock_address(read64(clocks_pa + --acquired * sizeof(u64)));
                    sptm_dart_shared_clock_release(address);
                }
                return false;
            }
            dart->clock_active = true;
            sysop("dsb sy");
            return true;
        }

        for (size_t index = 0; index < dart->clock_count; index++) {
            u64 address = sptm_dart_clock_address(read64(clocks_pa + index * sizeof(u64)));
            u32 value = read32(address);
            if (value == DART_UNAVAILABLE || value == UINT32_MAX)
                return false;
            write32(address, value | FPAG_CLOCK_PROTECTION);
        }
    }
    sysop("dsb sy");
    return true;
}

static bool sptm_dart_apply_tunables(const struct sptm_dart *dart)
{
    if (!dart->tunable_count)
        return true;
    u64 entries_pa = sptm_pointer_pa(dart->tunable_entries,
                                     dart->tunable_count * sizeof(struct sptm_dart_tunable));
    if (!entries_pa)
        return false;
    struct sptm_dart_tunable *entries = (void *)entries_pa;

    for (size_t index = 0; index < dart->tunable_count; index++) {
        struct sptm_dart_tunable *entry = &entries[index];
        bool known_base = false;
        for (size_t instance = 0; instance < dart->instance_count; instance++)
            known_base |= entry->base == dart->instances[instance];
        if (!known_base ||
            (entry->size != 1 && entry->size != 2 && entry->size != 4 && entry->size != 8) ||
            (entry->offset & (entry->size - 1)) || entry->offset > 0x10000 - entry->size)
            return false;

        u64 address = entry->base + entry->offset;
        u64 old, current, width_mask;
        switch (entry->size) {
            case 1:
                width_mask = UINT8_MAX;
                old = read8(address);
                if ((old & entry->mask) != (entry->value & entry->mask))
                    write8(address, (old & ~entry->mask) | (entry->value & entry->mask));
                current = read8(address);
                break;
            case 2:
                width_mask = UINT16_MAX;
                old = read16(address);
                if ((old & entry->mask) != (entry->value & entry->mask))
                    write16(address, (old & ~entry->mask) | (entry->value & entry->mask));
                current = read16(address);
                break;
            case 4:
                width_mask = UINT32_MAX;
                old = read32(address);
                if ((old & entry->mask) != (entry->value & entry->mask))
                    write32(address, (old & ~entry->mask) | (entry->value & entry->mask));
                current = read32(address);
                break;
            case 8:
                width_mask = UINT64_MAX;
                old = read64(address);
                if ((old & entry->mask) != (entry->value & entry->mask))
                    write64(address, (old & ~entry->mask) | (entry->value & entry->mask));
                current = read64(address);
                break;
            default:
                __builtin_unreachable();
        }
        if (((entry->mask | entry->value) & ~width_mask) ||
            (current & entry->mask) != (entry->value & entry->mask))
            return false;
    }
    sysop("dsb sy");
    return true;
}

static bool sptm_dart_program_dapf(const struct sptm_dart *dart)
{
    if (!dart->dapf_count)
        return true;
    u64 entries_pa =
        sptm_pointer_pa(dart->dapf_entries, dart->dapf_count * sizeof(struct sptm_dart_dapf));
    if (!entries_pa)
        return false;
    struct sptm_dart_dapf *entries = (void *)entries_pa;
    for (size_t index = 0; index < dart->dapf_count; index++) {
        struct sptm_dart_dapf *entry = &entries[index];
        write32(entry->base + 0x04, entry->r4);
        write64(entry->base + 0x08, entry->start);
        write64(entry->base + 0x10, entry->end);
        write32(entry->base + 0x00, entry->control);
        write32(entry->base + 0x20, entry->r20);
    }
    sysop("dsb sy");
    return true;
}

static void sptm_dart_powerdown_sidebands(struct sptm_dart *dart)
{
    u64 clocks_pa = sptm_pointer_pa(dart->clock_entries, dart->clock_count * sizeof(u64));
    if (clocks_pa) {
        if (dart->flags & SPTM_DART_UNGANG_SHARED_PS) {
            if (!dart->clock_active)
                return;
            for (size_t index = 0; index < dart->clock_count; index++) {
                u64 address = sptm_dart_clock_address(read64(clocks_pa + index * sizeof(u64)));
                sptm_dart_shared_clock_release(address);
            }
            dart->clock_active = false;
            sysop("dsb sy");
            return;
        }

        for (size_t index = 0; index < dart->clock_count; index++) {
            u64 address = sptm_dart_clock_address(read64(clocks_pa + index * sizeof(u64)));
            u32 value = read32(address);
            if (value != DART_UNAVAILABLE && value != UINT32_MAX)
                write32(address, value & ~FPAG_CLOCK_PROTECTION);
        }
    }
    sysop("dsb sy");
}

static bool sptm_dart_program_sids(struct sptm_dart *dart)
{
    for (u32 sid = 0; sid < dart->sid_count; sid++) {
        struct sptm_dart_sid *state = sptm_dart_sid(dart, sid);
        if (!state || !(state->flags & SPTM_DART_SID_KNOWN) ||
            (state->flags & SPTM_DART_SID_EXCLAVE))
            continue;

        u32 ttbr = 0;
        if (state->tcr & DART_TCR_TRANSLATE) {
            if (state->root) {
                if (!sptm_dart_valid_table(state, state->root, SPTM_PAGE_SIZE))
                    return false;
                ttbr = ((state->root >> 12) & 0xfffffffcULL) | DART_TTBR_VALID;
            }
        } else if (!(state->flags & SPTM_DART_SID_POLICY)) {
            return false;
        }

        for (size_t index = 0; index < dart->instance_count; index++) {
            u64 base = dart->instances[index];
            if (read32(base + DART_REG_PROTECT) & BIT(0)) {
                // Ignore stale locked TTBRs for non-translating SIDs.
                if (read32(base + DART_TCR + sid * sizeof(u32)) != state->tcr ||
                    ((state->tcr & DART_TCR_TRANSLATE) &&
                     read32(base + DART_TTBR + sid * sizeof(u32)) != ttbr))
                    return false;
                continue;
            }
            write32(base + DART_TTBR + sid * sizeof(u32), ttbr);
            write32(base + DART_TCR + sid * sizeof(u32), state->tcr);
        }
    }
    return sptm_dart_flush_all(dart);
}

static bool sptm_dart_discover(struct sptm_dart *dart)
{
    u8 version_major = 0, version_minor = 0, pa_width = 0;
    u16 sid_capacity = 0;
    bool hardware_flush_supported = true;

    for (size_t index = 0; index < dart->instance_count; index++) {
        u64 base = dart->instances[index];
        u32 params_4 = read32(base + DART_PARAMS_4);
        u32 params_8 = read32(base + DART_PARAMS_8);
        u32 params_c = read32(base + DART_PARAMS_C);
        if (params_4 == DART_UNAVAILABLE || params_8 == DART_UNAVAILABLE ||
            params_c == DART_UNAVAILABLE || params_4 == UINT32_MAX || params_8 == UINT32_MAX ||
            params_c == UINT32_MAX)
            return false;

        u8 current_major = (params_8 >> 8) & 0xff;
        u8 current_minor = params_8 & 0xff;
        u8 current_pa_width = (params_8 >> 24) & 0x3f;
        u16 current_sid_capacity = params_c & 0x1ff;
        if (!current_major || !current_pa_width || !current_sid_capacity ||
            current_sid_capacity < dart->sid_count)
            return false;
        if (index && (current_major != version_major || current_minor != version_minor ||
                      current_pa_width != pa_width || current_sid_capacity != sid_capacity))
            return false;
        version_major = current_major;
        version_minor = current_minor;
        pa_width = current_pa_width;
        sid_capacity = current_sid_capacity;
        hardware_flush_supported = hardware_flush_supported && (params_4 & BIT(3));
    }

    dart->version_major = version_major;
    dart->version_minor = version_minor;
    dart->hardware_flush_supported = hardware_flush_supported;
    dart->sid_words = (sid_capacity + 31) / 32;
    dart->counter_count = version_major >= 2 ? 9 : 6;
    dart->interrupt_status_offset =
        version_major > 2 || (version_major == 2 && version_minor >= 2) ? 0x164 : 0x160;
    dart->initialized = true;
    return true;
}

static bool sptm_dart_save_power_state(struct sptm_dart *dart)
{
    static const u16 counter_offsets[] = {
        0x760, 0x764, 0x768, 0x770, 0x774, 0x778, 0x780, 0x784, 0x788,
    };

    for (size_t index = 0; index < dart->instance_count; index++) {
        u64 base = dart->instances[index];
        for (size_t word = 0; word < dart->sid_words; word++) {
            u32 streams = read32(base + DART_ENABLE_STREAMS + word * sizeof(u32));
            if (streams == DART_UNAVAILABLE || streams == UINT32_MAX)
                return false;
            dart->saved_streams[index][word] = streams;
            dart->active_streams[index][word] = streams;
        }
        for (size_t counter = 0; counter < dart->counter_count; counter++)
            dart->saved_counters[index][counter] = read32(base + counter_offsets[counter]);
    }
    dart->saved_valid = true;
    return true;
}

static void sptm_dart_disable_translating_streams(struct sptm_dart *dart)
{
    u32 translating[(SPTM_MAX_DART_SIDS + 31) / 32] = {};
    for (u32 sid = 0; sid < dart->sid_count; sid++) {
        struct sptm_dart_sid *state = sptm_dart_sid(dart, sid);
        if (state && (state->flags & SPTM_DART_SID_KNOWN) &&
            !(state->flags & SPTM_DART_SID_EXCLAVE) && (state->tcr & DART_TCR_TRANSLATE))
            translating[sid / 32] |= BIT(sid % 32);
    }
    for (size_t index = 0; index < dart->instance_count; index++) {
        for (size_t word = 0; word < dart->sid_words; word++) {
            if (translating[word]) {
                write32(dart->instances[index] + DART_DISABLE_STREAMS + word * sizeof(u32),
                        translating[word]);
                dart->active_streams[index][word] &= ~translating[word];
            }
        }
    }
    sysop("dsb sy");
}

static void sptm_dart_restore_runtime_state(struct sptm_dart *dart)
{
    static const u16 counter_offsets[] = {
        0x760, 0x764, 0x768, 0x770, 0x774, 0x778, 0x780, 0x784, 0x788,
    };

    for (size_t index = 0; index < dart->instance_count; index++) {
        u64 base = dart->instances[index];
        if (dart->limits_valid && dart->saved_valid) {
            write32(base + DART_TEQRESERVE, dart->saved_teqreserve[index]);
            write32(base + DART_TLIMIT, dart->saved_tlimit[index]);
        }
        if (dart->saved_valid) {
            for (size_t counter = 0; counter < dart->counter_count; counter++)
                write32(base + counter_offsets[counter], dart->saved_counters[index][counter]);
        }
        for (size_t word = 0; word < dart->sid_words; word++) {
            u32 streams =
                dart->saved_valid ? dart->saved_streams[index][word] : dart->boot_streams[word];
            if (streams) {
                write32(base + DART_ENABLE_STREAMS + word * sizeof(u32), streams);
                dart->active_streams[index][word] |= streams;
            }
        }
    }
    sysop("dsb sy");
}

bool sptm_dart_power(struct exc_info *ctx, bool power_up)
{
    struct sptm_dart *dart = sptm_find_dart(ctx->regs[0]);
    if (!dart || !dart->initialized)
        return false;

    if (power_up) {
        if (!sptm_dart_powerup_sidebands(dart))
            return false;

        // Mark the DART powered before programming SIDs and flushing.
        dart->powered = true;

        if (!sptm_dart_apply_tunables(dart) || !sptm_dart_program_sids(dart))
            return false;
        if (!dart->limits_valid) {
            for (size_t index = 0; index < dart->instance_count; index++) {
                u64 base = dart->instances[index];
                dart->saved_tlimit[index] = read32(base + DART_TLIMIT);
                dart->saved_teqreserve[index] = read32(base + DART_TEQRESERVE);
            }
            dart->limits_valid = true;
        }
        if (!sptm_dart_program_dapf(dart) || !sptm_dart_clear_errors(dart))
            return false;
        sptm_dart_restore_runtime_state(dart);
    } else {
        if (!dart->powered) {
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            return true;
        }
        if (!sptm_dart_save_power_state(dart))
            return false;
        sptm_dart_disable_translating_streams(dart);
        sptm_dart_powerdown_sidebands(dart);
        dart->powered = false;
    }

    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_dart_init(struct exc_info *ctx)
{
    struct sptm_dart *dart = sptm_find_dart(ctx->regs[0]);
    if (!dart)
        return false;
    if (!sptm_dart_discover(dart))
        return false;
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

bool sptm_dart_error_endpoint(struct exc_info *ctx)
{
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}
