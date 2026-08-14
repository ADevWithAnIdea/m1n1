/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv.h"

#include "hv_sptm_internal.h"

#define SPTM_GENTER_XNU_PANIC_BEGIN 4
#define SPTM_PANIC_CPU_NONE         0xffff
#define SPTM_PANIC_DOMAIN_XNU       1
#define SPTM_PANIC_FLAG_OFFSET      0
#define SPTM_PANIC_CPU_OFFSET       8
#define SPTM_PANIC_DOMAIN_OFFSET    12
#define SPTM_PANIC_STATE_SIZE       13
u64 hv_sptm_init(u64 guest_adt, u64 cons_ops, u64 page_shift_const, u64 xnu_text)
{
    return sptm_boot_init(guest_adt, cons_ops, page_shift_const, xnu_text);
}

void hv_sptm_configure_panic(u64 state_pa)
{
    if (!sptm.enabled || (state_pa & 7) || !sptm_valid_pa(state_pa, SPTM_PANIC_STATE_SIZE)) {
        printf("HV: refusing invalid SPTM panic-state configuration\n");
        return;
    }

    sptm.panic_state_pa = state_pa;
}

static bool sptm_handle_xnu_panic_begin(struct exc_info *ctx)
{
    if (!sptm.panic_state_pa || ctx->cpu_id >= sptm.max_cpus)
        return false;

    struct sptm_cpu *cpu = sptm_find_cpu(sptm.hv_phys_ids[ctx->cpu_id]);
    if (!cpu)
        return false;

    u16 *owner = (u16 *)(sptm.panic_state_pa + SPTM_PANIC_CPU_OFFSET);
    u16 expected = SPTM_PANIC_CPU_NONE;
    bool first = __atomic_compare_exchange_n(owner, &expected, cpu->logical_id, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    if (first) {
        __atomic_store_n((u8 *)(sptm.panic_state_pa + SPTM_PANIC_DOMAIN_OFFSET),
                         SPTM_PANIC_DOMAIN_XNU, __ATOMIC_RELEASE);
        printf("HV: SPTM XNU panic owner CPU %u (HV CPU %lu)\n", cpu->logical_id, ctx->cpu_id);
    }

    /* Publish the irreversible panic latch after its owner metadata. */
    __atomic_store_n((u8 *)(sptm.panic_state_pa + SPTM_PANIC_FLAG_OFFSET), true, __ATOMIC_RELEASE);

    if (first)
        hv_exc_proxy(ctx, START_HV, HV_XNU_PANIC, NULL);

    return true;
}

static bool sptm_handle_dispatch(struct exc_info *ctx)
{
    u64 dispatch = ctx->regs[16];
    u32 domain = (dispatch >> 48) & 0xff;
    u32 table = (dispatch >> 32) & 0xff;
    u32 endpoint = dispatch;
    bool handled = false;

    if (!(dispatch & 0xff00ff0000000000ULL)) {
        if (domain == 2 && table == 0) {
            handled = sptm_handle_txm(ctx, endpoint);
        } else if (domain == 0 && table == 0) {
            spin_lock(&sptm.service_lock);
            handled = sptm_handle_xnu_bootstrap(ctx, endpoint);
            spin_unlock(&sptm.service_lock);
        } else if (domain == 0 && table == 3 && endpoint <= 16) {
            handled = sptm_handle_dart(ctx, endpoint);
        } else if (domain == 0 && table == 4 && endpoint <= 3) {
            handled = sptm_handle_dart(ctx, endpoint);
        } else if (domain == 0 && table == 5 && endpoint <= 2) {
            handled = sptm_handle_sart(ctx, endpoint);
        } else if (domain == 0 && table == 6 && endpoint <= 8) {
            handled = sptm_handle_nvme(ctx, endpoint);
        } else if (domain == 0 && table == 7 && endpoint <= 12) {
            handled = sptm_handle_uat(ctx, endpoint);
        } else if (domain == 0 && table == 9 && endpoint <= 12) {
            ctx->regs[0] = SPTM_STATUS_SUCCESS;
            handled = true;
        }
    }

    return handled;
}

static bool sptm_handle_shadow_hvc(struct exc_info *ctx, u32 immediate)
{
    u32 rt = immediate & 0x1f;
    u64 value = rt == 31 ? 0 : ctx->regs[rt];

    if (immediate >= 0x1c0 && immediate < 0x280) {
        u32 operation = (immediate - 0x1c0) >> 5;
        bool is_write = operation & 1;
        u32 reg = operation >> 1;

        if (reg < 2) {
            if (is_write)
                sptm.sprr_perm[reg] = value;
            else if (rt != 31)
                ctx->regs[rt] = sptm.sprr_perm[reg];
        } else {
            if (is_write)
                sptm.sprr_umprr = value;
            else if (rt != 31)
                ctx->regs[rt] = sptm.sprr_umprr;
        }
        return true;
    }

    if ((immediate >= 0x380 && immediate < 0x3a0) || (immediate >= 0x3c0 && immediate < 0x3e0))
        return hv_handle_pmc_hvc(ctx, immediate);

    if (immediate >= 0x400 && immediate < 0xa40) {
        return hv_handle_clpc_hvc(ctx, immediate);
    }

    if (immediate >= 0xa40 && immediate < 0xac0)
        return hv_handle_objc_bp_hvc(ctx, immediate);

    return false;
}

bool hv_sptm_handle_hvc(struct exc_info *ctx, u32 immediate)
{
    if (!sptm.enabled)
        return false;

    if (immediate == 0)
        return sptm_handle_dispatch(ctx);

    if (immediate == SPTM_GENTER_XNU_PANIC_BEGIN)
        return sptm_handle_xnu_panic_begin(ctx);

    return sptm_handle_shadow_hvc(ctx, immediate);
}
