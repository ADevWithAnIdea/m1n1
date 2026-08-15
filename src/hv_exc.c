/* SPDX-License-Identifier: MIT */

#include "hv.h"
#include "hv_sptm.h"
#include "assert.h"
#include "cpu_regs.h"
#include "exception.h"
#include "smp.h"
#include "soc.h"
#include "string.h"
#include "uart.h"
#include "uartproxy.h"

#define TIME_ACCOUNTING

extern spinlock_t bhl;

#define _SYSREG_ISS(_1, _2, op0, op1, CRn, CRm, op2)                                               \
    (((op0) << ESR_ISS_MSR_OP0_SHIFT) | ((op1) << ESR_ISS_MSR_OP1_SHIFT) |                         \
     ((CRn) << ESR_ISS_MSR_CRn_SHIFT) | ((CRm) << ESR_ISS_MSR_CRm_SHIFT) |                         \
     ((op2) << ESR_ISS_MSR_OP2_SHIFT))
#define SYSREG_ISS(...) _SYSREG_ISS(__VA_ARGS__)

#define PERCPU(x) pcpu[mrs(TPIDR_EL2)].x

struct hv_pcpu_data {
    u32 ipi_queued;
    u32 ipi_pending;
    u32 pmc_pending;
    u64 pmc_irq_mode;
    u64 exc_entry_pmcr0_cnt;
    u64 kernel_cntv_cval;
    u64 kernel_cntv_ctl;
    u64 kernel_cntkctl_el1;
    bool kernel_cntv_valid;
    /* Soft-cached guarded impdef registers (see SYSREG_SHADOW users below). */
    u64 agtcntrdir_el1;
    u64 agtcntrdir_el12;
    u64 siq_cfg_el1;
    u64 jctl_el0;
    u64 watchdogdiag0;
    u64 impdef_c13_4;
    u64 impdef_c15_c0_4;
    u64 impdef_c15_c0_5;
    u64 impdef_c12_0;
    u64 amx_ctx_el1;
    u64 amx_ctl_el1;
    u64 amx_state_t;
    u64 gxf_config_el1;
    u64 gxf_entry_el1;
    u64 gxf_pabentry_el1;
    u64 gxf_config_el12;
    u64 gxf_entry_el12;
    u64 gxf_pabentry_el12;
    u64 gxf_tpidr_gl1;
    u64 gxf_afsr1_gl12;
    u64 gxf_vbar_gl12;
    u64 gxf_spsr_gl12;
    u64 gxf_aspsr_gl12;
    u64 gxf_esr_gl12;
    u64 gxf_elr_gl12;
    u64 gxf_far_gl12;
    u64 gxf_sp_gl12;
} ALIGNED(64);

struct hv_pcpu_data pcpu[MAX_CPUS];

static u64 hv_clpc_core_perf_ctrl2[MAX_CPUS];
static u64 hv_clpc_core_perf_enable[MAX_CPUS][8];
static u64 hv_clpc_mem_stall_cfg[MAX_CPUS][3];
static s64 hv_clpc_counter_bias[MAX_CPUS][8];

#define HV_PMCR0_READ_HVC 0x3c0

/*
 * SPRR permission-remap table, soft-cached on M4+ SoCs where the real register
 * faults at EL2. Values taken from Sven's blog post which appear to work.
 */
static u64 hv_sprr_perm_el0 = 0x2010002030100000;
static u64 hv_sprr_perm_el1 = 0x2020a506f020f0e0;
static u64 hv_sprr_umprr_el1;

#define APPLE_CNTV_FREQ 24000000ULL

/*
 * Track EL2/proxy time hidden from the guest. The architectural counter and
 * Apple CNTVCT alias run in different clock domains, so each needs its own
 * accumulator.
 */
static u64 stolen_time = 0;
static u64 stolen_time_kernel_cntv = 0;

static inline u64 hv_kernel_cntv_now(void)
{
    return mrs(SYS_IMP_APL_CNTVCT_ALIAS_EL0) - stolen_time_kernel_cntv;
}

static inline s64 hv_kernel_cntv_delta(void)
{
    return (s64)(PERCPU(kernel_cntv_cval) - hv_kernel_cntv_now());
}

void hv_rearm_soft_timer(void)
{
    if (cpu_features->apple_sysregs_unlocked || !PERCPU(kernel_cntv_valid))
        return;

    u64 ctl = PERCPU(kernel_cntv_ctl) & (CNTx_CTL_ENABLE | CNTx_CTL_IMASK);
    if (ctl != CNTx_CTL_ENABLE)
        return;

    s64 apple_delta = hv_kernel_cntv_delta();
    if (apple_delta <= 0)
        return;

    u64 frequency = mrs(CNTFRQ_EL0);
    u64 arch_delta = (u64)(((__uint128_t)(u64)apple_delta * frequency +
                            APPLE_CNTV_FREQ - 1) /
                           APPLE_CNTV_FREQ);
    u64 deadline = mrs(CNTPCT_EL0) + arch_delta;
    u64 host_ctl = mrs(CNTP_CTL_EL0);

    if (!(host_ctl & CNTx_CTL_ENABLE) ||
        (s64)(deadline - mrs(CNTP_CVAL_EL0)) < 0) {
        msr(CNTP_CVAL_EL0, deadline);
        msr(CNTP_CTL_EL0, CNTx_CTL_ENABLE);
    }
}

static void hv_kernel_cntv_init(void)
{
    if (PERCPU(kernel_cntv_valid))
        return;

    /* CTL/TVAL are readable at EL2; capture XNU's initial deadline once. */
    u32 tval = (u32)mrs(SYS_IMP_APL_KERNEL_CNTV_TVAL_EL0);
    PERCPU(kernel_cntv_ctl) =
        mrs(SYS_IMP_APL_KERNEL_CNTV_CTL_EL0) & (CNTx_CTL_ENABLE | CNTx_CTL_IMASK);
    PERCPU(kernel_cntv_cval) = hv_kernel_cntv_now() + (s64)(s32)tval;
    PERCPU(kernel_cntv_valid) = true;
    hv_rearm_soft_timer();
}

static u64 hv_kernel_cntv_read_ctl(void)
{
    hv_kernel_cntv_init();

    u64 ctl = PERCPU(kernel_cntv_ctl) & (CNTx_CTL_ENABLE | CNTx_CTL_IMASK);
    if ((ctl & CNTx_CTL_ENABLE) && hv_kernel_cntv_delta() <= 0)
        ctl |= CNTx_CTL_ISTATUS;
    return ctl;
}

static u64 hv_kernel_cntv_read_tval(void)
{
    hv_kernel_cntv_init();
    return (u32)hv_kernel_cntv_delta();
}

static void hv_kernel_cntv_write_ctl(u64 val)
{
    hv_kernel_cntv_init();
    PERCPU(kernel_cntv_ctl) = val & (CNTx_CTL_ENABLE | CNTx_CTL_IMASK);
    hv_rearm_soft_timer();
}

static void hv_kernel_cntv_write_tval(u64 val)
{
    hv_kernel_cntv_init();
    PERCPU(kernel_cntv_cval) = hv_kernel_cntv_now() + (s64)(s32)(u32)val;
    hv_rearm_soft_timer();
}

static bool hv_kernel_cntv_pending(void)
{
    if (!PERCPU(kernel_cntv_valid))
        return false;

    u64 ctl = hv_kernel_cntv_read_ctl();
    return (ctl & (CNTx_CTL_ISTATUS | CNTx_CTL_IMASK | CNTx_CTL_ENABLE)) ==
           (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE);
}

#define KERNEL_CNTKCTL_MASK                                                                       \
    (CNTHCTL_EL0PCTEN | CNTHCTL_EL0VCTEN | CNTHCTL_EVNTI | CNTHCTL_EVNTDIR | CNTHCTL_EVNTEN)

static bool hv_handle_kernel_cntkctl(struct exc_info *ctx, u64 rt, bool is_read)
{
    if (is_read) {
        if (rt < 31)
            ctx->regs[rt] = PERCPU(kernel_cntkctl_el1);
        return true;
    }

    u64 val = rt < 31 ? ctx->regs[rt] : 0;
    PERCPU(kernel_cntkctl_el1) = val;

    // Rescale the event bit from XNU's 24 MHz counter to CNTFRQ_EL0.
    u64 cntkctl = val & KERNEL_CNTKCTL_MASK;
    if (val & CNTHCTL_EVNTEN) {
        u32 apple_index = FIELD_GET(CNTHCTL_EVNTI, val);
        u64 apple_period = 1ULL << (apple_index + 1);
        u64 arch_period =
            (apple_period * mrs(CNTFRQ_EL0) + APPLE_CNTV_FREQ / 2) / APPLE_CNTV_FREQ;
        u32 arch_index = 0;
        u64 candidate_period = 2;

        while (arch_index < 15 && candidate_period < arch_period) {
            candidate_period <<= 1;
            arch_index++;
        }
        if (arch_index && candidate_period >= arch_period &&
            arch_period - (candidate_period >> 1) < candidate_period - arch_period)
            arch_index--;

        cntkctl &= ~CNTHCTL_EVNTI;
        cntkctl |= FIELD_PREP(CNTHCTL_EVNTI, arch_index);
    }

    msr(SYS_CNTKCTL_EL12, (mrs(SYS_CNTKCTL_EL12) & ~KERNEL_CNTKCTL_MASK) | cntkctl);
    sysop("isb");
    return true;
}

static bool hv_handle_pmcr0(struct exc_info *ctx, u32 rt, bool is_read)
{
    u64 value = rt < 31 ? ctx->regs[rt] : 0;

    if (is_read) {
        value = (mrs(SYS_IMP_APL_PMCR0) & ~PMCR0_IMODE_MASK) |
                PERCPU(pmc_irq_mode);
        if (PERCPU(pmc_pending))
            value |= PMCR0_IACT;
        if (rt < 31)
            ctx->regs[rt] = value;
    } else {
        PERCPU(pmc_pending) = !!(value & PMCR0_IACT);
        PERCPU(pmc_irq_mode) = value & PMCR0_IMODE_MASK;
        msr(SYS_IMP_APL_PMCR0, value);
    }

    return true;
}

bool hv_handle_pmc_hvc(struct exc_info *ctx, u32 immediate)
{
    return hv_handle_pmcr0(ctx, immediate & 0x1f, immediate >= HV_PMCR0_READ_HVC);
}

void hv_exit_guest(void) __attribute__((noreturn));

static u64 exc_entry_time;

extern u64 hv_cpus_in_guest;
extern int hv_pinned_cpu;
extern int hv_want_cpu;

static bool time_stealing = true;

static void _hv_exc_proxy(struct exc_info *ctx, uartproxy_boot_reason_t reason, u32 type,
                          void *extra)
{
    int from_el = FIELD_GET(SPSR_M, ctx->spsr) >> 2;

    hv_wdt_breadcrumb('P');

    /*
     * Get all the CPUs into the HV before running the proxy, to make sure they all exit to
     * the guest with a consistent time offset.
     */
    if (time_stealing)
        hv_rendezvous();

    u64 entry_time = mrs(CNTPCT_EL0);
    u64 kernel_cntv_entry_time = mrs(SYS_IMP_APL_CNTVCT_ALIAS_EL0);

    ctx->elr_phys = hv_translate(ctx->elr, false, false, NULL);
    ctx->far_phys = hv_translate(ctx->far, false, false, NULL);
    ctx->sp_phys = hv_translate(from_el == 0 ? ctx->sp[0] : ctx->sp[1], false, false, NULL);
    ctx->extra = extra;

    struct uartproxy_msg_start start = {
        .reason = reason,
        .code = type,
        .info = ctx,
    };

    hv_wdt_suspend();
    int ret = uartproxy_run(&start);
    hv_wdt_resume();

    switch (ret) {
        case EXC_RET_HANDLED:
            hv_wdt_breadcrumb('p');
            if (time_stealing) {
                stolen_time += mrs(CNTPCT_EL0) - entry_time;
                stolen_time_kernel_cntv += mrs(SYS_IMP_APL_CNTVCT_ALIAS_EL0) -
                                           kernel_cntv_entry_time;
            }
            break;
        case EXC_EXIT_GUEST:
            hv_rendezvous();
            spin_unlock(&bhl);
            hv_exit_guest(); // does not return
        default:
            printf("Guest exception not handled, rebooting.\n");
            print_regs(ctx->regs, 0);
            flush_and_reboot(); // does not return
    }
}

static void hv_maybe_switch_cpu(struct exc_info *ctx, uartproxy_boot_reason_t reason, u32 type,
                                void *extra)
{
    while (hv_want_cpu != -1) {
        if (hv_want_cpu == smp_id()) {
            hv_want_cpu = -1;
            _hv_exc_proxy(ctx, reason, type, extra);
        } else {
            // Unlock the HV so the target CPU can get into the proxy
            spin_unlock(&bhl);
            while (hv_want_cpu != -1)
                sysop("dmb sy");
            spin_lock(&bhl);
        }
    }
}

void hv_exc_proxy(struct exc_info *ctx, uartproxy_boot_reason_t reason, u32 type, void *extra)
{
    /*
     * Wait while another CPU is pinned or being switched to.
     * If a CPU switch is requested, handle it before actually handling the
     * exception. We still tell the host the real reason code, though.
     */
    while ((hv_pinned_cpu != -1 && hv_pinned_cpu != smp_id()) || hv_want_cpu != -1) {
        if (hv_want_cpu == smp_id()) {
            hv_want_cpu = -1;
            _hv_exc_proxy(ctx, reason, type, extra);
        } else {
            // Unlock the HV so the target CPU can get into the proxy
            spin_unlock(&bhl);
            while ((hv_pinned_cpu != -1 && hv_pinned_cpu != smp_id()) || hv_want_cpu != -1)
                sysop("dmb sy");
            spin_lock(&bhl);
        }
    }

    /* Handle the actual exception */
    _hv_exc_proxy(ctx, reason, type, extra);

    /*
     * If as part of handling this exception we want to switch CPUs, handle it without returning
     * to the guest.
     */
    hv_maybe_switch_cpu(ctx, reason, type, extra);
}

void hv_set_time_stealing(bool enabled, bool reset)
{
    time_stealing = enabled;
    if (reset) {
        stolen_time = 0;
        stolen_time_kernel_cntv = 0;
    }
    hv_apply_time_stealing_offset();
}

void hv_apply_time_stealing_offset(void)
{
    msr(CNTVOFF_EL2, stolen_time);
    if (!cpu_features->apple_sysregs_unlocked)
        hv_rearm_soft_timer();
}

void hv_add_time(s64 time)
{
    u64 ticks = time < 0 ? (u64)-time : (u64)time;
    u64 kernel_ticks =
        (u64)((__uint128_t)ticks * APPLE_CNTV_FREQ / mrs(CNTFRQ_EL0));

    stolen_time -= (u64)time;
    if (time < 0)
        stolen_time_kernel_cntv += kernel_ticks;
    else
        stolen_time_kernel_cntv -= kernel_ticks;

    if (!cpu_features->apple_sysregs_unlocked)
        hv_rearm_soft_timer();
}

static void hv_update_fiq(void)
{
    u64 hcr = mrs(HCR_EL2);
    bool fiq_pending = false;

    if (mrs(CNTP_CTL_EL02) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        fiq_pending = true;
        reg_clr(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_P);
    } else {
        reg_set(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_P);
    }

    if (mrs(CNTV_CTL_EL02) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        fiq_pending = true;
        reg_clr(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_V);
    } else {
        reg_set(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_V);
    }

    fiq_pending |= PERCPU(ipi_pending) || PERCPU(pmc_pending);
    fiq_pending |= hv_kernel_cntv_pending();

    sysop("isb");

    if ((hcr & HCR_VF) && !fiq_pending) {
        hv_write_hcr(hcr & ~HCR_VF);
    } else if (!(hcr & HCR_VF) && fiq_pending) {
        hv_write_hcr(hcr | HCR_VF);
    }

}

#define SYSREG_MAP(sr, to)                                                                         \
    case SYSREG_ISS(sr):                                                                           \
        if (is_read)                                                                               \
            regs[rt] = _mrs(sr_tkn(to));                                                           \
        else                                                                                       \
            _msr(sr_tkn(to), regs[rt]);                                                            \
        return true;

#define SYSREG_PASS(sr)                                                                            \
    case SYSREG_ISS(sr):                                                                           \
        if (is_read)                                                                               \
            regs[rt] = _mrs(sr_tkn(sr));                                                           \
        else                                                                                       \
            _msr(sr_tkn(sr), regs[rt]);                                                            \
        return true;

/*
 * Soft-cache a guarded Apple impdef register: return the last value the guest
 * wrote (or the seeded reset default on first read) and swallow the write.
 * This drops the register's hardware side effect entirely.  `store` is any
 * lvalue: PERCPU(field) for per-CPU state, or a static global seeded with the
 * reset value the guest expects to read back.
 */
#define SYSREG_SHADOW(sr, store)                                                                   \
    case SYSREG_ISS(sr):                                                                           \
        if (is_read)                                                                               \
            regs[rt] = (store);                                                                    \
        else                                                                                       \
            (store) = regs[rt];                                                                    \
        return true;

static bool hv_handle_clpc_counter(struct exc_info *ctx, u64 rt, bool is_read, unsigned int counter)
{
    /*
     * Apple's PMGR kext consumes these as perf/power deltas. Live EL2 access
     * is unsafe in the current T8140/SPTM context, so provide coherent
     * monotonic guest-visible counters.
     */
    u64 cpu = mrs(TPIDR_EL2);
    u64 base = mrs(CNTPCT_EL0) + (counter * 0x1000000ULL);

    if (is_read) {
        if (rt < 31)
            ctx->regs[rt] = (u64)((s64)base + hv_clpc_counter_bias[cpu][counter]);
    } else {
        u64 val = rt < 31 ? ctx->regs[rt] : 0;
        hv_clpc_counter_bias[cpu][counter] = (s64)val - (s64)base;
    }

    return true;
}

static bool hv_handle_clpc_mem_stall_config(struct exc_info *ctx, u64 rt, bool is_read,
                                            unsigned int regno)
{
    /*
     * Apple's PMGR kext programs these CoreMemStallSampler controls with
     * read/modify/write. Keep readback coherent, but do not touch live EL2
     * hardware registers.
     */
    u64 cpu = mrs(TPIDR_EL2);
    u64 *cache = &hv_clpc_mem_stall_cfg[cpu][regno];

    if (is_read) {
        if (rt < 31)
            ctx->regs[rt] = *cache;
    } else {
        *cache = rt < 31 ? ctx->regs[rt] : 0;
    }

    return true;
}

static bool hv_handle_clpc_core_perf_ctrl2(struct exc_info *ctx, u64 rt, bool is_read)
{
    /*
     * Another sysreg used by Apple's PMGR. XNU only needs coherent state here;
     * live execution faults in this raw guest path.
     */
    u64 cpu = mrs(TPIDR_EL2);

    if (is_read) {
        if (rt < 31)
            ctx->regs[rt] = hv_clpc_core_perf_ctrl2[cpu];
    } else {
        hv_clpc_core_perf_ctrl2[cpu] = rt < 31 ? ctx->regs[rt] : 0;
    }

    return true;
}

static bool hv_handle_clpc_core_perf_enable(struct exc_info *ctx, u64 rt, bool is_read,
                                            unsigned int channel)
{
    u64 cpu = mrs(TPIDR_EL2);
    u64 *cache = &hv_clpc_core_perf_enable[cpu][channel];

    if (is_read) {
        if (rt < 31)
            ctx->regs[rt] = *cache;
    } else {
        *cache = rt < 31 ? ctx->regs[rt] : 0;
    }

    return true;
}

static bool hv_handle_gxf_shadow(struct exc_info *ctx, u64 reg, u64 rt, bool is_read)
{
    u64 *value;

    switch (reg) {
        case SYSREG_ISS(SYS_IMP_APL_GXF_STATUS_EL1):
            if (is_read && rt < 31)
                ctx->regs[rt] = 0;
            return is_read;
        case SYSREG_ISS(SYS_IMP_APL_GXF_CONFIG_EL1):
            value = &PERCPU(gxf_config_el1);
            break;
        case SYSREG_ISS(SYS_IMP_APL_GXF_ENTER_EL1):
            value = &PERCPU(gxf_entry_el1);
            break;
        case SYSREG_ISS(SYS_IMP_APL_GXF_ABORT_EL1):
            value = &PERCPU(gxf_pabentry_el1);
            break;
        case SYSREG_ISS(SYS_IMP_APL_GXF_CONFIG_EL12):
            value = &PERCPU(gxf_config_el12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_GXF_ENTER_EL12):
            value = &PERCPU(gxf_entry_el12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_GXF_ABORT_EL12):
            value = &PERCPU(gxf_pabentry_el12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_TPIDR_GL1):
            value = &PERCPU(gxf_tpidr_gl1);
            break;
        case SYSREG_ISS(SYS_IMP_APL_AFSR1_GL1):
        case SYSREG_ISS(SYS_IMP_APL_AFSR1_GL12):
            value = &PERCPU(gxf_afsr1_gl12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_VBAR_GL1):
        case SYSREG_ISS(SYS_IMP_APL_VBAR_GL12):
            value = &PERCPU(gxf_vbar_gl12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_SPSR_GL1):
        case SYSREG_ISS(SYS_IMP_APL_SPSR_GL12):
            value = &PERCPU(gxf_spsr_gl12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_ASPSR_GL1):
        case SYSREG_ISS(SYS_IMP_APL_ASPSR_GL12):
            value = &PERCPU(gxf_aspsr_gl12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_ESR_GL1):
        case SYSREG_ISS(SYS_IMP_APL_ESR_GL12):
            value = &PERCPU(gxf_esr_gl12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_ELR_GL1):
        case SYSREG_ISS(SYS_IMP_APL_ELR_GL12):
            value = &PERCPU(gxf_elr_gl12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_FAR_GL1):
        case SYSREG_ISS(SYS_IMP_APL_FAR_GL12):
            value = &PERCPU(gxf_far_gl12);
            break;
        case SYSREG_ISS(SYS_IMP_APL_SP_GL12):
            value = &PERCPU(gxf_sp_gl12);
            break;
        default:
            return false;
    }

    if (is_read) {
        if (rt < 31)
            ctx->regs[rt] = *value;
    } else {
        *value = rt < 31 ? ctx->regs[rt] : 0;
    }
    return true;
}

bool hv_handle_clpc_hvc(struct exc_info *ctx, u32 immediate)
{
    u32 operation = (immediate - 0x400) >> 5;
    u32 rt = immediate & 0x1f;
    bool is_read = operation & 1;
    u32 reg = operation >> 1;

    if (reg < 16) {
        if (reg & 1)
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, reg >> 1);
        return hv_handle_clpc_counter(ctx, rt, is_read, reg >> 1);
    }

    switch (reg) {
        case 16:
            return hv_handle_clpc_core_perf_ctrl2(ctx, rt, is_read);
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
            return hv_handle_clpc_counter(ctx, rt, is_read, reg - 17);
        case 22:
        case 23:
        case 24:
            return hv_handle_clpc_mem_stall_config(ctx, rt, is_read, reg - 22);
        default:
            __builtin_unreachable();
    }
}

bool hv_handle_objc_bp_hvc(struct exc_info *ctx, u32 immediate)
{
    u32 operation = (immediate - 0xa40) >> 5;
    u32 rt = immediate & 0x1f;
    bool is_read = operation & 1;
    u64 *value = operation < 2 ? &PERCPU(impdef_c15_c0_4) : &PERCPU(impdef_c15_c0_5);

    if (is_read) {
        if (rt < 31)
            ctx->regs[rt] = *value;
    } else {
        *value = rt < 31 ? ctx->regs[rt] : 0;
    }

    return true;
}

static bool hv_handle_msr_unlocked(struct exc_info *ctx, u64 iss)
{
    u64 reg = iss & (ESR_ISS_MSR_OP0 | ESR_ISS_MSR_OP2 | ESR_ISS_MSR_OP1 | ESR_ISS_MSR_CRn |
                     ESR_ISS_MSR_CRm);
    u64 rt = FIELD_GET(ESR_ISS_MSR_Rt, iss);
    bool is_read = iss & ESR_ISS_MSR_DIR;

    u64 *regs = ctx->regs;
    regs[31] = 0;

    if (!cpu_features->apple_sysregs_unlocked &&
        hv_handle_gxf_shadow(ctx, reg, rt, is_read))
        return true;

    switch (reg) {
        SYSREG_PASS(SYS_IMP_APL_CORE_NRG_ACC_DAT);
        SYSREG_PASS(SYS_IMP_APL_CORE_SRM_NRG_ACC_DAT);
        /* Architectural timer, for ECV */
        SYSREG_MAP(SYS_CNTV_CTL_EL0, SYS_CNTV_CTL_EL02)
        SYSREG_MAP(SYS_CNTV_CVAL_EL0, SYS_CNTV_CVAL_EL02)
        SYSREG_MAP(SYS_CNTV_TVAL_EL0, SYS_CNTV_TVAL_EL02)
        SYSREG_MAP(SYS_CNTP_CTL_EL0, SYS_CNTP_CTL_EL02)
        SYSREG_MAP(SYS_CNTP_CVAL_EL0, SYS_CNTP_CVAL_EL02)
        SYSREG_MAP(SYS_CNTP_TVAL_EL0, SYS_CNTP_TVAL_EL02)
        /* Software-model the write-locked Apple deadline timer. */
        case SYSREG_ISS(SYS_IMP_APL_KERNEL_CNTV_CTL_EL0):
            if (is_read)
                regs[rt] = hv_kernel_cntv_read_ctl();
            else
                hv_kernel_cntv_write_ctl(regs[rt]);
            return true;
        case SYSREG_ISS(SYS_IMP_APL_KERNEL_CNTV_TVAL_EL0):
            if (is_read)
                regs[rt] = hv_kernel_cntv_read_tval();
            else
                hv_kernel_cntv_write_tval(regs[rt]);
            return true;
        case SYSREG_ISS(SYS_IMP_APL_KERNEL_CNTKCTL_EL1):
            return hv_handle_kernel_cntkctl(ctx, rt, is_read);
        SYSREG_PASS(SYS_IMP_APL_KERNEL_CNTVCT_EL0)
        /* Spammy stuff seen on t600x p-cores */
        /* These are PMU/PMC registers */
        SYSREG_PASS(sys_reg(3, 2, 15, 12, 0));
        SYSREG_PASS(sys_reg(3, 2, 15, 13, 0));
        SYSREG_PASS(sys_reg(3, 2, 15, 14, 0));
        SYSREG_PASS(sys_reg(3, 2, 15, 15, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 7, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 8, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 9, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 10, 0));
        /* Noisy traps */
        SYSREG_PASS(SYS_IMP_APL_HID4)
        SYSREG_PASS(SYS_IMP_APL_EHID4)
        /* We don't normally trap these, but if we do, they're noisy */
        SYSREG_PASS(SYS_IMP_APL_GXF_STATUS_EL1)
        SYSREG_PASS(SYS_IMP_APL_CNTVCT_ALIAS_EL0)
        SYSREG_PASS(SYS_IMP_APL_TPIDR_GL1)
        SYSREG_MAP(SYS_IMP_APL_SPSR_GL1, SYS_IMP_APL_SPSR_GL12)
        SYSREG_MAP(SYS_IMP_APL_ASPSR_GL1, SYS_IMP_APL_ASPSR_GL12)
        SYSREG_MAP(SYS_IMP_APL_ELR_GL1, SYS_IMP_APL_ELR_GL12)
        SYSREG_MAP(SYS_IMP_APL_ESR_GL1, SYS_IMP_APL_ESR_GL12)
        /*
         * SPRR permission remapping. On unlocked SoCs, redirect to the EL12
         * alias as before; on M4+ SoCs the register faults at EL2, so
         * soft-cache it
         */
        case SYSREG_ISS(SYS_IMP_APL_SPRR_PERM_EL0):
            if (is_read)
                regs[rt] = hv_sprr_perm_el0;
            else
                hv_sprr_perm_el0 = regs[rt];
            return true;
        case SYSREG_ISS(SYS_IMP_APL_SPRR_PERM_EL1):
            if (cpu_features->apple_sysregs_unlocked) {
                if (is_read)
                    regs[rt] = _mrs(sr_tkn(SYS_IMP_APL_SPRR_PERM_EL12));
                else
                    _msr(sr_tkn(SYS_IMP_APL_SPRR_PERM_EL12), regs[rt]);
            } else if (is_read) {
                regs[rt] = hv_sprr_perm_el1;
            } else {
                hv_sprr_perm_el1 = regs[rt];
            }
            return true;
        case SYSREG_ISS(SYS_IMP_APL_SPRR_UMPRR_EL1):
            if (is_read)
                regs[rt] = hv_sprr_umprr_el1 & 0xffffffff;
            else
                hv_sprr_umprr_el1 = regs[rt] & 0xffffffff;
            return true;
        /*
         * Impdef sysregs locked on M4+ that are required by XNU
         */
        SYSREG_SHADOW(SYS_IMP_APL_AGTCNTRDIR_EL1, PERCPU(agtcntrdir_el1))
        SYSREG_SHADOW(SYS_IMP_APL_AGTCNTRDIR_EL12, PERCPU(agtcntrdir_el12))
        SYSREG_SHADOW(SYS_IMP_APL_SIQ_CFG_EL1, PERCPU(siq_cfg_el1))
        SYSREG_SHADOW(SYS_IMP_APL_JCTL_EL0, PERCPU(jctl_el0))
        SYSREG_SHADOW(SYS_IMP_APL_WATCHDOGDIAG0, PERCPU(watchdogdiag0))
        SYSREG_SHADOW(SYS_IMP_APL_S3_1_C15_C13_4, PERCPU(impdef_c13_4))
        SYSREG_SHADOW(SYS_IMP_APL_S3_6_C15_C0_4, PERCPU(impdef_c15_c0_4))
        SYSREG_SHADOW(SYS_IMP_APL_S3_6_C15_C0_5, PERCPU(impdef_c15_c0_5))
        SYSREG_SHADOW(SYS_IMP_APL_S3_4_C15_C12_0, PERCPU(impdef_c12_0))
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF0):
            return hv_handle_clpc_counter(ctx, rt, is_read, 0);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF1):
            return hv_handle_clpc_counter(ctx, rt, is_read, 1);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF2):
            return hv_handle_clpc_counter(ctx, rt, is_read, 2);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF3):
            return hv_handle_clpc_counter(ctx, rt, is_read, 3);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF4):
            return hv_handle_clpc_counter(ctx, rt, is_read, 4);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF5):
            return hv_handle_clpc_counter(ctx, rt, is_read, 5);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF6):
            return hv_handle_clpc_counter(ctx, rt, is_read, 6);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF7):
            return hv_handle_clpc_counter(ctx, rt, is_read, 7);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_ACC0):
            return hv_handle_clpc_counter(ctx, rt, is_read, 0);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_ACC1):
            return hv_handle_clpc_counter(ctx, rt, is_read, 1);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_ACC2):
            return hv_handle_clpc_counter(ctx, rt, is_read, 2);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_ACC3):
            return hv_handle_clpc_counter(ctx, rt, is_read, 3);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_ACC4):
            return hv_handle_clpc_counter(ctx, rt, is_read, 4);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE0):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 0);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE1):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 1);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE2):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 2);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE3):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 3);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE4):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 4);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE5):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 5);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE6):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 6);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_ENABLE7):
            return hv_handle_clpc_core_perf_enable(ctx, rt, is_read, 7);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_CORE_PERF_CTRL2):
            return hv_handle_clpc_core_perf_ctrl2(ctx, rt, is_read);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_MEM_STALL_CFG0):
            return hv_handle_clpc_mem_stall_config(ctx, rt, is_read, 0);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_MEM_STALL_CFG1):
            return hv_handle_clpc_mem_stall_config(ctx, rt, is_read, 1);
        case SYSREG_ISS(SYS_IMP_APL_CLPC_MEM_STALL_CFG2):
            return hv_handle_clpc_mem_stall_config(ctx, rt, is_read, 2);
        SYSREG_MAP(SYS_IMP_APL_APCTL_EL1, SYS_IMP_APL_APCTL_EL12)
         // Raw boot locks us out of AMX, fake it enough to boot XNU
         // We'll tell userspace we don't have it once booted
        case SYSREG_ISS(SYS_IMP_APL_AMXIDR_EL1):
            if (!is_read)
                return false;
            if (cpu_features->apple_sysregs_unlocked)
                regs[rt] = _mrs(sr_tkn(SYS_IMP_APL_AMXIDR_EL1));
            else
                regs[rt] = BIT(5); /* AMX v6 */
            return true;
        SYSREG_SHADOW(SYS_IMP_APL_AMX_CTX_EL1, PERCPU(amx_ctx_el1))
        case SYSREG_ISS(SYS_IMP_APL_AMX_CTL_EL1):
            if (cpu_features->apple_sysregs_unlocked) {
                if (is_read)
                    regs[rt] = _mrs(sr_tkn(SYS_IMP_APL_AMX_CTL_EL12));
                else
                    _msr(sr_tkn(SYS_IMP_APL_AMX_CTL_EL12), regs[rt]);
            } else if (is_read) {
                regs[rt] = PERCPU(amx_ctl_el1);
            } else {
                PERCPU(amx_ctl_el1) = regs[rt];
            }
            return true;
        case SYSREG_ISS(SYS_IMP_APL_AMX_STATE_T):
            if (cpu_features->apple_sysregs_unlocked) {
                if (is_read)
                    regs[rt] = _mrs(sr_tkn(SYS_IMP_APL_AMX_STATE_T));
                else
                    _msr(sr_tkn(SYS_IMP_APL_AMX_STATE_T), regs[rt]);
            } else if (is_read) {
                regs[rt] = PERCPU(amx_state_t);
            } else {
                PERCPU(amx_state_t) = regs[rt];
            }
            return true;
        /* pass through PMU handling */
        SYSREG_PASS(SYS_IMP_APL_PMCR1)
        SYSREG_PASS(SYS_IMP_APL_PMCR2)
        SYSREG_PASS(SYS_IMP_APL_PMCR3)
        SYSREG_PASS(SYS_IMP_APL_PMCR4)
        SYSREG_PASS(SYS_IMP_APL_PMESR0)
        SYSREG_PASS(SYS_IMP_APL_PMESR1)
        SYSREG_PASS(SYS_IMP_APL_PMSR)
#ifndef DEBUG_PMU_IRQ
        SYSREG_PASS(SYS_IMP_APL_PMC0)
#endif
        SYSREG_PASS(SYS_IMP_APL_PMC1)
        SYSREG_PASS(SYS_IMP_APL_PMC2)
        SYSREG_PASS(SYS_IMP_APL_PMC3)
        SYSREG_PASS(SYS_IMP_APL_PMC4)
        SYSREG_PASS(SYS_IMP_APL_PMC5)
        SYSREG_PASS(SYS_IMP_APL_PMC6)
        SYSREG_PASS(SYS_IMP_APL_PMC7)
        SYSREG_PASS(SYS_IMP_APL_PMC8)
        SYSREG_PASS(SYS_IMP_APL_PMC9)

        /* Outer Sharable TLB maintenance instructions */
        SYSREG_PASS(sys_reg(1, 0, 8, 1, 0)) // TLBI VMALLE1OS
        SYSREG_PASS(sys_reg(1, 0, 8, 1, 1)) // TLBI VAE1OS
        SYSREG_PASS(sys_reg(1, 0, 8, 1, 2)) // TLBI ASIDE1OS
        SYSREG_PASS(sys_reg(1, 0, 8, 5, 1)) // TLBI RVAE1OS

        case SYSREG_ISS(SYS_ACTLR_EL1):
            if (is_read) {
                if (cpu_features->actlr_el2)
                    regs[rt] = mrs(SYS_ACTLR_EL12);
                else
                    regs[rt] = mrs(SYS_IMP_APL_ACTLR_EL12);
            } else {
                if (cpu_features->actlr_el2)
                    msr(SYS_ACTLR_EL12, regs[rt]);
                else
                    msr(SYS_IMP_APL_ACTLR_EL12, regs[rt]);
            }
            return true;

        case SYSREG_ISS(SYS_IMP_APL_IPI_SR_EL1):
            if (is_read)
                regs[rt] = PERCPU(ipi_pending) ? IPI_SR_PENDING : 0;
            else if (regs[rt] & IPI_SR_PENDING)
                PERCPU(ipi_pending) = false;
            return true;

        /* shadow the interrupt mode and state flag */
        case SYSREG_ISS(SYS_IMP_APL_PMCR0):
            return hv_handle_pmcr0(ctx, rt, is_read);

        /*
         * Handle this one here because m1n1/Linux (will) use it for explicit cpuidle.
         * We can pass it through; going into deep sleep doesn't break the HV since we
         * don't do any wfis that assume otherwise in m1n1. However, don't het macOS
         * disable WFI ret (when going into systemwide sleep), since that breaks things.
         */
        case SYSREG_ISS(SYS_IMP_APL_CYC_OVRD):
            if (is_read) {
                regs[rt] = mrs(SYS_IMP_APL_CYC_OVRD);
            } else {
                if (regs[rt] & (CYC_OVRD_DISABLE_WFI_RET | CYC_OVRD_FIQ_MODE_MASK))
                    return false;
                msr(SYS_IMP_APL_CYC_OVRD, regs[rt]);
            }
            return true;
            /* clang-format off */
        /* IPI handling */
        SYSREG_PASS(SYS_IMP_APL_IPI_CR_EL1)
        /* M1RACLES reg, handle here due to silly 12.0 "mitigation" */
        case SYSREG_ISS(sys_reg(3, 5, 15, 10, 1)):
            if (is_read)
                regs[rt] = 0;
            return true;
    }
    return false;
}

static bool hv_handle_msr(struct exc_info *ctx, u64 iss)
{
    u64 reg = iss & (ESR_ISS_MSR_OP0 | ESR_ISS_MSR_OP2 | ESR_ISS_MSR_OP1 | ESR_ISS_MSR_CRn |
                     ESR_ISS_MSR_CRm);
    u64 rt = FIELD_GET(ESR_ISS_MSR_Rt, iss);
    bool is_read = iss & ESR_ISS_MSR_DIR;

    u64 *regs = ctx->regs;

    regs[31] = 0;

    switch (reg) {
        /* clang-format on */
        case SYSREG_ISS(SYS_IMP_APL_IPI_RR_LOCAL_EL1): {
            assert(!is_read);
            u64 mpidr = (regs[rt] & 0xff) | (mrs(MPIDR_EL1) & 0xffff00);
            for (int i = 0; i < MAX_CPUS; i++)
                if (mpidr == smp_get_mpidr(i)) {
                    pcpu[i].ipi_queued = true;
                    msr(SYS_IMP_APL_IPI_RR_LOCAL_EL1, regs[rt]);
                    return true;
                }
            return false;
        }
        case SYSREG_ISS(SYS_IMP_APL_IPI_RR_GLOBAL_EL1):
            assert(!is_read);
            u64 mpidr = (regs[rt] & 0xff) | ((regs[rt] & 0xff0000) >> 8);
            for (int i = 0; i < MAX_CPUS; i++) {
                if (mpidr == (smp_get_mpidr(i) & 0xffff)) {
                    pcpu[i].ipi_queued = true;
                    msr(SYS_IMP_APL_IPI_RR_GLOBAL_EL1, regs[rt]);
                    return true;
                }
            }
            return false;
#ifdef DEBUG_PMU_IRQ
        case SYSREG_ISS(SYS_IMP_APL_PMC0):
            if (is_read) {
                regs[rt] = mrs(SYS_IMP_APL_PMC0);
            } else {
                msr(SYS_IMP_APL_PMC0, regs[rt]);
                printf("msr(SYS_IMP_APL_PMC0, 0x%04lx_%08lx)\n", regs[rt] >> 32,
                       regs[rt] & 0xFFFFFFFF);
            }
            return true;
#endif
    }

    return false;
}

static void hv_get_context(struct exc_info *ctx)
{
    ctx->spsr = hv_get_spsr();
    ctx->elr = hv_get_elr();
    ctx->esr = hv_get_esr();
    ctx->far = hv_get_far();
    ctx->afsr1 = hv_get_afsr1();
    ctx->sp[0] = mrs(SP_EL0);
    ctx->sp[1] = mrs(SP_EL1);
    ctx->sp[2] = (u64)ctx;
    ctx->cpu_id = smp_id();
    ctx->mpidr = mrs(MPIDR_EL1);

    sysop("isb");
}

static void hv_exc_entry(void)
{
    // Enable SErrors in the HV, but only if not already pending
    if (!(mrs(ISR_EL1) & 0x100))
        sysop("msr daifclr, 4");

    __atomic_and_fetch(&hv_cpus_in_guest, ~BIT(smp_id()), __ATOMIC_ACQUIRE);
    spin_lock(&bhl);
    hv_wdt_breadcrumb('X');
    exc_entry_time = mrs(CNTPCT_EL0);
    /* disable PMU counters in the hypervisor */
    u64 pmcr0 = mrs(SYS_IMP_APL_PMCR0);
    PERCPU(exc_entry_pmcr0_cnt) = pmcr0 & PMCR0_CNT_MASK;
    msr(SYS_IMP_APL_PMCR0, pmcr0 & ~PMCR0_CNT_MASK);
}

static void hv_exc_exit(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('x');
    hv_update_fiq();
    /* reenable PMU counters */
    reg_set(SYS_IMP_APL_PMCR0, PERCPU(exc_entry_pmcr0_cnt));
    hv_apply_time_stealing_offset();
    spin_unlock(&bhl);
    hv_maybe_exit();
    __atomic_or_fetch(&hv_cpus_in_guest, BIT(smp_id()), __ATOMIC_ACQUIRE);

    hv_set_spsr(ctx->spsr);
    hv_set_elr(ctx->elr);
    msr(SP_EL0, ctx->sp[0]);
    msr(SP_EL1, ctx->sp[1]);
}

void hv_exc_sync(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('S');
    hv_get_context(ctx);
    bool handled = false;
    u32 ec = FIELD_GET(ESR_EC, ctx->esr);

    bool advance = true;

    switch (ec) {
        case ESR_EC_MSR:
            hv_wdt_breadcrumb('m');
            handled = hv_handle_msr_unlocked(ctx, FIELD_GET(ESR_ISS, ctx->esr));
            break;
        case ESR_EC_IMPDEF:
            hv_wdt_breadcrumb('a');
            switch (FIELD_GET(ESR_ISS, ctx->esr)) {
                case ESR_ISS_IMPDEF_MSR:
                    handled = hv_handle_msr_unlocked(ctx, ctx->afsr1);
                    break;
            }
            break;
    }

    if (handled) {
        hv_wdt_breadcrumb('#');
        ctx->elr += 4;
        hv_set_elr(ctx->elr);
        hv_update_fiq();
        hv_wdt_breadcrumb('s');
        return;
    }

    hv_exc_entry();

    switch (ec) {
        case ESR_EC_DABORT_LOWER:
            hv_wdt_breadcrumb('D');
            handled = hv_handle_dabort(ctx);
            break;
        case ESR_EC_MSR:
            hv_wdt_breadcrumb('M');
            handled = hv_handle_msr(ctx, FIELD_GET(ESR_ISS, ctx->esr));
            break;
        case ESR_EC_IMPDEF:
            hv_wdt_breadcrumb('A');
            switch (FIELD_GET(ESR_ISS, ctx->esr)) {
                case ESR_ISS_IMPDEF_MSR:
                    handled = hv_handle_msr(ctx, ctx->afsr1);
                    break;
            }
            break;
        case ESR_EC_HVC:
            hv_wdt_breadcrumb('H');
            handled = hv_sptm_handle_hvc(ctx, FIELD_GET(ESR_ISS, ctx->esr) & 0xffff);
            advance = false;
            break;
    }

    if (handled) {
        hv_wdt_breadcrumb('+');
        if (advance)
            ctx->elr += 4;
    } else {
        hv_wdt_breadcrumb('-');
        // VM code can forward a nested SError exception here
        if (FIELD_GET(ESR_EC, ctx->esr) == ESR_EC_SERROR)
            hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_SERROR, NULL);
        else
            hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_SYNC, NULL);
    }

    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('s');
}

void hv_exc_irq(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('I');
    hv_get_context(ctx);
    hv_exc_entry();
    hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_IRQ, NULL);
    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('i');
}

void hv_exc_fiq(struct exc_info *ctx)
{
    bool tick = false;

    hv_maybe_exit();

    if (mrs(CNTP_CTL_EL0) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        msr(CNTP_CTL_EL0, CNTx_CTL_ISTATUS | CNTx_CTL_IMASK | CNTx_CTL_ENABLE);
        tick = true;
    }

    int interruptible_cpu = hv_pinned_cpu;
    if (interruptible_cpu == -1)
        interruptible_cpu = boot_cpu_idx;

    if (smp_id() != interruptible_cpu && !(mrs(ISR_EL1) & 0x40) && hv_want_cpu == -1) {
        // Non-interruptible CPU and it was just a timer tick (or spurious), so just update FIQs
        hv_update_fiq();
        hv_arm_tick(true);
        return;
    }

    // Slow (single threaded) path
    hv_wdt_breadcrumb('F');
    hv_get_context(ctx);
    hv_exc_entry();

    // Only poll for HV events in the interruptible CPU
    if (tick) {
        if (smp_id() == interruptible_cpu) {
            hv_tick(ctx);
            hv_arm_tick(false);
        } else {
            hv_arm_tick(true);
        }
    }

    if (mrs(CNTV_CTL_EL0) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        msr(CNTV_CTL_EL0, CNTx_CTL_ISTATUS | CNTx_CTL_IMASK | CNTx_CTL_ENABLE);
        hv_exc_proxy(ctx, START_HV, HV_VTIMER, NULL);
    }

    u64 reg = mrs(SYS_IMP_APL_PMCR0);
    if ((reg & (PMCR0_IMODE_MASK | PMCR0_IACT)) == (PMCR0_IMODE_FIQ | PMCR0_IACT)) {
#ifdef DEBUG_PMU_IRQ
        printf("[FIQ] PMC IRQ, masking and delivering to the guest\n");
#endif
        reg_clr(SYS_IMP_APL_PMCR0, PMCR0_IACT | PMCR0_IMODE_MASK);
        PERCPU(pmc_pending) = true;
    }

    reg = mrs(SYS_IMP_APL_UPMCR0);
    if (FIELD_GET(UPMCR0_IMODE_T8020, reg) == UPMCR0_IMODE_FIQ &&
        (mrs(SYS_IMP_APL_UPMSR) & UPMSR_IACT)) {
        printf("[FIQ] UPMC IRQ, masking");
        reg_clr(SYS_IMP_APL_UPMCR0, UPMCR0_IMODE_T8020);
        hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_FIQ, NULL);
    }

    if (mrs(SYS_IMP_APL_IPI_SR_EL1) & IPI_SR_PENDING) {
        if (PERCPU(ipi_queued)) {
            PERCPU(ipi_pending) = true;
            PERCPU(ipi_queued) = false;
        }
        msr(SYS_IMP_APL_IPI_SR_EL1, IPI_SR_PENDING);
        sysop("isb");
    }

    hv_maybe_switch_cpu(ctx, START_HV, HV_CPU_SWITCH, NULL);

    // Handles guest timers
    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('f');
}

void hv_exc_serr(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('E');
    hv_get_context(ctx);
    hv_exc_entry();
    hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_SERROR, NULL);
    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('e');
}
