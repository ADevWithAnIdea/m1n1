/* SPDX-License-Identifier: MIT */

#include "smp.h"
#include "adt.h"
#include "aic.h"
#include "aic_regs.h"
#include "assert.h"
#include "cpu_regs.h"
#include "malloc.h"
#include "memory.h"
#include "pmgr.h"
#include "soc.h"
#include "string.h"
#include "types.h"
#include "utils.h"

#define CPU_START_OFF_S5L8960X 0x30000
#define CPU_START_OFF_S8000    0xd4000
#define CPU_START_OFF_T8103    0x54000
#define CPU_START_OFF_T8112    0x34000
#define CPU_START_OFF_T6020    0x28000
#define CPU_START_OFF_T6031    0x88000

#define CPU_REG_CORE    GENMASK(7, 0)
#define CPU_REG_CLUSTER GENMASK(10, 8)
#define CPU_REG_DIE     GENMASK(14, 11)

#define RVBAR_LOCK BIT(0)
#define RVBAR_ADDR GENMASK(47, 12)

#define SPIN_TABLE_STRIDE    128
#define SPIN_TABLE_PAGE_SIZE SZ_16K

struct spin_table_entry {
    volatile u64 mpidr;
    volatile u64 flag;
    volatile u64 target;
    volatile u64 args[4];
    volatile u64 retval;
    /* Keep independently active CPU slots on separate Apple cache lines. */
    u8 padding[SPIN_TABLE_STRIDE - 8 * sizeof(u64)];
};
static_assert(sizeof(struct spin_table_entry) == SPIN_TABLE_STRIDE, "invalid spin-table stride");

void *_reset_stack;
void *_reset_stack_el1;

#define DUMMY_STACK_SIZE 0x1000
u8 dummy_stack[DUMMY_STACK_SIZE];     // Highest EL
u8 dummy_stack_el1[DUMMY_STACK_SIZE]; // EL1 stack if EL3 exists

u8 *secondary_stacks[MAX_CPUS] = {dummy_stack};
u8 *secondary_reset_stacks[MAX_CPUS] = {dummy_stack};
u8 *secondary_stacks_el3[MAX_EL3_CPUS];

static bool wfe_mode = false;

static int target_cpu;
static int cpu_nodes[MAX_CPUS];
static union {
    struct spin_table_entry entries[MAX_CPUS];
    u8 page[SPIN_TABLE_PAGE_SIZE];
} spin_table_page ALIGNED(SPIN_TABLE_PAGE_SIZE);
static_assert(sizeof(spin_table_page.entries) <= sizeof(spin_table_page.page),
              "spin table does not fit in one page");
#define spin_table spin_table_page.entries
static bool spin_table_published;
static u64 pmgr_reg;
static u64 cpu_start_off;

extern u8 _vectors_start[0];
int boot_cpu_idx = -1;
u64 boot_cpu_mpidr = 0;

void smp_secondary_entry(void)
{
    struct spin_table_entry *me = &spin_table[target_cpu];

    if (in_el2())
        msr(TPIDR_EL2, target_cpu);
    else
        msr(TPIDR_EL1, target_cpu);

    printf("  Index: %d (table: %p)\n\n", target_cpu, me);

    me->mpidr = mrs(MPIDR_EL1) & 0xFFFFFF;

    sysop("dmb sy");
    me->flag++;
    sysop("dmb sy");
    u64 target;
    if (!cpu_features->fast_ipi)
        aic_write(AIC_IPI_MASK_SET, AIC_IPI_SELF); // we only use the "other" IPI

    while (1) {
        while (!(target = me->target)) {
            if (wfe_mode) {
                sysop("wfe");
            } else {
                deep_wfi();

                if (cpu_features->fast_ipi) {
                    msr(SYS_IMP_APL_IPI_SR_EL1, 1);
                } else {
                    aic_ack(); // Actually read IPI reason
                    aic_write(AIC_IPI_ACK, AIC_IPI_OTHER);
                    aic_write(AIC_IPI_MASK_CLR, AIC_IPI_OTHER);
                }
            }
            sysop("isb");
        }
        sysop("dmb sy");
        me->flag++;
        sysop("dmb sy");
        me->retval = ((u64 (*)(u64 a, u64 b, u64 c, u64 d))target)(me->args[0], me->args[1],
                                                                   me->args[2], me->args[3]);
        sysop("dmb sy");
        me->target = 0;
        sysop("dmb sy");
    }
}

void smp_secondary_prep_el3(void)
{
    msr(TPIDR_EL3, target_cpu);
    return;
}

u64 smp_secondary_stack_top(void)
{
    return (u64)secondary_stacks[smp_id()] + SECONDARY_STACK_SIZE;
}

static void smp_start_cpu(int index, int die, int cluster, int core, u64 impl, u64 cpu_start_base)
{
    int i;

    if (index >= MAX_CPUS)
        return;

    if (has_el3() && index >= MAX_EL3_CPUS)
        return;

    if (spin_table[index].flag)
        return;

    if (!cpu_features->apple_sysregs_unlocked &&
        (read64(impl) & RVBAR_ADDR) != (u64)_vectors_start) {
        printf("Failed! \n    RVBAR (=0x%lx) is locked and differs from entry point (=0x%lx)\n",
               read64(impl) & RVBAR_ADDR, (u64)_vectors_start);
    }

    printf("Starting CPU %d (%d:%d:%d)... ", index, die, cluster, core);

    memset(&spin_table[index], 0, sizeof(struct spin_table_entry));

    target_cpu = index;
    dc_civac_range(&target_cpu, sizeof(target_cpu));
    secondary_stacks[index] = memalign(0x4000, SECONDARY_STACK_SIZE);
    secondary_reset_stacks[index] = memalign(0x4000, SECONDARY_RESET_STACK_SIZE);
    if (!secondary_stacks[index] || !secondary_reset_stacks[index])
        panic("Failed to allocate stacks for CPU %d\n", index);

    memset(secondary_stacks[index], 0, SECONDARY_STACK_SIZE);
    dc_civac_range(secondary_stacks[index], SECONDARY_STACK_SIZE);
    dc_civac_range(&secondary_stacks[index], sizeof(secondary_stacks[index]));

    memset(secondary_reset_stacks[index], 0, SECONDARY_RESET_STACK_SIZE);
    mmu_map_ram_range_nc((u64)secondary_reset_stacks[index], SECONDARY_RESET_STACK_SIZE);
    dc_civac_range(&secondary_reset_stacks[index], sizeof(secondary_reset_stacks[index]));

    if (has_el3()) {
        secondary_stacks_el3[index] = memalign(0x4000, SECONDARY_STACK_SIZE);
        if (!secondary_stacks_el3[index])
            panic("Failed to allocate EL3 stack for CPU %d\n", index);
        memset(secondary_stacks_el3[index], 0, SECONDARY_STACK_SIZE);
        dc_civac_range(secondary_stacks_el3[index], SECONDARY_STACK_SIZE);
        _reset_stack = secondary_stacks_el3[index] + SECONDARY_STACK_SIZE; // EL3
        _reset_stack_el1 =
            secondary_reset_stacks[index] + SECONDARY_RESET_STACK_SIZE; // EL1

        dc_civac_range(&_reset_stack_el1, sizeof(void *));
    } else
        _reset_stack = secondary_reset_stacks[index] + SECONDARY_RESET_STACK_SIZE;

    dc_civac_range(&_reset_stack, sizeof(void *));

    sysop("dsb sy");

    if (cpu_features->apple_sysregs_unlocked) {
        // This also clears RVBAR_LOCK, so that HV can set RVBAR later when the core is running
        write64(impl, (u64)_vectors_start);
    }

    cpu_start_base += die * PMGR_DIE_OFFSET;

    // Some kind of system level startup/status bit
    // Without this, IRQs don't work
    write32(cpu_start_base + 0x4, 1 << (4 * cluster + core));

    // Actually start the core
    write32(cpu_start_base + 0x8 + 4 * cluster, 1 << core);

    for (i = 0; i < 100; i++) {
        if (spin_table[index].flag) {
            // Acquire the MPIDR published before the flag.
            sysop("dmb ld");
            break;
        }
        udelay(1000);
    }

    if (i >= 100) {
        printf("Failed!\n");
    } else {
        printf("  Started.\n");
    }

    _reset_stack = dummy_stack + DUMMY_STACK_SIZE;
    _reset_stack_el1 = dummy_stack_el1 + DUMMY_STACK_SIZE;
    dc_civac_range(&_reset_stack, sizeof(_reset_stack));
    dc_civac_range(&_reset_stack_el1, sizeof(_reset_stack_el1));
    sysop("dsb sy");
}

static void smp_stop_cpu(int index, int die, int cluster, int core, u64 impl, u64 cpu_start_base,
                         bool deep_sleep)
{
    int i;

    if (index >= MAX_CPUS)
        return;

    if (!spin_table[index].flag)
        return;

    printf("Stopping CPU %d (%d:%d:%d)... ", index, die, cluster, core);

    cpu_start_base += die * PMGR_DIE_OFFSET;

    // Request CPU stop
    write32(cpu_start_base + 0x0, 1 << (4 * cluster + core));

    u64 dsleep = deep_sleep;
    // Put the CPU to sleep
    smp_call1(index, cpu_sleep, dsleep);

    // If going into deep sleep, powering off the last core in a cluster kills our register
    // access, so just wait a bit.
    if (deep_sleep) {
        udelay(10000);
        printf("  Presumed stopped.\n");
        memset(&spin_table[index], 0, sizeof(struct spin_table_entry));
        sysop("dsb sy");
        return;
    }

    // Check that it actually shut down
    for (i = 0; i < 50; i++) {
        sysop("dmb ld");
        if (!(read64(impl + 0x100) & 0xff))
            break;
        udelay(1000);
    }

    if (i >= 50) {
        printf("Failed!\n");
    } else {
        printf("  Stopped.\n");

        memset(&spin_table[index], 0, sizeof(struct spin_table_entry));
        sysop("dsb sy");
    }
}

void smp_start_secondaries(void)
{
    printf("Starting secondary CPUs...\n");

    if (!spin_table_published) {
        memset(&spin_table_page, 0, sizeof(spin_table_page));
        /* Retype the entire mailbox page only after publishing its WB state. */
        dc_civac_range(&spin_table_page, sizeof(spin_table_page));
        sysop("dsb sy");
        mmu_retype_mapping((u64)&spin_table_page, (u64)&spin_table_page,
                           sizeof(spin_table_page), MAIR_IDX_DEVICE_nGnRnE,
                           PERM_RW);
        spin_table_published = true;
    }

    int pmgr_path[8];

    if (adt_path_offset_trace(adt, "/arm-io/pmgr", pmgr_path) < 0) {
        printf("Error getting /arm-io/pmgr node\n");
        return;
    }
    if (adt_get_reg(adt, pmgr_path, "reg", 0, &pmgr_reg, NULL) < 0) {
        printf("Error getting /arm-io/pmgr regs\n");
        return;
    }

    int arm_io_node;
    if ((arm_io_node = adt_path_offset(adt, "/arm-io")) < 0) {
        printf("Error getting /arm-io node\n");
        return;
    }

    int node = adt_path_offset(adt, "/cpus");
    if (node < 0) {
        printf("Error getting /cpus node\n");
        return;
    }

    memset(cpu_nodes, 0, sizeof(cpu_nodes));

    switch (chip_id) {
        case S5L8960X:
        case T7000:
        case T7001:
            cpu_start_off = CPU_START_OFF_S5L8960X;
            break;
        case S8000:
        case S8001:
        case S8003:
        case T8010:
        case T8011:
        case T8012:
        case T8015:
            cpu_start_off = CPU_START_OFF_S8000;
            break;
        case T8103:
        case T6000:
        case T6001:
        case T6002:
            cpu_start_off = CPU_START_OFF_T8103;
            break;
        case T8112:
        case T8122:
        case T8132:
        case T8140:
        case T8142:
            cpu_start_off = CPU_START_OFF_T8112;
            break;
        case T6020:
        case T6021:
        case T6022:
            cpu_start_off = CPU_START_OFF_T6020;
            break;
        case T6030:
            cpu_start_off = CPU_START_OFF_T8112;
            break;
        case T6031:
        case T6034:
        case T6040:
        case T6041:
        case T6050:
        case T6051:
            cpu_start_off = CPU_START_OFF_T6031;
            break;
        default:
            printf("CPU start offset is unknown for this SoC!\n");
            return;
    }

    ADT_FOREACH_CHILD(adt, node)
    {
        u32 cpu_id;

        if (ADT_GETPROP(adt, node, "cpu-id", &cpu_id) < 0)
            if (ADT_GETPROP(adt, node, "reg", &cpu_id) < 0)
                continue;

        if (cpu_id >= MAX_CPUS) {
            printf("cpu-id %d exceeds max CPU count %d: increase MAX_CPUS\n", cpu_id, MAX_CPUS);
            continue;
        }

        cpu_nodes[cpu_id] = node;
    }

    /* The boot cpu id never changes once set */
    if (boot_cpu_idx == -1) {
        /* Figure out which CPU we are on by seeing which CPU is running */

        /* This seems silly but it's what XNU does */
        for (int i = 0; i < MAX_CPUS; i++) {
            int cpu_node = cpu_nodes[i];
            if (!cpu_node)
                continue;
            const char *state = adt_getprop(adt, cpu_node, "state", NULL);
            if (!state)
                continue;
            if (strcmp(state, "running") == 0) {
                boot_cpu_idx = i;
                boot_cpu_mpidr = mrs(MPIDR_EL1);
                if (in_el2())
                    msr(TPIDR_EL2, boot_cpu_idx);
                else
                    msr(TPIDR_EL1, boot_cpu_idx);
                break;
            }
        }
    }

    if (boot_cpu_idx == -1) {
        printf(
            "Could not find currently running CPU in cpu table, can't start other processors!\n");
        return;
    }

    dc_civac_range(&boot_cpu_idx, sizeof(boot_cpu_idx));
    dc_civac_range(&boot_cpu_mpidr, sizeof(boot_cpu_mpidr));
    sysop("dsb sy");

    spin_table[boot_cpu_idx].mpidr = mrs(MPIDR_EL1) & 0xFFFFFF;

    for (int i = 0; i < MAX_CPUS; i++) {
        int cpu_node = cpu_nodes[i];

        if (!cpu_node)
            continue;

        u32 reg;
        u64 cpu_impl_reg[2];
        if (ADT_GETPROP(adt, cpu_node, "reg", &reg) < 0)
            continue;
        if (ADT_GETPROP_ARRAY(adt, cpu_node, "cpu-impl-reg", cpu_impl_reg) < 0) {
            u32 reg_len;
            const u64 *regs = adt_getprop(adt, arm_io_node, "reg", &reg_len);
            if (!regs)
                continue;
            u32 index = 2 * i + 2;
            if (reg_len < index)
                continue;
            memcpy(cpu_impl_reg, &regs[index], 16);
        }

        if (i == boot_cpu_idx) {
            // Check if already locked
            if (FIELD_GET(RVBAR_LOCK, read64(cpu_impl_reg[0])))
                continue;

            // Unlocked, write _vectors_start into boot CPU's rvbar
            write64(cpu_impl_reg[0], (u64)_vectors_start);
            sysop("dmb sy");

            continue;
        }

        u8 core = FIELD_GET(CPU_REG_CORE, reg);
        u8 cluster = FIELD_GET(CPU_REG_CLUSTER, reg);
        u8 die = FIELD_GET(CPU_REG_DIE, reg);

        smp_start_cpu(i, die, cluster, core, cpu_impl_reg[0], pmgr_reg + cpu_start_off);
    }
}

void smp_stop_secondaries(bool deep_sleep)
{
    printf("Stopping secondary CPUs...\n");
    int arm_io_node;
    if ((arm_io_node = adt_path_offset(adt, "/arm-io")) < 0) {
        printf("Error getting /arm-io node\n");
        return;
    }
    smp_set_wfe_mode(true);

    for (int i = 0; i < MAX_CPUS; i++) {
        int node = cpu_nodes[i];

        if (!node)
            continue;

        u32 reg;
        u64 cpu_impl_reg[2];
        if (ADT_GETPROP(adt, node, "reg", &reg) < 0)
            continue;
        if (ADT_GETPROP_ARRAY(adt, node, "cpu-impl-reg", cpu_impl_reg) < 0) {
            u32 reg_len;
            const u64 *regs = adt_getprop(adt, arm_io_node, "reg", &reg_len);
            if (!regs)
                continue;
            u32 index = 2 * i + 2;
            if (reg_len < index)
                continue;
            memcpy(cpu_impl_reg, &regs[index], 16);
        }

        u8 core = FIELD_GET(CPU_REG_CORE, reg);
        u8 cluster = FIELD_GET(CPU_REG_CLUSTER, reg);
        u8 die = FIELD_GET(CPU_REG_DIE, reg);

        smp_stop_cpu(i, die, cluster, core, cpu_impl_reg[0], pmgr_reg + cpu_start_off, deep_sleep);
    }
}

void smp_send_ipi(int cpu)
{
    if (cpu < 0 || cpu >= MAX_CPUS)
        return;

    u64 mpidr = spin_table[cpu].mpidr;
    if (cpu_features->fast_ipi) {
        msr(SYS_IMP_APL_IPI_RR_GLOBAL_EL1, (mpidr & 0xff) | ((mpidr & 0xff00) << 8));
    } else {
        aic_write(AIC_IPI_SEND, AIC_IPI_SEND_CPU(cpu));
    }
}

void smp_call4(int cpu, void *func, u64 arg0, u64 arg1, u64 arg2, u64 arg3)
{
    if (cpu < 0 || cpu >= MAX_CPUS || cpu == boot_cpu_idx)
        return;

    struct spin_table_entry *target = &spin_table[cpu];

    if (!target->flag || target->target)
        return;

    u64 flag = target->flag;
    target->args[0] = arg0;
    target->args[1] = arg1;
    target->args[2] = arg2;
    target->args[3] = arg3;
    sysop("dmb sy");
    target->target = (u64)func;
    sysop("dsb sy");

    if (wfe_mode)
        sysop("sev");
    else
        smp_send_ipi(cpu);

    while (target->flag == flag)
        udelay(1);
}

u64 smp_wait(int cpu)
{
    if (cpu < 0 || cpu >= MAX_CPUS)
        return 0;

    struct spin_table_entry *target = &spin_table[cpu];

    while (true) {
        if (!target->target)
            break;
        udelay(1);
    }

    sysop("dmb ld");
    return target->retval;
}

void smp_set_wfe_mode(bool new_mode)
{
    wfe_mode = new_mode;
    dc_civac_range(&wfe_mode, sizeof(wfe_mode));
    sysop("dsb sy");

    for (int cpu = 0; cpu < MAX_CPUS; cpu++)
        if (cpu != boot_cpu_idx && smp_is_alive(cpu))
            smp_send_ipi(cpu);

    sysop("sev");
}

bool smp_is_alive(int cpu)
{
    if (cpu >= MAX_CPUS)
        return false;

    return spin_table[cpu].flag;
}

uint64_t smp_get_mpidr(int cpu)
{
    if (cpu >= MAX_CPUS)
        return 0;

    return spin_table[cpu].mpidr;
}

u64 smp_get_release_addr(int cpu)
{
    if (cpu < 0 || cpu >= MAX_CPUS)
        return 0;

    struct spin_table_entry *target = &spin_table[cpu];

    target->args[0] = 0;
    target->args[1] = 0;
    target->args[2] = 0;
    target->args[3] = 0;
    sysop("dsb sy");
    return (u64)&target->target;
}
