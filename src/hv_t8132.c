/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv.h"
#include "adt.h"
#include "smp.h"
#include "soc.h"
#include "string.h"
#include "utils.h"

#define T8132_POWER_PAGE_SIZE      0x4000UL
#define T8132_CPU_CONTROL_OFFSET   0x8000UL
#define T8132_CPM_CONTROL0_OFFSET  0x4000UL
#define T8132_CPM_CONTROL1_OFFSET  0x8000UL
#define T8132_MAX_POWER_PAGES      (MAX_CPUS * 3)
#define T8132_POWER_SHADOW_ENTRIES 256

struct t8132_power_shadow {
    u64 ipa;
    u64 value;
    u8 width;
    bool valid;
};

static u64 t8132_power_pages[T8132_MAX_POWER_PAGES];
static u32 t8132_power_page_count;
static struct t8132_power_shadow t8132_power_shadow[T8132_POWER_SHADOW_ENTRIES];

static int t8132_power_page_index(u64 ipa)
{
    u64 page = ipa & ~(T8132_POWER_PAGE_SIZE - 1);

    for (u32 i = 0; i < t8132_power_page_count; i++)
        if (page == t8132_power_pages[i])
            return i;

    return -1;
}

static int t8132_power_add_page(u64 addr)
{
    addr &= ~(T8132_POWER_PAGE_SIZE - 1);
    if (t8132_power_page_index(addr) >= 0)
        return 0;
    if (t8132_power_page_count >= ARRAY_SIZE(t8132_power_pages))
        return -1;

    t8132_power_pages[t8132_power_page_count++] = addr;
    return 0;
}

static bool t8132_power_shadow_read(u64 ipa, u64 *value, int width)
{
    for (u32 i = 0; i < ARRAY_SIZE(t8132_power_shadow); i++) {
        struct t8132_power_shadow *entry = &t8132_power_shadow[i];
        if (entry->valid && entry->ipa == ipa && entry->width == width) {
            *value = entry->value;
            return true;
        }
    }
    return false;
}

static void t8132_power_shadow_write(u64 ipa, u64 value, int width)
{
    int free = -1;

    for (u32 i = 0; i < ARRAY_SIZE(t8132_power_shadow); i++) {
        struct t8132_power_shadow *entry = &t8132_power_shadow[i];
        if (entry->valid) {
            if (entry->ipa == ipa && entry->width == width) {
                entry->value = value;
                return;
            }
        } else if (free < 0) {
            free = i;
        }
    }

    if (free >= 0)
        t8132_power_shadow[free] = (struct t8132_power_shadow){
            .ipa = ipa, .value = value, .width = width, .valid = true,
        };
}

static bool t8132_power_hook(struct exc_info *ctx, u64 ipa, u64 *value,
                             bool write, int width)
{
    /* EL2 owns the live CPU/CPM state; XNU sees its writes through a shadow. */
    if (write) {
        t8132_power_shadow_write(ipa, *value, width);
        return true;
    }

    if (t8132_power_shadow_read(ipa, value, width))
        return true;
    return hv_pa_rw(ctx, ipa, value, false, width);
}

int hv_t8132_map_cpu_power_regs(void)
{
    if (chip_id != T8132)
        return 0;

    int cpus = adt_path_offset(adt, "/cpus");
    if (cpus < 0) {
        printf("HV: T8132 CPU power guard: /cpus is missing\n");
        return -1;
    }

    t8132_power_page_count = 0;
    memset(t8132_power_shadow, 0, sizeof(t8132_power_shadow));
    int failures = 0;

    int node = cpus;
    ADT_FOREACH_CHILD(adt, node)
    {
        u64 cpu_reg[2];
        u64 cpm_reg[2];
        if (ADT_GETPROP_ARRAY(adt, node, "cpu-impl-reg", cpu_reg) < 0 ||
            ADT_GETPROP_ARRAY(adt, node, "cpm-impl-reg", cpm_reg) < 0) {
            printf("HV: T8132 CPU power guard: incomplete CPU node %s\n",
                   adt_get_name(adt, node));
            failures++;
            continue;
        }

        if (cpu_reg[1] <= T8132_CPU_CONTROL_OFFSET ||
            t8132_power_add_page(cpu_reg[0] + T8132_CPU_CONTROL_OFFSET) < 0) {
            printf("HV: T8132 CPU power guard: invalid CPU range for %s\n",
                   adt_get_name(adt, node));
            failures++;
        }

        const u64 cpm_offsets[] = {
            T8132_CPM_CONTROL0_OFFSET, T8132_CPM_CONTROL1_OFFSET,
        };
        for (u32 i = 0; i < ARRAY_SIZE(cpm_offsets); i++) {
            if (cpm_reg[1] <= cpm_offsets[i])
                continue;
            if (t8132_power_add_page(cpm_reg[0] + cpm_offsets[i]) < 0) {
                printf("HV: T8132 CPU power guard: invalid CPM range for %s\n",
                       adt_get_name(adt, node));
                failures++;
            }
        }
    }

    for (u32 i = 0; i < t8132_power_page_count; i++)
        failures += hv_map_hook(t8132_power_pages[i], t8132_power_hook,
                                T8132_POWER_PAGE_SIZE) != 0;

    sysop("dsb ishst");
    sysop("tlbi vmalls12e1is");
    sysop("dsb ish");
    sysop("isb");
    return failures ? -failures : 0;
}
