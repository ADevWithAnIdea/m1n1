/* SPDX-License-Identifier: MIT */
/* Scheduled-family GPU DT population. No GPU MMIO or firmware execution. */

#include "gpu_fdt.h"
#include "libfdt/libfdt.h"

#define STATES 11
#define CLUSTERS 4 /* Maximum wire voltage columns; Pro supplies two. */
#define RAW_STATES 16

bool gpu_fdt_power_property(const char *name)
{
    static const char *const names[] = {
        "gpu-avg-power-filter-tc-ms",
        "gpu-avg-power-input-filter-tc",
        "gpu-avg-power-ki",
        "gpu-avg-power-ki-only",
        "gpu-avg-power-kp",
        "gpu-avg-power-min-duty-cycle",
        "gpu-avg-power-target-filter-tc",
        "gpu-fast-die0-integral-gain",
        "gpu-fast-die0-prop-tgt-delta",
        "gpu-fast-die0-proportional-gain",
        "gpu-fast-die0-release-temp",
        "gpu-perf-base-pstate",
        "gpu-perf-boost-ce-step",
        "gpu-perf-boost-min-util",
        "gpu-perf-dz",
        "gpu-perf-filter-drop-threshold",
        "gpu-perf-filter-time-constant",
        "gpu-perf-filter-time-constant2",
        "gpu-perf-integral-gain",
        "gpu-perf-integral-gain2",
        "gpu-perf-integral-min-clamp",
        "gpu-perf-proportional-gain",
        "gpu-perf-proportional-gain2",
        "gpu-perf-reset-iters",
        "gpu-perf-tgt-utilization",
        "gpu-ppm-filter-time-constant-ms",
        "gpu-ppm-ki",
        "gpu-ppm-kp",
        "gpu-pwr-filter-time-constant",
        "gpu-pwr-integral-gain",
        "gpu-pwr-integral-min-clamp",
        "gpu-pwr-min-duty-cycle",
        "gpu-pwr-proportional-gain",
        "gpu-se-engagement-criteria",
        "gpu-se-engagement-tolerance",
        "gpu-se-filter-time-constant",
        "gpu-se-filter-time-constant-1",
        "gpu-se-inactive-threshold",
        "gpu-se-ki",
        "gpu-se-ki-1",
        "gpu-se-kp",
        "gpu-se-kp-1",
        "gpu-se-reset-criteria",
        "gpu-se-reset-tolerance",
        "gpu-turbo-controller-input",
    };
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!strcmp(name, names[i]))
            return true;
    }
    return false;
}

static int opp_table(void *dt, int gpu, const char *name, unsigned count)
{
    int len;
    const fdt32_t *phandle = fdt_getprop(dt, gpu, name, &len);
    if (!phandle || len != sizeof(*phandle))
        return -FDT_ERR_BADVALUE;
    int table = fdt_node_offset_by_phandle(dt, fdt32_to_cpu(*phandle));
    if (table < 0)
        return table;
    unsigned found = 0;
    int child;
    fdt_for_each_subnode(child, dt, table)
        found++;
    return found == count ? table : -FDT_ERR_BADVALUE;
}

int gpu_fdt_populate_g16c_memory(void *dt, int gpu,
                               const struct gpu_fdt_region regions[GPU_FDT_G16C_REGIONS],
                               uint64_t private_base, uint64_t private_size)
{
    static const char names[] = "ttbs\0pagetables\0l2\0handoff\0firmware";
    int length;
    const void *property = fdt_getprop(dt, gpu, "memory-region-names", &length);
    if (!regions || !property || length != sizeof(names) || memcmp(property, names, length) ||
        private_base != 0xfffffc0000000000ULL || private_size != 0x2000000000ULL)
        return -FDT_ERR_BADVALUE;
    const fdt32_t *handles = fdt_getprop(dt, gpu, "memory-region", &length);
    if (!handles || length != GPU_FDT_G16C_REGIONS * sizeof(*handles))
        return -FDT_ERR_BADVALUE;
    int reserved = fdt_path_offset(dt, "/reserved-memory");
    if (reserved < 0 || fdt_address_cells(dt, reserved) != 2 || fdt_size_cells(dt, reserved) != 2)
        return -FDT_ERR_BADVALUE;
    uint32_t phandles[GPU_FDT_G16C_REGIONS];
    for (unsigned i = 0; i < GPU_FDT_G16C_REGIONS; i++) {
        uint64_t base = regions[i].base, size = regions[i].size;
        if (!base || !size || ((base | size) & 0x3fff) || base >= (1ULL << 42) ||
            size > (1ULL << 42) - base)
            return -FDT_ERR_BADVALUE;
        phandles[i] = fdt32_to_cpu(handles[i]);
        for (unsigned j = 0; j < i; j++) {
            if (phandles[i] == phandles[j] ||
                (base < regions[j].base + regions[j].size && regions[j].base < base + size))
                return -FDT_ERR_BADVALUE;
        }
        int node = fdt_node_offset_by_phandle(dt, phandles[i]);
        if (node < 0 || fdt_parent_offset(dt, node) != reserved ||
            !fdt_getprop(dt, node, "no-map", &length) || length != 0 ||
            !fdt_getprop(dt, node, "reg", &length) || length != 16)
            return -FDT_ERR_BADVALUE;
    }
    // Inputs and the entire target shape are checked before changing the DT.
    fdt64_t private_vm[2] = {cpu_to_fdt64(private_base), cpu_to_fdt64(private_size)};
    int ret = fdt_setprop(dt, gpu, "apple,rtkit-private-vm-region", private_vm, sizeof(private_vm));
    if (ret)
        return ret;
    for (unsigned i = 0; i < GPU_FDT_G16C_REGIONS; i++) {
        // Status insertion may move every sibling. Phandles remain stable.
        int node = fdt_node_offset_by_phandle(dt, phandles[i]);
        fdt64_t reg[2] = {cpu_to_fdt64(regions[i].base), cpu_to_fdt64(regions[i].size)};
        if (node < 0 || fdt_setprop_inplace(dt, node, "reg", reg, sizeof(reg)) ||
            fdt_setprop_string(dt, node, "status", "okay"))
            return -FDT_ERR_NOSPACE;
    }
    return 0;
}

int gpu_fdt_populate_g16c(void *dt, int gpu, const struct gpu_fdt_g16c *in)
{
    if (!in) return -FDT_ERR_BADVALUE;
    const unsigned clusters = in->core_size / (RAW_STATES * sizeof(*in->core));
    if (!in->core || !in->sram || !in->cs ||
        (clusters != 2 && clusters != 4) ||
        in->core_size != RAW_STATES * clusters * sizeof(*in->core) ||
        in->sram_size != in->core_size || in->cs_size < 24 ||
        in->cs->dies != 1 || !in->cs->count || in->cs->count > RAW_STATES ||
        in->cs_size != 24 + in->cs->count * sizeof(struct aux_perf_state) ||
        in->sample_clocks < 24000 || (in->power_count && !in->power) ||
        in->software_interrupt < 0x4000 || in->software_interrupt >= (1ULL << 48) ||
        !in->active_mcc_mask)
        return -FDT_ERR_BADVALUE;
    uint32_t firsts[STATES], high[STATES], low[STATES];
    unsigned groups = 0;
    for (unsigned first = 0; first < RAW_STATES;) {
        if (groups == STATES)
            return -FDT_ERR_BADVALUE;
        unsigned end = first + 1, hi = first, lo = first;
        while (end < RAW_STATES && in->core[end].volt == in->core[first].volt)
            end++;
        for (unsigned i = first; i < end; i++) {
            if (in->core[i].freq > in->core[hi].freq)
                hi = i;
            if (in->core[i].freq < in->core[lo].freq)
                lo = i;
        }
        if (groups == 5) {
            /* Qualified Max active ladder: both branches use row 6. */
            if (hi != 6 || lo != 5)
                return -FDT_ERR_BADVALUE;
            lo = hi;
        }
        if ((!groups && (in->core[hi].freq || in->core[lo].freq)) ||
            (groups && (in->core[hi].freq / 1000000 <= in->core[high[groups - 1]].freq / 1000000 ||
                        in->core[lo].freq / 1000000 <= in->core[low[groups - 1]].freq / 1000000)))
            return -FDT_ERR_BADVALUE;
        firsts[groups] = first;
        high[groups] = hi;
        low[groups] = lo;
        groups++;
        first = end;
    }
    if (groups != STATES)
        return -FDT_ERR_BADVALUE;
    for (unsigned i = 0; i < STATES; i++) {
        for (unsigned c = 0; c < clusters; c++) {
            unsigned row = firsts[i] + c * RAW_STATES;
            if (in->core[row].volt > UINT32_MAX / 1000 || in->sram[row].volt > UINT32_MAX / 1000)
                return -FDT_ERR_BADVALUE;
        }
    }
    const uint64_t *minimum = (const uint64_t *)&in->cs->states[in->cs->count];
    if (*minimum > UINT32_MAX)
        return -FDT_ERR_BADVALUE;
    for (unsigned i = 0; i < in->cs->count; i++) {
        if (in->cs->states[i].volt > UINT32_MAX)
            return -FDT_ERR_BADVALUE;
    }
    for (size_t i = 0; i < in->power_count; i++) {
        const char *name = in->power[i].name;
        if (!name || !gpu_fdt_power_property(name) || strlen(name) > 57)
            return -FDT_ERR_BADVALUE;
    }
    if (opp_table(dt, gpu, "operating-points-v2", STATES) < 0 ||
        opp_table(dt, gpu, "apple,cs-opp", in->cs->count) < 0)
        return -FDT_ERR_BADVALUE;

    /* Scalar insertion can move sibling nodes. Resolve OPP phandles only
     * after all insertions, then use in-place writes inside the tables. */
    if (fdt_setprop_u32(dt, gpu, "apple,chip-revision", in->revision) ||
        fdt_setprop_u32(dt, gpu, "apple,power-sample-period", in->sample_clocks / 24000) ||
        fdt_setprop_u32(dt, gpu, "apple,pwr-sample-period-aic-clks", in->sample_clocks) ||
        fdt_setprop_u32(dt, gpu, "apple,gpc-enabled", in->gpc) ||
        fdt_setprop_u32(dt, gpu, "apple,max-power-milliwatt", clusters == 2 ? 68444 : 132183) ||
        fdt_setprop_u32(dt, gpu, "apple,csafr-min-sram-microvolt", *minimum) ||
        fdt_setprop_u64(dt, gpu, "apple,firmware-sw-interrupt", in->software_interrupt) ||
        fdt_setprop_u32(dt, gpu, "apple,active-mcc-mask", in->active_mcc_mask))
        return -FDT_ERR_NOSPACE;
    for (size_t i = 0; i < in->power_count; i++) {
        char name[64] = "apple,";
        strcpy(name + 6, in->power[i].name + 4);
        /* The normalized sampling values above retain the qualified fallback
         * and integer truncation, even if both original ADT sources exist. */
        if (!strcmp(name, "apple,power-sample-period") ||
            !strcmp(name, "apple,pwr-sample-period-aic-clks"))
            continue;
        int ret = fdt_setprop_u32(dt, gpu, name, in->power[i].value);
        if (ret)
            return ret;
    }
    static const uint32_t relative_a[STATES] = {0,9,18,24,29,38,48,60,68,79,100};
    static const uint32_t relative_b[STATES] = {0,0,22,36,47,57,68,78,84,91,100};
    int table = opp_table(dt, gpu, "operating-points-v2", STATES);
    if (table < 0)
        return table;
    unsigned i = 0;
    int child;
    fdt_for_each_subnode(child, dt, table) {
        fdt32_t core[CLUSTERS], sram[CLUSTERS];
        for (unsigned c = 0; c < clusters; c++) {
            unsigned row = firsts[i] + c * RAW_STATES;
            core[c] = cpu_to_fdt32(in->core[row].volt * 1000);
            sram[c] = cpu_to_fdt32(in->sram[row].volt * 1000);
        }
        fdt32_t index[2] = {cpu_to_fdt32(high[i]), cpu_to_fdt32(low[i])};
        fdt32_t relative[2] = {cpu_to_fdt32(relative_a[i]), cpu_to_fdt32(relative_b[i])};
        if (fdt_setprop_inplace_u64(dt, child, "opp-hz", in->core[high[i]].freq) ||
            fdt_setprop_inplace_u64(dt, child, "apple,alternate-opp-hz", in->core[low[i]].freq) ||
            fdt_setprop_inplace(dt, child, "opp-microvolt", core, clusters * sizeof(*core)) ||
            fdt_setprop_inplace(dt, child, "apple,sram-microvolt", sram, clusters * sizeof(*sram)) ||
            fdt_setprop_inplace(dt, child, "apple,perf-index", index, sizeof(index)) ||
            fdt_setprop_inplace(dt, child, "apple,relative-power", relative, sizeof(relative)))
            return -FDT_ERR_BADVALUE;
        i++;
    }
    table = opp_table(dt, gpu, "apple,cs-opp", in->cs->count);
    if (table < 0)
        return table;
    i = 0;
    fdt_for_each_subnode(child, dt, table) {
        if (fdt_setprop_inplace_u64(dt, child, "opp-hz", in->cs->states[i].freq) ||
            fdt_setprop_inplace_u32(dt, child, "opp-microvolt", in->cs->states[i].volt))
            return -FDT_ERR_BADVALUE;
        i++;
    }
    return 0;
}
