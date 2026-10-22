/* SPDX-License-Identifier: MIT */
#ifndef GPU_FDT_H
#define GPU_FDT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct perf_state {
    uint32_t freq;
    uint32_t volt;
};

struct aux_perf_state {
    uint64_t volt;
    uint64_t freq;
};

struct aux_perf_states {
    uint64_t dies;
    uint64_t count;
    struct aux_perf_state states[];
};

/* Original numeric ADT values are consumed only by m1n1. Linux receives
 * standard big-endian FDT cells and operating-points-v2 child nodes. */
struct gpu_fdt_scalar {
    const char *name; /* original gpu-* ADT name */
    uint32_t value;   /* integer or IEEE-754 bit pattern */
};

struct gpu_fdt_g16c {
    const struct perf_state *core;
    size_t core_size;
    const struct perf_state *sram;
    size_t sram_size;
    const struct aux_perf_states *cs;
    size_t cs_size;
    uint32_t revision;
    uint32_t sample_clocks;
    bool gpc;
    const struct gpu_fdt_scalar *power;
    size_t power_count;
    uint64_t software_interrupt;
    uint32_t active_mcc_mask;
};

bool gpu_fdt_power_property(const char *name);
int gpu_fdt_populate_g16c(void *dt, int gpu, const struct gpu_fdt_g16c *input);

#define GPU_FDT_G16C_REGIONS 5
struct gpu_fdt_region {
    uint64_t base;
    uint64_t size;
};

int gpu_fdt_populate_g16c_memory(void *dt, int gpu,
                               const struct gpu_fdt_region regions[GPU_FDT_G16C_REGIONS],
                               uint64_t private_base, uint64_t private_size);

#endif
