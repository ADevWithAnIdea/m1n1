/* SPDX-License-Identifier: MIT */
#include "adt.h"
#include "kboot.h"
#include "soc.h"
#include "utils.h"
#include "libfdt/libfdt.h"

/* The kernel owns the topology and P-state indices. Populate only the
 * board-dependent frequencies, without exposing the raw ADT to Linux.
 */
int dt_set_cpu_opps(void *dt)
{
    static const struct {
        const char *path;
        const char *property;
        u32 count;
    } tables[] = {
        {"/opp-table-cpu-e", "voltage-states1-sram", 7},
        {"/opp-table-cpu-p0", "voltage-states5-sram", 20},
        {"/opp-table-cpu-p1", "voltage-states13-sram", 20},
    };

    if (chip_id != T6041)
        return 0;

    int pmgr = adt_path_offset(adt, "/arm-io/pmgr");
    if (pmgr < 0)
        return -1;

    for (u32 t = 0; t < ARRAY_SIZE(tables); t++) {
        int table = fdt_path_offset(dt, tables[t].path);
        if (table == -FDT_ERR_NOTFOUND)
            continue; /* Older kernels do not describe CPU DVFS yet. */
        if (table < 0)
            return -1;

        u32 size;
        const u32 *states = adt_getprop(adt, pmgr, tables[t].property, &size);
        if (!states || size != tables[t].count * 2 * sizeof(u32)) {
            printf("FDT: invalid CPU frequency table %s\n", tables[t].property);
            return -1;
        }

        int opp, len;
        u32 count = 0, last_khz = 0;
        fdt_for_each_subnode(opp, dt, table)
        {
            const fdt32_t *level = fdt_getprop(dt, opp, "opp-level", &len);
            if (!level || len != sizeof(*level) || count >= tables[t].count ||
                fdt32_ld(level) != count + 1)
                return -1;
            u32 khz = states[count * 2];
            if (khz <= last_khz || khz > 6000000 ||
                fdt_setprop_inplace_u64(dt, opp, "opp-hz", (u64)khz * 1000))
                return -1;
            last_khz = khz;
            count++;
        }
        if (opp != -FDT_ERR_NOTFOUND || count != tables[t].count)
            return -1;
        printf("FDT: CPU DVFS %s: %u states, max %u kHz\n", tables[t].path, count, last_khz);
    }
    return 0;
}
