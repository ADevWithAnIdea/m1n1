/* SPDX-License-Identifier: MIT */

#ifndef ATC_H
#define ATC_H

#include "types.h"

#define CIO3PLL_DCO_NCTRL            0x2a38
#define CIO3PLL_DCO_COARSEBIN_EFUSE0 GENMASK(6, 0)
#define CIO3PLL_DCO_COARSEBIN_EFUSE1 GENMASK(23, 17)

#define CIO3PLL_FRACN_CAN             0x2aa4
#define CIO3PLL_DLL_CAL_START_CAPCODE GENMASK(18, 17)

#define CIO3PLL_DTC_VREG        0x2a20
#define CIO3PLL_DTC_VREG_ADJUST GENMASK(16, 14)

#define AUS_COMMON_SHIM_BLK_VREG 0x0a04
#define AUS_VREG_TRIM            GENMASK(6, 2)

#define AUSPLL_DCO_EFUSE_SPARE         0x222c
#define AUSPLL_RODCO_ENCAP_EFUSE       GENMASK(10, 9)
#define AUSPLL_RODCO_BIAS_ADJUST_EFUSE GENMASK(14, 12)

#define AUSPLL_FRACN_CAN         0x22a4
#define AUSPLL_DLL_START_CAPCODE GENMASK(18, 17)

#define AUSPLL_CLKOUT_DTC_VREG 0x2220
#define AUSPLL_DTC_VREG_ADJUST GENMASK(16, 14)
#define AUSPLL_DTC_VREG_BYPASS BIT(7)

struct atc_tunable {
    u32 offset : 24;
    u32 size : 8;
    u32 mask;
    u32 value;
} PACKED;

struct atc_tunable_info {
    const char *adt_name;
    const char *fdt_name;
    size_t reg_offset;
    size_t reg_size;
    bool required;
};

extern const struct atc_tunable_info atc_tunables_t8103[];
extern const size_t atc_tunables_t8103_count;
extern const struct atc_tunable_info atc_tunables_t8122[];
extern const size_t atc_tunables_t8122_count;

/* Return the record count, zero for an absent optional table, or -1 on error. */
int atc_get_tunables(int adt_node, const struct atc_tunable_info *info,
                     const struct atc_tunable **tunables);

#endif
