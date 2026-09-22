/* SPDX-License-Identifier: MIT */

#ifndef ATC_H
#define ATC_H

#include "types.h"

#define ATCPHY_POWER_CTRL        0x20000
#define ATCPHY_POWER_STAT        0x20004
#define ATCPHY_POWER_SLEEP_SMALL BIT(0)
#define ATCPHY_POWER_SLEEP_BIG   BIT(1)
#define ATCPHY_POWER_CLAMP_EN    BIT(2)
#define ATCPHY_POWER_APB_RESET_N BIT(3)
#define ATCPHY_POWER_PHY_RESET_N BIT(4)
#define ATCPHY_MISC              0x20008
#define ATCPHY_MISC_RESET_N      BIT(0)
#define ATCPHY_MISC_LANE_SWAP    BIT(2)

#define ACIOPHY_CFG0                 0x08
#define ACIOPHY_CFG0_COMMON_BIG      BIT(0)
#define ACIOPHY_CFG0_COMMON_BIG_OV   BIT(1)
#define ACIOPHY_CFG0_COMMON_SMALL    BIT(2)
#define ACIOPHY_CFG0_COMMON_SMALL_OV BIT(3)
#define ACIOPHY_CFG0_COMMON_CLAMP    BIT(4)
#define ACIOPHY_CFG0_COMMON_CLAMP_OV BIT(5)
#define AUS_COMMON_SHIM_BIAS         0x0a00
#define AUS_COMMON_SHIM_BGBIAS_OV    BIT(1)
#define AUS_COMMON_DIG_RCAL1         0x804
#define AUS_COMMON_DIG_RCAL_DONE     BIT(0)

#define ACIOPHY_LANE_MODE_T8122       0x60
#define ACIOPHY_LANE_MODE_RX0         GENMASK(2, 0)
#define ACIOPHY_LANE_MODE_TX0         GENMASK(5, 3)
#define ACIOPHY_LANE_MODE_RX1         GENMASK(8, 6)
#define ACIOPHY_LANE_MODE_TX1         GENMASK(11, 9)
#define ACIOPHY_LANE_USB3             1
#define ACIOPHY_LANE_DP               2
#define ACIOPHY_CROSSBAR_T8122        0x64
#define ACIOPHY_CROSSBAR_PROTOCOL     GENMASK(4, 0)
#define ACIOPHY_CROSSBAR_USB3_DP      0x10
#define ACIOPHY_CROSSBAR_USB3_DP_SWAP 0x11
#define ACIOPHY_CROSSBAR_SINGLE_PMA   GENMASK(16, 5)
#define ACIOPHY_CROSSBAR_SINGLE_008   0x008
#define ACIOPHY_CROSSBAR_BOTH_PMA     BIT(17)

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
    const char *adt_fallback;
};

extern const struct atc_tunable_info atc_tunables_t8103[];
extern const size_t atc_tunables_t8103_count;
extern const struct atc_tunable_info atc_tunables_t8122[];
extern const size_t atc_tunables_t8122_count;

/* Return the record count, zero for an absent optional table, or -1 on error. */
int atc_get_tunables(int adt_node, const struct atc_tunable_info *info,
                     const struct atc_tunable **tunables);

int atc_usb3_init_t8122(int adt_node, uintptr_t core);

#endif
