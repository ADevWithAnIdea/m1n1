#include <assert.h>
#include <string.h>

#include "atc.h"
#include "adt.h"
#include "utils.h"

static_assert(sizeof(struct atc_tunable) == 12, "Invalid atc_tunable size");

const struct atc_tunable_info atc_tunables_t8103[] = {
    /* global tunables applied after power on or reset */
    {"tunable_ATC0AXI2AF", "apple,tunable-axi2af", 0x0, 0x4000, true},
    {"tunable_ATC_FABRIC", "apple,tunable-common-b", 0x45000, 0x4000, true},
    {"tunable_USB_ACIOPHY_TOP", "apple,tunable-common-b", 0x0, 0x4000, true},
    {"tunable_AUS_CMN_SHM", "apple,tunable-common-b", 0xa00, 0x4000, true},
    {"tunable_AUS_CMN_TOP", "apple,tunable-common-b", 0x800, 0x4000, true},
    {"tunable_AUSPLL_CORE", "apple,tunable-common-b", 0x2200, 0x4000, true},
    {"tunable_AUSPLL_TOP", "apple,tunable-common-b", 0x2000, 0x4000, true},
    {"tunable_CIO3PLL_CORE", "apple,tunable-common-b", 0x2a00, 0x4000, true},
    {"tunable_CIO3PLL_TOP", "apple,tunable-common-b", 0x2800, 0x4000, true},
    {"tunable_CIO_CIO3PLL_TOP", "apple,tunable-common-b", 0x2800, 0x4000, false},
    /* lane-specific tunables applied after a cable is connected */
    {"tunable_DP_LN0_AUSPMA_TX_TOP", "apple,tunable-lane0-dp", 0xc000, 0x1000, true},
    {"tunable_DP_LN1_AUSPMA_TX_TOP", "apple,tunable-lane1-dp", 0x13000, 0x1000, true},
    {"tunable_USB_LN0_AUSPMA_TX_TOP", "apple,tunable-lane0-usb", 0xc000, 0x1000, true},
    {"tunable_USB_LN0_AUSPMA_RX_TOP", "apple,tunable-lane0-usb", 0x9000, 0x1000, true},
    {"tunable_USB_LN0_AUSPMA_RX_SHM", "apple,tunable-lane0-usb", 0xb000, 0x1000, true},
    {"tunable_USB_LN0_AUSPMA_RX_EQ", "apple,tunable-lane0-usb", 0xa000, 0x1000, true},
    {"tunable_USB_LN1_AUSPMA_TX_TOP", "apple,tunable-lane1-usb", 0x13000, 0x1000, true},
    {"tunable_USB_LN1_AUSPMA_RX_TOP", "apple,tunable-lane1-usb", 0x10000, 0x1000, true},
    {"tunable_USB_LN1_AUSPMA_RX_SHM", "apple,tunable-lane1-usb", 0x12000, 0x1000, true},
    {"tunable_USB_LN1_AUSPMA_RX_EQ", "apple,tunable-lane1-usb", 0x11000, 0x1000, true},
    {"tunable_CIO_LN0_AUSPMA_TX_TOP", "apple,tunable-lane0-cio", 0xc000, 0x1000, true},
    {"tunable_CIO_LN0_AUSPMA_RX_TOP", "apple,tunable-lane0-cio", 0x9000, 0x1000, true},
    {"tunable_CIO_LN0_AUSPMA_RX_SHM", "apple,tunable-lane0-cio", 0xb000, 0x1000, true},
    {"tunable_CIO_LN0_AUSPMA_RX_EQ", "apple,tunable-lane0-cio", 0xa000, 0x1000, true},
    {"tunable_CIO_LN1_AUSPMA_TX_TOP", "apple,tunable-lane1-cio", 0x13000, 0x1000, true},
    {"tunable_CIO_LN1_AUSPMA_RX_TOP", "apple,tunable-lane1-cio", 0x10000, 0x1000, true},
    {"tunable_CIO_LN1_AUSPMA_RX_SHM", "apple,tunable-lane1-cio", 0x12000, 0x1000, true},
    {"tunable_CIO_LN1_AUSPMA_RX_EQ", "apple,tunable-lane1-cio", 0x11000, 0x1000, true},
};

const struct atc_tunable_info atc_tunables_t8122[] = {
    {"tunable_ATC0AXI2AF", "apple,tunable-axi2af", 0x0, 0x8000, true,
     "tunable_ATCAXI2AF"},
    {"tunable_ATC_FABRIC", "apple,tunable-common-b", 0x44000, 0x4000, true},

    {"tunable_CIO3PLL_CORE", "apple,tunable-common-b", 0x2a00, 0x200, true},
    {"tunable_CIO3PLL_TOP", "apple,tunable-common-b", 0x2800, 0x200, true},
    {"tunable_ACIOPHY_LANE_USBC0", "apple,tunable-common-b", 0x5000, 0x1000, true},
    {"tunable_ACIOPHY_PLL_TOP", "apple,tunable-common-b", 0x1000, 0x4000, true},
    {"tunable_ACIOPHY_TOP", "apple,tunable-common-b", 0x0, 0x4000, true},

    {"tunable_AUSCMN_DIG", "apple,tunable-common-b", 0x800, 0x200, true},
    {"tunable_AUSPLL_CORE", "apple,tunable-common-b", 0x2200, 0x4000, true},
    //{"tunable_AUX_SHM", "apple,tunable-common-b", 0x0, 0x0, true}, // TODO: offset?
    {"tunable_AUX_TOP", "apple,tunable-common-b", 0x16000, 0x4000, true},
    {"tunable_AUSCMN_SHM", "apple,tunable-common-b", 0xa00, 0x200, true},
    {"tunable_CLKMON_CFG", "apple,tunable-common-b", 0x2600, 0x100, false},

    {"tunable_LN0_RX_TOP_USB_DFLT", "apple,tunable-lane0-usb", 0x9000, 0x1000, true},
    {"tunable_LN0_RX_TOP_USB_EQA", "apple,tunable-lane0-usb", 0x9000, 0x1000, false},
    {"tunable_LN0_RX_EQ_USB_EQA", "apple,tunable-lane0-usb", 0xa000, 0x1000, true},
    {"tunable_LN0_RX_SHM_USB_DFLT", "apple,tunable-lane0-usb", 0xb000, 0x1000, true},
    {"tunable_LN0_TX_TOP_USB_DFLT", "apple,tunable-lane0-usb", 0xc000, 0x1000, true},
    {"tunable_LN0_TX_SHM_USB_DFLT", "apple,tunable-lane0-usb", 0xd000, 0x1000, true},
    {"tunable_LN0_RX_TOP_CIO_DFLT", "apple,tunable-lane0-cio", 0x9000, 0x1000, true},
    {"tunable_LN0_RX_EQ_CIO_EQA", "apple,tunable-lane0-cio", 0xa000, 0x1000, true},
    {"tunable_LN0_RX_SHM_CIO_DFLT", "apple,tunable-lane0-cio", 0xb000, 0x1000, true},
    {"tunable_LN0_TX_TOP_CIO_DFLT", "apple,tunable-lane0-cio", 0xc000, 0x1000, true},
    {"tunable_LN0_TX_SHM_CIO_DFLT", "apple,tunable-lane0-cio", 0xd000, 0x1000, true},

    {"tunable_LN1_RX_TOP_USB_DFLT", "apple,tunable-lane1-usb", 0x10000, 0x1000, true},
    {"tunable_LN1_RX_TOP_USB_EQA", "apple,tunable-lane1-usb", 0x10000, 0x1000, false},
    {"tunable_LN1_RX_EQ_USB_EQA", "apple,tunable-lane1-usb", 0x11000, 0x1000, true},
    {"tunable_LN1_RX_SHM_USB_DFLT", "apple,tunable-lane1-usb", 0x12000, 0x1000, true},
    {"tunable_LN1_TX_TOP_USB_DFLT", "apple,tunable-lane1-usb", 0x13000, 0x1000, true},
    {"tunable_LN1_TX_SHM_USB_DFLT", "apple,tunable-lane1-usb", 0x14000, 0x1000, true},
    {"tunable_LN1_RX_TOP_CIO_DFLT", "apple,tunable-lane1-cio", 0x10000, 0x1000, true},
    {"tunable_LN1_RX_EQ_CIO_EQA", "apple,tunable-lane1-cio", 0x11000, 0x1000, true},
    {"tunable_LN1_RX_SHM_CIO_DFLT", "apple,tunable-lane1-cio", 0x12000, 0x1000, true},
    {"tunable_LN1_TX_TOP_CIO_DFLT", "apple,tunable-lane1-cio", 0x13000, 0x1000, true},
    {"tunable_LN1_TX_SHM_CIO_DFLT", "apple,tunable-lane1-cio", 0x14000, 0x1000, true},
};

const size_t atc_tunables_t8103_count = ARRAY_SIZE(atc_tunables_t8103);
const size_t atc_tunables_t8122_count = ARRAY_SIZE(atc_tunables_t8122);

int atc_get_tunables(int adt_node, const struct atc_tunable_info *info,
                     const struct atc_tunable **tunables)
{
    *tunables = NULL;
    if (adt_node < 0)
        return -1;

    u32 length;
    const struct atc_tunable *table = adt_getprop(adt, adt_node, info->adt_name, &length);
    if (!table && info->adt_fallback)
        table = adt_getprop(adt, adt_node, info->adt_fallback, &length);
    if (!table) {
        printf("ADT: tunable %s not found\n", info->adt_name);
        return info->required ? -1 : 0;
    }

    if (length % sizeof(*table)) {
        printf("ADT: tunable %s with invalid length %d\n", info->adt_name, length);
        return -1;
    }

    size_t count = length / sizeof(*table);
    for (size_t i = 0; i < count; i++) {
        if (table[i].size != 32) {
            printf("ATC: tunable %s has invalid size %d\n", info->adt_name, table[i].size);
            return -1;
        }
        if (table[i].offset % sizeof(u32)) {
            printf("ATC: tunable %s has unaligned offset %x\n", info->adt_name, table[i].offset);
            return -1;
        }
        if (info->reg_size < sizeof(u32) || table[i].offset > info->reg_size - sizeof(u32)) {
            printf("ATC: tunable %s has invalid offset %x\n", info->adt_name, table[i].offset);
            return -1;
        }
    }

    *tunables = table;
    return count;
}

static int atc_apply_common_tunables(int adt_node, uintptr_t core,
                                     const struct atc_tunable_info *info, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(info[i].fdt_name, "apple,tunable-common-b"))
            continue;

        const struct atc_tunable *tunables;
        int n = atc_get_tunables(adt_node, &info[i], &tunables);
        /* PHY startup requires every common table to be present and nonempty. */
        if (n <= 0)
            return -1;
        for (int j = 0; j < n; j++)
            mask32(core + info[i].reg_offset + tunables[j].offset, tunables[j].mask,
                   tunables[j].value);
    }
    return 0;
}

int atc_usb3_init_t8122(int adt_node, uintptr_t core)
{
    /* T8122-generation ATC power and lane sequence, as in Linux phy-apple-atc. */
    set32(core + ATCPHY_MISC, ATCPHY_MISC_RESET_N);
    set32(core + ATCPHY_POWER_CTRL, ATCPHY_POWER_SLEEP_SMALL);
    if (poll32(core + ATCPHY_POWER_STAT, ATCPHY_POWER_SLEEP_SMALL, ATCPHY_POWER_SLEEP_SMALL,
               100000))
        return -1;
    set32(core + ATCPHY_POWER_CTRL, ATCPHY_POWER_SLEEP_BIG);
    if (poll32(core + ATCPHY_POWER_STAT, ATCPHY_POWER_SLEEP_BIG, ATCPHY_POWER_SLEEP_BIG, 100000))
        return -1;
    clear32(core + ATCPHY_POWER_CTRL, ATCPHY_POWER_CLAMP_EN);
    set32(core + ATCPHY_POWER_CTRL, ATCPHY_POWER_APB_RESET_N);

    bool swapped = read32(core + ATCPHY_MISC) & ATCPHY_MISC_LANE_SWAP;
    if (atc_apply_common_tunables(adt_node, core, atc_tunables_t8122, atc_tunables_t8122_count) <
        0) {
        printf("ATC: tunables failed\n");
        return -1;
    }

    set32(core + ACIOPHY_CFG0, ACIOPHY_CFG0_COMMON_SMALL);
    udelay(10);
    set32(core + ACIOPHY_CFG0, ACIOPHY_CFG0_COMMON_SMALL_OV);
    udelay(10);
    set32(core + ACIOPHY_CFG0, ACIOPHY_CFG0_COMMON_BIG);
    udelay(10);
    set32(core + ACIOPHY_CFG0, ACIOPHY_CFG0_COMMON_BIG_OV);
    udelay(10);
    clear32(core + ACIOPHY_CFG0, ACIOPHY_CFG0_COMMON_CLAMP);
    udelay(10);
    set32(core + ACIOPHY_CFG0, ACIOPHY_CFG0_COMMON_CLAMP_OV);
    udelay(10);
    set32(core + AUS_COMMON_SHIM_BIAS, AUS_COMMON_SHIM_BGBIAS_OV);
    udelay(10);

    u32 lane0 = swapped ? ACIOPHY_LANE_DP : ACIOPHY_LANE_USB3;
    u32 lane1 = swapped ? ACIOPHY_LANE_USB3 : ACIOPHY_LANE_DP;
    mask32(core + ACIOPHY_LANE_MODE_T8122,
           ACIOPHY_LANE_MODE_RX0 | ACIOPHY_LANE_MODE_TX0 | ACIOPHY_LANE_MODE_RX1 |
               ACIOPHY_LANE_MODE_TX1,
           FIELD_PREP(ACIOPHY_LANE_MODE_RX0, lane0) | FIELD_PREP(ACIOPHY_LANE_MODE_TX0, lane0) |
               FIELD_PREP(ACIOPHY_LANE_MODE_RX1, lane1) | FIELD_PREP(ACIOPHY_LANE_MODE_TX1, lane1));
    mask32(core + ACIOPHY_CROSSBAR_T8122,
           ACIOPHY_CROSSBAR_PROTOCOL | ACIOPHY_CROSSBAR_SINGLE_PMA | ACIOPHY_CROSSBAR_BOTH_PMA,
           FIELD_PREP(ACIOPHY_CROSSBAR_PROTOCOL,
                      swapped ? ACIOPHY_CROSSBAR_USB3_DP_SWAP : ACIOPHY_CROSSBAR_USB3_DP) |
               FIELD_PREP(ACIOPHY_CROSSBAR_SINGLE_PMA, ACIOPHY_CROSSBAR_SINGLE_008));

    set32(core + ATCPHY_POWER_CTRL, ATCPHY_POWER_PHY_RESET_N);
    if (poll32(core + AUS_COMMON_DIG_RCAL1, AUS_COMMON_DIG_RCAL_DONE, AUS_COMMON_DIG_RCAL_DONE,
               100000)) {
        printf("ATC: RCAL timed out\n");
        return -1;
    }

    return 0;
}
