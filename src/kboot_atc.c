#include <string.h>

#include "kboot_atc.h"
#include "adt.h"
#include "atc.h"
#include "devicetree.h"
#include "malloc.h"
#include "pmgr.h"
#include "utils.h"

#include "libfdt/libfdt.h"

#define MAX_ATC_DEVS 8

struct atc_fuse_info {
    u64 fuse_addr;
    u8 fuse_bit;
    u8 fuse_len;
    u32 reg_offset;
    u32 reg_mask;
};

struct atc_fuse_hw {
    const char *compatible;
    s32 port; /* -1 for don't care */
    const struct atc_fuse_info *fuses;
    size_t n_fuses;
};

static const struct atc_fuse_info atc_fuses_t8103_port0[] = {
    {0x23d2bc434, 9, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x23d2bc434, 15, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x23d2bc434, 21, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x23d2bc434, 23, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x23d2bc434, 4, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x23d2bc430, 29, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x23d2bc430, 26, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x23d2bc434, 2, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x23d2bc430, 31, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x23d2bc434, 4, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t8103_port1[] = {
    {0x23d2bc438, 19, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x23d2bc438, 25, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x23d2bc438, 31, 1, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    /* next three rows are some kind of workaround for port 1 */
    {0x23d2bc438, 14, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x23d2bc43c, 0, 1, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x23d2bc43c, 1, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x23d2bc438, 7, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x23d2bc438, 4, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x23d2bc438, 12, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x23d2bc438, 9, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x23d2bc438, 14, 4, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t6000_port0[] = {
    {0x2922bca14, 5, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x2922bca14, 11, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x2922bca14, 17, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x2922bca14, 19, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x2922bca14, 0, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x2922bca10, 25, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x2922bca10, 22, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x2922bca10, 30, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x2922bca10, 27, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x2922bca14, 0, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t6000_port1[] = {
    {0x2922bca18, 15, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x2922bca18, 21, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x2922bca18, 27, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x2922bca18, 29, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x2922bca18, 10, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x2922bca18, 3, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x2922bca18, 0, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x2922bca18, 8, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x2922bca18, 5, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x2922bca18, 10, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t6000_port2[] = {
    {0x2922bca1c, 25, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x2922bca1c, 31, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x2922bca20, 5, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x2922bca20, 7, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x2922bca1c, 20, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x2922bca1c, 13, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x2922bca1c, 10, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x2922bca1c, 18, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x2922bca1c, 15, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x2922bca1c, 20, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t6000_port3[] = {
    {0x2922bca24, 3, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x2922bca24, 9, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x2922bca24, 15, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x2922bca24, 17, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x2922bca20, 30, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x2922bca20, 23, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x2922bca20, 20, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x2922bca20, 28, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x2922bca20, 25, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x2922bca20, 30, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t6000_port4[] = {
    {0x22922bca14, 5, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x22922bca14, 11, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x22922bca14, 17, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x22922bca14, 19, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x22922bca14, 0, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x22922bca10, 25, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x22922bca10, 22, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x22922bca10, 30, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x22922bca10, 27, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x22922bca14, 0, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t6000_port5[] = {
    {0x22922bca18, 15, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x22922bca18, 21, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x22922bca18, 27, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x22922bca18, 29, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x22922bca18, 10, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x22922bca18, 3, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x22922bca18, 0, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x22922bca18, 8, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x22922bca18, 5, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x22922bca18, 10, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t8112_port0[] = {
    {0x23d2c8484, 3, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x23d2c8484, 9, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x23d2c8484, 15, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x23d2c8484, 17, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x23d2c8480, 30, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x23d2c8480, 23, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x23d2c8480, 20, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x23d2c8480, 28, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x23d2c8480, 25, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x23d2c8480, 30, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

static const struct atc_fuse_info atc_fuses_t8112_port1[] = {
    {0x23d2c8488, 13, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE0},
    {0x23d2c8488, 19, 6, CIO3PLL_DCO_NCTRL, CIO3PLL_DCO_COARSEBIN_EFUSE1},
    {0x23d2c8488, 25, 2, CIO3PLL_FRACN_CAN, CIO3PLL_DLL_CAL_START_CAPCODE},
    {0x23d2c8488, 27, 3, CIO3PLL_DTC_VREG, CIO3PLL_DTC_VREG_ADJUST},
    {0x23d2c8488, 8, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
    {0x23d2c8488, 1, 2, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_ENCAP_EFUSE},
    {0x23d2c8484, 30, 3, AUSPLL_DCO_EFUSE_SPARE, AUSPLL_RODCO_BIAS_ADJUST_EFUSE},
    {0x23d2c8488, 6, 2, AUSPLL_FRACN_CAN, AUSPLL_DLL_START_CAPCODE},
    {0x23d2c8488, 3, 3, AUSPLL_CLKOUT_DTC_VREG, AUSPLL_DTC_VREG_ADJUST},
    {0x23d2c8488, 8, 5, AUS_COMMON_SHIM_BLK_VREG, AUS_VREG_TRIM},
};

// Order "atc-phy" compatibles in reverse chronologically order to deal with mutliple compatible
// strings in ADT atc-phy nodes.
static const struct atc_fuse_hw atc_fuses[] = {
    {"atc-phy,t8132", -1, NULL, 0},
    {"atc-phy,t8122", -1, NULL, 0},
    {"atc-phy,t6020", -1, NULL, 0},
    {"atc-phy,t8112", 0, atc_fuses_t8112_port0, ARRAY_SIZE(atc_fuses_t8112_port0)},
    {"atc-phy,t8112", 1, atc_fuses_t8112_port1, ARRAY_SIZE(atc_fuses_t8112_port1)},
    /* t6002 uses the same fuses and the same atc-phy,t6000 compatible */
    {"atc-phy,t6000", 0, atc_fuses_t6000_port0, ARRAY_SIZE(atc_fuses_t6000_port0)},
    {"atc-phy,t6000", 1, atc_fuses_t6000_port1, ARRAY_SIZE(atc_fuses_t6000_port1)},
    {"atc-phy,t6000", 2, atc_fuses_t6000_port2, ARRAY_SIZE(atc_fuses_t6000_port2)},
    {"atc-phy,t6000", 3, atc_fuses_t6000_port3, ARRAY_SIZE(atc_fuses_t6000_port3)},
    {"atc-phy,t6000", 4, atc_fuses_t6000_port4, ARRAY_SIZE(atc_fuses_t6000_port4)},
    {"atc-phy,t6000", 5, atc_fuses_t6000_port5, ARRAY_SIZE(atc_fuses_t6000_port5)},
    {"atc-phy,t8103", 0, atc_fuses_t8103_port0, ARRAY_SIZE(atc_fuses_t8103_port0)},
    {"atc-phy,t8103", 1, atc_fuses_t8103_port1, ARRAY_SIZE(atc_fuses_t8103_port1)},
};

static u32 read_fuse(const struct atc_fuse_info *fuse)
{
    union {
        u64 dword;
        u32 words[2];
    } fuse_data;

    if (fuse->fuse_bit + fuse->fuse_len > 64) {
        printf("kboot: ATC fuse 0x%lx:%d:%d out of range\n", fuse->fuse_addr, fuse->fuse_bit,
               fuse->fuse_len);
        return 0;
    }

    /* Any other read triggers SErrors */
    fuse_data.words[0] = read32(fuse->fuse_addr);
    fuse_data.words[1] = read32(fuse->fuse_addr + 4);

    /*
     * Assuming we read 01 23 45 67 89 ab cd ef above and have bit_offset 12
     * and len 4 we want to end up with 0x2. When treating the data as u64
     * this is 0xefcdab8967452301 such that we can simply shift it by 12 bits
     * to get 0x000efcdab8967452 and then AND it with 0xf to
     * finally get 0x2 which is the value we want.
     */
    fuse_data.dword >>= fuse->fuse_bit;
    fuse_data.dword &= (1ULL << fuse->fuse_len) - 1;
    return FIELD_PREP(fuse->reg_mask, fuse_data.dword);
}

static int dt_append_atc_fuses_helper(void *dt, int fdt_node, const struct atc_fuse_info *fuses,
                                      size_t n_fuses)
{
    for (size_t i = 0; i < n_fuses; ++i) {
        if (fdt_appendprop_u32(dt, fdt_node, "apple,tunable-common-a", fuses[i].reg_offset) < 0)
            return -1;
        if (fdt_appendprop_u32(dt, fdt_node, "apple,tunable-common-a", fuses[i].reg_mask) < 0)
            return -1;
        if (fdt_appendprop_u32(dt, fdt_node, "apple,tunable-common-a", read_fuse(&fuses[i])) < 0)
            return -1;
    }

    return 0;
}

static int dt_append_fuses(void *dt, int adt_node, int fdt_node, int port)
{
    for (size_t i = 0; i < ARRAY_SIZE(atc_fuses); ++i) {
        if (!adt_is_compatible_at(adt, adt_node, atc_fuses[i].compatible, 0))
            continue;
        if (atc_fuses[i].port >= 0 && port != atc_fuses[i].port)
            continue;

        /*
         * Starting with t6020 fuses are no longer required. Create an empty
         * property to indicate to the driver that no fuses are intentional.
         */
        if (!atc_fuses[i].fuses)
            return fdt_setprop(dt, fdt_node, "apple,tunable-common-a", NULL, 0);

        return dt_append_atc_fuses_helper(dt, fdt_node, atc_fuses[i].fuses, atc_fuses[i].n_fuses);
    }

    /*
     * don't fail here until we have added all devices to retain backwards
     * compatibility with the previous atcphy version
     */
    printf("kboot: no fuses found for atcphy port %d\n", port);
    return 0;
}

static int dt_append_atc_tunable(void *dt, int adt_node, int fdt_node,
                                 const struct atc_tunable_info *tunable_info)
{
    const struct atc_tunable *tunable_adt;
    int count = atc_get_tunables(adt_node, tunable_info, &tunable_adt);
    if (count < 0)
        return -1;

    for (int j = 0; j < count; j++) {
        const struct atc_tunable *tunable = &tunable_adt[j];

        if (fdt_appendprop_u32(dt, fdt_node, tunable_info->fdt_name,
                               tunable->offset + tunable_info->reg_offset) < 0)
            return -1;
        if (fdt_appendprop_u32(dt, fdt_node, tunable_info->fdt_name, tunable->mask) < 0)
            return -1;
        if (fdt_appendprop_u32(dt, fdt_node, tunable_info->fdt_name, tunable->value) < 0)
            return -1;
    }

    return 0;
}

static void dt_copy_atc_tunables(void *dt, const char *adt_path, const char *dt_alias, int port)
{
    int ret;
    const struct atc_tunable_info *tunables;
    size_t tunable_count;

    int adt_node = adt_path_offset(adt, adt_path);
    if (adt_node < 0)
        return;

    const char *fdt_path = fdt_get_alias(dt, dt_alias);
    if (fdt_path == NULL) {
        printf("FDT: Unable to find alias %s\n", dt_alias);
        return;
    }

    int fdt_node = fdt_path_offset(dt, fdt_path);
    if (fdt_node < 0) {
        printf("FDT: Unable to find path %s for alias %s\n", fdt_path, dt_alias);
        return;
    }

    ret = dt_append_fuses(dt, adt_node, fdt_node, port);
    if (ret) {
        printf("kboot: Unable to copy ATC fuses for %s - USB3/Thunderbolt will not work\n",
               adt_path);
        goto cleanup;
    }

    if (adt_is_compatible_at(adt, adt_node, "atc-phy,t8132", 0) ||
        adt_is_compatible_at(adt, adt_node, "atc-phy,t8122", 0)) {
        tunables = &atc_tunables_t8122[0];
        tunable_count = atc_tunables_t8122_count;
    } else {
        tunables = &atc_tunables_t8103[0];
        tunable_count = atc_tunables_t8103_count;
    }

    for (size_t i = 0; i < tunable_count; ++i) {
        ret = dt_append_atc_tunable(dt, adt_node, fdt_node, &tunables[i]);
        if (ret)
            goto cleanup;
    }

    /*
     * For backwards compatibility with downstream drivers copy apple,tunable-common-b to
     * apple,tunable-common.
     * Don't remove this before 2027-01-01.
     */
    int prop_len;
    const void *tunable_common_b_fdt =
        fdt_getprop(dt, fdt_node, "apple,tunable-common-b", &prop_len);
    if (!tunable_common_b_fdt) {
        printf("kboot: Unable to find apple,tunable-common-b for %s\n", adt_path);
        goto cleanup;
    }

    void *tunable_common_b = malloc(prop_len);
    if (!tunable_common_b) {
        printf("kboot: Unable to copy apple,tunable-common-b to apple,tunable-common for %s\n",
               adt_path);
        goto cleanup;
    }
    memcpy(tunable_common_b, tunable_common_b_fdt, prop_len);

    ret = fdt_setprop(dt, fdt_node, "apple,tunable-common", tunable_common_b, prop_len);
    free(tunable_common_b);
    if (ret) {
        printf("kboot: Unable to copy apple,tunable-common-b to apple,tunable-common for %s\n",
               adt_path);
        goto cleanup;
    }

    return;

cleanup:
    /*
     * USB3 and Thunderbolt won't work if something went wrong. Clean up to make
     * sure we don't leave half-filled properties around so that we can at least
     * try to boot with USB2 support only.
     */
    for (size_t i = 0; i < atc_tunables_t8103_count; ++i)
        fdt_delprop(dt, fdt_node, atc_tunables_t8103[i].fdt_name);
    fdt_delprop(dt, fdt_node, "apple,tunable-common-a");
    fdt_delprop(dt, fdt_node, "apple,tunable-common");

    printf("FDT: Unable to setup ATC tunables for %s - USB3/Thunderbolt will not work\n", adt_path);
}

int kboot_setup_atc(void *dt)
{
    char adt_path[32];
    char fdt_alias[32];

    for (int i = 0; i < MAX_ATC_DEVS; ++i) {
        memset(adt_path, 0, sizeof(adt_path));
        snprintf(adt_path, sizeof(adt_path), "/arm-io/atc-phy%d", i);

        memset(fdt_alias, 0, sizeof(adt_path));
        snprintf(fdt_alias, sizeof(fdt_alias), "atcphy%d", i);

        dt_copy_atc_tunables(dt, adt_path, fdt_alias, i);
    }

    return 0;
}
