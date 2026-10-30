/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "dapf.h"
#include "adt.h"
#include "assert.h"
#include "malloc.h"
#include "memory.h"
#include "pmgr.h"
#include "string.h"
#include "utils.h"

struct dapf_t8020_config {
    u64 start;
    u64 end;
    u8 unk1;
    u8 r0_hi;
    u8 r0_lo;
    u8 unk2;
    u32 r4;
} PACKED;

static int dapf_init_t8020(const char *path, u64 base, const void *data, u32 length)
{
    const struct dapf_t8020_config *config = data;

    if ((length % sizeof(*config)) != 0) {
        printf("dapf: Invalid filter data length for %s\n", path);
        return -1;
    }

    int count = length / sizeof(*config);

    for (int i = 0; i < count; i++) {
        write32(base + 0x04, config[i].r4);
        write64(base + 0x08, config[i].start);
        write64(base + 0x10, config[i].end);
        write32(base + 0x00, (config[i].r0_hi << 4) | config[i].r0_lo);
        base += 0x40;
    }
    return 0;
}

struct dapf_t8110_config {
    u64 start;
    u64 end;
    u32 r20;
    u32 unk1;
    u32 r4;
    u32 unk2[5];
    u8 unk3;
    u8 r0_hi;
    u8 r0_lo;
    u8 unk4;
} PACKED;

struct dapf_t8110b_config {
    u64 start;
    u64 end;
    u32 r20;
    u32 unk1;
    u32 r4;
    u32 unk2[5];
    u8 unk3;
    u8 r0_hi;
    u8 r0_lo;
    u8 unk4;
    u32 pad;
} PACKED;

static int dapf_init_t8110a(u64 base, struct dapf_t8110_config *config, u32 length)
{
    int count = length / sizeof(*config);

    for (int i = 0; i < count; i++) {
        write32(base + 0x04, config[i].r4);
        write64(base + 0x08, config[i].start);
        write64(base + 0x10, config[i].end);
        write32(base + 0x00, (config[i].r0_hi << 4) | config[i].r0_lo);
        write32(base + 0x20, config[i].r20);
        base += 0x40;
    }
    return 0;
}

static int dapf_init_t8110b(u64 base, struct dapf_t8110b_config *config, u32 length)
{
    int count = length / sizeof(*config);

    for (int i = 0; i < count; i++) {
        write32(base + 0x04, config[i].r4);
        write64(base + 0x08, config[i].start);
        write64(base + 0x10, config[i].end);
        write32(base + 0x00, (config[i].r0_hi << 4) | config[i].r0_lo);
        write32(base + 0x20, config[i].r20);
        base += 0x40;
    }
    return 0;
}

static int dapf_init_t8110(const char *path, u64 base, const void *config, u32 length)
{
    // The least common multiple of 52 and 56 is 728 which is in the range of
    // the observed lengthe for "dapf-instance-0". The 52 byte variant is more
    // common and prefering that works so far.
    if (length % sizeof(struct dapf_t8110_config) == 0) {
        return dapf_init_t8110a(base, (struct dapf_t8110_config *)config, length);
    } else if (length % sizeof(struct dapf_t8110b_config) == 0) {
        return dapf_init_t8110b(base, (struct dapf_t8110b_config *)config, length);
    } else {
        printf("dapf: Invalid filter data length for %s\n", path);
        return -1;
    }
}

/* dart,t8110 keeps its filter data in the first dapf-instance-N present. */
static const void *dapf_filter_data(int node, u32 *length)
{
    if (!adt_is_compatible(adt, node, "dart,t8110"))
        return adt_getprop(adt, node, "filter-data-instance-0", length);

    for (int i = 0; i < 8; i++) {
        char prop[32];
        snprintf(prop, sizeof(prop), "dapf-instance-%d", i);
        const void *data = adt_getprop(adt, node, prop, length);
        if (data && *length)
            return data;
    }
    return NULL;
}

int dapf_init(const char *path, int index)
{
    int ret;
    int dart_path[8];
    int node = adt_path_offset_trace(adt, path, dart_path);
    if (node < 0) {
        printf("dapf: Error getting DAPF %s node.\n", path);
        return -1;
    }

    u64 base;
    if (adt_get_reg(adt, dart_path, "reg", index, &base, NULL) < 0) {
        printf("dapf: Error getting DAPF %s base address.\n", path);
        return -1;
    }

    bool t8110 = adt_is_compatible(adt, node, "dart,t8110");
    if (!t8110 && !adt_is_compatible(adt, node, "dart,t8020") &&
        !adt_is_compatible(adt, node, "dart,t6000")) {
        printf("dapf: DAPF %s at 0x%lx is of an unknown type\n", path, base);
        return -1;
    }

    /* M4-generation SoCs list no filter data for dart-ave's DAPF. */
    u32 length = 0;
    const void *data = dapf_filter_data(node, &length);
    if (!data || !length) {
        printf("dapf: %s has no filter data\n", path);
        return 0;
    }

    u32 pwr;
    if (!adt_getprop(adt, node, "clock-gates", &pwr))
        pwr = 0;
    if (pwr && (pmgr_adt_power_enable(path) < 0))
        return -1;

    if (t8110)
        ret = dapf_init_t8110(path, base, data, length);
    else
        ret = dapf_init_t8020(path, base, data, length);

    if (pwr)
        pmgr_adt_power_disable(path);

    if (!ret)
        printf("dapf: Initialized %s\n", path);

    return ret;
}

#define DAPF_REG_NONE    -1
#define DAPF_REG_UNKNOWN -2

/* DAPF reg indices for DARTs whose ADT has no "instance" list. */
struct entry {
    const char *path;
    int index;
};

struct entry dapf_entries[] = {
    {"/arm-io/dart-aop", 1},     {"/arm-io/dart-mtp", 1},
    {"/arm-io/dart-pmp", 1},     {"/arm-io/dart-dcp", 1},
    {"/arm-io/dart-dcpext0", 1}, {"/arm-io/dart-isp", 5},
    {"/arm-io/dart-isp0", 5},    {"/arm-io/dart-ane", 3},
    {"/arm-io/dart-ave", 3},     {NULL, -1},
};

static int dapf_table_index(const char *path)
{
    for (struct entry *entry = dapf_entries; entry->path; entry++) {
        if (!strcmp(entry->path, path))
            return entry->index;
    }
    return DAPF_REG_NONE;
}

/*
 * "instance" types a DART's reg ranges by fourcc, as {type, unit, name[8]} for
 * every range, or as {type, name[8]} for the DART ranges only, where an entry
 * of type DAPF puts the DAPF in the range after them.
 */
struct dapf_instance_short {
    u32 type;
    char name[8];
} PACKED;

struct dapf_instance_long {
    u32 type;
    u32 unit;
    char name[8];
} PACKED;

#define DAPF_INSTANCE_TYPE 0x44415046 /* DAPF */

static int dapf_reg_index(const char *path)
{
    int dart_path[8];
    int node = adt_path_offset_trace(adt, path, dart_path);
    if (node < 0)
        return DAPF_REG_UNKNOWN;

    u32 len = 0;
    const void *instance = adt_getprop(adt, node, "instance", &len);
    if (!instance || !len)
        return DAPF_REG_UNKNOWN;

    u32 regs = 0;
    while (!adt_get_reg(adt, dart_path, "reg", regs, NULL, NULL))
        regs++;

    if (len == regs * sizeof(struct dapf_instance_long)) {
        const struct dapf_instance_long *inst = instance;

        for (u32 i = 0; i < regs; i++) {
            if (inst[i].type == DAPF_INSTANCE_TYPE)
                return i;
        }
        return DAPF_REG_NONE;
    }

    if (len % sizeof(struct dapf_instance_short) == 0) {
        const struct dapf_instance_short *inst = instance;
        u32 count = len / sizeof(*inst);

        if (count + 1 != regs)
            return count == regs ? DAPF_REG_NONE : DAPF_REG_UNKNOWN;
        for (u32 i = 0; i < count; i++) {
            if (inst[i].type == DAPF_INSTANCE_TYPE)
                return count;
        }
        return DAPF_REG_NONE;
    }

    return DAPF_REG_UNKNOWN;
}

int dapf_init_all(void)
{
    int ret = 0;
    int count = 0;
    int node = adt_path_offset(adt, "/arm-io");
    if (node < 0)
        return -1;

    ADT_FOREACH_CHILD(adt, node)
    {
        const char *type = adt_getprop(adt, node, "device_type", NULL);
        if (!type || strcmp(type, "dart"))
            continue;

        char path[64];
        snprintf(path, sizeof(path), "/arm-io/%s", adt_get_name(adt, node));

        int index = dapf_reg_index(path);
        if (index == DAPF_REG_UNKNOWN)
            index = dapf_table_index(path);
        if (index == DAPF_REG_NONE)
            continue;

        if (dapf_init(path, index) < 0)
            ret = -1;
        count += 1;
    }
    return ret ? ret : count;
}
