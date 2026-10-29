/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "dapf.h"
#include "adt.h"
#include "assert.h"
#include "malloc.h"
#include "memory.h"
#include "pmgr.h"
#include "string.h"
#include "utils.h"

/* Modern ADTs describe the type and logical instance of each reg bank.
 * A bank at the old DAPF index may instead be shared FPAG clock protection. */
enum dapf_bank_type {
    DAPF_BANK_LEGACY,
    DAPF_BANK_TRAD,
    DAPF_BANK_FPAD,
    DAPF_BANK_FPAG,
    DAPF_BANK_OTHER,
    DAPF_BANK_INVALID,
};

struct dapf_instance {
    char type[4];
    u32 instance;
    char name[8];
};

static enum dapf_bank_type dapf_get_bank_type(int node, int index, int *instance)
{
    *instance = -1;
    if (chip_id != T8140)
        return DAPF_BANK_LEGACY;

    u32 length = 0;
    const struct dapf_instance *banks = adt_getprop(adt, node, "instance", &length);

    if (!banks)
        return DAPF_BANK_LEGACY;
    if (length % sizeof(*banks) || index < 0 || (u32)index >= length / sizeof(*banks))
        return DAPF_BANK_INVALID;
    if (!memcmp(banks[index].type, "TRAD", 4))
        return DAPF_BANK_TRAD;
    if (!memcmp(banks[index].type, "FPAG", 4))
        return DAPF_BANK_FPAG;
    if (!memcmp(banks[index].type, "FPAD", 4)) {
        if (banks[index].instance > INT32_MAX)
            return DAPF_BANK_INVALID;
        *instance = banks[index].instance;
        return DAPF_BANK_FPAD;
    }
    return DAPF_BANK_OTHER;
}

struct dapf_t8020_config {
    u64 start;
    u64 end;
    u8 unk1;
    u8 r0_hi;
    u8 r0_lo;
    u8 unk2;
    u32 r4;
} PACKED;

static int dapf_init_t8020(const char *path, u64 base, int node)
{
    u32 length = 0;
    const char *prop = "filter-data-instance-0";
    const struct dapf_t8020_config *config = adt_getprop(adt, node, prop, &length);

    if (!config || !length || (length % sizeof(*config)) != 0) {
        printf("dapf: Error getting ADT node %s property %s.\n", path, prop);
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

static int dapf_init_t8110(const char *path, u64 base, int node, int instance)
{
    u32 length = 0;
    char prop[32];
    const void *config = NULL;

    /* Match the FPAD logical instance, not the reg index. Older ADTs have no
     * instance descriptors; retain their existing property search. */
    if (instance >= 0) {
        snprintf(prop, sizeof(prop), "dapf-instance-%d", instance);
        config = adt_getprop(adt, node, prop, &length);
    } else {
        for (int i = 0; i < 8; i++) {
            snprintf(prop, sizeof(prop), "dapf-instance-%d", i);
            length = 0;
            config = adt_getprop(adt, node, prop, &length);
            if (config && length)
                break;
        }
    }

    if (!config || !length) {
        printf("dapf: Error getting ADT node %s dapf-instance property.\n", path);
        return -1;
    }

    // The least common multiple of 52 and 56 is 728 which is in the range of
    // the observed lengthe for "dapf-instance-0". The 52 byte variant is more
    // common and prefering that works so far.
    if (length % sizeof(struct dapf_t8110_config) == 0) {
        return dapf_init_t8110a(base, (struct dapf_t8110_config *)config, length);
    } else if (length % sizeof(struct dapf_t8110b_config) == 0) {
        return dapf_init_t8110b(base, (struct dapf_t8110b_config *)config, length);
    } else {
        printf("dapf: Invalid length for %s property %s\n", path, prop);
        return -1;
    }
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

    int instance;
    switch (dapf_get_bank_type(node, index, &instance)) {
        case DAPF_BANK_LEGACY:
        case DAPF_BANK_FPAD:
            break;
        case DAPF_BANK_TRAD:
        case DAPF_BANK_FPAG:
        case DAPF_BANK_OTHER:
        case DAPF_BANK_INVALID:
            printf("dapf: Refusing non-FPAD or invalid bank %d of %s\n", index, path);
            return -1;
    }

    u64 base;
    if (adt_get_reg(adt, dart_path, "reg", index, &base, NULL) < 0) {
        printf("dapf: Error getting DAPF %s base address.\n", path);
        return -1;
    }

    const char *power_path = path;
    char owner_path[64];
    u32 pwr = 0;
    if (!adt_getprop(adt, node, "clock-gates", &pwr)) {
        pwr = 0;
        /* Neo puts these gates on the owning device rather than its DART.
         * MTP has neither property and retains the existing ungated path. */
        const char prefix[] = "/arm-io/dart-";
        if (chip_id == T8140 && !strncmp(path, prefix, sizeof(prefix) - 1)) {
            int length = snprintf(owner_path, sizeof(owner_path), "/arm-io/%s",
                                  path + sizeof(prefix) - 1);
            if (length < 0 || (size_t)length >= sizeof(owner_path))
                return -1;
            int owner = adt_path_offset(adt, owner_path);
            if (owner >= 0 && adt_getprop(adt, owner, "clock-gates", &pwr))
                power_path = owner_path;
        }
    }
    if (pwr && (pmgr_adt_power_enable(power_path) < 0))
        return -1;

    if (adt_is_compatible(adt, node, "dart,t8020")) {
        ret = dapf_init_t8020(path, base, node);
    } else if (adt_is_compatible(adt, node, "dart,t6000")) {
        ret = dapf_init_t8020(path, base, node);
    } else if (adt_is_compatible(adt, node, "dart,t8110")) {
        ret = dapf_init_t8110(path, base, node, instance);
    } else {
        printf("dapf: DAPF %s at 0x%lx is of an unknown type\n", path, base);
        ret = -1;
    }

    if (pwr)
        pmgr_adt_power_disable(power_path);

    if (!ret)
        printf("dapf: Initialized %s\n", path);

    return ret;
}

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

int dapf_init_all(void)
{
    int ret = 0;
    int count = 0;
    struct entry *entry = dapf_entries;

    while (entry->path != NULL) {
        int node = adt_path_offset(adt, entry->path);
        if (node < 0) {
            entry++;
            continue;
        }
        int instance;
        switch (dapf_get_bank_type(node, entry->index, &instance)) {
            case DAPF_BANK_LEGACY:
            case DAPF_BANK_FPAD:
            case DAPF_BANK_INVALID: /* Let dapf_init report invalid metadata. */
                break;
            case DAPF_BANK_TRAD:
            case DAPF_BANK_FPAG:
            case DAPF_BANK_OTHER:
                printf("dapf: Skipping non-FPAD bank %d of %s\n", entry->index, entry->path);
                entry++;
                continue;
        }
        if (dapf_init(entry->path, entry->index) < 0) {
            ret = -1;
        }
        entry++;
        count += 1;
    }
    return ret ? ret : count;
}
