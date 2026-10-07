/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

#include "adt.h"

#define SPTM_INIT_MAX_INSTANCES 8
#define FPAG_PROTECTION_BASE    0x140
#define FPAG_PROTECTION_STRIDE  0x40
#define DART_TCR_BYPASS         BIT(1)
#define DART_TCR_APF_BYPASS     BIT(2)
#define DART_TCR_REMAP_ENABLE   BIT(7)

struct sptm_init_allocator {
    u64 next;
    u64 end;
};

struct sptm_init_instances {
    u64 base[SPTM_INIT_MAX_INSTANCES];
    u64 size[SPTM_INIT_MAX_INSTANCES];
    u32 count;
};

struct sptm_init_tunable {
    u32 offset;
    u32 size;
    u64 mask;
    u64 value;
} PACKED;

static void *sptm_init_alloc(struct sptm_init_allocator *allocator, size_t size, size_t alignment)
{
    u64 address = ALIGN_UP(allocator->next, alignment);
    assert(address + size <= allocator->end);
    allocator->next = address + size;
    return (void *)address;
}

static void *sptm_init_alloc_zero(struct sptm_init_allocator *allocator, size_t size,
                                  size_t alignment)
{
    void *result = sptm_init_alloc(allocator, size, alignment);
    memset(result, 0, size);
    return result;
}

static u64 sptm_adt_integer(int node, const char *name, u64 fallback)
{
    u32 size;
    const void *value = adt_getprop(adt, node, name, &size);
    if (!value)
        return fallback;

    u64 result = 0;
    memcpy(&result, value, min(size, (u32)sizeof(result)));
    return result;
}

static bool sptm_adt_has(int node, const char *name)
{
    return adt_get_property(adt, node, name) != NULL;
}

static bool sptm_adt_u32_contains(int node, const char *name, u32 wanted)
{
    u32 size;
    const u32 *values = adt_getprop(adt, node, name, &size);
    if (!values)
        return false;
    for (size_t index = 0; index < size / sizeof(*values); index++) {
        if (values[index] == wanted)
            return true;
    }
    return false;
}

static bool sptm_dart_mapper_sid(int node, u32 sid)
{
    int child = node;
    ADT_FOREACH_CHILD(adt, child)
    {
        if (sptm_adt_u32_contains(child, "reg", sid))
            return true;
    }
    return false;
}

static bool sptm_dart_remap(int node, u32 sid, u32 *target)
{
    u32 size;
    const u32 *remaps = adt_getprop(adt, node, "remap", &size);
    if (!remaps)
        return false;
    for (size_t index = 0; index < size / sizeof(*remaps); index++) {
        if ((remaps[index] & 0xff) == sid) {
            *target = (remaps[index] >> 8) & 0xff;
            return true;
        }
    }
    return false;
}

static void sptm_dart_instances(int node, int *path, struct sptm_init_instances *trad,
                                struct sptm_init_instances *fpag, struct sptm_init_instances *fpad)
{
    u32 size;
    const char *instances = adt_getprop(adt, node, "instance", &size);
    for (size_t index = 0; instances && index < size / 16; index++) {
        struct sptm_init_instances *kind = NULL;
        const char *tag = instances + index * 16;
        if (!memcmp(tag, "TRAD", 4))
            kind = trad;
        else if (!memcmp(tag, "FPAG", 4))
            kind = fpag;
        else if (!memcmp(tag, "FPAD", 4))
            kind = fpad;
        if (!kind)
            continue;

        assert(kind->count < ARRAY_SIZE(kind->base));
        adt_get_reg(adt, path, "reg", index, &kind->base[kind->count], &kind->size[kind->count]);
        kind->count++;
    }
}

static void sptm_dart_sid_states(int node, const char *name, struct sptm_dart_sid *states,
                                 u32 sid_count)
{
    u64 global_dva_base = sptm_adt_integer(node, "vm-base", 0);
    u64 global_dva_size = sptm_adt_integer(node, "vm-size", 0);
    bool dynamic = sptm_adt_integer(node, "dart-options", 0) & 0x10;

    for (u32 sid = 0; sid < sid_count; sid++) {
        struct sptm_dart_sid *state = &states[sid];
        char property[32];
        state->root_level = 1;

        snprintf(property, sizeof(property), "pt-region-%u", sid);
        u32 pt_size;
        const u64 *pt_region = adt_getprop(adt, node, property, &pt_size);
        bool translating = sptm_adt_u32_contains(node, "sid", sid) ||
                           sptm_dart_mapper_sid(node, sid) || (dynamic && sid) || pt_region;
        if (translating) {
            snprintf(property, sizeof(property), "vm-base-%u", sid);
            state->dva_base = sptm_adt_integer(node, property, global_dva_base);
            snprintf(property, sizeof(property), "vm-size-%u", sid);
            state->dva_size = sptm_adt_integer(node, property, global_dva_size);
            state->root_level = state->dva_size > BIT(36) ? 0 : 1;
        }

        u32 remap;
        if (sptm_dart_remap(node, sid, &remap)) {
            state->flags = SPTM_DART_SID_KNOWN | SPTM_DART_SID_POLICY;
            state->tcr = DART_TCR_REMAP_ENABLE | remap << 8;
        } else {
            snprintf(property, sizeof(property), "bypass-%u", sid);
            bool bypass = sptm_adt_has(node, property);
            snprintf(property, sizeof(property), "apf-bypass-%u", sid);
            bool apf_bypass = sptm_adt_has(node, property);
            if (bypass || apf_bypass) {
                state->flags = SPTM_DART_SID_KNOWN | SPTM_DART_SID_ENABLED | SPTM_DART_SID_POLICY;
                state->tcr =
                    (bypass ? DART_TCR_BYPASS : 0) | (apf_bypass ? DART_TCR_APF_BYPASS : 0);
            } else if (translating) {
                state->flags = SPTM_DART_SID_KNOWN;
                state->tcr = DART_TCR_TRANSLATE | (state->root_level ? 0 : BIT(3));
                if (pt_region && pt_size >= 2 * sizeof(u64)) {
                    state->pt_start = pt_region[0];
                    state->pt_end = pt_region[1];
                    snprintf(property, sizeof(property), "l2-tt-%u", sid);
                    state->root = sptm_adt_integer(node, property, state->pt_start);
                    if (!cpu_features->apple_sysregs_unlocked && !strcmp(name, "dart-pmp") &&
                        !sid)
                        state->flags |= SPTM_DART_SID_ENABLED;
                }
            }
        }

        if (sptm_adt_u32_contains(node, "exclave-sid", sid)) {
            state->root = 0;
            state->pt_start = 0;
            state->pt_end = 0;
            state->tcr = 0;
            state->root_level = 1;
            state->flags = SPTM_DART_SID_KNOWN | SPTM_DART_SID_ENABLED | SPTM_DART_SID_EXCLAVE;
        }
    }
}

static u32 sptm_dart_tunables(int node, const struct sptm_init_instances *trad,
                              struct sptm_dart_tunable *output)
{
    u32 count = 0;
    for (u32 instance = 0; instance < trad->count; instance++) {
        char property[40];
        snprintf(property, sizeof(property), "dart-tunables-instance-%u", instance);
        u32 size;
        const struct sptm_init_tunable *tunables = adt_getprop(adt, node, property, &size);
        for (size_t index = 0; tunables && index < size / sizeof(*tunables); index++) {
            assert(count < SPTM_MAX_DART_TUNABLES);
            output[count].base = trad->base[instance];
            output[count].offset = tunables[index].offset;
            output[count].size = tunables[index].size;
            output[count].mask = tunables[index].mask;
            output[count].value = tunables[index].value;
            count++;
        }
    }
    return count;
}

static u32 sptm_dart_dapf(int node, const struct sptm_init_instances *fpad,
                          struct sptm_dart_dapf *output)
{
    u32 count = 0;
    for (u32 instance = 0; instance < fpad->count; instance++) {
        char property[32];
        snprintf(property, sizeof(property), "dapf-instance-%u", instance);
        u32 size;
        const u8 *entries = adt_getprop(adt, node, property, &size);
        if (!entries)
            continue;
        size_t stride = size % 52 == 0 ? 52 : (size % 56 == 0 ? 56 : 55);
        for (size_t index = 0; index < size / stride; index++) {
            const u8 *entry = entries + index * stride;
            struct sptm_dart_dapf *dapf = &output[count++];
            assert(count <= SPTM_MAX_DART_DAPF);
            dapf->base = fpad->base[instance] + index * 0x40;
            memcpy(&dapf->start, entry, sizeof(dapf->start));
            memcpy(&dapf->end, entry + 8, sizeof(dapf->end));
            memcpy(&dapf->r20, entry + 16, sizeof(dapf->r20));
            memcpy(&dapf->r4, entry + 24, sizeof(dapf->r4));
            dapf->control = entry[49] << 4 | entry[50];
        }
    }
    return count;
}

static u32 sptm_dart_clocks(int node, const struct sptm_init_instances *trad,
                            const struct sptm_init_instances *fpag, u64 *output)
{
    u32 size;
    const u32 *slices = adt_getprop(adt, node, "clock-protection-slice-index", &size);
    if (!slices)
        return 0;
    u32 count = min(size / sizeof(*slices), fpag->count * trad->count);
    assert(count <= SPTM_MAX_DART_CLOCKS);
    for (u32 index = 0; index < count; index++) {
        u32 fpag_index = index / trad->count;
        output[index] = fpag->base[fpag_index] + FPAG_PROTECTION_BASE +
                        (slices[index] - 1) * FPAG_PROTECTION_STRIDE;
    }
    return count;
}

static u32 sptm_dart_flags(int node, const char *name)
{
    static const struct {
        const char *property;
        u32 flag;
    } flags[] = {
        {"flush-by-dva", SPTM_DART_FLUSH_BY_DVA},
        {"avoid-tlbi-in-map", SPTM_DART_AVOID_MAP_TLBI},
        {"relaxed-rw-protections", SPTM_DART_RELAXED_RW},
        {"retention", SPTM_DART_RETENTION},
        {"allow-pte-remap", SPTM_DART_ALLOW_PTE_REMAP},
        {"clamp-tlimits", SPTM_DART_CLAMP_TLIMITS},
        {"ignore-secondary", SPTM_DART_IGNORE_SECONDARY},
        {"dart-ungang-shared-ps", SPTM_DART_UNGANG_SHARED_PS},
    };
    u32 result = 0;
    for (size_t index = 0; index < ARRAY_SIZE(flags); index++) {
        if (sptm_adt_has(node, flags[index].property))
            result |= flags[index].flag;
    }

    if (!cpu_features->apple_sysregs_unlocked &&
        (!strcmp(name, "dart-apcie0") || !strcmp(name, "dart-apcie2") ||
         !strcmp(name, "dart-pmp") || !strcmp(name, "dart-usb2")))
        result &= ~SPTM_DART_FLUSH_BY_DVA;
    return result;
}

static void sptm_init_darts(struct sptm_init_allocator *allocator)
{
    int path[8];
    int arm_io = adt_path_offset_trace(adt, "/arm-io", path);
    size_t depth = 0;
    while (path[depth])
        depth++;

    int node = arm_io;
    ADT_FOREACH_CHILD(adt, node)
    {
        if (!adt_is_compatible(adt, node, "dart,t8110") || !sptm_adt_has(node, "dart-id"))
            continue;

        path[depth] = node;
        path[depth + 1] = 0;
        struct sptm_init_instances trad = {0}, fpag = {0}, fpad = {0};
        sptm_dart_instances(node, path, &trad, &fpag, &fpad);
        if (!trad.count || trad.count > SPTM_MAX_DART_INSTANCES)
            continue;

        u32 sid_count = sptm_adt_integer(node, "sid-count", 16);
        struct sptm_dart_sid *states =
            sptm_init_alloc_zero(allocator, sid_count * sizeof(*states), 16);
        struct sptm_dart_dapf *dapf =
            sptm_init_alloc(allocator, SPTM_MAX_DART_DAPF * sizeof(*dapf), 16);
        struct sptm_dart_tunable *tunables =
            sptm_init_alloc(allocator, SPTM_MAX_DART_TUNABLES * sizeof(*tunables), 16);
        u64 *clocks = sptm_init_alloc(allocator, SPTM_MAX_DART_CLOCKS * sizeof(*clocks), 16);
        struct sptm_dart_config *config = sptm_init_alloc_zero(allocator, sizeof(*config), 16);
        const char *name = adt_get_name(adt, node);

        sptm_dart_sid_states(node, name, states, sid_count);
        config->sid_states = (u64)states;
        config->dapf_entries = (u64)dapf;
        config->clock_entries = (u64)clocks;
        config->tunable_entries = (u64)tunables;
        config->dapf_count = sptm_dart_dapf(node, &fpad, dapf);
        config->clock_count = sptm_dart_clocks(node, &trad, &fpag, clocks);
        config->tunable_count = sptm_dart_tunables(node, &trad, tunables);
        config->flags = sptm_dart_flags(node, name);

        u64 info =
            sptm_adt_integer(node, "dart-id", 0) | (u64)sid_count << 32 | (u64)trad.count << 48;
        hv_sptm_configure_dart(info, (u64)config, trad.base[0], trad.base[1], trad.base[2],
                               trad.base[3]);
    }
}

static void sptm_init_sart(void)
{
    int path[8];
    int node = adt_path_offset_trace(adt, "/arm-io/sart-ans", path);
    u64 base, canary_base = 0;
    adt_get_reg(adt, path, "reg", 0, &base, NULL);
    adt_get_reg(adt, path, "reg", 1, &canary_base, NULL);
    u64 canary = canary_base + sptm_adt_integer(node, "power-canary-offset", 0);
    u64 info = sptm_adt_has(node, "exclusive-bounds") ? BIT(16) : 0;
    for (u32 index = 0; index < SPTM_SART_ENTRIES; index++) {
        if (read32(base + index * sizeof(u32)) & 0xff)
            info |= BIT(index);
    }
    hv_sptm_configure_sart(base, canary, info);
}

static void sptm_init_nvme(struct sptm_init_allocator *allocator)
{
    int ans_path[8];
    int ans = adt_path_offset_trace(adt, "/arm-io/ans", ans_path);
    int defaults = adt_path_offset(adt, "/defaults");
    int carveouts = adt_path_offset(adt, "/chosen/carveout-memory-map");
    u64 main_bar, queue_bar;
    adt_get_reg(adt, ans_path, "reg", 3, &main_bar, NULL);
    if (sptm_adt_has(ans, "nvme-secure-reg-layout")) {
        queue_bar = main_bar + 0x4000;
    } else if (sptm_adt_has(defaults, "nvme-iboot-sptm-security") &&
               sptm_adt_has(ans, "nvme-secure-bar")) {
        adt_get_reg(adt, ans_path, "reg", 9, &queue_bar, NULL);
    } else {
        queue_bar = main_bar;
    }

    u32 queue_entries = sptm_adt_integer(ans, "nvme-queue-entries", 64);
    u64 tcb_bytes = ALIGN_UP((u64)queue_entries * SPTM_NVME_TCB_SIZE, SPTM_NVME_TCB_ALIGNMENT);
    u64 prp_bytes = ALIGN_UP((u64)queue_entries * SPTM_NVME_PRP_SLOT_SIZE, SPTM_PAGE_SIZE);
    void *admin_tcbs = sptm_init_alloc_zero(allocator, tcb_bytes, SPTM_PAGE_SIZE);
    void *io_tcbs = sptm_init_alloc_zero(allocator, tcb_bytes, SPTM_PAGE_SIZE);
    void *prp_scratch = sptm_init_alloc_zero(allocator, prp_bytes, SPTM_PAGE_SIZE);
    void *command_state =
        sptm_init_alloc_zero(allocator, queue_entries * SPTM_NVME_COMMAND_SIZE, 16);

    bool tl_wa = sptm_adt_has(ans, "nvme-tl-wa");
    bool vdma_wa = sptm_adt_has(ans, "nvme-vdma-wa");
    bool sha_present = sptm_adt_has(ans, "nvme-ans-sha-present");
    u8 flags =
        sptm_adt_has(ans, "nvme-prp-flush-wa") | tl_wa << 1 | vdma_wa << 2 | sha_present << 3;
    u8 protocol = sptm_adt_has(ans, "nvme-linear-sq") ? 2 : 1;
    u8 tl_slots = tl_wa ? sptm_adt_integer(ans, "nvme-num-sl", 0) : 0;
    u64 packed = queue_entries | (u64)protocol << 32 | (u64)flags << 40 | (u64)tl_slots << 48;
    u64 trusted[2];
    ADT_GETPROP_ARRAY(adt, carveouts, "region-id-55", trusted);

    u64 *config = sptm_init_alloc_zero(allocator, SPTM_NVME_CONFIG_WORDS * sizeof(*config), 16);
    config[0] = queue_bar;
    config[1] = main_bar + 0x28000;
    config[2] = trusted[0];
    config[3] = trusted[0] + trusted[1];
    config[4] = (u64)admin_tcbs;
    config[5] = (u64)io_tcbs;
    config[6] = tcb_bytes;
    config[7] = (u64)prp_scratch;
    config[8] = (u64)command_state;
    config[9] = allocator->end;
    config[10] = packed;
    if (tl_wa) {
        adt_get_reg(adt, ans_path, "reg", 10, &config[11], NULL);
        adt_get_reg(adt, ans_path, "reg", 11, &config[12], NULL);
        adt_get_reg(adt, ans_path, "reg", 12, &config[13], NULL);
    }
    if (vdma_wa)
        adt_get_reg(adt, ans_path, "reg", 13, &config[14], NULL);
    if (sha_present)
        adt_get_reg(adt, ans_path, "reg", 14, &config[15], NULL);
    config[16] = sptm.managed_end;
    hv_sptm_configure_nvme((u64)config);
}

void sptm_init_platform(u64 guest_adt, u64 aux_start, u64 aux_end)
{
    struct sptm_init_allocator allocator = {aux_start, aux_end};
    void *firmware_adt = adt;
    adt = (void *)guest_adt;
    sptm_init_sart();
    sptm_init_nvme(&allocator);
    sptm_init_darts(&allocator);
    adt = firmware_adt;
}
