// SPDX-License-Identifier: GPL-2.0-only

#include "pmu.h"
#include "adt.h"
#include "spmi.h"
#include "string.h"
#include "utils.h"

#define PMU_PANIC_COUNTER_OFFSET 2

static bool adt_get_u32(int node, const char *name, u32 *value)
{
    u32 len;
    const void *prop = adt_getprop(adt, node, name, &len);

    if (!prop || len < sizeof(*value))
        return false;

    memcpy(value, prop, sizeof(*value));
    return true;
}

int pmu_reset_panic_counter(void)
{
    int bus = adt_path_offset(adt, "/arm-io");
    if (bus < 0)
        return -1;

    ADT_FOREACH_CHILD(adt, bus)
    {
        if (!adt_is_compatible(adt, bus, "aapl,spmi") &&
            !adt_is_compatible(adt, bus, "spmi,gen3"))
            continue;

        int pmu = bus;
        ADT_FOREACH_CHILD(adt, pmu)
        {
            u32 primary, slave, scratchpad;
            if (!adt_get_u32(pmu, "is-primary", &primary) || primary != 1 ||
                !adt_get_u32(pmu, "reg", &slave) ||
                !adt_get_u32(pmu, "info-leg_scrpad", &scratchpad))
                continue;

            char path[64];
            int len = snprintf(path, sizeof(path), "/arm-io/%s", adt_get_name(adt, bus));
            if (len < 0 || (size_t)len >= sizeof(path))
                return -1;

            spmi_dev_t *spmi = spmi_init(path);
            if (!spmi)
                return -1;

            u8 zero = 0;
            u16 counter = scratchpad + PMU_PANIC_COUNTER_OFFSET;
            int ret = spmi_ext_write_long(spmi, slave, counter, &zero, sizeof(zero));
            spmi_shutdown(spmi);

            if (!ret)
                printf("pmu: cleared panic counter at %s:%02x reg %04x\n", path, slave,
                       counter);
            return ret;
        }
    }

    return -1;
}
