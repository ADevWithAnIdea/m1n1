/* SPDX-License-Identifier: MIT */

#include "pmu.h"
#include "adt.h"
#include "spmi.h"
#include "string.h"
#include "types.h"
#include "utils.h"

/* The PMU keeps a count of unclean boots in its legacy scratchpad, and iBoot diverts to
 * recoveryOS once that count passes a threshold. A few crashes in a row therefore leave the
 * machine somewhere only a human at the keyboard can bring it back from, which is expensive
 * when the machine is being driven remotely. Clearing the count on every boot means a crash
 * costs a reboot rather than a recovery trip.
 *
 * This mirrors PMU.reset_panic_counter in proxyclient/m1n1/hw/pmu.py, which does the same
 * thing over the proxy after the fact; doing it here means it happens even when the crash
 * comes before anything can talk to the proxy.
 */
#define PMU_PANIC_COUNTER_OFFSET 2

/* Primary PMUs reached over SPMI. An i2c PMU also has a panic counter, but writing it needs a
 * two-byte register address and this tree's i2c driver only offers one, so those machines are
 * reported rather than poked at a register that would be the wrong one. */
static const char *const pmu_spmi_compatible[] = {
    "pmu,spmi",
    "pmu,d2422",
    "pmu,d2449",
};

static int pmu_reset_panic_counter_spmi(const char *bus_path, int pmu_node)
{
    u32 len = 0;

    /* The first word of reg is the device's address on the bus. Fetched by pointer because
     * the property holds several words and adt_getprop_copy requires an exact length. */
    const void *reg = adt_getprop(adt, pmu_node, "reg", &len);
    if (!reg || len < sizeof(u32)) {
        printf("pmu: no usable reg property under %s\n", bus_path);
        return -1;
    }
    u32 slave;
    memcpy(&slave, reg, sizeof(slave));

    const void *scrpad_prop = adt_getprop(adt, pmu_node, "info-leg_scrpad", &len);
    if (!scrpad_prop || len < sizeof(u32)) {
        printf("pmu: no info-leg_scrpad under %s\n", bus_path);
        return -1;
    }
    u32 scrpad;
    memcpy(&scrpad, scrpad_prop, sizeof(scrpad));

    spmi_dev_t *spmi = spmi_init(bus_path);
    if (!spmi) {
        printf("pmu: spmi_init failed for %s\n", bus_path);
        return -1;
    }

    u8 zero = 0;
    u16 counter = scrpad + PMU_PANIC_COUNTER_OFFSET;
    int ret = spmi_ext_write_long(spmi, slave, counter, &zero, sizeof(zero));
    spmi_shutdown(spmi);

    if (ret < 0) {
        printf("pmu: failed to clear panic counter at %s:%02x reg %04x (%d)\n", bus_path, slave,
               counter, ret);
        return -1;
    }

    printf("pmu: cleared panic counter at %s:%02x reg %04x\n", bus_path, slave, counter);
    return 0;
}

int pmu_reset_panic_counter(void)
{
    int node = adt_path_offset(adt, "/arm-io");
    if (node < 0)
        return -1;

    ADT_FOREACH_CHILD(adt, node)
    {
        if (!adt_is_compatible(adt, node, "aapl,spmi") &&
            !adt_is_compatible(adt, node, "spmi,gen3"))
            continue;

        int it = node;
        ADT_FOREACH_CHILD(adt, it)
        {
            u32 primary = 0;
            if (ADT_GETPROP(adt, it, "is-primary", &primary) < 0 || primary != 1)
                continue;

            for (size_t i = 0; i < ARRAY_SIZE(pmu_spmi_compatible); i++) {
                if (!adt_is_compatible(adt, it, pmu_spmi_compatible[i]))
                    continue;

                char bus_path[64];
                int ret =
                    snprintf(bus_path, sizeof(bus_path), "/arm-io/%s", adt_get_name(adt, node));
                if (ret < 0 || (size_t)ret >= sizeof(bus_path))
                    continue;

                return pmu_reset_panic_counter_spmi(bus_path, it);
            }
        }
    }

    printf("pmu: no primary SPMI PMU found, panic counter left alone\n");
    return -1;
}
