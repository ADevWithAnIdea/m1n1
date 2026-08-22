/* SPDX-License-Identifier: MIT */

#include "hv.h"
#include "utils.h"

#define G17P_INBOX_MESSAGE  0
#define G17P_INBOX_ENDPOINT 8

#define G17P_INIT_ENDPOINT    0x20
#define G17P_WORK_ENDPOINT    0x21
#define G17P_INIT_MESSAGE     0x81
#define G17P_WORK_MESSAGE     0x83
#define G17P_WORK_DOORBELL    10
#define G17P_INITDATA_VA_MASK (BIT(43) - 1)

#define G17P_GATE_TARGETS 3

static u64 g17p_gate_base;
static u64 g17p_gate_message;
static u64 g17p_gate_initdata;
static u32 g17p_gate_proxy_id;
static u32 g17p_gate_kick_count;
static u32 g17p_gate_targets[G17P_GATE_TARGETS];

static void g17p_compute_gate_endpoint(struct exc_info *ctx, u64 endpoint_value)
{
    u32 endpoint = endpoint_value & 0xff;
    u32 message_type = (g17p_gate_message >> 48) & 0xff;

    if (endpoint == G17P_INIT_ENDPOINT && message_type == G17P_INIT_MESSAGE) {
        g17p_gate_initdata = g17p_gate_message & G17P_INITDATA_VA_MASK;
        return;
    }
    if (endpoint != G17P_WORK_ENDPOINT || message_type != G17P_WORK_MESSAGE ||
        (g17p_gate_message & 0xffff) != G17P_WORK_DOORBELL)
        return;

    u32 ordinal = ++g17p_gate_kick_count;
    for (u32 i = 0; i < G17P_GATE_TARGETS; i++) {
        if (g17p_gate_targets[i] != ordinal)
            continue;

        struct hv_vm_proxy_hook_data hook = {
            .flags = FIELD_PREP(MMIO_EVT_WIDTH, 3) | MMIO_EVT_WRITE,
            .id = g17p_gate_proxy_id,
            .addr = g17p_gate_base + G17P_INBOX_ENDPOINT,
            .data = {
                endpoint_value,
                g17p_gate_message,
                g17p_gate_initdata,
                ordinal,
            },
        };
        hv_exc_proxy(ctx, START_HV, HV_HOOK_VM, &hook);
        break;
    }
}

static bool g17p_compute_gate_hook(struct exc_info *ctx, u64 addr, u64 *val, bool write,
                                   int width)
{
    if (!write)
        return hv_pa_rw(ctx, addr, val, false, width);

    u64 offset = addr - g17p_gate_base;
    if (offset == G17P_INBOX_MESSAGE) {
        g17p_gate_message = val[0];
        if (width >= 4)
            g17p_compute_gate_endpoint(ctx, val[1]);
    } else if (offset == G17P_INBOX_ENDPOINT) {
        g17p_compute_gate_endpoint(ctx, val[0]);
    }

    return hv_pa_rw(ctx, addr, val, true, width);
}

__attribute__((used, retain)) int hv_g17p_compute_gate_config(u64 inbox_base, u32 proxy_id,
                                                              u32 target0, u32 target1,
                                                              u32 target2)
{
    g17p_gate_base = inbox_base;
    g17p_gate_message = 0;
    g17p_gate_initdata = 0;
    g17p_gate_proxy_id = proxy_id;
    g17p_gate_kick_count = 0;
    g17p_gate_targets[0] = target0;
    g17p_gate_targets[1] = target1;
    g17p_gate_targets[2] = target2;

    return hv_map_hook(inbox_base, g17p_compute_gate_hook, 0x10);
}
