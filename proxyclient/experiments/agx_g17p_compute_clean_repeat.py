#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute the coherent minimal native control lifecycle, then two CL2 jobs."""

import os
import struct
import sys
import tempfile


os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"

from m1n1.agx import g17p, g17p_compute as compute, g17p_initdata  # noqa: E402

from agx_g17p_compute_relocated_control import (  # noqa: E402
    install_relocated_boot_module,
)
from agx_g17p_native_add3 import (  # noqa: E402
    CONTEXT,
    OPERAND_TABLE,
    SHARED_SUPPORT,
    SUPPORT_STATE,
    build_client_graph,
    build_firmware_graph,
    submit_built,
    submit_next_workload,
)
PAGE = 0x4000
PRIMARY_RECORD_B = 0xFFFFFC20015E8000


def _registration(control_class, sequence, first_object, operand_table,
                  slot_offset, count):
    body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
    struct.pack_into(
        "<IIII", body, 0,
        0x20, int(control_class), 0x3F, int(sequence),
    )
    struct.pack_into("<Q", body, 0x14, int(first_object))
    struct.pack_into("<Q", body, 0x1C, int(operand_table))
    struct.pack_into("<Q", body, 0x24,
                     int(operand_table) + int(slot_offset))
    struct.pack_into("<I", body, 0x2C, int(count))
    struct.pack_into("<I", body, 0x34, 1)
    return bytes(body)


def _install_exact_context_table(backend):
    """Retain only firmware contexts 0/1 and caller context 2."""
    for context in (0, 1):
        high_root = backend.u.memalign(PAGE, PAGE)
        backend.u.proxy.memset32(high_root, 0, PAGE)
        backend.u.proxy.dc_civac(high_root, PAGE)
        backend.space.uat.set_l0(context, 1, high_root, context)
    for context in range(3, backend.space.uat.NUM_CONTEXTS):
        backend.u.proxy.write64(
            backend.space.uat.gpu_region + context * 16, 0)
        backend.u.proxy.write64(
            backend.space.uat.gpu_region + context * 16 + 8, 0)
    backend.u.proxy.dc_civac(
        backend.space.uat.gpu_region,
        backend.space.uat.NUM_CONTEXTS * 16,
    )
    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()
    backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")


def _adopt_completed_boot_group(backend):
    queues = backend.muxed_queue_pair(0)
    indices = {
        kind: queue.indices()
        for kind, (_entry, queue) in queues.items()
    }
    if any(state["done"] != 3 or state["read"] != 3
           or state["write"] != 3 for state in indices.values()):
        raise RuntimeError(
            "compact startup group is not complete at 3/3/3: %r" % indices)
    backend.adopt_completed_staged_group()
    print("COMPACT STARTUP ADOPTED: queues at 3/3/3", flush=True)


def _run_minimal_control_lifecycle(front, backend):
    runtime = front.g17p_runtime
    if runtime is None:
        raise RuntimeError("source boot exposed no runtime control interface")
    before = runtime["read_control_counters"]()
    if before["primary"] != [2, 2, 2]:
        raise RuntimeError("minimal opening did not retire: %r" % before)

    runtime["announce_runtime_tick"](
        0, "minimal compute tick 0", update_sequence=True)
    runtime["advance_runtime_ticks"](39)

    # The object is compact when the host publishes class 2. Firmware expands
    # it in place into the 36-record scheduler array visible at the later CL2
    # kick. The paired state begins at one at this publication boundary.
    support = compute.build_compute_class2_support(
        OPERAND_TABLE,
        0,
        SUPPORT_STATE,
        active=0,
        resource_class=0x17,
        cursor=0xB8,
        final_kind=3,
    )
    state = bytearray(PAGE)
    struct.pack_into("<Q", state, 0, 1)
    backend._write_dva(SHARED_SUPPORT, support)
    backend._write_dva(SUPPORT_STATE, state)
    backend._clean_dva_range(SHARED_SUPPORT, PAGE)
    backend._clean_dva_range(SUPPORT_STATE, PAGE)
    backend.u.inst("dsb sy")

    trailing_tick = bytearray(g17p.CONTROL_MESSAGE_SIZE)
    struct.pack_into("<II", trailing_tick, 0, 0x2E, 40)
    registration = runtime["announce_control_bodies"]((
        _registration(
            2, 40, SHARED_SUPPORT, OPERAND_TABLE, 0x5C0, 0x28),
        trailing_tick,
    ), "minimal compute class-2 sequence 40 and trailing tick")
    if not registration["consumed"]:
        raise RuntimeError(
            "minimal class-2 registration did not retire: %r" % registration)
    after = runtime["read_control_counters"]()
    if after["primary"] != [44, 44, 44]:
        raise RuntimeError("minimal lifecycle ended at %r" % after)
    if after["secondary"] != [1, 1, 1]:
        raise RuntimeError("minimal secondary lifecycle ended at %r" % after)

    dispatch = g17p_initdata.build_compute_dispatch_record()
    address = (PRIMARY_RECORD_B
               + g17p_initdata.COMPUTE_DISPATCH_RECORD_STRIDE)
    backend._write_dva(address, dispatch)
    backend._clean_dva_range(address, len(dispatch))
    backend.u.inst("dsb sy")
    print(
        "CLEAN COMPUTE lifecycle PASS: primary=%r secondary=%r" %
        (after["primary"], after["secondary"]),
        flush=True,
    )


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute_clean_repeat.py accepts no arguments")
    os.environ["G17P_FINAL_26_6_SECONDARY_TARGET"] = "1"
    install_relocated_boot_module()

    # The shim resolves this module during import, after the relocated compact
    # opening has been installed under the cold-boot module name.
    from m1n1.agx.shim import DRMAsahiShim

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        # The compact startup path already retired pair zero during firmware
        # bring-up. Adopt those indices without ringing its queues again.
        _adopt_completed_boot_group(backend)
        client = build_client_graph(
            backend,
            distinct_empty_high=True,
            native_shader_attributes=True,
            workload_count=2,
        )
        _install_exact_context_table(backend)
        queue = build_firmware_graph(
            backend,
            client["terminator"],
            client["space"],
            alias_context0_queue=True,
            item_capacity=2,
        )
        _run_minimal_control_lifecycle(front, backend)
        submit_built(front, backend, client, queue=queue)
        submit_next_workload(backend, client, queue, 1)
        print(
            "CLEAN COMPUTE REPEAT PASS: 2/2 exact source-built outputs",
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
