#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Classify one compute shader store through an unmapped caller BO."""

import os
import pathlib
import struct
import sys
import tempfile
import time


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"

from m1n1.agx import g17p, g17p_compute as compute  # noqa: E402
from m1n1.agx.g17p_backend import G17PQueueFence  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim  # noqa: E402


PAGE = 0x4000
CONTEXT = 2
WORK_DOORBELL_CHANNEL = 0x0a


def physical_read(backend, pa, size):
    backend.u.proxy.dc_ivac(pa, size)
    return bytes(backend.u.iface.readmem(pa, size))


def main(inject_soft_fault=True):
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute_soft_fault.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        from agx_g17p_compute import (
            create_render_cadence_workload,
            drain_boot_group,
            run_render_cadence_submission,
        )

        drain_boot_group(front, backend)
        render_workload = create_render_cadence_workload(front)
        rendered = run_render_cadence_submission(
            front, backend, render_workload, "compute fault prerequisite")
        render_fence = backend.pair_fence(
            rendered, name="compute fault prerequisite")
        render_fence.wait(timeout=0.2, event_pump=backend.event_pump)
        render_pa = rendered["semantic_witness_pa"]
        if not any(physical_read(backend, render_pa, PAGE)):
            raise RuntimeError("prerequisite render produced no output")
        backend.quiesce_submission(rendered, semantic_complete=True)

        from agx_g17p_compute_source_initial import (
            _tick,
            seed_completed_control_history,
        )
        from agx_g17p_native_add3 import (
            OUTER_RING,
            build_client_graph,
            build_firmware_graph,
            prepare_client_workload,
        )

        client = build_client_graph(
            backend,
            distinct_empty_high=True,
            native_shader_attributes=True,
            workload_count=2,
            client_slot_count=2,
            dispatch_grids=((64, 1, 1),) * 2,
            threadgroups=((32, 1, 1),) * 2,
            indirect_dispatch=True,
            indirect_layout="native",
        )
        queue = build_firmware_graph(
            backend,
            client["terminator"],
            client["space"],
            alias_context0_queue=True,
            item_capacity=2,
            indirect_dispatch=True,
            resource_base=client["resource_base"],
            cdm_base=client["cdm_base"],
        )
        prepared = prepare_client_workload(client, 0)
        client["expected"] = prepared["expected"]
        client["output_pa"] = prepared["output_pa"]
        client["space"].flush()
        backend.u.inst("dsb sy")
        seed_completed_control_history(backend)

        entry = backend.channels.by_name("CL_2")
        if entry is None or int(entry["ring_addr"]) != OUTER_RING:
            raise RuntimeError("source world exposes no expected CL_2 channel")
        if backend.channels.counters(entry) != [0, 0, 0]:
            raise RuntimeError("CL_2 is not virgin")

        initial = queue.initial_spec
        published = backend.submitter.stage(
            entry,
            queue,
            (initial["descriptor"], initial["optional"], initial["event"]),
            group_number=1,
            slot=0,
            first_submit=True,
            kind="compute",
            announce=False,
            event_counter_low=2,
        )
        for address, size in (
            (initial["item_ring"], 0x18),
            (initial["pointers"], 0x80),
            (initial["event"], compute.COMPUTE_EVENT_SIZE),
            (OUTER_RING, g17p.RING_SLOT_SIZE),
        ):
            backend._clean_dva_range(address, size)
        for address in entry["state_addrs"]:
            backend._clean_dva_range(address, 4)
        backend.u.inst("dsb sy")

        fence = G17PQueueFence(
            backend.submitter,
            entry,
            queue,
            published,
            name="unmapped-output compute",
        )
        output_dva = client["outputs"][0]["dva"]
        output_pa = client["output_pa"]
        before = physical_read(backend, output_pa, 256)
        if any(before):
            raise RuntimeError("compute output was not zero before publication")
        reports_before = backend.snapshot_report_channel_states()

        if inject_soft_fault:
            client["space"].uat.iounmap(CONTEXT, output_dva, PAGE)
            client["space"].uat.flush_dirty()
            client["space"].uat.invalidate_cache()
            backend.u.inst(
                "dsb sy; tlbi aside1os, x0; dsb sy; isb", CONTEXT << 48)
            if any(pa is not None for pa, _span in
                   client["space"].uat.iotranslate(
                       CONTEXT, output_dva, PAGE)):
                raise RuntimeError("output DVA still translates after unmap")

        backend.submitter.notify(WORK_DOORBELL_CHANNEL)
        deadline = time.monotonic() + 0.2
        while time.monotonic() < deadline and not fence.signaled():
            if backend.event_pump is not None:
                backend.event_pump()
            time.sleep(0.0001)

        after = physical_read(backend, output_pa, 256)
        reports_after = backend.snapshot_report_channel_states()
        queue_state = queue.indices()
        channel_state = backend.channels.counters(entry)
        print("SOFT FAULT queue=%r channel=%r" % (
            queue_state, channel_state), flush=True)
        print("SOFT FAULT reports before=%r" % reports_before, flush=True)
        print("SOFT FAULT reports after=%r" % reports_after, flush=True)

        initial_expected = struct.pack("<64f", *prepared["expected"])
        if inject_soft_fault and after != before:
            raise RuntimeError(
                "unmapped compute output changed physical backing")
        if not inject_soft_fault and after != initial_expected:
            raise RuntimeError(
                "mapped baseline compute output did not match add3")
        if not fence.signaled():
            raise RuntimeError(
                "initial output neither completed nor crashed: queue=%r "
                "channel=%r" % (queue_state, channel_state))
        if inject_soft_fault:
            print(
                "COMPUTE SOFT-FAULT PASS: CL2 completed with unmapped shader "
                "output DVA %#x; original PA %#x remained exactly unchanged" % (
                    output_dva, output_pa),
                flush=True,
            )
        else:
            print(
                "COMPUTE SOFT-FAULT BASELINE initial PASS: mapped output "
                "DVA %#x PA %#x matched exact add3 bytes" % (
                    output_dva, output_pa),
                flush=True,
            )

        from agx_g17p_native_add3 import (
            await_next_workload,
            stage_next_workload,
        )

        runtime = front.g17p_runtime
        if runtime is None:
            raise RuntimeError("soft-fault test has no cold-boot runtime")
        control_before = runtime["read_control_counters"]()["primary"]
        if control_before != [67, 67, 67]:
            raise RuntimeError(
                "post-fault native control suffix requires 67-entry prefix, "
                "got %r" % control_before)
        control_result = runtime["announce_control_bodies"](
            tuple(_tick(sequence) for sequence in range(0x3F, 0xA7)),
            "soft-fault recovery primary control suffix 0x3f..0xa6",
        )
        if (control_result["crashed"] is not None or
                not control_result["consumed"]):
            raise RuntimeError(
                "post-fault native control suffix did not retire: %r" %
                control_result)
        control_after = runtime["read_control_counters"]()["primary"]
        if control_after != [171, 171, 171]:
            raise RuntimeError(
                "post-fault native control suffix ended at %r" %
                control_after)
        print(
            "COMPUTE SOFT-FAULT retired native primary control suffix: "
            "%r -> %r" % (control_before, control_after),
            flush=True,
        )

        acknowledged = backend.acknowledge_report_channels()
        print(
            "COMPUTE SOFT-FAULT returned report credits before recovery: %r" %
            acknowledged,
            flush=True,
        )
        recovery_dva = client["outputs"][1]["dva"]
        recovery_translation = client["space"].uat.iotranslate(
            CONTEXT, recovery_dva, PAGE)
        if (not recovery_translation or
                any(pa is None for pa, _span in recovery_translation)):
            raise RuntimeError(
                "recovery output DVA %#x is not mapped: %r" % (
                    recovery_dva, recovery_translation))
        print(
            "COMPUTE SOFT-FAULT recovery output DVA %#x remains mapped: %r" %
            (recovery_dva, recovery_translation),
            flush=True,
        )
        recovered = stage_next_workload(
            backend,
            client,
            queue,
            1,
            require_previous_retired=True,
            notify=True,
            persistent_runtime_queue=True,
            persistent_startup_queue=True,
            persistent_runtime_fresh_descriptors=True,
            persistent_runtime_fresh_events=True,
            fast_sequential=True,
            strict_release_publish=True,
        )
        recovered_result = await_next_workload(
            backend, recovered, timeout=0.2)
        if recovered_result["actual"] != recovered["workload"]["expected"]:
            raise RuntimeError("post-soft-fault compute output mismatch")
        print(
            "COMPUTE SOFT-FAULT%s RECOVERY PASS: the next persistent-queue "
            "command produced its exact output at PA %#x" %
            ("" if inject_soft_fault else " BASELINE",
             recovered["workload"]["output_pa"]),
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
