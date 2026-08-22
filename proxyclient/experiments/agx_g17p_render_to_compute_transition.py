#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fence one native render before repurposing its idle graph for compute."""

import ctypes
import math
import os
import pathlib
import struct
import sys
import tempfile
import types


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"

from m1n1.agx import g17p  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim  # noqa: E402
from m1n1.hw.uat import MemoryAttr  # noqa: E402


PAGE = 0x4000
DEPENDENCY_ALIAS = 0x10008000000


def physical_read(backend, pa, size):
    backend.u.proxy.dc_ivac(pa, size)
    return bytes(backend.u.iface.readmem(pa, size))


def finite_dependency(before, after):
    for offset in range(0, PAGE - 256 + 1, 4):
        body = after[offset:offset + 256]
        values = struct.unpack("<64f", body)
        if (body != before[offset:offset + 256]
                and all(math.isfinite(value) for value in values)):
            return offset, values
    raise RuntimeError(
        "render target has no changed finite 64-float dependency window")


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_render_to_compute_transition.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        # Importing the compute experiment module changes process-wide defaults,
        # so leave it until the ordinary render world is already running.
        from agx_g17p_compute import (
            create_render_cadence_workload,
            drain_boot_group,
            packed_cmdbuf,
            run_render_cadence_submission,
        )

        drain_boot_group(front, backend)
        workload = create_render_cadence_workload(front)
        rendered = run_render_cadence_submission(
            front, backend, workload, "pre-compute dependency render")

        render_fence = backend.pair_fence(
            rendered, name="render-to-compute")
        render_fence.wait(timeout=0.2, event_pump=backend.event_pump)
        if not render_fence.signaled():
            raise RuntimeError("render-to-compute submission fence did not signal")

        target_pa = rendered["semantic_witness_pa"]
        render_before = bytes(PAGE)
        render_after = physical_read(backend, target_pa, PAGE)
        if render_after == render_before:
            raise RuntimeError("render dependency target remained zero")
        dependency_offset, dependency_values = finite_dependency(
            render_before, render_after)
        backend.quiesce_submission(rendered, semantic_complete=True)
        print(
            "MIXED TRANSITION render PASS: TA/3D fences signaled and target "
            "PA %#x changed; dependency window +%#x" % (
                target_pa, dependency_offset),
            flush=True,
        )

        # Render's completed pool/support pages and compute's scheduler/support
        # pages deliberately share native addresses. Construct compute only
        # after both render queues are fenced and quiesced.
        from agx_g17p_compute_source_initial import seed_completed_control_history
        from agx_g17p_native_add3 import (
            CONTEXT,
            build_client_graph,
            build_firmware_graph,
            prepare_client_workload,
            submit_built,
        )

        client = build_client_graph(
            backend,
            distinct_empty_high=True,
            native_shader_attributes=True,
            workload_count=1,
            client_slot_count=1,
            dispatch_grids=((64, 1, 1),),
            threadgroups=((32, 1, 1),),
            indirect_dispatch=True,
            indirect_layout="native",
        )
        queue = build_firmware_graph(
            backend,
            client["terminator"],
            client["space"],
            alias_context0_queue=True,
            item_capacity=1,
            indirect_dispatch=True,
            resource_base=client["resource_base"],
            cdm_base=client["cdm_base"],
        )
        client["space"].uat.iomap_at(
            CONTEXT,
            DEPENDENCY_ALIAS,
            target_pa,
            PAGE,
            AttrIndex=MemoryAttr.Shared,
            AP=2,
            nG=1,
            UXN=1,
            OS=1,
        )
        client["space"].uat.flush_dirty()
        client["space"].uat.invalidate_cache()
        backend.u.proxy.dc_civac(target_pa, PAGE)
        backend.u.inst(
            "dsb sy; tlbi aside1os, x0; dsb sy; isb", CONTEXT << 48)

        dependent = prepare_client_workload(
            client,
            0,
            input_a_dependency={
                "expected": dependency_values,
                "output_dva": DEPENDENCY_ALIAS + dependency_offset,
            },
        )
        client["expected"] = dependent["expected"]
        client["output_pa"] = dependent["output_pa"]
        client["space"].flush()
        backend.u.inst("dsb sy")

        seed_completed_control_history(backend)
        completed = submit_built(front, backend, client, queue=queue)
        if not completed["fence"]["signaled"]:
            raise RuntimeError("dependent compute fence did not signal")
        print(
            "MIXED RENDER->COMPUTE PASS: fenced render PA %#x+%#x was read "
            "by exact dependent add3 output at PA %#x" % (
                target_pa,
                dependency_offset,
                dependent["output_pa"],
            ),
            flush=True,
        )

        compute_pa = dependent["output_pa"]
        compute_before = physical_read(backend, compute_pa, PAGE)
        next_pair = backend.submission_queue_pair()
        if next_pair is None:
            next_pair = backend.queue_pair
        backend.rebuild_registered_submission_graph(next_pair)

        second_target = workload["targets"][workload["next_target"]]
        workload["next_target"] += 1
        render_alias = second_target["address"]
        second_target["target"]._no_push = True
        backend.space.uat.iounmap(
            backend.space.context, render_alias, PAGE)
        backend.space.uat.iomap_at(
            backend.space.context,
            render_alias,
            compute_pa,
            PAGE,
            AttrIndex=MemoryAttr.Shared,
            AP=2,
            nG=1,
            UXN=1,
            OS=1,
        )
        backend.space.uat.flush_dirty()
        backend.space.uat.invalidate_cache()
        backend.u.proxy.dc_civac(compute_pa, PAGE)
        backend.u.inst(
            "dsb sy; tlbi aside1os, x0; dsb sy; isb",
            backend.space.context << 48,
        )

        # The direct compute checkpoint reconstructs completed control history.
        # Reuse the already-admitted render pair without appending an unrelated
        # control generation while testing this data-plane dependency.
        backend.runtime_submission_announced.add(backend.group_number)
        body = packed_cmdbuf(
            64,
            64,
            color_attachment={
                "type": 0,
                "size": PAGE,
                "pointer": render_alias,
            },
        )
        storage = ctypes.create_string_buffer(body)
        args = types.SimpleNamespace(cmdbuf=ctypes.addressof(storage))
        front.submit(front.memfd, args)
        rendered_after_compute = backend.last_submission
        if rendered_after_compute is None:
            raise RuntimeError("compute-to-render produced no submission")
        final_render_fence = backend.pair_fence(
            rendered_after_compute, name="compute-to-render")
        final_render_fence.wait(timeout=0.2, event_pump=backend.event_pump)
        if not final_render_fence.signaled():
            raise RuntimeError("compute-to-render submission fence did not signal")

        final = physical_read(backend, compute_pa, PAGE)
        expected_final = bytearray(compute_before)
        for index, value in enumerate(render_after):
            if value:
                expected_final[index] = value
        if final != bytes(expected_final):
            changed = sum(
                left != right for left, right in zip(final, compute_before))
            mismatched = sum(
                left != right for left, right in zip(final, expected_final))
            raise RuntimeError(
                "compute-to-render target mismatch: changed=%d mismatched=%d" %
                (changed, mismatched))
        print(
            "MIXED COMPUTE->RENDER PASS: exact compute PA %#x was reused as "
            "render attachment %#x and the complete page matched the expected "
            "render-over-compute overlay" % (compute_pa, render_alias),
            flush=True,
        )

        return 0


if __name__ == "__main__":
    raise SystemExit(main())
