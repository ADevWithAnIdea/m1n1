#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage generated add3 on CL_0 before firmware's first control-start.

This is an experiment-only wrapper around the established cold-boot module. It
does not alter that module: at runtime it wraps the last scalar-publication step,
builds the same compact compute graph used by ``agx_g17p_compute.py``, and leaves
its CL_0 producer visible before initdata is handed to either firmware instance.
"""

import importlib.util
import os
import pathlib
import struct
import sys
import time


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import agx_g17p_compute as compact  # noqa: E402
from m1n1.agx import g17p            # noqa: E402
from m1n1.agx.g17p_shim import G17PShimBackend  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim          # noqa: E402


def load_boot_module():
    path = HERE / "agx_g17p_boot.py"
    name = "m1n1_g17p_compute_initial_start"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute_initial_start.py accepts no arguments")
    for name, value in DRMAsahiShim.G17P_DEFAULTS.items():
        os.environ.setdefault(name, value)

    boot = load_boot_module()
    original_apply_scalars = boot.apply_scalars
    staged = {}

    def stage_before_initdata(arena, instances):
        original_apply_scalars(arena, instances)
        backend = G17PShimBackend(
            boot.u,
            instances[0]["root_va"],
            lambda _channel=0: None,
            context=boot.CONTEXT,
            adopt=True,
            firmware_root="high",
        )
        backend.space.use_absent_handoff()
        compact.prepare_runtime_registration(backend)
        objects, expected, terminator, client_space = compact.build_client_graph(
            backend)
        queue = compact.build_firmware_graph(backend, terminator)
        entry = backend.channels.by_name("CL_0")
        compact.install_active_channel_record(backend)
        published = backend.submitter.stage(
            entry,
            queue,
            (compact.DESCRIPTOR, compact.OPTIONAL, compact.EVENT),
            group_number=1,
            slot=0,
            first_submit=True,
            kind="compute",
            announce=False,
        )
        for address, size in (
            (compact.ITEM_RING, 0x18),
            (compact.QUEUE_POINTERS, 0x80),
            (entry["ring_addr"], g17p.RING_SLOT_SIZE),
        ):
            backend._clean_dva_range(address, size)
        for address in entry["state_addrs"]:
            backend._clean_dva_range(address, 4)
        backend.space.flush()
        backend.u.inst("dsb sy")
        output_pa = objects["output"][1]
        client_before = {
            name: compact.physical_read(
                backend, pa,
                compact.RESOURCE_SIZE if name == "resource" else compact.PAGE,
            )
            for name, (_address, pa) in objects.items()
            if name in ("resource", "input_a", "input_b", "output", "shader")
        }
        before = client_before["output"][:64 * 4]
        staged.update({
            "backend": backend,
            "entry": entry,
            "queue": queue,
            "published": published,
            "objects": objects,
            "expected": expected,
            "output_pa": output_pa,
            "before": before,
            "client_before": client_before,
        })
        print(
            "COMPUTE INITIAL-START staged CL_0 before initdata: "
            "queue=%s channel=%s" % (
                queue.indices(), backend.channels.counters(entry)),
            flush=True,
        )

    boot.apply_scalars = stage_before_initdata
    state = boot.main(list(DRMAsahiShim.G17P_COLD_BOOT_ARGS), return_state=True)
    if not staged:
        raise RuntimeError("pre-initdata compute hook did not run")

    backend = staged["backend"]
    deadline = time.monotonic() + compact.COMPLETION_TIMEOUT
    after = staged["before"]
    while time.monotonic() < deadline:
        after = compact.physical_read(
            backend, staged["output_pa"], len(staged["before"]))
        if after != staged["before"]:
            break
        time.sleep(0.0001)

    print(
        "COMPUTE INITIAL-START result queue=%s channel=%s boot=%s" % (
            staged["queue"].indices(),
            backend.channels.counters(staged["entry"]),
            state["artifact"],
        ),
        flush=True,
    )
    for name in ("resource", "input_a", "input_b", "output", "shader"):
        _address, pa = staged["objects"][name]
        size = compact.RESOURCE_SIZE if name == "resource" else compact.PAGE
        before = staged["client_before"][name]
        current = compact.physical_read(backend, pa, size)
        count, offsets = compact.changed_offsets(before, current)
        print(
            "COMPUTE INITIAL-START client delta %s: %d bytes (%s)" %
            (name, count, offsets),
            flush=True,
        )

    if after == staged["before"]:
        print("COMPUTE INITIAL-START OUTPUT: unchanged", flush=True)
        return 2
    actual = list(struct.unpack("<64f", after))
    if actual != staged["expected"]:
        mismatch = next(
            index for index, pair in enumerate(zip(actual, staged["expected"]))
            if pair[0] != pair[1]
        )
        print(
            "COMPUTE INITIAL-START OUTPUT: changed but wrong at %d: "
            "got %r expected %r" % (
                mismatch, actual[mismatch], staged["expected"][mismatch]),
            flush=True,
        )
        return 3
    print(
        "COMPUTE INITIAL-START OUTPUT: EXECUTED, 64/64 exact add3 results",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
