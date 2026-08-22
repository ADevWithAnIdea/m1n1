#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Publish the output-positive native-client CL2 job after firmware startup.

This is a deliberately narrow positive control.  Fresh firmware receives the
normal generated cold-boot image.  The clean-room client closure and exact CL2
work descriptor are built before startup, but the queue remains invisible until
both firmware instances acknowledge initdata.  One explicit 0x83 work doorbell
then names CL_2.  Only the known shader-produced t256 output page is success.
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

import agx_g17p_compute as exact  # noqa: E402
from m1n1.agx import g17p          # noqa: E402
from m1n1.agx.g17p_shim import G17PShimBackend  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim          # noqa: E402


def load_boot_module():
    path = HERE / "agx_g17p_boot.py"
    name = "m1n1_g17p_compute_native_initial_start"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_compute_native_initial_start.py accepts no arguments")
    os.environ["M1N1DEVICE"] = "/dev/m1n1-neo"
    os.environ.setdefault("G17P_FINAL_26_6_SECONDARY_LIFECYCLE", "1")
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

        native = exact.install_native_client_context(backend)
        if os.getenv("G17P_COMPUTE_NATIVE_CONTEXT2") == "1":
            exact.install_native_context2(backend)
        if os.getenv("G17P_COMPUTE_NATIVE_FULL_FIRMWARE") == "1":
            exact.install_native_firmware_high_context(backend)
        # The reduced closure inherits low operand pages from the generated
        # context. A full-context positive control already carries the exact
        # captured namespace and must retain it unchanged.
        if not native["full_context"]:
            exact.map_operand_pages(backend, native["space"])
        exact.install_native_compute_primary_records(backend)
        descriptor = native["descriptor"]
        terminator = int.from_bytes(descriptor[0xEE0:0xEE8], "little")
        queue = exact.build_firmware_graph(
            backend,
            terminator,
            reuse_scheduler_lifecycle=False,
            descriptor_override=descriptor,
        )
        entry = backend.channels.by_name("CL_2")
        if entry is None:
            raise RuntimeError("cold boot exposes no CL_2 channel")
        backend.submitter.deferred_producers = []
        published = backend.submitter.stage(
            entry,
            queue,
            (exact.DESCRIPTOR, exact.OPTIONAL, exact.EVENT),
            group_number=1,
            slot=0,
            first_submit=True,
            kind="compute",
            announce=False,
        )
        for address, size in (
            (exact.ITEM_RING, 0x18),
            (exact.QUEUE_POINTERS, 0x80),
            (queue.address, g17p.QUEUE_RECORD_STRIDE),
            (entry["ring_addr"], g17p.RING_SLOT_SIZE),
        ):
            backend._clean_dva_range(address, size)
        backend.space.flush()
        backend.u.inst("dsb sy")
        exact.audit_exact_cl2_pointer_closure(backend, entry, queue)
        if os.getenv("G17P_COMPUTE_NATIVE_KEEP_SLOT3") == "1":
            print(
                "COMPUTE retained native context-3 root in both hardware "
                "slots 3 and %d" % native["hardware_slot"],
                flush=True,
            )
        else:
            native["restore_displaced_logical_slot"]()

        output_pa = native["output_pa"]
        before = exact.physical_read(backend, output_pa, exact.PAGE)
        staged.update({
            "backend": backend,
            "entry": entry,
            "queue": queue,
            "published": published,
            "deferred_producers": list(
                backend.submitter.deferred_producers),
            "output_pa": output_pa,
            "before": before,
            "expected": native["expected_output"],
        })

        def publish_first_work(ascs):
            def ring(channel=0):
                ascs[0].db.send(boot.DoorbellMsg(
                    TYPE=g17p.MSG_WORK_DOORBELL,
                    CHANNEL=int(channel),
                ))

            backend.submitter.doorbell = ring
            deferred = staged["deferred_producers"]
            if len(deferred) != 1:
                raise RuntimeError(
                    "expected one withheld CL_2 producer, got %d" %
                    len(deferred))
            for address, value in deferred:
                backend._write_dva(address, value)
                backend._clean_dva_range(address, len(value))
            backend.submitter.deferred_producers = None
            backend.space.flush()
            backend.u.inst("dsb sy")
            exact.trigger_submission(None, backend, "work", "CL_2")
            staged["rung_during_control"] = True
            print(
                "COMPUTE NATIVE LIVE-PUBLISH sent CL_2 in the native "
                "control 0x84 -> work 0x83 interval",
                flush=True,
            )
            return {"channel": "CL_2", "published": True}

        boot.FINAL_26_6_FIRST_WORK = publish_first_work
        print(
            "COMPUTE NATIVE LIVE-PUBLISH staged CL_2 with producer withheld "
            "before initdata: queue=%s channel=%s hardware_slot=%d "
            "output_pa=%#x" % (
                queue.indices(), backend.channels.counters(entry),
                native["hardware_slot"], output_pa),
            flush=True,
        )

    boot.apply_scalars = stage_before_initdata
    state = boot.main(list(DRMAsahiShim.G17P_COLD_BOOT_ARGS), return_state=True)
    if not staged:
        raise RuntimeError("pre-initdata native compute hook did not run")

    backend = staged["backend"]
    doorbell_message = state["doorbell_message"]

    secondary_target = int(os.getenv(
        "G17P_COMPUTE_NATIVE_SECONDARY_TARGET", "0"), 0)
    if secondary_target:
        secondary_before = 16
        if secondary_target < secondary_before:
            raise ValueError(
                "G17P_COMPUTE_NATIVE_SECONDARY_TARGET must be at least 16")
        missing = secondary_target - secondary_before
        if missing:
            bodies = []
            for _index in range(missing):
                body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
                struct.pack_into("<I", body, 0, 0x22)
                bodies.append(bytes(body))
            secondary = state["announce_secondary_control_bodies"](
                bodies,
                "compute native secondary 0x22 parity",
            )
            if (secondary["crashed"] is not None
                    or not secondary["consumed"]
                    or secondary["after"] != [
                        secondary_target,
                        secondary_target,
                        secondary_target,
                    ]):
                raise RuntimeError(
                    "secondary did not reach requested native parity: %r" %
                    (secondary,))
            print(
                "COMPUTE NATIVE secondary control parity reached %d with "
                "%d consumed 0x22 records" % (secondary_target, missing),
                flush=True,
            )

    rung_during_control = bool(staged.get("rung_during_control"))
    if not rung_during_control:
        def ring(channel=0):
            state["ascs"][0].db.send(doorbell_message(
                TYPE=g17p.MSG_WORK_DOORBELL,
                CHANNEL=int(channel),
            ))

        backend.submitter.doorbell = ring
        if len(staged["deferred_producers"]) != 1:
            raise RuntimeError(
                "expected one withheld CL_2 producer, got %d" %
                len(staged["deferred_producers"]))
        for address, value in staged["deferred_producers"]:
            backend._write_dva(address, value)
            backend._clean_dva_range(address, len(value))
        backend.submitter.deferred_producers = None
        backend.space.flush()
        backend.u.inst("dsb sy")

        before = exact.physical_read(
            backend, staged["output_pa"], exact.PAGE)
        if before != staged["before"]:
            raise RuntimeError(
                "native output page changed before explicit CL_2 publication")
        print(
            "COMPUTE NATIVE LIVE-PUBLISH staged after initdata ACK: "
            "queue=%s channel=%s slot=%d producer=%d" % (
                staged["queue"].indices(),
                backend.channels.counters(staged["entry"]),
                staged["published"]["slot"],
                staged["published"]["producer"],
            ),
            flush=True,
        )
        exact.trigger_submission(None, backend, "work", "CL_2")
        print("COMPUTE NATIVE LIVE-PUBLISH sent explicit CL_2 0x83 doorbell",
              flush=True)

    after = staged["before"]
    deadline = time.monotonic() + 0.1
    while time.monotonic() < deadline:
        for asc in state["ascs"]:
            if asc.has_messages():
                asc.work()
        after = exact.physical_read(
            backend, staged["output_pa"], len(staged["before"]))
        if after == staged["expected"]:
            break
        time.sleep(0.0001)

    changed = sum(
        left != right for left, right in zip(staged["before"], after))
    artifact_dir = pathlib.Path(state["artifact"]).parent
    before_path = artifact_dir / "compute_native_output_before.bin"
    after_path = artifact_dir / "compute_native_output_after.bin"
    before_path.write_bytes(staged["before"])
    after_path.write_bytes(after)
    print(
        "COMPUTE NATIVE LIVE-PUBLISH result queue=%s channel=%s "
        "changed=%d delta=%s boot=%s" % (
            staged["queue"].indices(),
            backend.channels.counters(staged["entry"]),
            changed,
            exact.byte_delta(staged["before"], after) or "none",
            state["artifact"],
        ),
        flush=True,
    )
    print(
        "COMPUTE NATIVE LIVE-PUBLISH pages before=%s after=%s" %
        (before_path, after_path),
        flush=True,
    )
    if after != staged["expected"]:
        print(
            "COMPUTE OUTPUT: NOT EXECUTED, physical page does not match "
            "the known t256 post-write image",
            flush=True,
        )
        return 2
    print(
        "COMPUTE OUTPUT: EXECUTED, native client page changed %d bytes and "
        "matches the known t256 post-write image" % changed,
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
