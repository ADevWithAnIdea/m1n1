#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Alternate packed DRM submissions between two file-private G17P VMs.

This is the hardware gate for drm-shim's process boundary. Each synthetic DRM
file receives the same GPU virtual address for a distinct memfd range. The test
submits A, switches the admitted firmware context's UAT root to B, destroys B's
queue, BO, and context, then switches back and submits A again. Success proves
serialized VM isolation rather than reliance on globally unique addresses.
"""

import argparse
import ctypes
import datetime
import hashlib
import os
import pathlib
import struct
import sys
import tempfile
import types

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.setdefault("AGX_GPU", "G17")

from m1n1.agx.g17p_shim import (                          # noqa: E402
    G17PUnsupported,
    uncompressed_twiddled_size,
)
from m1n1.agx import g17p                                  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim                     # noqa: E402

from agx_g17p_compare_live_dump import snapshot_pages, snapshot_read  # noqa: E402
from agx_g17p_shim_submit import packed_cmdbuf, sample_page_heads  # noqa: E402


PAGE = 0x4000
WIDTH = 64
HEIGHT = 64
FILE_A = 0x41
FILE_B = 0x42


PROFILES = {
    "native-aba": {
        "G17P_COLD_BOOT": "1",
        "G17P_LOGICAL_VM_SWITCH": "1",
        "G17P_MIRROR_REGISTERED_VM": "1",
        "G17P_SHARED_RETAINED_PIPELINES": "1",
        "G17P_CLEAR_A_BEFORE_B": "1",
        "G17P_WAIT_CHANNEL_COMPLETION": "1",
        "G17P_REUSE_QUEUE_ITEMS": "0",
        "G17P_ALTERNATE_QUEUE_PAIRS": "1",
        "G17P_RUNTIME_PAIR_REGISTRATION": "1",
        "G17P_RUNTIME_PAIR_GROWTH": "1",
        "G17P_RUNTIME_LOW_ROOT_GROWTH": "1",
    },
    "root-switch-aba": {
        "G17P_LOGICAL_VM_SWITCH": "1",
        "G17P_LOGICAL_VM_STRIDE": "0",
    },
}


def configure_profile():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile", choices=sorted(PROFILES),
        help="set the hardware-proven multicontext experiment defaults",
    )
    parser.add_argument(
        "--diagnostics", action="store_true",
        help="save the pair-one graph and both ASC mailbox histories on failure",
    )
    args = parser.parse_args()
    if args.profile:
        for name, value in PROFILES[args.profile].items():
            os.environ.setdefault(name, value)
    if args.diagnostics:
        os.environ.setdefault("G17P_DUMP_PAIR1_PRE_NOTIFY", "1")
        os.environ.setdefault("G17P_DUMP_REFUSED_PAIR", "1")
        os.environ.setdefault("G17P_CRASH_POSTMORTEM", "1")
    return args


PAIR1_DUMP_OBJECTS = (
    (0xfffffc2000000000, 0x100),
    (0xfffffc20000150e0, 0x80),
    (0xfffffc2000228000, 0x20000),
    (0xfffffc2000250000, 0x20000),
    (0xfffffc20015f8000, 0x4000),
    (0xfffffc2001620000, 0x4000),
    (0xfffffc2001640000, 0x4000),
    (0xfffffc2001648000, 0x4000),
    (0xfffffc2001658000, 0x80),
    (0xfffffc20c0000180, 0x180),
    (0xfffffc20c000d0e0, 0x4000),
    (0xfffffc20c00189c0, 0x9c0),
    (0xfffffc20c00b2240, 0x2240),
    (0xfffffc20c05e8080, 0x440),
    (0xfffffc20c0600180, 0x180),
    (0xfffffc20c07b8000, 0x4000),
    (0xfffffc20c0820100, 0x2300),
    (0xfffffc20c0870080, 0x2780),
    (0xfffffc20c0872800, 0x100),
    (0xfffffc20c0878000, 0x4000),
    (0xfffffc20c0888000, 0x4000),
    (0xfffffc20c08a0000, 0x88),
    (0xfffffc20c08a8000, 0x4000),
)


def dump_refused_pair(backend, label):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    root = pathlib.Path(os.getenv(
        "G17P_ARTIFACTS", "/Users/user/asahi_re/artifacts/agx_g17p"))
    output = root / ("refused_pair1_%s_%s" % (label, stamp))
    output.mkdir(parents=True, exist_ok=False)
    skipped = []
    for address, size in PAIR1_DUMP_OBJECTS:
        try:
            body = backend._read_dva(address, size)
        except Exception as exc:  # noqa: BLE001
            skipped.append((address, size, str(exc)))
            continue
        (output / ("%016x.bin" % address)).write_bytes(body)
    if skipped:
        (output / "unmapped.txt").write_text("".join(
            "%#x:%#x %s\n" % row for row in skipped))
    print("Saved refused graph to %s; %d spans unmapped" % (
        output, len(skipped)), flush=True)
    return output


def dump_native_high_graph(backend, pages, label):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    root = pathlib.Path(os.getenv(
        "G17P_ARTIFACTS", "/Users/user/asahi_re/artifacts/agx_g17p"))
    output = root / ("native_high_graph_%s_%s" % (label, stamp))
    output.mkdir(parents=True, exist_ok=False)
    addresses = sorted(
        address for context, selector, address in pages
        if context == 64 and selector == 1)
    skipped = []
    for address in addresses:
        try:
            body = backend._read_dva(address, PAGE)
        except Exception:
            skipped.append(address)
            continue
        (output / ("%016x.bin" % address)).write_bytes(body)
    if skipped:
        (output / "unmapped.txt").write_text(
            "".join("%#x\n" % address for address in skipped))
    print("Saved %d-page firmware high graph to %s; %d native pages unmapped" % (
        len(addresses) - len(skipped), output, len(skipped)), flush=True)
    return output


def translated_pa(backend, context, address):
    translated = backend.execution_contexts[context]["space"].uat.iotranslate(
        context, address, PAGE)
    if not translated or translated[0][0] is None:
        raise RuntimeError(
            "context %d does not translate color address %#x" %
            (context, address))
    return translated[0][0]


def heads(backend, obj):
    return sample_page_heads(
        backend,
        {"dva": obj._addr, "pa": obj._pa, "size": obj._size},
        invalidate_only=True,
    )


def physical_contents(backend, obj):
    backend.u.proxy.dc_civac(obj._pa, obj._size)
    return bytes(backend.u.iface.readmem(obj._pa, obj._size))


def object_state(backend, context):
    """Read complete firmware-visible output objects through one logical VM."""
    state = {}
    space = backend.execution_contexts[context]["space"]
    objects = backend.execution_contexts[context]["render_objects"]
    for name, obj in sorted(objects.items()):
        ranges = space.uat.iotranslate(context, obj._addr, obj._size)
        for pa, size in ranges:
            if pa is None:
                raise RuntimeError(
                    "context %d does not translate %s at %#x" %
                    (context, name, obj._addr))
            backend.u.proxy.dc_civac(pa, size)
        body = space.uat.ioread(context, obj._addr, obj._size)
        state[name] = bytes(body)
    return state


def print_object_delta(label, before, after):
    names = sorted(set(before) | set(after))
    for name in names:
        old = before.get(name, bytes(len(after.get(name, b""))))
        new = after.get(name, bytes(len(old)))
        changed = sum(a != b for a, b in zip(old, new)) + abs(len(old) - len(new))
        nonzero = sum(value != 0 for value in new)
        digest = hashlib.sha256(new).hexdigest()[:16]
        print(
            "%s %-20s changed=%-6d nonzero=%-6d sha256=%s head=%s" % (
                label, name, changed, nonzero, digest, new[:32].hex()),
            flush=True,
        )


def print_submission_state(backend, label, submission):
    headers = {}
    for kind in ("tiling", "fragment"):
        address = submission["items"][kind][0]
        selector, sequence, context = struct.unpack(
            "<IQI", backend._read_dva(address, 16))
        headers[kind] = {
            "address": address,
            "selector": selector,
            "sequence": sequence,
            "context": context,
        }
    table = []
    for slot in range(backend.space.uat.NUM_CONTEXTS):
        base = backend.space.uat.gpu_region + slot * 16
        low = backend.u.proxy.read64(base)
        high = backend.u.proxy.read64(base + 8)
        if low or high:
            table.append((slot, low, high))
    print("%s descriptor headers: %r" % (label, headers), flush=True)
    print("%s hardware UAT slots: %r" % (label, table), flush=True)
    produced = {
        index: backend.channels.counters(backend.channels.entries[index])
        for index in range(12, len(backend.channels.entries))
    }
    print("%s firmware-produced channel counters: %r" % (
        label, produced), flush=True)


def submit(front, file_id, storage, label):
    try:
        result = front.submit(
            file_id,
            types.SimpleNamespace(cmdbuf=ctypes.addressof(storage)),
        )
    except Exception:
        if os.getenv("G17P_DUMP_REFUSED_PAIR") == "1":
            dump_refused_pair(front.g17p, label)
        if os.getenv("G17P_CRASH_POSTMORTEM") == "1":
            runtime = getattr(front, "g17p_boot_runtime", None) or {}
            capture = runtime.get("capture_crash_postmortem")
            if capture is None:
                print("No in-process ASC runtime is available for crash postmortem",
                      flush=True)
            else:
                capture("%s_refusal" % label)
        raise
    submission = front.g17p.last_submission
    if result != 0 or not front.g17p.pair_queue_completed(submission):
        raise RuntimeError(
            "%s did not complete its firmware queues (return %r)" %
            (label, result))
    queues = {
        kind: submission[kind]["queue"].indices()
        for kind in ("tiling", "fragment")
    }
    print("%s queues completed in context %d: %s; scheduler_drained=%s" % (
        label, front.g17p.active_execution_context, queues,
        front.g17p.pair_retired(submission)), flush=True)
    if os.getenv("G17P_MULTICONTEXT_DIAGNOSTIC_STATE") == "1":
        print_submission_state(front.g17p, label, submission)
    return submission


def main():
    configure_profile()
    size = uncompressed_twiddled_size(WIDTH, HEIGHT)
    if size != PAGE:
        raise AssertionError("64x64 BGRA8 should occupy exactly one GPU page")

    fresh_a_control = os.getenv("G17P_SECOND_A_FRESH_TARGET") == "1"

    with tempfile.TemporaryFile() as memfd:
        memfd.truncate((3 if fresh_a_control else 2) * size)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        dump_pre_notify = os.getenv("G17P_DUMP_PAIR1_PRE_NOTIFY") == "1"
        dump_high_graph = (
            os.getenv("G17P_DUMP_NATIVE_HIGH_GRAPH_PRE_NOTIFY") == "1")
        dump_a2_high_graph = (
            os.getenv("G17P_DUMP_NATIVE_A2_HIGH_GRAPH_PRE_NOTIFY") == "1")
        transplant_native = os.getenv(
            "G17P_TRANSPLANT_NATIVE_PAIR1_DESCRIPTORS", "")
        if (dump_pre_notify or dump_high_graph or dump_a2_high_graph
                or transplant_native):
            dumped = set()
            native_pages = None
            if transplant_native or dump_high_graph or dump_a2_high_graph:
                native_snapshot = pathlib.Path(os.getenv(
                    "G17P_NATIVE_PAIR1_SNAPSHOT",
                    "/Users/user/asahi_re/artifacts/agx_g17p/"
                    "second_0x83_20260729_032917"))
                native_pages = snapshot_pages(native_snapshot)
                if transplant_native:
                    if transplant_native == "1":
                        transplant_native = "both"
                    if transplant_native not in ("both", "tiling", "fragment"):
                        raise RuntimeError(
                            "G17P_TRANSPLANT_NATIVE_PAIR1_DESCRIPTORS must be "
                            "both, tiling, or fragment")

            def pre_notify_dump(current, pair_index):
                if dump_a2_high_graph and current.group_number == 2:
                    dump_native_high_graph(current, native_pages, "A2-pre-notify")
                if pair_index == 1 and pair_index not in dumped:
                    if transplant_native:
                        descriptors = {
                            "tiling": (0xfffffc20c00189c0, 0x9c0),
                            "fragment": (0xfffffc20c00b2240, 0x2240),
                        }
                        names = descriptors if transplant_native == "both" \
                            else (transplant_native,)
                        for name in names:
                            address, size = descriptors[name]
                            body, missing = snapshot_read(
                                native_pages, address, size)
                            if body is None:
                                raise RuntimeError(
                                    "native %s descriptor page %#x is absent" %
                                    (name, missing))
                            current._write_dva(address, body)
                        print(
                            "Transplanted native pair-one %s descriptor(s) before notify" %
                            transplant_native,
                            flush=True,
                        )
                    if dump_pre_notify:
                        dump_refused_pair(current, "pre-notify")
                    if dump_high_graph:
                        dump_native_high_graph(
                            current, native_pages, "pre-notify")
                    dumped.add(pair_index)

            backend.pre_notify_hook = pre_notify_dump

        address_a = front.create_bo_from_memfd(FILE_A, 0, size, 0)
        object_a = front.bos[0]
        context_a = object_a._drm_context
        address_b = front.create_bo_from_memfd(FILE_B, size, size, 0)
        object_b = front.bos[size]
        context_b = object_b._drm_context
        address_a2 = None
        object_a2 = None
        if fresh_a_control:
            address_a2 = front.create_bo_from_memfd(FILE_A, 2 * size, size, 0)
            object_a2 = front.bos[2 * size]
            if object_a2._drm_context != context_a:
                raise RuntimeError("file A's second BO changed UAT context")
            if object_a2._pa in (object_a._pa, object_b._pa):
                raise RuntimeError("fresh A-control BO reused physical backing")

        if context_a == context_b:
            raise RuntimeError("two DRM files were assigned the same UAT context")
        logical_vm_switch = os.getenv("G17P_LOGICAL_VM_SWITCH") == "1"
        logical_vm_stride = int(
            os.getenv("G17P_LOGICAL_VM_STRIDE", "0x100000000"), 0)
        same_dva = not logical_vm_switch or logical_vm_stride == 0
        if same_dva and address_a != address_b:
            raise RuntimeError(
                "file-private allocators did not reuse the same DVA: %#x != %#x" %
                (address_a, address_b))
        if not same_dva and address_a == address_b:
            raise RuntimeError("logical VM slices unexpectedly reused one DVA")
        if object_a._pa == object_b._pa:
            raise RuntimeError("two color BOs share physical backing")

        root_a = backend.execution_contexts[context_a]["space"].uat.ttbr0_base
        root_b = backend.execution_contexts[context_b]["space"].uat.ttbr0_base
        if root_a == root_b:
            raise RuntimeError("two DRM files share one low translation root")
        if translated_pa(backend, context_a, address_a) != object_a._pa:
            raise RuntimeError("context A resolves the shared DVA to the wrong BO")
        if translated_pa(backend, context_b, address_b) != object_b._pa:
            raise RuntimeError("context B resolves the shared DVA to the wrong BO")

        print(
            "Independent VMs: A=context %d root=%#x DVA=%#x PA=%#x; "
            "B=context %d root=%#x DVA=%#x PA=%#x" % (
                context_a, root_a, address_a, object_a._pa,
                context_b, root_b, address_b, object_b._pa),
            flush=True,
        )
        if backend.mirror_registered_vm:
            mirrored_b_pa = translated_pa(backend, context_a, address_b)
            if mirrored_b_pa != object_b._pa:
                raise RuntimeError(
                    "registered context maps B at %#x to %#x, expected %#x" %
                    (address_b, mirrored_b_pa, object_b._pa))
            print(
                "Registered context %d mirrors B DVA %#x to PA %#x" %
                (context_a, address_b, mirrored_b_pa),
                flush=True,
            )

        if os.getenv("G17P_SHARED_RETAINED_PIPELINES") == "1":
            context_a_state = backend.execution_contexts[context_a]
            context_b_state = backend.execution_contexts[context_b]
            old_pipeline_base = context_b_state["ctx"].pipeline_base
            context_b_state["ctx"].pipeline_base = context_a_state["ctx"].pipeline_base
            print(
                "B retained-pipeline probe: pipeline base %#x -> %#x; "
                "file BO allocator and UAT root remain context-private" % (
                    old_pipeline_base,
                    context_b_state["ctx"].pipeline_base,
                ),
                flush=True,
            )

        body_a = packed_cmdbuf(
            WIDTH, HEIGHT,
            color_attachment={"type": 0, "size": size, "pointer": address_a},
        )
        body_b = packed_cmdbuf(
            WIDTH, HEIGHT,
            color_attachment={"type": 0, "size": size, "pointer": address_b},
        )
        storage_a = ctypes.create_string_buffer(body_a)
        storage_b = ctypes.create_string_buffer(body_b)
        storage_a2 = None
        if fresh_a_control:
            body_a2 = packed_cmdbuf(
                WIDTH, HEIGHT,
                color_attachment={
                    "type": 0, "size": size, "pointer": address_a2,
                },
            )
            storage_a2 = ctypes.create_string_buffer(body_a2)
        zero = [bytes(32)]
        before_a = heads(backend, object_a)
        before_b = heads(backend, object_b)
        before_a2 = heads(backend, object_a2) if fresh_a_control else None
        if (before_a != zero or before_b != zero
                or (fresh_a_control and before_a2 != zero)):
            raise RuntimeError("fresh file-private color BOs are not zero")

        if os.getenv("G17P_B_FIRST_PROBE") == "1":
            submit(front, FILE_B, storage_b, "B-first")
            after_a = heads(backend, object_a)
            after_b = heads(backend, object_b)
            print_object_delta(
                "B-first/B", {}, object_state(backend, context_b))
            if after_b == before_b or not any(after_b[0]):
                raise RuntimeError(
                    "B-first did not write context B's color BO")
            if after_a != before_a:
                raise RuntimeError(
                    "B-first wrote context A's same-DVA color BO")
            print(
                "PASS: context B rendered as the first work through registered context 1",
                flush=True,
            )
            return 0

        pipeline_first = os.getenv("G17P_PIPELINE_FIRST_PAIR") == "1"
        submit(front, FILE_A, storage_a, "A1")
        if os.getenv("G17P_PREFILL_SECOND_PAIR") == "1":
            second = backend.prefilled_second_submission
            if second is None or not backend.pair_retired(second):
                raise RuntimeError(
                    "pre-staged pair 1 did not complete and drain its scheduler job")
            if second["submission_ordinal"] != 1:
                raise RuntimeError("pre-staged work is not global submission 2")
            print(
                "OBSERVED: pre-staged pair 1 retired global submission 2 while A1 was live; "
                "no pair-one target witness was measured",
                flush=True,
            )
            return 2
        if pipeline_first:
            print("A1 published without waiting; immediately building A-control",
                  flush=True)
            after_a1 = None
            state_a1 = None
        else:
            after_a1 = heads(backend, object_a)
            after_b0 = heads(backend, object_b)
            state_a1 = None
            if os.getenv("G17P_MULTICONTEXT_DIAGNOSTIC_STATE") == "1":
                state_a1 = object_state(backend, context_a)
                print_object_delta("A1/A", {}, state_a1)
            if after_a1 == before_a or not any(after_a1[0]):
                raise RuntimeError("A1 did not write context A's color BO")
            if after_b0 != before_b:
                raise RuntimeError("A1 wrote context B's same-DVA color BO")

        if os.getenv("G17P_CRASH_AFTER_A1") == "1":
            runtime = getattr(front, "g17p_boot_runtime", None) or {}
            capture = runtime.get("capture_crash_postmortem")
            if capture is None:
                raise RuntimeError(
                    "no in-process ASC runtime is available for A1 postmortem")
            result = capture("A1_success")
            if (len(result) != 2 or any(
                    value != "ASC firmware reported a crash"
                    for value in result.values())):
                raise RuntimeError("A1 postmortem did not save both reports: %r"
                                   % result)
            print("PASS: A1 executed and both private histories were captured",
                  flush=True)
            return 0

        cleared_a_before_b = os.getenv("G17P_CLEAR_A_BEFORE_B") == "1"
        if cleared_a_before_b:
            backend.u.iface.writemem(object_a._pa, bytes(object_a._size))
            backend.u.proxy.dc_civac(object_a._pa, object_a._size)
            if heads(backend, object_a) != zero:
                raise RuntimeError("context A color BO did not clear before B1")
            print(
                "Cleared A after A1 to distinguish a cached A target from B execution",
                flush=True,
            )

        if os.getenv("G17P_SECOND_A_CONTROL") == "1":
            if not cleared_a_before_b and not fresh_a_control:
                raise RuntimeError(
                    "G17P_SECOND_A_CONTROL requires a cleared or fresh target")
            control_storage = storage_a2 if fresh_a_control else storage_a
            control_object = object_a2 if fresh_a_control else object_a
            submit(front, FILE_A, control_storage, "A-control")
            after_a_control = heads(backend, control_object)
            if pipeline_first:
                after_a1 = heads(backend, object_a)
                if after_a1 == before_a or not any(after_a1[0]):
                    raise RuntimeError(
                        "pipelined A1 did not write its original target")
            if after_a_control == zero or not any(after_a_control[0]):
                raise RuntimeError(
                    "second A submission retired without rendering to its target")
            if heads(backend, object_b) != before_b:
                raise RuntimeError("second A submission modified context B")
            print(
                "PASS: second A submission wrote %s target" % (
                    "fresh" if fresh_a_control else "cleared"),
                flush=True,
            )
            return 0

        diagnostic_state = os.getenv("G17P_MULTICONTEXT_DIAGNOSTIC_STATE") == "1"
        state_a_before_b = object_state(backend, context_a) if diagnostic_state else None
        state_b0 = object_state(backend, context_b) if diagnostic_state else None
        pair1_stalled = False
        try:
            b_submission = submit(front, FILE_B, storage_b, "B1")
        except TimeoutError:
            if os.getenv("G17P_CONTINUE_AFTER_PAIR1_STALL") != "1":
                raise
            pair1_stalled = True
            stalled = backend.last_submission
            queues = {
                kind: stalled[kind]["queue"].indices()
                for kind in ("tiling", "fragment")
            }
            print(
                "B1 remained scheduler-linked at %s; continuing to native "
                "global ordinal 2 on pair zero" % queues,
                flush=True,
            )
        after_a_b1 = heads(backend, object_a)
        after_b1 = heads(backend, object_b)
        if diagnostic_state:
            state_a_b1 = object_state(backend, context_a)
            state_b1 = object_state(backend, context_b)
            print_object_delta("B1/A", state_a_before_b, state_a_b1)
            print_object_delta("B1/B", state_b0, state_b1)
        if pair1_stalled:
            expected_a_b1 = zero if cleared_a_before_b else after_a1
            if after_a_b1 != expected_a_b1:
                raise RuntimeError(
                    "stalled B1 modified context A's color BO")
            if after_b1 == before_b or not any(after_b1[0]):
                raise RuntimeError(
                    "scheduler-linked B1 did not write context B's color BO")
            print(
                "B1 wrote context B despite its retained scheduler node",
                flush=True,
            )

            if os.getenv("G17P_FORCE_UNLINK_PAIR1_AFTER_OUTPUT") == "1":
                job_lists = {
                    stalled[kind]["queue"].job_list_addr
                    for kind in ("tiling", "fragment")
                }
                for address in job_lists:
                    before = g17p.parse_job_list(
                        backend._read_dva(address, g17p.JOB_LIST_SIZE),
                        own_address=address,
                    )
                    backend._write_dva(address, g17p.build_job_list(address))
                    after = g17p.parse_job_list(
                        backend._read_dva(address, g17p.JOB_LIST_SIZE),
                        own_address=address,
                    )
                    if not after["empty"]:
                        raise RuntimeError(
                            "forced pair-one job-list unlink did not stick")
                    print(
                        "Forced pair-one job list %#x from %s to empty" %
                        (address, before),
                        flush=True,
                    )

            try:
                submit(front, FILE_A, storage_a, "A2-after-stalled-B1")
            except TimeoutError:
                print(
                    "A2 retained scheduler state; checking its physical output",
                    flush=True,
                )
            after_a2 = heads(backend, object_a)
            if after_a2 == before_a or not any(after_a2[0]):
                raise RuntimeError(
                    "pair-zero A2 did not write A after the pair-one stall")
            if heads(backend, object_b) != before_b:
                raise RuntimeError(
                    "pair-zero A2 modified context B after the pair-one stall")
            print(
                "PASS: pair zero executed global ordinal 2 after a linked pair-one placeholder",
                flush=True,
            )
            return 0
        if after_b1 == before_b or not any(after_b1[0]):
            if cleared_a_before_b and after_a_b1 != zero:
                raise RuntimeError(
                    "B1 rendered through context A's cached color target")
            raise RuntimeError("B1 did not write context B's color BO")
        expected_a_b1 = zero if cleared_a_before_b else after_a1
        if after_a_b1 != expected_a_b1:
            raise RuntimeError("B1 modified context A's same-DVA color BO")

        b_physical_after_b1 = physical_contents(backend, object_b)
        if not any(b_physical_after_b1):
            raise RuntimeError("B1 left context B's full physical target zero")
        if b_submission["queue_pair"] != 1:
            raise RuntimeError(
                "B1 used queue pair %r instead of B-owned pair 1" %
                b_submission["queue_pair"])
        pair_b_tombstone = backend.destroy_muxed_queue_pair(1)
        try:
            backend.muxed_queue_pair(1)
        except G17PUnsupported as exc:
            stale_pair_error = str(exc)
        else:
            raise RuntimeError("destroyed B queue pair remained usable")
        print(
            "B queue pair destroyed at generation %d; stale pair rejected (%s)" % (
                pair_b_tombstone["generation"], stale_pair_error),
            flush=True,
        )

        front.bo_free(size)
        if size in front.bos or object_b._map is not None:
            raise RuntimeError("context B color BO teardown did not complete")
        context_b_tombstone = front.destroy_g17p_context_for_fd(FILE_B)
        stale_translations = backend.execution_contexts[context_a]["space"].uat.iotranslate(
            context_b, address_b, size)
        if any(pa is not None for pa, _span in stale_translations):
            raise RuntimeError(
                "destroyed context B still translates %#x: %r" %
                (address_b, stale_translations))
        try:
            backend.activate_execution_context(context_b)
        except G17PUnsupported as exc:
            stale_context_error = str(exc)
        else:
            raise RuntimeError("destroyed context B remained activatable")
        print(
            "B color BO and context render graph destroyed; UAT roots %r unbound; "
            "stale context rejected (%s); switching back to A" %
            (context_b_tombstone["roots"], stale_context_error),
            flush=True,
        )

        backend.u.iface.writemem(object_a._pa, bytes(object_a._size))
        backend.u.proxy.dc_civac(object_a._pa, object_a._size)
        if heads(backend, object_a) != zero:
            raise RuntimeError("context A target did not clear before A2")
        submit(front, FILE_A, storage_a, "A2")
        after_a2 = heads(backend, object_a)
        if after_a2 == zero or not any(after_a2[0]):
            raise RuntimeError("A2 did not write context A after B teardown")
        backend.u.proxy.dc_civac(object_b._pa, object_b._size)
        if bytes(backend.u.iface.readmem(object_b._pa, object_b._size)) != b_physical_after_b1:
            raise RuntimeError("A2 changed context B's released physical target")

        front.bo_free(0)
        if 0 in front.bos or object_a._map is not None:
            raise RuntimeError("context A color BO teardown did not complete")

        print(
            "PASS: independent same-DVA VMs executed A/B/A with B teardown",
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
