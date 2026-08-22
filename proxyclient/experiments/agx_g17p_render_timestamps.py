#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove reusable caller timestamps across exact native renders."""

import os
import pathlib
import struct
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"

from m1n1.agx.g17p_backend import G17PWorkBuilder  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim  # noqa: E402


PAGE = 0x4000
GLOBAL_STATUS = 0xFFFFFC2000024C60
CURRENT_JOBS = 0xFFFFFC20C07D0000
CALLER_TIMESTAMP_ALIAS = 0xFFFFFC2181400000
CANARY = 0xA5A5A5A5A5A5A5A5
EXPECTED_PIXEL = struct.pack("<I", 0x18060180)
SUBMISSION_COUNT = 3
TIMESTAMP_SLOT_STRIDE = 0x40
FIRST_STAGE_TIMESTAMP_OFFSETS = {
    "ta_start": 0x08,
    "ta_end": 0x10,
    "fragment_start": 0x18,
    "fragment_end": 0x20,
}


def stage_timestamp_offsets(index):
    base = index * TIMESTAMP_SLOT_STRIDE
    return {
        name: base + offset
        for name, offset in FIRST_STAGE_TIMESTAMP_OFFSETS.items()
    }


def read_candidate(backend, address, size):
    try:
        return backend._read_dva(address, size)
    except Exception as exc:  # noqa: BLE001
        print("RENDER TIMESTAMP candidate %#x unavailable: %s" %
              (address, exc), flush=True)
        return None


def changed_qwords(before, after):
    if before is None or after is None:
        return []
    changes = []
    for offset in range(0, min(len(before), len(after)), 8):
        old = struct.unpack_from("<Q", before, offset)[0]
        new = struct.unpack_from("<Q", after, offset)[0]
        if old != new:
            changes.append((offset, old, new))
    return changes


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_render_timestamps.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        from agx_g17p_compute import (  # noqa: E402
            create_render_cadence_workload,
            drain_boot_group,
            physical_read,
            run_render_cadence_submission,
        )

        drain_boot_group(front, backend)
        pair = backend.submission_queue_pair()
        if pair is None:
            pair = backend.queue_pair
        item = backend.queue_pair_submissions.get(pair, 0)

        candidates = {
            "global": (GLOBAL_STATUS, 0x20),
            "current_jobs": (CURRENT_JOBS, 0x80),
        }
        for kind in ("tiling", "fragment"):
            base = G17PWorkBuilder.PAIR_STATUS_BASES[kind][pair]
            candidates["%s_status" % kind] = (base + item * 0x40, 0x40)

        before = {
            name: read_candidate(backend, address, size)
            for name, (address, size) in candidates.items()
        }
        counter_before = backend.u.mrs("CNTPCT_EL0")
        counter_frequency = backend.u.mrs("CNTFRQ_EL0")

        timestamp_pa = backend.u.memalign(PAGE, PAGE)
        timestamp_page = struct.pack("<Q", CANARY) * (PAGE // 8)
        backend.u.iface.writemem(timestamp_pa, timestamp_page)
        backend.u.proxy.dc_civac(timestamp_pa, PAGE)
        backend.map_firmware_existing_at(
            CALLER_TIMESTAMP_ALIAS, timestamp_pa, PAGE)
        original_supplied = front.g17p_supplied
        active_offsets = stage_timestamp_offsets(0)

        def timestamp_supplied():
            supplied = dict(original_supplied())
            supplied.update(
                ta_user_timestamp_start=(
                    CALLER_TIMESTAMP_ALIAS
                    + active_offsets["ta_start"]),
                ta_user_timestamp_end=(
                    CALLER_TIMESTAMP_ALIAS
                    + active_offsets["ta_end"]),
                fragment_user_timestamp_start=(
                    CALLER_TIMESTAMP_ALIAS
                    + active_offsets["fragment_start"]),
                fragment_user_timestamp_end=(
                    CALLER_TIMESTAMP_ALIAS
                    + active_offsets["fragment_end"]),
            )
            return supplied

        front.g17p_supplied = timestamp_supplied

        workload = create_render_cadence_workload(front)
        submissions = []
        all_ordered = []
        expected_target = (
            EXPECTED_PIXEL * (0x1000 // len(EXPECTED_PIXEL))
            + bytes(PAGE - 0x1000)
        )
        for index in range(SUBMISSION_COUNT):
            active_offsets = stage_timestamp_offsets(index)
            backend.u.proxy.dc_ivac(timestamp_pa, PAGE)
            iteration_before_page = bytes(
                backend.u.iface.readmem(timestamp_pa, PAGE))
            iteration_counter_before = backend.u.mrs("CNTPCT_EL0")
            submission = run_render_cadence_submission(
                front, backend, workload,
                "timestamp witness render %d" % (index + 1))
            iteration_counter_after = backend.u.mrs("CNTPCT_EL0")
            backend.u.proxy.dc_ivac(timestamp_pa, PAGE)
            iteration_after_page = bytes(
                backend.u.iface.readmem(timestamp_pa, PAGE))

            target = physical_read(
                backend, submission["semantic_witness_pa"], PAGE)
            exact_target_match = target == expected_target
            redirected_values = {
                name: struct.unpack_from(
                    "<Q", iteration_after_page, offset)[0]
                for name, offset in active_offsets.items()
            }
            changed_offsets = [
                offset for offset in range(0, PAGE, 8)
                if iteration_before_page[offset:offset + 8]
                != iteration_after_page[offset:offset + 8]
            ]
            ordered = [redirected_values[name] for name in (
                "ta_start", "ta_end", "fragment_start", "fragment_end")]
            expected_changed = sorted(active_offsets.values())
            if not submission.get("output_changed") or not exact_target_match:
                raise RuntimeError(
                    "render %d did not produce its exact output" % (index + 1))
            if changed_offsets != expected_changed:
                raise RuntimeError(
                    "render %d changed unexpected timestamp qwords: %r" %
                    (index + 1, changed_offsets))
            if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
                raise RuntimeError(
                    "render %d timestamps are not strictly ordered: %r" %
                    (index + 1, ordered))
            if not all(
                    iteration_counter_before <= value <= iteration_counter_after
                    for value in ordered):
                raise RuntimeError(
                    "render %d timestamps %r escape the 1 GHz interval %d..%d" %
                    (index + 1, ordered, iteration_counter_before,
                     iteration_counter_after))
            print(
                "RENDER TIMESTAMP render=%d target_pa=%#x exact=1 "
                "offsets=%r values=%r interval=%d..%d" % (
                    index + 1, submission["semantic_witness_pa"],
                    active_offsets, redirected_values,
                    iteration_counter_before, iteration_counter_after),
                flush=True,
            )
            submissions.append(submission)
            all_ordered.extend(ordered)

        counter_after = backend.u.mrs("CNTPCT_EL0")
        after = {
            name: read_candidate(backend, address, size)
            for name, (address, size) in candidates.items()
        }

        backend.u.proxy.dc_ivac(timestamp_pa, PAGE)
        redirected = bytes(backend.u.iface.readmem(timestamp_pa, PAGE))
        print(
            "RENDER TIMESTAMP final aperture changed qwords=%r" %
            changed_qwords(timestamp_page, redirected),
            flush=True,
        )

        for name, (address, _size) in candidates.items():
            changes = changed_qwords(before[name], after[name])
            print("RENDER TIMESTAMP %-16s %#x qword changes=%r" %
                  (name, address, changes), flush=True)

        for index, submission in enumerate(submissions):
            ta = submission["items"]["tiling"][0]
            fragment = submission["items"]["fragment"][0]
            ta_body = backend._read_dva(
                ta, G17PWorkBuilder.BODY_STRIDE["tiling"])
            fragment_body = backend._read_dva(
                fragment, G17PWorkBuilder.BODY_STRIDE["fragment"])
            pointers = {
                "ta_internal": struct.unpack_from("<Q", ta_body, 0x08FE)[0],
                "ta_user_start": struct.unpack_from("<Q", ta_body, 0x090E)[0],
                "ta_user_end": struct.unpack_from("<Q", ta_body, 0x0916)[0],
                "fragment_internal": struct.unpack_from(
                    "<Q", fragment_body, 0x2198)[0],
                "fragment_user_start": struct.unpack_from(
                    "<Q", fragment_body, 0x21A8)[0],
                "fragment_user_end": struct.unpack_from(
                    "<Q", fragment_body, 0x21B0)[0],
            }
            print(
                "RENDER TIMESTAMP render=%d descriptor pointers=%r" %
                (index + 1, pointers), flush=True)
        print(
            "RENDER TIMESTAMP architectural interval=%d..%d frequency=%d" %
            (counter_before, counter_after, counter_frequency),
            flush=True,
        )

        if all_ordered != sorted(all_ordered) or len(set(all_ordered)) != len(all_ordered):
            raise RuntimeError(
                "timestamps are not monotonic across renders: %r" % all_ordered)
        print(
            "RENDER TIMESTAMP REUSE PASS renders=%d timestamps=%d domain=%d Hz" %
            (SUBMISSION_COUNT, len(all_ordered), counter_frequency),
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
