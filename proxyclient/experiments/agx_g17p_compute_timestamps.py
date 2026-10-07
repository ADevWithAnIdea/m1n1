#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove internal and caller-visible compute timestamp destinations."""

import struct

from agx_g17p_compute_source_indirect import run


PAGE = 0x4000
WORKLOADS = 4
INTERNAL_OBJECT_DVA = 0x10009000000
INTERNAL_FIRMWARE_DVA = 0xFFFFFC2002200000
USER_OBJECT_DVA = 0x10009004000
USER_FIRMWARE_DVA = 0xFFFFFC2181400000
TIMESTAMP_RECORD_SIZE = 0x20
CANARY_BYTE = 0xA5
CANARY_QWORD = int.from_bytes(bytes((CANARY_BYTE,)) * 8, "little")
COMMAND_TIMESTAMP_FREQUENCY = 24_000_000


def _command_ticks(counter, architectural_frequency):
    return (
        int(counter) * COMMAND_TIMESTAMP_FREQUENCY
        // int(architectural_frequency)
    )


def install_timestamp_object(backend, client):
    space = client["space"]
    body = bytes((CANARY_BYTE,)) * PAGE
    objects = {}
    for name, va, alias in (
        ("internal", INTERNAL_OBJECT_DVA, INTERNAL_FIRMWARE_DVA),
        ("user", USER_OBJECT_DVA, USER_FIRMWARE_DVA),
    ):
        allocated_va, pa = space.alloc_at(
            va, PAGE, "compute_%s_timestamp_object" % name)
        backend.u.iface.writemem(pa, body)
        backend.u.proxy.dc_civac(pa, PAGE)
        backend.map_firmware_existing_at(alias, pa, PAGE)
        objects[name] = {
            "va": allocated_va,
            "pa": pa,
            "size": PAGE,
            "firmware_alias": alias,
        }
    status_addresses = {
        ordinal: (
            INTERNAL_FIRMWARE_DVA + ordinal * TIMESTAMP_RECORD_SIZE,
            INTERNAL_FIRMWARE_DVA + ordinal * TIMESTAMP_RECORD_SIZE + 8,
        )
        for ordinal in range(WORKLOADS)
    }
    user_timestamp_addresses = {
        ordinal: (
            USER_FIRMWARE_DVA + ordinal * TIMESTAMP_RECORD_SIZE,
            USER_FIRMWARE_DVA + ordinal * TIMESTAMP_RECORD_SIZE + 8,
        )
        for ordinal in range(WORKLOADS)
    }
    client.update({
        "status_addresses": status_addresses,
        "user_timestamp_addresses": user_timestamp_addresses,
        "timestamp_objects": objects,
        "timestamp_counter_before": backend.u.mrs("CNTPCT_EL0"),
        "architectural_counter_frequency": backend.u.mrs("CNTFRQ_EL0"),
    })
    print(
        "COMPUTE TIMESTAMP bound internal DVA/PA/alias %#x/%#x/%#x and "
        "user DVA/PA/aperture %#x/%#x/%#x" % (
            objects["internal"]["va"], objects["internal"]["pa"],
            objects["internal"]["firmware_alias"],
            objects["user"]["va"], objects["user"]["pa"],
            objects["user"]["firmware_alias"],
        ),
        flush=True,
    )


def verify_timestamp_object(backend, client, repeated):
    if len(repeated) != WORKLOADS - 1:
        raise RuntimeError(
            "timestamp experiment completed %d post-start workloads, expected %d"
            % (len(repeated), WORKLOADS - 1))
    if not all(result["fence"]["signaled"] for result in repeated):
        raise RuntimeError("timestamp experiment has an unsignaled work fence")

    objects = client["timestamp_objects"]
    pages = {}
    for name, obj in objects.items():
        backend.u.proxy.dc_ivac(obj["pa"], PAGE)
        pages[name] = bytes(backend.u.iface.readmem(obj["pa"], PAGE))
    counter_after = backend.u.mrs("CNTPCT_EL0")
    counter_before = client["timestamp_counter_before"]
    architectural_frequency = client["architectural_counter_frequency"]
    if architectural_frequency <= 0 or counter_after <= counter_before:
        raise RuntimeError("architectural counter interval is invalid")
    command_before = _command_ticks(counter_before, architectural_frequency)
    command_after = _command_ticks(counter_after, architectural_frequency)
    if command_after <= command_before:
        raise RuntimeError("scaled command-timestamp interval is invalid")

    internal_records = []
    previous_end = None
    for ordinal in range(WORKLOADS):
        offset = ordinal * TIMESTAMP_RECORD_SIZE
        start, end, guard_a, guard_b = struct.unpack_from(
            "<4Q", pages["internal"], offset)
        if start == CANARY_QWORD:
            raise RuntimeError(
                "workload %d left its first timestamp destination unwritten" %
                ordinal)
        if guard_a != CANARY_QWORD or guard_b != CANARY_QWORD:
            raise RuntimeError(
                "workload %d wrote outside its two 64-bit destinations" %
                ordinal)

        if ordinal == 0:
            if end != CANARY_QWORD:
                raise RuntimeError(
                    "pre-start workload unexpectedly wrote its second "
                    "timestamp destination")
            values = (("startup_status", start),)
            duration = None
        else:
            if end == CANARY_QWORD:
                raise RuntimeError(
                    "post-start workload %d left its second timestamp "
                    "destination unwritten" % ordinal)
            duration = end - start
            if not 0 < duration < COMMAND_TIMESTAMP_FREQUENCY:
                raise RuntimeError(
                    "workload %d timestamp pair is not forward ordered" %
                    ordinal)
            if previous_end is not None and start < previous_end:
                raise RuntimeError(
                    "workload %d starts before its predecessor ended" % ordinal)
            values = (("start", start), ("end", end))
            previous_end = end

        for label, value in values:
            if not command_before <= value <= command_after:
                raise RuntimeError(
                    "workload %d %s timestamp %#x is outside scaled "
                    "CNTPCT interval %#x..%#x" % (
                        ordinal, label, value,
                        command_before, command_after))
        if ordinal and duration is None:
            raise RuntimeError(
                "post-start workload %d has no duration" % ordinal)
        internal_records.append({
            "ordinal": ordinal,
            "start": start,
            "end": None if end == CANARY_QWORD else end,
            "duration_ticks": duration,
        })

    user_records = []
    previous_end = None
    for ordinal in range(WORKLOADS):
        offset = ordinal * TIMESTAMP_RECORD_SIZE
        start, end, guard_a, guard_b = struct.unpack_from(
            "<4Q", pages["user"], offset)
        if guard_a != CANARY_QWORD or guard_b != CANARY_QWORD:
            raise RuntimeError(
                "workload %d wrote outside its two user timestamp qwords" %
                ordinal)
        if ordinal:
            if start == CANARY_QWORD or end == CANARY_QWORD:
                raise RuntimeError(
                    "post-start workload %d did not write both user "
                    "timestamps" % ordinal)
            if not start < end:
                raise RuntimeError(
                    "workload %d user timestamps are not forward ordered" %
                    ordinal)
            if previous_end is not None and start < previous_end:
                raise RuntimeError(
                    "workload %d user timestamp starts before its predecessor "
                    "ended" % ordinal)
            previous_end = end
            for label, value in (("start", start), ("end", end)):
                if not counter_before <= value <= counter_after:
                    raise RuntimeError(
                        "workload %d user %s timestamp %#x is outside direct "
                        "CNTPCT interval %#x..%#x" % (
                            ordinal, label, value,
                            counter_before, counter_after))
        user_records.append({
            "ordinal": ordinal,
            "start": None if start == CANARY_QWORD else start,
            "end": None if end == CANARY_QWORD else end,
        })

    used = WORKLOADS * TIMESTAMP_RECORD_SIZE
    canary_tail = bytes((CANARY_BYTE,)) * (PAGE - used)
    for name, body in pages.items():
        if body[used:] != canary_tail:
            raise RuntimeError(
                "firmware wrote outside selected %s timestamp records" % name)
    print(
        "COMPUTE TIMESTAMP PASS: exact outputs plus three internal 24 MHz "
        "and three caller-visible 1 GHz post-start pairs "
        "(architectural counter %d Hz): internal=%r user=%r" % (
            architectural_frequency, internal_records, user_records),
        flush=True,
    )


if __name__ == "__main__":
    raise SystemExit(run(
        repeat_workloads=WORKLOADS,
        client_slot_count=WORKLOADS,
        client_dispatch_grids=((64, 1, 1),) * WORKLOADS,
        client_threadgroups=((32, 1, 1),) * WORKLOADS,
        client_setup=install_timestamp_object,
        result_verifier=verify_timestamp_object,
    ))
