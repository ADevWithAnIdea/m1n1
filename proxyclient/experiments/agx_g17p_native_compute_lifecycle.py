#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct the final-26.6 primary compute-control prefix from fields."""

import struct

from m1n1.agx import g17p_compute as compute
from m1n1.agx import g17p_initdata
from m1n1.hw.uat import MemoryAttr

from agx_g17p_compute import drain_boot_group


PAGE = 0x4000
PACKED_OBJECT = 0xFFFFFC20C0868000
TABLE_A = 0x70013A0000
CLASS2_TABLE = 0x7000208000
TABLE_STRIDE = 0x40
TABLE_FLAG = 1 << 60
PRIMARY_RECORD_B = 0xFFFFFC20015E8000
SEQUENCE_22_STATE = 0xFFFFFC2001630000
SEQUENCE_22_PAGE_LIST = 0x70018D0000
SEQUENCE_22_TABLE = 0x7001AD8000
SEQUENCE_22_BUFFERS = (
    0x7000220000, 0x7000328000, 0x7000430000, 0x7000538000,
    0x7000640000, 0x7000748000, 0x7000850000, 0x7000958000,
    0x7000A60000, 0x7000B68000, 0x7000C70000, 0x7000D78000,
    0x7000E80000, 0x7000F88000, 0x7001090000, 0x7001198000,
    0x70012A0000, 0x70013A8000, 0x7000000000, 0x7000108000,
    0x70014B0000,
)


def _root_ranges(space, address, size):
    ranges = space.uat.iotranslate_root(space.uat.ttbr0_base, address, size)
    if not ranges or any(pa is None for pa, _length in ranges):
        raise RuntimeError("native lifecycle DVA %#x is unmapped" % address)
    return ranges


def _write_low(space, address, body):
    written = 0
    for pa, length in _root_ranges(space, address, len(body)):
        take = min(length, len(body) - written)
        space.iface.writemem(pa, body[written:written + take])
        space.p.dc_civac(pa, take)
        written += take
        if written == len(body):
            break
    if written != len(body):
        raise RuntimeError("short lifecycle write at %#x" % address)


def _sequence_22_operand_table():
    body = bytearray(PAGE)
    for index, address in enumerate(SEQUENCE_22_BUFFERS):
        struct.pack_into("<Q", body, index * TABLE_STRIDE,
                         int(address) | TABLE_FLAG)
    return bytes(body)


def _ensure_low_pages(backend, address, size):
    start = address & ~(PAGE - 1)
    end = (address + size + PAGE - 1) & ~(PAGE - 1)
    missing = []
    run_start = None
    for page in range(start, end, PAGE):
        ranges = backend.space.uat.iotranslate_root(
            backend.space.uat.ttbr0_base, page, PAGE)
        mapped = bool(ranges and ranges[0][0] is not None)
        if not mapped and run_start is None:
            run_start = page
        elif mapped and run_start is not None:
            missing.append((run_start, page - run_start))
            run_start = None
    if run_start is not None:
        missing.append((run_start, end - run_start))

    for run_address, run_size in missing:
        pa = backend.u.memalign(PAGE, run_size)
        backend.u.proxy.memset32(pa, 0, run_size)
        backend.u.proxy.dc_civac(pa, run_size)
        backend.space.uat.iomap_at(
            backend.space.context,
            run_address,
            pa,
            run_size,
            AttrIndex=MemoryAttr.Shared,
            AP=2,
            nG=1,
            UXN=1,
            OS=1,
        )
    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()


def install_late_control_graph(
        backend, packed_object=PACKED_OBJECT,
        state_address=SEQUENCE_22_STATE):
    """Construct the native sequence-54 class-1 inputs after startup work."""
    packed_object = int(packed_object)
    state_address = int(state_address)
    backend._ensure_firmware_range(packed_object, PAGE)
    backend._ensure_firmware_range(state_address, PAGE)
    sequence22_support = compute.build_compute_class1_support(
        SEQUENCE_22_TABLE,
        SEQUENCE_22_PAGE_LIST,
        state_address,
        active=0,
        resource_class=0x12,
        cursor=0x90,
        final_kind=2,
    )
    sequence22_state = bytearray(PAGE)
    struct.pack_into("<I", sequence22_state, 0, 1)
    sequence22_page_list = b"".join(
        struct.pack("<Q", base + offset)
        for base in SEQUENCE_22_BUFFERS
        for offset in range(0, 0x100000, 0x1000)
    )
    if len(sequence22_page_list) != 0xA800:
        raise RuntimeError("sequence-22 page inventory has wrong size")
    for address in SEQUENCE_22_BUFFERS:
        _ensure_low_pages(backend, address, 0x100000)
    _ensure_low_pages(
        backend, SEQUENCE_22_PAGE_LIST, len(sequence22_page_list))
    _ensure_low_pages(backend, SEQUENCE_22_TABLE, PAGE)
    _write_low(backend.space, SEQUENCE_22_PAGE_LIST, sequence22_page_list)
    _write_low(backend.space, SEQUENCE_22_TABLE,
               _sequence_22_operand_table())
    backend._write_dva(
        packed_object,
        sequence22_support + bytes(PAGE - len(sequence22_support)),
    )
    backend._write_dva(state_address, sequence22_state)

    for address in (packed_object, state_address):
        backend._clean_dva_range(address, PAGE)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "LATE CONTROL built: measured sequence-54 21-operand class1, "
        "operand table, page inventory, and state",
        flush=True,
    )


def _install_sequence_56_class2(
        backend, packed_object=PACKED_OBJECT,
        state_address=SEQUENCE_22_STATE):
    """Rewrite the shared native object for the sequence-56 class-2 control."""
    packed_object = int(packed_object)
    state_address = int(state_address)
    support = compute.build_compute_class2_support(
        CLASS2_TABLE,
        0,
        state_address,
        active=0,
        resource_class=0x17,
        cursor=0xB8,
        final_kind=3,
    )
    _ensure_low_pages(backend, CLASS2_TABLE, PAGE)
    _write_low(backend.space, CLASS2_TABLE, bytes(PAGE))
    backend._write_dva(
        packed_object,
        support + bytes(PAGE - len(support)),
    )
    backend._clean_dva_range(packed_object, PAGE)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "LATE CONTROL rewrote shared object for measured sequence-56 class2",
        flush=True,
    )


def _registration(first_object, operand_table, sequence,
                  control_class=1,
                  slot_offset=0x440, count=0x20):
    body = bytearray(0x40)
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


def _tick(sequence):
    body = bytearray(0x40)
    struct.pack_into("<II", body, 0, 0x2E, int(sequence))
    return bytes(body)


def _adopt_completed_boot_group(backend):
    """Adopt a startup group that the compact control path already retired."""
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
    print(
        "NATIVE STARTUP ADOPTED: queues retired at 3/3/3; this is not "
        "an output-execution witness",
        flush=True,
    )


def advance_native_compute_lifecycle(front, backend, client,
                                     prepare_late_controls=None,
                                     initial_group_already_completed=False,
                                     skip_boot_group=False,
                                     boot_group_already_drained=False,
                                     expected_opening_count=2,
                                     opening_prefix_adjustment=0,
                                     control_packed_object=PACKED_OBJECT,
                                     control_state_address=SEQUENCE_22_STATE):
    """Publish the exact non-work history retained before native add3."""
    if boot_group_already_drained:
        print(
            "NATIVE LIFECYCLE continuing after output-witnessed bootstrap "
            "render",
            flush=True,
        )
    elif skip_boot_group:
        print(
            "NATIVE LIFECYCLE headless: no bootstrap render was published",
            flush=True,
        )
    elif initial_group_already_completed:
        _adopt_completed_boot_group(backend)
    else:
        drain_boot_group(front, backend)
    if prepare_late_controls is not None:
        prepare_late_controls()
    runtime = front.g17p_runtime
    if runtime is None:
        raise RuntimeError("source boot exposed no G17P runtime controls")
    counters = runtime["read_control_counters"]()
    expected_opening_count = int(expected_opening_count)
    opening_prefix_adjustment = int(opening_prefix_adjustment)
    control_packed_object = int(control_packed_object)
    control_state_address = int(control_state_address)
    if opening_prefix_adjustment < 0 or opening_prefix_adjustment > 53:
        raise ValueError("invalid compute opening-prefix adjustment")
    expected_opening = [expected_opening_count] * 3
    if counters["primary"] != expected_opening:
        raise RuntimeError(
            "native opening did not retire at %r: %r" % (
                expected_opening, counters))

    # TABLE_A belongs to the generated compute context and is blank at the
    # native publication boundary.
    _write_low(client["space"], TABLE_A, bytes(PAGE))
    backend.u.inst("dsb sy")

    runtime["announce_runtime_tick"](
        0, "native compute prefix tick 0", update_sequence=True)
    runtime["advance_runtime_ticks"](53 - opening_prefix_adjustment)
    sequence_54 = runtime["announce_control_bodies"]((
        _registration(
            control_packed_object, SEQUENCE_22_TABLE, 54,
            slot_offset=0x480, count=0x18),
    ), "native measured class-1 sequence-54 registration")
    if sequence_54["crashed"] is not None or not sequence_54["consumed"]:
        raise RuntimeError(
            "firmware did not consume native sequence-54 class1: "
            "%r" % sequence_54)
    between = runtime["announce_control_bodies"]((
        _tick(54),
        _tick(55),
    ), "native compute ticks 54 and 55")
    if between["crashed"] is not None or not between["consumed"]:
        raise RuntimeError(
            "firmware did not consume native ticks 54 and 55: %r" % between)
    _install_sequence_56_class2(
        backend,
        packed_object=control_packed_object,
        state_address=control_state_address,
    )
    sequence_56 = runtime["announce_control_bodies"]((
        _registration(
            control_packed_object, CLASS2_TABLE, 56,
            control_class=2, slot_offset=0x5C0, count=0x28),
    ), "native measured class-2 sequence-56 registration")
    if sequence_56["crashed"] is not None or not sequence_56["consumed"]:
        raise RuntimeError(
            "firmware did not consume native sequence-56 class2: %r" %
            sequence_56)
    pair = {
        "sequence_54": sequence_54,
        "between": between,
        "sequence_56": sequence_56,
    }
    first_suffix = runtime["announce_runtime_tick"](
        56, "native compute suffix tick 56", update_sequence=True)
    suffix = runtime["advance_runtime_ticks"](62)

    final = runtime["read_control_counters"]()
    expected_final_count = (
        expected_opening_count + 65 - opening_prefix_adjustment)
    expected_final = [expected_final_count] * 3
    if final["primary"] != expected_final:
        raise RuntimeError(
            "native compute lifecycle ended at %r, expected primary %r" % (
                final, expected_final))
    dispatch = g17p_initdata.build_compute_dispatch_record()
    dispatch_address = (
        PRIMARY_RECORD_B + g17p_initdata.COMPUTE_DISPATCH_RECORD_STRIDE
    )
    backend._write_dva(dispatch_address, dispatch)
    backend._clean_dva_range(dispatch_address, len(dispatch))
    backend.u.inst("dsb sy")
    print(
        "NATIVE LIFECYCLE built compute dispatch record at %#x" %
        dispatch_address,
        flush=True,
    )
    print(
        "NATIVE LIFECYCLE PASS: exact semantic compute history at primary "
        "%d (opening-prefix adjustment %d); "
        "late-controls=%r first-suffix=%r suffix=%r controls=%r" %
        (expected_final_count, opening_prefix_adjustment,
         pair, first_suffix, suffix, final),
        flush=True,
    )
    return {"pair": pair, "first_suffix": first_suffix, "suffix": suffix,
            "controls": final}
