#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit one native pre-kick G17P compute graph against its constructors.

The full snapshot and targeted CL_2 metadata must come from the same mailbox
stop.  The targeted record identifies the live queue; all bytes, mappings and
pointer targets are then read from the full snapshot through the address space
that owns them.  This intentionally does not replay any captured state.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import struct
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from m1n1.agx import g17p, g17p_compute as compute  # noqa: E402
import agx_g17p_compute as current  # noqa: E402


PAGE = 0x4000
FW_ROOT = (64, 1)
LOW_ALIAS_ROOT = (0, 0)
CLIENT_ROOT = (3, 0)
NATIVE_PRIMARY_ROOT = 0xFFFFFC20001A8000
DEFAULT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_t256_write_full_20260806_085603"
)
DEFAULT_TARGET = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260806_085451/CL_2"
)


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


class Snapshot:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.manifest = json.loads((self.path / "manifest.json").read_text())
        self.ram = (self.path / self.manifest["ram_file"]).read_bytes()
        self.roots = {}
        for root in self.manifest["root_mappings"]:
            key = (integer(root["root_ctx_id"]), integer(root["selector"]))
            self.roots[key] = {
                integer(mapping["va"]): mapping
                for mapping in root["mappings"]
                if mapping.get("blob_index") is not None
            }

    def mapping(self, root, address):
        page = integer(address) & ~(PAGE - 1)
        try:
            return self.roots[root][page]
        except KeyError as error:
            raise RuntimeError(
                "root %s does not map %#x" % (root, integer(address))) from error

    def read(self, root, address, size):
        address = integer(address)
        remaining = integer(size)
        body = bytearray()
        while remaining:
            page = address & ~(PAGE - 1)
            offset = address - page
            take = min(remaining, PAGE - offset)
            mapping = self.mapping(root, address)
            blob = integer(mapping["blob_index"])
            source = self.ram[blob * PAGE:(blob + 1) * PAGE]
            if len(source) != PAGE:
                raise RuntimeError("short RAM blob %d" % blob)
            body.extend(source[offset:offset + take])
            address += take
            remaining -= take
        return bytes(body)

    def describe(self, root, address, size):
        address = integer(address)
        size = integer(size)
        pages = []
        cursor = address & ~(PAGE - 1)
        end = (address + size + PAGE - 1) & ~(PAGE - 1)
        while cursor < end:
            mapping = self.mapping(root, cursor)
            pages.append({
                "dva": cursor,
                "pa": integer(mapping["pa"]),
                "pte": integer(mapping["pte"]),
                "blob_index": integer(mapping["blob_index"]),
            })
            cursor += PAGE
        body = self.read(root, address, size)
        return {
            "root_context": root[0],
            "root_selector": root[1],
            "address": address,
            "length": size,
            "page_count": len(pages),
            "pages": pages,
            "nonzero_bytes": sum(byte != 0 for byte in body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }


def u16(body, offset):
    return struct.unpack_from("<H", body, offset)[0]


def u32(body, offset):
    return struct.unpack_from("<I", body, offset)[0]


def u64(body, offset):
    return struct.unpack_from("<Q", body, offset)[0]


def decode_registers(descriptor, start=compute.COMPUTE_REGISTER_START,
                     capacity=compute.COMPUTE_REGISTER_CAPACITY):
    registers = []
    for index in range(capacity):
        offset = start + index * compute.COMPUTE_REGISTER_SIZE
        number, value = struct.unpack_from("<IQ", descriptor, offset)
        if number == 0 and value == 0:
            break
        registers.append((number, value))
    return registers


def differing_bytes(left, right, ignored=()):
    ignored = tuple(ignored)
    return [
        offset for offset, (a, b) in enumerate(zip(left, right))
        if a != b and not any(start <= offset < end for start, end in ignored)
    ]


def object_record(snapshot, name, root, address, length, ownership, lifecycle,
                  logical_length=None):
    record = snapshot.describe(root, address, length)
    record.update({
        "name": name,
        "ownership": ownership,
        "lifecycle": lifecycle,
        "logical_length": length if logical_length is None else logical_length,
    })
    return record


def add_pointer(snapshot, pointers, owner, offset, root, target, length, role,
                tag_mask=0):
    raw = integer(target)
    address = raw & ~integer(tag_mask)
    mapping = snapshot.mapping(root, address)
    pointers.append({
        "owner": owner,
        "offset": integer(offset),
        "raw_value": raw,
        "tag_mask": integer(tag_mask),
        "target": address,
        "target_length": integer(length),
        "target_root_context": root[0],
        "target_root_selector": root[1],
        "target_pa": integer(mapping["pa"]) + (address & (PAGE - 1)),
        "target_pte": integer(mapping["pte"]),
        "role": role,
    })


def build_report(snapshot, target_path):
    target = json.loads((target_path / "target.json").read_text())
    if target["channel"] != "CL_2" or target["producer_before"] != 0:
        raise RuntimeError("target is not the first CL_2 publication")
    if len(target["queues"]) != 1:
        raise RuntimeError("target contains %d queues" % len(target["queues"]))
    queue_meta = target["queues"][0]
    queue_address = integer(queue_meta["queue_dva"])
    queue = snapshot.read(FW_ROOT, queue_address, g17p.QUEUE_RECORD_STRIDE)
    if queue.hex() != queue_meta["descriptor_hex"]:
        raise RuntimeError(
            "targeted queue bytes do not match the full snapshot; the captures "
            "are not from the same pre-kick stop")

    item_addresses = tuple(integer(value) for value in
                           queue_meta["inner_entries"][0])
    descriptor_address, optional_address, event_address = item_addresses
    descriptor = snapshot.read(
        FW_ROOT, descriptor_address, compute.COMPUTE_DESCRIPTOR_SIZE)
    optional = snapshot.read(
        FW_ROOT, optional_address, compute.COMPUTE_OPTIONAL_SIZE)
    event = snapshot.read(FW_ROOT, event_address, 0x40)
    registers = decode_registers(descriptor)
    register_values = {}
    for number, value in registers:
        register_values.setdefault(number, []).append(value)

    pointer_block = u64(queue, g17p.QUEUE_POINTERS_ADDR)
    item_ring = u64(queue, g17p.QUEUE_RING_ADDR)
    job_list = u64(queue, g17p.QUEUE_JOB_LIST_ADDR)
    channel_record = u64(queue, g17p.QUEUE_CONTEXT_ADDR)
    scheduler = u64(descriptor, 0x10)
    scheduler_page = scheduler & ~(PAGE - 1)
    scheduler_body = snapshot.read(FW_ROOT, scheduler, 0x100)
    shared_support = u64(descriptor, 0xFB2)
    shared_body = snapshot.read(FW_ROOT, shared_support, PAGE)
    support_state = u64(shared_body, 0x4C)
    queue_context_low = u64(optional, 0x08)
    queue_context_high = u64(optional, 0x10)
    queue_context = snapshot.read(FW_ROOT, queue_context_high, PAGE)
    resource = register_values[0x1A510][0]
    cdm = register_values[0x1A420][0]
    cdm_body = snapshot.read(CLIENT_ROOT, cdm, compute.CDM_RECORD_SIZE + 4)
    encoded_shader = u64(cdm_body, 0x08)
    shader_control = encoded_shader >> 32
    shader = ((encoded_shader & 0xFFFFFFFF) << 6
              | ((shader_control & 0x3FFFFFFF) << 40))
    operand_table = u64(shared_body, 0x30)
    primary_root = snapshot.read(FW_ROOT, NATIVE_PRIMARY_ROOT, 0xC0)
    main_config_address = u64(primary_root, 0x18)
    main_config = snapshot.read(FW_ROOT, main_config_address, 0x600)
    main_region_views = tuple(
        u64(main_config, 0x2D0 + index * 8) for index in range(6))
    expected_main_region_views = (
        current.PRIMARY_RECORD_SENTINEL,
        current.PRIMARY_RECORD_A_LOW,
        current.PRIMARY_RECORD_A_HIGH,
        current.PRIMARY_RECORD_B_LOW,
        current.PRIMARY_RECORD_B_HIGH,
        0,
    )
    if main_region_views != expected_main_region_views:
        raise RuntimeError(
            "same-stop main config +0x2d0 region views differ: %r" %
            (main_region_views,))

    objects = []
    add_object = objects.append
    add_object(object_record(
        snapshot, "queue", FW_ROOT, queue_address, 0xC0, "host",
        "Host publishes pointers and identity; firmware advances queue state."))
    add_object(object_record(
        snapshot, "queue_pointer_block", FW_ROOT, pointer_block, 0x80,
        "shared", "Host initializes capacity/producer; firmware advances consumers."))
    add_object(object_record(
        snapshot, "item_ring", FW_ROOT, item_ring, PAGE, "host",
        "Host writes item triplets before producer publication; retained while queued."))
    add_object(object_record(
        snapshot, "compute_descriptor", FW_ROOT, descriptor_address, PAGE,
        "host", "Immutable host command for this submission."))
    add_object(object_record(
        snapshot, "optional_item", FW_ROOT, optional_address, 0xC0,
        "host", "Host metadata paired with the descriptor."))
    add_object(object_record(
        snapshot, "event_item", FW_ROOT, event_address, 0x400,
        "shared", "Host initializes the header; firmware writes completion state."))
    add_object(object_record(
        snapshot, "queue_context", FW_ROOT, queue_context_high, PAGE,
        "host", "Registered per-queue context; retained for the queue lifetime."))
    add_object(object_record(
        snapshot, "scheduler_page", FW_ROOT, scheduler_page, PAGE,
        "shared", "Contains a shared-state pointer and per-work scheduler records."))
    add_object(object_record(
        snapshot, "scheduler_record", FW_ROOT, scheduler, 0x100,
        "shared", "Host selects a slot; firmware owns runtime scheduling state."))
    add_object(object_record(
        snapshot, "shared_support", FW_ROOT, shared_support, PAGE,
        "shared", "Registered support/configuration for the compute queue."))
    add_object(object_record(
        snapshot, "support_state", FW_ROOT, support_state, PAGE,
        "shared", "One active word before the kick; retained with shared support."))
    add_object(object_record(
        snapshot, "zero_page", FW_ROOT, u64(descriptor, 0xFCB), PAGE,
        "host", "Mapped blank for the descriptor lifetime."))
    add_object(object_record(
        snapshot, "job_lists", FW_ROOT, job_list, 0x60,
        "shared", "Four intrusive 0x18-byte list heads retained by the queue."))
    add_object(object_record(
        snapshot, "channel_record", FW_ROOT, channel_record, 0x40,
        "shared", "Fresh host destination; firmware activates and updates it."))
    add_object(object_record(
        snapshot, "resource_table", CLIENT_ROOT, resource, 0xC000,
        "host", "Client binding table retained until the command completes."))
    add_object(object_record(
        snapshot, "cdm_stream", CLIENT_ROOT, cdm,
        compute.CDM_RECORD_SIZE + 4, "host",
        "Command record plus 32-bit terminator; consumed by this dispatch.",
        logical_length=compute.CDM_RECORD_SIZE + 4))
    add_object(object_record(
        snapshot, "shader", CLIENT_ROOT, shader, 0x8000, "host",
        "Executable client allocation; logical program length is not encoded here.",
        logical_length=None))
    add_object(object_record(
        snapshot, "output", CLIENT_ROOT,
        register_values[0x14070][0] & ~1, PAGE, "shared",
        "Blank before the kick; physical content mutation proves execution."))
    add_object(object_record(
        snapshot, "operand_table", CLIENT_ROOT, operand_table, PAGE,
        "host", "Twenty-one tagged entries retained by shared support."))
    add_object(object_record(
        snapshot, "operand_page_lists", CLIENT_ROOT, 0x7000000000,
        3 * PAGE, "host",
        "Three 4-KiB-page DVA lists used by the registration lifecycle."))
    add_object(object_record(
        snapshot, "main_config", FW_ROOT, main_config_address, 0x600,
        "shared", "Host publishes channels and region views; its embedded "
        "device-control ring changes during operation."))
    add_object(object_record(
        snapshot, "main_region_sentinel", FW_ROOT,
        current.PRIMARY_RECORD_SENTINEL, PAGE, "host",
        "High-only blank page named by main config +0x2d0."))
    add_object(object_record(
        snapshot, "main_record_page_a", FW_ROOT,
        current.PRIMARY_RECORD_A_HIGH, PAGE, "shared",
        "Five 0x10-byte records; context-0 and firmware-high views alias."))
    add_object(object_record(
        snapshot, "main_record_page_b", FW_ROOT,
        current.PRIMARY_RECORD_B_HIGH, PAGE, "shared",
        "Four 0x20-byte records; context-0 and firmware-high views alias."))
    add_object(object_record(
        snapshot, "main_record_predecessor", FW_ROOT,
        current.PRIMARY_RECORD_PREDECESSOR, PAGE, "shared",
        "Computed predecessor page adjacent to the two main record pages."))
    add_object(object_record(
        snapshot, "pre_cl2_class1_support", FW_ROOT,
        current.NATIVE_CLASS1_SUPPORT, PAGE, "shared",
        "Compact class-1 support object registered at sequences 90 and 95."))
    add_object(object_record(
        snapshot, "pre_cl2_class1_state", FW_ROOT,
        current.NATIVE_CLASS1_STATE, PAGE, "shared",
        "Class-1 support state; count is 0x4e at the pre-kick boundary."))
    for index, (address, size) in enumerate(current.NATIVE_CLASS1_LOW_EXTENTS):
        add_object(object_record(
            snapshot, "pre_cl2_class1_low_extent_%d" % index, CLIENT_ROOT,
            address, size, "host",
            "Blank mapped extent in the sparse class-1 low region."))
    add_object(object_record(
        snapshot, "pre_cl2_class1_operand", CLIENT_ROOT,
        current.NATIVE_CLASS1_OPERAND,
        current.NATIVE_CONTROL_OPERAND_SIZE, "host",
        "Blank operand/control table; controls select slots +0x440/+0x580."))
    add_object(object_record(
        snapshot, "pre_cl2_class2_support", FW_ROOT,
        current.NATIVE_CLASS2_SUPPORT, PAGE, "shared",
        "Compact class-2 support object registered at sequence 92."))
    add_object(object_record(
        snapshot, "pre_cl2_class2_state", FW_ROOT,
        current.NATIVE_CLASS2_STATE, PAGE, "shared",
        "Class-2 support state; count is 0x0c at the pre-kick boundary."))

    pointers = []
    for owner, offset, root, target_address, length, role in (
        ("queue", 0x00, FW_ROOT, pointer_block, 0x80, "queue state/pointers"),
        ("queue", 0x08, FW_ROOT, item_ring, PAGE, "item ring"),
        ("queue", 0x10, FW_ROOT, job_list, 0x60, "four job-list heads"),
        ("queue", 0x9C, FW_ROOT, channel_record, 0x40, "channel-control record"),
        ("item_ring", 0x00, FW_ROOT, descriptor_address, PAGE,
         "compute descriptor"),
        ("item_ring", 0x08, FW_ROOT, optional_address, 0xC0,
         "optional item"),
        ("item_ring", 0x10, FW_ROOT, event_address, 0x400, "event item"),
        ("descriptor", 0x10, FW_ROOT, scheduler, 0x100,
         "scheduler record"),
        ("descriptor", 0x740, LOW_ALIAS_ROOT, u64(descriptor, 0x740),
         compute.COMPUTE_REGISTER_CAPACITY * compute.COMPUTE_REGISTER_SIZE,
         "primary register array locator"),
        ("descriptor", 0xE60, LOW_ALIAS_ROOT, u64(descriptor, 0xE60),
         4 * compute.COMPUTE_REGISTER_SIZE,
         "secondary register array locator"),
        ("descriptor", 0xED8, CLIENT_ROOT, u64(descriptor, 0xED8), 0xC000,
         "resource table"),
        ("descriptor", 0xEE0, CLIENT_ROOT, u64(descriptor, 0xEE0), 4,
         "CDM terminator"),
        ("descriptor", 0xF40, FW_ROOT, u64(descriptor, 0xF40), 8,
         "dispatch word A"),
        ("descriptor", 0xF48, FW_ROOT, u64(descriptor, 0xF48), 8,
         "dispatch word B"),
        ("descriptor", 0xF7C, FW_ROOT, u64(descriptor, 0xF7C), 8,
         "status word A"),
        ("descriptor", 0xF84, FW_ROOT, u64(descriptor, 0xF84), 8,
         "status word B"),
        ("descriptor", 0xFB2, FW_ROOT, shared_support, PAGE,
         "shared support"),
        ("descriptor", 0xFCB, FW_ROOT, u64(descriptor, 0xFCB), PAGE,
         "blank page"),
        ("optional", 0x08, LOW_ALIAS_ROOT, queue_context_low, PAGE,
         "low queue-context alias"),
        ("optional", 0x10, FW_ROOT, queue_context_high, PAGE,
         "high queue-context alias"),
        ("optional", 0x36, FW_ROOT, u64(optional, 0x36), PAGE,
         "shared support"),
        ("optional", 0x4A, FW_ROOT, u64(optional, 0x4A), 0x40,
         "channel-control record"),
        ("queue_context", 0x210, FW_ROOT, u64(queue_context, 0x210), PAGE,
         "descriptor back-reference"),
        ("queue_context", 0x218, FW_ROOT, u64(queue_context, 0x218), 0xC0,
         "queue back-reference"),
        ("scheduler_page", 0x00, FW_ROOT,
         u64(snapshot.read(FW_ROOT, scheduler_page, 8), 0), PAGE,
         "scheduler shared-state page"),
        ("scheduler_record", 0x00, FW_ROOT, u64(scheduler_body, 0), 0x40,
         "selected scheduler slot"),
        ("shared_support", 0x30, CLIENT_ROOT, operand_table, PAGE,
         "context-3 operand table"),
        ("shared_support", 0x4C, FW_ROOT, support_state, PAGE,
         "support active-state page"),
        ("cdm", 0x08, CLIENT_ROOT, shader, 0x8000,
         "encoded shader pointer"),
        ("main_config", 0x2D0, FW_ROOT,
         current.PRIMARY_RECORD_SENTINEL, PAGE,
         "high-only blank sentinel"),
        ("main_config", 0x2D8, LOW_ALIAS_ROOT,
         current.PRIMARY_RECORD_A_LOW, PAGE,
         "context-0 view of record page A"),
        ("main_config", 0x2E0, FW_ROOT,
         current.PRIMARY_RECORD_A_HIGH, PAGE,
         "firmware-high view of record page A"),
        ("main_config", 0x2E8, LOW_ALIAS_ROOT,
         current.PRIMARY_RECORD_B_LOW, PAGE,
         "context-0 view of record page B"),
        ("main_config", 0x2F0, FW_ROOT,
         current.PRIMARY_RECORD_B_HIGH, PAGE,
         "firmware-high view of record page B"),
    ):
        add_pointer(snapshot, pointers, owner, offset, root, target_address,
                    length, role)

    pointer_registers = {
        0x1A510: (resource, 0xC000, "resource table", 0),
        0x1A420: (cdm, compute.CDM_RECORD_SIZE + 4, "CDM stream", 0),
        0x1A4D0: (resource + 0x1480, 8, "resource internal word 0", 0),
        0x1A4D8: (resource + 0x1488, 8, "resource internal word 1", 0),
        0x1A4E0: (resource + 0x1490, 8, "resource internal word 2", 0),
        0x1A4E8: (resource + 0x1498, 8, "resource internal word 3", 0),
        0x14070: (register_values[0x14070][0], PAGE,
                  "tagged output/robustness page", 1),
        0x10229: (register_values[0x10229][0], 8, "scratch", 0),
        0x140A8: (register_values[0x140A8][0], 8, "scratch", 0),
        0x10099: (register_values[0x10099][0], 8, "tagged scratch", 1),
        0x10091: (register_values[0x10091][0], 8, "scratch", 0),
        0x0A5C1: (register_values[0x0A5C1][0], 8, "tagged blank state", 1),
        0x0A5C9: (register_values[0x0A5C9][0], 8, "scratch", 0),
    }
    for number, (value, length, role, tag) in pointer_registers.items():
        index = next(i for i, pair in enumerate(registers) if pair[0] == number)
        add_pointer(
            snapshot, pointers, "primary_registers",
            compute.COMPUTE_REGISTER_START
            + index * compute.COMPUTE_REGISTER_SIZE + 4,
            CLIENT_ROOT, value, length, "register %#x: %s" % (number, role),
            tag_mask=tag)

    resource_body = snapshot.read(CLIENT_ROOT, resource, 0xC000)
    for offset, length, role in (
            (0x14A0, 0x20, "texture descriptor inside resource object"),
            (0x14A8, 0x20, "sampler descriptor inside resource object"),
            (0x14C8, PAGE, "texture backing/base address")):
        add_pointer(snapshot, pointers, "resource_table", offset, CLIENT_ROOT,
                    u64(resource_body, offset), length, role)

    operand_body = snapshot.read(CLIENT_ROOT, operand_table, PAGE)
    operand_entries = []
    for index in range(compute.COMPUTE_OPERAND_TABLE_ENTRIES):
        offset = index * compute.COMPUTE_OPERAND_TABLE_STRIDE
        tagged = u64(operand_body, offset)
        add_pointer(
            snapshot, pointers, "operand_table", offset, CLIENT_ROOT, tagged,
            compute.COMPUTE_OPERAND_BUFFER_SIZE,
            "operand tranche %d" % index,
            tag_mask=compute.COMPUTE_OPERAND_BUFFER_FLAG)
        operand_entries.append(tagged)
    if any(operand_body[compute.COMPUTE_OPERAND_TABLE_ENTRIES
                        * compute.COMPUTE_OPERAND_TABLE_STRIDE:]):
        raise RuntimeError("operand table has a nonzero tail")

    for owner, low_buffer, operand, state in (
            ("pre_cl2_class1_support", current.NATIVE_CLASS1_PAGE_LIST,
             current.NATIVE_CLASS1_OPERAND, current.NATIVE_CLASS1_STATE),
            ("pre_cl2_class2_support", current.NATIVE_CLASS2_PAGE_LIST,
             current.NATIVE_CLASS2_OPERAND, current.NATIVE_CLASS2_STATE)):
        add_pointer(
            snapshot, pointers, owner, 0x14, CLIENT_ROOT, low_buffer,
            (current.NATIVE_CLASS1_LOW_SPAN
             if owner == "pre_cl2_class1_support"
             else current.NATIVE_CLASS2_PAGE_LIST_SIZE),
            "low page-list region reconstructed from the operand namespace")
        add_pointer(
            snapshot, pointers, owner, 0x30, CLIENT_ROOT, operand,
            current.NATIVE_CONTROL_OPERAND_SIZE, "operand/control table")
        add_pointer(
            snapshot, pointers, owner, 0x4C, FW_ROOT, state, PAGE,
            "firmware state page")

    control_entries = {
        integer(entry["absolute_index"]): entry
        for entry in target["device_control"]["entries"]
    }
    # This is the complete non-tick control history retained at the successful
    # pre-kick stop, not merely the final CL2 suffix.  The pages named by early
    # entries have already been rewritten by firmware at this boundary, so
    # their final bytes are retirement evidence rather than constructor input.
    expected_controls = (
        (1, 1, 0, 0xFFFFFC20C0830000,
         0x7000208000, 0x440, 0x28, 0),
        (3, 1, 1, 0xFFFFFC20C0830000,
         0x7000208000, 0x580, 0x38, 0),
        (47, 2, 44, 0xFFFFFC20C08C0000,
         0x7000208000, 0x5C0, 0x28, 1),
        (50, 2, 46, 0xFFFFFC20C0900000,
         0x7000208000, 0x5C0, 0x28, 1),
        (55, 1, 50, current.NATIVE_CLASS1_SUPPORT,
         0x7000208000, 0x4C0, 0x10, 0),
        (96, 1, 90, current.NATIVE_CLASS1_SUPPORT,
         current.NATIVE_CLASS1_OPERAND, 0x440, 0x28, 0),
        (99, 2, 92, current.NATIVE_CLASS2_SUPPORT,
         current.NATIVE_CLASS2_OPERAND, 0x5C0, 0x18, 1),
        (103, 1, 95, current.NATIVE_CLASS1_SUPPORT,
         current.NATIVE_CLASS1_OPERAND, 0x580, 0x38, 0),
    )
    control_history = []
    for (index, control_class, sequence, first_object, table,
         slot_offset, count, context_word) in expected_controls:
        words = [integer(value) for value in control_entries[index]["u32"]]
        decoded_first = words[5] | (words[6] << 32)
        decoded_table = words[7] | (words[8] << 32)
        decoded_slot = words[9] | (words[10] << 32)
        decoded = {
            "absolute_index": index,
            "opcode": words[0],
            "class": words[1],
            "mask": words[2],
            "sequence": words[3],
            "first_object": decoded_first,
            "operand_table": decoded_table,
            "slot": decoded_slot,
            "count": words[11],
            "context_word": words[12],
            "trailing_word": words[13],
        }
        expected = {
            "opcode": 0x20,
            "class": control_class,
            "mask": 0x3F,
            "sequence": sequence,
            "first_object": first_object,
            "operand_table": table,
            "slot": table + slot_offset,
            "count": count,
            "context_word": context_word,
            "trailing_word": 1,
        }
        decoded["matches_expected"] = all(
            decoded[name] == value for name, value in expected.items())
        decoded["expected"] = expected
        control_history.append(decoded)
        add_pointer(
            snapshot, pointers, "device_control[%d]" % index, 0x14,
            FW_ROOT, decoded_first, PAGE, "compact control support object")
        add_pointer(
            snapshot, pointers, "device_control[%d]" % index, 0x1C,
            CLIENT_ROOT, decoded_table,
            current.NATIVE_CONTROL_OPERAND_SIZE, "operand/control table")
        add_pointer(
            snapshot, pointers, "device_control[%d]" % index, 0x24,
            CLIENT_ROOT, decoded_slot, 0x40, "selected operand slot")
    if not all(entry["matches_expected"] for entry in control_history):
        raise RuntimeError(
            "same-stop device-control history does not decode as expected")

    final_control_objects = []
    for first_object in dict.fromkeys(
            entry["first_object"] for entry in control_history):
        body = snapshot.read(FW_ROOT, first_object, PAGE)
        control_class = u32(body, 0x00)
        inner_class = u32(body, 0x10)
        compact = control_class in (1, 2) and inner_class == control_class
        record = {
            "address": first_object,
            "format": "compact" if compact else "firmware_transformed",
            "nonzero_bytes": sum(value != 0 for value in body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        add_object(object_record(
            snapshot, "control_object_%x" % first_object, FW_ROOT,
            first_object, PAGE, "shared",
            ("Still uses the compact 0x70-byte control-support format at the "
             "pre-kick boundary." if compact else
             "Firmware transformed the earlier compact input in place; final "
             "bytes must not be reused as constructor input."),
            logical_length=0x70 if compact else None))
        if compact:
            low32 = u32(body, 0x14)
            operand = u64(body, 0x30)
            state = u64(body, 0x4C)
            low = (operand & ~0xFFFFFFFF) | low32
            record["fields"] = {
                "class": control_class,
                "active": u32(body, 0x08),
                "inner_class": inner_class,
                "low_pointer_low32": low32,
                "low_pointer": low,
                "word_18": u64(body, 0x18),
                "word_20": u64(body, 0x20),
                "word_28": u64(body, 0x28),
                "operand_table": operand,
                "word_40": u64(body, 0x40),
                "cursor": u32(body, 0x48),
                "state": state,
                "field_54": u32(body, 0x54),
                "field_5c": u32(body, 0x5C),
                "final_kind": u32(body, 0x60),
            }
            add_pointer(
                snapshot, pointers,
                "control_object_%x" % first_object, 0x14,
                CLIENT_ROOT, low, PAGE,
                "low client object reconstructed in the operand namespace")
            add_pointer(
                snapshot, pointers,
                "control_object_%x" % first_object, 0x30,
                CLIENT_ROOT, operand, current.NATIVE_CONTROL_OPERAND_SIZE,
                "operand/control table")
            add_pointer(
                snapshot, pointers,
                "control_object_%x" % first_object, 0x4C,
                FW_ROOT, state, PAGE, "firmware state page")
        else:
            nonzero_qwords = []
            for offset in range(0, PAGE, 8):
                value = u64(body, offset)
                if value:
                    nonzero_qwords.append({"offset": offset, "value": value})
            record["nonzero_qwords"] = nonzero_qwords
        final_control_objects.append(record)

    checks = []

    def check(name, native, generated, ignored=()):
        differences = differing_bytes(native, generated, ignored)
        checks.append({
            "name": name,
            "native_length": len(native),
            "generated_length": len(generated),
            "ignored_ranges": list(ignored),
            "differing_bytes": len(differences),
            "first_differences": differences[:32],
            "byte_exact": not differences and len(native) == len(generated),
        })

    queue_built = g17p.build_queue_record(
        pointer_block, item_ring, job_list, channel_record,
        uuid=u32(queue, g17p.QUEUE_UUID),
        priority=u32(queue, g17p.QUEUE_PRIORITY),
        prio5=u32(queue, g17p.QUEUE_PRIO5),
        unk_2c=u32(queue, g17p.QUEUE_UNK_2C),
        unk_38=u32(queue, g17p.QUEUE_UNK_38),
        unk_94=u32(queue, g17p.QUEUE_UNK_94),
        sentinel_size=2,
    )
    check("queue", queue, queue_built)

    pointer_native = snapshot.read(FW_ROOT, pointer_block, 0x80)
    pointer_built = bytearray(0x80)
    pointer_built[:g17p.QUEUE_PTR_BLOCK_SIZE] = g17p.build_queue_pointers(
        u32(pointer_native, g17p.QUEUE_PTR_RING_SIZE))
    struct.pack_into("<I", pointer_built, 0x60, u32(pointer_native, 0x60))
    check("queue pointer block host fields", pointer_native,
          bytes(pointer_built), ignored=((0x40, 0x44),))

    descriptor_built = compute.build_compute_descriptor(
        registers,
        scheduler_record=scheduler,
        low_alias=u64(descriptor, 0x740) - compute.COMPUTE_REGISTER_START,
        cdm_terminator=u64(descriptor, 0xEE0),
        submit_sequence=u64(descriptor, 0x04),
        context_id=u32(descriptor, 0x0C),
        grid_index=u32(descriptor, 0xF54),
        dispatch_a=u64(descriptor, 0xF40),
        dispatch_b=u64(descriptor, 0xF48),
        status_a=u64(descriptor, 0xF7C),
        status_b=u64(descriptor, 0xF84),
        shared_control=shared_support,
        zero_page=u64(descriptor, 0xFCB),
        protection_index=u32(descriptor, 0xF60),
        support_control=u32(descriptor, 0xFBA),
        support_flags=u32(descriptor, 0xFBE),
    )
    check("compute descriptor", descriptor, descriptor_built)

    optional_built = compute.build_compute_optional(
        queue_context_low, queue_context_high,
        grid_index=u16(optional, 0x18),
        submission_ordinal=u16(optional, 0x3E),
        shared_control=u64(optional, 0x36),
        channel_control=u64(optional, 0x4A),
        uuid=u16(optional, 0x5A),
        field_46=u16(optional, 0x46),
        field_1e=u16(optional, 0x1E),
        field_32=u16(optional, 0x32),
        field_56=u16(optional, 0x56),
        field_5e=u16(optional, 0x5E),
    )
    check("optional item", optional, optional_built)

    event_word = u32(event, 0x08)
    event_built = compute.build_compute_event(
        event_word >> 8, u32(event, 0x04) & 0xFFFF,
        counter_low=event_word & 0xFF)[:0x40]
    check("event header", event, event_built)

    scheduler_built = compute.build_compute_scheduler_record(
        u64(scheduler_body, 0x00),
        work_id=u32(scheduler_body, 0x08),
        phase=u32(scheduler_body, 0x0C),
        job_list=u64(scheduler_body, 0xA0),
        node_id=u64(scheduler_body, 0xA8) & 0xFFFFFF,
    )
    check("scheduler record", scheduler_body, scheduler_built)

    shared_built = compute.build_compute_shared_support(
        operand_table, support_state,
        word_08=u64(shared_body, 0x08),
        word_10=u64(shared_body, 0x10),
        header=u64(shared_body, 0x00),
        resource_class=u64(shared_body, 0x20) >> 40,
        cursor=u32(shared_body, 0x48),
        field_5c=u32(shared_body, 0x5C),
        final_kind=u32(shared_body, 0x60),
    )
    check("shared support", shared_body, shared_built)

    grid = u16(optional, 0x18)
    qctx_flags = u64(queue_context, 0x200) & ~((grid * 4) << 40 | 4)
    queue_context_built = compute.build_compute_queue_context(
        descriptor_address, queue_address, grid,
        flags_200=qctx_flags,
        word_220=u64(queue_context, 0x220),
        word_330=u64(queue_context, 0x330),
        word_338=u64(queue_context, 0x338),
        word_350=u64(queue_context, 0x350),
        word_358=u64(queue_context, 0x358),
        word_378=u64(queue_context, 0x378),
    )
    check("queue context", queue_context, queue_context_built)

    first_operand = operand_entries[0] & ~compute.COMPUTE_OPERAND_BUFFER_FLAG
    check(
        "operand table", operand_body,
        compute.build_compute_operand_table(first_operand))
    page_lists = snapshot.read(CLIENT_ROOT, 0x7000000000, 3 * PAGE)
    check(
        "operand page lists", page_lists,
        compute.build_compute_operand_page_lists(first_operand))

    class1_support = snapshot.read(
        FW_ROOT, current.NATIVE_CLASS1_SUPPORT, PAGE)
    class1_state = snapshot.read(
        FW_ROOT, current.NATIVE_CLASS1_STATE, PAGE)
    class1_state_built = bytearray(PAGE)
    struct.pack_into("<Q", class1_state_built, 0, 0x4E)
    check(
        "pre-CL2 class1 support", class1_support,
        compute.build_compute_class1_support(
            current.NATIVE_CLASS1_OPERAND,
            current.NATIVE_CLASS1_PAGE_LIST,
            current.NATIVE_CLASS1_STATE,
            active=0, cursor=0xE8, final_kind=2,
            word_20=0x0000352000001820,
            word_28=0x00001D0000000000,
            field_54=0x4E))
    check("pre-CL2 class1 state", class1_state, bytes(class1_state_built))
    for index, (address, size) in enumerate(current.NATIVE_CLASS1_LOW_EXTENTS):
        check(
            "pre-CL2 class1 low extent %d" % index,
            snapshot.read(CLIENT_ROOT, address, size), bytes(size))
    check(
        "pre-CL2 class1 operand region",
        snapshot.read(
            CLIENT_ROOT, current.NATIVE_CLASS1_OPERAND,
            current.NATIVE_CONTROL_OPERAND_SIZE),
        bytes(current.NATIVE_CONTROL_OPERAND_SIZE))

    class2_support = snapshot.read(
        FW_ROOT, current.NATIVE_CLASS2_SUPPORT, PAGE)
    class2_state = snapshot.read(
        FW_ROOT, current.NATIVE_CLASS2_STATE, PAGE)
    class2_state_built = bytearray(PAGE)
    struct.pack_into("<Q", class2_state_built, 0, 0x0C)
    check(
        "pre-CL2 class2 support", class2_support,
        compute.build_compute_class2_support(
            current.NATIVE_CLASS2_OPERAND,
            current.NATIVE_CLASS2_PAGE_LIST,
            current.NATIVE_CLASS2_STATE,
            active=1, cursor=0xD0, final_kind=3,
            word_20=0x00001CF0000002F0,
            word_28=0x00001A0000000000,
            field_54=0x0C))
    check("pre-CL2 class2 state", class2_state, bytes(class2_state_built))

    main_region_built = b"".join(
        struct.pack("<Q", value) for value in expected_main_region_views)
    check(
        "main config +0x2d0 region views",
        main_config[0x2D0:0x300], main_region_built)

    record_page_a_built = bytearray(PAGE)
    for index, record in enumerate(current.NATIVE_COMPUTE_RECORDS_A):
        struct.pack_into("<4I", record_page_a_built, index * 0x10, *record)
    record_page_b_built = bytearray(PAGE)
    for index, record in enumerate(current.NATIVE_COMPUTE_RECORDS_B):
        struct.pack_into("<5I", record_page_b_built, index * 0x20, *record)
    predecessor_built = bytearray(PAGE)
    for offset, value in current.NATIVE_COMPUTE_PREDECESSOR_U32:
        struct.pack_into("<I", predecessor_built, offset, value)
    for offset, value in current.NATIVE_COMPUTE_PREDECESSOR_U64:
        struct.pack_into("<Q", predecessor_built, offset, value)
    check(
        "main config blank sentinel",
        snapshot.read(FW_ROOT, current.PRIMARY_RECORD_SENTINEL, PAGE),
        bytes(PAGE))
    check(
        "main config record page A",
        snapshot.read(FW_ROOT, current.PRIMARY_RECORD_A_HIGH, PAGE),
        bytes(record_page_a_built))
    check(
        "main config record page B",
        snapshot.read(FW_ROOT, current.PRIMARY_RECORD_B_HIGH, PAGE),
        bytes(record_page_b_built))
    check(
        "main config predecessor page",
        snapshot.read(FW_ROOT, current.PRIMARY_RECORD_PREDECESSOR, PAGE),
        bytes(predecessor_built))

    low_mapping = snapshot.mapping(LOW_ALIAS_ROOT, queue_context_low)
    high_mapping = snapshot.mapping(FW_ROOT, queue_context_high)
    alias_checks = [{
        "name": "queue context low/high",
        "low": queue_context_low,
        "high": queue_context_high,
        "low_pa": integer(low_mapping["pa"]),
        "high_pa": integer(high_mapping["pa"]),
        "same_physical_page": integer(low_mapping["pa"]) ==
                              integer(high_mapping["pa"]),
        "same_bytes": snapshot.read(LOW_ALIAS_ROOT, queue_context_low, PAGE) ==
                      queue_context,
    }]
    descriptor_low = u64(descriptor, 0x740) - compute.COMPUTE_REGISTER_START
    descriptor_low_mapping = snapshot.mapping(LOW_ALIAS_ROOT, descriptor_low)
    descriptor_high_mapping = snapshot.mapping(FW_ROOT, descriptor_address)
    alias_checks.append({
        "name": "descriptor low/high",
        "low": descriptor_low,
        "high": descriptor_address,
        "low_pa": integer(descriptor_low_mapping["pa"]),
        "high_pa": integer(descriptor_high_mapping["pa"]),
        "same_physical_page": integer(descriptor_low_mapping["pa"]) ==
                              integer(descriptor_high_mapping["pa"]),
        "same_bytes": snapshot.read(
            LOW_ALIAS_ROOT, descriptor_low, PAGE) == descriptor,
    })
    for name, low, high in (
            ("main record page A low/high",
             current.PRIMARY_RECORD_A_LOW, current.PRIMARY_RECORD_A_HIGH),
            ("main record page B low/high",
             current.PRIMARY_RECORD_B_LOW, current.PRIMARY_RECORD_B_HIGH)):
        low_mapping = snapshot.mapping(LOW_ALIAS_ROOT, low)
        high_mapping = snapshot.mapping(FW_ROOT, high)
        alias_checks.append({
            "name": name,
            "low": low,
            "high": high,
            "low_pa": integer(low_mapping["pa"]),
            "high_pa": integer(high_mapping["pa"]),
            "same_physical_page": integer(low_mapping["pa"]) ==
                                  integer(high_mapping["pa"]),
            "same_bytes": snapshot.read(LOW_ALIAS_ROOT, low, PAGE) ==
                          snapshot.read(FW_ROOT, high, PAGE),
        })

    native_final_tuple = {
        "grid": grid,
        "queue": queue_address,
        "queue_pointers": pointer_block,
        "item_ring": item_ring,
        "descriptor": descriptor_address,
        "optional": optional_address,
        "event": event_address,
        "queue_context_low": queue_context_low,
        "queue_context_high": queue_context_high,
        "scheduler": scheduler,
        "shared_support": shared_support,
        "support_state": support_state,
        "zero_page": u64(descriptor, 0xFCB),
        "dispatch_a": u64(descriptor, 0xF40),
        "dispatch_b": u64(descriptor, 0xF48),
        "status_a": u64(descriptor, 0xF7C),
        "status_b": u64(descriptor, 0xF84),
        "submission_ordinal": u16(optional, 0x3E),
        "queue_uuid": u32(queue, g17p.QUEUE_UUID),
        "dispatch_identity": register_values[0x1A540][0],
        "shared_support_header": u64(shared_body, 0x00),
        "queue_context_word_350": u64(queue_context, 0x350),
        "queue_context_word_358": u64(queue_context, 0x358),
    }
    current_register_values = dict(current.compute_registers())
    current_final_tuple = {
        "grid": current.GRID,
        "queue": current.QUEUE,
        "queue_pointers": current.QUEUE_POINTERS,
        "item_ring": current.ITEM_RING,
        "descriptor": current.DESCRIPTOR,
        "optional": current.OPTIONAL,
        "event": current.EVENT,
        "queue_context_low": current.QUEUE_CONTEXT_LOW,
        "queue_context_high": current.QUEUE_CONTEXT_HIGH,
        "scheduler": current.SCHEDULER,
        "shared_support": current.SHARED_SUPPORT,
        "support_state": current.SUPPORT_STATE,
        "zero_page": current.ZERO_PAGE,
        "dispatch_a": current.DISPATCH_A,
        "dispatch_b": current.DISPATCH_B,
        "status_a": current.STATUS_A,
        "status_b": current.STATUS_B,
        "submission_ordinal": current.SUBMISSION_ORDINAL,
        "queue_uuid": current.QUEUE_UUID,
        "dispatch_identity": current_register_values[0x1A540],
        "shared_support_header": current.SHARED_SUPPORT_HEADER,
        "queue_context_word_350": current.QUEUE_CONTEXT_WORD_350,
        "queue_context_word_358": current.QUEUE_CONTEXT_WORD_358,
    }
    current_final_tuple_checks = [{
        "field": name,
        "native": native_final_tuple[name],
        "current": current_final_tuple[name],
        "equal": native_final_tuple[name] == current_final_tuple[name],
    } for name in native_final_tuple]

    report = {
        "format": "m1n1-t8140-g17p-native-compute-graph-audit-v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "full_snapshot": str(snapshot.path),
        "targeted_capture": str(target_path),
        "capture_alignment": {
            "queue_address": queue_address,
            "targeted_queue_matches_full_snapshot": True,
            "channel": target["channel"],
            "producer_before": target["producer_before"],
            "producer_after": target["producer_after"],
            "trigger_endpoint": snapshot.manifest["trigger_endpoint"],
            "trigger_type": snapshot.manifest["trigger_type"],
            "trigger_message": snapshot.manifest["trigger_message"],
        },
        "object_count": len(objects),
        "objects": objects,
        "pointer_count": len(pointers),
        "pointers": pointers,
        "registers": [
            {"index": index, "number": number, "value": value}
            for index, (number, value) in enumerate(registers)
        ],
        "device_control_history": control_history,
        "pre_cl2_control_suffix": control_history[-3:],
        "final_control_objects": final_control_objects,
        "main_config_region_views": [
            {
                "offset": 0x2D0 + index * 8,
                "value": value,
                "role": (
                    "high-only blank sentinel",
                    "record page A context-0 view",
                    "record page A firmware-high view",
                    "record page B context-0 view",
                    "record page B firmware-high view",
                    "null terminator",
                )[index],
            }
            for index, value in enumerate(main_region_views)
        ],
        "constructor_checks": checks,
        "alias_checks": alias_checks,
        "current_final_tuple_checks": current_final_tuple_checks,
    }
    return report


def write_summary(path, report):
    lines = [
        "G17P Native Compute Graph Audit",
        "================================",
        "",
        "Full pre-kick snapshot: `%s`" % report["full_snapshot"],
        "Matching targeted metadata: `%s`" % report["targeted_capture"],
        "",
        "The targeted queue bytes match the full snapshot at `%#x`; all object "
        "bytes and mappings below therefore describe the same blocked compute "
        "doorbell." % report["capture_alignment"]["queue_address"],
        "",
        "Objects: %d. Pointer edges: %d." % (
            report["object_count"], report["pointer_count"]),
        "",
        "Constructor checks",
        "------------------",
    ]
    for check in report["constructor_checks"]:
        lines.append("- %s: %s (%d differing bytes)" % (
            check["name"], "byte-exact" if check["byte_exact"] else "DIFFERS",
            check["differing_bytes"]))
    lines.extend(["", "Aliases", "-------"])
    for check in report["alias_checks"]:
        lines.append("- %s: PA alias=%s, byte alias=%s" % (
            check["name"], check["same_physical_page"], check["same_bytes"]))
    lines.extend(["", "Main config +0x2d0 views", "------------------------"])
    for view in report["main_config_region_views"]:
        lines.append("- +%#x: `%#x`: %s" % (
            view["offset"], view["value"], view["role"]))
    lines.extend(["", "Current final tuple", "-------------------"])
    for check in report["current_final_tuple_checks"]:
        lines.append("- %s: current `%#x`, native `%#x`: %s" % (
            check["field"], check["current"], check["native"],
            "equal" if check["equal"] else "DIFFERS"))
    lines.extend(["", "Complete device-control history",
                  "-------------------------------"])
    for control in report["device_control_history"]:
        lines.append(
            "- index %d: class %d sequence %#x, first `%#x`, table `%#x`, "
            "slot `%#x`, count `%#x`, context %d: %s" % (
                control["absolute_index"], control["class"],
                control["sequence"], control["first_object"],
                control["operand_table"], control["slot"],
                control["count"], control["context_word"],
                "exact" if control["matches_expected"] else "DIFFERS"))
    lines.extend(["", "Final control-object forms",
                  "--------------------------"])
    for obj in report["final_control_objects"]:
        lines.append("- `%#x`: %s, %d nonzero bytes" % (
            obj["address"], obj["format"], obj["nonzero_bytes"]))
    lines.extend(["", "Object inventory", "----------------"])
    for obj in report["objects"]:
        lines.append(
            "- %s: root %d/%d `%#x`, length `%#x`, %s; %s" % (
                obj["name"], obj["root_context"], obj["root_selector"],
                obj["address"], obj["length"], obj["ownership"],
                obj["lifecycle"]))
    lines.extend(["", "Pointer inventory", "-----------------"])
    for pointer in report["pointers"]:
        lines.append(
            "- %s +%#x -> root %d/%d `%#x` +`%#x`: %s" % (
                pointer["owner"], pointer["offset"],
                pointer["target_root_context"], pointer["target_root_selector"],
                pointer["target"], pointer["target_length"], pointer["role"]))
    path.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=pathlib.Path,
                        default=DEFAULT_SNAPSHOT)
    parser.add_argument("--target", type=pathlib.Path, default=DEFAULT_TARGET)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    snapshot = Snapshot(args.snapshot)
    report = build_report(snapshot, args.target)
    output = args.output
    if output is None:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output = pathlib.Path(
            "/Users/user/asahi_re/artifacts/agx_g17p/"
            "native_compute_graph_audit_%s" % stamp)
    output.mkdir(parents=True, exist_ok=False)
    (output / "audit.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")
    write_summary(output / "summary.md", report)
    print((output / "summary.md").read_text(), end="")
    print("Artifact: %s" % output)
    failed = [check for check in report["constructor_checks"]
              if not check["byte_exact"]]
    failed.extend(check for check in report["alias_checks"]
                  if not check["same_physical_page"] or not check["same_bytes"])
    failed.extend(check for check in report["current_final_tuple_checks"]
                  if not check["equal"])
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
