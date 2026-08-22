#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare output-positive G17P compute captures by semantic object role.

Raw same-DVA page comparisons are dominated by allocator placement, unrelated
render history, and firmware-owned retirement state.  This tool starts at the
published CL2 queue in each capture, follows the known pointer graph, and
compares fields by role.  It also builds the current add3 graph offline so the
report distinguishes native variability from state the experiment does not
faithfully construct.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import struct
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from m1n1.agx import g17p, g17p_compute as compute  # noqa: E402
import agx_g17p_compute as current  # noqa: E402


PAGE = 0x4000
SCHEDULER_RECORD_COUNT = 36
DEFAULT_AUG6 = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260806_085451/CL_2"
)
DEFAULT_AUG10 = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260810_202312/CL_2"
)
DEFAULT_AUG6_AUDIT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_compute_graph_audit_systematic_20260810/audit.json"
)
DEFAULT_OUTPUT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "positive_compute_capture_delta_ledger_20260810"
)


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def u16(body, offset):
    return struct.unpack_from("<H", body, offset)[0]


def u32(body, offset):
    return struct.unpack_from("<I", body, offset)[0]


def u64(body, offset):
    return struct.unpack_from("<Q", body, offset)[0]


def hex_value(value):
    return None if value is None else "%#x" % integer(value)


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def difference_runs(left, right):
    limit = min(len(left), len(right))
    runs = []
    offset = 0
    while offset < limit:
        if left[offset] == right[offset]:
            offset += 1
            continue
        end = offset + 1
        while end < limit and left[end] != right[end]:
            end += 1
        runs.append({
            "start": offset,
            "end": end,
            "left_hex": left[offset:end].hex(),
            "right_hex": right[offset:end].hex(),
        })
        offset = end
    if len(left) != len(right):
        runs.append({
            "start": limit,
            "end": max(len(left), len(right)),
            "left_hex": left[limit:].hex(),
            "right_hex": right[limit:].hex(),
        })
    return runs


def diff_summary(left, right):
    runs = difference_runs(left, right)
    return {
        "left_length": len(left),
        "right_length": len(right),
        "differing_bytes": sum(run["end"] - run["start"] for run in runs),
        "runs": runs,
        "byte_exact": not runs,
    }


def nonzero_qwords(body, limit=None):
    limit = len(body) if limit is None else min(len(body), integer(limit))
    return [
        {"offset": offset, "value": u64(body, offset)}
        for offset in range(0, limit - 7, 8)
        if u64(body, offset)
    ]


def qword_deltas(left, right, limit=None):
    limit = min(len(left), len(right)) if limit is None else min(
        len(left), len(right), integer(limit))
    return [
        {
            "offset": offset,
            "left": u64(left, offset),
            "right": u64(right, offset),
        }
        for offset in range(0, limit - 7, 8)
        if u64(left, offset) != u64(right, offset)
    ]


class TargetCapture:
    def __init__(self, path, label):
        self.path = pathlib.Path(path)
        self.label = label
        self.target = json.loads((self.path / "target.json").read_text())
        manifest = json.loads((self.path / "pages.json").read_text())
        raw = (self.path / "pages.bin").read_bytes()
        self.records = {}
        self.pages = {}
        for record in manifest["pages"]:
            address = integer(record["dva"])
            offset = integer(record["capture_offset"])
            body = raw[offset:offset + PAGE]
            if len(body) != PAGE:
                raise RuntimeError("short page %#x in %s" % (address, path))
            self.records[address] = record
            self.pages[address] = body

    def has(self, address, size=1):
        address = integer(address)
        end = address + integer(size)
        return all(
            page in self.pages
            for page in range(address & ~(PAGE - 1),
                              (end + PAGE - 1) & ~(PAGE - 1), PAGE)
        )

    def read(self, address, size, required=True):
        address = integer(address)
        remaining = integer(size)
        out = bytearray()
        while remaining:
            page = address & ~(PAGE - 1)
            offset = address - page
            take = min(remaining, PAGE - offset)
            body = self.pages.get(page)
            if body is None:
                if required:
                    raise RuntimeError(
                        "%s does not contain page %#x" % (self.label, page))
                return None
            out.extend(body[offset:offset + take])
            address += take
            remaining -= take
        return bytes(out)

    def page_record(self, address):
        return self.records.get(integer(address) & ~(PAGE - 1))


def decode_registers(descriptor):
    registers = []
    for index in range(compute.COMPUTE_REGISTER_CAPACITY):
        offset = compute.COMPUTE_REGISTER_START + index * compute.COMPUTE_REGISTER_SIZE
        number, value = struct.unpack_from("<IQ", descriptor, offset)
        if not number and not value:
            break
        registers.append({
            "index": index,
            "offset": offset,
            "number": number,
            "value": value,
        })
    return registers


def register_map(registers):
    out = {}
    for entry in registers:
        out.setdefault(entry["number"], []).append(entry["value"])
    return out


def decode_control_entries(target):
    decoded = []
    for entry in target["device_control"]["entries"]:
        words = [integer(value) for value in entry["u32"]]
        if words[0] != 0x20:
            continue
        decoded.append({
            "absolute_index": integer(entry["absolute_index"]),
            "opcode": words[0],
            "class": words[1],
            "mask": words[2],
            "sequence": words[3],
            "first_object": words[5] | (words[6] << 32),
            "operand_table": words[7] | (words[8] << 32),
            "slot": words[9] | (words[10] << 32),
            "count": words[11],
            "context_word": words[12],
            "trailing_word": words[13],
        })
    return decoded


def decode_event_records(body):
    return [
        {
            "index": index,
            "selector": u32(body, index * 0x40),
            "subtype": u32(body, index * 0x40 + 0x04),
            "counter": u32(body, index * 0x40 + 0x08),
            "word_10": u32(body, index * 0x40 + 0x10),
            "nonzero_bytes": sum(
                value != 0
                for value in body[index * 0x40:(index + 1) * 0x40]),
        }
        for index in range(len(body) // 0x40)
    ]


def field_table(body, fields):
    result = {}
    for name, offset, kind in fields:
        read = {"u16": u16, "u32": u32, "u64": u64}[kind]
        result[name] = {"offset": offset, "width": int(kind[1:]) // 8,
                        "value": read(body, offset)}
    return result


OPTIONAL_FIELDS = (
    ("selector", 0x00, "u32"),
    ("context_low", 0x08, "u64"),
    ("context_high", 0x10, "u64"),
    ("grid", 0x18, "u16"),
    ("field_1a", 0x1A, "u16"),
    ("field_1e", 0x1E, "u16"),
    ("field_22", 0x22, "u16"),
    ("field_32", 0x32, "u16"),
    ("shared_support", 0x36, "u64"),
    ("submission_ordinal", 0x3E, "u16"),
    ("field_46", 0x46, "u16"),
    ("channel_control", 0x4A, "u64"),
    ("field_52", 0x52, "u16"),
    ("field_56", 0x56, "u16"),
    ("uuid", 0x5A, "u16"),
    ("field_5e", 0x5E, "u16"),
    ("field_62", 0x62, "u16"),
    ("field_66", 0x66, "u16"),
)

QUEUE_CONTEXT_FIELDS = tuple(
    ("word_%03x" % offset, offset, "u64")
    for offset in (0x200, 0x210, 0x218, 0x220, 0x228, 0x330, 0x338,
                   0x350, 0x358, 0x378)
)

SHARED_SUPPORT_FIELDS = (
    ("header", 0x00, "u64"),
    ("word_08", 0x08, "u64"),
    ("word_10", 0x10, "u64"),
    ("word_18", 0x18, "u64"),
    ("resource_20", 0x20, "u64"),
    ("resource_28", 0x28, "u64"),
    ("operand_table", 0x30, "u64"),
    ("word_40", 0x40, "u64"),
    ("cursor", 0x48, "u32"),
    ("support_state", 0x4C, "u64"),
    ("field_54", 0x54, "u32"),
    ("field_5c", 0x5C, "u32"),
    ("final_kind", 0x60, "u32"),
)


def object_record(capture, name, address, size):
    body = capture.read(address, size, required=False)
    if body is None:
        return {"name": name, "address": address, "size": size,
                "available": False}
    page = capture.page_record(address) or {}
    return {
        "name": name,
        "address": address,
        "size": size,
        "available": True,
        "sha256": sha256(body),
        "nonzero_bytes": sum(value != 0 for value in body),
        "translation": page.get("translation"),
        "pa": page.get("pa"),
        "resolved_via": page.get("resolved_via"),
    }


SCRATCH_REGISTERS = (
    (0x10229, "scratch_a800"),
    (0x140A8, "scratch_b000"),
    (0x10099, "scratch_1400_tag5"),
    (0x10091, "scratch_a400"),
    (0x0A5C1, "blank_state_tag5"),
    (0x0A5C9, "scratch_1000"),
)


def decode_scratch_targets(capture, regmap):
    targets = []
    pages = {}
    for number, role in SCRATCH_REGISTERS:
        raw = regmap[number][0]
        address = raw & ~0x7
        page = address & ~(PAGE - 1)
        body = capture.read(page, PAGE)
        pages.setdefault(page, body)
        offset = address - page
        targets.append({
            "register": number,
            "role": role,
            "raw": raw,
            "address": address,
            "tag": raw & 0x7,
            "page": page,
            "page_offset": offset,
            "target_64": body[offset:offset + 0x40],
            "target_64_nonzero": sum(
                value != 0 for value in body[offset:offset + 0x40]),
        })
    return targets, [
        {
            "address": page,
            "sha256": sha256(body),
            "nonzero_bytes": sum(value != 0 for value in body),
            "nonzero_qwords": nonzero_qwords(body),
            "body": body,
        }
        for page, body in sorted(pages.items())
    ]


def decode_scheduler_layout(page, state):
    records = []
    for index in range(SCHEDULER_RECORD_COUNT):
        body = page[index * 0x100:(index + 1) * 0x100]
        pointer = u64(body, 0)
        records.append({
            "index": index,
            "pointer": pointer,
            "state_delta": pointer - state if pointer else None,
            "marker": u32(body, 0x10),
            "nonzero_qwords": nonzero_qwords(body),
        })
    return records


def extract_capture(capture):
    target = capture.target
    if target["channel"] != "CL_2" or target["producer_before"] != 0:
        raise RuntimeError("%s is not a first-publication CL2 capture" % capture.label)
    if len(target["queues"]) != 1:
        raise RuntimeError("%s has %d queues" %
                           (capture.label, len(target["queues"])))

    queue_meta = target["queues"][0]
    queue_address = integer(queue_meta["queue_dva"])
    queue = capture.read(queue_address, g17p.QUEUE_RECORD_STRIDE)
    descriptor_address, optional_address, event_address = (
        integer(value) for value in queue_meta["inner_entries"][0])
    descriptor = capture.read(descriptor_address, PAGE)
    optional = capture.read(optional_address, compute.COMPUTE_OPTIONAL_SIZE)
    event = capture.read(event_address, compute.COMPUTE_EVENT_SIZE)
    registers = decode_registers(descriptor)
    regmap = register_map(registers)

    addresses = {
        "queue": queue_address,
        "queue_pointers": u64(queue, g17p.QUEUE_POINTERS_ADDR),
        "item_ring": u64(queue, g17p.QUEUE_RING_ADDR),
        "job_lists": u64(queue, g17p.QUEUE_JOB_LIST_ADDR),
        "channel_record": u64(queue, g17p.QUEUE_CONTEXT_ADDR),
        "descriptor": descriptor_address,
        "optional": optional_address,
        "event": event_address,
        "scheduler_record": u64(descriptor, 0x10),
        "queue_context_low": u64(optional, 0x08),
        "queue_context": u64(optional, 0x10),
        "shared_support": u64(descriptor, 0xFB2),
        "zero_page": u64(descriptor, 0xFCB),
        "resource": regmap[0x1A510][0],
        "cdm": regmap[0x1A420][0],
        "output": regmap[0x14070][0] & ~1,
        "dispatch_a": u64(descriptor, 0xF40),
        "dispatch_b": u64(descriptor, 0xF48),
        "status_a": u64(descriptor, 0xF7C),
        "status_b": u64(descriptor, 0xF84),
    }
    scheduler_page = addresses["scheduler_record"] & ~(PAGE - 1)
    scheduler_page_body = capture.read(scheduler_page, PAGE)
    addresses["scheduler_page"] = scheduler_page
    addresses["scheduler_state"] = u64(scheduler_page_body, 0)
    shared_support = capture.read(addresses["shared_support"], PAGE)
    addresses["support_state"] = u64(shared_support, 0x4C)
    addresses["operand_table"] = u64(shared_support, 0x30)

    object_sizes = {
        "queue": g17p.QUEUE_RECORD_STRIDE,
        "queue_pointers": 0x80,
        "item_ring": PAGE,
        "job_lists": 0x60,
        "channel_record": 0x40,
        "descriptor": PAGE,
        "optional": compute.COMPUTE_OPTIONAL_SIZE,
        "event": compute.COMPUTE_EVENT_SIZE,
        "scheduler_record": 0x100,
        "scheduler_page": PAGE,
        "scheduler_state": PAGE,
        "queue_context": PAGE,
        "shared_support": PAGE,
        "support_state": PAGE,
        "zero_page": PAGE,
        "resource": PAGE,
        "cdm": 0x30,
        "output": PAGE,
        "operand_table": PAGE,
        "dispatch_a": 8,
        "dispatch_b": 8,
        "status_a": 8,
        "status_b": 8,
    }
    objects = {
        name: object_record(capture, name, address, object_sizes[name])
        for name, address in addresses.items()
        if name in object_sizes
    }

    queue_pointers = capture.read(addresses["queue_pointers"], 0x80)
    item_ring = capture.read(addresses["item_ring"], PAGE)
    job_lists = capture.read(addresses["job_lists"], 0x60)
    channel_record = capture.read(addresses["channel_record"], 0x40)
    queue_context = capture.read(addresses["queue_context"], PAGE)
    scheduler_record = capture.read(addresses["scheduler_record"], 0x100)
    scheduler_state = capture.read(addresses["scheduler_state"], PAGE)
    resource = capture.read(addresses["resource"], PAGE)
    cdm = capture.read(addresses["cdm"], 0x30)
    scratch_targets, scratch_pages = decode_scratch_targets(capture, regmap)

    output = capture.read(addresses["output"], PAGE)
    settled = None
    settled_source = None
    settled_path = capture.path / "target_after_settled.bin"
    if settled_path.exists():
        settled = settled_path.read_bytes()
        settled_source = settled_path.name
    else:
        resample_manifest_path = capture.path / "resample_after.json"
        resample_blob_path = capture.path / "resample_after.bin"
        if resample_manifest_path.exists() and resample_blob_path.exists():
            manifest = json.loads(resample_manifest_path.read_text())
            blob = resample_blob_path.read_bytes()
            output_page = addresses["output"] & ~(PAGE - 1)
            for record in manifest["pages"]:
                if integer(record["dva"]) != output_page:
                    continue
                offset = integer(record["capture_offset"])
                settled = blob[offset:offset + PAGE]
                if len(settled) != PAGE:
                    raise RuntimeError(
                        "short output page in %s" % resample_blob_path)
                settled_source = "%s:%#x" % (
                    resample_blob_path.name, output_page)
                break
    settled_difference = None
    if settled is not None:
        settled_difference = diff_summary(output, settled)

    control_entries = decode_control_entries(target)
    control_objects = []
    for entry in control_entries:
        address = entry["first_object"]
        body = capture.read(address, PAGE, required=False)
        record = dict(entry)
        record["object_available"] = body is not None
        if body is not None:
            record["object_nonzero_bytes"] = sum(value != 0 for value in body)
            record["object_sha256"] = sha256(body)
            if u32(body, 0) in (1, 2) and u32(body, 0x10) == u32(body, 0):
                record["object_form"] = "compact"
                record["object_fields"] = field_table(
                    body, SHARED_SUPPORT_FIELDS)
            else:
                record["object_form"] = "firmware_transformed"
        control_objects.append(record)

    return {
        "label": capture.label,
        "path": str(capture.path.resolve()),
        "page_count": len(capture.pages),
        "addresses": addresses,
        "objects": objects,
        "queue_fields": g17p.parse_queue_record(queue),
        "queue": queue,
        "queue_pointer_fields": g17p.parse_queue_pointers(queue_pointers),
        "queue_pointers": queue_pointers,
        "item_ring": item_ring,
        "job_lists": job_lists,
        "channel_record": channel_record,
        "descriptor": descriptor,
        "descriptor_registers": registers,
        "optional": optional,
        "optional_fields": field_table(optional, OPTIONAL_FIELDS),
        "event": event,
        "event_records": decode_event_records(event),
        "queue_context": queue_context,
        "queue_context_fields": field_table(
            queue_context, QUEUE_CONTEXT_FIELDS),
        "scheduler_record": scheduler_record,
        "scheduler_page": scheduler_page_body,
        "scheduler_layout": decode_scheduler_layout(
            scheduler_page_body, addresses["scheduler_state"]),
        "scheduler_state": scheduler_state,
        "scheduler_nonzero_qwords": nonzero_qwords(scheduler_record),
        "shared_support": shared_support,
        "shared_support_fields": field_table(
            shared_support, SHARED_SUPPORT_FIELDS),
        "resource": resource,
        "resource_nonzero_qwords": nonzero_qwords(resource),
        "cdm": cdm,
        "scratch_targets": scratch_targets,
        "scratch_pages": scratch_pages,
        "output": output,
        "settled_output": settled,
        "settled_output_source": settled_source,
        "settled_output_difference": settled_difference,
        "control_entries": control_entries,
        "control_objects": control_objects,
    }


def build_generated():
    profile = {
        "grid_index": current.GRID,
        "queue_uuid": current.QUEUE_UUID,
        "dispatch_identity": current.DISPATCH_IDENTITY,
        "register_gate": 2,
        "submission_ordinal": current.SUBMISSION_ORDINAL,
        "optional_field_46": 2,
        "optional_field_56": 4,
        "shared_support_word_08": 2,
        "queue_context_word_220": 0xFFFF080400000001,
    }
    profile.update(current.OUTPUT_POSITIVE_FINAL_26_6_PROFILE)
    stream = compute.build_cdm_stream((
        compute.build_direct_dispatch(
            current.SHADER, grid=(64, 1, 1), threadgroup=(32, 1, 1)),
    ))
    descriptor = compute.build_compute_descriptor(
        current.compute_registers(
            profile["dispatch_identity"], profile["register_gate"]),
        scheduler_record=current.SCHEDULER,
        low_alias=current.DESCRIPTOR_LOW,
        cdm_terminator=current.CDM + len(stream) - 4,
        submit_sequence=current.SUBMIT_SEQUENCE,
        context_id=3,
        grid_index=profile["grid_index"],
        dispatch_a=current.DISPATCH_A,
        dispatch_b=current.DISPATCH_B,
        status_a=current.STATUS_A,
        status_b=current.STATUS_B,
        zero_page=current.ZERO_PAGE,
        shared_control=current.SHARED_SUPPORT,
        protection_index=1,
        support_control=0xE0A00001,
        support_flags=0,
    )
    optional = compute.build_compute_optional(
        current.QUEUE_CONTEXT_LOW, current.QUEUE_CONTEXT_HIGH,
        grid_index=profile["grid_index"],
        submission_ordinal=profile["submission_ordinal"],
        shared_control=current.SHARED_SUPPORT,
        channel_control=current.CHANNEL_CONTROL,
        uuid=profile["queue_uuid"],
        field_46=profile["optional_field_46"],
        field_1e=2, field_32=3,
        field_56=profile["optional_field_56"], field_5e=2,
    )
    queue_context = compute.build_compute_queue_context(
        current.DESCRIPTOR, current.QUEUE, profile["grid_index"],
        flags_200=0x1000000000000000,
        word_220=profile["queue_context_word_220"],
        word_330=0, word_338=8,
        word_350=current.QUEUE_CONTEXT_WORD_350,
        word_358=current.QUEUE_CONTEXT_WORD_358,
    )
    shared_support = compute.build_compute_shared_support(
        current.CLIENT_STATE, current.SUPPORT_STATE,
        word_08=profile["shared_support_word_08"],
        word_10=current.SUPPORT_WORD_10,
        header=current.SHARED_SUPPORT_HEADER,
        resource_class=0x15, cursor=0xA8, final_kind=2,
    )
    resource = compute.build_buffer_resource_table(
        (current.BUFFER_A, current.BUFFER_B, current.BUFFER_OUT),
        size=current.RESOURCE_SIZE)
    queue = g17p.build_queue_record(
        pointers_addr=current.QUEUE_POINTERS,
        ring_addr=current.ITEM_RING,
        job_list_addr=current.JOB_LIST,
        context_addr=current.CHANNEL_CONTROL,
        uuid=profile["queue_uuid"],
        priority=2,
        prio5=2,
        unk_2c=2,
        unk_38=0,
        sentinel_size=2,
    )
    queue_pointers = bytearray(0x80)
    queue_pointers[:g17p.QUEUE_PTR_BLOCK_SIZE] = g17p.build_queue_pointers()
    struct.pack_into("<I", queue_pointers, g17p.QUEUE_PTR_WRITE, 3)
    struct.pack_into("<I", queue_pointers, 0x60, 0x500)
    item_ring = bytearray(PAGE)
    struct.pack_into(
        "<3Q", item_ring, 0,
        current.DESCRIPTOR, current.OPTIONAL, current.EVENT)
    job_lists = bytearray(0x60)
    for offset in range(0, 0x60, g17p.JOB_LIST_SIZE):
        job_lists[offset:offset + g17p.JOB_LIST_SIZE] = (
            g17p.build_job_list(current.JOB_LIST + offset))
    scheduler_page = bytearray(PAGE)
    struct.pack_into("<Q", scheduler_page, 0, current.SHARED_STATE)
    scheduler_page[0x100:0x200] = (
        compute.build_compute_scheduler_record(current.SCHEDULER_SLOT))
    generated_regmap = register_map(decode_registers(descriptor))
    scratch_targets = []
    for number, role in SCRATCH_REGISTERS:
        raw = generated_regmap[number][0]
        address = raw & ~0x7
        scratch_targets.append({
            "register": number,
            "role": role,
            "raw": raw,
            "address": address,
            "tag": raw & 0x7,
            "page": address & ~(PAGE - 1),
            "page_offset": address & (PAGE - 1),
            "target_64": bytes(0x40),
            "target_64_nonzero": 0,
        })
    return {
        "profile": profile,
        "queue": queue,
        "queue_fields": g17p.parse_queue_record(queue),
        "queue_pointers": bytes(queue_pointers),
        "queue_pointer_fields": g17p.parse_queue_pointers(queue_pointers),
        "item_ring": bytes(item_ring),
        "job_lists": bytes(job_lists),
        "descriptor": descriptor,
        "descriptor_registers": decode_registers(descriptor),
        "optional": optional,
        "optional_fields": field_table(optional, OPTIONAL_FIELDS),
        "event": compute.build_compute_event(
            1, profile["grid_index"], counter_low=2),
        "event_records": decode_event_records(compute.build_compute_event(
            1, profile["grid_index"], counter_low=2)),
        "queue_context": queue_context,
        "queue_context_fields": field_table(
            queue_context, QUEUE_CONTEXT_FIELDS),
        "scheduler_record": compute.build_compute_scheduler_record(
            current.SCHEDULER_SLOT),
        "scheduler_page": bytes(scheduler_page),
        "scheduler_layout": decode_scheduler_layout(
            scheduler_page, current.SHARED_STATE),
        "scheduler_state": (
            bytes(4) + struct.pack("<I", 1) + bytes(PAGE - 8)),
        "scheduler_nonzero_qwords": nonzero_qwords(
            compute.build_compute_scheduler_record(current.SCHEDULER_SLOT)),
        "shared_support": shared_support,
        "shared_support_fields": field_table(
            shared_support, SHARED_SUPPORT_FIELDS),
        "support_state": compute.build_compute_shared_state(),
        "resource": resource,
        "resource_nonzero_qwords": nonzero_qwords(resource[:PAGE]),
        "cdm": stream,
        "scratch_targets": scratch_targets,
        "scratch_pages": [
            {
                "address": page,
                "sha256": sha256(bytes(PAGE)),
                "nonzero_bytes": 0,
                "nonzero_qwords": [],
                "body": bytes(PAGE),
            }
            for page in sorted({item["page"] for item in scratch_targets})
        ],
        "shader_sha256": sha256(current.ADD3_SHADER),
        "shader_size": len(current.ADD3_SHADER),
    }


def compare_named_fields(left, right, generated, key):
    names = sorted(set(left[key]) | set(right[key]) | set(generated[key]))
    rows = []
    for name in names:
        lvalue = left[key].get(name, {}).get("value")
        rvalue = right[key].get(name, {}).get("value")
        gvalue = generated[key].get(name, {}).get("value")
        rows.append({
            "field": name,
            "offset": (left[key].get(name) or right[key].get(name)
                       or generated[key].get(name))["offset"],
            "aug6": lvalue,
            "aug10": rvalue,
            "generated": gvalue,
            "native_stable": lvalue == rvalue,
            "generated_matches_aug10": gvalue == rvalue,
            "generated_matches_either": gvalue in (lvalue, rvalue),
        })
    return rows


def compare_scalar_dicts(left, right, generated):
    rows = []
    for name in sorted(set(left) | set(right) | set(generated)):
        rows.append({
            "field": name,
            "aug6": left.get(name),
            "aug10": right.get(name),
            "generated": generated.get(name),
        })
    return rows


POINTER_REGISTERS = {
    0x1A510: "resource",
    0x1A420: "cdm",
    0x1A4D0: "resource+0x1480",
    0x1A4D8: "resource+0x1488",
    0x1A4E0: "resource+0x1490",
    0x1A4E8: "resource+0x1498",
    0x14070: "output/robustness",
    0x10229: "scratch",
    0x140A8: "scratch",
    0x10099: "scratch-tagged",
    0x10091: "scratch",
    0x0A5C1: "blank-state-tagged",
    0x0A5C9: "scratch",
}


def compare_registers(left, right, generated):
    count = max(len(left), len(right), len(generated))
    rows = []
    for index in range(count):
        values = []
        for source in (left, right, generated):
            values.append(source[index] if index < len(source) else None)
        numbers = [entry["number"] if entry else None for entry in values]
        register = numbers[0] if numbers[0] == numbers[1] == numbers[2] else None
        row = {
            "index": index,
            "numbers": numbers,
            "register_order_matches": len(set(numbers)) == 1,
            "register": register,
            "role": POINTER_REGISTERS.get(register),
            "aug6": values[0]["value"] if values[0] else None,
            "aug10": values[1]["value"] if values[1] else None,
            "generated": values[2]["value"] if values[2] else None,
        }
        row["native_stable"] = row["aug6"] == row["aug10"]
        row["generated_matches_aug10"] = row["generated"] == row["aug10"]
        row["generated_matches_either"] = row["generated"] in (
            row["aug6"], row["aug10"])
        rows.append(row)
    return rows


def candidate(identifier, rank, area, status, observation, current_state,
              next_test=None):
    return {
        "id": identifier,
        "rank": rank,
        "area": area,
        "status": status,
        "observation": observation,
        "current_state": current_state,
        "next_test": next_test,
    }


def build_candidates(left, right, generated, comparisons, old_audit):
    constructor_exact = {
        item["name"]: item["byte_exact"]
        for item in old_audit["constructor_checks"]
    }
    return [
        candidate(
            "D00", 0, "full-width final-26.6 queue UUID",
            "ruled_out",
            "The two audited positives use UUIDs 0x172 and 0x1bd; an earlier "
            "final-26.6 positive profile uses 0x1aa. The queue carries the "
            "full 32-bit identity and the optional item duplicates its low "
            "16 bits.",
            "Generated state uses the already output-positive 0x1aa identity "
            "coherently. The 18:52 isolation also retired with that value but "
            "without a physical output mutation.",
        ),
        candidate(
            "D01", 1, "final-26.6 main-config region views and record pages",
            "ruled_out",
            "The Aug-6 main config, +0x2d0 view table, predecessor, and A/B "
            "record pages are fully captured and constructor-exact. The Aug-10 "
            "targeted capture omits the main-config page and its view closure.",
            "The 19:37 isolation installed the complete final-26.6 closure "
            "byte-exact; CL2 retired without physical output.",
        ),
        candidate(
            "D02", 2, "secondary/private-peer lifecycle shared state",
            "ruled_out",
            "Both positive captures have a mature secondary lifecycle, but "
            "the CL2 pointer closure does not name the endpoint-0x23/private "
            "peer state which caused that lifecycle.",
            "The private records contain endpoint, message and timestamp, not "
            "host pointers. Advancing the secondary lifecycle to native count "
            "36 completed both exchanges but did not produce physical output.",
        ),
        candidate(
            "D03", 3, "client resource/binding table",
            "ruled_out",
            "The first resource page is data-dependent and differs heavily "
            "between two successful native workloads. Its internal pointer "
            "roles are known for Aug-6, but the generated three-buffer table "
            "is structurally much sparser and has never led to a physical "
            "compute output mutation on G17P.",
            "The 21:07 coherent isolation substituted the native resource/CDM "
            "contract under one final-26.6 identity. CL2 retired without "
            "physical output.",
        ),
        candidate(
            "D04", 4, "CDM stream and shader contract",
            "ruled_out",
            "Both positive captures execute native CDM/shader payloads. The "
            "generated 0x30-byte direct-dispatch stream and 184-byte add3 "
            "shader are clean-room constructed but have no positive G17P "
            "execution witness.",
            "The 21:07 coherent native CDM/shader substitution retired without "
            "physical output, so this contract is not the missing gate.",
        ),
        candidate(
            "D05", 5, "scratch and robustness-page prestate",
            "ruled_out",
            "All three Aug-6 scratch pages are zero, exactly matching generated "
            "state. Final 26.6 has eight unrelated qwords at page +0x1080, "
            "outside selected offsets and absent from the Aug-6 positive.",
            "There is no native-stable nonzero scratch prestate to isolate; "
            "the tagged robustness target is the output tested in D03/D04.",
        ),
        candidate(
            "D06", 6, "scheduler page and selected slot runtime state",
            "ruled_out",
            "Both captures normalize to the same 36 pointer records and one "
            "selected state word. Generated state originally had only records "
            "0 and 1.",
            "Both captures normalize to the same 36 pointer records and one "
            "selected state word. The 21:42 hardware isolation populated "
            "records 2..35; CL2 and its channel retired without a physical "
            "output mutation.",
        ),
        candidate(
            "D07", 7, "CL2 descriptor scalar identity profile",
            "ruled_out",
            "The captures differ by 26 descriptor bytes plus coherent optional, "
            "queue-context, queue UUID, event, and shared-support scalars.",
            "The 2026-08-10 18:09 hardware run used the complete final-26.6 "
            "profile; CL2 retired 3/3/3 but output did not change.",
        ),
        candidate(
            "D08", 8, "CL2 channel-control record array",
            "ruled_out",
            "Final-26.6 has three active records followed by two empty "
            "sentinels, unlike the older capture.",
            "The 2026-08-10 17:18 run installed the exact array and still "
            "retired without physical output.",
        ),
        candidate(
            "D09", 9, "Aug-6 core queue/descriptor pointer closure",
            "ruled_out_as_missing_constructor_bytes",
            "The offline Aug-6 audit proves 38 objects, 107 pointer edges, and "
            "all audited host constructors byte-exact, including queue, "
            "descriptor, optional, event header, qctx, shared support, operand "
            "tables, aliases, and compact controls.",
            "Exactness does not rule out lifecycle state outside the audited "
            "closure, but it does rule out an omitted byte in those builders.",
        ),
        candidate(
            "D10", 10, "context-3 UAT topology and leaf permissions",
            "ruled_out",
            "A hardware run reconstructed all nine table pages, eight links, "
            "1,542 leaves, exact slot placement, and captured permissions.",
            "CL2 still retired without output; mapping coverage/topology is not "
            "the remaining gate.",
        ),
        candidate(
            "D11", 11, "dispatch/status words and blank descriptor page",
            "ruled_out",
            "Both positive captures have zero dispatch/status values before "
            "the kick and a blank descriptor zero page.",
            "The generated path initializes the same values; the Aug-6 zero "
            "page constructor check is %s." %
            ("exact" if constructor_exact.get("compute descriptor") else "recorded"),
        ),
        candidate(
            "D12", 12, "event-page historical records",
            "ruled_out",
            "Final 26.6 retains 15 older 0x40-byte event records after the "
            "current record, while the Aug-6 positive leaves the entire tail "
            "zero.",
            "Generated state matches the output-positive Aug-6 zero tail. The "
            "historical records are pooled residue, not required prestate.",
        ),
    ]


def json_ready(report):
    if isinstance(report, bytes):
        return {"length": len(report), "sha256": sha256(report),
                "hex": report.hex()}
    if isinstance(report, dict):
        return {key: json_ready(value) for key, value in report.items()}
    if isinstance(report, list):
        return [json_ready(value) for value in report]
    return report


def markdown(report):
    left = report["captures"]["aug6"]
    right = report["captures"]["aug10"]
    comparisons = report["comparisons"]
    lines = [
        "# G17P Output-Positive Compute Capture Delta Ledger",
        "",
        "This compares two captures whose settled physical target page changed. "
        "Addresses are matched by semantic role, not by allocator placement. "
        "Queue/counter retirement alone is not success.",
        "",
        "## Capture Basis",
        "",
        "| Capture | Pages | CL2 queue | Grid | UUID | Settled output witness |",
        "|---|---:|---:|---:|---:|---|",
        "| Aug-6 | %d | `%#x` | `%#x` | `%#x` | %s |" % (
            left["page_count"], left["addresses"]["queue"],
            left["optional_fields"]["grid"]["value"],
            left["queue_fields"]["uuid"],
            "8,469 changed bytes in immediate resample"),
        "| Aug-10 final 26.6 | %d | `%#x` | `%#x` | `%#x` | %s |" % (
            right["page_count"], right["addresses"]["queue"],
            right["optional_fields"]["grid"]["value"],
            right["queue_fields"]["uuid"],
            "%d changed bytes in settled reread" %
            right["settled_output_difference"]["differing_bytes"]
            if right["settled_output_difference"] is not None
            else "no settled output page available"),
        "",
        "## Ranked Delta List",
        "",
    ]
    for item in report["candidates"]:
        lines.extend([
            "### %s. %s [%s]" % (
                item["id"], item["area"], item["status"]),
            "",
            "**Observed:** %s" % item["observation"],
            "",
            "**Current path:** %s" % item["current_state"],
            "",
        ])
        if item.get("next_test"):
            lines.extend(["**Next isolation:** %s" % item["next_test"], ""])

    lines.extend([
        "## CL2 Field Deltas",
        "",
        "### Register program",
        "",
        "The register number/order is identical across both positive captures "
        "and the generated descriptor. The table lists every value that differs "
        "between either native capture or the generated path.",
        "",
        "| Index | Register | Role | Aug-6 | Aug-10 | Generated |",
        "|---:|---:|---|---:|---:|---:|",
    ])
    for row in comparisons["registers"]:
        if (row["aug6"] == row["aug10"] == row["generated"] and
                row["register_order_matches"]):
            continue
        register = row["register"]
        lines.append("| %d | %s | %s | %s | %s | %s |" % (
            row["index"], "-" if register is None else "`%#x`" % register,
            row["role"] or "scalar/unknown",
            hex_value(row["aug6"]), hex_value(row["aug10"]),
            hex_value(row["generated"])))

    for heading, key in (
            ("Optional item", "optional_fields"),
            ("Queue context", "queue_context_fields"),
            ("Shared support", "shared_support_fields")):
        lines.extend([
            "", "### %s" % heading, "",
            "| Offset | Field | Aug-6 | Aug-10 | Generated | Match Aug-10 |",
            "|---:|---|---:|---:|---:|---|",
        ])
        for row in comparisons[key]:
            lines.append("| `%#x` | %s | %s | %s | %s | %s |" % (
                row["offset"], row["field"], hex_value(row["aug6"]),
                hex_value(row["aug10"]), hex_value(row["generated"]),
                "yes" if row["generated_matches_aug10"] else "no"))

    lines.extend([
        "", "## Queue Transport Fields", "",
        "Queue object pointers differ only by allocator placement; each names "
        "the same semantic queue-pointer block, item ring, job-list head, and "
        "channel record. All scalar fields are listed, including unknowns.",
        "",
        "| Field | Aug-6 | Aug-10 | Generated |",
        "|---|---:|---:|---:|",
    ])
    for row in comparisons["queue_fields"]:
        lines.append("| %s | %s | %s | %s |" % (
            row["field"], hex_value(row["aug6"]),
            hex_value(row["aug10"]), hex_value(row["generated"])))
    lines.extend([
        "", "Queue-pointer indices are the pre-kick producer/consumer state.",
        "",
        "| Field | Aug-6 | Aug-10 | Generated |",
        "|---|---:|---:|---:|",
    ])
    for row in comparisons["queue_pointer_fields"]:
        lines.append("| %s | %s | %s | %s |" % (
            row["field"], hex_value(row["aug6"]),
            hex_value(row["aug10"]), hex_value(row["generated"])))

    lines.extend([
        "", "## Object-Level Deltas", "",
        "| Role | Aug-6 nonzero | Aug-10 nonzero | Same bytes | Note |",
        "|---|---:|---:|---|---|",
    ])
    for row in comparisons["objects"]:
        lines.append("| %s | %s | %s | %s | %s |" % (
            row["role"], row.get("aug6_nonzero", "-"),
            row.get("aug10_nonzero", "-"),
            "yes" if row.get("byte_exact") else "no",
            row.get("note", "")))

    lines.extend([
        "", "## Resource Page Qword Deltas", "",
        "The complete machine-readable list is in `audit.json`. These are all "
        "changed qwords in the first 16 KiB resource page; this deliberately "
        "includes unlabeled fields.",
        "",
        "| Offset | Aug-6 | Aug-10 |",
        "|---:|---:|---:|",
    ])
    for row in comparisons["resource_qword_deltas"]:
        lines.append("| `%#x` | `%#x` | `%#x` |" % (
            row["offset"], row["left"], row["right"]))

    lines.extend([
        "", "## Scratch Targets and Pages", "",
        "All six scratch register values and tags are identical across both "
        "positive captures and the generated descriptor. Each selected 64-byte "
        "target window is zero in both captures. The table includes every "
        "containing page so unrelated, unlabeled bytes are not omitted.",
        "",
        "| Page | Aug-6 nonzero | Aug-10 nonzero | Generated nonzero | Native exact |",
        "|---:|---:|---:|---:|---|",
    ])
    for row in comparisons["scratch_pages"]:
        lines.append("| `%#x` | %d | %d | %d | %s |" % (
            row["address"], row["aug6_nonzero"], row["aug10_nonzero"],
            row["generated_nonzero"],
            "yes" if row["aug6_aug10"]["byte_exact"] else "no"))

    lines.extend([
        "", "## Scheduler Pointer Page", "",
        "State deltas are allocation-normalized pointers. Both positive "
        "captures contain all 36 records; the generated baseline omits records "
        "2 through 35. Record 1 is selected and carries marker `0x50`.",
        "",
        "| Record | Aug-6 state delta | Aug-10 state delta | Generated state delta | Marker |",
        "|---:|---:|---:|---:|---:|",
    ])
    for row in comparisons["scheduler_layout"]:
        generated_delta = row["generated_state_delta"]
        lines.append("| %d | `%#x` | `%#x` | %s | `%#x` |" % (
            row["index"], row["aug6_state_delta"],
            row["aug10_state_delta"],
            "-" if generated_delta is None else "`%#x`" % generated_delta,
            row["aug10_marker"]))

    lines.extend([
        "", "## Event Record History", "",
        "The first 0x40-byte record is the current host publication. Later "
        "records are pooled history: Aug-6 and generated leave all 15 zero, "
        "while final 26.6 retains older records.",
        "",
        "| Record | Aug-6 nonzero | Aug-10 nonzero | Generated nonzero |",
        "|---:|---:|---:|---:|",
    ])
    for index in range(len(comparisons["event_records"]["aug6"])):
        lines.append("| %d | %d | %d | %d |" % (
            index,
            comparisons["event_records"]["aug6"][index]["nonzero_bytes"],
            comparisons["event_records"]["aug10"][index]["nonzero_bytes"],
            comparisons["event_records"]["generated"][index]["nonzero_bytes"],
        ))

    lines.extend([
        "", "## Control Histories", "",
        "| Capture | Ring index | Class | Sequence | First object | Operand | Slot | Count | Context |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for capture_name in ("aug6", "aug10"):
        for entry in report["captures"][capture_name]["control_entries"]:
            lines.append("| %s | %d | %d | `%#x` | `%#x` | `%#x` | `%#x` | `%#x` | `%#x` |" % (
                capture_name, entry["absolute_index"], entry["class"],
                entry["sequence"], entry["first_object"],
                entry["operand_table"], entry["slot"], entry["count"],
                entry["context_word"]))

    lines.extend([
        "", "## Systematic Test Order", "",
        "All capture-visible candidates D00 through D12 are exhausted. Do not "
        "revisit them unless a new output-positive capture contradicts their "
        "recorded evidence.",
        "",
        "The remaining compute gate is not an isolated field delta in this "
        "audited host-visible closure, or depends on an interaction/lifecycle "
        "input that the two pre-kick snapshots do not encode.",
        "",
    ])
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aug6", type=pathlib.Path, default=DEFAULT_AUG6)
    parser.add_argument("--aug10", type=pathlib.Path, default=DEFAULT_AUG10)
    parser.add_argument("--aug6-audit", type=pathlib.Path,
                        default=DEFAULT_AUG6_AUDIT)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main():
    args = parse_args()
    left = extract_capture(TargetCapture(args.aug6, "aug6"))
    right = extract_capture(TargetCapture(args.aug10, "aug10"))
    generated = build_generated()
    old_audit = json.loads(args.aug6_audit.read_text())

    object_rows = []
    for role in sorted(set(left["objects"]) | set(right["objects"])):
        lrecord = left["objects"].get(role, {})
        rrecord = right["objects"].get(role, {})
        row = {"role": role}
        if lrecord.get("available"):
            row["aug6_nonzero"] = lrecord["nonzero_bytes"]
        if rrecord.get("available"):
            row["aug10_nonzero"] = rrecord["nonzero_bytes"]
        if lrecord.get("available") and rrecord.get("available"):
            lbody = left.get(role)
            rbody = right.get(role)
            if isinstance(lbody, bytes) and isinstance(rbody, bytes):
                delta = diff_summary(lbody, rbody)
                row.update({
                    "byte_exact": delta["byte_exact"],
                    "differing_bytes": delta["differing_bytes"],
                })
        if role in ("resource", "cdm", "output"):
            row["note"] = "client workload data; semantic comparison required"
        elif role in ("scheduler_page", "scheduler_state", "support_state"):
            row["note"] = "shared/firmware runtime state"
        else:
            row["note"] = "role-matched object"
        object_rows.append(row)

    scratch_rows = []
    scratch_sources = []
    for source in (left, right, generated):
        scratch_sources.append({
            item["address"]: item for item in source["scratch_pages"]
        })
    for page in sorted(set().union(*(set(item) for item in scratch_sources))):
        records = [source.get(page) for source in scratch_sources]
        row = {"address": page}
        for label, record in zip(("aug6", "aug10", "generated"), records):
            row[label + "_nonzero"] = (
                None if record is None else record["nonzero_bytes"])
            row[label + "_nonzero_qwords"] = (
                [] if record is None else record["nonzero_qwords"])
        if records[0] is not None and records[1] is not None:
            row["aug6_aug10"] = diff_summary(
                records[0]["body"], records[1]["body"])
        if records[1] is not None and records[2] is not None:
            row["aug10_generated"] = diff_summary(
                records[1]["body"], records[2]["body"])
        scratch_rows.append(row)

    scheduler_rows = []
    for index in range(SCHEDULER_RECORD_COUNT):
        records = [source["scheduler_layout"][index]
                   for source in (left, right, generated)]
        scheduler_rows.append({
            "index": index,
            "aug6_state_delta": records[0]["state_delta"],
            "aug10_state_delta": records[1]["state_delta"],
            "generated_state_delta": records[2]["state_delta"],
            "aug6_marker": records[0]["marker"],
            "aug10_marker": records[1]["marker"],
            "generated_marker": records[2]["marker"],
        })

    comparisons = {
        "queue_fields": compare_scalar_dicts(
            left["queue_fields"], right["queue_fields"],
            generated["queue_fields"]),
        "queue_pointer_fields": compare_scalar_dicts(
            left["queue_pointer_fields"], right["queue_pointer_fields"],
            generated["queue_pointer_fields"]),
        "queue_aug6_aug10": diff_summary(left["queue"], right["queue"]),
        "queue_aug10_generated": diff_summary(
            right["queue"], generated["queue"]),
        "queue_pointers_aug6_aug10": diff_summary(
            left["queue_pointers"], right["queue_pointers"]),
        "queue_pointers_aug10_generated": diff_summary(
            right["queue_pointers"], generated["queue_pointers"]),
        "item_ring_aug6_aug10": diff_summary(
            left["item_ring"], right["item_ring"]),
        "item_ring_aug10_generated": diff_summary(
            right["item_ring"], generated["item_ring"]),
        "job_lists_aug6_aug10": diff_summary(
            left["job_lists"], right["job_lists"]),
        "job_lists_aug10_generated": diff_summary(
            right["job_lists"], generated["job_lists"]),
        "registers": compare_registers(
            left["descriptor_registers"], right["descriptor_registers"],
            generated["descriptor_registers"]),
        "optional_fields": compare_named_fields(
            left, right, generated, "optional_fields"),
        "queue_context_fields": compare_named_fields(
            left, right, generated, "queue_context_fields"),
        "shared_support_fields": compare_named_fields(
            left, right, generated, "shared_support_fields"),
        "descriptor_aug6_aug10": diff_summary(
            left["descriptor"], right["descriptor"]),
        "descriptor_aug10_generated": diff_summary(
            right["descriptor"], generated["descriptor"]),
        "optional_aug6_aug10": diff_summary(left["optional"], right["optional"]),
        "event_aug6_aug10": diff_summary(left["event"], right["event"]),
        "event_aug10_generated": diff_summary(
            right["event"], generated["event"]),
        "event_records": {
            "aug6": left["event_records"],
            "aug10": right["event_records"],
            "generated": generated["event_records"],
        },
        "queue_context_aug6_aug10": diff_summary(
            left["queue_context"], right["queue_context"]),
        "scheduler_record_aug6_aug10": diff_summary(
            left["scheduler_record"], right["scheduler_record"]),
        "scheduler_state_aug6_aug10": diff_summary(
            left["scheduler_state"], right["scheduler_state"]),
        "scheduler_layout": scheduler_rows,
        "shared_support_aug6_aug10": diff_summary(
            left["shared_support"], right["shared_support"]),
        "resource_aug6_aug10": diff_summary(left["resource"], right["resource"]),
        "resource_aug10_generated": diff_summary(
            right["resource"], generated["resource"][:PAGE]),
        "resource_qword_deltas": qword_deltas(
            left["resource"], right["resource"]),
        "cdm_aug6_aug10": diff_summary(left["cdm"], right["cdm"]),
        "cdm_aug10_generated": diff_summary(right["cdm"], generated["cdm"]),
        "scratch_pages": scratch_rows,
        "objects": object_rows,
    }
    report = {
        "format": "m1n1-t8140-g17p-positive-compute-delta-ledger-v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "captures": {"aug6": left, "aug10": right},
        "generated": generated,
        "comparisons": comparisons,
    }
    report["candidates"] = build_candidates(
        left, right, generated, comparisons, old_audit)

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "audit.json").write_text(
        json.dumps(json_ready(report), indent=2, sort_keys=True) + "\n")
    (args.output / "summary.md").write_text(markdown(report) + "\n")
    print("audit=%s" % (args.output / "audit.json"))
    print("summary=%s" % (args.output / "summary.md"))
    print("candidates=%d unresolved=%d" % (
        len(report["candidates"]),
        sum(item["status"] == "unresolved" for item in report["candidates"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
