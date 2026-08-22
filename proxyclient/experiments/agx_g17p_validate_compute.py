#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate generated G17P compute objects against targeted hardware captures."""

import argparse
import json
import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.agx import g17p_compute as compute  # noqa: E402


PAGE_SIZE = 0x4000


class Capture:
    def __init__(self, path):
        self.path = path.resolve()
        self.target = json.loads((self.path / "target.json").read_text())
        manifest = json.loads((self.path / "pages.json").read_text())
        self.raw = (self.path / "pages.bin").read_bytes()
        self.pages = {int(page["dva"]): page for page in manifest["pages"]}

    def read(self, address, size):
        out = bytearray()
        while size:
            page_address = address & ~(PAGE_SIZE - 1)
            page = self.pages.get(page_address)
            if page is None:
                raise ValueError("capture has no page for %#x" % address)
            offset = address - page_address
            take = min(size, PAGE_SIZE - offset)
            start = int(page["capture_offset"]) + offset
            out.extend(self.raw[start:start + take])
            address += take
            size -= take
        return bytes(out)


def register_array(body):
    result = []
    for index in range(compute.COMPUTE_REGISTER_CAPACITY):
        offset = compute.COMPUTE_REGISTER_START + index * compute.COMPUTE_REGISTER_SIZE
        number, value = struct.unpack_from("<IQ", body, offset)
        if number == 0:
            break
        result.append((number, value))
    return result


def first_difference(expected, actual):
    for offset, (left, right) in enumerate(zip(expected, actual)):
        if left != right:
            return offset, left, right
    if len(expected) != len(actual):
        return min(len(expected), len(actual)), None, None
    return None


def require_equal(label, expected, actual):
    difference = first_difference(expected, actual)
    if difference is None:
        print("PASS %-24s %#x bytes" % (label, len(expected)))
        return
    offset, left, right = difference
    raise AssertionError(
        "%s differs at +%#x: generated=%s captured=%s" %
        (label, offset,
         "end" if left is None else "%#04x" % left,
         "end" if right is None else "%#04x" % right)
    )


def validate(path):
    capture = Capture(path)
    queue = capture.target["queues"][0]
    descriptor_address, optional_address, event_address = queue["inner_entries"][0]
    descriptor = capture.read(descriptor_address, compute.COMPUTE_DESCRIPTOR_SIZE)
    optional = capture.read(optional_address, compute.COMPUTE_OPTIONAL_SIZE)
    event = capture.read(event_address, 0x40)
    registers = register_array(descriptor)
    if len(registers) != 36:
        raise AssertionError("native descriptor has %d registers, expected 36" %
                             len(registers))

    generated_descriptor = compute.build_compute_descriptor(
        registers,
        scheduler_record=struct.unpack_from("<Q", descriptor, 0x10)[0],
        low_alias=struct.unpack_from("<Q", descriptor, 0x740)[0] - 0x40,
        cdm_terminator=struct.unpack_from("<Q", descriptor, 0xEE0)[0],
        submit_sequence=struct.unpack_from("<Q", descriptor, 0x04)[0],
        context_id=struct.unpack_from("<I", descriptor, 0x0C)[0],
        grid_index=struct.unpack_from("<I", descriptor, 0xF54)[0],
        dispatch_a=struct.unpack_from("<Q", descriptor, 0xF40)[0],
        dispatch_b=struct.unpack_from("<Q", descriptor, 0xF48)[0],
        status_a=struct.unpack_from("<Q", descriptor, 0xF7C)[0],
        status_b=struct.unpack_from("<Q", descriptor, 0xF84)[0],
        shared_control=struct.unpack_from("<Q", descriptor, 0xFB2)[0],
        zero_page=struct.unpack_from("<Q", descriptor, 0xFCB)[0],
        protection_index=struct.unpack_from("<I", descriptor, 0xF60)[0],
        support_control=struct.unpack_from("<I", descriptor, 0xFBA)[0],
        support_flags=struct.unpack_from("<I", descriptor, 0xFBE)[0],
    )
    require_equal("compute descriptor", generated_descriptor, descriptor)

    scheduler_address = struct.unpack_from("<Q", descriptor, 0x10)[0]
    scheduler = capture.read(scheduler_address, 0x100)
    node = struct.unpack_from("<Q", scheduler, 0xA8)[0] & 0x00FFFFFF
    generated_scheduler = compute.build_compute_scheduler_record(
        slot_addr=struct.unpack_from("<Q", scheduler, 0x00)[0],
        work_id=struct.unpack_from("<I", scheduler, 0x08)[0],
        phase=struct.unpack_from("<I", scheduler, 0x0C)[0],
        job_list=struct.unpack_from("<Q", scheduler, 0xA0)[0],
        node_id=node,
    )
    require_equal("compute scheduler", generated_scheduler, scheduler)

    generated_optional = compute.build_compute_optional(
        context_low=struct.unpack_from("<Q", optional, 0x08)[0],
        context_high=struct.unpack_from("<Q", optional, 0x10)[0],
        grid_index=struct.unpack_from("<H", optional, 0x18)[0],
        submission_ordinal=struct.unpack_from("<H", optional, 0x3E)[0],
        shared_control=struct.unpack_from("<Q", optional, 0x36)[0],
        channel_control=struct.unpack_from("<Q", optional, 0x4A)[0],
        uuid=struct.unpack_from("<H", optional, 0x5A)[0],
        field_46=struct.unpack_from("<H", optional, 0x46)[0],
        field_1e=struct.unpack_from("<H", optional, 0x1E)[0],
        field_32=struct.unpack_from("<H", optional, 0x32)[0],
        field_56=struct.unpack_from("<H", optional, 0x56)[0],
        field_5e=struct.unpack_from("<H", optional, 0x5E)[0],
    )
    require_equal("compute optional", generated_optional, optional)

    group_number = struct.unpack_from("<I", event, 0x08)[0] >> 8
    grid_index = struct.unpack_from("<I", event, 0x04)[0] & 0xFFFF
    generated_event = compute.build_compute_event(
        group_number, grid_index,
        counter_low=struct.unpack_from("<I", event, 0x08)[0] & 0xFF,
    )[:0x40]
    require_equal("compute event", generated_event, event)

    context_high = struct.unpack_from("<Q", optional, 0x10)[0]
    context_page = capture.read(context_high, compute.COMPUTE_QUEUE_CONTEXT_SIZE)
    generated_context = compute.build_compute_queue_context(
        descriptor_address,
        queue["queue_dva"],
        grid_index=grid_index,
        flags_200=struct.unpack_from("<Q", context_page, 0x200)[0]
        & ~(((grid_index * 4) << 40) | 4),
        word_220=struct.unpack_from("<Q", context_page, 0x220)[0],
        word_330=struct.unpack_from("<Q", context_page, 0x330)[0],
        word_338=struct.unpack_from("<Q", context_page, 0x338)[0],
        word_350=struct.unpack_from("<Q", context_page, 0x350)[0],
        word_358=struct.unpack_from("<Q", context_page, 0x358)[0],
        word_378=struct.unpack_from("<Q", context_page, 0x378)[0],
    )
    require_equal("compute queue context", generated_context, context_page)

    shared_control = struct.unpack_from("<Q", descriptor, 0xFB2)[0]
    try:
        shared = capture.read(
            shared_control, compute.COMPUTE_SHARED_SUPPORT_SIZE)
    except ValueError:
        print("SKIP compute shared support: page was not captured")
    else:
        generated_shared = compute.build_compute_shared_support(
            client_state=struct.unpack_from("<Q", shared, 0x30)[0],
            firmware_state=struct.unpack_from("<Q", shared, 0x4C)[0],
            word_08=struct.unpack_from("<Q", shared, 0x08)[0],
            word_10=struct.unpack_from("<Q", shared, 0x10)[0],
            header=struct.unpack_from("<Q", shared, 0x00)[0],
            resource_class=struct.unpack_from("<Q", shared, 0x20)[0] >> 40,
            cursor=struct.unpack_from("<I", shared, 0x48)[0],
            field_5c=struct.unpack_from("<I", shared, 0x5C)[0],
            final_kind=struct.unpack_from("<I", shared, 0x60)[0],
        )
        require_equal("compute shared support", generated_shared, shared)

    cdm_base = next(value for number, value in registers if number == 0x1A420)
    cdm_terminator = struct.unpack_from("<Q", descriptor, 0xEE0)[0]
    if (cdm_base & ~(PAGE_SIZE - 1)) not in capture.pages:
        print("SKIP CDM stream: client page was not captured")
        print("PASS %s" % capture.path)
        return
    cdm_span = cdm_terminator - cdm_base
    if cdm_span < compute.CDM_RECORD_SIZE or cdm_span % compute.CDM_RECORD_SIZE:
        raise AssertionError("native CDM terminator does not follow whole records")
    for index in range(cdm_span // compute.CDM_RECORD_SIZE):
        address = cdm_base + index * compute.CDM_RECORD_SIZE
        record = capture.read(address, compute.CDM_RECORD_SIZE)
        (config, constant, shader_low, shader_control,
         grid_x, grid_y, grid_z, group_x, group_y, group_z,
         tail) = struct.unpack("<11I", record)
        shader_va = ((shader_control & 0x3FFFFFFF) << 40) | (shader_low << 6)
        generated_record = compute.build_direct_dispatch(
            shader_va,
            grid=(grid_x, grid_y, grid_z),
            threadgroup=(group_x, group_y, group_z),
            config=config,
            constant=constant,
            tail=tail,
        )
        require_equal("CDM record %d" % index, generated_record, record)
    terminator = capture.read(cdm_terminator, 4)
    require_equal("CDM terminator", struct.pack("<I", compute.CDM_TERMINATOR),
                  terminator)
    print("PASS %s" % capture.path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    for path in args.capture:
        validate(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
