#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild one captured G17P compute descriptor and require byte identity."""

import json
import pathlib
import struct
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from m1n1.agx import g17p_compute as compute  # noqa: E402


PAGE = 0x4000
CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260805_105240/CL_0"
)


def load_descriptor(capture):
    target = json.loads((capture / "target.json").read_text())
    manifest = json.loads((capture / "pages.json").read_text())
    raw = (capture / "pages.bin").read_bytes()
    pages = {}
    for record in manifest["pages"]:
        offset = int(record["capture_offset"])
        pages[int(record["dva"])] = raw[offset:offset + PAGE]
    address = int(target["queues"][0]["inner_entries"][0][0])
    body = bytearray()
    cursor = address
    while len(body) < compute.COMPUTE_DESCRIPTOR_SIZE:
        page = cursor & ~(PAGE - 1)
        if page not in pages:
            raise RuntimeError("descriptor page %#x is absent" % page)
        offset = cursor - page
        take = min(
            PAGE - offset, compute.COMPUTE_DESCRIPTOR_SIZE - len(body))
        body.extend(pages[page][offset:offset + take])
        cursor += take
    return address, bytes(body)


def decode_registers(descriptor):
    registers = []
    for index in range(compute.COMPUTE_REGISTER_CAPACITY):
        offset = compute.COMPUTE_REGISTER_START + index * compute.COMPUTE_REGISTER_SIZE
        number, value = struct.unpack_from("<IQ", descriptor, offset)
        if number == 0 and value == 0:
            break
        registers.append((number, value))
    return registers


def difference_runs(left, right):
    runs = []
    offset = 0
    while offset < len(left):
        if left[offset] == right[offset]:
            offset += 1
            continue
        end = offset + 1
        while end < len(left) and left[end] != right[end]:
            end += 1
        runs.append((offset, end, left[offset:end], right[offset:end]))
        offset = end
    return runs


def main():
    if len(sys.argv) > 2:
        raise SystemExit(
            "usage: agx_g17p_audit_compute_descriptor.py [capture/CL_N]")
    capture = pathlib.Path(sys.argv[1]) if len(sys.argv) == 2 else CAPTURE
    address, native = load_descriptor(capture)
    registers = decode_registers(native)
    generated = compute.build_compute_descriptor(
        registers,
        scheduler_record=struct.unpack_from("<Q", native, 0x10)[0],
        low_alias=struct.unpack_from("<Q", native, 0x740)[0]
        - compute.COMPUTE_REGISTER_START,
        cdm_terminator=struct.unpack_from("<Q", native, 0xEE0)[0],
        submit_sequence=struct.unpack_from("<Q", native, 0x04)[0],
        context_id=struct.unpack_from("<I", native, 0x0C)[0],
        grid_index=struct.unpack_from("<I", native, 0xF54)[0],
        dispatch_a=struct.unpack_from("<Q", native, 0xF40)[0],
        dispatch_b=struct.unpack_from("<Q", native, 0xF48)[0],
        status_a=struct.unpack_from("<Q", native, 0xF7C)[0],
        status_b=struct.unpack_from("<Q", native, 0xF84)[0],
        shared_control=struct.unpack_from("<Q", native, 0xFB2)[0],
        zero_page=struct.unpack_from("<Q", native, 0xFCB)[0],
        protection_index=struct.unpack_from("<I", native, 0xF60)[0],
        support_control=struct.unpack_from("<I", native, 0xFBA)[0],
        support_flags=struct.unpack_from("<I", native, 0xFBE)[0],
    )
    runs = difference_runs(native, generated)
    print(
        "descriptor=%#x registers=%d native_nonzero=%d generated_nonzero=%d "
        "differing_bytes=%d runs=%d"
        % (
            address,
            len(registers),
            sum(byte != 0 for byte in native),
            sum(byte != 0 for byte in generated),
            sum(end - start for start, end, _left, _right in runs),
            len(runs),
        )
    )
    for start, end, left, right in runs:
        print(
            "+%#05x..+%#05x native=%s generated=%s"
            % (start, end, left.hex(), right.hex())
        )
    return 1 if runs else 0


if __name__ == "__main__":
    raise SystemExit(main())
