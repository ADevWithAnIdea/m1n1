#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Correlate native G17P compute register programs and CDM records."""

import argparse
import json
import pathlib
import struct


PAGE = 0x4000
DESCRIPTOR_DECODE_SIZE = 0x1000
REGISTER_START = 0x40
REGISTER_SIZE = 0x0C
REGISTER_CAPACITY = 128
CDM_RECORD_SIZE = 0x2C


def load_capture(path):
    target = json.loads((path / "target.json").read_text())
    manifest = json.loads((path / "pages.json").read_text())
    raw = (path / "pages.bin").read_bytes()
    pages = {}
    for record in manifest["pages"]:
        address = int(record["dva"])
        offset = int(record["capture_offset"])
        body = raw[offset:offset + PAGE]
        if len(body) != PAGE:
            raise ValueError("truncated page %#x in %s" % (address, path))
        pages[address] = body
    return target, pages


def read_dva(pages, address, size):
    result = bytearray()
    while size:
        page = address & ~(PAGE - 1)
        offset = address - page
        body = pages.get(page)
        if body is None:
            raise KeyError("unmapped captured DVA %#x" % address)
        take = min(size, PAGE - offset)
        result.extend(body[offset:offset + take])
        address += take
        size -= take
    return bytes(result)


def register_program(descriptor):
    registers = []
    for index in range(REGISTER_CAPACITY):
        offset = REGISTER_START + index * REGISTER_SIZE
        number, value = struct.unpack_from("<IQ", descriptor, offset)
        if number == 0 and value == 0:
            break
        registers.append((number, value))
    return registers


def first_value(registers, number):
    for candidate, value in registers:
        if candidate == number:
            return value
    raise KeyError("register %#x is absent" % number)


def decode_item(path, target, pages, queue_index, inner_index, inner_entry):
    descriptor_address = int(inner_entry[0])
    descriptor = read_dva(pages, descriptor_address, DESCRIPTOR_DECODE_SIZE)
    if struct.unpack_from("<I", descriptor, 0)[0] != 3:
        raise ValueError("CL item at %#x is not compute" % descriptor_address)
    registers = register_program(descriptor)
    cdm = first_value(registers, 0x1A420)
    resource = first_value(registers, 0x1A510)
    terminator = struct.unpack_from("<Q", descriptor, 0xEE0)[0]
    if terminator < cdm or (terminator - cdm) % CDM_RECORD_SIZE:
        raise ValueError("invalid CDM extent %#x..%#x" % (cdm, terminator))
    record_count = (terminator - cdm) // CDM_RECORD_SIZE
    stream = read_dva(pages, cdm, record_count * CDM_RECORD_SIZE + 4)
    if struct.unpack_from("<I", stream, record_count * CDM_RECORD_SIZE)[0] != 0x40000000:
        raise ValueError("CDM stream at %#x has no terminator" % cdm)
    records = []
    for index in range(record_count):
        values = struct.unpack_from("<IIQ3I3II", stream, index * CDM_RECORD_SIZE)
        records.append(values)
    return {
        "path": path,
        "captured": target.get("captured_utc", "?"),
        "queue_index": queue_index,
        "inner_index": inner_index,
        "inner_entry": tuple(int(value) for value in inner_entry),
        "descriptor": descriptor_address,
        "resource": resource,
        "cdm": cdm,
        "registers": registers,
        "records": records,
    }


def decode_capture(path):
    target, pages = load_capture(path)
    decoded = []
    errors = []
    for queue_index, queue in enumerate(target["queues"]):
        for inner_index, inner_entry in enumerate(queue["inner_entries"]):
            if not inner_entry or not int(inner_entry[0]):
                continue
            try:
                decoded.append(decode_item(
                    path, target, pages, queue_index, inner_index, inner_entry))
            except (KeyError, ValueError, IndexError) as error:
                errors.append((queue_index, inner_index, error))
    return decoded, errors


def format_values(values):
    return ", ".join("%#x" % value for value in sorted(values))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    decoded = []
    for capture in args.captures:
        try:
            items, errors = decode_capture(capture)
            decoded.extend(items)
            for queue_index, inner_index, error in errors:
                print("SKIP %s q%d/i%d: %s" % (
                    capture, queue_index, inner_index, error))
        except (KeyError, ValueError, IndexError) as error:
            print("SKIP %s: %s" % (capture, error))

    print("decoded items: %d" % len(decoded))
    for item in decoded:
        configs = {record[0] for record in item["records"]}
        constants = {record[1] for record in item["records"]}
        tails = {record[-1] for record in item["records"]}
        print(
            "%s q%d/i%d desc=%#x resource=%#x cdm=%#x records=%d "
            "config={%s} word1={%s} tail={%s}" % (
                item["path"].parent.name, item["queue_index"],
                item["inner_index"],
                item["descriptor"], item["resource"], item["cdm"],
                len(item["records"]), format_values(configs),
                format_values(constants), format_values(tails),
            )
        )

    programs = {}
    for item in decoded:
        for ordinal, (number, value) in enumerate(item["registers"]):
            programs.setdefault((ordinal, number), set()).add(value)
    print("\nordered register fields that vary:")
    varying = 0
    for (ordinal, number), values in sorted(programs.items()):
        if len(values) < 2:
            continue
        varying += 1
        print("  [%02d] reg=%#07x values={%s}" % (
            ordinal, number, format_values(values)))
    if not varying:
        print("  none")

    print("\ninvariant ordered register program:")
    if decoded:
        baseline = decoded[0]["registers"]
        for ordinal, (number, value) in enumerate(baseline):
            values = programs[(ordinal, number)]
            if len(values) == 1:
                print("  [%02d] reg=%#07x value=%#x" % (
                    ordinal, number, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
