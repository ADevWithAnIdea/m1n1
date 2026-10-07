#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare two bounded native partial-render owner captures offline."""

import argparse
import json
from pathlib import Path
import struct


PAGE_SIZE = 0x4000
LAYOUT = {
    "TA_2": {"descriptor_size": 0x9c0, "register_offset": 0x60},
    "3D_2": {"descriptor_size": 0x2240, "register_offset": 0xa0},
}


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def load_half(capture, half):
    directory = capture / half
    target = json.loads((directory / "target.json").read_text())
    index = json.loads((directory / "pages.json").read_text())
    blob = (directory / "pages.bin").read_bytes()
    pages = {}
    for record in index["pages"]:
        offset = int(record["capture_offset"])
        pages[int(record["dva"])] = blob[offset:offset + PAGE_SIZE]
    return target, pages


def read_pages(pages, address, size):
    result = bytearray()
    while size:
        page_dva = address & ~(PAGE_SIZE - 1)
        page = pages.get(page_dva)
        if page is None:
            raise RuntimeError("capture is missing DVA %#x" % page_dva)
        offset = address - page_dva
        count = min(size, PAGE_SIZE - offset)
        result += page[offset:offset + count]
        address += count
        size -= count
    return bytes(result)


def byte_runs(first, second):
    runs = []
    start = None
    for offset, (left, right) in enumerate(zip(first, second)):
        if left != right and start is None:
            start = offset
        if left == right and start is not None:
            runs.append({
                "offset": start,
                "size": offset - start,
                "first_hex": first[start:offset].hex(),
                "second_hex": second[start:offset].hex(),
            })
            start = None
    if start is not None:
        runs.append({
            "offset": start,
            "size": len(first) - start,
            "first_hex": first[start:].hex(),
            "second_hex": second[start:].hex(),
        })
    return runs


def registers(body, offset):
    result = []
    empty = 0
    while offset + 12 <= len(body):
        number, value = struct.unpack_from("<IQ", body, offset)
        if number == 0 and value == 0:
            empty += 1
            if empty >= 3:
                break
        else:
            empty = 0
            result.append((number, value))
        offset += 12
    return result


def register_delta(first, second):
    if len(first) != len(second):
        return {
            "first_count": len(first),
            "second_count": len(second),
            "ordered_differences": [],
        }
    differences = []
    for index, (left, right) in enumerate(zip(first, second)):
        if left != right:
            differences.append({
                "index": index,
                "first_number": left[0],
                "second_number": right[0],
                "first_value": left[1],
                "second_value": right[1],
                "value_delta": right[1] - left[1]
                    if left[0] == right[0] else None,
            })
    return {
        "first_count": len(first),
        "second_count": len(second),
        "ordered_differences": differences,
    }


def queue_summary(target):
    queue = target["queues"][0]
    return {
        "producer_before": int(target["producer_before"]),
        "producer_after": int(target["producer_after"]),
        "outer_dva": int(target["outer_dva"]),
        "queue_dva": int(queue["queue_dva"]),
        "state_dva": int(queue["state_dva"]),
        "inner_dva": int(queue["inner_dva"]),
        "third_dva": int(queue["third_dva"]),
        "queue_context_dva": int(queue["queue_context_dva"]),
        "inner_entries": queue["inner_entries"],
        "state_u32": queue["state_u32"],
    }


def numeric_delta(first, second):
    result = {}
    for key in (
        "producer_before", "producer_after", "outer_dva", "queue_dva",
        "state_dva", "inner_dva", "third_dva", "queue_context_dva",
    ):
        result[key] = second[key] - first[key]
    return result


def compare_half(first_capture, second_capture, half):
    first_target, first_pages = load_half(first_capture, half)
    second_target, second_pages = load_half(second_capture, half)
    first_queue = first_target["queues"][0]
    second_queue = second_target["queues"][0]
    first_descriptor_dva = int(first_queue["inner_entries"][0][0])
    second_descriptor_dva = int(second_queue["inner_entries"][0][0])
    size = LAYOUT[half]["descriptor_size"]
    first_descriptor = read_pages(first_pages, first_descriptor_dva, size)
    second_descriptor = read_pages(second_pages, second_descriptor_dva, size)
    first_summary = queue_summary(first_target)
    second_summary = queue_summary(second_target)
    first_queue_record = bytes.fromhex(first_queue["descriptor_hex"])
    second_queue_record = bytes.fromhex(second_queue["descriptor_hex"])
    return {
        "first": first_summary,
        "second": second_summary,
        "numeric_delta": numeric_delta(first_summary, second_summary),
        "descriptor_dva": {
            "first": first_descriptor_dva,
            "second": second_descriptor_dva,
            "delta": second_descriptor_dva - first_descriptor_dva,
        },
        "queue_record_byte_runs": byte_runs(
            first_queue_record, second_queue_record),
        "descriptor_byte_runs": byte_runs(
            first_descriptor, second_descriptor),
        "registers": register_delta(
            registers(first_descriptor, LAYOUT[half]["register_offset"]),
            registers(second_descriptor, LAYOUT[half]["register_offset"]),
        ),
    }


def main():
    args = arguments()
    first = args.first.resolve()
    second = args.second.resolve()
    report = {
        "format": "m1n1-g17p-partial-owner-diff-v1",
        "first": str(first),
        "second": str(second),
        "halves": {
            half: compare_half(first, second, half) for half in LAYOUT
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("partial-owner diff: %s" % args.output)
    for half, result in report["halves"].items():
        delta = result["numeric_delta"]
        print(
            "%s: producer %+d, outer %+x, queue %+x, qctx %+x, "
            "descriptor %+x; %d register differences, %d descriptor runs" % (
                half, delta["producer_after"], delta["outer_dva"],
                delta["queue_dva"], delta["queue_context_dva"],
                result["descriptor_dva"]["delta"],
                len(result["registers"]["ordered_differences"]),
                len(result["descriptor_byte_runs"]),
            )
        )


if __name__ == "__main__":
    main()
