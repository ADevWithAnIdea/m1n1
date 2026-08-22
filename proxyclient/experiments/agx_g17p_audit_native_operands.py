#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the context-3 operand table in a full clean-room GPU snapshot."""

import argparse
import hashlib
import json
import pathlib
import struct


PAGE = 0x4000
TABLE_DVA = 0x7000208000
TABLE_STRIDE = 0x40
BUFFER_FLAG = 0x1000000000000000
BUFFER_SIZE = 0x100000


def root_mappings(manifest, context):
    roots = [
        root for root in manifest["root_mappings"]
        if int(root["root_ctx_id"]) == context
        and int(root["selector"]) == 0
    ]
    if len(roots) != 1:
        raise RuntimeError(
            "context %d has %d selector-0 roots" %
            (context, len(roots)))
    return roots[0], {
        int(mapping["va"]): mapping
        for mapping in roots[0]["mappings"]
    }


def report_ranges(ram, mappings, comparison):
    ordered = [mappings[address] for address in sorted(mappings)]
    ranges = []
    current = []
    for mapping in ordered:
        address = int(mapping["va"])
        if current and address != int(current[-1]["va"]) + PAGE:
            ranges.append(current)
            current = []
        current.append(mapping)
    if current:
        ranges.append(current)

    print("context_ranges=%d mapped_pages=%d" % (len(ranges), len(ordered)))
    for index, records in enumerate(ranges):
        start = int(records[0]["va"])
        end = int(records[-1]["va"]) + PAGE
        nonzero_pages = 0
        nonzero_bytes = 0
        ptes = set()
        aliases = 0
        equal_contents = 0
        for mapping in records:
            blob_index = int(mapping["blob_index"])
            body = ram[blob_index * PAGE:(blob_index + 1) * PAGE]
            count = sum(byte != 0 for byte in body)
            nonzero_pages += bool(count)
            nonzero_bytes += count
            ptes.add(int(mapping["pte"]) & 0xFF00000000000FFF)
            other = comparison.get(int(mapping["va"]))
            aliases += bool(
                other is not None
                and int(other["pa"]) == int(mapping["pa"])
            )
            if other is not None:
                other_index = int(other["blob_index"])
                other_body = ram[
                    other_index * PAGE:(other_index + 1) * PAGE]
                equal_contents += body == other_body
        print(
            "range[%02d] dva=%#x..%#x length=%#x pages=%d "
            "nonzero_pages=%d nonzero_bytes=%d ptes=%s "
            "same_dva_context1_pa=%d/%d same_dva_context1_bytes=%d/%d" % (
                index, start, end, end - start, len(records),
                nonzero_pages, nonzero_bytes,
                ",".join("%#x" % pte for pte in sorted(ptes)),
                aliases, len(records), equal_contents, len(records)))


def report_low_pointer_records(ram, mappings):
    """Describe pointer arrays in the context-3 low configuration region."""
    records = []
    for address in sorted(mappings):
        if not 0x7000000000 <= address < 0x8000000000:
            continue
        mapping = mappings[address]
        blob_index = int(mapping["blob_index"])
        body = ram[blob_index * PAGE:(blob_index + 1) * PAGE]
        if not any(body):
            continue
        pointers = []
        scalars = []
        for offset in range(0, PAGE, 8):
            value = struct.unpack_from("<Q", body, offset)[0]
            if not value:
                continue
            target = value & ((1 << 60) - 1)
            if (target & ~(PAGE - 1)) in mappings:
                pointers.append((offset, value, target))
            else:
                scalars.append((offset, value))
        records.append((address, body, pointers, scalars))

    print("low_nonzero_pages=%d" % len(records))
    for address, body, pointers, scalars in records:
        print(
            "low_page=%#x nonzero_bytes=%d pointer_qwords=%d scalar_qwords=%d" %
            (address, sum(byte != 0 for byte in body),
             len(pointers), len(scalars)))
        runs = []
        start = previous = None
        delta = None
        for record in pointers:
            if previous is None:
                start = previous = record
                continue
            candidate_delta = (
                record[0] - previous[0], record[2] - previous[2])
            if delta is None:
                delta = candidate_delta
                previous = record
                continue
            if candidate_delta == delta:
                previous = record
                continue
            runs.append((start, previous, delta))
            start = previous = record
            delta = None
        if previous is not None:
            runs.append((start, previous, delta))
        for first, last, step in runs:
            count = ((last[0] - first[0]) // (step[0] if step else 1) + 1
                     if step else 1)
            print(
                "  pointer_run source=+%#x..+%#x count=%d "
                "target=%#x..%#x step=%s tag=%#x" % (
                    first[0], last[0] + 8, count,
                    first[2], last[2],
                    "%#x/%#x" % step if step else "single",
                    first[1] & ~((1 << 60) - 1)))
        if scalars:
            print(
                "  scalars=%s" % ", ".join(
                    "+%#x=%#x" % item for item in scalars[:32]))
            if len(scalars) > 32:
                print("  scalars_omitted=%d" % (len(scalars) - 32))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "capture", type=pathlib.Path,
        nargs="?",
        default=pathlib.Path(
            "/Users/user/asahi_re/artifacts/agx_g17p/"
            "native_t256_write_full_20260806_085603"),
    )
    parser.add_argument("--context", type=int, default=3)
    args = parser.parse_args()

    manifest = json.loads((args.capture / "manifest.json").read_text())
    ram = (args.capture / manifest["ram_file"]).read_bytes()
    root, mappings = root_mappings(manifest, args.context)
    _context1_root, context1 = root_mappings(manifest, 1)
    report_ranges(ram, mappings, context1)
    report_low_pointer_records(ram, mappings)

    def page(address):
        page_address = int(address) & ~(PAGE - 1)
        mapping = mappings.get(page_address)
        if mapping is None:
            raise RuntimeError("unmapped context-%d DVA %#x" % (
                args.context, page_address))
        index = int(mapping["blob_index"])
        body = ram[index * PAGE:(index + 1) * PAGE]
        if len(body) != PAGE:
            raise RuntimeError("short blob %d" % index)
        return mapping, body

    table_mapping, table = page(TABLE_DVA)
    entries = []
    for offset in range(0, PAGE, TABLE_STRIDE):
        tagged = struct.unpack_from("<Q", table, offset)[0]
        if tagged == 0:
            break
        if not tagged & BUFFER_FLAG:
            raise RuntimeError(
                "entry %d lacks operand tag: %#x" %
                (offset // TABLE_STRIDE, tagged))
        entries.append(tagged & ~BUFFER_FLAG)

    print(
        "context=%d root=%#x table=%#x pa=%#x pte=%#x entries=%d" % (
            args.context, int(root["root_pa"]), TABLE_DVA,
            int(table_mapping["pa"]), int(table_mapping["pte"]),
            len(entries)))
    print(
        "table_nonzero=%d table_sha256=%s zero_tail=%s" % (
            sum(byte != 0 for byte in table),
            hashlib.sha256(table).hexdigest(),
            "yes" if not any(table[len(entries) * TABLE_STRIDE:]) else "no"))

    for index, base in enumerate(entries):
        nonzero_pages = []
        nonzero_bytes = 0
        ptes = set()
        pas = []
        digest = hashlib.sha256()
        for offset in range(0, BUFFER_SIZE, PAGE):
            mapping, body = page(base + offset)
            pas.append(int(mapping["pa"]))
            ptes.add(int(mapping["pte"]) & 0xFF00000000000FFF)
            count = sum(byte != 0 for byte in body)
            if count:
                nonzero_pages.append((offset, count))
                nonzero_bytes += count
            digest.update(body)
        physically_contiguous = all(
            right == left + PAGE
            for left, right in zip(pas, pas[1:]))
        page_summary = ",".join(
            "%#x:%d" % item for item in nonzero_pages[:8]) or "none"
        if len(nonzero_pages) > 8:
            page_summary += ",..."
        print(
            "entry[%02d] base=%#x length=%#x pages=%d "
            "nonzero_pages=%d nonzero_bytes=%d ptes=%s contiguous_pa=%s "
            "sha256=%s nonzero=%s" % (
                index, base, BUFFER_SIZE, BUFFER_SIZE // PAGE,
                len(nonzero_pages), nonzero_bytes,
                ",".join("%#x" % pte for pte in sorted(ptes)),
                "yes" if physically_contiguous else "no",
                digest.hexdigest(), page_summary))


if __name__ == "__main__":
    main()
