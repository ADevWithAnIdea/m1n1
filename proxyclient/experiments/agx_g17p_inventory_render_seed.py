#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory capture-derived G17P render pages and their changing fields.

This is an offline clean-room tool. It reads host-visible UAT snapshots only;
it does not inspect firmware or any other Apple binary.
"""

import argparse
import collections
import json
import pathlib
import struct


PAGE = 0x4000
DEFAULT_ROOT = 7
DEFAULT_SNAPSHOTS = (
    "pre_work_0x83_v2_20260724_193713",
    "second_0x83_20260729_032917",
    "third_0x83_20260802_160229",
    "fourth_0x83_20260803_024355",
    "sixth_0x83_20260729_034810",
)

# Pages whose initial contents the live builder already generates or explicitly
# defines as zero. Everything else nonzero in the render root is render-extra.
MODELED_PAGES = {
    0x1000000000,
    0x1000018000,
    0x1000048000,
    0x1000058000,
    0x1000068000,
    0x1000078000,
    0x10001990000,
    0x100019A0000,
    0x10001A8000,
    0x10001AA8000,
    0x10001AF8000,
    0x10001B0000,
    0x10001B4000,
    0x1000240000,
    0x1000008000,
    0x100000C000,
    0x100002C000,
    0x1000080000,
    0x1000100000,
    0x1000140000,
    0x1000178000,
    0x1000300000,
    0x1000504000,
}


def canonicalize(value, shift):
    if value & (1 << (shift - 1)):
        value |= ~((1 << shift) - 1)
    return value & 0xFFFFFFFFFFFFFFFF


class Snapshot:
    def __init__(self, path, root):
        self.path = path
        manifest = json.loads((path / "manifest.json").read_text())
        ram = (path / manifest["ram_file"]).read_bytes()
        shift = int(manifest["vaddr_shift"])
        self.pages = {}
        self.all_mapped = set()
        for group in manifest["root_mappings"]:
            for mapping in group["mappings"]:
                va = canonicalize(int(mapping["va"]), shift)
                self.all_mapped.add(va)
                if int(group["root_index"]) != root:
                    continue
                blob = mapping.get("blob_index")
                if blob is None:
                    continue
                start = int(blob) * PAGE
                self.pages[va] = ram[start:start + PAGE]


def nonzero_span(body):
    indices = [index for index, byte in enumerate(body) if byte]
    return (indices[0], indices[-1] + 1) if indices else (0, 0)


def runs(addresses):
    addresses = sorted(addresses)
    if not addresses:
        return []
    output = []
    begin = previous = addresses[0]
    for address in addresses[1:]:
        if address != previous + PAGE:
            output.append((begin, previous + PAGE))
            begin = address
        previous = address
    output.append((begin, previous + PAGE))
    return output


def pointer_candidates(body, mapped):
    found = []
    for offset in range(0, PAGE, 8):
        value = struct.unpack_from("<Q", body, offset)[0]
        page = value & ~(PAGE - 1)
        if value and page in mapped:
            found.append((offset, value))
    return found


def changing_words(address, snapshots, width):
    present = [(snapshot.path.name, snapshot.pages.get(address))
               for snapshot in snapshots]
    present = [(name, body) for name, body in present if body is not None]
    if len(present) < 2:
        return []
    unpack = "<I" if width == 4 else "<Q"
    output = []
    for offset in range(0, PAGE, width):
        values = [struct.unpack_from(unpack, body, offset)[0]
                  for _name, body in present]
        if len(set(values)) == 1:
            continue
        monotonic = all(a <= b for a, b in zip(values, values[1:]))
        output.append({
            "offset": offset,
            "values": values,
            "snapshots": [name for name, _body in present],
            "monotonic": monotonic,
        })
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts", type=pathlib.Path,
        default=pathlib.Path("~/asahi_re/artifacts/agx_g17p").expanduser())
    parser.add_argument("--root", type=int, default=DEFAULT_ROOT)
    parser.add_argument("--snapshot", action="append", default=[])
    parser.add_argument("--json", type=pathlib.Path)
    args = parser.parse_args()

    names = args.snapshot or list(DEFAULT_SNAPSHOTS)
    snapshots = [Snapshot(args.artifacts / name, args.root) for name in names]
    baseline = snapshots[0]
    seeded = {
        address: body for address, body in baseline.pages.items()
        if address not in MODELED_PAGES and any(body)
    }
    mapped = set().union(*(snapshot.all_mapped for snapshot in snapshots))

    records = []
    for address, body in sorted(seeded.items()):
        first, end = nonzero_span(body)
        pointers = pointer_candidates(body, mapped)
        changes32 = changing_words(address, snapshots, 4)
        changes64 = changing_words(address, snapshots, 8)
        records.append({
            "address": address,
            "nonzero": sum(bool(byte) for byte in body),
            "first_nonzero": first,
            "last_nonzero": end,
            "pointer_candidates": [
                {"offset": offset, "value": value}
                for offset, value in pointers
            ],
            "changing_u32": changes32,
            "changing_u64": changes64,
        })

    print("baseline %s root %d" % (baseline.path.name, args.root))
    print("%d capture-derived render-extra pages, %d non-zero bytes" % (
        len(records), sum(record["nonzero"] for record in records)))
    print("%d contiguous runs" % len(runs(seeded)))
    for begin, end in runs(seeded):
        members = [record for record in records
                   if begin <= record["address"] < end]
        print("  %#014x-%#014x  %3d pages  %6d non-zero  %3d pointers  "
              "%4d changing u32" % (
                  begin, end, len(members),
                  sum(record["nonzero"] for record in members),
                  sum(len(record["pointer_candidates"]) for record in members),
                  sum(len(record["changing_u32"]) for record in members)))

    print("\npages with pointers or changing aligned words")
    for record in records:
        pointers = record["pointer_candidates"]
        changes = record["changing_u32"]
        if not pointers and not changes:
            continue
        monotonic = sum(change["monotonic"] for change in changes)
        print("  %#014x  nz=%-5d span=+%#05x..+%#05x  ptr=%-3d "
              "change32=%-4d monotonic=%d" % (
                  record["address"], record["nonzero"],
                  record["first_nonzero"], record["last_nonzero"],
                  len(pointers), len(changes), monotonic))
        for pointer in pointers[:12]:
            print("      pointer +%#06x -> %#018x" % (
                pointer["offset"], pointer["value"]))
        for change in [item for item in changes if item["monotonic"]][:12]:
            print("      monotonic u32 +%#06x: %s" % (
                change["offset"], " ".join("%#x" % value
                                             for value in change["values"])))

    if args.json:
        output = {
            "format": "m1n1-g17p-render-seed-inventory-v1",
            "snapshots": [snapshot.path.name for snapshot in snapshots],
            "root": args.root,
            "page_size": PAGE,
            "pages": records,
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(output, indent=2) + "\n")
        print("\nwrote %s" % args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
