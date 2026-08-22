#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare device-address dumps with a saved G17P hardware snapshot."""

import argparse
import json
import pathlib
import struct


PAGE = 0x4000


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def snapshot_pages(path):
    manifest = json.loads((path / "manifest.json").read_text())
    ram_path = path / manifest.get("ram_file", "ram.bin")
    ram = ram_path.read_bytes()
    pages = {}
    for group in manifest["root_mappings"]:
        root_context = integer(group.get("root_ctx_id", -1))
        selector = integer(group.get("selector", -1))
        for mapping in group["mappings"]:
            blob_index = mapping.get("blob_index")
            if blob_index is None:
                continue
            address = integer(mapping["va"])
            key = (root_context, selector, address)
            offset = integer(blob_index) * PAGE
            pages[key] = ram[offset:offset + PAGE]
    return pages


def snapshot_read(pages, address, size):
    # Firmware graph addresses use context 64's upper root. Descriptor and
    # queue-context low aliases are host objects in context 0; context 1 is the
    # render address space and is only the fallback for other low addresses.
    roots = ((64, 1), (0, 0), (1, 0)) if address >= (1 << 63) else (
        (0, 0), (1, 0), (64, 1))
    output = bytearray()
    offset = 0
    while offset < size:
        current = address + offset
        page = current & ~(PAGE - 1)
        page_offset = current - page
        length = min(PAGE - page_offset, size - offset)
        body = None
        for root_context, selector in roots:
            body = pages.get((root_context, selector, page))
            if body is not None:
                break
        if body is None:
            return None, page
        output += body[page_offset:page_offset + length]
        offset += length
    return bytes(output), None


def differing_runs(want, got):
    runs = []
    index = 0
    while index < len(want):
        if want[index] == got[index]:
            index += 1
            continue
        end = index + 1
        while end < len(want) and want[end] != got[end]:
            end += 1
        runs.append((index, end))
        index = end
    return runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=pathlib.Path)
    parser.add_argument("dump", type=pathlib.Path)
    parser.add_argument("--max-runs", type=int, default=24)
    args = parser.parse_args()

    pages = snapshot_pages(args.snapshot)
    for path in sorted(args.dump.glob("*.bin")):
        address = int(path.stem, 16)
        got = path.read_bytes()
        want, missing = snapshot_read(pages, address, len(got))
        if want is None:
            print("%#018x len %#x: native page %#x unavailable" %
                  (address, len(got), missing))
            continue
        runs = differing_runs(want, got)
        total = sum(end - start for start, end in runs)
        print("%#018x len %#x: %d differing bytes in %d runs" %
              (address, len(got), total, len(runs)))
        for start, end in runs[:args.max_runs]:
            qword = start & ~7
            native_qword = struct.unpack_from("<Q", want, qword)[0]
            live_qword = struct.unpack_from("<Q", got, qword)[0]
            print("  +%#06x..+%#06x native=%s live=%s qword %#018x -> %#018x" %
                  (start, end, want[start:end].hex(), got[start:end].hex(),
                   native_qword, live_qword))
        if len(runs) > args.max_runs:
            print("  ... %d more runs" % (len(runs) - args.max_runs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
