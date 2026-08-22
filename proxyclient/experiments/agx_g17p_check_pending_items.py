#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the pending item records in a targeted G17P capture."""

import json
import pathlib
import struct
import sys

from agx_g17p_queue import item_record_size, pending_entry_span

PAGE_SIZE = 0x4000


def load_half(directory, half):
    root = pathlib.Path(directory) / half
    target = json.loads((root / "target.json").read_text())
    manifest = json.loads((root / "pages.json").read_text())
    blob = (root / "pages.bin").read_bytes()
    pages = {
        int(record["dva"]): blob[
            int(record["capture_offset"]):
            int(record["capture_offset"]) + int(manifest["page_size"])
        ]
        for record in manifest["pages"]
    }

    def read(dva, count):
        out = bytearray()
        while count:
            page = pages.get(dva & ~(PAGE_SIZE - 1))
            if page is None:
                return None
            offset = dva & (PAGE_SIZE - 1)
            take = min(count, PAGE_SIZE - offset)
            out += page[offset:offset + take]
            dva += take
            count -= take
        return bytes(out)

    return target, read


def main(directory):
    failures = 0
    for half, work_selector in (("TA_0", 0x00), ("3D_0", 0x01)):
        target, read = load_half(directory, half)
        queue = target["queues"][0]
        start, end = pending_entry_span(queue)
        raw = read(int(queue["inner_dva"]) + start * 8, (end - start) * 8)
        if raw is None:
            print("%s: pending item-ring entries are absent" % half)
            failures += 1
            continue

        pointers = struct.unpack("<%dQ" % (end - start), raw)
        selectors = []
        for pointer in pointers:
            header = read(pointer, 4) if pointer else None
            if header is None:
                selectors.append(None)
                failures += 1
                continue
            selector = struct.unpack("<I", header)[0]
            try:
                item_record_size(selector)
            except ValueError:
                failures += 1
            selectors.append(selector)

        expected = ([work_selector, 0x0E] if len(selectors) == 2
                    else [work_selector, 0x0F, 0x0E])
        if selectors != expected:
            failures += 1
        print("%s: pending [%d,%d) pointers %s selectors %s %s"
              % (half, start, end, [hex(pointer) for pointer in pointers],
                 [None if selector is None else hex(selector)
                  for selector in selectors],
                 "OK" if selectors == expected else "UNEXPECTED"))

    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s <targeted-capture>" % pathlib.Path(sys.argv[0]).name)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
