#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check what a single captured submission can say about the per-item index family.

The ABI record lists twelve fields of a work item that advance by a uniform stride, derived from
watching a guest republish the same item repeatedly. Those strides describe how one item changes
between consecutive submissions, so a single capture cannot test them: its items are different
items, not the same item at different times. An earlier version of this script compared them
across items within one submission and called every field a mismatch, which tested the wrong thing.

What a single capture can test is the index family, which the record describes as holding within a
submission: offset 0x7a8 is the item's index, 0x7a0 is that index times 0x100, and 0x7b0 is that
index times 0x101. This checks that, and reports the shape of the submission while doing so, since
the entries turn out not to be uniform.

Offline. Reads only a capture directory.
"""
import json
import struct
import sys
import pathlib

PAGE = 0x4000
INDEX = 0x7A8
INDEX_X100 = 0x7A0
INDEX_X101 = 0x7B0
# An index plausibly numbers items within one submission; anything larger is a different field
# in a differently shaped item rather than an index.
MAX_PLAUSIBLE_INDEX = 64


def load(directory, half):
    target = json.load(open("%s/%s/target.json" % (directory, half)))
    pages = json.load(open("%s/%s/pages.json" % (directory, half)))
    pages = pages["pages"] if isinstance(pages, dict) and "pages" in pages else pages
    blob = open("%s/%s/pages.bin" % (directory, half), "rb").read()
    by_page = {}
    for record in pages:
        dva = record["dva"]
        dva = int(dva, 0) if isinstance(dva, str) else int(dva)
        by_page[dva] = blob[record["capture_offset"]:record["capture_offset"] + PAGE]

    def read(dva, count):
        out = bytearray()
        while count:
            page = by_page.get(dva & ~(PAGE - 1))
            if page is None:
                return None
            offset = dva & (PAGE - 1)
            take = min(count, PAGE - offset)
            out += page[offset:offset + take]
            dva += take
            count -= take
        return bytes(out)

    return target, read


def main(directory):
    failures = 0
    for half in ("TA_0", "3D_0"):
        try:
            target, read = load(directory, half)
        except FileNotFoundError:
            print("%s: not in this capture" % half)
            continue
        queue = (target.get("queues") or [{}])[0]
        count = int(queue["captured_inner_items"])
        entries = struct.unpack("<%dQ" % count, read(int(queue["inner_dva"]), count * 8))
        items = [entries[i * 3] for i in range(count // 3)]

        indexed, other, empty = [], [], []
        print("\n%s: %d entries, %d groups" % (half, count, len(items)))
        for position, address in enumerate(items):
            body = read(address, 0x1000)
            if body is None:
                other.append(position)
                continue
            index = struct.unpack_from("<I", body, INDEX)[0]
            x100 = struct.unpack_from("<I", body, INDEX_X100)[0]
            x101 = struct.unpack_from("<I", body, INDEX_X101)[0]
            if index == 0 and x100 == 0 and x101 == 0:
                empty.append(position)
                continue
            if index > MAX_PLAUSIBLE_INDEX:
                other.append(position)
                continue
            indexed.append(position)
            consistent = (x100 == index * 0x100) and (x101 == index * 0x101)
            if not consistent:
                failures += 1
            print("   group %2d  index %-3d  x100 %#-8x x101 %#-8x  %s"
                  % (position, index, x100, x101, "OK" if consistent else "INCONSISTENT"))

        print("   shape: %d indexed, %d other, %d all-zero"
              % (len(indexed), len(other), len(empty)))
        if indexed:
            numbers = []
            for position in indexed:
                body = read(items[position], 0x1000)
                numbers.append(struct.unpack_from("<I", body, INDEX)[0])
            expected = list(range(1, len(numbers) + 1))
            print("   indices %s%s" % (numbers,
                                       "" if numbers == expected else "  (not 1..n)"))

    print("\n%s" % ("index family holds wherever an index is present"
                    if not failures else "%d inconsistent items" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        print("usage: %s <capture directory>" % pathlib.Path(sys.argv[0]).name)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
