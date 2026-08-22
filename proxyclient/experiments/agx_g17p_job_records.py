# SPDX-License-Identifier: MIT
"""Is the pool A field at +0x10 a first-record marker, or does every job in use carry it?

The model calls it a first-record marker, inferred from a capture in which only one submission had
ever been made, so only record zero was in use. A capture at a host's thirteenth submission can tell
the two apart.
"""
import json
import pathlib
import struct
import sys

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                 "/Users/user/asahi_re/artifacts/agx_g17p/"
                 "live_submission_targeted_20260728_003032")
LAYOUT = {0x00: ("tiling", 0x10), 0x01: ("fragment", 0x20)}


def load(channel):
    index = json.load(open(D / channel / "pages.json"))
    blob = (D / channel / "pages.bin").read_bytes()
    size = int(index["page_size"])
    return {int(p["dva"]): int(p["capture_offset"]) for p in index["pages"]}, blob, size


def read(pages, blob, size, dva, length):
    page = dva & ~(size - 1)
    if page not in pages:
        return None
    start = pages[page] + (dva - page)
    out = blob[start:start + length]
    return out if len(out) == length else None


for channel in ("TA_0",):
    target = json.load(open(D / channel / "target.json"))
    pages, blob, size = load(channel)
    records = []
    for queue in target["queues"]:
        for triple in queue["inner_entries"]:
            head = read(pages, blob, size, triple[0], 4)
            if head is None:
                continue
            selector = struct.unpack("<I", head)[0]
            if selector not in LAYOUT:
                continue
            _, at = LAYOUT[selector]
            body = read(pages, blob, size, triple[0], at + 8)
            if body is None:
                continue
            records.append(struct.unpack_from("<Q", body, at)[0])

    print("pool A records named by %d successive submissions:" % len(records))
    for position, address in enumerate(records):
        body = read(pages, blob, size, address, 0x100)
        if body is None:
            print("  submission %d record %#x: page not captured" % (position, address))
            continue
        fields = {off: struct.unpack_from("<I", body, off)[0]
                  for off in (0x0c, 0x10, 0x24, 0xc0)}
        nonzero = sum(1 for byte in body if byte)
        print("  submission %d record %#014x: +0x0c %#x  +0x10 %#x  +0x24 %#x  +0xc0 %#x  "
              "(%d non-zero bytes)"
              % (position, address, fields[0x0c], fields[0x10], fields[0x24],
                 fields[0xc0], nonzero))
