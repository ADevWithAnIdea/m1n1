# SPDX-License-Identifier: MIT
"""Across a live host's captured submissions, does the packed shared object change?

The parameter-buffer binding is by the address of the packed shared object, so what a working host
does across successive submissions decides whether a driver reuses one or has to unbind.
"""
import json
import pathlib
import struct
import sys

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                 "/Users/user/asahi_re/artifacts/agx_g17p/"
                 "live_submission_targeted_20260728_003032")

LAYOUT = {0x00: ("tiling", 0x10, 0x08), 0x01: ("fragment", 0x20, 0x00)}


def load(channel):
    index = json.load(open(D / channel / "pages.json"))
    blob = (D / channel / "pages.bin").read_bytes()
    size = int(index["page_size"])
    pages = {int(page["dva"]): int(page["capture_offset"]) for page in index["pages"]}
    return pages, blob, size


def read(pages, blob, size, dva, length):
    page = dva & ~(size - 1)
    if page not in pages:
        return None
    start = pages[page] + (dva - page)
    return blob[start:start + length]


for channel in ("TA_0", "3D_0"):
    target = json.load(open(D / channel / "target.json"))
    pages, blob, size = load(channel)
    print("== %s  producer %s -> %s" % (channel, target["producer_before"],
                                        target["producer_after"]))
    seen = []
    for queue in target["queues"]:
        for triple in queue["inner_entries"]:
            descriptor = triple[0]
            head = read(pages, blob, size, descriptor, 4)
            if head is None:
                continue
            selector = struct.unpack("<I", head)[0]
            if selector not in LAYOUT:
                continue
            kind, pointers, gap = LAYOUT[selector]
            body = read(pages, blob, size, descriptor, pointers + 8 + gap + 24)
            if body is None or len(body) < pointers + 8 + gap + 24:
                continue
            first = struct.unpack_from("<Q", body, pointers)[0]
            rest = struct.unpack_from("<3Q", body, pointers + 8 + gap)
            sequence = struct.unpack_from("<Q", body, 4)[0]
            seen.append((kind, sequence, first, rest[0], rest[1], rest[2]))

    print("   %d work descriptors" % len(seen))
    print("   %-9s %4s  %-14s %-14s %-14s %-14s"
          % ("kind", "seq", "pool A rec", "PACKED SHARED", "pool B rec", "zero shared"))
    for kind, sequence, a, packed, b, zero in seen:
        print("   %-9s %4d  %#014x %#014x %#014x %#014x"
              % (kind, sequence, a, packed, b, zero))
    packed_set = {entry[3] for entry in seen}
    print("   distinct packed shared objects: %d -> %s"
          % (len(packed_set), ["%#x" % v for v in sorted(packed_set)]))
