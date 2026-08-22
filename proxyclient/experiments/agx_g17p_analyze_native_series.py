#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the native descriptor series in a targeted work-ring dump."""

import argparse
import json
import pathlib
import struct

from agx_g17p_compare_live_dump import snapshot_pages, snapshot_read


PAGE = 0x4000
KINDS = {
    "tiling": {
        "channel": "TA_0",
        "base": 0xfffffc20c0018000,
        "size": 0x9c0,
        "selector": 0,
        "offsets": (0x3a0, 0x420, 0x6b0, 0x6b8, 0x878, 0x87c,
                    0x880, 0x884, 0x944),
    },
    "fragment": {
        "channel": "3D_0",
        "base": 0xfffffc20c00b0000,
        "size": 0x2240,
        "selector": 1,
        "offsets": (0xc8, 0xe0, 0x420, 0x494, 0x6b0, 0x6b8,
                    0x1e80, 0x1ea8, 0x1f7c, 0x1f9c, 0x2114,
                    0x2118, 0x211c, 0x2120, 0x21d8),
    },
}


class TargetedDump:
    def __init__(self, path):
        self.path = path
        metadata = json.loads((path / "pages.json").read_text())
        body = (path / "pages.bin").read_bytes()
        self.pages = {
            int(page["dva"]): body[int(page["capture_offset"]):
                                   int(page["capture_offset"]) + PAGE]
            for page in metadata["pages"]
        }
        self.target = json.loads((path / "target.json").read_text())

    def read(self, address, size):
        output = bytearray()
        while len(output) < size:
            current = address + len(output)
            page = current & ~(PAGE - 1)
            offset = current - page
            body = self.pages.get(page)
            if body is None:
                return None
            length = min(PAGE - offset, size - len(output))
            output += body[offset:offset + length]
        return bytes(output)

    def ring_pointers(self):
        pointers = []
        for queue in self.target["queues"]:
            for entry in queue["inner_entries"]:
                pointers.extend(int(pointer) for pointer in entry if pointer)
        return pointers


class SnapshotDump:
    """Read descriptor arrays from a full UAT snapshot."""

    def __init__(self, path):
        self.pages = snapshot_pages(path)

    def read(self, address, size):
        body, _missing = snapshot_read(self.pages, address, size)
        return body


def descriptor_series(path, kind, spec):
    snapshot = (path / "manifest.json").exists()
    dump = SnapshotDump(path) if snapshot else TargetedDump(path / spec["channel"])
    descriptors = {}
    addresses = (
        (spec["base"] + ordinal * spec["size"] for ordinal in range(32))
        if snapshot else dump.ring_pointers()
    )
    for address in addresses:
        delta = address - spec["base"]
        if delta < 0 or delta % spec["size"]:
            continue
        ordinal = delta // spec["size"]
        body = dump.read(address, spec["size"])
        if body is None or struct.unpack_from("<I", body)[0] != spec["selector"]:
            continue
        # A zero-filled unused tiling slot has the same selector value as a real
        # tiling descriptor. Every populated descriptor names its first object
        # through the pointer at +0x10, so use that as the occupancy predicate.
        if snapshot and kind == "tiling" and struct.unpack_from("<Q", body, 0x10)[0] == 0:
            continue
        descriptors[ordinal] = (address, body)
    return sorted(descriptors.items())


def u32(body, offset):
    return struct.unpack_from("<I", body, offset)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=pathlib.Path)
    parser.add_argument("--all-differences", action="store_true",
                        help="also list every aligned word that changes in the series")
    args = parser.parse_args()

    for kind, spec in KINDS.items():
        series = descriptor_series(args.dump, kind, spec)
        print("== %s: %d descriptors" % (kind, len(series)))
        print("   ordinals: %s" % ", ".join(str(ordinal) for ordinal, _ in series))
        for ordinal, (address, _) in series:
            print("   ordinal %-2d address %#018x" % (ordinal, address))
        print("   selected fields:")
        for offset in spec["offsets"]:
            values = [u32(body, offset) for _, (_, body) in series]
            print("      +%#06x  %s" %
                  (offset, " ".join("%08x" % value for value in values)))

        if not args.all_differences or not series:
            continue
        changing = []
        for offset in range(0, spec["size"], 4):
            values = [u32(body, offset) for _, (_, body) in series]
            if len(set(values)) > 1:
                changing.append((offset, values))
        print("   all changing aligned words: %d" % len(changing))
        for offset, values in changing:
            print("      +%#06x  %s" %
                  (offset, " ".join("%08x" % value for value in values)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
