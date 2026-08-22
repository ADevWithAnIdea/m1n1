#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recover the published device-control entries from a working snapshot.

The producer counter gives the absolute number of entries published by the
host.  Recover the live ring window in chronological order; reading only the
first four slots hides later scheduler-object registrations in captures taken
after several submissions.

The chain is the one the replay walks: initdata at `init_addr` names a second region at `+0x18`,
whose `+0x1a0` is the device-control block, whose `+0x18` is the ring. Entries are `0x40` bytes.

Offline. Reads a snapshot directory.
"""
import json
import pathlib
import struct
import sys

PAGE = 0x4000
CONTROL_BLOCK = 0x1A0
CONTROL_RING_PTR = 0x18
ENTRY_SIZE = 0x40
RING_ENTRIES = 256


class Snapshot:
    """Reads firmware-context device addresses out of a captured world."""

    def __init__(self, directory):
        self.dir = pathlib.Path(directory)
        self.manifest = json.load(open(self.dir / "manifest.json"))
        self.ram = open(self.dir / "ram.bin", "rb")
        self.pages = {}
        for group in self.manifest["root_mappings"]:
            # The firmware context: context 64 at selector 1, the same root the replay selects.
            if group.get("root_ctx_id") != 64 or group.get("selector") != 1:
                continue
            for mapping in group["mappings"]:
                if mapping.get("blob_index") is None:
                    continue
                self.pages[int(mapping["va"]) & ~(PAGE - 1)] = int(mapping["blob_index"])

    def read(self, dva, size):
        out = bytearray()
        while size:
            page = dva & ~(PAGE - 1)
            index = self.pages.get(page)
            if index is None:
                raise KeyError("no captured page for %#x" % dva)
            offset = dva & (PAGE - 1)
            take = min(size, PAGE - offset)
            self.ram.seek(index * PAGE + offset)
            out += self.ram.read(take)
            dva += take
            size -= take
        return bytes(out)

    def u64(self, dva):
        return struct.unpack("<Q", self.read(dva, 8))[0]

    def u32(self, dva):
        return struct.unpack("<I", self.read(dva, 4))[0]


def main(directory):
    snap = Snapshot(directory)
    init_addr = int(snap.manifest["init_addr"])
    region_b = snap.u64(init_addr + 0x18)
    control_base = region_b + CONTROL_BLOCK
    state = [snap.u64(control_base + off) for off in (0, 8, 0x10)]
    ring = snap.u64(control_base + CONTROL_RING_PTR)

    print("init_addr      %#x" % init_addr)
    print("region_b       %#x" % region_b)
    print("control block  %#x" % control_base)
    print("control ring   %#x" % ring)
    print("state pointers %s" % " ".join("%#x" % s for s in state))
    print("counters       %s" % [snap.u32(s) for s in state])

    published = snap.u32(state[2])
    first = max(0, published - RING_ENTRIES)
    entries = []
    print("\nthe live published entries in chronological order:")
    for absolute_index in range(first, published):
        index = absolute_index % RING_ENTRIES
        body = snap.read(ring + index * ENTRY_SIZE, ENTRY_SIZE)
        entries.append(body)
        words = struct.unpack("<16I", body)
        nonzero = [(i * 4, w) for i, w in enumerate(words) if w]
        print("  entry %d (slot %d)  opcode %#06x  %s"
              % (absolute_index, index, words[0] & 0xFFFF,
                 " ".join("+%#04x=%#x" % nz for nz in nonzero[:8]) or "all zero"))

    out = pathlib.Path(directory) / "device_control_entries.bin"
    out.write_bytes(b"".join(entries))
    print("\nwrote %d entries (%d bytes) to %s" % (len(entries), len(b"".join(entries)), out))
    print("distinct entries: %d" % len({bytes(e) for e in entries}))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
