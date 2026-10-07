#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Walk everything firmware can reach from initdata in a snapshot, and size the coldboot's world.

Firmware services channels in a replayed world and none from a cold bring-up, and both are fresh
firmware boots reading different memory. So the difference is a memory difference, and the first
question is how much smaller the cold world is and what kind of thing is missing from it.

Follows firmware-context pointers transitively from initdata, the same worklist the submission
capture uses, and reports the reachable set by region. Compare the result against the objects a
coldboot run prints when it builds its arena.

Offline. Reads a snapshot directory.
"""
import json
import pathlib
import struct
import sys
from collections import Counter

PAGE = 0x4000
FW_TAG = 0xFFFFFC20
MAX_PAGES = 4096


class Snapshot:
    def __init__(self, directory):
        self.dir = pathlib.Path(directory)
        self.manifest = json.load(open(self.dir / "manifest.json"))
        self.ram = open(self.dir / "ram.bin", "rb")
        self.pages = {}
        for group in self.manifest["root_mappings"]:
            if group.get("root_ctx_id") != 64 or group.get("selector") != 1:
                continue
            for mapping in group["mappings"]:
                if mapping.get("blob_index") is None:
                    continue
                self.pages[int(mapping["va"]) & ~(PAGE - 1)] = int(mapping["blob_index"])

    def page(self, va):
        index = self.pages.get(va)
        if index is None:
            return None
        self.ram.seek(index * PAGE)
        return self.ram.read(PAGE)

    def u64(self, dva):
        page = self.page(dva & ~(PAGE - 1))
        if page is None:
            return None
        return struct.unpack_from("<Q", page, dva & (PAGE - 1))[0]


def main(directory):
    snap = Snapshot(directory)
    init = int(snap.manifest["init_addr"])
    print("snapshot          %s" % pathlib.Path(directory).name)
    print("init_addr         %#x" % init)
    print("firmware-context pages mapped in the snapshot: %d" % len(snap.pages))

    # Transitive closure over firmware-tagged pointers, from initdata.
    seen = {init & ~(PAGE - 1)}
    pending = [init & ~(PAGE - 1)]
    unmapped = Counter()
    rounds = 0
    while pending and len(seen) < MAX_PAGES:
        rounds += 1
        frontier, pending = pending, []
        for base in frontier:
            body = snap.page(base)
            if body is None:
                continue
            for offset in range(0, PAGE - 8, 8):
                word = struct.unpack_from("<Q", body, offset)[0]
                if (word >> 32) != FW_TAG:
                    continue
                target = word & ~(PAGE - 1)
                if target in seen:
                    continue
                if target not in snap.pages:
                    unmapped[target] += 1
                    continue
                seen.add(target)
                pending.append(target)

    print("\nreachable from initdata: %d pages in %d rounds" % (len(seen), rounds))
    print("referenced but not mapped: %d distinct" % len(unmapped))

    # Group the reachable set by megabyte, which separates the regions cleanly.
    regions = Counter(page >> 20 for page in seen)
    print("\nreachable pages by region:")
    for region, count in sorted(regions.items()):
        print("   %#014x   %4d pages  (%d KiB)" % (region << 20, count, count * 16))

    print("\nthe snapshot's mapped set by region, for comparison:")
    allregions = Counter(page >> 20 for page in snap.pages)
    for region, count in sorted(allregions.items()):
        reached = regions.get(region, 0)
        note = "" if reached == count else "   %d of these reachable from initdata" % reached
        print("   %#014x   %4d pages%s" % (region << 20, count, note))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
