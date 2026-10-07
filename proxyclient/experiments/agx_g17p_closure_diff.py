#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Walk a working initdata closure and a cold one in parallel, and list what the cold one lacks.

Firmware reaches 39 pages over 8 rounds from a working host's descriptor and 19 over 3 from a cold
bring-up, with nothing dangling on either side. So the cold world is a smaller graph of the same
kind, and the objects it lacks are reachable only through pointer fields its objects do not carry.

Matching is by the path taken from the root, not by address, since the two worlds place their
objects differently. Two objects correspond when the same sequence of offsets leads to each.

Reports pointer fields set natively and zero from cold; each one names an object the bring-up does
not build. Also reports the reverse, and fields where both are set, so the correspondence itself can
be checked rather than assumed.

Offline. Reads a snapshot directory and a coldboot artifact directory.
"""
import json
import pathlib
import struct
import sys
from collections import deque

PAGE = 0x4000
FW_TAG = 0xFFFFFC20
MAX_DEPTH = 10


class NativeWorld:
    """Firmware-context pages from a snapshot."""

    def __init__(self, directory):
        d = pathlib.Path(directory)
        self.manifest = json.load(open(d / "manifest.json"))
        self.ram = open(d / "ram.bin", "rb")
        self.index = {}
        for group in self.manifest["root_mappings"]:
            if group.get("root_ctx_id") != 64 or group.get("selector") != 1:
                continue
            for mapping in group["mappings"]:
                if mapping.get("blob_index") is None:
                    continue
                self.index[int(mapping["va"]) & ~(PAGE - 1)] = int(mapping["blob_index"])
        self.root = int(self.manifest["init_addr"])

    def page(self, va):
        i = self.index.get(va & ~(PAGE - 1))
        if i is None:
            return None
        self.ram.seek(i * PAGE)
        return self.ram.read(PAGE)


class ColdWorld:
    """Pages a coldboot run saved with --dump-closure."""

    def __init__(self, directory):
        d = pathlib.Path(directory)
        meta = json.load(open(d / "initdata_closure.json"))
        blob = (d / "initdata_closure.bin").read_bytes()
        self.pages = {}
        for n, va in enumerate(sorted(meta["pages"])):
            self.pages[va] = blob[n * PAGE:(n + 1) * PAGE]
        self.root = int(meta["init_va"])

    def page(self, va):
        return self.pages.get(va & ~(PAGE - 1))


def read_u64(world, dva):
    page = world.page(dva)
    if page is None:
        return None
    return struct.unpack_from("<Q", page, dva & (PAGE - 1))[0]


def is_pointer(value):
    return value is not None and (value >> 32) == FW_TAG


def main(snapshot_dir, coldboot_dir):
    native = NativeWorld(snapshot_dir)
    cold = ColdWorld(coldboot_dir)
    print("native root %#x, cold root %#x" % (native.root, cold.root))

    missing = []
    extra = []
    matched = 0
    seen = set()
    queue = deque([(native.root, cold.root, "", 0)])

    while queue:
        n_addr, c_addr, path, depth = queue.popleft()
        if depth > MAX_DEPTH:
            continue
        key = (n_addr & ~(PAGE - 1), c_addr & ~(PAGE - 1))
        if key in seen:
            continue
        seen.add(key)
        n_page, c_page = native.page(n_addr), cold.page(c_addr)
        if n_page is None or c_page is None:
            continue
        matched += 1

        # Compare the two objects field by field within the page they start in.
        start_n, start_c = n_addr & (PAGE - 1), c_addr & (PAGE - 1)
        span = min(PAGE - start_n, PAGE - start_c)
        for offset in range(0, span - 8, 8):
            n_word = struct.unpack_from("<Q", n_page, start_n + offset)[0]
            c_word = struct.unpack_from("<Q", c_page, start_c + offset)[0]
            n_ptr, c_ptr = is_pointer(n_word), is_pointer(c_word)
            if n_ptr and c_ptr:
                queue.append((n_word, c_word, "%s+%#x" % (path, offset), depth + 1))
            elif n_ptr and not c_ptr:
                missing.append((path, offset, n_word, c_word, depth))
            elif c_ptr and not n_ptr:
                extra.append((path, offset, n_word, c_word, depth))

    print("objects matched by path: %d" % matched)

    print("\npointer fields set natively and not from cold: %d" % len(missing))
    for path, offset, n_word, c_word, depth in missing[:40]:
        print("   depth %d  root%s+%#06x  native %#014x  cold %#018x"
              % (depth, path or "", offset, n_word, c_word))
    if len(missing) > 40:
        print("   ... %d more" % (len(missing) - 40))

    print("\npointer fields set from cold and not natively: %d" % len(extra))
    for path, offset, n_word, c_word, depth in extra[:12]:
        print("   depth %d  root%s+%#06x  native %#018x  cold %#014x"
              % (depth, path or "", offset, n_word, c_word))

    # Group the missing ones by depth, which says whether the cold graph stops early or is
    # thin throughout.
    if missing:
        by_depth = {}
        for _, _, _, _, depth in missing:
            by_depth[depth] = by_depth.get(depth, 0) + 1
        print("\nmissing pointers by depth: %s"
              % " ".join("d%d=%d" % (d, n) for d, n in sorted(by_depth.items())))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        print("usage: agx_g17p_closure_diff.py <snapshot dir> <coldboot dir>")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
