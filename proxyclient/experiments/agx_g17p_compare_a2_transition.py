#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare native and generated descriptor transitions."""

import argparse
import pathlib
import struct

from agx_g17p_compare_live_dump import snapshot_pages, snapshot_read


PAGE = 0x4000
DESCRIPTORS = {
    "tiling": (0xfffffc20c0018000, 0x9c0),
    "fragment": (0xfffffc20c00b0000, 0x2240),
}


def dump_read(path, address, size):
    output = bytearray()
    while len(output) < size:
        current = address + len(output)
        page = current & ~(PAGE - 1)
        offset = current - page
        body = (path / ("%016x.bin" % page)).read_bytes()
        length = min(PAGE - offset, size - len(output))
        output += body[offset:offset + length]
    return bytes(output)


def word(body, offset):
    return struct.unpack_from("<I", body, offset)[0]


def describe(kind, native_before, native_after, generated_before,
             generated_after):
    categories = {"missing": [], "extra": [], "different": []}
    for offset in range(0, len(native_before), 4):
        nb = word(native_before, offset)
        na = word(native_after, offset)
        gb = word(generated_before, offset)
        ga = word(generated_after, offset)
        native_changed = nb != na
        generated_changed = gb != ga
        native_delta = (na - nb) & 0xffffffff
        generated_delta = (ga - gb) & 0xffffffff
        row = (offset, nb, na, gb, ga, native_delta, generated_delta)
        if native_changed and not generated_changed:
            categories["missing"].append(row)
        elif generated_changed and not native_changed:
            categories["extra"].append(row)
        elif native_changed and generated_changed and native_delta != generated_delta:
            categories["different"].append(row)

    print("== %s" % kind)
    print("   missing native changes: %d; extra generated changes: %d; "
          "different deltas: %d" % tuple(len(categories[name]) for name in
                                          ("missing", "extra", "different")))
    for name in ("missing", "extra", "different"):
        if not categories[name]:
            continue
        print("   %s:" % name)
        for offset, nb, na, gb, ga, nd, gd in categories[name]:
            print("      +%#06x native %08x -> %08x (%+#x), "
                  "generated %08x -> %08x (%+#x)" %
                  (offset, nb, na, nd, gb, ga, gd))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=pathlib.Path)
    parser.add_argument("dump", type=pathlib.Path)
    parser.add_argument("--before-ordinal", type=int, default=0)
    parser.add_argument("--after-ordinal", type=int, default=2)
    args = parser.parse_args()

    if args.before_ordinal < 0 or args.after_ordinal <= args.before_ordinal:
        parser.error("descriptor ordinals must satisfy 0 <= before < after")

    pages = snapshot_pages(args.snapshot)
    for kind, (base, size) in DESCRIPTORS.items():
        before_address = base + args.before_ordinal * size
        after_address = base + args.after_ordinal * size
        native_before, missing = snapshot_read(pages, before_address, size)
        if native_before is None:
            raise RuntimeError("native %s A1 is missing page %#x" % (kind, missing))
        native_after, missing = snapshot_read(pages, after_address, size)
        if native_after is None:
            raise RuntimeError("native %s A2 is missing page %#x" % (kind, missing))
        describe(
            kind,
            native_before,
            native_after,
            dump_read(args.dump, before_address, size),
            dump_read(args.dump, after_address, size),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
