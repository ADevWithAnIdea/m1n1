#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the cold world's reachable objects against a working one by contents, not by pointers.

The earlier parallel walk matched twenty-nine objects by the path taken from the descriptor root and
compared their pointer fields, finding only three differences, all staged work. It did not compare
anything else in them. Eleven objects are checked byte-exact by the handoff gate; the rest have never
been compared at all, and a scalar that differs would look exactly like what is observed, a
descriptor firmware accepts and then does nothing with.

Pointer-valued words are excluded from the comparison, since the two worlds place their objects at
different addresses and a difference there is expected and meaningless. What is left is the scalars.
"""
import argparse
import json
import pathlib
import struct
import sys

PAGE = 0x4000


def load_cold(directory):
    index = json.loads((directory / "initdata_closure.json").read_bytes())
    blob = (directory / "initdata_closure.bin").read_bytes()
    # The index is a plain list of device addresses, in the order the blob holds them.
    pages = {}
    for position, dva in enumerate(index["pages"]):
        offset = position * PAGE
        pages[int(dva) & 0xffffffffffffffff] = blob[offset:offset + PAGE]
    return index, pages


def looks_like_pointer(value):
    """A device address in either half, which the two worlds place differently."""
    if not value:
        return False
    if 0xfffffc0000000000 <= value <= 0xfffffc21ffffffff:
        return True
    return 0x1000000000 <= value <= 0x1002000000 or 0x7000000000 <= value <= 0x7002000000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cold", type=pathlib.Path, help="a coldboot_* directory")
    parser.add_argument("--detail", action="store_true",
                        help="print every scalar that differs from the closest native page")
    parser.add_argument("--native", type=pathlib.Path,
                        default=pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p/"
                                             "pre_work_0x83_v2_20260724_193713"))
    args = parser.parse_args()

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from agx_g17p_render_objects import Roots, load_snapshot

    index, cold_pages = load_cold(args.cold.resolve())
    print("cold closure: %d pages" % len(cold_pages))
    if not cold_pages:
        raise SystemExit("the cold dump holds no pages; index keys were %s"
                         % (sorted(index) if isinstance(index, dict) else type(index)))

    manifest, ram = load_snapshot(args.native.resolve())
    roots = Roots(manifest, ram)
    native_pages = {}
    for identity, pages in roots.by_root.items():
        if identity[1] != 64:
            continue
        native_pages.update(pages)
    print("native firmware-context pages available: %d" % len(native_pages))

    # The two worlds place objects differently, so compare the scalar profile of each cold page
    # against every native page and report the closest, rather than assuming an address match.
    print()
    print("per-page scalar comparison, pointer-valued words excluded")
    unmatched = 0
    for dva in sorted(cold_pages):
        cold = cold_pages[dva]
        scalars = [(offset, struct.unpack_from("<Q", cold, offset)[0])
                   for offset in range(0, PAGE - 8, 8)
                   if not looks_like_pointer(struct.unpack_from("<Q", cold, offset)[0])]
        nonzero = [(offset, value) for offset, value in scalars if value]
        best = None
        for native_dva, native in native_pages.items():
            agree = sum(1 for offset, value in nonzero
                        if struct.unpack_from("<Q", native, offset)[0] == value)
            if best is None or agree > best[0]:
                best = (agree, native_dva)
        if not nonzero:
            continue
        agree, native_dva = best
        ratio = agree / len(nonzero)
        flag = "" if ratio >= 0.9 else "   <-- differs"
        if ratio < 0.9:
            unmatched += 1
        print("  %#014x  %4d non-zero scalars, best native %#014x agrees on %4d (%3.0f%%)%s"
              % (dva, len(nonzero), native_dva, agree, ratio * 100, flag))
        if args.detail and ratio < 1.0:
            native = native_pages[native_dva]
            for offset, value in nonzero:
                other = struct.unpack_from("<Q", native, offset)[0]
                if other != value:
                    print("        +%#06x  cold %#018x  native %#018x"
                          % (offset, value, other))

    print()
    print("%d of %d cold pages have no native page agreeing on 90%% of their scalars"
          % (unmatched, len(cold_pages)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
