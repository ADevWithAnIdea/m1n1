# SPDX-License-Identifier: MIT
"""Measure the support-item pools both channels share.

Support items live outside their descriptors, in two pools, and the tiling and fragment halves
interleave inside them. So a record's size is bounded by the smallest gap between neighbouring
records across both halves, not by one half's stride, and writing a whole stride would overwrite
the other channel's record.
"""
import json
import struct
import sys

D = sys.argv[1]
PAGE = 0x4000

addrs = {1: [], 2: []}
for half in ("TA_0", "3D_0"):
    target = json.load(open("%s/%s/target.json" % (D, half)))
    pj = json.load(open("%s/%s/pages.json" % (D, half)))
    pages = pj["pages"] if isinstance(pj, dict) and "pages" in pj else pj
    blob = open("%s/%s/pages.bin" % (D, half), "rb").read()
    by_page = {}
    for rec in pages:
        dva = int(rec["dva"], 0) if isinstance(rec["dva"], str) else int(rec["dva"])
        by_page[dva] = blob[rec["capture_offset"]:rec["capture_offset"] + PAGE]

    def read(dva, count):
        out = bytearray()
        while count:
            page = by_page.get(dva & ~(PAGE - 1))
            if page is None:
                return None
            off = dva & (PAGE - 1)
            take = min(count, PAGE - off)
            out += page[off:off + take]
            dva += take
            count -= take
        return bytes(out)

    q = (target.get("queues") or [{}])[0]
    count = int(q["captured_inner_items"])
    raw = read(int(q["inner_dva"]), count * 8)
    entries = list(struct.unpack("<%dQ" % count, raw))
    for i in range(count // 3):
        for k in (1, 2):
            a = entries[i * 3 + k]
            if a:
                addrs[k].append((a, half, i))

for k in (1, 2):
    items = sorted(addrs[k])
    print("\nsupport %d: %d records across both halves" % (k, len(items)))
    print("  range %#014x .. %#014x" % (items[0][0], items[-1][0]))
    gaps = sorted({b[0] - a[0] for a, b in zip(items, items[1:]) if b[0] != a[0]})
    print("  distinct gaps between neighbours: %s" % [hex(g) for g in gaps])
    print("  smallest gap (upper bound on record size): %#x" % gaps[0])
    pages_used = sorted({a & ~(PAGE - 1) for a, _, _ in items})
    print("  pages: %s" % [hex(p) for p in pages_used])
    for a, half, i in items[:6]:
        print("    %#014x  %s item %d" % (a, half, i))
