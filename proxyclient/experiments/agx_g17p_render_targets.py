# SPDX-License-Identifier: MIT
"""Enumerate every render address the submission's register arrays name.

The poison test covered seven pages, which are the ones the capture happened to fetch under a
per-item cap. A framebuffer at the dimensions this submission carries would be hundreds of pages
and cannot be among them, so "nothing was written" may only mean "nothing was written to those
seven". This lists the full set from the captured descriptors, offline.
"""
import json
import pathlib
import struct
import sys
from collections import defaultdict

D = sys.argv[1]
PAGE = 0x4000
LOW, HIGH = 0x10000000000, 0x20000000000
STARTS = {"TA": 0x78, "3D": 0xAC}


def captured_halves(path):
    root = pathlib.Path(path)
    halves = []
    for prefix in ("TA", "3D"):
        candidates = sorted(
            child.name for child in root.iterdir()
            if child.is_dir() and child.name.startswith(prefix + "_")
            and (child / "target.json").exists()
        )
        if len(candidates) != 1:
            raise SystemExit("expected one captured %s half, found %s" %
                             (prefix, candidates))
        halves.append(candidates[0])
    return halves

for half in captured_halves(D):
    target = json.load(open("%s/%s/target.json" % (D, half)))
    pj = json.load(open("%s/%s/pages.json" % (D, half)))
    pages = pj["pages"] if isinstance(pj, dict) and "pages" in pj else pj
    blob = open("%s/%s/pages.bin" % (D, half), "rb").read()
    by_page = {}
    for rec in pages:
        dva = int(rec["dva"], 0) if isinstance(rec["dva"], str) else int(rec["dva"])
        by_page[dva] = blob[rec["capture_offset"]:rec["capture_offset"] + PAGE]
    captured_render = {d for d in by_page if not (d >> 42) & 1}

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
    entries = tuple(value for item in q["inner_entries"] for value in item)
    start = STARTS[half.split("_", 1)[0]]

    by_reg = defaultdict(set)
    for item in range(len(entries) // 3):
        desc = entries[item * 3]
        body = read(desc, 0x2240)
        if not body:
            continue
        cursor, empties = start, 0
        while cursor + 0xC <= len(body):
            number, value = struct.unpack_from("<IQ", body, cursor)
            if number == 0 and value == 0:
                empties += 1
                if empties >= 3:
                    break
            else:
                empties = 0
                if LOW <= value < HIGH:
                    by_reg[number].add(value)
            cursor += 0xC

    allvals = set()
    for vals in by_reg.values():
        allvals |= vals
    pagesnamed = {v & ~(PAGE - 1) for v in allvals}
    print("\n%s: %d distinct render values, %d distinct pages, %d of those captured"
          % (half, len(allvals), len(pagesnamed), len(pagesnamed & captured_render)))
    for number in sorted(by_reg):
        vals = sorted(by_reg[number])
        span = "" if len(vals) == 1 else "  (%d values, span %#x)" % (
            len(vals), vals[-1] - vals[0])
        got = sum(1 for v in vals if (v & ~(PAGE - 1)) in captured_render)
        print("   reg %#07x -> %s%s  captured %d/%d"
              % (number, " ".join("%#x" % v for v in vals[:3]), span, got, len(vals)))
