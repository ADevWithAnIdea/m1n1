# SPDX-License-Identifier: MIT
"""Look for an output buffer across a whole work item, not just its register array.

Every "nothing was written" result so far checked the seven pages the register arrays name. If the
accelerator writes to a framebuffer named somewhere else in the item, by the descriptor's pointer
block or by a field the register walk skips, those checks were looking in the wrong place and the
conclusion is unsupported.

Scans each item's whole body for render-context addresses, at 8-byte alignment, and reports them by
where they sit and how large a region they imply. A framebuffer at this submission's dimensions
would be about 14 MB, so anything naming a region of that order stands out from tile buffers.
"""
import json
import pathlib
import struct
import sys
from collections import defaultdict

D = sys.argv[1]
PAGE = 0x4000
LOW, HIGH = 0x10000000000, 0x20000000000
BODY = 0x2240


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


def load(half):
    target = json.load(open("%s/%s/target.json" % (D, half)))
    pj = json.load(open("%s/%s/pages.json" % (D, half)))
    pages = pj["pages"] if isinstance(pj, dict) and "pages" in pj else pj
    blob = open("%s/%s/pages.bin" % (D, half), "rb").read()
    by_page = {}
    for rec in pages:
        dva = rec["dva"]
        dva = int(dva, 0) if isinstance(dva, str) else int(dva)
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

    return target, read, {d for d in by_page if not (d >> 42) & 1}


for half in captured_halves(D):
    target, read, captured_render = load(half)
    q = (target.get("queues") or [{}])[0]
    entries = tuple(value for item in q["inner_entries"] for value in item)

    # Every render-context address anywhere in any of the three entries of every group.
    where = defaultdict(list)
    for group in range(len(entries) // 3):
        for slot in range(3):
            base = entries[group * 3 + slot]
            if not base:
                continue
            body = read(base, BODY)
            if body is None:
                continue
            for off in range(0, len(body) - 8, 8):
                value = struct.unpack_from("<Q", body, off)[0]
                if LOW <= value < HIGH:
                    where[value].append((group, slot, off))

    pages_named = sorted({v & ~(PAGE - 1) for v in where})
    missing = [p for p in pages_named if p not in captured_render]
    print("\n%s: %d distinct render addresses over %d pages, %d of those pages not captured"
          % (half, len(where), len(pages_named), len(missing)))

    # Group addresses into contiguous runs, which is what a large buffer looks like.
    runs = []
    for page in pages_named:
        if runs and page == runs[-1][1] + PAGE:
            runs[-1][1] = page
        else:
            runs.append([page, page])
    print("   contiguous page runs:")
    for start, end in runs:
        size = end - start + PAGE
        note = ""
        if size >= 0x100000:
            note = "  <-- %d MB, large enough to be an output buffer" % (size // 0x100000)
        print("     %#014x .. %#014x  %#x%s" % (start, end + PAGE, size, note))

    # Which offsets in the item name addresses outside the register array, since the register
    # walk starts at 0x78 (tiling) or 0xac (fragment) and the pointer block sits before it.
    early = sorted({off for refs in where.values() for _, slot, off in refs if off < 0x78})
    if early:
        print("   addresses in the pointer block (before the register array): %s"
              % ", ".join("+%#04x" % off for off in early[:10]))
