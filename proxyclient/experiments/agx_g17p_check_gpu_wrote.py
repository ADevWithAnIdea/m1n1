# SPDX-License-Identifier: MIT
"""After a grafted submission completes, did the accelerator write to its render memory?

A completion counter says firmware consumed a publication; it does not say the GPU executed
anything. The render pages were mapped at physical addresses this host allocated, and those
addresses are in the attempt manifest, so they can be read back directly and compared with the
bytes that were written into them. A difference is the accelerator's own work.
"""
import json
import sys

sys.path.insert(0, "proxyclient")

from m1n1.setup import *  # noqa: F401,F403

manifest_path = sys.argv[1]
capture_dir = sys.argv[2]
PAGE = 0x4000

manifest = json.load(open(manifest_path))
grafts = manifest.get("grafted_submission") or {}
if "TA_0" not in grafts:
    grafts = {"single": grafts}

captured = {}
for half in ("TA_0", "3D_0"):
    try:
        pj = json.load(open("%s/%s/pages.json" % (capture_dir, half)))
        blob = open("%s/%s/pages.bin" % (capture_dir, half), "rb").read()
    except FileNotFoundError:
        continue
    pages = pj["pages"] if isinstance(pj, dict) and "pages" in pj else pj
    for rec in pages:
        dva = int(rec["dva"], 0) if isinstance(rec["dva"], str) else int(rec["dva"])
        captured.setdefault(dva, blob[rec["capture_offset"]:rec["capture_offset"] + PAGE])

total_changed = 0
for half, graft in grafts.items():
    for entry in graft.get("render_pages") or []:
        dva = int(entry["dva"])
        pa = int(entry["pa"]) if entry.get("pa") else None
        if pa is None:
            print("%s %#014x: no physical address recorded" % (half, dva))
            continue
        p.dc_civac(pa, PAGE)
        now = iface.readmem(pa, PAGE)
        was = captured.get(dva)
        if was is None:
            print("%s %#014x: not in the capture" % (half, dva))
            continue
        diff = sum(1 for a, b in zip(was, now) if a != b)
        total_changed += diff
        print("%s render %#014x pa %#x: %d of %d bytes differ from what was written"
              % (half, dva, pa, diff, PAGE))

print("\nTOTAL bytes changed by the accelerator: %d" % total_changed)
