# SPDX-License-Identifier: MIT
"""Do the render pages carry frame-varying data, or are they static?

Every "nothing was written" result assumes those pages are somewhere the accelerator would write.
If they are static configuration, poisoning them proves nothing about rendering and the whole line
of evidence is aimed at the wrong memory.

Two captures of the same submission index from different boots is a free test. Pages that differ
between boots carry something derived from the run; pages identical byte for byte across independent
boots are far more likely to be fixed setup.

Offline. Compares two capture directories.
"""
import json
import sys

PAGE = 0x4000


def render_pages(directory, half):
    try:
        pj = json.load(open("%s/%s/pages.json" % (directory, half)))
    except FileNotFoundError:
        return {}
    pages = pj["pages"] if isinstance(pj, dict) and "pages" in pj else pj
    blob = open("%s/%s/pages.bin" % (directory, half), "rb").read()
    out = {}
    for rec in pages:
        dva = rec["dva"]
        dva = int(dva, 0) if isinstance(dva, str) else int(dva)
        if (dva >> 42) & 1:
            continue
        out[dva] = blob[rec["capture_offset"]:rec["capture_offset"] + PAGE]
    return out


left, right = sys.argv[1], sys.argv[2]
print("A: %s" % left.split("/")[-1])
print("B: %s" % right.split("/")[-1])

for half in ("TA_0", "3D_0"):
    a, b = render_pages(left, half), render_pages(right, half)
    shared = sorted(set(a) & set(b))
    print("\n%s: %d render pages in A, %d in B, %d at the same address"
          % (half, len(a), len(b), len(shared)))
    for dva in shared:
        pa, pb = a[dva], b[dva]
        differing = sum(1 for x, y in zip(pa, pb) if x != y)
        nonzero = sum(1 for x in pa if x)
        verdict = "identical" if differing == 0 else "%d/%d bytes differ" % (differing, PAGE)
        print("   %#014x  %-22s  (%d nonzero bytes in A)" % (dva, verdict, nonzero))
