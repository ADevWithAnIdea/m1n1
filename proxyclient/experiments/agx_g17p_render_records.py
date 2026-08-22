# SPDX-License-Identifier: MIT
"""Test whether all dense render pages are 5-byte records differing only in phase.

One page reaches 100% tag coverage at stride 5 phase 0. The others show the same pattern by
eye at a different starting offset, which is a claim worth checking rather than asserting:
for each page the best phase is searched and reported with its coverage.
"""
import json
import struct
import sys
from collections import Counter

D = sys.argv[1]
pj = json.load(open(D + '/pages.json'))
pages = pj['pages'] if isinstance(pj, dict) and 'pages' in pj else pj
blob = open(D + '/pages.bin', 'rb').read()
PAGE = 0x4000
TAGS = {0x02, 0x82}

def as_int(x):
    return int(x, 0) if isinstance(x, str) else int(x)

for rec in sorted(pages, key=lambda r: as_int(r['dva'])):
    dva = as_int(rec['dva'])
    if (dva >> 42) & 1:
        continue
    body = blob[rec['capture_offset']:rec['capture_offset'] + PAGE]
    nz = sum(1 for b in body if b)
    if nz < 500:
        continue
    first = min(i for i in range(PAGE) if body[i])
    last = max(i for i in range(PAGE) if body[i]) + 1
    best = None
    for phase in range(5):
        start = first + phase
        idx = range(start, last - 5, 5)
        n = len(idx)
        if not n:
            continue
        hit = sum(1 for i in idx if body[i] in TAGS)
        # A record is <tag> <u16 le> 00 00; check the two pad bytes too.
        pad = sum(1 for i in idx if body[i + 3] == 0 and body[i + 4] == 0)
        if best is None or hit / n > best[1]:
            best = (phase, hit / n, pad / n, n)
    phase, hit, pad, n = best
    vals = [struct.unpack_from('<H', body, i + 1)[0]
            for i in range(first + phase, last - 5, 5)
            if body[i] in TAGS]
    print('%#014x first +%#06x  best phase %d: %.1f%% tagged, %.1f%% padded, %d records'
          % (dva, first, phase, hit * 100, pad * 100, n))
    if vals:
        c = Counter(vals)
        rising = sum(1 for a, b in zip(vals, vals[1:]) if b >= a)
        print('    16-bit field: %d distinct, min %#x max %#x, %.0f%% non-decreasing'
              % (len(c), min(vals), max(vals), 100 * rising / max(1, len(vals) - 1)))
        print('    first values: %s' % ' '.join('%#x' % v for v in vals[:12]))
