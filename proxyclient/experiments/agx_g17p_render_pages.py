# SPDX-License-Identifier: MIT
"""Structural look at captured render pages, with the alignment bug fixed.

The first pass scanned 8-byte words at 4-byte alignment. Over an array of small qwords such
as 0xb4 that manufactures a word 0xb400000000, which lands inside the render address range,
so every reference it reported was an artifact of its own scan. Pointers are 8-byte aligned;
only aligned words are considered here.
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
LOW, HIGH = 0x1000000000, 0x2ffffff8000

def as_int(x):
    return int(x, 0) if isinstance(x, str) else int(x)

render = []
for rec in pages:
    dva = as_int(rec['dva'])
    if (dva >> 42) & 1:
        continue
    render.append((dva, blob[rec['capture_offset']:rec['capture_offset'] + PAGE]))
render.sort()
known = {d for d, _ in render}

print('=== aligned references only ===')
any_ref = False
for dva, body in render:
    refs = Counter()
    for i in range(0, PAGE, 8):
        w = struct.unpack_from('<Q', body, i)[0]
        if LOW <= w < HIGH and (w & 0x3fff) or (LOW <= w < HIGH):
            refs[w & ~(PAGE - 1)] += 1
    if refs:
        any_ref = True
        print('  %#014x -> %s' % (dva, ', '.join(
            '%#014x%s x%d' % (p, ' [captured]' if p in known else '', c)
            for p, c in sorted(refs.items())[:8])))
if not any_ref:
    print('  none: no 8-byte-aligned word in any captured render page is a render address.')
    print('  The pages do not point at each other, so the register array is the only')
    print('  thing naming them and a capture cannot be extended by following them.')

print('\n=== record shape of the dense pages ===')
for dva, body in render:
    nz = sum(1 for b in body if b)
    if nz < 500:
        continue
    end = max(i for i in range(PAGE) if body[i]) + 1
    # Leading-byte histogram over plausible small record strides.
    print('  %#014x  nonzero %5d  populated to +%#06x' % (dva, nz, end))
    for stride in (4, 5, 6, 8):
        tags = Counter(body[i] for i in range(0, end - stride, stride))
        top = tags.most_common(4)
        cover = sum(c for _, c in top) / max(1, len(range(0, end - stride, stride)))
        print('     stride %d: leading bytes %s  (top4 = %.0f%% of records)'
              % (stride, ' '.join('%02x:%d' % t for t in top), cover * 100))
    print('     head: %s' % body[:32].hex(' '))

print('\n=== the 0x40-stride record page ===')
for dva, body in render:
    nz = sum(1 for b in body if b)
    if not (0 < nz <= 100):
        continue
    recs = []
    for off in range(0, PAGE, 0x40):
        chunk = body[off:off + 0x40]
        if any(chunk):
            a, b = struct.unpack_from('<II', chunk, 0)
            recs.append((off, a, b, chunk[8:].rstrip(b'\0')))
    if recs and all(r[2] == recs[0][2] for r in recs):
        print('  %#014x: %d records at 0x40 stride, second word constant %#x'
              % (dva, len(recs), recs[0][2]))
        print('     first words: %s' % ' '.join('%#x' % r[1] for r in recs))
        print('     range %#x..%#x, all bytes past +8 zero: %s'
              % (min(r[1] for r in recs), max(r[1] for r in recs),
                 all(not r[3] for r in recs)))

print('\n=== the small-integer array page ===')
for dva, body in render:
    words = [struct.unpack_from('<Q', body, i)[0] for i in range(0, PAGE, 8)]
    nzi = [i for i, w in enumerate(words) if w]
    if not nzi or len(nzi) > 60:
        continue
    lo, hi = nzi[0], nzi[-1]
    vals = words[lo:hi + 1]
    if all(v < 0x10000 for v in vals):
        c = Counter(vals)
        print('  %#014x: %d qwords at +%#06x..+%#06x, all < 0x10000'
              % (dva, len(vals), lo * 8, hi * 8))
        print('     most common: %s' % ' '.join('%#x:x%d' % t for t in c.most_common(6)))
        print('     distinct %d, min %#x, max %#x' % (len(c), min(vals), max(vals)))
