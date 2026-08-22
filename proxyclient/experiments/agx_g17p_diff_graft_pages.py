# SPDX-License-Identifier: MIT
"""Find what a graft overwrites besides the submission itself.

The abort happens during device-control setup, before any work is processed, so the graft is
changing state that path depends on. The graft writes whole 16 KiB pages, and a page can hold
several channels' queue descriptors, so this compares each captured page against the snapshot's
copy and reports which byte ranges differ and whether the submission's own objects explain them.
"""
import json
import struct
import sys

SNAP = sys.argv[1]
CAP = sys.argv[2]
PAGE = 0x4000

manifest = json.load(open(SNAP + '/manifest.json'))
# ram.bin is a concatenation of captured pages indexed by a mapping's blob_index,
# not addressed by physical address.
ram = open(SNAP + '/ram.bin', 'rb')

def val(x):
    return int(x, 0) if isinstance(x, str) else int(x)

# Map va -> pa for the firmware context.
fw = {}
for group in manifest['root_mappings']:
    if group.get('root_ctx_id') == 64 and group.get('selector') == 1:
        for m in group['mappings']:
            fw[val(m['va'])] = m

target = json.load(open(CAP + '/target.json'))
pj = json.load(open(CAP + '/pages.json'))
pages = pj['pages'] if isinstance(pj, dict) and 'pages' in pj else pj
blob = open(CAP + '/pages.bin', 'rb').read()

q = (target.get('queues') or [{}])[0]
own = {}
if q.get('queue_dva'):
    own[val(q['queue_dva'])] = ('queue descriptor', 0xc0)
if q.get('state_dva'):
    own[val(q['state_dva'])] = ('queue state', 0x80)
if q.get('inner_dva'):
    own[val(q['inner_dva'])] = ('entry array', 33 * 8)
own[val(target['outer_dva'])] = ('outer record', 0x18)

print('capture channel %s, %d pages\n' % (target.get('channel'), len(pages)))

for rec in sorted(pages, key=lambda r: val(r['dva'])):
    dva = val(rec['dva'])
    if not (dva >> 42) & 1:
        continue
    m = fw.get(dva)
    if m is None:
        print('%#014x  not mapped in the snapshot (graft creates it)' % dva)
        continue
    if m.get('blob_index') is None:
        print('%#014x  mapped but no captured contents' % dva)
        continue
    ram.seek(int(m['blob_index']) * PAGE)
    original = ram.read(PAGE)
    captured = blob[rec['capture_offset']:rec['capture_offset'] + PAGE]
    if len(original) != PAGE:
        print('%#014x  snapshot copy unavailable' % dva)
        continue
    # Contiguous differing ranges.
    runs = []
    i = 0
    while i < PAGE:
        if original[i] != captured[i]:
            j = i
            while j < PAGE and original[j] != captured[j]:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    total = sum(b - a for a, b in runs)
    print('%#014x  %d differing bytes in %d runs' % (dva, total, len(runs)))
    for a, b in runs[:12]:
        addr = dva + a
        explained = None
        for base, (name, size) in own.items():
            if base <= addr < base + size:
                explained = name
                break
        print('     +%#06x..+%#06x (%4d bytes) at %#014x  %s'
              % (a, b, b - a, addr, explained or '*** NOT part of this submission ***'))
    if len(runs) > 12:
        print('     ... %d more runs' % (len(runs) - 12))
