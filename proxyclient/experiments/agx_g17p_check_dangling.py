# SPDX-License-Identifier: MIT
"""Find the null pointer the grafted submission stores through.

Firmware walks the grafted queue and stores through a pointer that is zero. The fault registers
name page 0xfffffc20c0600000 at +0x1140 and +0x1a0e. This dumps that region from both halves and
then reports, for every firmware address the captured pages reference, whether the graft supplies
it, whether the snapshot maps it, and whether its contents there are zero.
"""
import json
import struct
import sys

SNAP = sys.argv[1]
CAP = sys.argv[2]
PAGE = 0x4000
FW_TAG = 0xfffffc20 << 32

manifest = json.load(open(SNAP + '/manifest.json'))
ram = open(SNAP + '/ram.bin', 'rb')

def val(x):
    return int(x, 0) if isinstance(x, str) else int(x)

snap_fw = {}
for group in manifest['root_mappings']:
    if group.get('root_ctx_id') == 64 and group.get('selector') == 1:
        for m in group['mappings']:
            snap_fw[val(m['va'])] = m

def snapshot_page(dva):
    m = snap_fw.get(dva & ~(PAGE - 1))
    if m is None or m.get('blob_index') is None:
        return None
    ram.seek(int(m['blob_index']) * PAGE)
    return ram.read(PAGE)

captured = {}
for half in ('TA_0', '3D_0'):
    pj = json.load(open('%s/%s/pages.json' % (CAP, half)))
    pages = pj['pages'] if isinstance(pj, dict) and 'pages' in pj else pj
    blob = open('%s/%s/pages.bin' % (CAP, half), 'rb').read()
    for rec in pages:
        dva = val(rec['dva'])
        captured.setdefault(dva, (half, blob[rec['capture_offset']:
                                            rec['capture_offset'] + PAGE]))

print('=== page 0xfffffc20c0600000 around the fault offsets ===')
entry = captured.get(0xfffffc20c0600000)
if entry is None:
    print('  not captured')
else:
    half, body = entry
    for base in (0x1100, 0x1140, 0x19c0, 0x1a00):
        for off in range(base, base + 0x40, 16):
            print('  +%#06x  %s' % (off, body[off:off + 16].hex(' ')))
        print()

print('=== firmware addresses referenced by captured pages ===')
missing_unmapped = []
zero_in_snapshot = []
for dva, (half, body) in sorted(captured.items()):
    if not (dva >> 42) & 1:
        continue
    # Queue and descriptor pointers are observed at four-byte-aligned offsets
    # such as queue +0x9c and descriptor +0x44. An eight-byte walk falsely
    # certified the original targeted captures as closed.
    for i in range(0, PAGE - 7, 4):
        w = struct.unpack_from('<Q', body, i)[0]
        if (w >> 32) != 0xfffffc20:
            continue
        page = w & ~(PAGE - 1)
        if page in captured:
            continue
        snap = snapshot_page(page)
        if snap is None:
            missing_unmapped.append((dva + i, w))
        elif not any(snap):
            zero_in_snapshot.append((dva + i, w))

def summarise(name, items):
    pages = sorted({w & ~(PAGE - 1) for _, w in items})
    print('%s: %d references to %d distinct pages' % (name, len(items), len(pages)))
    for pg in pages[:14]:
        srcs = sorted({src for src, w in items if (w & ~(PAGE - 1)) == pg})[:3]
        print('    %#014x  referenced from %s'
              % (pg, ' '.join('%#x' % s for s in srcs)))

summarise('not mapped in the snapshot at all', missing_unmapped)
summarise('mapped but entirely zero in the snapshot', zero_in_snapshot)

if missing_unmapped or zero_in_snapshot:
    raise SystemExit(1)
