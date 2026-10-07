# SPDX-License-Identifier: MIT
"""Read only explicitly inventoried caller output pages after failed startup."""
import json
from pathlib import Path
import sys
import struct

directory = Path(sys.argv[1]).resolve()
inventory = json.loads((directory / 'constructed_render_inventory.json').read_text())
pages = {row['dva']: row['pa'] for row in inventory['pages']}
outputs = [0x10000058000 + i * 0x18000 for i in range(8)]
selected = [(va, [pages[va + i * 0x4000] for i in range(4)]) for va in outputs]
from m1n1.setup import u, p, iface
if int(u.adt['/chosen'].chip_id) != 0x8140:
    raise RuntimeError('Neo-only postmortem')
if (directory / 'boot.json').exists():
    boot = json.loads((directory / 'boot.json').read_text())
    def read_dva(va, size):
        matches = [r for r in boot['allocations'] if r['va'] <= va and va + size <= r['va'] + r['size']]
        if not matches:
            raise RuntimeError('report range is not in the owned firmware arena')
        row = matches[-1]
        pa = row['pa'] + va - row['va']
        p.dc_ivac(pa, size)
        return bytes(iface.readmem(pa, size))
    ring = boot['report_channels']['primary_ch13']
    state = read_dva(ring['counters'][0]['address'], 0x24)
    head, tail = (struct.unpack_from('<I', state, offset)[0] for offset in (0, 32))
    if not 0 <= head < 256 or not 0 <= tail < 256:
        raise RuntimeError('invalid owned report interval')
    rows = []
    for i in range(min((tail - head) % 256, 16)):
        slot = (head + i) % 256
        body = read_dva(ring['records_address'] + slot * 0x48, 0x48)
        rows.append(dict(slot=slot, hex=body.hex()))
    result = dict(head=head, tail=tail, records=rows)
    (directory / 'growth_pending_reports.json').write_text(json.dumps(result, indent=2) + '\n')
    print(result)
    if '--reports-only' in sys.argv:
        raise SystemExit
for index, (va, physical) in enumerate(selected):
    body = bytearray()
    for pa in physical:
        p.dc_ivac(pa, 0x4000)
        body += iface.readmem(pa, 0x4000)
    (directory / ('failed_caller_output_%d.bin' % index)).write_bytes(body)
    print(hex(va), 'nonzero bytes', sum(value != 0 for value in body))
