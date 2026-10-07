#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent complete-image audit for the bounded render-root probe."""
import argparse
import json
from pathlib import Path
import struct


def audit(directory):
    state = json.loads((directory / 'pending_growth.json').read_text())
    boot = json.loads((directory / 'boot.json').read_text())
    probe = state['native_render']
    assert state['passed'] and probe['passed'] and state['source_only']
    assert not boot['capture_read_audit'] and not boot['capture_write_audit']
    counts = state['triangles']
    assert counts in ([1, 2], [400017, 400000])
    if counts == [1, 2]:
        assert not state['growth']['replies']
    else:
        from audit_g17p_pending_growth import audit as audit_growth
        audit_growth(directory)
        assert probe['growth_root']['root_pa'] == probe['roots'][1]
    assert state['aggregate_pending'] and state['before_outputs_zero']
    assert state['prior_unchanged'] and probe['installed_before_second_producer']
    assert probe['table_before'] == probe['table_after']
    roots = struct.unpack('<4Q', bytes.fromhex(probe['table_before']))
    for index, root in enumerate(probe['roots']):
        assert roots[index * 2] & 0x0000ffffffffc000 == root
        assert roots[index * 2] & 1 and roots[index * 2] >> 48 == index + 1
    assert len(set(probe['roots'])) == 2
    assert len(probe['outputs']) == 18
    ranges = []
    for index, row in enumerate(probe['outputs']):
        expected = bytearray(65536)
        if index < 16:
            count = counts[index // 8]
            for offset in (32516, 32520):
                struct.pack_into('<f', expected, offset, count * (index % 8 + 1) / 8)
        elif index == 16:
            expected[:] = struct.pack('<f', 0.25) * 16384
        else:
            expected[:16384] = bytes([0x5a]) * 16384
        output = (directory / ('native_render_output_%02d.bin' % index)).read_bytes()
        guard = (directory / ('native_render_guard_%02d.bin' % index)).read_bytes()
        assert output == expected and guard == bytes([0xa0 + index]) * 65536
        assert row['exact'] and row['guard_unchanged']
        ranges.extend((row['pa'], row['guard']))
    for index, left in enumerate(ranges):
        assert left % 16384 == 0
        assert all(abs(left - right) >= 65536 for right in ranges[index + 1:])
    for index in range(2):
        body = (directory / ('pending_growth_timestamp_%d.bin' % index)).read_bytes()
        values = struct.unpack_from('<4Q', body)
        assert len(body) == 16384 and not any(body[32:])
        assert 0 < values[0] < values[1] and 0 < values[2] < values[3]
    for work in state['staged']:
        assert work['pending']
        assert all(queue['done'] == queue['read'] == 3 and queue['write'] == 6
                   for queue in work['queues'].values())
    for work in probe['fences'] + [state['fence']]:
        assert work['signaled'] and work['error'] is None
    for index, identity in enumerate(probe['prepublication_selectors'], 1):
        for kind in ('tiling', 'fragment'):
            assert identity[kind]['context'] == (
                1 if probe['mode'] in ('integrated', 'baseline', 'registers-only') else index)
            assert all(value >> 8 == (1 if probe['mode'] == 'baseline' else index)
                       for value in identity[kind]['stamps'])
    return dict(directory=str(directory), mode=probe['mode'], complete_outputs=18,
                unchanged_guards=18, captured_bytes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(audit(parser.parse_args().directory), sort_keys=True))
