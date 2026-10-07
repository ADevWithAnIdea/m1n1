#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently reconstruct full same-DVA native render-VM output images."""
import argparse
import json
from pathlib import Path
import struct

PAGE, SIZE, USC = 16384, 65536, 0x10000000000


def audit(directory):
    state = json.loads((directory / 'native_render_vms.json').read_text())
    boot = json.loads((directory / 'boot.json').read_text())
    assert state['passed'] and state['source_only']
    assert not boot['capture_read_audit'] and not boot['capture_write_audit']
    assert len(state['warmups']) == len(state['waves']) == 2
    limits = set(state.get('expected_limits', ()))
    assert limits <= {0, 1}
    ranges, outputs = [], 0

    def witness(row, owner, count, *, limited=False):
        nonlocal outputs
        assert row['owner'] == owner and row['context'] == (1, 4)[owner]
        assert row['prior_unchanged']
        assert row.get('limited', False) == limited
        expected = {USC + 0x8000000: struct.pack('<f', .25) * 16384,
                    USC + 0x8010000: bytes([0x5a]) * 16384 + bytes(49152)}
        for color in range(8):
            image = bytearray(SIZE)
            for pixel in (0x7efc, 0x7f00):
                struct.pack_into('<f', image, pixel + (2 + 2 * owner) * 4,
                                 count * (color + 1) / 8)
            expected[USC + 0x58000 + color * 0x18000] = bytes(image)
        assert len(row['outputs']) == 10
        assert {item['dva'] for item in row['outputs']} == set(expected)
        for item in row['outputs']:
            body = (directory / item['file']).read_bytes()
            assert len(body) == SIZE and item['copyback']
            if not limited:
                assert body == expected[item['dva']] and item['exact']
            ranges.append((item['pa'], SIZE))
            outputs += int(not limited)
        assert len(row['timestamps']) == 1
        stamp = row['timestamps'][0]
        body = (directory / stamp['file']).read_bytes()
        values = struct.unpack_from('<4Q', body)
        assert len(body) == PAGE and body[32:] == bytes(PAGE - 32)
        assert 0 < values[0] < values[1] and 0 < values[2] < values[3]
        assert list(values) == stamp['values'] and stamp['exact']
        ranges.append((stamp['pa'], PAGE))

    for owner, row in enumerate(state['warmups']):
        witness(row, owner, 1)
    root_bytes = state['waves'][0]['before_roots']
    roots = struct.unpack('<4Q', bytes.fromhex(root_bytes))
    assert roots[0] & 0x0000ffffffffc000 != roots[2] & 0x0000ffffffffc000
    for slot in (1, 2):
        for entry in roots[(slot - 1) * 2:slot * 2]:
            assert entry & 1 and entry >> 48 == slot
    for index, wave in enumerate(state['waves']):
        wave_limits = limits if index == 0 else set()
        assert wave['before_zero'] == [True, True]
        assert wave['before_roots'] == wave['pre_kick_roots'] == wave['after_roots'] == root_bytes
        assert [(row['owner'], row['context'], row['pair'], row['pending'])
                for row in wave['staged']] == [(1, 1, 0, True), (4, 2, 1, True)]
        assert len(wave['fences']) == 2
        assert all(row['signaled'] and row['error'] == (-12 if owner in wave_limits else None)
                   for owner, row in enumerate(wave['fences']))
        assert len(wave['outputs']) == len(wave['sentinels']) == 2
        assert all(row['exact'] and row['foreign_absent'] for row in wave['sentinels'])
        pins = wave.get('failed_timestamp_pins', ())
        if 'failed_timestamp_pins' in wave:
            assert len(pins) == len(wave_limits)
            assert {pin['owner'] for pin in pins} == wave_limits
            assert len({pin['address'] for pin in pins}) == len(pins)
        for pin in pins:
            assert pin['owner'] in wave_limits and pin['unbound'] and pin['mapped'] and pin['retained']
            assert -12 in pin['error_fences'] and pin['next_address'] != pin['address']
            assert pin['before'] == pin['after'] == [[pin['pa'], PAGE]]
        for owner, row in enumerate(wave['outputs']):
            witness(row, owner, wave['triangles'][owner], limited=owner in wave_limits)
        growth = wave['growth']
        assert growth['pool_vm_ids'] == {'0': 1, '1': 2} and not growth['failed']
        counters, counts = [0, 0], [8, 8]
        for row in growth['replies']:
            owner, counter = row['pool_id'], row['counter']
            vm = owner + 1
            assert row['vm_id'] == vm and counter == counters[owner]
            raw = bytes.fromhex(row['request_hex'])
            scheduling = struct.unpack_from('<I', raw, 16)[0], struct.unpack_from('<Q', raw, 64)[0]
            assert scheduling in (((0, 1),) if owner == 0 else ((0, 1), (2, 4)))
            request = bytearray(72)
            struct.pack_into('<5I', request, 0, 6, vm, owner, counter, scheduling[0])
            struct.pack_into('<2Q', request, 56, 1, scheduling[1])
            assert raw == request
            assert bytes.fromhex(row['command_hex']) == struct.pack('<5I', 8,
                int(not row['negative_reply']), owner, vm, counter) + bytes(44)
            assert row['old_count'] == counts[owner] and not row['captured_reply_bytes']
            counts[owner] += len(row['block_dvas'])
            assert row['new_count'] == counts[owner]
            counters[owner] += 1
        assert growth['pool_counters'] == dict(zip(('0', '1'), counters))
        assert {int(key) for key in growth['limit_reports']} == limits
        for owner in limits:
            report = growth['limit_reports'][str(owner)]
            raw = bytes.fromhex(report['record_hex'])
            assert struct.unpack_from('<4I', raw) == (7, 0, 1, owner * 2 + 1)
            node, cookie, zero, descriptor, event, vm, pool = struct.unpack_from('<7Q', raw, 16)
            assert node in (0xfffffc2000000100, 0xfffffc2000000200) and cookie and not zero
            assert descriptor == report['fragment_dva']
            assert (event, vm, pool) == (owner * 2 + 1, owner + 1, owner)
            assert report['generation'] == 2 + owner
            assert report['completion'] == 'report-consumed-without-command'
    # Growth snapshots are cumulative; count physical allocations only once.
    for row in state['waves'][-1]['growth']['replies']:
        if row['allocation_bytes']:
            ranges.append((row['new_physical'], row['allocation_bytes']))
    ranges.sort()
    assert all(pa % PAGE == 0 for pa, size in ranges)
    assert all(pa + size <= following for (pa, size), (following, _) in zip(ranges, ranges[1:]))
    return dict(directory=str(directory), complete_outputs=outputs,
                stable_native_slots=[1, 2], growth_counts=counts, limits=sorted(limits),
                failed_timestamp_pins=sum(len(wave.get('failed_timestamp_pins', ()))
                                          for wave in state['waves']), captured_bytes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(audit(parser.parse_args().directory), sort_keys=True))
