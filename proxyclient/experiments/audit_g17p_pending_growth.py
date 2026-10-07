#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent full-buffer audit of the bounded two-pool caller fixture."""
import argparse
import json
from pathlib import Path
import struct


def audit(directory):
    state = json.loads((directory / 'pending_growth.json').read_text())
    boot = json.loads((directory / 'boot.json').read_text())
    assert state['passed'] and state['source_only']
    limits = set(state.get('expected_limits', ()))
    assert limits <= {0, 1}
    assert not boot['capture_read_audit'] and not boot['capture_write_audit']
    assert state['aggregate_pending'] and state['before_outputs_zero']
    assert state['prior_unchanged'] and state['fence']['signaled']
    assert state['fence']['error'] == (-12 if limits else None)
    assert len(state['staged']) == 2 and {row['pool'] for row in state['staged']} == {0, 1}
    for work in state['staged']:
        assert work['pending']
        for queue in work['queues'].values():
            assert queue['done'] == queue['read'] == 3 and queue['write'] == 6
    ranges = []
    for index, row in enumerate(state['outputs']):
        expected = bytearray(65536)
        if index < 16:
            counts = state.get('triangles', [400017, 400000])
            assert counts in ([400017, 400000], [1048576, 400000])
            count = counts[index // 8]
            # This caller shifts its viewport two pixels right.
            for offset in (32516, 32520):
                struct.pack_into('<f', expected, offset, count * (index % 8 + 1) / 8)
        elif index == 16:
            expected[:] = struct.pack('<f', 0.25) * 16384
        elif index == 17:
            expected[:16384] = bytes([0x5a]) * 16384
        else:
            raise AssertionError('unexpected output')
        output = (directory / ('pending_growth_output_%02d.bin' % index)).read_bytes()
        assert len(output) == 65536
        owner = 0 if index < 8 else 1
        if owner not in limits:
            assert output == expected and row['exact']
        assert row['owned'] and row['copyback']
        ranges.append((row['pa'], 65536))
    assert len(state['outputs']) == 18
    for index in range(2):
        body = (directory / ('pending_growth_timestamp_%d.bin' % index)).read_bytes()
        values = struct.unpack_from('<4Q', body)
        assert len(body) == 16384 and not any(body[32:])
        assert all(0 < values[i] < values[i + 1] for i in (0, 2))
        assert state['timestamps'][index]['exact']
    counters, counts = {0: 0, 1: 0}, {0: 8, 1: 8}
    native_pair = state.get('native_render', {}).get('mode') == 'native'
    expected_vms = {0: 1, 1: 2 if native_pair else 1}
    if 'pool_vm_ids' in state['growth']:
        assert {int(key): value for key, value in state['growth']['pool_vm_ids'].items()} == expected_vms
    for reply in state['growth']['replies']:
        owner, counter = reply['pool_id'], reply['counter']
        assert counter == counters[owner]
        vm = expected_vms[owner]
        assert reply.get('vm_id', 1) == vm
        request = bytearray(struct.pack('<4I', 6, vm, owner, counter) + bytes(40) +
                            struct.pack('<2Q', 1, 1))
        actual = bytes.fromhex(reply['request_hex'])
        scheduling = (struct.unpack_from('<I', actual, 16)[0],
                      struct.unpack_from('<Q', actual, 64)[0])
        # A second-owner request can switch back to the sequential pair after
        # the older job retires, even within the same pending wave.
        assert scheduling in (((0, 1), (2, 4)) if owner == 1 else ((0, 1),))
        struct.pack_into('<I', request, 16, scheduling[0])
        struct.pack_into('<Q', request, 64, scheduling[1])
        assert actual == request
        assert bytes.fromhex(reply['command_hex']) == struct.pack(
            '<5I', 8, int(not reply['negative_reply']), owner, vm, counter) + bytes(44)
        assert reply['old_count'] == counts[owner] and not reply['captured_reply_bytes']
        counts[owner] += len(reply['block_dvas'])
        assert reply['new_count'] == counts[owner]
        if reply['allocation_bytes']:
            ranges.append((reply['new_physical'], reply['allocation_bytes']))
        counters[owner] += 1
    assert all(value > 0 for value in counters.values())
    assert not state['growth']['failed'] and not state['growth']['captured_reply_bytes']
    if not limits:
        assert [(row['pool_id'], row['mask']) for row in state['growth']['terminals']] == [
            (0, 3), (1, 12), (0, 3), (1, 12)]
    else:
        assert {int(key) for key in state['growth']['limit_reports']} == limits
        identities = {row['pool_id']: row for row in state['limit_owners']}
        for owner, work in enumerate(state['work_fences']):
            assert work['signaled'] and work['error'] == (-12 if owner in limits else None)
        for owner in limits:
            limit = state['growth']['limit_reports'][str(owner)]
            identity = identities[owner]
            body = bytes.fromhex(limit['record_hex'])
            assert struct.unpack_from('<4I', body) == (7, 0, 1, identity['event_slot'])
            node, cookie, zero, descriptor, event, vm, pool = struct.unpack_from('<7Q', body, 16)
            assert identity['job_list'] in (0xfffffc2000000000, 0xfffffc2000000018)
            assert node in (0xfffffc2000000100, 0xfffffc2000000200)
            assert cookie and not zero and descriptor == identity['fragment']
            assert (event, vm, pool) == (identity['event_slot'], 1, owner)
            assert limit['completion'] == 'report-consumed-without-command'
        assert len(state['recovery_draws']) == 2
        for index, draw in enumerate(state['recovery_draws'], 2):
            assert draw['triangles'] == 1 and not draw['device_lost']
            assert draw['prior_unchanged'] and draw['independent'] and draw['sync_ok']
            assert draw['fence']['signaled'] and draw['fence']['error'] is None
            for color, row in enumerate(draw['outputs']):
                expected = bytearray(65536)
                for offset in (32516, 32520):
                    struct.pack_into('<f', expected, offset, (color + 1) / 8)
                assert (directory / ('graphics_%03d_color%d.bin' % (index, color))).read_bytes() == expected
                assert row['owned'] and row['exact']
            body = (directory / ('graphics_%03d_timestamps.bin' % index)).read_bytes()
            assert len(body) == 16384 and not any(body[32:])
            values = struct.unpack_from('<4Q', body)
            assert all(0 < values[i] < values[i + 1] for i in (0, 2))
    for row in state['pool_ownership']:
        assert row['exact'] and row['counts'] == [counts[row['owner']]] * 2
        assert all(item['actual'] == item['expected'] for item in row['mappings'])
    ranges.sort()
    assert all(pa + size <= following for (pa, size), (following, _) in zip(ranges, ranges[1:]))
    return dict(directory=str(directory), complete_outputs=18 - sum(8 if owner == 0 else 10 for owner in limits),
                limits=sorted(limits), recovery_outputs=16 if limits else 0, pools=counts,
                requests=counters, captured_bytes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(audit(parser.parse_args().directory), sort_keys=True))
