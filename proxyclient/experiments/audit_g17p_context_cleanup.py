#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit full caller outputs and bounded cleanup-page reuse from saved data."""
import argparse
import json
from pathlib import Path
import struct


def audit(directory):
    read = lambda name: json.loads((directory / (name + '.json')).read_text())
    boot, batch, rebind = read('boot'), read('modern_batch'), read('modern_rebind')
    cleanup = read('source_context_cleanup')
    assert not boot['capture_read_audit'] and not boot['capture_write_audit']
    assert batch['count'] == 2 and batch['all_pages_exact'] and not batch['errors']
    assert batch['fence']['error'] is None
    assert len(batch['fence']['metadata']['command_indices']) == 2
    expected = []
    for index, row in enumerate(batch['outputs']):
        graph = row['graph']
        body = struct.pack('<64f', *(2000.25 + graph * 129 + lane for lane in range(64)))
        expected.append(body + bytes(16384 - len(body)))
        assert (directory / ('modern_batch_%03d.bin' % index)).read_bytes() == expected[-1]
    assert (directory / 'modern_rebind_old_output.bin').read_bytes() == expected[0]
    new = struct.pack('<64f', *(value + 4096 for value in struct.unpack_from('<64f', expected[0])))
    assert (directory / 'modern_rebind_new_output.bin').read_bytes() == new + bytes(16384 - 256)
    assert all(rebind[key] for key in ('exact', 'previous_unchanged', 'owned', 'timestamps_ok', 'sync_ok'))
    assert rebind['error'] is None and rebind['old_pa'] != rebind['new_pa']
    stamps = (directory / 'modern_rebind_timestamps.bin').read_bytes()
    values = struct.unpack_from('<6Q', stamps)
    assert all(a < b for a, b in zip(values, values[1:])) and values[0] > 0
    assert len(stamps) == 16384 and not any(stamps[48:])
    assert cleanup['source_only'] and cleanup['cleanup_receipt']['state'] == 'consumed'
    command = cleanup['commands'][0]
    body = bytes.fromhex(command['body_hex'])
    control = bytes.fromhex(cleanup['before']['channel_control']['hex'])
    assert body == struct.pack('<II', 0x14, 0) + bytes(control[i] for i in (0x26, 0, 1, 4)) + \
        struct.pack('<Q', cleanup['control']) + bytes(44)
    assert command['after']['control_counters'] == [command['publication']['target']] * 3
    if 'maintenance_receipt' in cleanup:
        maintenance = cleanup['maintenance_receipt']
        assert maintenance['state'] == 'consumed' and len(maintenance['records']) == 6
        target = command['publication']['target']
        for row, (kind, phase) in zip(maintenance['records'],
                                     ((k, p) for k in range(3) for p in (1, 2))):
            assert row['kind'] == kind and row['phase'] == phase and row['state'] == 'consumed'
            assert bytes.fromhex(row['body_hex']) == struct.pack('<3I', 0x1b, kind, phase) + bytes(52)
            assert row['publication']['before'] == [target] * 3
            target += 1
            assert row['publication']['target'] == target
        assert cleanup['after_maintenance']['control_counters'] == [target] * 3
    pages, physical = [], [row['pa'] for row in batch['outputs']] + [rebind['new_pa']]
    for kind, sentinel in (('descriptor', 0xa7), ('context', 0xa8)):
        row = read('cleanup_' + kind + '_relocation')
        assert row['old_guard_unchanged'] and row['cleanup_consumed']
        assert row['relocated_bytes'] == row['reused_bytes'] == 16384
        assert row['old_pa'] != row['new_pa'] and row['freed_to_heap'] == 0
        assert row['high'] in cleanup['cleanup_receipt']['retained_resources']
        assert row['low'] in cleanup['cleanup_receipt']['retained_resources']
        assert (directory / ('cleanup_' + kind + '_old_guard.bin')).read_bytes() == bytes([sentinel]) * 16384
        physical.extend((row['old_pa'], row['new_pa']))
        pages.append(kind)
    if (directory / 'cleanup_root_relocation.json').exists():
        row = read('cleanup_root_relocation')
        assert row['old_guard_unchanged'] and row['cleanup_consumed']
        assert row['relocated_bytes'] == row['reused_bytes'] == 16384
        assert row['old_pa'] != row['new_pa'] and row['freed_to_heap'] == 0
        assert row['old_pa'] in cleanup['cleanup_receipt']['retained_resources']
        before, after = map(bytes.fromhex, (row['table_before'], row['table_after']))
        expected = bytearray(before)
        assert len(before) == len(after) == 64 * 16 and row['slots'] == [2, 3]
        for slot in row['slots']:
            old = struct.unpack_from('<Q', before, slot * 16)[0]
            assert old >> 48 == slot and old & 0x0000ffffffffc000 == row['old_pa']
            struct.pack_into('<Q', expected, slot * 16,
                             (old & ~0x0000ffffffffc000) | row['new_pa'])
        assert after == expected
        assert (directory / 'cleanup_root_old_guard.bin').read_bytes() == bytes([0xad]) * 16384
        physical.extend((row['old_pa'], row['new_pa']))
        pages.append('root')
    for kind, sentinel in (('queue', 0xa9), ('channel_control', 0xaa),
                           ('pointers', 0xab), ('item_ring', 0xac)):
        if not (directory / ('cleanup_' + kind + '_relocation.json')).exists():
            continue
        row = read('cleanup_' + kind + '_relocation')
        assert row['old_guard_unchanged'] and row['cleanup_consumed']
        assert row['relocated_bytes'] == row['reused_bytes'] == 16384
        assert row['old_pa'] != row['new_pa'] and row['freed_to_heap'] == 0
        assert row['high'] in cleanup['cleanup_receipt']['retained_resources']
        assert row['aliases'] and row['roots'] and row['table_pages'] > 0
        mask = 0x0000ffffffffc000
        for alias in row['aliases']:
            assert alias['before'] & mask == row['old_pa']
            assert alias['after'] & mask == row['new_pa']
            assert alias['before'] & ~mask == alias['after'] & ~mask
        assert (directory / ('cleanup_' + kind + '_old_guard.bin')).read_bytes() == bytes([sentinel]) * 16384
        physical.extend((row['old_pa'], row['new_pa']))
        pages.append(kind)
    assert len(set(physical)) == len(physical) and all(not pa % 16384 for pa in physical)
    return dict(directory=str(directory), complete_outputs=3, reused_pages=pages,
                maintenance_records=len(cleanup.get('maintenance_receipt', {}).get('records', ())),
                captured_bytes=0, general_reclaim_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(audit(parser.parse_args().directory), sort_keys=True))
