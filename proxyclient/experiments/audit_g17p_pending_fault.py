#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the bounded completed-prefix / anonymous command-fetch fault contract."""
import argparse
import json
from pathlib import Path
import struct


def audit(directory):
    state = json.loads((directory / 'pending_fault.json').read_text())
    boot = json.loads((directory / 'boot.json').read_text())
    assert not boot['capture_read_audit'] and not boot['capture_write_audit']
    assert state['source_only'] and state['zero_capture'] and state['injected']
    assert state['kind'] == 'command-fetch' and state['completed_prefix'] == 1
    assert state['fault_index'] in (1, 2)
    assert state['retained_backing'] and state['fault_leaf_still_unmapped']
    assert state['device_lost'] and state['all_staged_fences_terminal']
    assert state['staged_count'] == 3 and len(state['outputs']) == 3
    assert state['prefix_fence']['signaled'] and state['prefix_fence']['error'] is None
    aggregate = state['aggregate']
    assert aggregate['signaled'] and aggregate['error'] == -5
    assert len(aggregate['commands']) == 2
    assert len(set(aggregate['metadata']['command_indices'])) == 2
    physical = []
    for index, row in enumerate(state['outputs']):
        expected = (struct.pack('<64f', *(2000.25 + 129 * index + lane for lane in range(64)))
                    + bytes(16384 - 256)) if index == 0 else bytes(16384)
        assert row['index'] == index and row['cpu_matches']
        assert (directory / ('pending_before_%d.bin' % index)).read_bytes() == expected
        assert (directory / ('pending_after_%d.bin' % index)).read_bytes() == expected
        fence = row['fence']
        assert fence['signaled'] and fence['error'] == (None if index == 0 else -5)
        if index:
            assert fence['terminal_reason'] == 'unattributed-command-fault'
            assert aggregate['commands'][index - 1]['metadata']['submission_ordinal'] == \
                fence['metadata']['submission_ordinal']
        physical.append(row['pa'])
    assert len(set(physical)) == 3 and all(pa % 16384 == 0 for pa in physical)
    stamps = (directory / 'pending_timestamps.bin').read_bytes()
    assert len(stamps) == 16384 and stamps[16:] == bytes(16384 - 16)
    start, end = struct.unpack_from('<QQ', stamps)
    assert 0 < start < end
    assert state['timestamps'] == [[start, end], [0, 0], [0, 0]]
    leases = state['lease_window']
    assert len(leases) == 2 and all(row['state'] == 'quarantined' for row in leases)
    assert {row['owner']['ordinal'] for row in leases} == {
        row['metadata']['submission_ordinal'] for row in aggregate['commands']}
    reports = [bytes.fromhex(row['record_hex'])
               for name, ring in state['reports'].items() if name.endswith('_ch13')
               for row in ring.get('records', ())]
    assert reports == [struct.pack('<4I', 4, 0, 0, 0xffffffff) + bytes(56)]
    closed = state.get('close_after_fault')
    if closed is not None:
        assert not closed['queue_released'] and closed['deferred_bos'] == 26
        assert all(closed[key] for key in ('closed_handles', 'closed_queue',
            'cpu_maps_retained', 'output_mappings_unchanged',
            'physical_outputs_unchanged', 'vm_destroy_rejected'))
    return dict(directory=str(directory), complete_prefix_outputs=1,
                fault_index=state['fault_index'], quarantined_commands=2,
                closed_backing_retained=closed is not None, captured_bytes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(audit(parser.parse_args().directory), sort_keys=True))
