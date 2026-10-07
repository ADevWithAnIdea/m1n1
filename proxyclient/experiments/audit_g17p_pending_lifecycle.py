#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit source pending-close/timeout results without using fixture oracles."""
import argparse
import json
from pathlib import Path
import struct


def audit(directory):
    state = json.loads((directory / 'pending_lifecycle.json').read_text())
    boot = json.loads((directory / 'boot.json').read_text())
    assert not boot['capture_read_audit'] and not boot['capture_write_audit']
    assert state['source_only'] and state['pass'] and state['pending_before'] and state['staged'] == 2
    assert state['prefix']['error'] is state['prefix_after']['error'] is None
    pages = []
    for index, row in enumerate(state['outputs']):
        expected = struct.pack('<64f', *(2000.25 + 129 * index + lane for lane in range(64))) + bytes(16384 - 256)
        before = (directory / ('lifecycle_before_%d.bin' % index)).read_bytes()
        after = (directory / ('lifecycle_after_%d.bin' % index)).read_bytes()
        assert before == (expected if index == 0 else bytes(16384))
        assert after == (bytes(16384) if state['loop'] and index else expected)
        pages.append(row['pa'])
    assert len(pages) == len(set(pages)) == 3
    stamps = (directory / 'lifecycle_timestamps.bin').read_bytes()
    assert len(stamps) == 16384 and not any(stamps[48:])
    values = struct.unpack_from('<6Q', stamps)
    assert 0 < values[0] < values[1]
    if state['loop']:
        assert state['device_lost'] and state['aggregate']['error'] in (-110, -19, -5)
        assert all(row['error'] is not None for row in state['commands'])
        assert state['leases']
    else:
        assert state['aggregate']['error'] is None
        assert all(a < b for a, b in zip(values, values[1:]))
    if state['close_pending']:
        before, after = state['closed_pending'], state['closed_after']
        assert before['handles_removed'] and before['cpu_maps_retained'] and not before['queue_released']
        assert before['deferred_bos'] == before['bo_count'] > 0
        assert after['queue_released'] and after['cpu_maps_closed'] and not after['deferred_bos']
    return dict(directory=str(directory), complete_outputs=1 if state['loop'] else 3,
                timeout_error=state['aggregate']['error'], pending_close=state['close_pending'], captured_bytes=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(audit(parser.parse_args().directory), sort_keys=True))
