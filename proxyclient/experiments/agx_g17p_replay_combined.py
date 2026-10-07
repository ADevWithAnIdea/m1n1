#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay one held native combined-workload render and check all eight images."""
import argparse
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('snapshot', type=Path)
parser.add_argument('--resource-log', type=Path, required=True)
parser.add_argument('--output-root', type=Path, required=True)
args = parser.parse_args()
snapshot = args.snapshot.resolve()
output = args.output_root.resolve()
manifest = json.loads((snapshot / 'manifest.json').read_text())
held = manifest['held_native_producer_stores']
if len(held) != 2 or {x['channel'] for x in held} != {'TA_2', '3D_2'}:
    raise ValueError('replay requires the complete held native render publication')
images = {int(n): int(address, 16) for n, address in re.findall(
    r'G17P_COMBINED_RESOURCE image(\d+)=0x([0-9a-f]+)', args.resource_log.read_text())}
if set(images) != set(range(8)):
    raise ValueError('missing exact native image addresses')

# Reserve proxy scratch above all captured caller backing. The underlying
# helper adds its 128-MiB m1n1 allowance to this explicit base.
env = dict(os.environ, M1N1HEAP='10080000000')
heap_start, heap_end = 0x10088000000, 0x100c8000000
if any(heap_start <= int(row['original_pa']) < heap_end
       for row in manifest['blob_pages'] + manifest['table_page_records']):
    raise ValueError('captured backing overlaps replay scratch heap')
repo = Path(__file__).resolve().parents[2]
command = [sys.executable, str(repo / 'proxyclient/experiments/agx_g17p_replay_initdata.py'),
           '--snapshot', str(snapshot), '--output-root', str(output),
           '--replay-first-work', '--resume-post-control',
           '--defer-work-channel', 'TA_2', '--defer-work-channel', '3D_2',
           '--use-captured-work-message', '--wait-for-work-events', '1',
           '--watch-context', '1', '--watch-render-from-start',
           '--require-render-change', '--timeout', '15']
for base in images.values():
    for offset in range(0, 0x10000, 0x4000):
        command += ['--watch-render-dva', hex(base + offset)]
output.mkdir(parents=True, exist_ok=True)
existing = set(output.glob('replay_first_work_original_pa_attempt_*'))
with (output / 'replay.log').open('w') as log:
    result = subprocess.run(command, cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT)
created = set(output.glob('replay_first_work_original_pa_attempt_*')) - existing
if len(created) != 1:
    raise RuntimeError('replay did not retain exactly one attempt')
attempt, = created
report = []
for target, base in sorted(images.items()):
    after = b''.join((attempt / ('render_watch_%x_after.bin' % (base + offset))).read_bytes()
                     for offset in range(0, 0x10000, 0x4000))
    before = b''.join((attempt / ('render_watch_%x_before.bin' % (base + offset))).read_bytes()
                      for offset in range(0, 0x10000, 0x4000))
    expected = bytearray(0x10000)
    expected[0x7f04:0x7f0c] = struct.pack('<f', 16384.0 * (target + 1)) * 2
    bad = [i for i, (actual, want) in enumerate(zip(after, expected)) if actual != want]
    row = dict(target=target, dva=base, bad_bytes=len(bad), first_bad=bad[:1],
               complete=len(after) == 0x10000, before_all_a5=before == b'\xa5' * 0x10000,
               changed_bytes=sum(a != b for a, b in zip(before, after)))
    report.append(row)
    print(row, flush=True)
(attempt / 'combined_image_oracle.json').write_text(json.dumps(report, indent=2) + '\n')
passed = result.returncode == 0 and all(row['complete'] and row['before_all_a5']
                                       and not row['bad_bytes'] for row in report)
print('G17P_COMBINED_REPLAY_' + ('PASS' if passed else 'FAIL'), attempt, flush=True)
raise SystemExit(0 if passed else 1)
