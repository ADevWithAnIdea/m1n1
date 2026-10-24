#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare production Rust bindings with every write in the native65 trace.

This is a host-only layout/protocol check. The input is the completed native
Metal65 reference, including full observed wrappers and startup MMIO history.
It compiles the actual Linux binding implementation, uses observed scratch
addresses as semantic inputs, and compares all780 emitted writes byte-for-byte.
Passing this check does not qualify kernel allocation or resource recycling.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--linux', type=Path, required=True)
parser.add_argument('--capture', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
source = args.linux.resolve() / 'drivers/gpu/drm/asahi/scheduled_execution_g16c.rs'
native = json.loads((args.capture / 'console-sixtyfive-v1.json').read_text())
assert native['native_gpu_output_verified'] and native['guest_temporary_directory_removed']
assert native['guest_binary_verified'] and native['single_user_verified']
assert native['guest_cpu_counts'] == {'ncpu': 16, 'activecpu': 16}
assert native['live_Metal_queues'] == 65
observed = json.loads((args.capture / 'observed-publications.json').read_text())
assert len(observed) == 65 and not any('observation_error' in row for row in observed)
rows = []
for row in observed:
    for publication in row['publications']:
        for item in publication['items']:
            if item['kind'] != 15:
                continue
            wrapper = bytes.fromhex(item['wrapper'])
            rows.append((struct.unpack_from('<H', wrapper, 0x18)[0], item['scratch_low']))
assert len(rows) == 65 and [grid for grid, _ in rows] == list(range(65))
assert len({scratch for _, scratch in rows}) == 65
history = json.loads((args.capture / 'startup-history.json').read_text())
assert history['single_user'] and not history['truncated']
args.output.mkdir(parents=True, exist_ok=False)
code = '#![allow(dead_code)]\nuse std::io::Write;\n'
code += f'#[path={json.dumps(str(source))}]mod wire;\nfn main(){{\n'
for grid, address in rows:
    code += (f'for(o,w,v)in wire::BindingG16C::compute({grid},{address}).unwrap().transactions(){{'
        'let mut out=std::io::stdout().lock();'
        'out.write_all(&(o as u32).to_le_bytes()).unwrap();'
        'out.write_all(&[w]).unwrap();out.write_all(&v.to_le_bytes()).unwrap();}\n')
code += ('assert!(wire::BindingG16C::compute(128,0x4000).is_none());'
    'assert!(wire::BindingG16C::compute(255,0x4000).is_none());}\n')
rust = args.output / 'bindings.rs'
binary = args.output / 'bindings'
rust.write_text(code)
subprocess.run(['rustc', '--edition=2021', '-Dwarnings', str(rust), '-o', str(binary)], check=True)
actual = subprocess.check_output([str(binary.resolve())])
assert len(actual) == 65 * 12 * 13
sgx = history['aperture'][0]
writes = [w for w in history['writes'] if not w['before_init']
    and w['address'] - sgx in (0xd06030, 0x4090, 0x4098, 0x21068, 0x21070)]
expected = b''.join(struct.pack('<IBQ', w['address'] - sgx, w['width'], w['value']) for w in writes)
assert actual == expected
(args.output / 'transactions.bin').write_bytes(actual)
sha = lambda data: hashlib.sha256(data).hexdigest()
proof = dict(native65_complete_transactions_equal_production_Rust=True,
    register_writes=780, observed_grid_range='0..64', invalid128_and255_rejected=True,
    source_sha256=sha(source.read_bytes()), transactions_sha256=sha(actual),
    native_history_sha256=sha((args.capture / 'startup-history.json').read_bytes()),
    physical_engine_count_claim=False, kernel_allocation_or_recycling_qualified=False)
(args.output / 'summary.json').write_text(json.dumps(proof, indent=2) + '\n')
print('PASS65 complete production Rust bindings match all780 native writes, including start bank64')
