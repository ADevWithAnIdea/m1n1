#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two async, distinct-output jobs from our offline Mesa arithmetic shader."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m1n1.g16c import uapi
from m1n1.g16c.memory import GPU_SHARED_RW

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('capture', type=Path)
p.add_argument('output', type=Path)
p.add_argument('--balanced', action='store_true',
    help='use two million-iteration jobs so either independent worker may publish first')
a = p.parse_args()
m = json.loads((a.capture / 'manifest.json').read_text())
assert m['offline_only'] and not m['gpu_execution'] and m['apple_binary_pages'] == 0
raw = (a.capture / 'cmdbuf.bin').read_bytes()
assert hashlib.sha256(raw).hexdigest() == m['cmdbuf_sha256']
c, = uapi.parse_command_buffer(raw)
assert c.header.cmd_type == 1 and len(raw) == 72
images = {}
objects = []
for o in m['objects']:
    b = (a.capture / o['filename']).read_bytes()
    assert len(b) == o['size'] and hashlib.sha256(b).hexdigest() == o['sha256']
    images[o['handle']] = b
    objects.append((o['handle'], o['flags'], len(b)))
binds = [uapi.drm_asahi_gem_bind_op(flags=2 | (4 if r['attributes'] == GPU_SHARED_RW else 0),
    handle=r['handle'], offset=r['offset'], range=r['size'], addr=r['address']) for r in m['bindings']]
def base(handle):
    rows = {r['address'] - r['offset'] for r in m['bindings'] if r['handle'] == handle}
    assert len(rows) == 1
    return rows.pop()
rootbase, uniformbase, outputbase = base(13), base(11), base(10)
assert struct.unpack_from('<QQQ', images[13]) == (rootbase + 0xc0, uniformbase, outputbase)
iterations, = struct.unpack_from('<I', images[11])
assert iterations == 1000000 and len(images[10]) == 16384 and images[10][:128] == b'\xa5' * 128
def literal32(dst, value):
    return bytes((((dst & 15) << 4) | 12, 0x80 | (value & 127), ((dst >> 4) << 6) | 2,
        (value >> 24) & 254, (value >> 6) & 30, (value >> 9) & 12, (value >> 13) & 255, (value >> 21) & 15))
assert images[13][0x100:0x110] == literal32(2, rootbase & 0xffffffff) + literal32(3, rootbase >> 32)
stream = bytearray(images[14][:48])
assert c.payload.cdm_ctrl_stream_base == base(14)
encoded, = struct.unpack_from('<Q', stream, 8)
assert ((encoded & 0xffffffff) << 6) | ((encoded >> 32 & 0x3fffffff) << 40) == rootbase + 0x100
out, uniform, table, cdm = 0x2000000000, 0x2000100000, (1 << 40) + 0x2000000, 0x2ffe000000
root = bytearray(images[13])
struct.pack_into('<QQQ', root, 0, table + 0xc0, uniform, out)
root[0x100:0x110] = literal32(2, table & 0xffffffff) + literal32(3, table >> 32)
second_iterations = iterations if a.balanced else 1
ubo = bytearray(images[11]); struct.pack_into('<I', ubo, 0, second_iterations)
struct.pack_into('<Q', stream, 8, (((table + 0x100) >> 6) & 0xffffffff) |
    ((0x40000000 | ((table + 0x100) >> 40)) << 32))
for handle, address, b in ((100, out, images[10]), (101, uniform, ubo), (102, table, root),
                            (103, cdm, bytes(stream).ljust(16384, b'\0'))):
    assert all(address + len(b) <= op.addr or op.addr + op.range <= address for op in binds)
    images[handle] = bytes(b); objects.append((handle, 2, len(b)))
    binds.append(uapi.drm_asahi_gem_bind_op(flags=6, handle=handle, range=len(b), addr=address))
second = uapi.drm_asahi_cmd_compute.from_bytes(c.payload.to_bytes())
second.cdm_ctrl_stream_base, second.cdm_ctrl_stream_end = cdm, cdm + 48
commands = b''.join(uapi.drm_asahi_cmd_header(1, 64, 0xffff, 0xffff).to_bytes() + cmd.to_bytes()
                    for cmd in (c.payload, second))
metadata = struct.pack('<8I', 0x384f4347, 2 if a.balanced else 1, len(objects), len(binds), len(commands), 10, 100, iterations)
metadata += b''.join(struct.pack('<IIQ', *o) for o in objects)
metadata += b''.join(op.to_bytes() for op in binds) + commands
a.output.mkdir(parents=True, exist_ok=False)
(a.output / 'inputs.bin').write_bytes(metadata)
for handle, b in images.items():
    (a.output / f'gem-{handle}.bin').write_bytes(b)
for handle, steps in ((10, iterations), (100, second_iterations)):
    expected = bytearray(images[handle])
    for i in range(16):
        v = 0x5a110000 ^ i
        for j in range(steps):
            v = (((v << 7) | (v >> 25)) + 0x9e3779b9 + j) & 0xffffffff
        struct.pack_into('<I', expected, i * 4, v)
    (a.output / f'expected-gem-{handle}.bin').write_bytes(expected)
report = dict(own_mesa_resources=True, apple_binary_pages=0, gpu_execution=False,
    source_capture=str(a.capture), source_manifest_sha256=hashlib.sha256((a.capture/'manifest.json').read_bytes()).hexdigest(),
    iterations=[iterations, second_iterations], output_handles=[10, 100], output_words=16,
    independent_CPU_oracle=True, original_GEMs_exact=True,
    relocated_own_launcher_pointer_literals=True,
    files={f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in a.output.iterdir()})
(a.output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: two own-Mesa jobs, bounded CPU oracles and disjoint outputs; offline only')
