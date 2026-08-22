# SPDX-License-Identifier: MIT
"""What, outside a work descriptor, names the parameter-buffer state?

Firmware binds it before any work runs and refuses a different one, and the device-control config
objects do not mention it. So something else does. This resolves the packed shared object's nested
pages and then searches the whole firmware context for anything pointing at any of them.
"""
import collections
import pathlib
import struct
import sys

sys.path.insert(0, '/Users/user/asahi_re/m1n1/proxyclient')
sys.path.insert(0, '/Users/user/asahi_re/m1n1/proxyclient/experiments')

from agx_g17p_render_objects import Roots, load_snapshot

import importlib.util
import types

directory = pathlib.Path('/Users/user/asahi_re/m1n1/proxyclient/m1n1/agx')
package = types.ModuleType('g17ppkg')
package.__path__ = [str(directory)]
sys.modules['g17ppkg'] = package
for name in ('g17p', 'g17p_submission'):
    spec = importlib.util.spec_from_file_location('g17ppkg.' + name, directory / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules['g17ppkg.' + name] = module
    setattr(package, name, module)
    spec.loader.exec_module(module)
build = sys.modules['g17ppkg.g17p_submission']

SNAPSHOT = pathlib.Path('/Users/user/asahi_re/artifacts/agx_g17p/'
                        'pre_work_0x83_v2_20260724_193713')
FIRMWARE = (1, 64, 1)
POOL_A, PACKED, POOL_B, ZERO = (0xfffffc20c0828100, 0xfffffc20c0868000,
                                0xfffffc20c0838080, 0xfffffc20c083a800)

manifest, ram = load_snapshot(SNAPSHOT)
roots = Roots(manifest, ram)

packed, packed_root = roots.read(PACKED, 0x100)
if packed is None:
    print('the packed shared object is not in the snapshot; listing roots that hold '
          'anything near it')
    for identity, pages in sorted(roots.by_root.items()):
        near = [dva for dva in pages if 0xfffffc20c0800000 <= dva < 0xfffffc20c0900000]
        if near:
            print('  root %s holds %d pages in that range, e.g. %s'
                  % (identity, len(near), ['%#x' % d for d in sorted(near)[:4]]))
    raise SystemExit(0)
print('packed shared object found in root %s' % (packed_root,))

offsets = build.SHARED_OBJECT_POINTER_OFFSETS
nested = {}
for index, offset in enumerate(offsets):
    value = struct.unpack_from('<Q', packed, offset)[0]
    nested['nested_%d' % index] = value
    print('packed +%#04x = %#014x' % (offset, value))

targets = {POOL_A: 'record pool A', PACKED: 'packed shared object',
           POOL_B: 'record pool B', ZERO: 'zero shared object'}
for name, value in nested.items():
    if value:
        targets[value] = name
pages = {addr & ~0x3fff for addr in targets}

print()
print('searching the firmware context for references')
referrers = collections.defaultdict(list)
for dva, page in roots.by_root.get(FIRMWARE, {}).items():
    if dva in pages:
        continue
    for offset in range(0, len(page) - 8, 4):
        value = struct.unpack_from('<Q', page, offset)[0]
        if value in targets:
            referrers[dva].append((offset, value, targets[value]))
        elif value and (value & ~0x3fff) in pages:
            referrers[dva].append((offset, value, 'inside ' + targets.get(
                value & ~0x3fff, 'a bound page')))

if not referrers:
    print('  nothing outside those pages points at any of them')
for dva, hits in sorted(referrers.items()):
    print('  %#014x: %d references' % (dva, len(hits)))
    for offset, value, label in hits[:6]:
        print('      +%#06x = %#014x  %s' % (offset, value, label))
