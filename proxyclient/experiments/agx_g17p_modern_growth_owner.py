#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Select a source pool ID, then test unmodified production binding/growth.

Only the initial source allocation's owner scalar is selected here. Descriptor
binding, registration, allocation, replies and completion use driver code.
"""
import json
import os
from pathlib import Path
import struct

import agx_g17p_modern_partial as partial
from m1n1.agx import g17p_growth, g17p_render_startup


def main():
    owner = int(os.getenv('G17P_PROBE_POOL_OWNER', '1'), 0)
    if owner not in (0, 1):
        raise ValueError('bounded pool owner discriminator accepts only 0/1')
    for name in ('ACK', 'NAMESPACE', 'POSITIVE', 'DESCRIPTOR'):
        if os.getenv('G17P_PROBE_POOL_' + name) == '1':
            raise ValueError('retired pool override: ' + name)
    original_early = g17p_render_startup.G17PFirstRender.early_state
    original_validate = g17p_growth.validate_growth_request
    state = dict(owner=owner, requests=[], source_only=True, driver_binding=True)
    artifact = None

    def save():
        if artifact is not None:
            (artifact / 'growth_owner_probe.json').write_text(json.dumps(state, indent=2) + '\n')

    def early(startup, prepared):
        nonlocal artifact
        artifact = Path(startup.boot.LAST_ARTIFACT)
        address = startup.boot.SUBMISSION_ADDRESSES['descriptor_shared_object'] + 0xc
        submitter = prepared['submitter']
        if struct.unpack('<I', submitter.read(address, 4))[0] != 0:
            raise RuntimeError('source partial owner preimage is not zero')
        submitter.write(address, struct.pack('<I', owner))
        startup.boot.u.inst('dsb sy')
        state.update(address=address, before=0, after=owner)
        save()
        restore = original_early(startup, prepared)
        print('GROWTH OWNER: selected source pool %d; production binding and allocator' % owner,
              flush=True)
        return restore

    def validate(request, counter, **kwargs):
        if not state['requests'] or state['requests'][-1]['counter'] != counter:
            state['requests'].append(dict(counter=counter, raw=bytes(request).hex(),
                                          words=struct.unpack('<18I', request)))
        save()
        return original_validate(request, counter, **kwargs)

    g17p_render_startup.G17PFirstRender.early_state = early
    g17p_growth.validate_growth_request = validate
    os.environ['G17P_MODERN_PARTIAL_ONE_VARYING'] = '1'
    os.environ['G17P_MODERN_PARTIAL_TRIANGLES'] = '200000'
    os.environ['G17P_REACTIVE_TVB_GROWTH'] = (
        '0' if os.getenv('G17P_PROBE_POOL_STATIC') == '1' else '1')
    try:
        return partial.main()
    finally:
        save()
        g17p_render_startup.G17PFirstRender.early_state = original_early
        g17p_growth.validate_growth_request = original_validate


if __name__ == '__main__':
    raise SystemExit(main())
