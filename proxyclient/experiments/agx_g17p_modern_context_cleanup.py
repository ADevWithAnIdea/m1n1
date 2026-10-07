#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay measured cleanup records against an owned, completed source context.

Optional bounded descriptor relocation repurposes only the returned old page.
Consumed control records do not license general reclamation.
"""
import json
import os
from pathlib import Path
import struct
import time

import agx_g17p_modern_compute_batch as batch
from m1n1.agx.g17p_lifecycle import (
    relocate_completed_compute_page,
    relocate_completed_transport_page, relocate_completed_compute_root)


class CleanupShim(batch.DRMAsahiShim):
    def modern_enable(self):
        result = super().modern_enable()
        if result:
            return result
        adapter = self.modern.adapter
        original_pull = adapter._pull_compute_writable_bindings
        sampled = False

        def pull(vm, runtime):
            nonlocal sampled
            original_pull(vm, runtime)
            if sampled:
                for relocation in runtime.get('cleanup_relocations', []):
                    after = self.g17p.space.read(relocation['old_pa'], batch.PAGE)
                    relocation['old_guard_unchanged'] = after == bytes([relocation['guard']]) * batch.PAGE
                    artifact = Path(self.g17p_boot_artifact).parent
                    (artifact / ('cleanup_%s_old_guard.bin' % relocation['kind'])).write_bytes(after)
                    (artifact / ('cleanup_%s_relocation.json' % relocation['kind'])).write_text(
                        json.dumps(relocation, indent=2) + '\n')
                    if not relocation['old_guard_unchanged']:
                        raise RuntimeError('retired %s physical page changed after reuse' % relocation['kind'])
                    if relocation['kind'] == 'descriptor':
                        (artifact / 'cleanup_relocation.json').write_text(json.dumps(relocation, indent=2) + '\n')
                return
            sampled = True
            if adapter.device_lost or runtime["publication_window"].snapshot():
                raise RuntimeError("cleanup requires successful terminal work")
            backend = self.g17p
            artifact = Path(self.g17p_boot_artifact).parent
            native = runtime["native"]
            spec = native._queue_addresses(0)
            control = spec["channel_control"]
            transport = tuple((name, spec[name] & -batch.PAGE, guard)
                              for name, guard in (('queue', 0xa9), ('channel_control', 0xaa),
                                                  ('pointers', 0xab), ('item_ring', 0xac)))
            channel = backend.channels.entries[12]
            state = dict(control=control, commands=[], freed_bytes=0,
                         source_only=True, reclaim_qualified=False)

            def snapshot(label):
                row = dict(label=label, control_counters=backend.channels.counters(channel),
                           reports=backend.read_report_channels(limit=256))
                for name, address, size in (("channel_control", control, 0x100),
                        ("queue", runtime["queue"].address, 0xc0)):
                    body = backend._read_dva(address, size)
                    filename = "cleanup_%s_%s.bin" % (label, name)
                    (artifact / filename).write_bytes(body)
                    row[name] = dict(address=address, file=filename, hex=body.hex())
                return row

            def save():
                (artifact / "source_context_cleanup.json").write_text(
                    json.dumps(state, indent=2) + "\n")

            state["before"] = snapshot("before")
            save()
            cleanup = runtime['context_cleanup'] = adapter.begin_compute_cleanup()
            deadline = time.monotonic() + 0.25
            while not cleanup.step() and time.monotonic() < deadline:
                backend.event_pump()
            state['cleanup_receipt'] = cleanup.snapshot()
            state['commands'].append(dict(body_hex=cleanup.body.hex(),
                publication=cleanup.publication, consumed=cleanup.state == 'consumed',
                after=snapshot('after_cleanup')))
            save()
            if cleanup.state != 'consumed':
                raise RuntimeError('cleanup is not consumed; all storage remains pinned')
            if os.getenv("G17P_CLEANUP_GC") == "1":
                maintenance = adapter.begin_compute_maintenance(cleanup)
                deadline = time.monotonic() + 0.25
                completed = 0
                while not maintenance.step():
                    if maintenance.index != completed:
                        completed = maintenance.index
                        deadline = time.monotonic() + 0.25
                    if time.monotonic() >= deadline:
                        break
                    backend.event_pump()
                state['maintenance_receipt'] = maintenance.snapshot()
                state['after_maintenance'] = snapshot('after_maintenance')
                save()
                if maintenance.state != 'consumed':
                    raise RuntimeError('post-cleanup maintenance not consumed; all resources retained')
            print("SOURCE CLEANUP: measured records consumed; zero bytes freed", flush=True)
            pages = []
            if os.getenv('G17P_CLEANUP_RELOCATE_DESCRIPTOR') == '1':
                pages.append(('descriptor', native.DESCRIPTOR, native.DESCRIPTOR_LOW, 0xa7))
            if os.getenv('G17P_CLEANUP_RELOCATE_CONTEXT') == '1':
                pages.append(('context', spec['context_high'], spec['context_low'], 0xa8))
            runtime['cleanup_relocations'] = []
            for kind, high, low, guard in pages:
                page = batch.PAGE
                relocation = relocate_completed_compute_page(backend, cleanup, high=high, low=low)
                relocation.update(kind=kind, guard=guard)
                backend.space.write(relocation['old_pa'], bytes([guard]) * page)
                backend.u.proxy.dc_cvac(relocation['old_pa'], page)
                backend.u.inst('dsb sy')
                relocation['reused_bytes'] = page
                runtime['cleanup_relocations'].append(relocation)
                (artifact / ('cleanup_%s_relocation.json' % kind)).write_text(
                    json.dumps(relocation, indent=2) + '\n')
                if kind == 'descriptor':
                    runtime['cleanup_descriptor_relocation'] = relocation
                    (artifact / 'cleanup_relocation.json').write_text(json.dumps(relocation, indent=2) + '\n')
                print('SOURCE CLEANUP: old %s PA repurposed as guard' % kind, flush=True)
            selected = os.getenv('G17P_CLEANUP_RELOCATE_TRANSPORT', '')
            if selected:
                if selected not in {row[0] for row in transport} | {'all'}:
                    raise ValueError('unknown owned cleanup transport page')
                for kind, high, guard in transport:
                    if selected not in (kind, 'all'):
                        continue
                    relocation = relocate_completed_transport_page(backend, cleanup, high=high)
                    relocation.update(kind=kind, guard=guard, reused_bytes=batch.PAGE)
                    runtime['cleanup_relocations'].append(relocation)
                    backend.space.write(relocation['old_pa'], bytes([guard]) * batch.PAGE)
                    backend.u.proxy.dc_cvac(relocation['old_pa'], batch.PAGE)
                    backend.u.inst('dsb sy')
                    (artifact / ('cleanup_%s_relocation.json' % kind)).write_text(
                        json.dumps(relocation, indent=2) + '\n')
                    print('SOURCE CLEANUP: old %s PA repurposed after all-alias migration' % kind, flush=True)
            if os.getenv('G17P_CLEANUP_RELOCATE_ROOT') == '1':
                relocation = relocate_completed_compute_root(backend, cleanup, runtime['client']['space'])
                relocation.update(kind='root', guard=0xad, reused_bytes=batch.PAGE)
                runtime['cleanup_relocations'].append(relocation)
                backend.space.write(relocation['old_pa'], bytes([0xad]) * batch.PAGE)
                backend.u.proxy.dc_cvac(relocation['old_pa'], batch.PAGE)
                backend.u.inst('dsb sy')
                (artifact / 'cleanup_root_relocation.json').write_text(json.dumps(relocation, indent=2) + '\n')
                print('SOURCE CLEANUP: old compute root PA repurposed as guard', flush=True)

        adapter._pull_compute_writable_bindings = pull
        return result


if __name__ == "__main__":
    os.environ["G17P_MODERN_BATCH_COMMANDS"] = "2"
    batch.DRMAsahiShim = CleanupShim
    raise SystemExit(batch.main())
