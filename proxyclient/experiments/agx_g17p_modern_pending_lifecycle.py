#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Caller-owned branch/timeout and close-while-pending lifecycle probes.

The branch uses the local public G17P ISA jump encoding. No firmware
program is read or changed. Firmware objects remain on the ordinary shim path.
"""
import argparse
import os
from pathlib import Path
import struct
import sys
import tempfile
import time

import agx_g17p_modern_compute_batch as batch
from agx_g17p_modern_graphics_sequence import report_json

FD, PAGE, uapi = batch.FD, batch.PAGE, batch.uapi


def branch_program(loop=False):
    image = bytearray(batch.build_add3_code_image())
    main = bytes(image[0x3c0:0x3f8])
    # G17P jump: 0f 00 54, signed displacement48, zero link byte.
    # Hypothesized target is PC+4+displacement; +6 skips the ten-byte
    # instruction, -4 branches to itself. Always require a full-output
    # positive control before using the backward variant as a timeout probe.
    displacement = ((-4 if loop else 6) & ((1 << 48) - 1)).to_bytes(6, 'little')
    program = bytes.fromhex('0f0054') + displacement + bytes(1) + main
    struct.pack_into('<I', image, 0x340, 0x100)
    image[0x3c0:0x3c0 + len(program)] = program
    return bytes(image)


def run(loop=False, close_pending=False):
    bodies, jobs = batch.build_workloads(3)
    bodies[batch.CODE_IMAGE] = (branch_program(), False)
    sizes = {dva: (len(body) + PAGE - 1) & -PAGE for dva, (body, _) in bodies.items()}
    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), sum(sizes.values()) + 2 * PAGE)
        front = batch.DRMAsahiShim(memfd.fileno())
        if front.modern_enable():
            raise RuntimeError('modern entrypoint failed')
        driver = front.modern
        vm = driver.create_vm(FD, batch.modern.VM_END - batch.modern.VM_KERNEL_MIN_SIZE, batch.modern.VM_END)
        mapping, offset = {}, 0
        for handle, (dva, (body, writable)) in enumerate(bodies.items(), 1):
            bo = driver.create_bo(FD, handle, offset, sizes[dva])
            offset += sizes[dva]
            bo.token['map'][:len(body)] = body
            mapping[dva] = driver.bind(FD, vm.vm_id, uapi.drm_asahi_gem_bind_op(
                uapi.DRM_ASAHI_BIND_READ | (uapi.DRM_ASAHI_BIND_WRITE if writable else 0),
                handle, 0, sizes[dva], dva))
        stamps = driver.create_bo(FD, len(bodies) + 1, offset, PAGE)
        offset += PAGE
        timestamp = driver.bind_object(FD, uapi.drm_asahi_gem_bind_object(
            uapi.DRM_ASAHI_BIND_OBJECT_OP_BIND, uapi.DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
            stamps.handle, 0, 0, PAGE, 0, 0))
        queue = driver.create_queue(FD, vm.vm_id, 0, batch.USC_BASE)
        streams = [batch.command(timestamp.object_handle, cdm_base=job['cdm'],
            attachments=((job['output'], PAGE),), timestamp_offset=index * 16)
            for index, job in enumerate(jobs)]
        prefix, _ = driver.submit(FD, queue.queue_id, streams[0])
        adapter, backend = driver.adapter, front.g17p
        directory = Path(front.g17p_boot_artifact).parent
        state = dict(source_only=True, loop=loop, close_pending=close_pending,
                     prefix=prefix.snapshot(), outputs=[])
        def save():
            (directory / 'pending_lifecycle.json').write_text(report_json(state))
        if prefix.error is not None or bytes(mapping[jobs[0]['output']].bo.token['map']) != jobs[0]['expected']:
            raise RuntimeError('caller branch fallthrough control did not execute exactly')
        if loop:
            driver.bind(FD, vm.vm_id, uapi.drm_asahi_gem_bind_op(
                uapi.DRM_ASAHI_BIND_UNBIND, 0, 0, PAGE, batch.CODE_IMAGE))
            bo = driver.create_bo(FD, len(bodies) + 2, offset, PAGE)
            bo.token['map'][:] = branch_program(True)
            mapping[batch.CODE_IMAGE] = driver.bind(FD, vm.vm_id, uapi.drm_asahi_gem_bind_op(
                uapi.DRM_ASAHI_BIND_READ, bo.handle, 0, PAGE, batch.CODE_IMAGE))
        for module in tuple(sys.modules.values()):
            if (getattr(module, '__file__', '') or '').endswith('agx_g17p_boot.py'):
                module.READ_CRASH = True
                module.CRASH_OUTPUT_DIR = directory
                module.CRASH_CAPTURE_TAG = 'pending_lifecycle'
        original_submit, original_finish = adapter._submit_compute, adapter._finish_compute
        original_notify = backend.submitter.notify
        staged, notifications = [], []
        def stage(*args, **kwargs):
            work = original_submit(*args, **kwargs)
            staged.append(work)
            return work
        adapter._submit_compute = stage
        adapter._finish_compute = lambda work, **_kwargs: work['fence']
        backend.submitter.notify = lambda value: notifications.append(value)
        pending, _ = driver.submit(FD, queue.queue_id, b''.join(streams[1:]))
        adapter._submit_compute, adapter._finish_compute = original_submit, original_finish
        backend.submitter.notify = original_notify
        state.update(pending_before=not pending.signaled(), staged=len(staged), notifications=notifications)
        for index, job in enumerate(jobs):
            body = backend.space.read(mapping[job['output']].bo.token['pa'], PAGE)
            (directory / ('lifecycle_before_%d.bin' % index)).write_bytes(body)
            if body != (job['expected'] if index == 0 else bytes(PAGE)):
                raise RuntimeError('lifecycle output changed before work kick')
        if not state['pending_before'] or len(staged) != 2:
            raise RuntimeError('lifecycle suffix was not pending')
        if close_pending:
            bos = tuple(driver.file(FD).bos.values())
            driver.destroy_queue(FD, queue.queue_id)
            for bo in bos:
                driver.destroy_bo(FD, bo.handle)
            state['closed_pending'] = dict(queue_released=queue.lifetime.released,
                deferred_bos=len(driver.deferred_bos), bo_count=len(bos),
                cpu_maps_retained=all(bo.token['map'] is not None for bo in bos),
                handles_removed=not driver.file(FD).bos and not driver.file(FD).queues)
            if (queue.lifetime.released or len(driver.deferred_bos) != len(bos) or
                    not state['closed_pending']['cpu_maps_retained']):
                raise RuntimeError('pending close released reachable storage')
        save()
        original_notify(0x0a)
        start = time.monotonic()
        for work in staged:
            original_finish(work, copyback=False)
        state.update(host_finish_elapsed=time.monotonic() - start,
                     aggregate=pending.snapshot(), prefix_after=prefix.snapshot(),
                     device_lost=adapter.device_lost,
                     commands=[work['fence'].snapshot() for work in staged])
        # An explicit bounded watchdog observation, not an execution settle
        # delay: distinguish the host's 200ms deadline from firmware recovery.
        if loop and pending.error is not None:
            until = time.monotonic() + 5
            while adapter.fatal_notification is None and time.monotonic() < until:
                backend.event_pump()
            state['watchdog_observed_seconds'] = time.monotonic() - start
        for index, job in enumerate(jobs):
            bo = mapping[job['output']].bo
            body = backend.space.read(bo.token['pa'], PAGE)
            (directory / ('lifecycle_after_%d.bin' % index)).write_bytes(body)
            state['outputs'].append(dict(index=index, pa=bo.token['pa'], exact=body == job['expected'], zero=not any(body)))
        (directory / 'lifecycle_timestamps.bin').write_bytes(backend.space.read(stamps.token['pa'], PAGE))
        state.update(fatal_notification=adapter.fatal_notification,
            reports=backend.read_report_channels(limit=256),
            leases=adapter.compute_runtime['publication_window'].snapshot())
        if close_pending:
            driver.reap_deferred()
            state['closed_after'] = dict(queue_released=queue.lifetime.released,
                deferred_bos=len(driver.deferred_bos),
                cpu_maps_closed=all(bo.token['map'] is None for bo in bos))
        state['pass'] = (prefix.error is None and state['outputs'][0]['exact'] and
            (pending.error is not None and all(row['zero'] for row in state['outputs'][1:]) if loop else
             pending.error is None and all(row['exact'] for row in state['outputs'])))
        if close_pending:
            state['pass'] &= (state['closed_after']['queue_released'] and
                state['closed_after']['deferred_bos'] == 0 and state['closed_after']['cpu_maps_closed'])
        save()
        print('PENDING LIFECYCLE: %s pass=%s' % (directory, state['pass']), flush=True)
        return 0 if state['pass'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--loop', action='store_true')
    parser.add_argument('--close-pending', action='store_true')
    args = parser.parse_args()
    if args.loop and args.close_pending:
        parser.error('run timeout and successful pending close separately')
    raise SystemExit(run(args.loop, args.close_pending))
