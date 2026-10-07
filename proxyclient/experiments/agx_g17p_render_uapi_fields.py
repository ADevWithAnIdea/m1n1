#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise independently visible modern render fields on one G17P boot."""

import os
import struct
import tempfile

from agx_g17p_render_uapi_timestamps import (
    CANARY,
    EXPECTED_PIXEL,
    FD,
    OUTPUT_DVA,
    OUTPUT_HANDLE,
    PAGE_SIZE,
    TIMESTAMP_BO_HANDLE,
    TIMESTAMP_OFFSETS,
    command,
)
from m1n1.agx.g17p_uapi import (
    DRM_ASAHI_BIND_OBJECT_OP_BIND,
    DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_WRITE,
    DRM_ASAHI_CMD_RENDER,
    DRM_ASAHI_RENDER_DBIAS_IS_INT,
    DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES,
    DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS,
    drm_asahi_attachment,
    drm_asahi_cmd_render,
    drm_asahi_gem_bind_object,
    drm_asahi_gem_bind_op,
)
from m1n1.agx import g17p
from m1n1.agx.shim import DRMAsahiShim


SAMPLER_HANDLE = 3
QUERY_HANDLE = 4
SECOND_OUTPUT_HANDLE = 5
SAMPLER_DVA = 0x1500010000
QUERY_DVA = 0x1500020000
SECOND_OUTPUT_DVA = OUTPUT_DVA + PAGE_SIZE


def render_command(timestamp_object, *, output_dva=OUTPUT_DVA,
                   sampler=False, query=False,
                   dbias_is_int=False):
    attachment = drm_asahi_attachment(output_dva, PAGE_SIZE, 0, 0)
    payload = drm_asahi_cmd_render()
    payload.flags = DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
    if dbias_is_int:
        payload.flags |= DRM_ASAHI_RENDER_DBIAS_IS_INT
    payload.vdm_ctrl_stream_base = 0x1000018000
    payload.isp_scissor_base = 0x100019A0000
    payload.isp_dbias_base = 0x10001AF8000
    payload.isp_oclqry_base = QUERY_DVA if query else 0
    payload.ppp_multisamplectl = 0x88
    payload.ppp_ctrl = 0x202
    payload.width_px = 64
    payload.height_px = 64
    payload.layers = 1
    payload.utile_width_px = 32
    payload.utile_height_px = 32
    payload.samples = 1
    payload.sample_size_B = 1
    payload.bg.usc = 0x01990240
    payload.bg.rsrc_spec = 0x40
    payload.eot.usc = 0x01990640
    payload.partial_bg.usc = payload.bg.usc
    payload.partial_bg.rsrc_spec = payload.bg.rsrc_spec
    payload.partial_eot.usc = payload.eot.usc
    payload.partial_eot.rsrc_spec = payload.eot.rsrc_spec
    if sampler:
        payload.sampler_heap = SAMPLER_DVA
        payload.sampler_count = 1
    payload.ts_vtx.start.handle = timestamp_object
    payload.ts_vtx.start.offset = TIMESTAMP_OFFSETS["vertex_start"]
    payload.ts_vtx.end.handle = timestamp_object
    payload.ts_vtx.end.offset = TIMESTAMP_OFFSETS["vertex_end"]
    payload.ts_frag.start.handle = timestamp_object
    payload.ts_frag.start.offset = TIMESTAMP_OFFSETS["fragment_start"]
    payload.ts_frag.end.handle = timestamp_object
    payload.ts_frag.end.offset = TIMESTAMP_OFFSETS["fragment_end"]
    return (
        command(DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS, attachment.to_bytes())
        + command(DRM_ASAHI_CMD_RENDER, payload.to_bytes())
    )


def expected_output():
    return (
        EXPECTED_PIXEL * (0x1000 // len(EXPECTED_PIXEL))
        + bytes(PAGE_SIZE - 0x1000)
    )


def main():
    if len(os.sys.argv) != 1:
        raise SystemExit("agx_g17p_render_uapi_fields.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), 6 * PAGE_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        from agx_g17p_compute import drain_boot_group

        drain_boot_group(front, backend)
        vm = front.modern.create_vm(FD, 0x7000000000, 0x7800000000)
        output_bo = front.modern.create_bo(
            FD, OUTPUT_HANDLE, 0, PAGE_SIZE)
        second_output_bo = front.modern.create_bo(
            FD, SECOND_OUTPUT_HANDLE, 5 * PAGE_SIZE, PAGE_SIZE)
        timestamp_bo = front.modern.create_bo(
            FD, TIMESTAMP_BO_HANDLE, PAGE_SIZE, 2 * PAGE_SIZE)
        sampler_bo = front.modern.create_bo(
            FD, SAMPLER_HANDLE, 3 * PAGE_SIZE, PAGE_SIZE)
        query_bo = front.modern.create_bo(
            FD, QUERY_HANDLE, 4 * PAGE_SIZE, PAGE_SIZE)

        for bo, address, flags in (
                (output_bo, OUTPUT_DVA,
                 DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE),
                (second_output_bo, SECOND_OUTPUT_DVA,
                 DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE),
                (sampler_bo, SAMPLER_DVA, DRM_ASAHI_BIND_READ),
                (query_bo, QUERY_DVA,
                 DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE)):
            front.modern.bind(FD, vm.vm_id, drm_asahi_gem_bind_op(
                flags, bo.handle, 0, PAGE_SIZE, address))

        object_bind = drm_asahi_gem_bind_object(
            DRM_ASAHI_BIND_OBJECT_OP_BIND,
            DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
            timestamp_bo.handle, 0, 0, 2 * PAGE_SIZE, 0, 0)
        timestamp_object = front.modern.bind_object(FD, object_bind)
        def internal_render_queue(priority):
            # Queue creation must obey the upstream 39-bit userspace window.
            # This focused compatibility harness then selects the retained
            # backend-owned 1 TiB USC graph, just as the C transport oracle
            # does after validating Mesa's ordinary queue and command.
            queue = front.modern.create_queue(
                FD, vm.vm_id, priority, 0x1000000000)
            queue.usc_exec_base = 0x10000000000
            queue.token["usc_exec_base"] = queue.usc_exec_base
            return queue

        queues = {
            "low": internal_render_queue(0),
            "medium": internal_render_queue(1),
        }

        sampler_bo.token["map"][:8] = bytes.fromhex(
            "0000000000000000")
        query_initial = struct.pack("<Q", CANARY) * (PAGE_SIZE // 8)

        cases = (
            ("medium", second_output_bo, SECOND_OUTPUT_DVA,
             {"query": True, "dbias_is_int": True}),
            ("low", output_bo, OUTPUT_DVA, {"sampler": True}),
        )
        for name, selected_output, output_dva, kwargs in cases:
            output_bo.token["map"][:] = bytes(PAGE_SIZE)
            second_output_bo.token["map"][:] = bytes(PAGE_SIZE)
            query_bo.token["map"][:] = query_initial
            timestamp_initial = struct.pack("<Q", CANARY) * (
                2 * PAGE_SIZE // 8)
            timestamp_bo.token["map"][:] = timestamp_initial

            fence, commands = front.modern.submit(
                FD, queues[name].queue_id,
                render_command(
                    timestamp_object.object_handle,
                    output_dva=output_dva, **kwargs))
            output = bytes(selected_output.token["map"][:PAGE_SIZE])
            untouched_output = (
                second_output_bo if selected_output is output_bo else output_bo)
            timestamps = bytes(timestamp_bo.token["map"][:2 * PAGE_SIZE])
            changed = [
                offset for offset in range(0, 2 * PAGE_SIZE, 8)
                if timestamps[offset:offset + 8]
                != timestamp_initial[offset:offset + 8]
            ]
            state = commands[0].hardware_state
            pair = int(backend.last_submission["queue_pair"])
            expected_profile = g17p.queue_priority_profile(
                queues[name].priority)
            actual_profiles = []
            for _kind, (_entry, hardware_queue) in sorted(
                    backend.muxed_queue_pair(pair).items()):
                record = backend._read_dva(
                    hardware_queue.address, g17p.QUEUE_DESCRIPTOR_SIZE)
                actual_profiles.append((
                    struct.unpack_from(
                        "<I", record, g17p.QUEUE_PRIORITY)[0],
                    struct.unpack_from(
                        "<I", record, g17p.QUEUE_UNK_2C)[0],
                    struct.unpack_from(
                        "<Q", record, g17p.QUEUE_UNK_30)[0],
                    struct.unpack_from(
                        "<I", record, g17p.QUEUE_UNK_38)[0],
                    struct.unpack_from(
                        "<I", record, g17p.QUEUE_PRIO5)[0],
                ))
            expected_tuple = tuple(expected_profile[field] for field in (
                "priority", "unk_2c", "unk_30", "unk_38", "prio5"))
            print(
                "RENDER UAPI QUEUE %s id=%d pair=%d output_exact=%d "
                "isolated=%d fence=%d profile=%r sampler=(%#x,%d) "
                "query=%#x flags=%#x ts_changed=%r" % (
                    name, queues[name].queue_id, pair,
                    output == expected_output(),
                    bytes(untouched_output.token["map"][:PAGE_SIZE])
                    == bytes(PAGE_SIZE), fence.signaled(), actual_profiles,
                    state.sampler_heap, state.sampler_count,
                    state.oclqry_base, state.flags, changed),
                flush=True,
            )
            if output != expected_output():
                raise RuntimeError("%s render output was not exact" % name)
            if bytes(untouched_output.token["map"][:PAGE_SIZE]) != bytes(PAGE_SIZE):
                raise RuntimeError("%s render changed the other queue's output" % name)
            if not fence.signaled():
                raise RuntimeError("%s render fence did not signal" % name)
            if actual_profiles != [expected_tuple, expected_tuple]:
                raise RuntimeError(
                    "%s firmware priority profile mismatch: %r != %r" % (
                        name, actual_profiles, expected_tuple))
            if changed != sorted(TIMESTAMP_OFFSETS.values()):
                raise RuntimeError("%s timestamp writes were not exact" % name)
            if bytes(query_bo.token["map"][:PAGE_SIZE]) != query_initial:
                raise RuntimeError(
                    "%s changed an unused occlusion-query array" % name)

        for queue in queues.values():
            front.modern.destroy_queue(FD, queue.queue_id)
            if not queue.lifetime.released:
                raise RuntimeError(
                    "completed queue %d was not physically released" %
                    queue.queue_id)
        for handle in (
                OUTPUT_HANDLE, SECOND_OUTPUT_HANDLE, TIMESTAMP_BO_HANDLE,
                SAMPLER_HANDLE, QUERY_HANDLE):
            if not front.modern.destroy_bo(FD, handle):
                raise RuntimeError("failed to close GEM handle %d" % handle)
        front.modern.destroy_vm(FD, vm.vm_id)

        print(
            "RENDER UAPI QUEUE PRIORITY/ISOLATION/LIFECYCLE PASS",
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
