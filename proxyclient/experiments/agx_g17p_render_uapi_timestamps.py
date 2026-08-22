#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove render timestamps through the unmodified modern Asahi UAPI model."""

import os
import pathlib
import struct
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"
# This focused test still names the backend-owned opening VDM/scissor/pipeline
# objects. The production UAPI resolver remains strict unless this explicit
# transition aid is enabled.
os.environ["G17P_ALLOW_INTERNAL_RENDER_POINTERS"] = "1"

from m1n1.agx.g17p_modern import PAGE_SIZE  # noqa: E402
from m1n1.agx.g17p_uapi import (  # noqa: E402
    DRM_ASAHI_BARRIER_NONE,
    DRM_ASAHI_BIND_OBJECT_OP_BIND,
    DRM_ASAHI_BIND_OBJECT_OP_UNBIND,
    DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_WRITE,
    DRM_ASAHI_CMD_RENDER,
    DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES,
    DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS,
    drm_asahi_attachment,
    drm_asahi_cmd_header,
    drm_asahi_cmd_render,
    drm_asahi_gem_bind_object,
    drm_asahi_gem_bind_op,
)
from m1n1.agx.shim import DRMAsahiShim  # noqa: E402


FD = 73
OUTPUT_HANDLE = 1
TIMESTAMP_BO_HANDLE = 2
# Keep caller-owned BOs outside the backend's fixed 0x10..0x16 retained and
# allocator ranges while staying below the advertised userspace VM ceiling.
# Matching the real-Mesa smoke target makes the field harness a direct control
# for address-dependent attachment behavior.
OUTPUT_DVA = 0x2FFFFD8000
EXPECTED_PIXEL = struct.pack("<I", 0x18060180)
CANARY = 0xA5A5A5A5A5A5A5A5
TIMESTAMP_OFFSETS = {
    "vertex_start": 0x10,
    "vertex_end": 0x18,
    "fragment_start": PAGE_SIZE + 0x20,
    "fragment_end": PAGE_SIZE + 0x28,
}


def command(command_type, payload):
    header = drm_asahi_cmd_header(
        command_type, len(payload),
        DRM_ASAHI_BARRIER_NONE, DRM_ASAHI_BARRIER_NONE)
    return header.to_bytes() + payload


def render_command(timestamp_object):
    attachment = drm_asahi_attachment(OUTPUT_DVA, PAGE_SIZE, 0, 0)
    payload = drm_asahi_cmd_render()
    payload.flags = DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
    payload.vdm_ctrl_stream_base = 0x1000018000
    payload.isp_scissor_base = 0x100019A0000
    payload.isp_dbias_base = 0x10001AF8000
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
    payload.eot.rsrc_spec = 0
    payload.partial_bg.usc = payload.bg.usc
    payload.partial_bg.rsrc_spec = payload.bg.rsrc_spec
    payload.partial_eot.usc = payload.eot.usc
    payload.partial_eot.rsrc_spec = payload.eot.rsrc_spec
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


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_render_uapi_timestamps.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), 3 * PAGE_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        if os.environ.get("G17P_MODERN_DIRECT_BOOTSTRAP") != "1":
            from agx_g17p_compute import drain_boot_group  # noqa: E402

            drain_boot_group(front, backend)
        vm = front.modern.create_vm(FD, 0x7000000000, 0x7800000000)
        output_bo = front.modern.create_bo(
            FD, OUTPUT_HANDLE, 0, PAGE_SIZE)
        timestamp_bo = front.modern.create_bo(
            FD, TIMESTAMP_BO_HANDLE, PAGE_SIZE, 2 * PAGE_SIZE)

        output_bind = drm_asahi_gem_bind_op(
            DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
            output_bo.handle, 0, PAGE_SIZE, OUTPUT_DVA)
        front.modern.bind(FD, vm.vm_id, output_bind)
        object_bind = drm_asahi_gem_bind_object(
            DRM_ASAHI_BIND_OBJECT_OP_BIND,
            DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
            timestamp_bo.handle, 0, 0, 2 * PAGE_SIZE, 0, 0)
        timestamp_object = front.modern.bind_object(FD, object_bind)
        queue = front.modern.create_queue(
            FD, vm.vm_id, 1, 0x10000000000)

        timestamp_initial = struct.pack("<Q", CANARY) * (
            2 * PAGE_SIZE // 8)
        timestamp_bo.token["map"][:] = timestamp_initial
        output_bo.token["map"][:] = bytes(PAGE_SIZE)
        counter_before = backend.u.mrs("CNTPCT_EL0")
        fence, commands = front.modern.submit(
            FD, queue.queue_id, render_command(timestamp_object.object_handle))
        counter_after = backend.u.mrs("CNTPCT_EL0")

        output = bytes(output_bo.token["map"][:PAGE_SIZE])
        expected = (
            EXPECTED_PIXEL * (0x1000 // len(EXPECTED_PIXEL))
            + bytes(PAGE_SIZE - 0x1000)
        )
        timestamp_result = bytes(timestamp_bo.token["map"][:2 * PAGE_SIZE])
        values = {
            name: struct.unpack_from("<Q", timestamp_result, offset)[0]
            for name, offset in TIMESTAMP_OFFSETS.items()
        }
        changed = [
            offset for offset in range(0, 2 * PAGE_SIZE, 8)
            if timestamp_initial[offset:offset + 8]
            != timestamp_result[offset:offset + 8]
        ]
        ordered = [values[name] for name in (
            "vertex_start", "vertex_end", "fragment_start", "fragment_end")]
        print(
            "RENDER UAPI TIMESTAMP output_exact=%d fence_signaled=%d "
            "object=%d aperture=%#x values=%r changed=%r interval=%d..%d" % (
                output == expected, fence.signaled(),
                timestamp_object.object_handle,
                timestamp_object.token["address"], values, changed,
                counter_before, counter_after),
            flush=True,
        )

        if output != expected:
            raise RuntimeError("modern UAPI render output was not exact")
        if not fence.signaled():
            raise RuntimeError("modern UAPI render fence did not signal")
        if changed != sorted(TIMESTAMP_OFFSETS.values()):
            raise RuntimeError(
                "modern UAPI timestamps changed unexpected qwords: %r" % changed)
        if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
            raise RuntimeError(
                "modern UAPI timestamps are not strictly ordered: %r" % ordered)
        if not all(counter_before <= value <= counter_after for value in ordered):
            raise RuntimeError(
                "modern UAPI timestamps escape the 1 GHz interval: %r" % ordered)
        resolved = commands[0].timestamp_objects
        if len(resolved) != 4:
            raise RuntimeError(
                "modern UAPI resolved %d timestamp references" % len(resolved))

        alias = timestamp_object.token["address"]
        unbind = drm_asahi_gem_bind_object(
            DRM_ASAHI_BIND_OBJECT_OP_UNBIND, 0, 0, 0, 0, 0,
            timestamp_object.object_handle, 0)
        front.modern.bind_object(FD, unbind)
        translated = backend.space.uat.iotranslate_root(
            backend.firmware_high_root, alias, 2 * PAGE_SIZE)
        if any(pa is not None for pa, _size in translated):
            raise RuntimeError("timestamp aperture alias survived object unbind")
        print(
            "RENDER UAPI TIMESTAMP PASS exact render, four 1 GHz writes, "
            "two-page object, alias teardown",
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
