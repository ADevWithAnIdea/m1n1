#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove uncompressed depth/stencil load and store through the modern UAPI."""

import os
import struct
import tempfile

from agx_g17p_render_uapi_timestamps import (
    EXPECTED_PIXEL,
    FD,
    OUTPUT_DVA,
    PAGE_SIZE,
    command,
)
from m1n1.agx.g17p_uapi import (
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_WRITE,
    DRM_ASAHI_CMD_RENDER,
    DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES,
    DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS,
    drm_asahi_attachment,
    drm_asahi_cmd_render,
    drm_asahi_gem_bind_op,
)
from m1n1.agx.shim import DRMAsahiShim


OUTPUT_HANDLE = 1
DEPTH_HANDLE = 2
STENCIL_HANDLE = 3
DEPTH_DVA = 0x20000100000
STENCIL_DVA = 0x20000200000

Z_LOAD = 1 << 15
S_LOAD = 1 << 14
Z_STORE = 1 << 19
S_STORE = 1 << 18

WIDTH = 64
HEIGHT = 64
ZLS_PIXELS = (WIDTH - 1) | ((HEIGHT - 1) << 15)


def render_command(*, zls_ctrl, depth_clear, stencil_clear,
                   depth_comp=0, stencil_comp=0,
                   depth_stride=0, stencil_stride=0,
                   layers=1, samples=1, sample_size=1,
                   utile_width=32, utile_height=32,
                   multisample_control=0x88):
    attachment = drm_asahi_attachment(OUTPUT_DVA, PAGE_SIZE, 0, 0)
    payload = drm_asahi_cmd_render()
    payload.flags = DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
    payload.isp_zls_pixels = ZLS_PIXELS
    payload.vdm_ctrl_stream_base = 0x1000018000
    payload.isp_scissor_base = 0x100019A0000
    payload.isp_dbias_base = 0x10001AF8000
    payload.depth.base = DEPTH_DVA
    payload.depth.comp_base = depth_comp
    payload.depth.stride = depth_stride
    payload.stencil.base = STENCIL_DVA
    payload.stencil.comp_base = stencil_comp
    payload.stencil.stride = stencil_stride
    payload.zls_ctrl = zls_ctrl
    payload.ppp_multisamplectl = multisample_control
    payload.ppp_ctrl = 0x202
    payload.width_px = WIDTH
    payload.height_px = HEIGHT
    payload.layers = layers
    payload.utile_width_px = utile_width
    payload.utile_height_px = utile_height
    payload.samples = samples
    payload.sample_size_B = sample_size
    payload.bg.usc = 0x01990240
    payload.bg.rsrc_spec = 0x40
    payload.eot.usc = 0x01990640
    payload.partial_bg.usc = payload.bg.usc
    payload.partial_bg.rsrc_spec = payload.bg.rsrc_spec
    payload.partial_eot.usc = payload.eot.usc
    payload.partial_eot.rsrc_spec = payload.eot.rsrc_spec
    payload.isp_bgobjdepth = struct.unpack("<I", struct.pack("<f", depth_clear))[0]
    payload.isp_bgobjvals = stencil_clear
    return (
        command(DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS, attachment.to_bytes())
        + command(DRM_ASAHI_CMD_RENDER, payload.to_bytes())
    )


def color_expected():
    return EXPECTED_PIXEL * (0x1000 // 4) + bytes(PAGE_SIZE - 0x1000)


def depth_image(value):
    word = struct.pack("<f", value)
    return word * (WIDTH * HEIGHT) + bytes(PAGE_SIZE - WIDTH * HEIGHT * 4)


def stencil_image(value):
    return bytes([value]) * (WIDTH * HEIGHT) + bytes(PAGE_SIZE - WIDTH * HEIGHT)


def main():
    if len(os.sys.argv) != 1:
        raise SystemExit("agx_g17p_render_uapi_zls.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), 3 * PAGE_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        from agx_g17p_compute import drain_boot_group

        drain_boot_group(front, backend)
        vm = front.modern.create_vm(FD, 0x7000000000, 0x7800000000)
        output = front.modern.create_bo(FD, OUTPUT_HANDLE, 0, PAGE_SIZE)
        depth = front.modern.create_bo(FD, DEPTH_HANDLE, PAGE_SIZE, PAGE_SIZE)
        stencil = front.modern.create_bo(
            FD, STENCIL_HANDLE, 2 * PAGE_SIZE, PAGE_SIZE)

        for bo, address in (
                (output, OUTPUT_DVA),
                (depth, DEPTH_DVA),
                (stencil, STENCIL_DVA)):
            front.modern.bind(FD, vm.vm_id, drm_asahi_gem_bind_op(
                DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
                bo.handle, 0, PAGE_SIZE, address))

        queue = front.modern.create_queue(FD, vm.vm_id, 1, 0x10000000000)
        cases = (
            ("store", Z_STORE | S_STORE, 0.25, 0x5a,
             depth_image(0.25), stencil_image(0x5a)),
            ("load_store", Z_LOAD | S_LOAD | Z_STORE | S_STORE,
             0.25, 0x5a, depth_image(0.75), stencil_image(0x7b)),
        )

        for name, control, clear_depth, clear_stencil, expected_z, expected_s in cases:
            output.token["map"][:] = bytes(PAGE_SIZE)
            if name == "load_store":
                depth.token["map"][:] = depth_image(0.75)
                stencil.token["map"][:] = stencil_image(0x7b)
            else:
                depth.token["map"][:] = bytes(PAGE_SIZE)
                stencil.token["map"][:] = bytes(PAGE_SIZE)

            fence, commands = front.modern.submit(
                FD, queue.queue_id,
                render_command(
                    zls_ctrl=control,
                    depth_clear=clear_depth,
                    stencil_clear=clear_stencil,
                ),
            )
            got_color = bytes(output.token["map"][:PAGE_SIZE])
            got_depth = bytes(depth.token["map"][:PAGE_SIZE])
            got_stencil = bytes(stencil.token["map"][:PAGE_SIZE])
            print(
                "RENDER UAPI ZLS %s color_exact=%d depth_exact=%d "
                "stencil_exact=%d fence=%d ctrl=%#x pixels=%#x" % (
                    name,
                    got_color == color_expected(),
                    got_depth == expected_z,
                    got_stencil == expected_s,
                    fence.signaled(),
                    commands[0].hardware_state.zls_ctrl,
                    commands[0].payload.isp_zls_pixels,
                ),
                flush=True,
            )
            if got_color != color_expected():
                raise RuntimeError("%s color output was not exact" % name)
            if got_depth != expected_z:
                raise RuntimeError("%s depth output was not exact" % name)
            if got_stencil != expected_s:
                raise RuntimeError("%s stencil output was not exact" % name)
            if not fence.signaled():
                raise RuntimeError("%s render fence did not signal" % name)

        print("RENDER UAPI ZLS PASS", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
