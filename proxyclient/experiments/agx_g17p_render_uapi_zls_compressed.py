#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove compressed ZLS store/load by decompressing to exact caller bytes."""

import hashlib
import os
import tempfile

from agx_g17p_compute import drain_boot_group
from agx_g17p_render_uapi_zls import (
    DEPTH_DVA,
    FD,
    HEIGHT,
    OUTPUT_DVA,
    PAGE_SIZE,
    S_LOAD,
    S_STORE,
    STENCIL_DVA,
    WIDTH,
    Z_LOAD,
    Z_STORE,
    color_expected,
    depth_image,
    render_command,
    stencil_image,
)
from m1n1.agx.g17p_uapi import (
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_WRITE,
    drm_asahi_gem_bind_op,
)
from m1n1.agx.shim import DRMAsahiShim


OUTPUT_HANDLE = 1
DEPTH_HANDLE = 2
STENCIL_HANDLE = 3
DEPTH_META_HANDLE = 4
STENCIL_META_HANDLE = 5
DEPTH_META_DVA = 0x1500030000
STENCIL_META_DVA = 0x1500040000

Z_LOAD_COMPRESSED = 1 << 2
S_LOAD_COMPRESSED = 1 << 4
Z_STORE_COMPRESSED = 1 << 6
S_STORE_COMPRESSED = 1 << 8


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if len(os.sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_render_uapi_zls_compressed.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), 5 * PAGE_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        drain_boot_group(front, backend)

        vm = front.modern.create_vm(FD, 0x7000000000, 0x7800000000)
        objects = (
            (front.modern.create_bo(FD, OUTPUT_HANDLE, 0, PAGE_SIZE),
             OUTPUT_DVA),
            (front.modern.create_bo(FD, DEPTH_HANDLE, PAGE_SIZE, PAGE_SIZE),
             DEPTH_DVA),
            (front.modern.create_bo(
                FD, STENCIL_HANDLE, 2 * PAGE_SIZE, PAGE_SIZE), STENCIL_DVA),
            (front.modern.create_bo(
                FD, DEPTH_META_HANDLE, 3 * PAGE_SIZE, PAGE_SIZE),
             DEPTH_META_DVA),
            (front.modern.create_bo(
                FD, STENCIL_META_HANDLE, 4 * PAGE_SIZE, PAGE_SIZE),
             STENCIL_META_DVA),
        )
        for bo, address in objects:
            front.modern.bind(FD, vm.vm_id, drm_asahi_gem_bind_op(
                DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
                bo.handle, 0, PAGE_SIZE, address))
            bo.token["map"][:] = bytes(PAGE_SIZE)

        output, depth, stencil, depth_meta, stencil_meta = (
            pair[0] for pair in objects)
        queue = front.modern.create_queue(FD, vm.vm_id, 1, 0x10000000000)

        compressed_store = (
            Z_STORE | S_STORE | Z_STORE_COMPRESSED | S_STORE_COMPRESSED)
        fence, _commands = front.modern.submit(
            FD, queue.queue_id,
            render_command(
                zls_ctrl=compressed_store,
                depth_clear=0.25,
                stencil_clear=0x5a,
                depth_comp=DEPTH_META_DVA,
                stencil_comp=STENCIL_META_DVA,
            ),
        )
        compressed = {
            "depth": bytes(depth.token["map"][:PAGE_SIZE]),
            "stencil": bytes(stencil.token["map"][:PAGE_SIZE]),
            "depth_meta": bytes(depth_meta.token["map"][:PAGE_SIZE]),
            "stencil_meta": bytes(stencil_meta.token["map"][:PAGE_SIZE]),
        }
        changed = {name: sum(byte != 0 for byte in body)
                   for name, body in compressed.items()}
        print(
            "RENDER UAPI ZLS COMPRESSED store fence=%d ctrl=%#x "
            "changed=%r sha256=%r" % (
                fence.signaled(), compressed_store, changed,
                {name: digest(body) for name, body in compressed.items()},
            ),
            flush=True,
        )
        if not fence.signaled():
            raise RuntimeError("compressed ZLS store fence did not signal")
        if not changed["depth_meta"] or not changed["stencil_meta"]:
            raise RuntimeError("compressed ZLS store did not write both metadata pages")

        # Load the compressed image just produced, but disable compression on
        # store. The resulting ordinary buffers have independently predictable
        # bytes and therefore prove semantic compressed load, not just metadata
        # traffic or descriptor retirement.
        decompress = (
            Z_LOAD | S_LOAD | Z_STORE | S_STORE
            | Z_LOAD_COMPRESSED | S_LOAD_COMPRESSED)
        output.token["map"][:] = bytes(PAGE_SIZE)
        fence, _commands = front.modern.submit(
            FD, queue.queue_id,
            render_command(
                zls_ctrl=decompress,
                depth_clear=0.875,
                stencil_clear=0xe1,
                depth_comp=DEPTH_META_DVA,
                stencil_comp=STENCIL_META_DVA,
            ),
        )
        got_depth = bytes(depth.token["map"][:PAGE_SIZE])
        got_stencil = bytes(stencil.token["map"][:PAGE_SIZE])
        print(
            "RENDER UAPI ZLS COMPRESSED load color_exact=%d depth_exact=%d "
            "stencil_exact=%d fence=%d ctrl=%#x size=%dx%d" % (
                bytes(output.token["map"][:PAGE_SIZE]) == color_expected(),
                got_depth == depth_image(0.25),
                got_stencil == stencil_image(0x5a),
                fence.signaled(), decompress, WIDTH, HEIGHT,
            ),
            flush=True,
        )
        if bytes(output.token["map"][:PAGE_SIZE]) != color_expected():
            raise RuntimeError("compressed-load color output was not exact")
        if got_depth != depth_image(0.25):
            raise RuntimeError("compressed depth did not decode to the exact clear")
        if got_stencil != stencil_image(0x5a):
            raise RuntimeError("compressed stencil did not decode to the exact clear")
        if not fence.signaled():
            raise RuntimeError("compressed ZLS load fence did not signal")

        print("RENDER UAPI ZLS COMPRESSED PASS", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
