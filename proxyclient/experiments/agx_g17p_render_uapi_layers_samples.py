#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove layered and multisampled render geometry with exact ZLS pages."""

import os
import tempfile

from agx_g17p_compute import drain_boot_group
from agx_g17p_render_uapi_zls import (
    DEPTH_DVA,
    FD,
    OUTPUT_DVA,
    PAGE_SIZE,
    S_STORE,
    STENCIL_DVA,
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
MAX_PLANES = 4


def expected_depth(planes, value):
    return depth_image(value) * planes + bytes(PAGE_SIZE * (MAX_PLANES - planes))


def expected_stencil(planes, value):
    used = 64 * 64 * planes
    return bytes([value]) * used + bytes(PAGE_SIZE * MAX_PLANES - used)


def expected_layered_stencil(layers, value):
    one = stencil_image(value)
    return one * layers + bytes(PAGE_SIZE * (MAX_PLANES - layers))


def page_summary(actual, expected):
    pages = []
    for index in range(MAX_PLANES):
        start = index * PAGE_SIZE
        got = actual[start:start + PAGE_SIZE]
        want = expected[start:start + PAGE_SIZE]
        mismatches = [offset for offset, pair in enumerate(zip(got, want))
                      if pair[0] != pair[1]]
        pages.append(
            "%d:nz=%d want_nz=%d mismatch=%d first=%s" % (
                index, sum(bool(value) for value in got),
                sum(bool(value) for value in want), len(mismatches),
                "none" if not mismatches else hex(mismatches[0]),
            )
        )
    return "; ".join(pages)


def mismatch_detail(actual, expected):
    mismatches = [offset for offset, pair in enumerate(zip(actual, expected))
                  if pair[0] != pair[1]]
    if not mismatches:
        return "none"
    runs = []
    start = previous = mismatches[0]
    for offset in mismatches[1:]:
        if offset != previous + 1:
            runs.append((start, previous + 1))
            start = offset
        previous = offset
    runs.append((start, previous + 1))
    head = mismatches[0]
    sample = actual[head:head + 64].hex()
    values = sorted(set(actual[offset] for offset in mismatches))
    return "runs=%s values=%s first_bytes=%s" % (
        ",".join("%#x..%#x" % run for run in runs[:16]),
        ",".join("%#x" % value for value in values[:32]), sample,
    )


def main():
    if len(os.sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_render_uapi_layers_samples.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), 12 * PAGE_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        drain_boot_group(front, backend)

        vm = front.modern.create_vm(FD, 0x7000000000, 0x7800000000)
        output = front.modern.create_bo(
            FD, OUTPUT_HANDLE, 0, MAX_PLANES * PAGE_SIZE)
        depth = front.modern.create_bo(
            FD, DEPTH_HANDLE, 4 * PAGE_SIZE, MAX_PLANES * PAGE_SIZE)
        stencil = front.modern.create_bo(
            FD, STENCIL_HANDLE, 8 * PAGE_SIZE, MAX_PLANES * PAGE_SIZE)
        for bo, address in (
                (output, OUTPUT_DVA),
                (depth, DEPTH_DVA),
                (stencil, STENCIL_DVA)):
            front.modern.bind(FD, vm.vm_id, drm_asahi_gem_bind_op(
                DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
                bo.handle, 0, bo.size, address))

        queue = front.modern.create_queue(FD, vm.vm_id, 1, 0x10000000000)
        cases = (
            {
                "name": "layers3",
                "layers": 3,
                "samples": 1,
                "sample_size": 8,
                "utile_width": 32,
                "utile_height": 32,
                "multisample": 0x88,
                # Main ZLS array stride is encoded as
                # ((stride_pages - 1) << 14) | 1.
                "depth_stride": 1,
                "stencil_stride": 1,
                "depth_expected": expected_depth(3, 0.25),
                "stencil_expected": expected_layered_stencil(3, 0x5a),
            },
            {
                "name": "msaa2",
                "layers": 1,
                "samples": 2,
                "sample_size": 8,
                "utile_width": 32,
                "utile_height": 32,
                "multisample": 0x44cc,
                "depth_stride": 0,
                "stencil_stride": 0,
                "depth_expected": expected_depth(2, 0.25),
                "stencil_expected": expected_stencil(2, 0x5a),
            },
            {
                "name": "msaa4",
                "layers": 1,
                "samples": 4,
                "sample_size": 8,
                "utile_width": 32,
                "utile_height": 16,
                "multisample": 0xeaa26e26,
                "depth_stride": 0,
                "stencil_stride": 0,
                "depth_expected": expected_depth(4, 0.25),
                "stencil_expected": expected_stencil(4, 0x5a),
            },
        )

        for case in cases:
            output.token["map"][:] = bytes(output.size)
            depth.token["map"][:] = bytes(depth.size)
            stencil.token["map"][:] = bytes(stencil.size)
            fence, commands = front.modern.submit(
                FD, queue.queue_id,
                render_command(
                    zls_ctrl=Z_STORE | S_STORE,
                    depth_clear=0.25,
                    stencil_clear=0x5a,
                    depth_stride=case["depth_stride"],
                    stencil_stride=case["stencil_stride"],
                    layers=case["layers"],
                    samples=case["samples"],
                    sample_size=case["sample_size"],
                    utile_width=case["utile_width"],
                    utile_height=case["utile_height"],
                    multisample_control=case["multisample"],
                ),
            )
            got_output = bytes(output.token["map"][:output.size])
            got_depth = bytes(depth.token["map"][:depth.size])
            got_stencil = bytes(stencil.token["map"][:stencil.size])
            color_first_exact = got_output[:PAGE_SIZE] == color_expected()
            color_tail_zero = not any(got_output[PAGE_SIZE:])
            depth_exact = got_depth == case["depth_expected"]
            stencil_exact = got_stencil == case["stencil_expected"]
            state = commands[0].hardware_state
            print(
                "RENDER UAPI GEOMETRY %s color_first_exact=%d "
                "color_tail_zero=%d depth_exact=%d stencil_exact=%d fence=%d "
                "layers=%d samples=%d utile=%#x blocks=%d tile=%#x" % (
                    case["name"], color_first_exact, color_tail_zero,
                    depth_exact, stencil_exact, fence.signaled(),
                    state.layers, state.samples, state.utile_config,
                    state.blocks_per_utile, state.tile_config,
                ),
                flush=True,
            )
            if not depth_exact:
                print("  depth pages: " + page_summary(
                    got_depth, case["depth_expected"]), flush=True)
                print("  depth mismatch: " + mismatch_detail(
                    got_depth, case["depth_expected"]), flush=True)
            if not stencil_exact:
                print("  stencil pages: " + page_summary(
                    got_stencil, case["stencil_expected"]), flush=True)
                print("  stencil mismatch: " + mismatch_detail(
                    got_stencil, case["stencil_expected"]), flush=True)
            if not color_first_exact or not color_tail_zero:
                raise RuntimeError("%s color output was not exact" % case["name"])
            if not depth_exact:
                raise RuntimeError("%s depth output was not exact" % case["name"])
            if not stencil_exact:
                raise RuntimeError("%s stencil output was not exact" % case["name"])
            if not fence.signaled():
                raise RuntimeError("%s render fence did not signal" % case["name"])

        print("RENDER UAPI LAYERS/MSAA PASS", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
