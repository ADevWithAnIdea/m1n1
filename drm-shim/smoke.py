#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check exact compute and render outputs through the native G17G DRM bridge."""

from contextlib import ExitStack
import ctypes
import hashlib
import mmap
import os
from pathlib import Path
import struct
import sys
import tempfile

from m1n1.drm_shim import g17g_backend as backend, g17g_uapi as api
from m1n1.drm_shim.g17g_modern import PAGE_SIZE, USC_EXEC_BASE, VM_END, VM_KERNEL_MIN_SIZE


def checked(result, operation):
    if result < 0:
        raise OSError(-result, f"{operation}: {os.strerror(-result)}")
    return result


def open_bridge():
    root = Path(__file__).resolve().parents[1]
    suffix = "dylib" if sys.platform == "darwin" else "so"
    path = root / "build" / f"libg17g_drm_shim.{suffix}"
    if not path.is_file():
        raise SystemExit("Build the bridge with python3 drm-shim/build_bridge.py first.")
    bridge = ctypes.PyDLL(str(path))
    bridge.g17g_drm_init.argtypes = [ctypes.c_int]
    bridge.g17g_drm_open_file.restype = ctypes.c_int64
    bridge.g17g_drm_close_file.argtypes = [ctypes.c_uint64]
    bridge.g17g_drm_ioctl.argtypes = [ctypes.c_uint64, ctypes.c_ulong, ctypes.c_void_p]
    bridge.g17g_drm_mmap_fd.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_int)]
    return bridge


def compute_case():
    graph = backend.build_add_compute_graph()
    dispatch, = graph["dispatch_outputs"]
    output = dispatch["output"]
    expected = struct.pack("<64f", *dispatch["expected_values"]).ljust(PAGE_SIZE, b"\xa5")
    pages = {va: body for va, body in backend.context1_page_images(graph).items()
             if va >= USC_EXEC_BASE}
    base, = graph["cdm_addresses"]
    work = api.drm_asahi_cmd_compute(cdm_ctrl_stream_base=base,
                                     cdm_ctrl_stream_end=base + graph["cdm_size"])
    outputs = ((output, PAGE_SIZE, hashlib.sha256(expected).hexdigest()),)
    return api.DRM_ASAHI_CMD_COMPUTE, work, pages, outputs


def render_case():
    graph = backend.build_partial_render_products()
    params = graph["parameters"]
    scissor = params.resolved_scissor_array()
    depth_bias = params.resolved_depth_bias_array()
    low = {0x1000000000, 0x1000018000, 0x1000048000, 0x1000058000, 0x1000068000,
           depth_bias & -PAGE_SIZE}
    images = backend.render_context1_page_images(graph)
    pages = {address: body for address, body in images.items()
             if address in low or address >= USC_EXEC_BASE}
    pages.setdefault(depth_bias & -PAGE_SIZE, bytes(PAGE_SIZE))
    work = api.drm_asahi_cmd_render(
        flags=api.DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES,
        vdm_ctrl_stream_base=graph["vdm_stream_base"],
        isp_scissor_base=scissor, isp_dbias_base=depth_bias,
        ppp_multisamplectl=params.multisample_control, ppp_ctrl=params.ppp_control,
        width_px=params.width, height_px=params.height, layers=params.layers,
        utile_width_px=params.utile_width, utile_height_px=params.utile_height,
        samples=params.samples, sample_size_B=32,
    )
    for pipeline, address, resources in (
        (work.bg, params.load_pipeline, params.load_pipeline_bind),
        (work.eot, params.store_pipeline, params.store_pipeline_bind),
        (work.partial_bg, params.partial_load_pipeline, params.partial_load_pipeline_bind),
        (work.partial_eot, params.partial_store_pipeline, params.partial_store_pipeline_bind),
    ):
        pipeline.usc = address - USC_EXEC_BASE
        pipeline.rsrc_spec = resources & 0xffffffff
    outputs = tuple((item["base"], item["size"], item["expected_sha256"])
                    for item in graph["attachments"])
    return api.DRM_ASAHI_CMD_RENDER, work, pages, outputs


def submit_case(bridge, file, kind, work, pages, outputs):
    def ioctl(number, payload):
        request = 0xc0006400 | ctypes.sizeof(payload) << 16 | number
        checked(bridge.g17g_drm_ioctl(file, request, ctypes.byref(payload)),
                type(payload).__name__)
        return payload

    output_pages = {address for base, size, _ in outputs
                    for address in range(base, base + size, PAGE_SIZE)}
    if not output_pages <= pages.keys():
        raise RuntimeError("fixture is missing a mapped output page")
    with ExitStack() as stack:
        vm = ioctl(0x42, api.drm_asahi_vm_create(VM_END - VM_KERNEL_MIN_SIZE, VM_END))
        queue = ioctl(0x48, api.drm_asahi_queue_create(0, vm.vm_id, 1))
        mappings = {}
        for address, body in pages.items():
            bo = ioctl(0x45, api.drm_asahi_gem_create(PAGE_SIZE))
            offset = ioctl(0x46, api.drm_asahi_gem_mmap_offset(bo.handle)).offset
            fd = checked(bridge.g17g_drm_mmap_fd(file, offset, PAGE_SIZE, None), "map BO")
            try:
                mapping = stack.enter_context(mmap.mmap(fd, PAGE_SIZE))
            finally:
                os.close(fd)
            flags = api.DRM_ASAHI_BIND_READ
            if address in output_pages:
                flags |= api.DRM_ASAHI_BIND_WRITE
                body = b"\xa5" * PAGE_SIZE
                mappings[address] = mapping
            mapping[:] = body
            bind = api.drm_asahi_gem_bind_op(flags, bo.handle, 0, PAGE_SIZE, address)
            ioctl(0x44, api.drm_asahi_vm_bind(vm.vm_id, 1, ctypes.sizeof(bind), 0,
                                            ctypes.addressof(bind)))

        header = api.drm_asahi_cmd_header(kind, ctypes.sizeof(work),
                                          api.DRM_ASAHI_BARRIER_NONE, api.DRM_ASAHI_BARRIER_NONE)
        command = ctypes.create_string_buffer(header.to_bytes() + work.to_bytes())
        ioctl(0x4a, api.drm_asahi_submit(cmdbuf=ctypes.addressof(command), queue_id=queue.queue_id,
                                        cmdbuf_size=ctypes.sizeof(command) - 1))
        for base, size, expected in outputs:
            actual = hashlib.sha256()
            for address in range(base, base + size, PAGE_SIZE):
                count = min(PAGE_SIZE, base + size - address)
                actual.update(mappings[address][:count])
            if actual.hexdigest() != expected:
                raise RuntimeError(f"GPU output at {base:#x} differs from the oracle")
        ioctl(0x49, api.drm_asahi_queue_destroy(queue.queue_id))
    return sum(size for _, size, _ in outputs)


def main():
    bridge = open_bridge()
    with tempfile.TemporaryFile() as backing:
        checked(bridge.g17g_drm_init(backing.fileno()), "initialize bridge")
        file = checked(bridge.g17g_drm_open_file(), "open DRM file")
        try:
            for engine, work in (("compute", compute_case), ("render", render_case)):
                size = submit_case(bridge, file, *work())
                print(f"G17G {engine} smoke passed. All {size:,} output bytes match.")
        finally:
            checked(bridge.g17g_drm_close_file(file), "close DRM file")


if __name__ == "__main__":
    main()
