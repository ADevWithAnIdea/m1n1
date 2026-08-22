#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit one exact add3 dispatch through the modern Asahi UAPI model."""

import os
import pathlib
import struct
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("AGX_GPU", "G17")
os.environ.setdefault("G17P_COLD_BOOT", "1")
os.environ.setdefault("M1N1HEAP_RESERVE", "1")

from m1n1.agx import g17p_compute as compute  # noqa: E402
from m1n1.agx import g17p_modern as modern  # noqa: E402
from m1n1.agx import g17p_uapi as uapi  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim  # noqa: E402
from agx_g17p_native_add3 import (  # noqa: E402
    CDM as NATIVE_CDM,
    CLIENT_WORKLOAD_STRIDE,
    CODE_IMAGE as NATIVE_CODE_IMAGE,
    INPUT_A as NATIVE_INPUT_A,
    INPUT_B as NATIVE_INPUT_B,
    OUTPUT as NATIVE_OUTPUT,
    OUTPUT_WORKLOAD_STRIDE,
    RESOURCE as NATIVE_RESOURCE,
    RESOURCE_SIZE,
    SHADER as NATIVE_SHADER,
    build_add3_preamble,
)
from g17p_add3_code import build_add3_code_image  # noqa: E402


PAGE = 0x4000
FD = 17
# The original source-compute graph lives above 1 TiB.  The upstream UAPI
# exposes a 39-bit userspace window, so preserve the graph's relative layout
# while placing this independent caller namespace at 64 GiB.
USC_BASE = 0x1000000000


def rebase_native(address):
    return USC_BASE + int(address) - NATIVE_CODE_IMAGE


CODE_IMAGE = rebase_native(NATIVE_CODE_IMAGE)
INPUT_A = rebase_native(NATIVE_INPUT_A)
INPUT_B = rebase_native(NATIVE_INPUT_B)
CALLER_CDM = rebase_native(NATIVE_CDM + CLIENT_WORKLOAD_STRIDE)
CALLER_SHADER = rebase_native(NATIVE_SHADER + CLIENT_WORKLOAD_STRIDE)
CALLER_RESOURCE = rebase_native(NATIVE_RESOURCE + CLIENT_WORKLOAD_STRIDE)
CALLER_OUTPUT = rebase_native(NATIVE_OUTPUT + OUTPUT_WORKLOAD_STRIDE)
CALLER_SAMPLER_HEAP = CALLER_RESOURCE + RESOURCE_SIZE
CALLER_HELPER_CODE = USC_BASE + PAGE
CALLER_HELPER_DATA = CALLER_SAMPLER_HEAP + PAGE

# Nearest-filter, clamp-to-edge sampler with the native 14.0 maximum LOD.
DEFAULT_SAMPLER = bytes.fromhex("00000e0080070000")


def command(timestamp_handle=None, sampler_heap=0, sampler_count=0,
            helper_binary=0, helper_cfg=0, helper_data=0,
            attachments=None):
    payload = uapi.drm_asahi_cmd_compute()
    payload.cdm_ctrl_stream_base = CALLER_CDM
    payload.cdm_ctrl_stream_end = CALLER_CDM + compute.CDM_RECORD_SIZE + 4
    payload.sampler_heap = int(sampler_heap)
    payload.sampler_count = int(sampler_count)
    payload.helper.binary = int(helper_binary)
    payload.helper.cfg = int(helper_cfg)
    payload.helper.data = int(helper_data)
    if timestamp_handle is not None:
        payload.ts.start.handle = timestamp_handle
        payload.ts.start.offset = 0
        payload.ts.end.handle = timestamp_handle
        payload.ts.end.offset = 8

    if attachments is None:
        attachments = ((CALLER_OUTPUT, PAGE),)
    attachment_records = b"".join(
        uapi.drm_asahi_attachment(pointer, size, 0, 0).to_bytes()
        for pointer, size in attachments)
    attachment_header = uapi.drm_asahi_cmd_header(
        uapi.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS,
        len(attachment_records),
        uapi.DRM_ASAHI_BARRIER_NONE,
        uapi.DRM_ASAHI_BARRIER_NONE,
    )
    header = uapi.drm_asahi_cmd_header(
        uapi.DRM_ASAHI_CMD_COMPUTE,
        len(payload.to_bytes()),
        uapi.DRM_ASAHI_BARRIER_NONE,
        uapi.DRM_ASAHI_BARRIER_NONE,
    )
    return (attachment_header.to_bytes() + attachment_records
            + header.to_bytes() + payload.to_bytes())


def main(use_timestamps=True, use_sampler=False, use_helper=False):
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_modern_compute.py accepts no arguments")

    input_ordinal = int(os.getenv("G17P_MODERN_INPUT_ORDINAL", "0"), 0)
    input_base = 1000.0 + input_ordinal * 128.0
    input_b = 0.5 + input_ordinal
    bodies = {
        CODE_IMAGE: build_add3_code_image(),
        CALLER_SHADER: build_add3_preamble(CALLER_SHADER, USC_BASE),
        CALLER_CDM: compute.build_cdm_stream((
            compute.build_direct_dispatch(
                CALLER_SHADER,
                grid=(64, 1, 1),
                threadgroup=(32, 1, 1),
                config=0x80000,
                constant=0x1000000,
                tail=0x60000160,
            ),
        )),
        CALLER_RESOURCE: compute.build_buffer_resource_table(
            (INPUT_A, INPUT_B, CALLER_OUTPUT), size=RESOURCE_SIZE),
        INPUT_A: struct.pack("<64f", *(input_base + i for i in range(64))),
        INPUT_B: struct.pack("<64f", *(input_b for _ in range(64))),
        CALLER_OUTPUT: bytes(PAGE),
    }
    if use_sampler:
        bodies[CALLER_SAMPLER_HEAP] = DEFAULT_SAMPLER
    if use_helper:
        bodies[CALLER_HELPER_CODE] = build_add3_code_image()
        bodies[CALLER_HELPER_DATA] = bytes(PAGE)
    sizes = {address: max(PAGE, len(body))
             for address, body in bodies.items()}
    timestamp_offset = sum(sizes.values())
    total = timestamp_offset + PAGE

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), total)
        front = DRMAsahiShim(memfd.fileno())
        if front.modern_enable() != 0:
            raise RuntimeError("could not select the modern direct bootstrap")
        driver = front.modern
        vm = driver.create_vm(
            FD,
            modern.VM_END - modern.VM_KERNEL_MIN_SIZE,
            modern.VM_END,
        )

        offset = 0
        handle = 1
        for address, body in bodies.items():
            size = sizes[address]
            bo = driver.create_bo(FD, handle, offset, size)
            bo.token["map"][:len(body)] = body
            flags = uapi.DRM_ASAHI_BIND_READ
            if address not in (
                    CODE_IMAGE, CALLER_CDM, CALLER_SHADER,
                    CALLER_HELPER_CODE):
                flags |= uapi.DRM_ASAHI_BIND_WRITE
            driver.bind(
                FD,
                vm.vm_id,
                uapi.drm_asahi_gem_bind_op(
                    flags,
                    handle,
                    0,
                    size,
                    address,
                ),
            )
            offset += size
            handle += 1

        timestamp_bo = timestamp = None
        if use_timestamps:
            timestamp_bo = driver.create_bo(FD, handle, offset, PAGE)
            timestamp_op = uapi.drm_asahi_gem_bind_object(
                uapi.DRM_ASAHI_BIND_OBJECT_OP_BIND,
                uapi.DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
                timestamp_bo.handle,
                0,
                0,
                PAGE,
                0,
                0,
            )
            timestamp = driver.bind_object(FD, timestamp_op)
        queue = driver.create_queue(FD, vm.vm_id, 0, USC_BASE)

        output_binding = next(
            binding for binding in vm.bindings
            if binding.addr == CALLER_OUTPUT)
        expected = tuple(input_base + input_b + i for i in range(64))
        if os.getenv("G17P_MODERN_ATTACHMENT_MATRIX", "0") == "1":
            attachment_variants = (
                ("none", ()),
                ("output", ((CALLER_OUTPUT, PAGE),)),
                ("input-first", ((INPUT_A, PAGE), (CALLER_OUTPUT, PAGE))),
            )
        else:
            attachment_variants = (
                ("output", ((CALLER_OUTPUT, PAGE),)),
            )

        start = end = 0
        for label, attachments in attachment_variants:
            output_binding.bo.token["map"][:PAGE] = bytes(PAGE)
            if timestamp_bo is not None:
                timestamp_bo.token["map"][:16] = bytes(16)
            fence, commands = driver.submit(
                FD, queue.queue_id,
                command(
                    None if timestamp is None else timestamp.object_handle,
                    CALLER_SAMPLER_HEAP if use_sampler else 0,
                    1 if use_sampler else 0,
                    (CALLER_HELPER_CODE - USC_BASE) | 1 if use_helper else 0,
                    0,
                    CALLER_HELPER_DATA if use_helper else 0,
                    attachments,
                ))
            if not fence.signaled():
                raise RuntimeError(
                    "modern compute %s submission fence did not signal" %
                    label)
            if commands[0].hardware_state.attachments != attachments:
                raise RuntimeError(
                    "modern compute %s attachment state changed" % label)

            output = bytes(output_binding.bo.token["map"][:256])
            actual = struct.unpack("<64f", output)
            if actual != expected:
                changed = sum(value != 0 for value in output)
                raise RuntimeError(
                    "modern compute %s output mismatch (%d changed bytes)" %
                    (label, changed))

            if timestamp_bo is not None:
                start, end = struct.unpack(
                    "<QQ", timestamp_bo.token["map"][:16])
                if not start or end <= start:
                    raise RuntimeError(
                        "modern compute %s timestamps are invalid: %#x..%#x" %
                        (label, start, end))
            print(
                "MODERN COMPUTE ATTACHMENT PASS: %s exact output, %d hints" %
                (label, len(attachments)),
                flush=True,
            )
        print(
            "MODERN COMPUTE PASS: %d exact 64-float caller output(s) at "
            "DVA %#x; %s" % (
                len(attachment_variants),
                CALLER_OUTPUT,
                ("caller timestamps %#x..%#x" % (start, end))
                if timestamp_bo is not None else "timestamps disabled"),
            flush=True,
        )
        print(
            "MODERN COMPUTE OUTPUT DVA %#x" % CALLER_OUTPUT,
            flush=True,
        )
        if use_sampler:
            print(
                "MODERN COMPUTE SAMPLER heap %#x count 1" %
                CALLER_SAMPLER_HEAP,
                flush=True,
            )
        if use_helper:
            print(
                "MODERN COMPUTE HELPER binary %#x cfg 0 data %#x" % (
                    (CALLER_HELPER_CODE - USC_BASE) | 1,
                    CALLER_HELPER_DATA,
                ),
                flush=True,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
