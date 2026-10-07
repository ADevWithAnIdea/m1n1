#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Advance a source-built G17P world to the native compute lifecycle count.

This experiment accepts no options and restores no captured bytes.  It reuses
one guarded render BO, explicitly clears it before every submission, and only
counts a submission after the GPU changes that physical target.
"""

import ctypes
import os
import pathlib
import struct
import sys
import tempfile
import types


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ["M1N1DEVICE"] = "/dev/m1n1-neo"
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"

from m1n1.agx.shim import DRMAsahiShim  # noqa: E402

from agx_g17p_compute import drain_boot_group, physical_read  # noqa: E402
from agx_g17p_shim_submit import packed_cmdbuf  # noqa: E402


PAGE = 0x4000
GUARD_SIZE = 0x20000
TARGET_CONTROL_COUNT = 67


def primary_control_counters(backend):
    entry = backend.channels.entries[12]
    return backend.channels.counters(entry)


def clear_target(backend, pa):
    backend.u.proxy.memset32(pa, 0, GUARD_SIZE)
    backend.u.proxy.dc_civac(pa, GUARD_SIZE)
    backend.u.inst("dsb sy")
    before = physical_read(backend, pa, PAGE)
    if any(before):
        raise RuntimeError("guarded lifecycle target did not clear")
    return before


def advance_source_lifecycle(front, backend):
    """Execute source-built renders until primary control reaches 67."""
    drain_boot_group(front, backend)
    os.ftruncate(front.memfd, GUARD_SIZE)
    target_dva = front.create_bo_from_memfd(
        front.memfd, 0, GUARD_SIZE, 0)
    target = front.bos[0]
    target._no_push = True
    body = packed_cmdbuf(
        64, 64,
        color_attachment={
            "type": 0,
            "size": PAGE,
            "pointer": target_dva,
        },
    )
    storage = ctypes.create_string_buffer(body)
    args = types.SimpleNamespace(cmdbuf=ctypes.addressof(storage))

    before_count = primary_control_counters(backend)
    print(
        "LIFECYCLE source start control=%s target=%#x pa=%#x guard=%#x" %
        (before_count, target_dva, target._pa, GUARD_SIZE),
        flush=True,
    )
    submissions = 0
    while primary_control_counters(backend)[0] < TARGET_CONTROL_COUNT:
        before = clear_target(backend, target._pa)
        front.submit(front.memfd, args)
        after = physical_read(backend, target._pa, PAGE)
        if after == before or not any(after):
            raise RuntimeError(
                "source render %d retired without changing its cleared target" %
                (submissions + 1))
        submissions += 1
        counters = primary_control_counters(backend)
        print(
            "LIFECYCLE render %d executed control=%s output_head=%s" %
            (submissions, counters, after[:32].hex()),
            flush=True,
        )
        if len(set(counters)) != 1:
            raise RuntimeError(
                "primary control counters diverged: %r" % counters)
        if counters[0] > TARGET_CONTROL_COUNT:
            raise RuntimeError(
                "primary control overshot target %d: %r" %
                (TARGET_CONTROL_COUNT, counters))

    final = primary_control_counters(backend)
    if final != [TARGET_CONTROL_COUNT] * 3:
        raise RuntimeError(
            "source lifecycle ended at %r, expected %d" %
            (final, TARGET_CONTROL_COUNT))
    runtime = front.g17p_runtime or {}
    all_controls = runtime.get("read_control_counters", lambda: {})()
    print(
        "LIFECYCLE PASS: %d source-built renders, primary control=%s, "
        "all controls=%r" % (submissions, final, all_controls),
        flush=True,
    )
    print(
        "LIFECYCLE final target u32[0:8]=%r" %
        (struct.unpack("<8I", physical_read(backend, target._pa, 32)),),
        flush=True,
    )
    return {
        "submissions": submissions,
        "control": final,
        "all_controls": all_controls,
        "target_dva": target_dva,
        "target_pa": target._pa,
    }


def run():
    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        advance_source_lifecycle(front, backend)
        return 0


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_source_lifecycle.py accepts no arguments")
    raise SystemExit(run())
