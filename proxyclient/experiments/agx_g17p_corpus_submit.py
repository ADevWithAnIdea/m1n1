#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit the clean-room A18 triangle corpus through the G17P DRM backend.

Run this after ``agx_g17p_boot.py`` starts firmware without the first work
doorbell.  The corpus supplies only userspace-authored BO contents; queue,
register-program and completion construction still comes from the backend.
"""

import argparse
import ctypes
import os
import pathlib
import re
import struct
import sys
import tempfile
import types

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

# UAT fixes its L0 split when imported. Select the T8140 generation before
# importing any AGX modules, matching the working G17P shim harness.
os.environ.setdefault("AGX_GPU", "G17")

from m1n1.agx.g17p_device import PAGE                         # noqa: E402
from m1n1.agx.g17p_shim import (                              # noqa: E402
    G17P_RENDER_CONTEXT_BASE,
    command_buffer_from_drm,
)
from m1n1.agx.shim import DRMAsahiShim                        # noqa: E402
from m1n1.agx.uapi import drm_asahi_cmdbuf_t                  # noqa: E402
from m1n1.hw.uat import MemoryAttr                            # noqa: E402


DEFAULT_CORPUS = pathlib.Path(
    "~/asahi_re/public/agx-re/experiments/EXP-0009-iotrace-bringup/"
    "raw/draw_maps").expanduser()
G1A_CONTROLS = pathlib.Path(
    "~/asahi_re/public/agx-re/experiments/EXP-G1a-usc-sysval-uvs/"
    "raw/pick").expanduser()
G1A_CODE = pathlib.Path(
    "~/asahi_re/public/agx-re/experiments/EXP-0019-state-packets/"
    "raw/hex/base_code.hex").expanduser()
G1A_CONTEXT = DEFAULT_CORPUS / (
    "bo_sigusr1_h0_va48000_cpu108cc4000_sz8000.hex")
M4_FULL_CORPUS = pathlib.Path(
    "~/asahi_re/gpu/experiments/EXP-M4-03-cmdstream-pipeline/"
    "work/draw_tri.maps").expanduser()
M4_INDEXED_CORPUS = pathlib.Path(
    "~/asahi_re/gpu/experiments/EXP-M4-03-cmdstream-pipeline/"
    "work/draw_idx.maps").expanduser()
RESOURCE_BASE = 0x100_0000_0000
OUTPUT_VA = RESOURCE_BASE + 0x0008_0000
G1A_OUTPUT_VA = RESOURCE_BASE + 0x0005_8000
G1A_VERTEX_VA = RESOURCE_BASE + 0x0001_8700
SCISSOR_VA = RESOURCE_BASE + 0x019a_0000


def u32_override(text):
    try:
        offset_text, value_text = text.split("=", 1)
        offset = int(offset_text, 0)
        value = int(value_text, 0)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(
            "expected OFFSET=VALUE, with each value accepted by int(..., 0)")
    if offset < 0 or offset > 0x7ffc or offset & 3:
        raise argparse.ArgumentTypeError(
            "encoder offset must be a 32-bit-aligned value in 0..0x7ffc")
    if value < 0 or value > 0xffffffff:
        raise argparse.ArgumentTypeError("encoder value must fit in 32 bits")
    return offset, value


def va_copy(text):
    try:
        source_text, destination_text = text.split("=", 1)
        source = int(source_text, 0)
        destination = int(destination_text, 0)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(
            "expected SOURCE_VA=DESTINATION_VA")
    if source < 0 or destination < 0:
        raise argparse.ArgumentTypeError("GPU VAs must be nonnegative")
    return source, destination


def va_span(text):
    try:
        address_text, size_text = text.split(":", 1)
        address = int(address_text, 0)
        size = int(size_text, 0)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(
            "expected VA:SIZE, with each value accepted by int(..., 0)")
    if address < 0 or size <= 0:
        raise argparse.ArgumentTypeError(
            "watch address must be nonnegative and size must be positive")
    return address, size


def read_bodump(path):
    """Read the interposer's address-prefixed hexadecimal BO dump."""
    lines = path.read_text().splitlines()
    if not lines:
        raise ValueError("empty BODUMP %s" % path)
    header = re.search(r"read=0x([0-9a-fA-F]+)", lines[0])
    if header is None:
        raise ValueError("BODUMP has no read size: %s" % path)
    data = bytearray(int(header.group(1), 16))
    for line in lines[1:]:
        match = re.match(r"^([0-9a-fA-F]+):\s*(.*)$", line)
        if match is None:
            continue
        offset = int(match.group(1), 16)
        payload = b"".join(bytes.fromhex(word)
                           for word in match.group(2).split())
        if offset + len(payload) > len(data):
            raise ValueError("BODUMP line exceeds read size: %s at %#x" %
                             (path, offset))
        data[offset:offset + len(payload)] = payload
    return bytes(data)


def bodump_va(path):
    """Recover a BO's original GPU virtual address from its header or name."""
    first = path.open().readline()
    match = re.search(r"gpu_va=0x([0-9a-fA-F]+)", first)
    if match is not None:
        return int(match.group(1), 16)
    for pattern in (r"_va([0-9a-fA-F]+)_", r"__([0-9a-fA-F]+)__"):
        match = re.search(pattern, path.name)
        if match is not None:
            return int(match.group(1), 16)
    raise ValueError("cannot recover GPU VA from %s" % path)


def corpus_bos(directory):
    """Return ``(original VA, bytes, path)`` for every captured BO."""
    result = []
    for path in sorted(directory.glob("*.hex")):
        result.append((bodump_va(path), read_bodump(path), path))
    if not result:
        raise ValueError("no BODUMP files in %s" % directory)
    return result


def g1a_base_bos(directory, code_path, context_path):
    """Return the coherent baseline draw retained across EXP-G1a and EXP-0019."""
    result = []
    seen = set()
    for path in sorted(directory.glob("base__*.hex")):
        address = bodump_va(path)
        if address in seen:
            raise ValueError("duplicate G1a baseline BO at %#x" % address)
        seen.add(address)
        result.append((address, read_bodump(path), path))
    if not result:
        raise ValueError("no G1a baseline controls in %s" % directory)
    # The VDM's final bind pair names low offset 0x48000. G1a retained only BOs
    # that varied, so recover this invariant one-word context block from the
    # same-generation EXP-0009 capture instead of silently executing zeros.
    context_address = bodump_va(context_path)
    if context_address != 0x48000:
        raise ValueError("G1a context BO is at %#x, expected 0x48000" %
                         context_address)
    result.append((context_address, read_bodump(context_path), context_path))
    result.append((bodump_va(code_path), read_bodump(code_path), code_path))
    return result


def m4_full_bos(directory):
    """Return the complete M4 draw corpus, including its context-base BO."""
    result = []
    for path in sorted(directory.glob("bo_sigusr1_*.hex")):
        address = bodump_va(path)
        result.append((address, read_bodump(path), path))
    if not result:
        raise ValueError("no M4 draw BODUMPs in %s" % directory)
    return result


def a18_m4_closure_bos(m4_directory, controls, code_path, context_path):
    """Use the complete M4 allocation closure with A18-native draw payloads.

    G16G and G17P use the same userspace addresses and the command/control
    encoding was hardware-confirmed identical.  The M4 capture retains the
    large heaps that the focused A18 experiments pruned; exact-address A18
    controls and code win over their M4 counterparts here.
    """
    merged = {address: (data, path)
              for address, data, path in m4_full_bos(m4_directory)}
    for address, data, path in g1a_base_bos(
            controls, code_path, context_path):
        merged[address] = (data, path)
    return [(address, data, path)
            for address, (data, path) in sorted(merged.items())]


def target_va(original):
    """Low corpus VAs are offsets in the queue's render-context window."""
    if original < G17P_RENDER_CONTEXT_BASE:
        return G17P_RENDER_CONTEXT_BASE + original
    return original


def ensure_mapping(backend, address, size, executable, fresh_pages=None):
    """Map a range, optionally replacing each page's physical backing once."""
    uat = backend.space.uat
    first = address & ~(PAGE - 1)
    last = (address + size + PAGE - 1) & ~(PAGE - 1)
    for page in range(first, last, PAGE):
        translated = uat.iotranslate(backend.space.context, page, PAGE)
        pa = translated[0][0] if translated and translated[0][0] is not None else None
        replace = fresh_pages is not None and page not in fresh_pages
        if pa is None or replace:
            pa = backend.u.memalign(PAGE, PAGE)
            backend.u.proxy.memset32(pa, 0, PAGE)
        if fresh_pages is not None:
            fresh_pages.add(page)
        # Re-publish the leaf even when it existed. Some pages overlap the cold
        # boot's broad render extent, whose execute permission is not suitable
        # for the corpus's command and shader pages.
        uat.iomap_at(
            backend.space.context, page, pa, PAGE,
            AttrIndex=MemoryAttr.Shared, AP=2, nG=1,
            UXN=0 if executable else 1)
    uat.flush_dirty()
    uat.invalidate_cache()
    backend.u.inst("dsb sy")


def write_dva(backend, address, data):
    """Write through the live UAT and clean every physical destination."""
    written = 0
    for pa, size in backend.space.uat.iotranslate(
            backend.space.context, address, len(data)):
        if pa is None:
            raise RuntimeError("unmapped corpus byte at %#x" % (address + written))
        chunk = data[written:written + size]
        backend.u.iface.writemem(pa, chunk)
        backend.u.proxy.dc_civac(pa, len(chunk))
        written += len(chunk)
    if written != len(data):
        raise RuntimeError("short corpus write: %#x of %#x" % (written, len(data)))


def adopt_completed_opening_group(backend):
    """Continue after final-26.6 cold boot consumed the staged render group."""
    states = {
        kind: queue.indices()
        for kind, (_entry, queue) in backend.muxed_queue_pair(0).items()
    }
    if states and all(
            state["write"] and state["write"] % 3 == 0
            and state["done"] == state["read"] == state["write"]
            for state in states.values()):
        backend.adopt_completed_staged_group()
        print("adopted completed cold-boot render group: %r" % states,
              flush=True)


def packed_cmdbuf(output_va, load_pipeline, load_bind,
                  store_pipeline, store_bind):
    attachment = {"type": 0, "size": 0x4080, "pointer": output_va}
    return drm_asahi_cmdbuf_t.subcon.build({
        "flags": 0,
        "encoder_ptr": G17P_RENDER_CONTEXT_BASE + 0x18000,
        "encoder_id": 0,
        "cmd_ta_id": 0,
        "cmd_3d_id": 0,
        "ds_flags": 0,
        "depth_buffer": 0,
        "stencil_buffer": 0,
        "scissor_array": SCISSOR_VA,
        "depth_bias_array": RESOURCE_BASE + 0x01af_8000,
        "fb_width": 64,
        "fb_height": 64,
        # These programs are retained by the cold boot. The command-line
        # overrides isolate their register bindings from the userspace corpus.
        "load_pipeline": load_pipeline,
        "load_pipeline_bind": load_bind,
        "store_pipeline": store_pipeline,
        "store_pipeline_bind": store_bind,
        "partial_reload_pipeline": 0,
        "partial_reload_pipeline_bind": 0,
        "partial_store_pipeline": 0,
        "partial_store_pipeline_bind": 0,
        "depth_clear_value": 0.0,
        "stencil_clear_value": 0,
        "attachments": [attachment] + [
            {"type": 0, "size": 0, "pointer": 0} for _ in range(15)],
        "attachment_count": 1,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("exp0009", "g1a-base", "m4-full",
                                                "m4-indexed", "a18-m4-closure"),
                        default="exp0009")
    parser.add_argument("--corpus", type=pathlib.Path, default=DEFAULT_CORPUS)
    parser.add_argument("--g1a-controls", type=pathlib.Path, default=G1A_CONTROLS)
    parser.add_argument("--g1a-code", type=pathlib.Path, default=G1A_CODE)
    parser.add_argument("--g1a-context", type=pathlib.Path, default=G1A_CONTEXT)
    parser.add_argument("--m4-full-corpus", type=pathlib.Path,
                        default=M4_FULL_CORPUS)
    parser.add_argument("--m4-indexed-corpus", type=pathlib.Path,
                        default=M4_INDEXED_CORPUS)
    parser.add_argument("--encoder-u32", action="append", type=u32_override,
                        default=[], metavar="OFFSET=VALUE",
                        help="replace one u32 in the corpus VDM before submission")
    parser.add_argument("--fresh-backing", action="store_true",
                        help="remap every corpus page to a fresh PA before writing it")
    parser.add_argument("--executable-va", action="append",
                        type=lambda value: int(value, 0), default=[],
                        help="mark an additional corpus BO base executable; repeatable")
    parser.add_argument("--copy-bo", action="append", type=va_copy, default=[],
                        metavar="SOURCE_VA=DESTINATION_VA",
                        help="copy one corpus BO to another VA; repeatable")
    parser.add_argument("--watch-va", action="append", type=va_span, default=[],
                        metavar="VA:SIZE",
                        help="report byte changes in an additional GPU VA range; repeatable")
    parser.add_argument("--clear-va", action="append", type=va_span, default=[],
                        metavar="VA:SIZE",
                        help="clear an additional GPU VA range before submission; repeatable")
    parser.add_argument("--load-pipeline", type=lambda value: int(value, 0),
                        default=0x01990240)
    parser.add_argument("--load-bind", type=lambda value: int(value, 0),
                        default=0x40)
    parser.add_argument("--store-pipeline", type=lambda value: int(value, 0),
                        default=0x01990640)
    parser.add_argument("--store-bind", type=lambda value: int(value, 0),
                        default=0)
    parser.add_argument("--samples", type=int, choices=(1, 2, 4), default=1,
                        help="sample count for the generated TA/fragment register programs")
    parser.add_argument("--bootstrap", action="store_true",
                        help="execute and verify the retained generated A18 render before "
                             "publishing the corpus as ordinary post-start work")
    args = parser.parse_args()

    if args.profile == "g1a-base":
        bos = g1a_base_bos(args.g1a_controls.expanduser(),
                            args.g1a_code.expanduser(),
                            args.g1a_context.expanduser())
        output_va = G1A_OUTPUT_VA
        output_size = 0x4000
        expected = None
    elif args.profile == "m4-full":
        bos = m4_full_bos(args.m4_full_corpus.expanduser())
        output_va = G1A_OUTPUT_VA
        expected = next((data for va, data, _path in bos
                         if va == output_va), None)
        if expected is None:
            raise RuntimeError("M4 corpus has no render target at %#x" % output_va)
        output_size = len(expected)
    elif args.profile == "m4-indexed":
        bos = m4_full_bos(args.m4_indexed_corpus.expanduser())
        output_va = G1A_OUTPUT_VA
        expected = next((data for va, data, _path in bos
                         if va == output_va), None)
        if expected is None:
            raise RuntimeError("M4 indexed corpus has no render target at %#x" %
                               output_va)
        output_size = len(expected)
    elif args.profile == "a18-m4-closure":
        bos = a18_m4_closure_bos(
            args.m4_full_corpus.expanduser(),
            args.g1a_controls.expanduser(), args.g1a_code.expanduser(),
            args.g1a_context.expanduser())
        output_va = G1A_OUTPUT_VA
        output_size = 0x4000
        expected = None
    else:
        bos = corpus_bos(args.corpus.expanduser())
        output_va = OUTPUT_VA
        expected = next((data for va, data, _path in bos
                         if va == output_va), None)
        if expected is None:
            raise RuntimeError("corpus has no render target at %#x" % output_va)
        output_size = len(expected)

    for source, destination in args.copy_bo:
        matches = [(data, path) for address, data, path in bos
                   if address == source]
        if len(matches) != 1:
            raise RuntimeError("corpus has %d BOs at copy source %#x" %
                               (len(matches), source))
        data, path = matches[0]
        bos.append((destination, data, path))
        print("copied %s: %#x -> %#x" % (path.name, source, destination),
              flush=True)

    for offset, value in args.encoder_u32:
        matches = [index for index, (address, _data, _path) in enumerate(bos)
                   if address == 0x18000]
        if len(matches) != 1:
            raise RuntimeError("corpus has %d VDM BOs at 0x18000" % len(matches))
        index = matches[0]
        address, data, path = bos[index]
        if offset + 4 > len(data):
            raise RuntimeError("VDM override +%#x exceeds %s" % (offset, path))
        patched = bytearray(data)
        old = struct.unpack_from("<I", patched, offset)[0]
        struct.pack_into("<I", patched, offset, value)
        bos[index] = (address, bytes(patched), path)
        print("VDM +%#x: %#010x -> %#010x" % (offset, old, value), flush=True)

    print("render pipelines: load=(%#x,%#x) store=(%#x,%#x)" % (
        args.load_pipeline, args.load_bind,
        args.store_pipeline, args.store_bind), flush=True)
    body = packed_cmdbuf(
        output_va,
        args.load_pipeline, args.load_bind,
        args.store_pipeline, args.store_bind)
    storage = ctypes.create_string_buffer(body)
    submit = types.SimpleNamespace(cmdbuf=ctypes.addressof(storage))

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p

        if args.bootstrap:
            # packed_cmdbuf retains the captured 0x4080 attachment extent, so
            # give it two device pages even though 64x64 BGRA occupies one.
            bootstrap_size = 0x8000
            memfd.truncate(bootstrap_size)
            bootstrap_va = front.create_bo_from_memfd(
                memfd.fileno(), 0, bootstrap_size, 0)
            bootstrap_obj = front.bos[0]
            bootstrap_obj._no_push = True
            bootstrap_body = packed_cmdbuf(
                bootstrap_va,
                args.load_pipeline, args.load_bind,
                args.store_pipeline, args.store_bind)
            bootstrap_storage = ctypes.create_string_buffer(bootstrap_body)
            bootstrap_submit = types.SimpleNamespace(
                cmdbuf=ctypes.addressof(bootstrap_storage))
            bootstrap_before = backend._read_dva(
                bootstrap_va, bootstrap_size)
            if any(bootstrap_before):
                raise RuntimeError("bootstrap target did not begin clear")
            bootstrap_result = front.submit(
                memfd.fileno(), bootstrap_submit)
            bootstrap_after = backend._read_dva(
                bootstrap_va, bootstrap_size)
            bootstrap_changed = sum(
                left != right
                for left, right in zip(bootstrap_before, bootstrap_after))
            bootstrap_submission = getattr(backend, "last_submission", None)
            bootstrap_retired = (
                bootstrap_submission is not None
                and backend.pair_retired(bootstrap_submission))
            print("bootstrap result=%r changed=%d retired=%s" %
                  (bootstrap_result, bootstrap_changed, bootstrap_retired),
                  flush=True)
            if (bootstrap_result != 0 or not bootstrap_retired
                    or bootstrap_changed == 0):
                raise RuntimeError(
                    "retained A18 bootstrap render did not execute")

        executable = {
            RESOURCE_BASE,
            RESOURCE_BASE + 0x0008_8000,
            G17P_RENDER_CONTEXT_BASE + 0x18000,
            G17P_RENDER_CONTEXT_BASE + 0x48000,
            RESOURCE_BASE + 0x0012_0000,
            RESOURCE_BASE + 0x0012_8000,
            RESOURCE_BASE + 0x0013_0000,
            RESOURCE_BASE + 0x0013_8000,
        }
        executable.update(args.executable_va)
        fresh_pages = set() if args.fresh_backing else None
        for original, data, path in bos:
            address = target_va(original)
            ensure_mapping(backend, address, len(data), address in executable,
                           fresh_pages=fresh_pages)
            if original == output_va:
                write_dva(backend, address, bytes(len(data)))
            else:
                write_dva(backend, address, data)
            print("loaded %-66s at %#x (%#x bytes)" %
                  (path.name, address, len(data)), flush=True)

        if args.profile == "g1a-base":
            # The retained baseline shader fetches one float2 vertex buffer from
            # this explicit VA. Its surrounding shared-heap page is deliberately
            # preserved because it also carries compiler-generated staging data.
            vertices = struct.pack("<6f", -1.0, -1.0, 3.0, -1.0, -1.0, 3.0)
            ensure_mapping(backend, G1A_VERTEX_VA, len(vertices), False,
                           fresh_pages=fresh_pages)
            write_dva(backend, G1A_VERTEX_VA, vertices)

        ensure_mapping(backend, output_va, output_size, False,
                       fresh_pages=fresh_pages)
        write_dva(backend, output_va, bytes(output_size))
        ensure_mapping(backend, SCISSOR_VA, 0x10, False,
                       fresh_pages=fresh_pages)
        write_dva(backend, SCISSOR_VA, struct.pack("<IIIf", 64, 64, 0, 1.0))
        for address, size in args.clear_va:
            write_dva(backend, address, bytes(size))
            print("cleared %#x:%#x before submission" % (address, size),
                  flush=True)
        before = backend._read_dva(output_va, output_size)
        if any(before):
            raise RuntimeError("render target did not clear")
        watched_before = {
            (address, size): backend._read_dva(address, size)
            for address, size in args.watch_va
        }

        submit_error = None
        try:
            # Corpus BOs are deliberately mapped at their recorded userspace
            # addresses instead of allocated through the DRM memfd shim. Give
            # the backend the same ownership/extent object a real shim BO would
            # provide without weakening submit_drm's live-BO check.
            context_id = front.g17p_context_for_fd(memfd.fileno())
            target_obj = types.SimpleNamespace(
                _addr=output_va, _size=max(output_size, 0x4080))
            drm = drm_asahi_cmdbuf_t.parse(body)
            if args.samples != 1:
                drm.samples = args.samples
                drm.ppp_multisamplectl = {
                    2: 0x44cc,
                    4: 0xeaa26e26,
                }[args.samples]
                drm.ppp_ctrl = 0x202
                drm.iogpu_unk_49 = 8
            backend.bind_color_attachment(
                output_va, min(output_size, target_obj._size),
                drm.fb_width, drm.fb_height)
            cmdbuf = command_buffer_from_drm(
                drm, pipeline_base=backend.ctx.pipeline_base,
                **front.g17p_supplied())
            adopt_completed_opening_group(backend)
            queue_state = {
                kind: queue.indices()
                for kind, (_entry, queue) in backend.muxed_queue_pair(0).items()
            }
            if (queue_state
                    and all(state["done"] == state["read"] == 0
                            and state["write"] == 3
                            for state in queue_state.values())):
                print("executing caller-rewritten cold-boot group", flush=True)
                backend.execute_rewritten_staged_group(cmdbuf)
            else:
                backend.submit_drm(
                    drm, (target_obj,), context_id=context_id,
                    **front.g17p_supplied())
            result = 0
        except TimeoutError as error:
            result = -1
            submit_error = error
        submission = getattr(backend, "last_submission", None)
        if submission is None:
            raise RuntimeError("corpus submission failed before completion")
        after = backend._read_dva(output_va, output_size)
        changed = sum(left != right for left, right in zip(before, after))
        matching = (sum(left == right for left, right in zip(expected, after))
                    if expected is not None else 0)
        pixels = sum(any(after[offset:offset + 4])
                     for offset in range(0, min(0x4000, len(after)), 4))
        expected_size = len(expected) if expected is not None else 0
        print("result: %d bytes changed, %d/%d bytes match corpus, %d nonzero pixels" %
              (changed, matching, expected_size, pixels), flush=True)
        for (address, size), old in watched_before.items():
            new = backend._read_dva(address, size)
            changed_watch = sum(left != right for left, right in zip(old, new))
            print("watch %#x:%#x: %d bytes changed, %d nonzero before, %d after" %
                  (address, size, changed_watch,
                   sum(value != 0 for value in old),
                   sum(value != 0 for value in new)), flush=True)
        witnesses = {}
        for name, obj in sorted(backend.render_objects.items()):
            data = backend._read_dva(obj._addr, obj._size)
            nonzero = sum(value != 0 for value in data)
            witnesses[name] = nonzero
        print("render witnesses: %s" % ", ".join(
            "%s=%d" % item for item in sorted(witnesses.items())), flush=True)
        if args.profile in ("g1a-base", "a18-m4-closure"):
            expected_pixel = bytes((0xbf, 0x80, 0x40, 0xff))
            print("g1a expected-color pixels: %d" % after.count(expected_pixel),
                  flush=True)
        if submit_error is not None:
            print("submission wait: %s" % submit_error, flush=True)
            print("scheduler drained: %s" % backend.pair_retired(submission),
                  flush=True)
            raise submit_error
        if result != 0:
            raise RuntimeError("corpus submission returned %r" % result)
        if not backend.pair_retired(submission):
            raise RuntimeError("queues retired but the scheduler did not drain")
        if changed == 0 or pixels == 0:
            raise RuntimeError("corpus submission completed without drawing")
        print("PASS: clean-room A18 triangle executed through the DRM backend", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
