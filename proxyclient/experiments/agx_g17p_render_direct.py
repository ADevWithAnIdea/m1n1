#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit one native-shape direct triangle and require target bytes to change."""

import os
import pathlib
import json
import struct
import sys
import tempfile
import time


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_ALLOW_INTERNAL_RENDER_POINTERS"] = "1"
os.environ["G17P_LOGICAL_VM_SWITCH"] = "1"
os.environ["G17P_LOGICAL_VM_STRIDE"] = "0"

from agx_g17p_compute import (  # noqa: E402
    drain_boot_group,
    run_render_cadence,
)
from agx_g17p_render_uapi_timestamps import command  # noqa: E402
from m1n1.agx import g17p_encoder, g17p_render, g17p_shim  # noqa: E402
from m1n1.agx.g17p_modern import PAGE_SIZE  # noqa: E402
from m1n1.agx.g17p_uapi import (  # noqa: E402
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_WRITE,
    DRM_ASAHI_CMD_RENDER,
    DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES,
    DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS,
    drm_asahi_attachment,
    drm_asahi_cmd_render,
    drm_asahi_gem_bind_op,
)
from m1n1.agx.shim import DRMAsahiShim  # noqa: E402


FD = 74
OUTPUT_HANDLE = 1
OUTPUT_DVA = 0x10000058000
OUTPUT_SIZE = 2 * PAGE_SIZE
ENCODER_DVA = 0x1000018000
CONTEXT_BASE = 0x1000000000
USC_EXEC_BASE = 0x10000000000
WIDTH = 128
HEIGHT = 37
USE_NATIVE_CONTEXT4_TRANSPORT = False
PHASE_WITNESSES = {
    "ta_status": (0x1000078000, PAGE_SIZE),
    "fragment_status": (0x10001A8000, PAGE_SIZE),
    "tilemap": (0x10001B0000, PAGE_SIZE),
    "heapmeta": (0x10001B1000, 0x3000),
    "tile_parameter_cache": (0x10001D8000, PAGE_SIZE),
    "aux_fb": (0x10000250000, PAGE_SIZE),
    "tiler_heap_target": (0x10000018000, PAGE_SIZE),
    "load_render_store": (0x10000118000, PAGE_SIZE),
    "tiler_sparse": (0x10000140000, PAGE_SIZE),
}
NATIVE_CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260817_181315"
)
NATIVE_DESCRIPTOR_CAPTURE = NATIVE_CAPTURE
NATIVE_CODE_CAPTURE = NATIVE_CAPTURE


class NativeRenderObject:
    """Non-owning view of a subrange inside another mapped render object."""

    def __init__(self, address, size):
        self._addr = address
        self._size = size


def captured_page(half, address, capture=NATIVE_CAPTURE):
    root = capture / half
    metadata = json.loads((root / "pages.json").read_text())["pages"]
    record = next(item for item in metadata if item["dva"] == address)
    body = (root / "pages.bin").read_bytes()
    start = record["capture_offset"]
    return body[start:start + PAGE_SIZE]


def captured_object(half, address, size, capture=NATIVE_CAPTURE):
    result = bytearray()
    while len(result) < size:
        cursor = address + len(result)
        page = captured_page(half, cursor & ~(PAGE_SIZE - 1), capture)
        offset = cursor & (PAGE_SIZE - 1)
        take = min(size - len(result), PAGE_SIZE - offset)
        result.extend(page[offset:offset + take])
    return bytes(result)


def captured_scan_pages(half, capture=NATIVE_CAPTURE):
    """Return every page retained by the bounded coherent client scan."""
    root = capture / half
    metadata = json.loads((root / "pages.json").read_text())["pages"]
    body = (root / "pages.bin").read_bytes()
    result = {}
    for record in metadata:
        if not any(source.get("kind") == "target_descriptor_scan_page"
                   for source in record.get("sources", ())):
            continue
        start = record["capture_offset"]
        result[record["dva"]] = body[start:start + PAGE_SIZE]
    return result


def captured_scan_mappings(half, capture=NATIVE_CAPTURE):
    """Return coherent client pages with their exact native UAT leaf policy."""
    root = capture / half
    metadata = json.loads((root / "pages.json").read_text())["pages"]
    body = (root / "pages.bin").read_bytes()
    result = {}
    for record in metadata:
        if not any(source.get("kind") == "target_descriptor_scan_page"
                   for source in record.get("sources", ())):
            continue
        required = ("attr_index", "ap", "pxn", "uxn", "os")
        missing = [field for field in required if field not in record]
        if missing:
            raise RuntimeError(
                "captured page %#x has no native leaf %s" % (
                    record["dva"], ", ".join(missing)))
        start = record["capture_offset"]
        result[record["dva"]] = {
            "body": body[start:start + PAGE_SIZE],
            "flags": {
                "AttrIndex": record["attr_index"],
                "AP": record["ap"],
                "PXN": record["pxn"],
                "UXN": record["uxn"],
                "OS": record["os"],
                "nG": 1,
            },
        }
    return result


def captured_all_pages(half, capture=NATIVE_CAPTURE):
    """Return every retained page, including its capture provenance."""
    root = capture / half
    metadata = json.loads((root / "pages.json").read_text())["pages"]
    body = (root / "pages.bin").read_bytes()
    return {
        record["dva"]: {
            "body": body[
                record["capture_offset"]:
                record["capture_offset"] + PAGE_SIZE],
            "sources": record.get("sources", []),
        }
        for record in metadata
    }


def captured_registers(half, descriptor, register_offset,
                       capture=NATIVE_CAPTURE):
    body = captured_object(half, descriptor, PAGE_SIZE, capture=capture)
    cursor = register_offset
    registers = []
    empty = 0
    while cursor + 12 <= len(body):
        number, value = struct.unpack_from("<IQ", body, cursor)
        if number == 0 and value == 0:
            empty += 1
            if empty == 3:
                break
        else:
            empty = 0
            registers.append((number, value))
        cursor += 12
    return registers


def captured_submission_descriptor(half, capture=NATIVE_CAPTURE):
    target = json.loads((capture / half / "target.json").read_text())
    return target["queues"][0]["inner_entries"][0][0]


def report_register_differences(label, native, generated):
    differences = []
    for index, (native_entry, generated_entry) in enumerate(
            zip(native, generated)):
        if native_entry != generated_entry:
            differences.append((index, native_entry, generated_entry))
    print(
        "G17P DIRECT %s registers native=%d generated=%d differences=%d" % (
            label, len(native), len(generated), len(differences)),
        flush=True,
    )
    for index, native_entry, generated_entry in differences:
        print(
            "  %s[%02d] reg native=%#x/%#018x generated=%#x/%#018x" % (
                label, index, native_entry[0], native_entry[1],
                generated_entry[0], generated_entry[1]),
            flush=True,
        )


def direct_stream():
    return g17p_encoder.build_encoder(g17p_encoder.G17PEncoderParameters(
        context_base=CONTEXT_BASE,
        binds=[
            g17p_encoder.G17PBindPair(CONTEXT_BASE + offset, control)
            for offset, control in (
                (0x40, 0x700),
                (0x58000, 0x500),
                (0x5801c, 0x700),
                (0x58030, 0x500),
                (0x5804c, 0xa00),
                (0x68900, 0x300),
                (0x58060, 0x200),
                (0x5806c, 0x200),
            )
        ],
        draw_state=CONTEXT_BASE + 0x48000,
        vertex_count=3,
        instance_count=1,
        opcode=g17p_encoder.DRAW_OPCODE_DIRECT,
        header_state=0x4a00,
        header_class=0x404,
    ))


def render_commands():
    attachment = drm_asahi_attachment(OUTPUT_DVA, OUTPUT_SIZE, 0, 0)
    payload = drm_asahi_cmd_render()
    payload.flags = DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
    payload.vdm_ctrl_stream_base = ENCODER_DVA
    payload.isp_scissor_base = 0x10000148000
    payload.isp_dbias_base = 0x100002A0000
    payload.ppp_multisamplectl = 0x88
    payload.ppp_ctrl = 0x202
    payload.width_px = WIDTH
    payload.height_px = HEIGHT
    payload.layers = 1
    payload.utile_width_px = 32
    payload.utile_height_px = 32
    payload.samples = 1
    payload.sample_size_B = 8
    payload.isp_bgobjdepth = 0x3F800000
    payload.isp_merge_upper_x = 0x3C5DB3D9
    payload.isp_merge_upper_y = 0x3D3FBE23
    payload.bg.usc = 0x00138100
    payload.bg.rsrc_spec = 0x40
    payload.eot.usc = 0x00138340
    return (
        command(DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS, attachment.to_bytes())
        + command(DRM_ASAHI_CMD_RENDER, payload.to_bytes())
    )


def changed_span(before, after):
    changed = [index for index, pair in enumerate(zip(before, after))
               if pair[0] != pair[1]]
    return None if not changed else (changed[0], changed[-1] + 1)


def read_phase_witnesses(backend):
    return {
        name: backend._read_dva(address, size)
        for name, (address, size) in PHASE_WITNESSES.items()
    }


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_render_direct.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), OUTPUT_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        drain_boot_group(front, backend)
        runtime = front.g17p_runtime
        if runtime is None:
            raise RuntimeError("cold boot exposes no runtime control plane")
        cadence = run_render_cadence(front, backend, runtime)
        if cadence["workload"]["next_target"] != 31:
            raise RuntimeError("final-26.6 render cadence did not reach 32 work items")
        print(
            "G17P DIRECT reached the output-positive 32-render lifecycle",
            flush=True,
        )

        # The prior discriminator redirected the admitted ASID through a cloned
        # low root.  Remap this final focused pass into the already admitted
        # primary context so cached firmware context state cannot distinguish it
        # from the output-positive opening cadence.  This is the last submission,
        # so replacing the cadence's client mappings is intentional.
        front.g17p_fd_contexts.clear()
        vm = front.modern.create_vm(FD, 0x7000000000, 0x7800000000)
        if int(vm.token) != backend.primary_execution_context:
            raise RuntimeError(
                "direct render did not acquire admitted primary context")
        backend.activate_execution_context(int(vm.token))
        if USE_NATIVE_CONTEXT4_TRANSPORT:
            backend.forced_queue_pair = 4
            backend.forced_channel_pair = 2
            backend.forced_descriptor_pair = 3
            backend.forced_descriptor_context = 4
            transport = "native context-4 queue pair 4 on TA_2/3D_2"
        else:
            backend.forced_queue_pair = 0
            backend.forced_channel_pair = 0
            backend.forced_descriptor_pair = 0
            backend.forced_descriptor_context = None
            transport = "output-positive generated queue pair 0 on TA_0/3D_0"
        print(
            "G17P DIRECT using admitted primary context %d, %s" % (
                int(vm.token), transport),
            flush=True,
        )

        stream = direct_stream()
        stream_page = stream + bytes(PAGE_SIZE - len(stream))
        direct_pages = {
            CONTEXT_BASE: g17p_render.build_direct_bind0(),
            ENCODER_DVA: stream_page,
            CONTEXT_BASE + 0x48000: g17p_render.build_index_buffer(),
            CONTEXT_BASE + 0x58000: g17p_render.build_direct_bind_group(),
            CONTEXT_BASE + 0x68000: g17p_render.build_viewport(WIDTH, HEIGHT),
        }
        native_high_mappings = captured_scan_mappings("3D_2")
        for address in range(OUTPUT_DVA, OUTPUT_DVA + OUTPUT_SIZE, PAGE_SIZE):
            native_high_mappings.pop(address, None)
        native_high_pages = {
            address: mapping["body"]
            for address, mapping in native_high_mappings.items()
        }
        direct_pages.update(native_high_pages)
        print(
            "G17P DIRECT coherent high graph pages=%d native_uxn=%d" % (
                len(native_high_pages),
                sum(mapping["flags"]["UXN"]
                    for mapping in native_high_mappings.values())),
            flush=True,
        )
        for address, body in direct_pages.items():
            flags = native_high_mappings.get(address, {}).get("flags", {
                "AttrIndex": 2,
                "AP": 2,
                "PXN": 0,
                "UXN": 0,
                "OS": 1,
                "nG": 1,
            })
            backend.ctx.gobj.new_at(
                address, PAGE_SIZE,
                name="g17p_direct_fresh_%x" % address,
                **flags,
            )
            backend._write_dva(address, body)
            if backend._read_dva(address, len(body)) != body:
                raise RuntimeError(
                    "direct render page %#x did not read back" % address)

        # This pass suballocates heap metadata and TPC state from the tilemap
        # extent instead of naming the retained profile's separate objects.
        front.g17p_submission_state["heapmeta"] = 0x10001B1000
        front.g17p_submission_state["aux_fb"] = 0x10000250000
        # This native TPC address is a subrange of the larger tilemap extent;
        # build_submission allocates that complete extent on fresh backing.
        backend.render_objects["tile_parameter_cache"] = NativeRenderObject(
            0x10001D8000, PAGE_SIZE)
        # The UAPI carries only the low resource-spec word. This native pass's
        # generation-specific high half differs from the retained profile.
        g17p_shim.G17P_LOAD_PIPELINE_BIND_PREFIX = 0xFFFF800000000000

        native_tiling_descriptor = captured_submission_descriptor(
            "TA_2", capture=NATIVE_DESCRIPTOR_CAPTURE)
        native_fragment_descriptor = captured_submission_descriptor(
            "3D_2", capture=NATIVE_DESCRIPTOR_CAPTURE)
        native_tiling = captured_registers(
            "TA_2", native_tiling_descriptor, 0x60,
            capture=NATIVE_DESCRIPTOR_CAPTURE)
        native_fragment = captured_registers(
            "3D_2", native_fragment_descriptor, 0xA0,
            capture=NATIVE_DESCRIPTOR_CAPTURE)
        native_tiling_body = captured_object(
            "TA_2", native_tiling_descriptor, 0x9c0,
            capture=NATIVE_DESCRIPTOR_CAPTURE)
        native_fragment_body = captured_object(
            "3D_2", native_fragment_descriptor, 0x2240,
            capture=NATIVE_DESCRIPTOR_CAPTURE)
        original_build_submission = backend.build_submission

        def build_submission_with_register_report(cmdbuf):
            built = original_build_submission(cmdbuf)
            report_register_differences(
                "TA", native_tiling, built["tiling_registers"])
            report_register_differences(
                "3D", native_fragment, built["fragment_registers"])
            if USE_NATIVE_CONTEXT4_TRANSPORT:
                built["tiling_registers"] = list(native_tiling)
                built["fragment_registers"] = list(native_fragment)
                print(
                    "G17P DIRECT installed coherent current native register programs",
                    flush=True,
                )
            return built

        backend.build_submission = build_submission_with_register_report

        prepublish_dir = pathlib.Path(
            "/Users/user/asahi_re/artifacts/agx_g17p/"
            "render_direct_prepublish_%d" % int(time.time()))
        prepublish_dir.mkdir(parents=True)
        prepublish_metadata = {}
        original_report_pair_progress = backend.report_pair_progress
        native_control_pages = captured_all_pages(
            "3D_2", capture=NATIVE_DESCRIPTOR_CAPTURE)
        original_pre_notify_hook = backend.pre_notify_hook
        def snapshot_control_graph(live_backend, pair_index):
            if original_pre_notify_hook is not None:
                original_pre_notify_hook(live_backend, pair_index)
            records = []
            generated_blob = bytearray()
            for address, native in sorted(native_control_pages.items()):
                if address >= 0xffff000000000000:
                    translated = live_backend.space.uat.iotranslate_root(
                        live_backend.firmware_high_root, address, PAGE_SIZE)
                else:
                    translated = live_backend.space.uat.iotranslate(
                        live_backend.space.context, address, PAGE_SIZE)
                if not translated or any(pa is None for pa, _size in translated):
                    continue
                generated = live_backend._read_dva(address, PAGE_SIZE)
                if len(generated) != PAGE_SIZE:
                    raise RuntimeError(
                        "short generated control-page read at %#x" % address)
                offset = len(generated_blob)
                generated_blob.extend(generated)
                native_body = native["body"]
                records.append({
                    "address": address,
                    "capture_offset": offset,
                    "different_bytes": sum(
                        left != right
                        for left, right in zip(native_body, generated)),
                    "native_nonzero": sum(bool(value) for value in native_body),
                    "generated_nonzero": sum(bool(value) for value in generated),
                    "sources": native["sources"],
                })
            (prepublish_dir / "control_pages_generated.bin").write_bytes(
                generated_blob)
            (prepublish_dir / "control_pages_compare.json").write_text(
                json.dumps(records, indent=2, sort_keys=True) + "\n")
            differing = sorted(
                (record for record in records if record["different_bytes"]),
                key=lambda record: record["different_bytes"], reverse=True)
            print(
                "G17P DIRECT control graph compared=%d differing=%d exact=%d" %
                (len(records), len(differing), len(records) - len(differing)),
                flush=True,
            )
            for record in differing[:24]:
                print(
                    "  control page %#x diff=%d native_nz=%d generated_nz=%d" %
                    (record["address"], record["different_bytes"],
                     record["native_nonzero"], record["generated_nonzero"]),
                    flush=True,
                )

        if USE_NATIVE_CONTEXT4_TRANSPORT:
            backend.pre_notify_hook = snapshot_control_graph

        def report_pair_progress_with_snapshot(pair, prefix=""):
            tiling_descriptor = int(pair["tiling"][0])
            shared = struct.unpack(
                "<Q", backend._read_dva(tiling_descriptor + 0x20, 8))[0]
            primary_index, low_alias = struct.unpack(
                "<QQ", backend._read_dva(shared + 0x20, 16))
            high_translation = backend.space.uat.iotranslate_root(
                backend.firmware_high_root, primary_index, PAGE_SIZE)
            low_translation = backend.space.uat.iotranslate(
                backend.space.context, low_alias, PAGE_SIZE)
            high_pa = high_translation[0][0] if high_translation else None
            low_pa = low_translation[0][0] if low_translation else None
            if high_pa is None or low_pa != high_pa:
                raise RuntimeError(
                    "primary-index aliases high=%#x/%r low=%#x/%r disagree" %
                    (primary_index, high_pa, low_alias, low_pa))
            print(
                "G17P DIRECT primary-index dual alias high=%#x low=%#x pa=%#x" %
                (primary_index, low_alias, high_pa),
                flush=True,
            )
            for label, items in pair.items():
                descriptor = int(items[0])
                if label == "tiling":
                    descriptor_size = 0x9c0
                    tail_start = 0x3cc
                    native_body = native_tiling_body
                    live_ranges = (
                        (0x760, 0x768),
                        (0x79c, 0x7b4),
                        (0x86e, 0x876),
                        (0x8a6, 0x8d8),
                        (0x934, 0x93c),
                        (0x945, 0x94d),
                    )
                else:
                    descriptor_size = 0x2240
                    tail_start = 0x4cc
                    native_body = native_fragment_body
                    live_ranges = (
                        (0x7a0, 0x7a8),
                        (0x0ec0, 0x0ec8),
                        (0x15e0, 0x15e8),
                        (0x1d00, 0x1d08),
                        (0x2140, 0x2150),
                        (0x2150, 0x2174),
                        (0x21ce, 0x21d6),
                        (0x21df, 0x21e7),
                    )
                generated_body = backend._read_dva(
                    descriptor, descriptor_size)
                combined = bytearray(generated_body)
                combined[tail_start:] = native_body[tail_start:descriptor_size]
                for start, end in live_ranges:
                    combined[start:end] = generated_body[start:end]
                backend._write_dva(descriptor, combined)
                if backend._read_dva(descriptor, descriptor_size) != bytes(combined):
                    raise RuntimeError(
                        "%s combined native tail did not read back" % label)
                print(
                    "G17P DIRECT installed complete native %s tail %#x:%#x "
                    "with live topology restored" %
                    (label, tail_start, descriptor_size),
                    flush=True,
                )
                if label == "tiling":
                    print(
                        "G17P DIRECT native TA tail includes TPC pointer "
                        "at 0x780:0x788",
                        flush=True,
                    )
                descriptor_body = backend._read_dva(
                    descriptor, descriptor_size)
                optional_body = backend._read_dva(int(items[1]), 0xc0)
                event_body = backend._read_dva(int(items[2]), 0x40)
                (prepublish_dir / (label + "_descriptor.bin")).write_bytes(
                    descriptor_body)
                (prepublish_dir / (label + "_optional.bin")).write_bytes(
                    optional_body)
                (prepublish_dir / (label + "_event.bin")).write_bytes(
                    event_body)
                prepublish_metadata[label] = {
                    "descriptor": descriptor,
                    "descriptor_size": descriptor_size,
                    "items": [int(address) for address in items],
                }
                print(
                    "G17P DIRECT prepublish %s descriptor %#x -> %s" % (
                        label, descriptor, prepublish_dir),
                    flush=True,
                )
            (prepublish_dir / "metadata.json").write_text(
                json.dumps(prepublish_metadata, indent=2, sort_keys=True)
                + "\n")
            return original_report_pair_progress(pair, prefix)

        if USE_NATIVE_CONTEXT4_TRANSPORT:
            backend.report_pair_progress = report_pair_progress_with_snapshot

        output = front.modern.create_bo(
            FD, OUTPUT_HANDLE, 0, OUTPUT_SIZE)
        front.modern.bind(FD, vm.vm_id, drm_asahi_gem_bind_op(
            DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
            output.handle, 0, OUTPUT_SIZE, OUTPUT_DVA))
        queue = front.modern.create_queue(
            FD, vm.vm_id, 1, USC_EXEC_BASE)

        before = bytes(OUTPUT_SIZE)
        output.token["map"][:] = before
        phase_before = read_phase_witnesses(backend)
        fence, commands = front.modern.submit(
            FD, queue.queue_id, render_commands())
        phase_after = read_phase_witnesses(backend)
        after = bytes(output.token["map"][:OUTPUT_SIZE])
        changed = sum(left != right for left, right in zip(before, after))
        nonzero = sum(value != 0 for value in after)
        print(
        "G17P DIRECT RENDER fence=%d changed=%d nonzero=%d span=%r "
            "encoder=%#x vertex_count=3 dimensions=%dx%d" % (
                fence.signaled(), changed, nonzero,
                changed_span(before, after), ENCODER_DVA, WIDTH, HEIGHT),
            flush=True,
        )
        print("G17P DIRECT prepublish artifact %s" % prepublish_dir, flush=True)
        for name, (address, _size) in PHASE_WITNESSES.items():
            old = phase_before[name]
            new = phase_after[name]
            delta = sum(left != right for left, right in zip(old, new))
            print(
                "G17P DIRECT PHASE %-20s dva=%#x changed=%d nonzero=%d "
                "span=%r" % (
                    name, address, delta, sum(value != 0 for value in new),
                    changed_span(old, new)),
                flush=True,
            )
        if not fence.signaled():
            raise RuntimeError("direct render fence did not signal")
        if not changed:
            raise RuntimeError("direct render changed zero target bytes")
        if len(commands) != 1:
            raise RuntimeError("direct render resolved %d commands" % len(commands))
        print("G17P DIRECT RENDER PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
