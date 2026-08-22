#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit the own-source minimum partial render through the modern UAPI.

The workload bundle contains only caller/compiler pages extracted from our
own-source Metal program. Queue state, work descriptors, register programs,
parameter-buffer objects, and completion state are built by the shim.

Set ``G17P_PARTIAL_RESOURCE_NEGATIVE=1`` to replace only the caller's reload
resource block with its valid clear block. Set ``G17P_PARTIAL_SUBMISSIONS``
to repeat the complete partial-render command in one firmware lifetime. Set
``G17P_PARTIAL_RENDER_CADENCE=1`` to establish the measured output-positive
32-render lifecycle before publishing the focused command.  The focused
``G17P_PARTIAL_NATIVE_REGISTER_TAIL=1`` discriminator substitutes only the
ten values that still differ from the exact native 128-by-128 descriptor pair.
"""

import hashlib
import datetime
import json
import math
import os
import pathlib
import struct
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PAYLOAD = pathlib.Path(os.environ.get(
    "G17P_PARTIAL_PAYLOAD",
    "/Users/user/asahi_re/artifacts/agx_g17p/workload_payloads/"
    "own_source_partial_accumulate_48217/manifest.json",
))

# Preserve the ordinary source-built opening payload through cold boot.  The
# partial bundle is mapped and installed only after that unavoidable group has
# retired; replacing the opening program leaves final-26.6 unable to consume
# the following runtime pair-registration tick.
os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_ALLOW_INTERNAL_RENDER_POINTERS"] = "1"
os.environ["G17P_LOGICAL_VM_SWITCH"] = "1"
os.environ["G17P_LOGICAL_VM_STRIDE"] = "0"
os.environ["G17P_SHARE_BOUND_SUBMISSION_STATE"] = "1"
os.environ["G17P_SHARE_BOUND_RECORD_POOLS"] = "1"
os.environ["G17P_NATIVE_PARTIAL_OPENING_QUEUE"] = "1"
# The retained opening parameter-buffer graph is the eight-group context-2
# form, not the generic 32-group created-pair inventory.  Its primary-index
# page was isolated on hardware as the last content dependency preventing a
# directly constructed partial render from executing.
os.environ["G17P_PARTIAL_OPENING_GRAPH"] = "1"

# A source-built compute command is independently proven to execute from an
# otherwise clean firmware lifetime.  Retain that backend when requested so
# the focused render can test whether the missing partial-render dependency is
# executed device lifecycle rather than another captured byte.  This must be
# selected before DRMAsahiShim.init() cold-boots firmware.
SOURCE_COMPUTE_BOOTSTRAP = (
    os.environ.get("G17P_PARTIAL_SOURCE_COMPUTE_BOOTSTRAP") == "1")
SOURCE_RENDER_BOOTSTRAP = (
    os.environ.get("G17P_PARTIAL_SOURCE_RENDER_BOOTSTRAP") == "1")
if SOURCE_COMPUTE_BOOTSTRAP:
    os.environ["G17P_MODERN_DIRECT_BOOTSTRAP"] = "1"

sys.path.insert(0, str(ROOT / "proxyclient"))
sys.path.insert(0, str(HERE))

from agx_g17p_compute import (  # noqa: E402
    FINAL_26_6_CLASS1_SUPPORT,
    FINAL_26_6_CLASS3_SUPPORT,
    FINAL_26_6_RENDER_PREFIX_COUNT,
    PRIMARY_CONTROL_OPERAND,
    drain_boot_group,
    install_channel_control_record,
    install_final_26_6_control_objects,
    map_client,
    map_firmware,
    run_render_cadence,
    run_render_cadence_submission,
    snapshot_generated_render_slot,
)
from agx_g17p_render_uapi_timestamps import command  # noqa: E402
from m1n1.agx import (  # noqa: E402
    g17p,
    g17p_compute,
    g17p_encoder,
    g17p_render,
    g17p_shim,
    g17p_submission,
)
from m1n1.agx.g17p_modern import PAGE_SIZE  # noqa: E402
from m1n1.hw.uat import MemoryAttr, Page_PTE  # noqa: E402
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


FD = 76
CONTEXT_BASE = 0x1000000000
ENCODER_DVA = CONTEXT_BASE + 0x18000
DRAW_STATE_DVA = CONTEXT_BASE + 0x48000
BIND_GROUP_DVA = CONTEXT_BASE + 0x58000
VIEWPORT_DVA = CONTEXT_BASE + 0x68000
USC_EXEC_BASE = 0x10000000000
RESOURCE_DVA = 0x100001C8000
SCISSOR_DVA = 0x100001F8000
DBIAS_DVA = 0x10000350000
WIDTH = 128
HEIGHT = 128
TRIANGLE_COUNT = 48_217
VERTEX_COUNT = TRIANGLE_COUNT * 3
ATTACHMENT_COUNT = 8
OUTPUT_SIZE = 4 * PAGE_SIZE
OUTPUT_DVAS = tuple(
    0x10000058000 + index * 0x18000
    for index in range(ATTACHMENT_COUNT)
)
PARTIAL_GRAPH_PHYSICAL_PAGES = (
    0xFFFFFC20C08F0000,  # primary index (also aliased at 0x1000190000)
    0xFFFFFC20C08E0000,  # secondary index
    0xFFFFFC2001680000,  # Pool A slots
    0xFFFFFC20016A0000,  # Pool B slots
    0xFFFFFC2001698000,  # packed-shared slots
    0xFFFFFC20016A8000,  # lifecycle flag
    0xFFFFFC20C08C8000,  # Pool A records
    0xFFFFFC20C08D8000,  # Pool B records and zero-shared object
    0xFFFFFC20C0908000,  # packed shared object
)
PARTIAL_TRANSPORT_PHYSICAL_PAGES = (
    0xFFFFFC20C07B8000,  # channel-control records
    0xFFFFFC20C07D0000,  # current-job records
)
PARTIAL_PARAMETER_PHYSICAL_PAGES = (
    0x1000078000,  # TA status
    0x10001A8000,  # fragment status
    0x10001B0000, 0x10001B4000, 0x10001B8000, 0x10001BC000,
    0x10001C0000, 0x10001C4000, 0x10001C8000, 0x10001CC000,
    0x10001D0000, 0x10001D8000,  # tilemap/PB pages present natively
)
PARTIAL_EXECUTION_PHYSICAL_PAGES = (
    0xFFFFFC20C0018000,  # TA descriptor
    0xFFFFFC20C00B0000, 0xFFFFFC20C00B4000,  # 3D descriptor
    0xFFFFFC20C05E8000,  # event records
    0xFFFFFC20C0600000,  # optional records
    0xFFFFFC20C0668000, 0xFFFFFC20C066C000,
    0xFFFFFC20C0670000,  # job list, rings, pointers, queue records
    0xFFFFFC20C08D0000,  # shared control
    0xFFFFFC2001688000,  # shared-control inner record
) + tuple(
    0xFFFFFC2000278000 + index * PAGE_SIZE for index in range(8)
) + tuple(
    0xFFFFFC20002A0000 + index * PAGE_SIZE for index in range(8)
)
PARTIAL_SCHEDULER_PHYSICAL_PAGES = (
    0x7001838000,
    0x7001840000,
)


def remap_outputs_to_native_physical(backend):
    """Reback only the eight outputs with their native-capture physical pages.

    This discriminator imports addresses and PTE policy, never captured bytes:
    every destination page is overwritten with the current source-built zero
    contents before its new mapping becomes visible to the GPU.
    """
    snapshot = pathlib.Path(os.environ.get(
        "G17P_PARTIAL_NATIVE_PHYSICAL_REFERENCE",
        "/Users/user/asahi_re/artifacts/agx_g17p/"
        "native_partial_pre_kick_20260819_234640"))
    manifest = json.loads((snapshot / "manifest.json").read_text())
    render_roots = [
        root for root in manifest["root_mappings"]
        if int(root["root_ctx_id"]) == 3 and int(root["selector"]) == 0
    ]
    if len(render_roots) != 1:
        raise RuntimeError(
            "native physical reference has %d context-3 render roots" %
            len(render_roots))
    render_root = render_roots[0]
    mappings = {
        int(mapping["va"]): mapping
        for mapping in render_root["mappings"]
    }

    heap_ranges = []
    cursor = int(backend.u.heap.offset)
    for blocks, used in backend.u.heap.blocks:
        size = int(blocks) * int(backend.u.heap.block)
        if used:
            heap_ranges.append((cursor, cursor + size))
        cursor += size

    spaces = [backend.space]
    if backend.space.mirror_space is not None:
        spaces.append(backend.space.mirror_space)
    remapped = []
    for base in OUTPUT_DVAS:
        for offset in range(0, OUTPUT_SIZE, PAGE_SIZE):
            address = base + offset
            mapping = mappings.get(address)
            if mapping is None or mapping.get("blob_index") is None:
                raise RuntimeError(
                    "native physical reference has no output page %#x" %
                    address)
            target = int(mapping["pa"])
            for start, end in heap_ranges:
                if target < end and start < target + PAGE_SIZE:
                    raise RuntimeError(
                        "native output PA %#x overlaps live heap %#x-%#x" %
                        (target, start, end))

            body = backend._read_dva(address, PAGE_SIZE)
            if any(body):
                raise RuntimeError(
                    "partial output %#x was nonzero before physical reback" %
                    address)
            backend.u.iface.writemem(target, body)
            backend.u.proxy.dc_civac(target, PAGE_SIZE)
            native_pte = Page_PTE(int(mapping["pte"]))
            for space in spaces:
                space.uat.iomap_at(
                    space.context, address, target, PAGE_SIZE,
                    AttrIndex=int(native_pte.AttrIndex),
                    AP=int(native_pte.AP), AF=int(native_pte.AF),
                    nG=int(native_pte.nG), SH=int(native_pte.SH),
                    UXN=int(native_pte.UXN), PXN=int(native_pte.PXN),
                    OS=int(native_pte.OS),
                )
            remapped.append((address, target))

    backend.space.flush()
    backend.u.inst("dsb sy")
    for context in sorted({
            int(space.context) for space in spaces
    } | {2, 3}):
        backend.u.inst("tlbi aside1os, x0", context << 48)
    backend.u.inst("dsb sy")
    for address, target in remapped:
        translated = backend.space.uat.iotranslate(
            backend.space.context, address, PAGE_SIZE)
        if translated != [(target, PAGE_SIZE)]:
            raise RuntimeError(
                "partial output reback failed at %#x: %r" %
                (address, translated))
        if any(backend._read_dva(address, PAGE_SIZE)):
            raise RuntimeError(
                "partial output %#x was not zero after physical reback" %
                address)
    print(
        "G17P PARTIAL rebound %d output pages to native physical placement "
        "without captured content (reference context 3/root %d)" %
        (len(remapped), int(render_root["root_index"])),
        flush=True,
    )
    return tuple(remapped)


def remap_partial_graph_to_native_physical(backend, include_transport=False):
    """Reback fixed partial-resource pages with native physical PAs.

    As with the output discriminator, only placement and native PTE policy are
    imported.  The bytes written into every destination PA are read from the
    just-built source graph before any mapping is changed.  The cumulative
    transport variant adds channel-control and current-job pages.
    """
    snapshot = pathlib.Path(os.environ.get(
        "G17P_PARTIAL_NATIVE_PHYSICAL_REFERENCE",
        "/Users/user/asahi_re/artifacts/agx_g17p/"
        "native_partial_pre_kick_20260819_234640"))
    manifest = json.loads((snapshot / "manifest.json").read_text())
    selected = manifest["selected_root"]
    firmware_roots = [
        root for root in manifest["root_mappings"]
        if int(root["root_index"]) == int(selected["index"])
        and int(root["root_ctx_id"]) == int(selected["ctx_id"])
        and int(root["selector"]) == 1
    ]
    if len(firmware_roots) != 1:
        raise RuntimeError(
            "native physical reference has %d selected firmware roots" %
            len(firmware_roots))
    firmware_root = firmware_roots[0]
    mappings = {
        int(mapping["va"]): mapping
        for mapping in firmware_root["mappings"]
    }

    heap_ranges = []
    cursor = int(backend.u.heap.offset)
    for blocks, used in backend.u.heap.blocks:
        size = int(blocks) * int(backend.u.heap.block)
        if used:
            heap_ranges.append((cursor, cursor + size))
        cursor += size

    prepared = []
    pages = PARTIAL_GRAPH_PHYSICAL_PAGES
    if include_transport:
        pages += PARTIAL_TRANSPORT_PHYSICAL_PAGES
    for address in pages:
        mapping = mappings.get(address)
        if mapping is None or mapping.get("blob_index") is None:
            raise RuntimeError(
                "native physical reference has no graph page %#x" % address)
        target = int(mapping["pa"])
        for start, end in heap_ranges:
            if target < end and start < target + PAGE_SIZE:
                raise RuntimeError(
                    "native graph PA %#x overlaps live heap %#x-%#x" %
                    (target, start, end))
        prepared.append((address, target, bytes(
            backend._read_dva(address, PAGE_SIZE)),
            Page_PTE(int(mapping["pte"]))))

    root = getattr(backend, "firmware_high_root", None)
    if root is None:
        raise RuntimeError(
            "native graph physical placement requires an adopted upper root")
    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()
    for address, target, body, native_pte in prepared:
        backend.u.iface.writemem(target, body)
        backend.u.proxy.dc_civac(target, PAGE_SIZE)
        backend.space.uat.iomap_at_root(
            root, address, target, PAGE_SIZE,
            ctx=backend.space.context,
            AttrIndex=int(native_pte.AttrIndex),
            AP=int(native_pte.AP), AF=int(native_pte.AF),
            nG=int(native_pte.nG), SH=int(native_pte.SH),
            UXN=int(native_pte.UXN), PXN=int(native_pte.PXN),
            OS=int(native_pte.OS),
        )

    # The packed shared object names the primary-index page through both its
    # firmware-high address and this GPU-visible low alias.  Keep them backed
    # by the same native PA, just as they are in the capture.
    primary_target = prepared[0][1]
    render_roots = [
        candidate for candidate in manifest["root_mappings"]
        if int(candidate["root_ctx_id"]) == 3
        and int(candidate["selector"]) == 0
    ]
    if len(render_roots) != 1:
        raise RuntimeError(
            "native physical reference has %d context-3 render roots" %
            len(render_roots))
    low_alias = 0x1000190000
    low_mapping = next((
        mapping for mapping in render_roots[0]["mappings"]
        if int(mapping["va"]) == low_alias
    ), None)
    if low_mapping is None or int(low_mapping["pa"]) != primary_target:
        raise RuntimeError(
            "native primary-index alias does not share PA %#x" %
            primary_target)
    low_pte = Page_PTE(int(low_mapping["pte"]))
    spaces = [backend.space]
    if backend.space.mirror_space is not None:
        spaces.append(backend.space.mirror_space)
    for space in spaces:
        space.uat.iomap_at(
            space.context, low_alias, primary_target, PAGE_SIZE,
            AttrIndex=int(low_pte.AttrIndex), AP=int(low_pte.AP),
            AF=int(low_pte.AF), nG=int(low_pte.nG), SH=int(low_pte.SH),
            UXN=int(low_pte.UXN), PXN=int(low_pte.PXN),
            OS=int(low_pte.OS),
        )

    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()
    for space in spaces[1:]:
        space.uat.flush_dirty()
        space.uat.invalidate_cache()
    backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
    for address, target, body, _native_pte in prepared:
        translated = backend.space.uat.iotranslate_root(
            root, address, PAGE_SIZE)
        if translated != [(target, PAGE_SIZE)]:
            raise RuntimeError(
                "partial graph reback failed at %#x: %r" %
                (address, translated))
        if backend._read_dva(address, PAGE_SIZE) != body:
            raise RuntimeError(
                "partial graph source bytes changed at %#x" % address)
    for space in spaces:
        translated = space.uat.iotranslate(
            space.context, low_alias, PAGE_SIZE)
        if translated != [(primary_target, PAGE_SIZE)]:
            raise RuntimeError(
                "partial primary-index low alias reback failed: %r" %
                (translated,))
    print(
        "G17P PARTIAL rebound %d %s pages to native physical placement "
        "without captured content (firmware root %d)" % (
            len(prepared),
            "resource/transport" if include_transport else "resource-graph",
            int(firmware_root["root_index"])),
        flush=True,
    )
    return tuple((address, target) for address, target, _body, _pte in prepared)


def remap_partial_caller_to_native_physical(backend):
    """Reback source caller/compiler and live PB pages with native PAs."""
    snapshot = pathlib.Path(os.environ.get(
        "G17P_PARTIAL_NATIVE_PHYSICAL_REFERENCE",
        "/Users/user/asahi_re/artifacts/agx_g17p/"
        "native_partial_pre_kick_20260819_234640"))
    manifest = json.loads((snapshot / "manifest.json").read_text())
    render_roots = [
        root for root in manifest["root_mappings"]
        if int(root["root_ctx_id"]) == 3 and int(root["selector"]) == 0
    ]
    if len(render_roots) != 1:
        raise RuntimeError(
            "native physical reference has %d context-3 render roots" %
            len(render_roots))
    render_root = render_roots[0]
    mappings = {
        int(mapping["va"]): mapping
        for mapping in render_root["mappings"]
    }
    caller_pages = set(load_manifest_pages("entries"))
    caller_pages.update(load_deferred_pages())
    caller_pages.update((CONTEXT_BASE, ENCODER_DVA, VIEWPORT_DVA))
    pages = tuple(sorted(caller_pages)) + PARTIAL_PARAMETER_PHYSICAL_PAGES
    if len(set(pages)) != 60:
        raise RuntimeError(
            "partial caller/PB physical inventory has %d unique pages, "
            "expected 60" % len(set(pages)))

    heap_ranges = []
    cursor = int(backend.u.heap.offset)
    for blocks, used in backend.u.heap.blocks:
        size = int(blocks) * int(backend.u.heap.block)
        if used:
            heap_ranges.append((cursor, cursor + size))
        cursor += size
    prepared = []
    for address in pages:
        mapping = mappings.get(address)
        if mapping is None or mapping.get("blob_index") is None:
            raise RuntimeError(
                "native physical reference has no caller/PB page %#x" %
                address)
        target = int(mapping["pa"])
        for start, end in heap_ranges:
            if target < end and start < target + PAGE_SIZE:
                raise RuntimeError(
                    "native caller/PB PA %#x overlaps live heap %#x-%#x" %
                    (target, start, end))
        prepared.append((address, target, bytes(
            backend._read_dva(address, PAGE_SIZE)),
            Page_PTE(int(mapping["pte"]))))
    if len({target for _address, target, _body, _pte in prepared}) \
            != len(prepared):
        raise RuntimeError("native caller/PB pages unexpectedly alias")

    spaces = [backend.space]
    if backend.space.mirror_space is not None:
        spaces.append(backend.space.mirror_space)
    for address, target, body, native_pte in prepared:
        backend.u.iface.writemem(target, body)
        backend.u.proxy.dc_civac(target, PAGE_SIZE)
        for space in spaces:
            space.uat.iomap_at(
                space.context, address, target, PAGE_SIZE,
                AttrIndex=int(native_pte.AttrIndex),
                AP=int(native_pte.AP), AF=int(native_pte.AF),
                nG=int(native_pte.nG), SH=int(native_pte.SH),
                UXN=int(native_pte.UXN), PXN=int(native_pte.PXN),
                OS=int(native_pte.OS),
            )
    for space in spaces:
        space.uat.flush_dirty()
        space.uat.invalidate_cache()
    backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
    for address, target, body, _native_pte in prepared:
        translated = backend.space.uat.iotranslate(
            backend.space.context, address, PAGE_SIZE)
        if translated != [(target, PAGE_SIZE)]:
            raise RuntimeError(
                "partial caller/PB reback failed at %#x: %r" %
                (address, translated))
        if backend._read_dva(address, PAGE_SIZE) != body:
            raise RuntimeError(
                "partial caller/PB source bytes changed at %#x" % address)
    print(
        "G17P PARTIAL rebound %d caller/PB pages to native physical "
        "placement without captured content (reference context 3/root %d)" %
        (len(prepared), int(render_root["root_index"])),
        flush=True,
    )
    return tuple((address, target) for address, target, _body, _pte in prepared)


def remap_partial_execution_to_native_physical(backend):
    """Reback the remaining queue/descriptor execution closure natively."""
    snapshot = pathlib.Path(os.environ.get(
        "G17P_PARTIAL_NATIVE_PHYSICAL_REFERENCE",
        "/Users/user/asahi_re/artifacts/agx_g17p/"
        "native_partial_pre_kick_20260819_234640"))
    manifest = json.loads((snapshot / "manifest.json").read_text())
    selected = manifest["selected_root"]
    firmware_root = next((
        root for root in manifest["root_mappings"]
        if int(root["root_index"]) == int(selected["index"])
        and int(root["root_ctx_id"]) == int(selected["ctx_id"])
        and int(root["selector"]) == 1
    ), None)
    context0_root = next((
        root for root in manifest["root_mappings"]
        if int(root["root_ctx_id"]) == 0 and int(root["selector"]) == 0
    ), None)
    if firmware_root is None or context0_root is None:
        raise RuntimeError(
            "native reference lacks the firmware or context-0 root")
    firmware_mappings = {
        int(mapping["va"]): mapping
        for mapping in firmware_root["mappings"]
    }
    context0_mappings = {
        int(mapping["va"]): mapping
        for mapping in context0_root["mappings"]
    }
    context0_by_pa = {}
    for mapping in context0_root["mappings"]:
        context0_by_pa.setdefault(int(mapping["pa"]), []).append(mapping)

    heap_ranges = []
    cursor = int(backend.u.heap.offset)
    for blocks, used in backend.u.heap.blocks:
        size = int(blocks) * int(backend.u.heap.block)
        if used:
            heap_ranges.append((cursor, cursor + size))
        cursor += size
    high = []
    for address in PARTIAL_EXECUTION_PHYSICAL_PAGES:
        mapping = firmware_mappings.get(address)
        if mapping is None or mapping.get("blob_index") is None:
            raise RuntimeError(
                "native physical reference has no execution page %#x" %
                address)
        target = int(mapping["pa"])
        for start, end in heap_ranges:
            if target < end and start < target + PAGE_SIZE:
                raise RuntimeError(
                    "native execution PA %#x overlaps live heap %#x-%#x" %
                    (target, start, end))
        high.append((address, target, bytes(
            backend._read_dva(address, PAGE_SIZE)),
            Page_PTE(int(mapping["pte"]))))
    scheduler = []
    for address in PARTIAL_SCHEDULER_PHYSICAL_PAGES:
        mapping = context0_mappings.get(address)
        if mapping is None or mapping.get("blob_index") is None:
            raise RuntimeError(
                "native physical reference has no scheduler page %#x" %
                address)
        target = int(mapping["pa"])
        for start, end in heap_ranges:
            if target < end and start < target + PAGE_SIZE:
                raise RuntimeError(
                    "native scheduler PA %#x overlaps live heap %#x-%#x" %
                    (target, start, end))
        body = bytes(backend.space.uat.ioread(0, address, PAGE_SIZE))
        scheduler.append((address, target, body,
                          Page_PTE(int(mapping["pte"]))))

    root = getattr(backend, "firmware_high_root", None)
    if root is None:
        raise RuntimeError(
            "native execution physical placement requires an adopted root")
    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()
    aliases = []
    for address, target, body, native_pte in high:
        backend.u.iface.writemem(target, body)
        backend.u.proxy.dc_civac(target, PAGE_SIZE)
        backend.space.uat.iomap_at_root(
            root, address, target, PAGE_SIZE,
            ctx=backend.space.context,
            AttrIndex=int(native_pte.AttrIndex),
            AP=int(native_pte.AP), AF=int(native_pte.AF),
            nG=int(native_pte.nG), SH=int(native_pte.SH),
            UXN=int(native_pte.UXN), PXN=int(native_pte.PXN),
            OS=int(native_pte.OS),
        )
        for alias_mapping in context0_by_pa.get(target, ()):
            alias = int(alias_mapping["va"])
            alias_pte = Page_PTE(int(alias_mapping["pte"]))
            backend.space.uat.iomap_at(
                0, alias, target, PAGE_SIZE,
                AttrIndex=int(alias_pte.AttrIndex), AP=int(alias_pte.AP),
                AF=int(alias_pte.AF), nG=int(alias_pte.nG),
                SH=int(alias_pte.SH), UXN=int(alias_pte.UXN),
                PXN=int(alias_pte.PXN), OS=int(alias_pte.OS),
            )
            aliases.append((alias, target, body))
    for address, target, body, native_pte in scheduler:
        backend.u.iface.writemem(target, body)
        backend.u.proxy.dc_civac(target, PAGE_SIZE)
        backend.space.uat.iomap_at(
            0, address, target, PAGE_SIZE,
            AttrIndex=int(native_pte.AttrIndex), AP=int(native_pte.AP),
            AF=int(native_pte.AF), nG=int(native_pte.nG),
            SH=int(native_pte.SH), UXN=int(native_pte.UXN),
            PXN=int(native_pte.PXN), OS=int(native_pte.OS),
        )
    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()
    backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")

    for address, target, body, _native_pte in high:
        translated = backend.space.uat.iotranslate_root(
            root, address, PAGE_SIZE)
        if translated != [(target, PAGE_SIZE)]:
            raise RuntimeError(
                "partial execution reback failed at %#x: %r" %
                (address, translated))
        if backend._read_dva(address, PAGE_SIZE) != body:
            raise RuntimeError(
                "partial execution source bytes changed at %#x" % address)
    for address, target, body in aliases:
        translated = backend.space.uat.iotranslate(0, address, PAGE_SIZE)
        if translated != [(target, PAGE_SIZE)]:
            raise RuntimeError(
                "partial execution alias failed at %#x: %r" %
                (address, translated))
        if bytes(backend.space.uat.ioread(0, address, PAGE_SIZE)) != body:
            raise RuntimeError(
                "partial execution alias bytes differ at %#x" % address)
    for address, target, body, _native_pte in scheduler:
        translated = backend.space.uat.iotranslate(0, address, PAGE_SIZE)
        if translated != [(target, PAGE_SIZE)]:
            raise RuntimeError(
                "partial scheduler reback failed at %#x: %r" %
                (address, translated))
        if bytes(backend.space.uat.ioread(0, address, PAGE_SIZE)) != body:
            raise RuntimeError(
                "partial scheduler source bytes changed at %#x" % address)
    print(
        "G17P PARTIAL rebound %d execution pages plus %d context-0 aliases "
        "and %d scheduler pages to native physical placement without "
        "captured content" % (len(high), len(aliases), len(scheduler)),
        flush=True,
    )
    return {
        "high": tuple((address, target) for address, target, _body, _pte
                      in high),
        "aliases": tuple((address, target) for address, target, _body
                         in aliases),
        "scheduler": tuple((address, target) for address, target, _body, _pte
                           in scheduler),
    }


def capture_reference_firmware_pages(backend, reference, output):
    """Freeze the live source world at every firmware DVA in a native oracle."""
    reference = pathlib.Path(reference)
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=False)
    native = json.loads((reference / "manifest.json").read_text())
    selected = int(native["selected_root"]["index"])
    pages = sorted({
        int(mapping["va"])
        for root in native["root_mappings"]
        if int(root["root_index"]) == selected
        for mapping in root["mappings"]
        if mapping.get("blob_index") is not None
    })
    raw = bytearray()
    records = []
    errors = []
    for address in pages:
        try:
            body = bytes(backend._read_dva(address, PAGE_SIZE))
        except Exception as error:  # noqa: BLE001 - a missing page is evidence
            errors.append({"dva": address, "error": str(error)})
            continue
        records.append({
            "dva": address,
            "capture_offset": len(raw),
            "nonzero_bytes": sum(value != 0 for value in body),
            "sha256": hashlib.sha256(body).hexdigest(),
        })
        raw.extend(body)
    (output / "pages.bin").write_bytes(raw)
    manifest = {
        "format": "m1n1-t8140-g17p-live-source-firmware-pages-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "phase": "after-opening-before-partial-submit",
        "reference": str(reference),
        "page_size": PAGE_SIZE,
        "pages": records,
        "read_errors": errors,
        "binary": "pages.bin",
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(
        "G17P PARTIAL source firmware snapshot: %d/%d pages, %d errors -> %s"
        % (len(records), len(pages), len(errors), output),
        flush=True,
    )
    return output

# Exact final-26.6 forced-partial registration closure.  The class-1 and
# class-2 compact objects share pages with earlier record pools; class 3 is the
# control header adjacent to the partial graph's Pool B.  Only the compact body
# and first state word are host-owned here.
PARTIAL_CLASS1_SUPPORT = 0xFFFFFC20C0828000
PARTIAL_CLASS1_STATE = 0xFFFFFC2001600000
PARTIAL_CLASS2_SUPPORT = 0xFFFFFC20C0870000
PARTIAL_CLASS2_STATE = 0xFFFFFC2001638000
PARTIAL_CLASS3_SUPPORT = 0xFFFFFC20C08D0000
PARTIAL_CLASS3_STATE = 0xFFFFFC2001688000
SOURCE_GATE_CLASS1_SUPPORT = 0xFFFFFC20C0878000
SOURCE_GATE_CLASS1_STATE = 0xFFFFFC2001648000
SOURCE_GATE_CLASS3_SUPPORT = 0xFFFFFC20C0850000
SOURCE_GATE_CLASS3_STATE = 0xFFFFFC2001650000

# Diagnostic captured/source substitution only.  This is record zero from the
# synchronized native device-control event immediately before class 2.  The
# source-built opening leaves five qwords different while the fresh record one
# named by TA_2/3D_2 is already byte-exact.  ``all``, ``head``, and ``tail``
# modes let one positive result be bisected without another code change; this
# captured body must not become the eventual constructed path.
NATIVE_PRECLASS2_CHANNEL0 = bytes.fromhex(
    "000004000f01c8000000c05d0000c400"
    "00000300000000000000000000000000"
    "00000000000002f57b00003ab7020000"
    "00000000000000000000000000000000"
)


def substitute_native_preclass2_channel0(backend):
    mode = os.environ.get("G17P_PARTIAL_NATIVE_PRECLASS2_CHANNEL0")
    if not mode:
        return None
    if mode == "1":
        mode = "all"
    ranges = {
        "all": (0, len(NATIVE_PRECLASS2_CHANNEL0)),
        "head": (0, len(NATIVE_PRECLASS2_CHANNEL0) // 2),
        "tail": (len(NATIVE_PRECLASS2_CHANNEL0) // 2,
                 len(NATIVE_PRECLASS2_CHANNEL0)),
    }
    if mode not in ranges:
        raise ValueError(
            "G17P_PARTIAL_NATIVE_PRECLASS2_CHANNEL0 must be all, head, or tail")
    start, end = ranges[mode]
    address = backend.CHANNEL_CONTROL_BASE + start
    body = NATIVE_PRECLASS2_CHANNEL0[start:end]
    before = backend._read_dva(address, len(body))
    backend._write_dva(address, body)
    backend._clean_dva_range(address, len(body))
    backend.u.inst("dsb sy")
    if backend._read_dva(address, len(body)) != body:
        raise RuntimeError("native pre-class2 channel-control substitution failed")
    changed = sum(left != right for left, right in zip(before, body))
    print(
        "G17P PARTIAL substituted native channel-control record-zero %s "
        "range (%d differing bytes)" % (mode, changed),
        flush=True,
    )
    return mode


def exact_encoder():
    return g17p_encoder.build_encoder(g17p_encoder.G17PEncoderParameters(
        context_base=CONTEXT_BASE,
        binds=[
            g17p_encoder.G17PBindPair(CONTEXT_BASE + offset, control)
            for offset, control in (
                (0x40, 0x700),
                (0x58000, 0x500),
                (0x5801C, 0x700),
                (0x58030, 0x500),
                (0x5804C, 0xA00),
                (0x68900, 0x300),
                (0x58060, 0x200),
                (0x5806C, 0x200),
            )
        ],
        draw_state=DRAW_STATE_DVA,
        vertex_count=VERTEX_COUNT,
        instance_count=1,
        opcode=g17p_encoder.DRAW_OPCODE_DIRECT,
        primitive=g17p_encoder.PRIMITIVE_TRIANGLE,
        header_flags=0x4000002E,
        header_mode=0x01000040,
        header_state=0x7600,
        header_class=0x2424,
        header_control=0x500,
        tail_count=1,
        tail_flags=0xC0000000,
    ))


def load_manifest_pages(section, payload=PAYLOAD):
    manifest = json.loads(payload.read_text())
    pages = {}
    for entry in manifest.get(section, ()):
        path = payload.parent / entry["path"]
        body = path.read_bytes()
        if len(body) != int(entry["size"]):
            raise RuntimeError(
                "%s page %#x has the wrong size" % (section, entry["va"]))
        if hashlib.sha256(body).hexdigest() != entry["sha256"]:
            raise RuntimeError(
                "%s page %#x failed its checksum" % (section, entry["va"]))
        pages[int(entry["va"])] = body
    return pages


def load_deferred_pages(payload=PAYLOAD):
    pages = load_manifest_pages("deferred_entries", payload)
    required = {DRAW_STATE_DVA, BIND_GROUP_DVA}
    if set(pages) != required:
        raise RuntimeError(
            "partial workload deferred pages are %r, expected %r" %
            (sorted(pages), sorted(required)))
    return pages


def install_caller_graph(backend, negative, fresh_pages=False):
    payload_pages = load_manifest_pages("entries")
    if not payload_pages or RESOURCE_DVA not in payload_pages:
        raise RuntimeError("partial workload manifest has no resource graph")
    pages = dict(payload_pages)
    bind0 = bytearray(g17p_render.build_direct_bind0())
    # The concentrated eight-R32F pass is the only captured direct workload
    # whose first bind-0 record carries this 0x20 low-field value.  Every other
    # caller page, including the complete encoder, compares byte-for-byte with
    # the coherent pre-kick capture.  Keep the discriminator local until its
    # semantic effect is proven on hardware, then promote it into the UAPI
    # model with a named field.
    struct.pack_into("<I", bind0, 0x40, 0x10040020)
    pages.update({
        CONTEXT_BASE: bytes(bind0),
        ENCODER_DVA: exact_encoder(),
        VIEWPORT_DVA: g17p_render.build_viewport(WIDTH, HEIGHT),
    })
    pages.update(load_deferred_pages())
    for address in pages:
        if fresh_pages:
            # A cloned VM initially names the opening render's physical pages.
            # Replace those aliases with new backing so reusing the same caller
            # DVAs cannot hit shader/resource cache state from the opening job.
            backend.space.alloc_at(
                address, PAGE_SIZE, "partial_caller_%x" % address,
                AttrIndex=MemoryAttr.Shared, AP=2, AF=1, nG=1, SH=0,
                UXN=0, OS=1,
            )
        else:
            map_client(
                backend, address, PAGE_SIZE,
                "partial_caller_%x" % address,
                read_only=True, reuse=True,
            )

    # The ordinary opening render maps the reference capture's complete dense
    # 56.5-MiB arena before this bundle is installed.  A caller page that lands
    # in that arena is therefore already translated, and map_client(reuse=True)
    # deliberately preserves its old leaf.  Replacing the bytes is insufficient:
    # the partial bundle's opaque program pages require the same executable
    # render-leaf policy they receive when the bundle is present at cold boot.
    # Keep each page's current physical identity, but make the permissions exact.
    old_uxn = {0: 0, 1: 0}
    spaces = [backend.space]
    if backend.space.mirror_space is not None:
        spaces.append(backend.space.mirror_space)
    for address in pages:
        pte = backend.space.uat.ioperm(backend.space.context, address)
        old_uxn[int(pte.UXN)] += 1
        translated = backend.space.uat.iotranslate(
            backend.space.context, address, PAGE_SIZE)
        if len(translated) != 1 or translated[0][0] is None:
            raise RuntimeError(
                "caller graph page %#x does not have one physical page" %
                address)
        pa = translated[0][0]
        for space in spaces:
            space.uat.iomap_at(
                space.context, address, pa, PAGE_SIZE,
                AttrIndex=MemoryAttr.Shared, AP=2, AF=1, nG=1, SH=0,
                UXN=0, OS=1,
            )
    backend.space.flush()
    backend.u.inst("dsb sy")
    for space in spaces:
        backend.u.inst("tlbi aside1os, x0", space.context << 48)
    backend.u.inst("dsb sy")
    print(
        "G17P PARTIAL rebound caller leaves: old UXN=0:%d UXN=1:%d; "
        "new UXN=0:%d" % (old_uxn[0], old_uxn[1], len(pages)),
        flush=True,
    )
    for address, body in pages.items():
        page = (bytes(body) + bytes(PAGE_SIZE))[:PAGE_SIZE]
        backend._write_dva(address, page)
        if backend._read_dva(address, PAGE_SIZE) != page:
            raise RuntimeError("caller graph page %#x did not read back" % address)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "G17P PARTIAL installed %d verified caller pages after opening" %
        len(pages),
        flush=True,
    )

    resource = bytearray(backend._read_dva(RESOURCE_DVA, PAGE_SIZE))
    original = bytes(resource)
    if negative:
        resource[0x000:0x300] = resource[0x300:0x600]
        changed = sum(a != b for a, b in zip(original, resource))
        if changed != 5:
            raise RuntimeError(
                "clear-over-reload mutation changed %d bytes, expected 5" %
                changed)
        backend._write_dva(RESOURCE_DVA, resource)
        if backend._read_dva(RESOURCE_DVA, PAGE_SIZE) != bytes(resource):
            raise RuntimeError("partial resource negative did not read back")
        print(
            "G17P PARTIAL RESOURCE NEGATIVE reload+0x0 <- clear+0x300 "
            "bytes=0x300 changed=5",
            flush=True,
        )
    return original


def render_commands():
    attachment_body = b"".join(
        drm_asahi_attachment(address, OUTPUT_SIZE, 0, 0).to_bytes()
        for address in OUTPUT_DVAS
    )
    payload = drm_asahi_cmd_render()
    payload.flags = DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
    payload.vdm_ctrl_stream_base = ENCODER_DVA
    payload.isp_scissor_base = SCISSOR_DVA
    payload.isp_dbias_base = DBIAS_DVA
    payload.ppp_multisamplectl = 0x88
    payload.ppp_ctrl = 0x202
    payload.width_px = WIDTH
    payload.height_px = HEIGHT
    payload.layers = 1
    payload.utile_width_px = 32
    payload.utile_height_px = 32
    payload.samples = 1
    payload.sample_size_B = 32
    payload.isp_bgobjdepth = 0x3F800000
    payload.isp_merge_upper_x = 0x3C5DB3D9
    payload.isp_merge_upper_y = 0x3C5DB3D9
    payload.bg.usc = 0x1E8240
    payload.bg.rsrc_spec = 0x40
    payload.eot.usc = 0x1E8480
    payload.eot.rsrc_spec = 0
    payload.partial_bg.usc = 0x1E8000
    payload.partial_bg.rsrc_spec = 0x40
    payload.partial_eot.usc = 0x1E8480
    payload.partial_eot.rsrc_spec = 0
    return (
        command(DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS, attachment_body)
        + command(DRM_ASAHI_CMD_RENDER, payload.to_bytes())
    )


def output_maximum(body):
    values = struct.unpack("<%df" % (len(body) // 4), body)
    finite = [value for value in values if math.isfinite(value)]
    if len(finite) != len(values):
        raise RuntimeError("partial output contains a non-finite float")
    return max(finite)


def validate_outputs(outputs, negative):
    maxima = tuple(output_maximum(body) for body in outputs)
    if negative:
        if not 0 < maxima[0] < 0.01:
            raise RuntimeError(
                "negative attachment zero did not retain only the final "
                "segment: %r" % (maxima,))
        if any(abs(value - maxima[0] * (index + 1)) > 0.002
               for index, value in enumerate(maxima)):
            raise RuntimeError(
                "negative outputs do not share final-segment scale: %r" %
                (maxima,))
    else:
        if any(abs(value - (index + 1)) > 0.02
               for index, value in enumerate(maxima)):
            raise RuntimeError(
                "partial reload lost accumulated segments: %r" % (maxima,))
    return maxima


def submission_count():
    raw = os.environ.get("G17P_PARTIAL_SUBMISSIONS", "1")
    try:
        value = int(raw, 0)
    except ValueError:
        raise SystemExit(
            "G17P_PARTIAL_SUBMISSIONS must be an integer") from None
    if value < 1:
        raise SystemExit("G17P_PARTIAL_SUBMISSIONS must be positive")
    return value


def run_source_render_bootstrap(front, backend):
    """Execute and witness one ordinary render before the partial graph.

    Direct-compute cold boot deliberately removes its staged opening TA/3D
    pair.  The executing partial replay instead inherits firmware state from a
    completed render.  Use a memfd page beyond all eight partial attachments
    so this discriminator establishes only that missing device lifetime; its
    witness remains mapped and cannot alias the focused outputs.
    """
    offset = ATTACHMENT_COUNT * OUTPUT_SIZE
    os.ftruncate(front.memfd, offset + PAGE_SIZE)
    address = front.create_bo_from_memfd(front.memfd, offset, PAGE_SIZE, 0)
    target = front.bos[offset]
    target._no_push = True
    workload = {
        "targets": [{"address": address, "target": target}],
        "next_target": 0,
    }
    submission = run_render_cadence_submission(
        front, backend, workload, "source-render bootstrap")
    if not submission.get("output_changed"):
        raise RuntimeError("source-render bootstrap produced no output")
    print(
        "G17P PARTIAL retained one output-positive source-built render "
        "before caller installation (pair=%d descriptor=%r)" % (
            submission["queue_pair"],
            dict(backend.descriptor_pair_submissions),
        ),
        flush=True,
    )
    return submission


def finish_partial_registration_cadence(front, backend, cadence):
    """Extend the common 32-render prefix to partial's 36-render boundary.

    The synchronized native control/work trace reaches sequence ``0x21`` after
    publishing 36 TA/3D pairs.  The common compute helper reaches render 32 at
    sequence ``0x1e``.  Renders 33 and 34 carry sequences ``0x1f`` and
    ``0x20``; renders 35 and 36 precede the final sequence ``0x21``.  Native
    stages render 36's outer records and class 2 before the work doorbell, so
    the final pre-notify hook reproduces that ordering while the other 35
    renders remain physically witnessed.  Marking the last two group ordinals
    as already announced suppresses the generic one-tick-per-submission policy.
    """
    workload = cadence["workload"]
    if workload["next_target"] != 31 or backend.group_number != 32:
        raise RuntimeError("partial cadence extension needs the 32-render prefix")

    first_address = workload["targets"][0]["address"]
    target_stride = 0x100000000
    final_target_count = 35
    os.ftruncate(front.memfd, final_target_count * PAGE_SIZE)
    for index in range(len(workload["targets"]), final_target_count):
        offset = index * PAGE_SIZE
        front.ctx.gobj.next_va = first_address + index * target_stride
        address = front.create_bo_from_memfd(
            front.memfd, offset, PAGE_SIZE, 0)
        target = front.bos[offset]
        target._no_push = True
        workload["targets"].append({"address": address, "target": target})

    activation_holder = {}
    for ordinal in range(33, 37):
        if ordinal >= 35:
            backend.runtime_submission_announced.add(backend.group_number)
        saved_descriptor_pair = backend.forced_descriptor_pair
        saved_pre_notify_hook = backend.pre_notify_hook
        if (ordinal == 36 and os.environ.get(
                "G17P_PARTIAL_CLASS2_BEFORE_FINAL_KICK") == "1"):
            def admit_before_final_kick(active_backend, pair_index):
                # submit_register_pair has already published both outer
                # producers at this point, but it has not sent the work
                # doorbell or advanced the host-side submission ordinal.
                active_backend.pre_notify_hook = saved_pre_notify_hook
                if saved_pre_notify_hook is not None:
                    saved_pre_notify_hook(active_backend, pair_index)
                activation_holder["value"] = activate_partial_render_graph(
                    front, active_backend, cadence,
                    final_render_staged=True,
                )

            backend.pre_notify_hook = admit_before_final_kick
        # Native's complete opening stays in descriptor namespace zero.  In
        # particular, descriptor pair one would use c1638000 as a render-status
        # page before class 2 reuses that address as its fresh state object.
        backend.forced_descriptor_pair = 0
        try:
            result = run_render_cadence_submission(
                front, backend, workload,
                "partial registration render %d" % ordinal,
            )
        finally:
            backend.forced_descriptor_pair = saved_descriptor_pair
            backend.pre_notify_hook = saved_pre_notify_hook
        expected_pair = 0
        if result["queue_pair"] != expected_pair:
            raise RuntimeError(
                "partial render %d selected pair %d, expected pair %d" %
                (ordinal, result["queue_pair"], expected_pair))

    if (workload["next_target"] != final_target_count
            or backend.group_number != 36
            or backend.queue_pair_submissions.get(0) != 36
            or backend.queue_pair_submissions.get(1, 0) != 0):
        raise RuntimeError("partial cadence did not reach 36 physical renders")
    print(
        "G17P PARTIAL reached 36 output-positive grid-0/1 renders before "
        "class 2; sequences 0x1f/0x20 were work-backed and 0x21 remains "
        "pending",
        flush=True,
    )
    if activation_holder:
        cadence["partial_activation"] = activation_holder["value"]


def install_partial_control_objects(backend):
    """Construct the three compact objects in the native partial closure."""
    objects = {
        "class1": g17p_compute.build_compute_compact_control_support(
            1, PRIMARY_CONTROL_OPERAND, 0, PARTIAL_CLASS1_STATE,
            active=0, resource_class=0x11, cursor=0x88, final_kind=2,
        ),
        "class2": g17p_compute.build_compute_compact_control_support(
            2, PRIMARY_CONTROL_OPERAND, 0, PARTIAL_CLASS2_STATE,
            active=0, resource_class=0x17, cursor=0xB8, final_kind=3,
        ),
        "class3": g17p_compute.build_compute_compact_control_support(
            3, PRIMARY_CONTROL_OPERAND, 0, PARTIAL_CLASS3_STATE,
            active=1, resource_class=0x19, cursor=0xE0, final_kind=3,
        ),
    }
    state = struct.pack("<I", 1)
    for address in (
            PARTIAL_CLASS1_SUPPORT, PARTIAL_CLASS1_STATE,
            PARTIAL_CLASS2_SUPPORT, PARTIAL_CLASS2_STATE,
            PARTIAL_CLASS3_SUPPORT, PARTIAL_CLASS3_STATE):
        map_firmware(backend, address, PAGE_SIZE)
    for name, support, state_address in (
            ("class1", PARTIAL_CLASS1_SUPPORT, PARTIAL_CLASS1_STATE),
            ("class2", PARTIAL_CLASS2_SUPPORT, PARTIAL_CLASS2_STATE),
            ("class3", PARTIAL_CLASS3_SUPPORT, PARTIAL_CLASS3_STATE)):
        body = objects[name]
        backend._write_dva(support, body)
        backend._write_dva(state_address, state)
        backend._clean_dva_range(support, len(body))
        backend._clean_dva_range(state_address, len(state))
    backend.u.inst("dsb sy")
    for name, support, state_address in (
            ("class1", PARTIAL_CLASS1_SUPPORT, PARTIAL_CLASS1_STATE),
            ("class2", PARTIAL_CLASS2_SUPPORT, PARTIAL_CLASS2_STATE),
            ("class3", PARTIAL_CLASS3_SUPPORT, PARTIAL_CLASS3_STATE)):
        if backend._read_dva(support, len(objects[name])) != objects[name]:
            raise RuntimeError(
                "partial %s compact control did not read back" % name)
        if backend._read_dva(state_address, len(state)) != state:
            raise RuntimeError(
                "partial %s state did not read back" % name)
    print(
        "G17P PARTIAL constructed exact class1/class2/class3 controls",
        flush=True,
    )
    return objects


def admit_source_compute_partial_class3(front, backend):
    """Splice the captured partial graphics gate onto the compute checkpoint.

    The source-compute checkpoint contains 67 completed records and ends at
    sequence 62.  Translate the known-positive compute class-3 transition onto
    that boundary: class 1/tick 63, tick 64, then class 3 at sequence 65.  Stop
    the direct bootstrap before its artificial tick-only suffix so these
    records form the next lifecycle rather than an invalid append after 0xa6.
    """
    runtime = front.g17p_runtime
    if runtime is None:
        raise RuntimeError("source compute exposes no runtime control plane")
    before = runtime["read_control_counters"]()
    if before.get("primary") != [67, 67, 67]:
        raise RuntimeError(
            "source-compute graphics gate needs the 67-record checkpoint: %r" %
            before)

    install_partial_control_objects(backend)
    # Class 3 validates its predecessor lineage.  The older c08c/c1678 class 1
    # retires in isolation but does not admit the c085/c165 class 3; use that
    # class-3 identity's known c0878/c1648 predecessor pair.
    class1_body = g17p_compute.build_compute_compact_control_support(
        1, PRIMARY_CONTROL_OPERAND, 0, SOURCE_GATE_CLASS1_STATE,
        active=1, resource_class=0x11, cursor=0x88, final_kind=2,
    )
    map_firmware(backend, SOURCE_GATE_CLASS1_SUPPORT, PAGE_SIZE)
    map_firmware(backend, SOURCE_GATE_CLASS1_STATE, PAGE_SIZE)
    backend._write_dva(SOURCE_GATE_CLASS1_SUPPORT, class1_body)
    backend._write_dva(SOURCE_GATE_CLASS1_STATE, struct.pack("<I", 1))
    backend._clean_dva_range(SOURCE_GATE_CLASS1_SUPPORT, len(class1_body))
    backend._clean_dva_range(SOURCE_GATE_CLASS1_STATE, 4)
    backend.space.flush()
    backend.u.inst("dsb sy")
    if (backend._read_dva(
            SOURCE_GATE_CLASS1_SUPPORT, len(class1_body)) != class1_body):
        raise RuntimeError("source-compute gate class-1 did not read back")
    class3_body = g17p_compute.build_compute_compact_control_support(
        3, PRIMARY_CONTROL_OPERAND, 0, SOURCE_GATE_CLASS3_STATE,
        active=2, resource_class=0x17, cursor=0xB8, final_kind=3,
    )
    map_firmware(backend, SOURCE_GATE_CLASS3_SUPPORT, PAGE_SIZE)
    map_firmware(backend, SOURCE_GATE_CLASS3_STATE, PAGE_SIZE)
    backend._write_dva(SOURCE_GATE_CLASS3_SUPPORT, class3_body)
    backend._write_dva(SOURCE_GATE_CLASS3_STATE, struct.pack("<I", 1))
    backend._clean_dva_range(SOURCE_GATE_CLASS3_SUPPORT, len(class3_body))
    backend._clean_dva_range(SOURCE_GATE_CLASS3_STATE, 4)
    backend.space.flush()
    backend.u.inst("dsb sy")
    if (backend._read_dva(
            SOURCE_GATE_CLASS3_SUPPORT, len(class3_body)) != class3_body):
        raise RuntimeError("source-compute gate class-3 did not read back")
    print(
        "G17P PARTIAL installed checkpoint-owned class 1 for the "
        "compute-to-graphics gate",
        flush=True,
    )

    uat = backend.space.uat
    for context in (2, 3):
        uat.set_l0(context, 0, uat.ttbr0_base, context)
        uat.set_l0(context, 1, uat.ttbr1_base, context)
    uat.flush_dirty()
    uat.invalidate_cache()
    backend.space.flush()
    backend.u.inst("dsb sy")
    for context in (2, 3):
        backend.u.inst("tlbi aside1os, x0", context << 48)
    backend.u.inst("dsb sy")

    def registration(control_class, sequence, first_object, slot_offset,
                     count, context_word):
        body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
        struct.pack_into(
            "<IIII", body, 0,
            0x20, int(control_class), 0x3F, int(sequence),
        )
        struct.pack_into("<Q", body, 0x14, int(first_object))
        struct.pack_into("<Q", body, 0x1C, PRIMARY_CONTROL_OPERAND)
        struct.pack_into(
            "<Q", body, 0x24,
            PRIMARY_CONTROL_OPERAND + int(slot_offset),
        )
        struct.pack_into("<I", body, 0x2C, int(count))
        struct.pack_into("<I", body, 0x30, int(context_word))
        struct.pack_into("<I", body, 0x34, 1)
        return bytes(body)

    def tick(sequence, context_word):
        body = bytearray(g17p.CONTROL_MESSAGE_SIZE)
        struct.pack_into("<II", body, 0, 0x2E, int(sequence))
        struct.pack_into("<I", body, 0x0C, int(context_word))
        return bytes(body)

    prefix_bodies = (
        registration(
            1, 63, SOURCE_GATE_CLASS1_SUPPORT, 0x440, 0x20, 1),
        tick(63, 1),
        tick(64, 1),
    )
    prefix = runtime["announce_control_bodies"](
        prefix_bodies, "source-compute pre-class3 prefix")
    if prefix["crashed"] is not None or not prefix["consumed"]:
        raise RuntimeError(
            "source-compute pre-class3 prefix did not retire: %r" % prefix)
    prefix_after = runtime["read_control_counters"]()
    if prefix_after.get("primary") != [70, 70, 70]:
        raise RuntimeError(
            "source-compute pre-class3 prefix ended incorrectly: %r" %
            prefix_after)

    install_channel_control_record(
        backend, 2, "source-compute partial pre-class3")
    runtime["set_runtime_control_sequence"](64)
    class3 = runtime["register_compute_control"](
        3, SOURCE_GATE_CLASS3_SUPPORT, PRIMARY_CONTROL_OPERAND,
        slot_offset=0x5C0, context_word=2, count=0x28,
    )
    trailing = runtime["announce_runtime_tick"](
        66, "source-compute class-3 trailing sequence 66",
        context_word=2, require_consumed=True, update_sequence=True,
    )
    after = runtime["read_control_counters"]()
    if after.get("primary") != [73, 73, 73]:
        raise RuntimeError(
            "source-compute partial graphics gate ended at wrong boundary: %r" %
            after)
    print(
        "G17P PARTIAL source-compute graphics gate PASS "
        "primary=%r sequence=%#x" %
        (after["primary"], class3["sequence"]),
        flush=True,
    )
    return {
        "before": before,
        "prefix": prefix,
        "class3": class3,
        "trailing": trailing,
        "after": after,
    }


def admit_render_cadence_compute_class3(front, backend):
    """Run the proven final-26.6 compute gate after real source renders.

    Unlike the direct-compute checkpoint experiment, the 32-render cadence
    gives firmware the same render-produced private state as the independently
    proven compute path.  Keep the known-positive class-1/class-3 identities,
    sequencing, and context-2 publication unchanged so this isolates whether
    an admitted class-3 lifecycle is the missing prerequisite for the partial
    graphics graph.
    """
    runtime = front.g17p_runtime
    if runtime is None:
        raise RuntimeError("render cadence exposes no runtime control plane")
    if (not backend.runtime_pair_registered
            or backend.group_number != FINAL_26_6_RENDER_PREFIX_COUNT
            or backend.queue_pair_submissions.get(0) !=
            FINAL_26_6_RENDER_PREFIX_COUNT // 2
            or backend.queue_pair_submissions.get(1) !=
            FINAL_26_6_RENDER_PREFIX_COUNT // 2):
        raise RuntimeError(
            "render-backed compute gate needs 32 alternating renders: "
            "groups=%d queues=%r" % (
                backend.group_number, backend.queue_pair_submissions))

    control_objects = install_final_26_6_control_objects(backend)
    runtime["advance_runtime_ticks"](33)
    runtime["announce_runtime_1b_grid"](
        "render-backed compute prefix 0x1b")
    runtime["announce_runtime_tick"](
        34, "render-backed compute prefix sequence 34",
        require_consumed=True, update_sequence=True)

    class1 = runtime["register_compute_control"](
        1, FINAL_26_6_CLASS1_SUPPORT, PRIMARY_CONTROL_OPERAND,
        slot_offset=0x440, context_word=1, count=0x20,
    )
    runtime["announce_runtime_tick"](
        36, "render-backed class-1 trailing sequence 36",
        context_word=1, require_consumed=True, update_sequence=True)

    install_channel_control_record(backend, 2, "context-2 activation")
    class3 = runtime["register_compute_control"](
        3, FINAL_26_6_CLASS3_SUPPORT, PRIMARY_CONTROL_OPERAND,
        slot_offset=0x5C0, context_word=2, count=0x28,
    )
    class3_tick = runtime["announce_runtime_tick"](
        38, "render-backed class-3 trailing sequence 38",
        context_word=2, require_consumed=True, update_sequence=True)
    class3["trailing_0x2e"] = class3_tick
    after = runtime["read_control_counters"]()
    print(
        "G17P PARTIAL render-backed compute class-3 PASS "
        "primary=%r class1=%r class3=%r objects=%s" % (
            after.get("primary"), class1, class3,
            ",".join(sorted(control_objects))),
        flush=True,
    )
    return {
        "class1": class1,
        "class3": class3,
        "after": after,
    }


def admit_captured_partial_control(front, backend):
    """Reproduce the exact control boundary of the positive partial capture.

    ``native_partial_pre_kick_20260819_234640`` has primary counters
    ``[42, 42, 42]``.  Its slots after the two-entry cold-boot opening are:
    ticks 0..33, class 2/tick 34, class 1/tick 35, tick 36, and the class-3
    registration at sequence 37.  The class-3 tick is deliberately absent:
    the snapshot was taken before the partial work kick at precisely that
    boundary.
    """
    runtime = front.g17p_runtime
    if runtime is None:
        raise RuntimeError("cold boot exposes no runtime control plane")
    before = runtime["read_control_counters"]()
    if before.get("primary") != [2, 2, 2]:
        raise RuntimeError(
            "captured partial admission needs the two-entry opening: %r" %
            before)

    install_partial_control_objects(backend)

    # Native has user roots 2 and 3 installed by this lifecycle.  The compact
    # controls themselves use the firmware root, but their generated support
    # records can name the low operand namespace through these contexts.
    uat = backend.space.uat
    for context in (2, 3):
        uat.set_l0(context, 0, uat.ttbr0_base, context)
        uat.set_l0(context, 1, uat.ttbr1_base, context)
    uat.flush_dirty()
    uat.invalidate_cache()
    backend.space.flush()
    backend.u.inst("dsb sy")
    for context in (2, 3):
        backend.u.inst("tlbi aside1os, x0", context << 48)
    backend.u.inst("dsb sy")

    tick0 = runtime["announce_runtime_tick"](
        0, "captured partial sequence 0",
        require_consumed=True, update_sequence=True)
    prefix = runtime["advance_runtime_ticks"](33)
    class2 = runtime["register_compute_control"](
        2, PARTIAL_CLASS2_SUPPORT, PRIMARY_CONTROL_OPERAND,
        slot_offset=0x5C0, context_word=0, count=0x28)
    class1 = runtime["register_compute_control"](
        1, PARTIAL_CLASS1_SUPPORT, PRIMARY_CONTROL_OPERAND,
        slot_offset=0x440, context_word=1, count=0x20)
    tick36 = runtime["announce_runtime_tick"](
        36, "captured partial sequence 36",
        context_word=1, require_consumed=True, update_sequence=True)

    # The captured class-3 handler targets the second 0x40-byte destination
    # record.  Initialize that host-owned record at the same boundary.
    install_channel_control_record(
        backend, 1, "captured partial pre-class3")
    class3 = runtime["register_compute_control"](
        3, PARTIAL_CLASS3_SUPPORT, PRIMARY_CONTROL_OPERAND,
        slot_offset=0x640, context_word=1, count=0x18,
        defer_tick=True)

    after = runtime["read_control_counters"]()
    if after.get("primary") != [42, 42, 42]:
        raise RuntimeError(
            "captured partial admission ended at the wrong boundary: %r" %
            after)
    print(
        "G17P PARTIAL exact captured control admission PASS "
        "primary=%r sequence=%#x" %
        (after["primary"], class3["sequence"]),
        flush=True,
    )
    return {
        "before": before,
        "tick0": tick0,
        "prefix": prefix,
        "class2": class2,
        "class1": class1,
        "tick36": tick36,
        "class3": class3,
        "after": after,
    }


def activate_partial_render_graph(
        front, backend, cadence, final_render_staged=False):
    """Enter the native forced-partial queue lifecycle at class 2.

    The graph visible at sequence 0x22 is *not* the final partial pair.  Native
    creates a fresh grid-2/3 incarnation on TA_2/3D_2, sharing the c087 page
    between its Pool B and the compact class-2 header.  The final grid-4/5
    partial graph is only created near class 3 sequence 0x49.
    """
    runtime = front.g17p_runtime
    if runtime is None:
        raise RuntimeError("cold boot exposes no runtime control plane")
    expected_prefix = 35 if final_render_staged else 36
    if (backend.group_number != expected_prefix
            or backend.queue_pair_submissions.get(0) != expected_prefix
            or backend.queue_pair_submissions.get(1, 0) != 0):
        raise RuntimeError(
            "partial activation requires %d retired renders%s" % (
                expected_prefix,
                " plus the staged final grid-0/1 group"
                if final_render_staged else "",
            ))

    if 1 in backend.muxed_queue_pairs:
        raise RuntimeError("partial pair one was created before native class 2")
    state = getattr(front, "g17p_submission_state", None) or {}
    optional = {
        kind: dict(state.get("%s_optional" % kind) or {})
        for kind in ("tiling", "fragment")
    }
    if any("shared_control" not in values
           for values in optional.values()):
        raise RuntimeError("partial activation lacks opening optional pointers")
    backend.partial_pre_class2_pair1_profile = True
    queues = backend.create_muxed_queue_pair(
        1, optional, channel_pair=2)
    builder = backend.paired_builder_for(1, 1)
    if builder.leaf_pages is None:
        builder.build_submission_graph()
    backend._map_pair_status_aliases(1)
    install_channel_control_record(backend, 1, "partial pre-class2 pair-1")
    substitute_native_preclass2_channel0(backend)

    class2_body = g17p_compute.build_compute_compact_control_support(
        2, PRIMARY_CONTROL_OPERAND, 0, PARTIAL_CLASS2_STATE,
        active=0, resource_class=0x17, cursor=0xB8, final_kind=3,
    )
    map_firmware(backend, PARTIAL_CLASS2_SUPPORT, PAGE_SIZE)
    map_firmware(backend, PARTIAL_CLASS2_STATE, PAGE_SIZE)
    backend._write_dva(PARTIAL_CLASS2_SUPPORT, class2_body)
    backend._write_dva(PARTIAL_CLASS2_STATE, struct.pack("<I", 1))
    for _name, address, size in backend.MUX_PAIR1_GRAPH:
        backend._clean_dva_range(address, size)
    for details in queues.values():
        backend._clean_dva_range(
            details["queue"], g17p.QUEUE_RECORD_STRIDE)
        backend._clean_dva_range(
            details["pointers"], max(g17p.QUEUE_PTR_BLOCK_SIZE, 0x80))
        backend._clean_dva_range(details["item_ring"], 0x4000)
    backend._clean_dva_range(
        backend.PARTIAL_PRE_CLASS2_PAIR1_JOB_LIST, g17p.JOB_LIST_SIZE)
    backend._clean_dva_range(PARTIAL_CLASS2_SUPPORT, len(class2_body))
    backend._clean_dva_range(PARTIAL_CLASS2_STATE, 4)
    backend.space.flush()
    backend.u.inst("dsb sy")
    expected_queues = backend.PARTIAL_PRE_CLASS2_PAIR1_QUEUES
    for kind, (_entry, queue) in backend.muxed_queue_pairs[1].items():
        spec = expected_queues[kind]
        if (queue.address != spec["queue"]
                or queue.pointers_addr != spec["pointers"]
                or queue.item_ring != spec["item_ring"]
                or queue.job_list_addr !=
                backend.PARTIAL_PRE_CLASS2_PAIR1_JOB_LIST):
            raise RuntimeError(
                "partial pre-class2 %s queue incarnation drifted" % kind)
    if backend._read_dva(
            PARTIAL_CLASS2_SUPPORT, len(class2_body)) != class2_body:
        raise RuntimeError("partial class-2 compact control did not read back")
    print(
        "G17P PARTIAL constructed fresh grid-2/3 pre-class2 incarnation "
        "on TA_2/3D_2",
        flush=True,
    )
    if final_render_staged:
        print(
            "G17P PARTIAL admitting class 2 after render 36 outer "
            "publication and before its work doorbell",
            flush=True,
        )

    # Native has an accelerator-visible context-2 root by the time this
    # class-2 handler runs.  Merely putting context 2 in the queue/optional
    # records does not install that UAT slot: cold boot leaves slot 2 on an
    # isolated blank root tagged with the sentinel ASID.  Give it the same
    # complete low/high graph that the established source activation path
    # uses, then invalidate ASID 2 before the control doorbell.
    uat = backend.space.uat
    uat.set_l0(2, 0, uat.ttbr0_base, 2)
    uat.set_l0(2, 1, uat.ttbr1_base, 2)
    uat.flush_dirty()
    uat.invalidate_cache()
    backend.space.flush()
    backend.u.inst("dsb sy")
    backend.u.inst("tlbi aside1os, x0", 2 << 48)
    backend.u.inst("dsb sy")
    for address in (PARTIAL_CLASS2_SUPPORT, builder.shared[0]):
        translated = uat.iotranslate(2, address, 4)
        if not translated or translated[0][0] is None:
            raise RuntimeError(
                "partial context 2 cannot translate %#x" % address)
    print(
        "G17P PARTIAL installed context-2 low/high roots before class 2",
        flush=True,
    )

    if os.environ.get("G17P_PARTIAL_DUMP_PRECLASS2") == "1":
        # Preserve the complete source graph immediately before the native
        # sequence-0x21 tick and class-2 doorbell.  The coherent replay is
        # post-admission, so this pre-admission image is the missing half of a
        # captured/source substitution differential.
        snapshot_generated_render_slot(backend, 36, 1)

    # The exact primary prefix is opening class 1/tick 0, ticks 1..33, then
    # class 2 sequence 34.  Its tick follows two TA_2/3D_2 publications, so it
    # must remain deferred here.
    runtime["advance_runtime_ticks"](33)
    class2 = runtime["register_compute_control"](
        2, PARTIAL_CLASS2_SUPPORT, PRIMARY_CONTROL_OPERAND,
        slot_offset=0x5C0, context_word=0, count=0x28,
        defer_tick=True)
    print(
        "G17P PARTIAL admitted pre-class2 grid-2/3 incarnation: %r" %
        class2,
        flush=True,
    )
    return {"class2": class2, "cadence": cadence, "builder": builder}


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_render_uapi_partial.py accepts no arguments")
    negative = os.environ.get("G17P_PARTIAL_RESOURCE_NEGATIVE") == "1"
    context2_graph = os.environ.get("G17P_PARTIAL_CONTEXT2_GRAPH") == "1"
    submissions = submission_count()
    if negative and submissions != 1:
        raise SystemExit("the semantic negative must use one submission")
    if SOURCE_RENDER_BOOTSTRAP and not SOURCE_COMPUTE_BOOTSTRAP:
        raise SystemExit(
            "G17P_PARTIAL_SOURCE_RENDER_BOOTSTRAP requires "
            "G17P_PARTIAL_SOURCE_COMPUTE_BOOTSTRAP")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), ATTACHMENT_COUNT * OUTPUT_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        direct_replay_graph = (
            os.environ.get("G17P_PARTIAL_DIRECT_REPLAY_GRAPH") == "1")
        direct_control_admission = (
            os.environ.get("G17P_PARTIAL_DIRECT_CONTROL_ADMISSION") == "1")
        if SOURCE_COMPUTE_BOOTSTRAP:
            if getattr(front, "g17p_direct_bootstrap", None) is None:
                raise RuntimeError(
                    "source-compute bootstrap did not retain its backend")
            if direct_control_admission:
                raise RuntimeError(
                    "captured control admission cannot follow the source-built "
                    "compute lifecycle")
            # Do what the generic first-render adapter would do, before the
            # direct replay profile selects pair 2 below.  Leaving this until
            # submit would overwrite forced_queue_pair and invalidate the
            # discriminator.
            backend.prepare_submission_runtime(reset_staged=False)
            backend.forced_queue_pair = 1
            backend.group_number = max(backend.group_number, 1)
            print(
                "G17P PARTIAL retained the completed source-compute "
                "lifecycle and prepared its first render graph",
                flush=True,
            )
            if os.environ.get(
                    "G17P_PARTIAL_SOURCE_COMPUTE_CLASS3") == "1":
                admit_source_compute_partial_class3(front, backend)
            if SOURCE_RENDER_BOOTSTRAP:
                run_source_render_bootstrap(front, backend)
        else:
            require_opening_witness = (
                os.environ.get(
                    "G17P_PARTIAL_REQUIRE_OPENING_RENDER_WITNESS") == "1")
            drain_boot_group(
                front, backend,
                require_output_witness=require_opening_witness)
            if require_opening_witness:
                print(
                    "G17P PARTIAL retained an output-positive source-built "
                    "opening render lifecycle",
                    flush=True,
                )
        if direct_control_admission and not direct_replay_graph:
            raise RuntimeError(
                "direct partial control admission requires the direct replay graph")
        if direct_control_admission:
            admit_captured_partial_control(front, backend)
        if (os.environ.get("G17P_PARTIAL_RENDER_CADENCE") == "1"
                or context2_graph):
            runtime = front.g17p_runtime
            if runtime is None:
                raise RuntimeError("cold boot exposes no runtime control plane")
            if context2_graph and not backend.runtime_pair_registered:
                # The helper's historical name reflects the alternating-queue
                # experiment that first needed it.  On final 26.6 this call is
                # only opcode 0x2e sequence 0.  Native publishes it after the
                # opening grid-0/1 render and before reusing that same queue;
                # grid 2/3 does not exist yet.
                opening_tick = runtime["register_runtime_pair"]()
                if not opening_tick.get("final_26_6"):
                    raise RuntimeError(
                        "partial opening expected the final-26.6 tick-only path")
                backend.runtime_pair_registered = True
                print(
                    "G17P PARTIAL retired opening tick 0 without creating "
                    "pair one",
                    flush=True,
                )
            saved_forced_pair = backend.forced_queue_pair
            alternating_transport_control = (
                os.environ.get(
                    "G17P_PARTIAL_ALTERNATING_TRANSPORT_CONTROL") == "1")
            if not alternating_transport_control:
                backend.forced_queue_pair = 0
            if os.environ.get("G17P_PARTIAL_DUMP_OPENING_SECOND") == "1":
                previous_hook = backend.pre_notify_hook
                dumped_opening_second = {"value": False}

                def dump_opening_second(active_backend, pair_index):
                    if previous_hook is not None:
                        previous_hook(active_backend, pair_index)
                    if (not dumped_opening_second["value"]
                            and active_backend.group_number == 1):
                        snapshot_generated_render_slot(
                            active_backend, 2, pair_index)
                        dumped_opening_second["value"] = True

                backend.pre_notify_hook = dump_opening_second
            try:
                cadence = run_render_cadence(
                    front, backend, runtime,
                    expected_pair=None if alternating_transport_control else 0,
                    # The synchronized partial trace keeps all 36 opening
                    # descriptors in the grid-0/1 namespace.  Alternating the
                    # descriptor namespace aliases pair one's tiling-status
                    # page at c1638000, which must remain fresh for the class-2
                    # state object published at slot 36.
                    alternate_descriptor_pairs=not context2_graph)
                if cadence["workload"]["next_target"] != 31:
                    raise RuntimeError(
                        "final-26.6 render cadence did not reach 32 work items")
                if context2_graph:
                    finish_partial_registration_cadence(
                        front, backend, cadence)
            finally:
                backend.forced_queue_pair = saved_forced_pair
            print(
                "G17P PARTIAL reached the output-positive %d-render "
                "lifecycle before caller installation" %
                (36 if context2_graph else 32),
                flush=True,
            )
            if os.environ.get("G17P_PARTIAL_RENDER_COMPUTE_CLASS3") == "1":
                admit_render_cadence_compute_class3(front, backend)
            if os.environ.get("G17P_PARTIAL_CADENCE_ONLY") == "1":
                print(
                    "G17P PARTIAL CADENCE-ONLY PASS queue_items=%r "
                    "descriptor_items=%r" % (
                        dict(backend.queue_pair_submissions),
                        dict(backend.descriptor_pair_submissions)),
                    flush=True,
                )
                return 0
            # The legacy cadence helper sizes the shared memfd to its 31
            # one-page witnesses, which is slightly smaller than eight 64-KiB
            # attachments. Its objects remain valid when the file is extended.
            os.ftruncate(memfd.fileno(), ATTACHMENT_COUNT * OUTPUT_SIZE)
        if context2_graph:
            # Admit context 2 while the primary render root is still active,
            # matching the proven final-26.6 transition.  The modern VM below
            # then replaces context 2's low root with its cloned caller root.
            activation = cadence.get("partial_activation")
            if activation is None:
                activation = activate_partial_render_graph(
                    front, backend, cadence)
            if os.environ.get("G17P_PARTIAL_ADMISSION_ONLY") == "1":
                print(
                    "G17P PARTIAL CLASS2 ADMISSION PASS sequence=%#x "
                    "queue_items=%r" % (
                        activation["class2"]["sequence"],
                        dict(backend.queue_pair_submissions)),
                    flush=True,
                )
                return 0
        # Keep the opening renderer's physical code pages intact by default:
        # reserve its primary VM identity, give the focused UAPI queue a cloned
        # low root, and replace every caller/compiler page with fresh physical
        # backing in that root.  The primary-VM discriminator deliberately
        # reuses the already-admitted root after the opening group has retired;
        # it isolates render-context admission from partial-render encoding.
        primary = backend.primary_execution_context
        use_primary_vm = os.environ.get("G17P_PARTIAL_PRIMARY_VM") == "1"
        desired_context = (
            primary if use_primary_vm else 3 if context2_graph else primary + 1)
        if not use_primary_vm:
            occupied = set(front.g17p_fd_contexts.values())
            occupied.update(front.g17p_modern_vm_contexts.values())
            for expected in range(1, desired_context):
                if expected in occupied:
                    continue
                reservation = front.modern.create_vm(
                    FD - 10 + expected, 0x7000000000, 0x7800000000)
                if int(reservation.token) != expected:
                    raise RuntimeError(
                        "partial VM reservation expected context %d, got %d" %
                        (expected, int(reservation.token)))
                occupied.add(expected)
        vm = front.modern.create_vm(FD, 0x7000000000, 0x7800000000)
        if int(vm.token) != desired_context:
            raise RuntimeError(
                "partial workload expected context %d, got context %d" %
                (desired_context, int(vm.token)))
        backend.activate_execution_context(int(vm.token))
        print(
            "G17P PARTIAL installing caller graph on %s context %d" % (
                "primary" if use_primary_vm else "fresh", int(vm.token)),
            flush=True,
        )
        install_caller_graph(
            backend, negative, fresh_pages=not use_primary_vm)

        # The compact UAPI carries only the low resource-spec word.  This
        # own-source G17P pass uses the generation-specific firmware binding
        # prefix measured in its native descriptor; the retained opening pass
        # uses the older 0x00078000 prefix.  Keep the choice at the workload
        # boundary until it has a named UAPI representation.
        g17p_shim.G17P_LOAD_PIPELINE_BIND_PREFIX = 0xFFFF800000000000

        original_build_submission = backend.build_submission

        def build_partial_submission(cmdbuf):
            print(
                "G17P PARTIAL translated pipelines load=(%#x,%#x) "
                "store=(%#x,%#x) partial-load=(%#x,%#x) "
                "partial-store=(%#x,%#x)" % (
                    cmdbuf.load_pipeline_bind, cmdbuf.load_pipeline,
                    cmdbuf.store_pipeline_bind, cmdbuf.store_pipeline,
                    cmdbuf.partial_load_pipeline_bind,
                    cmdbuf.partial_load_pipeline,
                    cmdbuf.partial_store_pipeline_bind,
                    cmdbuf.partial_store_pipeline,
                ),
                flush=True,
            )
            built = original_build_submission(cmdbuf)
            if os.environ.get(
                    "G17P_PARTIAL_NATIVE_REGISTER_TAIL") == "1":
                overrides = {
                    "tiling": {
                        0x0A5A1: 0x000000E900400020,
                        0x1CA10: 0x0200022303000247,
                        0x014A1: 0x0200022303000247,
                        0x0A349: 0x0200022303000247,
                        0x14308: 1,
                    },
                    "fragment": {
                        0x0A5A9: 0x000000ED00400020,
                        0x160E0: 0x0200022303000246,
                        0x01499: 0x0200022303000246,
                        0x0A341: 0x0200022303000246,
                        0x14048: 1,
                    },
                }
                for kind in ("tiling", "fragment"):
                    built["%s_registers" % kind] = [
                        (number, overrides[kind].get(number, value))
                        for number, value in built[
                            "%s_registers" % kind]
                    ]
                print(
                    "G17P PARTIAL substituted the exact native target "
                    "register tail (five TA and five 3D values)",
                    flush=True,
                )
            return built

        backend.build_submission = build_partial_submission

        # The native pass names this caller-supplied auxiliary framebuffer.  Its
        # parameter-buffer objects are one allocation: heap metadata is 0x1000
        # into the tile-map allocation and the TPC is 0x28000 into it.  Ordinary
        # compatibility renders used unrelated legacy addresses for these two
        # fields, a distinction that matters only once the render overflows TIB.
        front.g17p_submission_state["aux_fb"] = 0x10000300000
        front.g17p_submission_state["heapmeta"] = 0x10001B1000
        front.g17p_submission_state["tpc"] = 0x10001D8000

        outputs = []
        for index, address in enumerate(OUTPUT_DVAS):
            handle = index + 1
            bo = front.modern.create_bo(
                FD, handle, index * OUTPUT_SIZE, OUTPUT_SIZE)
            front.modern.bind(FD, vm.vm_id, drm_asahi_gem_bind_op(
                DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
                bo.handle, 0, OUTPUT_SIZE, address))
            outputs.append(bo)
        queue = front.modern.create_queue(FD, vm.vm_id, 1, USC_EXEC_BASE)

        if direct_replay_graph:
            # Structural discriminator: publish on the exact grid-4/5 graph
            # family used by the executing replay, without pretending that
            # this alone reproduces the later class-3 control admission.  The
            # replay's fresh first group enters with scheduler slot two; use
            # the established single-phase writer so the context-2 phase hook
            # does not advance that already-ready value to four.
            backend.partial_render_pair2_profile = True
            backend.forced_queue_pair = 2
            backend.forced_channel_pair = 2
            backend.forced_descriptor_pair = 2
            backend.forced_queue_context = (
                3 if os.environ.get(
                    "G17P_PARTIAL_REPLAY_QUEUE_CONTEXT3") == "1" else 2)
            backend.forced_descriptor_context = 3
            backend.forced_pool_record_indices = (0, 1)
            backend.native_scheduler_publication = False
            backend.allow_quiesced_primary_index_alias_rebind = True
            if backend.partial_fresh_queue_generation:
                print(
                    "G17P PARTIAL allocating a distinct queue-record, pointer, "
                    "and item-ring generation after source compute",
                    flush=True,
                )
            if backend.partial_fresh_transport_topology:
                print(
                    "G17P PARTIAL giving that generation a private copied "
                    "queue context and shared job list",
                    flush=True,
                )
            if backend.partial_replay_queue_live_fields:
                print(
                    "G17P PARTIAL applying the positive queue records' "
                    "RPTR2 and +0x94 live fields",
                    flush=True,
                )
            uat = backend.space.uat
            for context in (2, 3):
                uat.set_l0(context, 0, uat.ttbr0_base, context)
                uat.set_l0(context, 1, uat.ttbr1_base, context)
            uat.flush_dirty()
            uat.invalidate_cache()
            backend.space.flush()
            backend.u.inst("dsb sy")
            for context in (2, 3):
                backend.u.inst("tlbi aside1os, x0", context << 48)
            backend.u.inst("dsb sy")
            if os.environ.get("G17P_PARTIAL_REPLAY_ITEM1") == "1":
                # The physically positive generated replay creates an empty
                # pair-2 transport and publishes logical descriptor item one
                # as its first queue entry.  Reproduce that split explicitly:
                # queue indices remain zero, while optional/descriptor,
                # queue-context, and scheduler metadata all start at one.
                backend.queue_pair_submissions[2] = 1
                backend.descriptor_pair_submissions[2] = 1
                backend.pair_resource_submissions[2] = 0
                print(
                    "G17P PARTIAL starting fresh pair-2 transport at "
                    "replay logical item 1, resource item 0",
                    flush=True,
                )
            print(
                "G17P PARTIAL selecting direct grid-4/5 replay graph with "
                "records A0/B1, queue context %d, descriptor context 3 "
                "(control admission %s)" % (
                    backend.forced_queue_context,
                    "reproduced through captured sequence 37"
                    if direct_control_admission else
                    "source-compute lifecycle"
                    if SOURCE_COMPUTE_BOOTSTRAP else
                    "intentionally unchanged"),
                flush=True,
            )

        # The first fresh item in the executing clean-room replay retains
        # Pool-A record zero while advancing Pool B to record one.  Keep this
        # as an explicit differential until the direct path is physically
        # positive; the eventual repeated path must derive the full measured
        # A0,A0,A2,A2/... and B0,B1,B2,B3/... cadence from its item ordinal.
        if os.environ.get("G17P_PARTIAL_FORCE_REPLAY_POOL_RECORDS") == "1":
            backend.forced_pool_record_indices = (0, 1)
            print(
                "G17P PARTIAL forcing replay-positive Pool-A/Pool-B "
                "records 0/1",
                flush=True,
            )
        if os.environ.get("G17P_PARTIAL_REBASE_REPLAY_A0") == "1":
            opening_builder = backend.paired_builders.get(0)
            if (opening_builder is None
                    or opening_builder.leaf_pages is None
                    or opening_builder.tiling.array_a is None):
                raise RuntimeError(
                    "partial A0 rebase needs the completed opening graph")
            slot_page = opening_builder.leaf_pages["pool_a_slots"]
            slot_body = g17p_submission.build_context2_submission_leaf_pages()[
                "pool_a_slots"]
            slot = slot_page + g17p_submission.POOL_A_SLOT_OFFSET
            record_a0 = opening_builder.tiling.array_a
            backend._write_dva(slot_page, slot_body)
            backend._write_dva(record_a0, struct.pack("<Q", slot))
            backend._clean_dva_range(slot_page, len(slot_body))
            backend._clean_dva_range(record_a0, 8)
            backend.u.inst("dsb sy")
            if backend._read_dva(record_a0, 8) != struct.pack("<Q", slot):
                raise RuntimeError("partial A0 pointer rebase did not read back")
            backend.forced_pool_record_indices = (0, 1)
            print(
                "G17P PARTIAL regenerated Pool-A slots and rebased A0 %#x "
                "onto replay-equivalent slot %#x; forcing records 0/1" %
                (record_a0, slot),
                flush=True,
            )

        if os.environ.get(
                "G17P_PARTIAL_DUMP_FIRMWARE_BEFORE_SUBMIT") == "1":
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            artifact_root = pathlib.Path(os.environ.get(
                "G17P_ARTIFACTS",
                "/Users/user/asahi_re/artifacts/agx_g17p"))
            capture_reference_firmware_pages(
                backend,
                pathlib.Path(os.environ.get(
                    "G17P_PARTIAL_FIRMWARE_REFERENCE",
                    "/Users/user/asahi_re/artifacts/agx_g17p/"
                    "native_partial_pre_kick_20260819_234640")),
                artifact_root / (
                    "source_partial_pre_submit_firmware_" + stamp),
            )

        replay_queue_predecessor = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_QUEUE_PREDECESSOR") == "1")
        source_queue_predecessor = (
            os.environ.get(
                "G17P_PARTIAL_SOURCE_QUEUE_PREDECESSOR") == "1")
        if replay_queue_predecessor and source_queue_predecessor:
            raise RuntimeError(
                "select either replay or source queue predecessor, not both")
        replay_channel_control = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_CHANNEL_CONTROL") == "1")
        replay_current_jobs = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_CURRENT_JOBS") == "1")
        replay_shared_control = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_SHARED_CONTROL") == "1")
        replay_events = (
            os.environ.get("G17P_PARTIAL_REPLAY_EVENTS") == "1")
        replay_primary_index = (
            os.environ.get("G17P_PARTIAL_REPLAY_PRIMARY_INDEX") == "1")
        replay_resource_lifecycle = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_RESOURCE_LIFECYCLE") == "1")
        replay_output_physical = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_OUTPUT_PHYSICAL") == "1")
        replay_graph_physical = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_GRAPH_PHYSICAL") == "1")
        replay_transport_physical = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_TRANSPORT_PHYSICAL") == "1")
        replay_caller_physical = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_CALLER_PHYSICAL") == "1")
        replay_execution_physical = (
            os.environ.get(
                "G17P_PARTIAL_REPLAY_EXECUTION_PHYSICAL") == "1")
        if replay_graph_physical and replay_transport_physical:
            raise RuntimeError(
                "select graph or cumulative transport physical placement, "
                "not both")
        if (replay_output_physical or replay_graph_physical
                or replay_transport_physical or replay_caller_physical
                or replay_execution_physical) \
                and submissions != 1:
            raise RuntimeError(
                "native physical placement is a one-submission discriminator")
        dump_pre_notify = (
            os.environ.get("G17P_PARTIAL_DUMP_PRE_NOTIFY") == "1")
        if (replay_queue_predecessor or source_queue_predecessor
                or replay_channel_control
                or replay_current_jobs or replay_shared_control
                or replay_events or replay_primary_index
                or replay_resource_lifecycle or replay_output_physical
                or replay_graph_physical
                or replay_transport_physical
                or replay_caller_physical
                or replay_execution_physical
                or dump_pre_notify):
            pre_notify_done = {"value": False}

            def prepare_partial_graph(active_backend, pair_index):
                if pre_notify_done["value"]:
                    return
                reference = pathlib.Path(os.environ.get(
                    "G17P_PARTIAL_REPLAY_PRE_NOTIFY",
                    "/Users/user/asahi_re/artifacts/agx_g17p/"
                    "positive_replay_pre_notify_20260820_1805"))
                if replay_queue_predecessor:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial predecessor graft expected pair 2, got "
                            "%d" % pair_index)
                    filenames = {
                        "tiling": (
                            "tiling_queue_context_item_page_"
                            "fffffc2000278000.bin"),
                        "fragment": (
                            "fragment_queue_context_item_page_"
                            "fffffc20002a0000.bin"),
                    }
                    changed = {}
                    for kind, filename in filenames.items():
                        source = (reference / filename).read_bytes()
                        if len(source) < 0x380:
                            raise RuntimeError(
                                "partial predecessor reference %s is only "
                                "%#x bytes" % (reference / filename,
                                                len(source)))
                        predecessor = source[0x200:0x380]
                        page = active_backend.muxed_queue_context_pages[
                            pair_index][kind]["high"]
                        destination = page + 0x200
                        before = active_backend._read_dva(
                            destination, len(predecessor))
                        changed[kind] = sum(
                            left != right for left, right in
                            zip(before, predecessor))
                        active_backend._write_dva(destination, predecessor)
                        active_backend._clean_dva_range(
                            destination, len(predecessor))
                    active_backend.u.inst("dsb sy")
                    for kind, filename in filenames.items():
                        predecessor = (
                            reference / filename).read_bytes()[0x200:0x380]
                        page = active_backend.muxed_queue_context_pages[
                            pair_index][kind]["high"]
                        if active_backend._read_dva(
                                page + 0x200,
                                len(predecessor)) != predecessor:
                            raise RuntimeError(
                                "partial %s predecessor graft did not read "
                                "back" % kind)
                    print(
                        "G17P PARTIAL grafted replay queue predecessor "
                        "changed_bytes=%d tiling=%d fragment=%d" % (
                            sum(changed.values()), changed["tiling"],
                            changed["fragment"]),
                        flush=True,
                    )
                if source_queue_predecessor:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial source predecessor expected pair 2, got "
                            "%d" % pair_index)
                    published = active_backend.last_published_pair or {}
                    changed = {}
                    for kind in ("tiling", "fragment"):
                        items = published.get(kind)
                        if items is None or not items:
                            raise RuntimeError(
                                "partial %s publication has no descriptor" %
                                kind)
                        descriptor = int(items[0])
                        queue = active_backend.muxed_queue_pairs[
                            pair_index][kind][1]
                        predecessor = bytearray(
                            g17p_submission.build_queue_context_item(
                                kind, descriptor, queue.address,
                                pair=pair_index, item_index=0,
                                context_id=2,
                                grid_index=queue.grid_index,
                                locator_context_id=3))
                        # The measured fragment predecessor carries the graph
                        # context identity in this otherwise-zero word.  Its
                        # descriptor and locator remain source-derived here.
                        if kind == "fragment":
                            struct.pack_into("<Q", predecessor, 0x148, 3)
                        page = active_backend.muxed_queue_context_pages[
                            pair_index][kind]["high"]
                        destination = page + 0x200
                        before = active_backend._read_dva(
                            destination, len(predecessor))
                        changed[kind] = sum(
                            left != right for left, right in
                            zip(before, predecessor))
                        active_backend._write_dva(
                            destination, bytes(predecessor))
                        active_backend._clean_dva_range(
                            destination, len(predecessor))
                    active_backend.u.inst("dsb sy")
                    print(
                        "G17P PARTIAL built coherent source queue "
                        "predecessors changed_bytes=%d tiling=%d "
                        "fragment=%d" % (
                            sum(changed.values()), changed["tiling"],
                            changed["fragment"]),
                        flush=True,
                    )
                if replay_channel_control:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial channel-control graft expected pair 2, "
                            "got %d" % pair_index)
                    source_path = (
                        reference /
                        "channel_control_fffffc20c07b8000.bin")
                    source = source_path.read_bytes()
                    offset = 0xC0
                    size = active_backend.CHANNEL_CONTROL_STRIDE
                    if len(source) < offset + size:
                        raise RuntimeError(
                            "partial channel-control reference %s is only "
                            "%#x bytes" % (source_path, len(source)))
                    record = source[offset:offset + size]
                    destination = (
                        active_backend.CHANNEL_CONTROL_BASE + offset)
                    for kind in ("tiling", "fragment"):
                        pointer = active_backend.muxed_queue_pointer_sets[
                            pair_index][kind]["channel_control"]
                        if pointer != destination:
                            raise RuntimeError(
                                "partial %s optional item names channel "
                                "control %#x, expected graft destination %#x" %
                                (kind, pointer, destination))
                    before = active_backend._read_dva(destination, size)
                    changed = sum(
                        left != right for left, right in zip(before, record))
                    active_backend._write_dva(destination, record)
                    active_backend._clean_dva_range(destination, size)
                    active_backend.u.inst("dsb sy")
                    if active_backend._read_dva(
                            destination, size) != record:
                        raise RuntimeError(
                            "partial channel-control graft did not read back")
                    print(
                        "G17P PARTIAL grafted referenced replay channel "
                        "control changed_bytes=%d address=%#x" %
                        (changed, destination),
                        flush=True,
                    )
                if replay_current_jobs:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial current-job graft expected pair 2, got "
                            "%d" % pair_index)
                    source_path = (
                        reference / "current_jobs_fffffc20c07d0000.bin")
                    records = source_path.read_bytes()
                    if len(records) != 0x80:
                        raise RuntimeError(
                            "partial current-job reference %s is %#x bytes, "
                            "expected 0x80" % (source_path, len(records)))
                    destination = 0xFFFFFC20C07D0000
                    before = active_backend._read_dva(
                        destination, len(records))
                    changed = sum(
                        left != right for left, right in zip(before, records))
                    active_backend._write_dva(destination, records)
                    active_backend._clean_dva_range(
                        destination, len(records))
                    active_backend.u.inst("dsb sy")
                    if active_backend._read_dva(
                            destination, len(records)) != records:
                        raise RuntimeError(
                            "partial current-job graft did not read back")
                    print(
                        "G17P PARTIAL grafted replay current-job records "
                        "changed_bytes=%d address=%#x" %
                        (changed, destination),
                        flush=True,
                    )
                if replay_shared_control:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial shared-control graft expected pair 2, "
                            "got %d" % pair_index)
                    source_path = (
                        reference /
                        "tiling_shared_control_page_fffffc20c08d0000.bin")
                    source = source_path.read_bytes()
                    if len(source) < 0x100:
                        raise RuntimeError(
                            "partial shared-control reference %s is only "
                            "%#x bytes" % (source_path, len(source)))
                    control = source[:0x100]
                    destination = None
                    for kind in ("tiling", "fragment"):
                        pointer = active_backend.muxed_queue_pointer_sets[
                            pair_index][kind]["shared_control"]
                        if destination is None:
                            destination = pointer
                        elif pointer != destination:
                            raise RuntimeError(
                                "partial shared-control pointers disagree: "
                                "%#x != %#x" % (pointer, destination))
                    if destination != 0xFFFFFC20C08D0000:
                        raise RuntimeError(
                            "partial shared-control destination is %#x" %
                            destination)
                    inner = struct.unpack_from("<Q", control, 0x4C)[0]
                    if inner != 0xFFFFFC2001688000:
                        raise RuntimeError(
                            "partial replay shared control names inner %#x" %
                            inner)
                    inner_path = (
                        reference /
                        "tiling_shared_control_inner_page_"
                        "fffffc2001688000.bin")
                    inner_record = inner_path.read_bytes()[:8]
                    if len(inner_record) != 8:
                        raise RuntimeError(
                            "partial shared-control inner reference %s is "
                            "short" % inner_path)
                    before = active_backend._read_dva(
                        destination, len(control))
                    inner_before = active_backend._read_dva(
                        inner, len(inner_record))
                    changed_control = sum(
                        left != right for left, right in zip(before, control))
                    changed_inner = sum(
                        left != right for left, right in
                        zip(inner_before, inner_record))
                    active_backend._write_dva(destination, control)
                    active_backend._write_dva(inner, inner_record)
                    active_backend._clean_dva_range(
                        destination, len(control))
                    active_backend._clean_dva_range(inner, len(inner_record))
                    active_backend.u.inst("dsb sy")
                    if active_backend._read_dva(
                            destination, len(control)) != control:
                        raise RuntimeError(
                            "partial shared-control graft did not read back")
                    if active_backend._read_dva(
                            inner, len(inner_record)) != inner_record:
                        raise RuntimeError(
                            "partial shared-control inner graft did not read "
                            "back")
                    print(
                        "G17P PARTIAL grafted replay shared-control closure "
                        "changed_bytes=%d control=%d inner=%d" % (
                            changed_control + changed_inner,
                            changed_control, changed_inner),
                        flush=True,
                    )
                if replay_events:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial event graft expected pair 2, got %d" %
                            pair_index)
                    published = active_backend.last_published_pair or {}
                    filenames = {
                        "tiling": "tiling_event_fffffc20c05e9540.bin",
                        "fragment": "fragment_event_fffffc20c05e9500.bin",
                    }
                    changed = {}
                    expected_addresses = {}
                    for kind, filename in filenames.items():
                        items = published.get(kind)
                        if items is None or len(items) < 3:
                            raise RuntimeError(
                                "partial %s publication has no event item" %
                                kind)
                        destination = int(items[2])
                        expected_addresses[kind] = destination
                        event = (reference / filename).read_bytes()
                        if len(event) != 0x40:
                            raise RuntimeError(
                                "partial %s replay event is %#x bytes, "
                                "expected 0x40" % (kind, len(event)))
                        before = active_backend._read_dva(
                            destination, len(event))
                        changed[kind] = sum(
                            left != right for left, right in
                            zip(before, event))
                        active_backend._write_dva(destination, event)
                        active_backend._clean_dva_range(
                            destination, len(event))
                    active_backend.u.inst("dsb sy")
                    for kind, filename in filenames.items():
                        event = (reference / filename).read_bytes()
                        if active_backend._read_dva(
                                expected_addresses[kind],
                                len(event)) != event:
                            raise RuntimeError(
                                "partial %s event graft did not read back" %
                                kind)
                    print(
                        "G17P PARTIAL grafted replay event records "
                        "changed_bytes=%d tiling=%d fragment=%d" % (
                            sum(changed.values()), changed["tiling"],
                            changed["fragment"]),
                        flush=True,
                    )
                if replay_primary_index:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial primary-index graft expected pair 2, "
                            "got %d" % pair_index)
                    source_path = (
                        reference /
                        "bound_leaf_primary_index_fffffc20c08f0000.bin")
                    source = source_path.read_bytes()
                    if len(source) < 0x80:
                        raise RuntimeError(
                            "partial primary-index reference %s is only "
                            "%#x bytes" % (source_path, len(source)))
                    permutation = source[:0x80]
                    destination = 0xFFFFFC20C08F0000
                    before = active_backend._read_dva(
                        destination, len(permutation))
                    changed = sum(
                        left != right for left, right in
                        zip(before, permutation))
                    active_backend._write_dva(destination, permutation)
                    active_backend._clean_dva_range(
                        destination, len(permutation))
                    active_backend.u.inst("dsb sy")
                    if active_backend._read_dva(
                            destination, len(permutation)) != permutation:
                        raise RuntimeError(
                            "partial primary-index graft did not read back")
                    print(
                        "G17P PARTIAL installed replay primary-index "
                        "permutation changed_bytes=%d address=%#x" %
                        (changed, destination),
                        flush=True,
                    )
                if replay_resource_lifecycle:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial resource-lifecycle graft expected pair "
                            "2, got %d" % pair_index)
                    objects = (
                        ("bound_record_a_fffffc20c08c8100.bin",
                         0xFFFFFC20C08C8100, 0x100),
                        ("bound_record_b_fffffc20c08d8100.bin",
                         0xFFFFFC20C08D8100, 0x80),
                        ("bound_packed_shared_fffffc20c0908000.bin",
                         0xFFFFFC20C0908000, 0x88),
                        ("bound_leaf_shared_slots_fffffc2001698000.bin",
                         0xFFFFFC2001698000, 0x80),
                    )
                    changed = {}
                    expected = {}
                    for filename, destination, size in objects:
                        source_path = reference / filename
                        source = source_path.read_bytes()
                        if len(source) < size:
                            raise RuntimeError(
                                "partial resource reference %s is only %#x "
                                "bytes, expected %#x" % (
                                    source_path, len(source), size))
                        body = source[:size]
                        before = active_backend._read_dva(
                            destination, size)
                        changed[filename] = sum(
                            left != right for left, right in
                            zip(before, body))
                        active_backend._write_dva(destination, body)
                        active_backend._clean_dva_range(destination, size)
                        expected[destination] = body
                    active_backend.u.inst("dsb sy")
                    for destination, body in expected.items():
                        if active_backend._read_dva(
                                destination, len(body)) != body:
                            raise RuntimeError(
                                "partial resource-lifecycle graft at %#x did "
                                "not read back" % destination)
                    print(
                        "G17P PARTIAL installed replay resource lifecycle "
                        "changed_bytes=%d A=%d B=%d shared=%d slot=%d" % (
                            sum(changed.values()),
                            changed[objects[0][0]], changed[objects[1][0]],
                            changed[objects[2][0]], changed[objects[3][0]]),
                        flush=True,
                    )
                if replay_output_physical:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial output physical reback expected pair 2, "
                            "got %d" % pair_index)
                    remap_outputs_to_native_physical(active_backend)
                if replay_graph_physical:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial graph physical reback expected pair 2, "
                            "got %d" % pair_index)
                    remap_partial_graph_to_native_physical(active_backend)
                if replay_transport_physical:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial transport physical reback expected pair "
                            "2, got %d" % pair_index)
                    remap_partial_graph_to_native_physical(
                        active_backend, include_transport=True)
                if replay_caller_physical:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial caller/PB physical reback expected pair "
                            "2, got %d" % pair_index)
                    remap_partial_caller_to_native_physical(active_backend)
                if replay_execution_physical:
                    if pair_index != 2:
                        raise RuntimeError(
                            "partial execution physical reback expected pair "
                            "2, got %d" % pair_index)
                    remap_partial_execution_to_native_physical(active_backend)
                if dump_pre_notify:
                    snapshot_generated_render_slot(
                        active_backend, active_backend.group_number,
                        pair_index)
                pre_notify_done["value"] = True

            backend.pre_notify_hook = prepare_partial_graph

        command_buffer = render_commands()
        final_maxima = None
        for ordinal in range(submissions):
            for bo in outputs:
                bo.token["map"][:] = bytes(OUTPUT_SIZE)
            fence, commands = front.modern.submit(
                FD, queue.queue_id, command_buffer)
            if not fence.signaled():
                raise RuntimeError(
                    "partial render fence %d did not signal" % ordinal)
            live_outputs = tuple(
                backend._read_dva(address, OUTPUT_SIZE)
                for address in OUTPUT_DVAS
            )
            live_maxima = tuple(output_maximum(body) for body in live_outputs)
            bo_outputs = tuple(
                bytes(bo.token["map"][:OUTPUT_SIZE]) for bo in outputs
            )
            bo_maxima = tuple(output_maximum(body) for body in bo_outputs)
            print(
                "G17P PARTIAL output witness live=%r bo=%r equal=%d" % (
                    live_maxima, bo_maxima, int(live_outputs == bo_outputs)),
                flush=True,
            )
            witness_outputs = (
                live_outputs if replay_output_physical else bo_outputs)
            final_maxima = validate_outputs(witness_outputs, negative)
            if (ordinal < 3 or ordinal + 1 == submissions
                    or (ordinal + 1) % 32 == 0):
                print(
                    "G17P PARTIAL progress=%d/%d maxima=%r pair=%r item=%r" % (
                        ordinal + 1, submissions, final_maxima,
                        backend.submission_queue_pair(),
                        dict(backend.queue_pair_submissions)),
                    flush=True,
                )
            if len(commands) != 1:
                raise RuntimeError(
                    "partial submit resolved %d commands" % len(commands))

        print(
            "G17P PARTIAL UAPI PASS negative=%d submissions=%d triangles=%d "
            "vertices=%d attachments=%d maxima=%r queue_items=%r" % (
                negative, submissions, TRIANGLE_COUNT, VERTEX_COUNT,
                ATTACHMENT_COUNT, final_maxima,
                dict(backend.queue_pair_submissions)),
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
