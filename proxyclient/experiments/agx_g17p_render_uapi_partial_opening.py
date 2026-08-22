#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the minimum partial render as the cold opening UAPI submission.

This uses the same serialized DRM command and caller/compiler payload as the
runtime partial test, but installs the translated render recipe before GPU
firmware starts.  It is a discriminator for the independently known inability
of later generated nonempty-geometry groups to enter graphics execution.
"""

import dataclasses
import math
import os
from pathlib import Path
import struct
import sys
import time
import types


os.environ.setdefault("M1N1DEVICE", "/dev/ttys004")
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_NATIVE_LIFECYCLE_FIELDS"] = "1"
os.environ["G17P_NATIVE_TAIL_ITEM_FIELDS"] = "1"
os.environ["G17P_STRUCTURAL_TAIL_FIELDS"] = "1"
# These switches must be visible while agx_g17p_boot is imported: its fixed
# address inventory is selected at module initialization.  The runtime partial
# module also selects them, but importing it below the boot module was too late
# and silently constructed the older 32-group/shifted support graph.
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_NATIVE_PARTIAL_OPENING_QUEUE"] = "1"
os.environ["G17P_PARTIAL_OPENING_GRAPH"] = "1"
os.environ["G17P_ALLOW_INTERNAL_RENDER_POINTERS"] = "1"
# The clean first-application checkpoint has only the secondary opening 0x2a
# consumed at counters 1/1/1.  The 18-entry 0x22 suffix belongs to the later
# mature graphics lifecycle and changes firmware-internal state outside the
# otherwise-exact first-work closure.
os.environ["G17P_FINAL_26_6_SECONDARY_TARGET"] = "1"
_ARTIFACTS = (
    Path(__file__).resolve().parents[3] / "artifacts" / "agx_g17p")
os.environ.setdefault("G17P_ARTIFACTS", str(_ARTIFACTS))
PAYLOAD = (
    _ARTIFACTS / "workload_payloads" /
    "own_source_partial_accumulate_48217" / "manifest.json"
)
# Match the independently positive clean replay boundary: both opening records
# are present byte-exactly in the source-built ring, but their counters and the
# compact support object already carry the measured post-control state when
# fresh firmware accepts initdata.  Earlier presented-control tests predated
# the exact partial operand destination/count and therefore left a different
# consumed ring record visible to firmware.
os.environ["G17P_SOURCE_PRESENT_PRIMARY_CONTROL_DONE"] = "1"
# Native leaves the secondary instance's fixed-record page blank before this
# first kick.  The source path nevertheless needs non-null descriptor/queue
# operands there to avoid task 2 cache-maintaining address zero.  Publish only
# those four generated pointers for this discriminator; copying the primary
# records' headers into the secondary page is not native input and may select a
# second lifecycle owner for the same TA/3D group.
os.environ["G17P_PARTIAL_SECONDARY_RECORD_FIELDS"] = "header-pointers"
import agx_g17p_boot as boot  # noqa: E402
boot.SOURCE_NATIVE_PHYSICAL_TOPOLOGY = True
from agx_g17p_render_uapi_partial import (  # noqa: E402
    ATTACHMENT_COUNT,
    CONTEXT_BASE,
    DBIAS_DVA,
    ENCODER_DVA,
    OUTPUT_DVAS,
    OUTPUT_SIZE,
    RESOURCE_DVA,
    SCISSOR_DVA,
    TRIANGLE_COUNT,
    USC_EXEC_BASE,
    VIEWPORT_DVA,
    exact_encoder,
    load_deferred_pages,
    render_commands,
)
from m1n1.agx import g17p_render, g17p_shim, g17p_submission  # noqa: E402
from m1n1.agx.g17p_payload import parse_page_selector  # noqa: E402
from m1n1.agx.g17p_modern import (  # noqa: E402
    G17PModernDriver,
)
from m1n1.agx.g17p_uapi import (  # noqa: E402
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_WRITE,
    DRM_ASAHI_CMD_RENDER,
    DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES,
    parse_command_buffer,
)


PAGE = 0x4000
TILEMAP_DVA = 0x10001B0000
HEAPMETA_DVA = 0x10001B1000
TPC_DVA = 0x10001D8000
AUX_FB_DVA = 0x10000300000
TA_STATUS_DVA = 0x1000078000
FRAGMENT_STATUS_DVA = 0x10001A8000
DEFLAKE_1_DVA = 0x10000682A0
DEFLAKE_2_DVA = 0x1000068020
DEFLAKE_3_DVA = 0x1000068000
PARTIAL_RENDER_STATE = [None]
PARTIAL_RENDER_CONTROL_PUBLISHED = [False]
PARTIAL_PRIMARY_INDEX_PUBLISHED = [False]
INTEGRATION_OUTPUT_BO = [None]
NATIVE_CONTEXT0_EMPTY_HIGH_ROOT_PA = 0x10034BC8000
NATIVE_RENDER_EMPTY_HIGH_ROOT_PA = 0x10057B9C000
NATIVE_CONTEXT_HIGH_ROOTS_INSTALLED = [False]
PRIMARY_REGION_SCHEDULER_DVA = 0xfffffc20015e0000
FRAGMENT_OUTER_DVA = 0xfffffc20c079bdc0
TILING_OUTER_DVA = 0xfffffc20c0795dc0
def _publish_native_primary_region_scheduler(prepared):
    """Install the one-record primary scheduler page used before first work.

    Firmware's cold source opening leaves two 0x20-byte records here, while a
    native first-work capture has one.  A post-control graft proved that these
    four differing bytes alone decide whether otherwise-identical work reaches
    graphics execution.  This page has no raw descriptor pointer, so it is a
    host-owned computed dependency rather than part of either work closure.
    """
    body = bytearray(PAGE)
    struct.pack_into("<Q", body, 0, 0x0000002000019000)
    prepared["submitter"].write(PRIMARY_REGION_SCHEDULER_DVA, body)
    boot.u.inst("dsb sy")
    print(
        "G17P PARTIAL OPENING published one-record primary scheduler page",
        flush=True,
    )


def _audit_clean_first_work(prepared):
    """Publish the earlier 3D boundary and post-control resources.

    This runs after final-26.6 has processed the opening control and after the
    exact queue profile is applied, but before either work producer is visible.
    All bytes at this point come from the live source constructors; capture
    closure comparison is deliberately excluded from the integration path.
    """
    _publish_native_primary_region_scheduler(prepared)
    restore_3d_outer = prepared.pop("partial_restore_3d_outer", None)
    if restore_3d_outer is not None:
        restore_3d_outer()
        boot.u.inst("dsb sy")
    # Both clean closure copies keep the operand page and its four directory
    # pages zero.  A populated 28-entry directory is a later mature-world
    # state, not part of this first partial publication.  Leave it withheld so
    # the generated graph reaches the work boundary native actually presents.
    _install_native_context_high_roots(prepared)


def _install_native_context_high_roots(prepared):
    """Give the two hardware contexts their native empty upper roots.

    The clean capture's populated firmware upper tree is an off-table firmware
    root, not either entry in ``gpu-region``.  Source construction historically
    points both hardware slots at that tree.  Delay correcting the topology
    until the exact first-work audit has finished: initdata and the opening
    control can still use the source firmware tree, while the TA/3D producers
    see the same two-slot roots as native's first application render.
    """
    if NATIVE_CONTEXT_HIGH_ROOTS_INSTALLED[0]:
        raise RuntimeError("native empty hardware high roots installed twice")

    roots = (
        (0, 0, NATIVE_CONTEXT0_EMPTY_HIGH_ROOT_PA),
        (1, 1, NATIVE_RENDER_EMPTY_HIGH_ROOT_PA),
    )
    for _slot, _asid, root_pa in roots:
        for record in prepared["arena"].entries:
            begin = int(record["pa"])
            end = begin + int(record["size"])
            if begin <= root_pa < end or root_pa <= begin < root_pa + PAGE:
                raise RuntimeError(
                    "native empty high root %#x overlaps arena object %s at "
                    "%#x..%#x" % (root_pa, record["name"], begin, end))
        boot.p.memset32(root_pa, 0, PAGE)
        boot.p.dc_civac(root_pa, PAGE)

    uat = prepared["uat"]
    for slot, asid, root_pa in roots:
        uat.set_l0(slot, 1, root_pa, asid)
    uat.flush_dirty()
    uat.invalidate_cache()
    uat.invalidate_root_walk_cache()
    boot.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")

    expected = (
        0x0000010034BC8001,
        0x0001010057B9C001,
    )
    actual = tuple(
        int(boot.p.read64(uat.gpu_region + slot * 16 + 8))
        for slot, _asid, _root_pa in roots
    )
    if actual != expected:
        raise RuntimeError(
            "native high-root readback mismatch: %s != %s" %
            (tuple(hex(value) for value in actual),
             tuple(hex(value) for value in expected)))
    NATIVE_CONTEXT_HIGH_ROOTS_INSTALLED[0] = True
    print(
        "G17P PARTIAL OPENING installed native empty hardware high roots: "
        "slot 0 -> %#x, slot 1 -> %#x; source firmware root %#x retained "
        "off-table" % (
            NATIVE_CONTEXT0_EMPTY_HIGH_ROOT_PA,
            NATIVE_RENDER_EMPTY_HIGH_ROOT_PA,
            uat.ttbr1_base),
        flush=True,
    )


def _enter_clean_early_3d_state(prepared):
    """Expose only the source-built state present at native's 3D kick.

    Staging constructs the complete paired submission before firmware starts.
    Native instead makes six TA-owned ranges visible only after its earlier 3D
    kick.  Save our generated later bytes, install the independently measured
    early scalar/blank values, and return the transition which reconstructs
    the complete generated graph before TA publication.
    """
    _publish_native_primary_region_scheduler(prepared)
    _publish_partial_primary_index(prepared)
    submitter = prepared["submitter"]
    fragment_outer = FRAGMENT_OUTER_DVA
    tiling_outer = TILING_OUTER_DVA
    fragment_ranges = (
        (fragment_outer, bytes(0x18), "3D outer record"),
        (boot.QUEUE_POINTER_BLOCK_VA
         + boot.QUEUE_POINTER_BLOCK_STRIDE + 0x40,
         struct.pack("<I", 0), "3D queue write index"),
        (boot.SUBMISSION_ADDRESSES["3D_0_item_ring"],
         bytes(3 * 8), "3D item-ring group"),
        (boot.SUBMISSION_ADDRESSES["fragment_event_item"],
         bytes(0x40), "3D event record"),
        (boot.SUBMISSION_ADDRESSES["fragment_optional_item"],
         bytes(0xC0), "3D optional record"),
    )
    fragment_later = []
    for address, early, label in fragment_ranges:
        body = submitter.read(address, len(early))
        fragment_later.append((address, body, label))
        submitter.write(address, early)

    fragment_outer_restored = [False]

    def restore_fragment_outer():
        if fragment_outer_restored[0]:
            raise RuntimeError("partial 3D publication restored twice")
        for address, body, _label in fragment_later:
            submitter.write(address, body)
        fragment_outer_restored[0] = True
        print(
            "G17P PARTIAL OPENING published complete source-built 3D state: "
            + ", ".join(label for _address, _body, label in fragment_later),
            flush=True,
        )

    prepared["partial_restore_3d_outer"] = restore_fragment_outer
    ranges = (
        (tiling_outer, bytes(0x18), "TA outer record"),
        (boot.QUEUE_POINTER_BLOCK_VA + 0x40,
         struct.pack("<I", 0), "TA queue write index"),
        (boot.LEAF_PAGE_ADDRESSES["pool_a_slots"] + 0x4,
         struct.pack("<I", 1), "pool-A next slot"),
        (boot.PARTIAL_OPENING_SHARED_CONTROL_INNER_ADDRESS,
         struct.pack("<I", 1), "compact-control child phase"),
        (boot.SUBMISSION_ADDRESSES["TA_0_item_ring"],
         bytes(3 * 8), "TA item-ring group"),
        (boot.SUBMISSION_ADDRESSES["tiling_event_item"],
         bytes(0x40), "TA event record"),
        (boot.SUBMISSION_ADDRESSES["tiling_optional_item"],
         bytes(0xC0), "TA optional record"),
    )
    later = []
    for address, early, label in ranges:
        body = submitter.read(address, len(early))
        later.append((address, body, label))
        submitter.write(address, early)
    boot.u.inst("dsb sy")
    print(
        "G17P PARTIAL OPENING entered source-built early 3D state: %s" %
        ", ".join(label for _address, _body, label in later),
        flush=True,
    )
    restored = [False]

    def restore_later_state():
        if restored[0]:
            raise RuntimeError("partial later state restored twice")
        for address, body, _label in later:
            submitter.write(address, body)
        boot.u.inst("dsb sy")
        restored[0] = True
        print(
            "G17P PARTIAL OPENING restored complete source-built TA state",
            flush=True,
        )

    return restore_later_state


def _publish_native_pre_0x84_status(instances, _ascs):
    """Publish the five stable native primary status fields in host phase."""
    primary = instances[0]
    status_b_pa = primary["status_b_pa"]
    kern_va_base = (
        primary["state_va"] - boot.g17p.NATIVE_PRIMARY_WORK_STATE_OFFSET
    )
    fwctl_va = kern_va_base + boot.g17p.NATIVE_FWCTL_OFFSET
    writes = (
        (0x4018, struct.pack("<Q", 0x0005060100000000)),
        (0x4020, struct.pack("<Q", 61)),
        (0x40B0, struct.pack("<Q", 5)),
        (0x48E0, struct.pack("<Q", fwctl_va)),
        (0x48E8, struct.pack(
            "<Q", fwctl_va + boot.g17p.CONTROL_MESSAGE_SIZE)),
    )
    for offset, body in writes:
        boot.iface.writemem(status_b_pa + offset, body)
        boot.p.dc_civac(status_b_pa + offset, len(body))
    boot.u.inst("dsb sy")
    print(
        "G17P PARTIAL OPENING published 5 native primary status fields "
        "before 0x84",
        flush=True,
    )


def _validated_drm_command():
    """Parse the public byte stream and run the production scalar validator."""
    parsed = parse_command_buffer(render_commands())
    render = [entry for entry in parsed
              if entry.header.cmd_type == DRM_ASAHI_CMD_RENDER]
    if len(render) != 1:
        raise RuntimeError("partial stream did not parse as one render command")
    command = render[0]
    if len(command.fragment_attachments) != ATTACHMENT_COUNT:
        raise RuntimeError("partial stream lost its eight attachment hints")

    # The validator needs ownership bindings, not their live physical pages.
    # The cold hook checks every resulting DVA against the real UAT mapping
    # before publication.  A single complete fake binding lets the production
    # validator focus here on the UAPI's ranges, flags, geometry, TIB limit,
    # helpers, samplers, ZLS, and program encodings.
    binding = types.SimpleNamespace(
        # This fixture represents both the public VM window and the fixed
        # internal render window used by the source-built opening graph.  The
        # cold hook verifies every resolved address against the real UAT before
        # publication; limiting this synthetic binding to the public 39-bit VM
        # rejects the valid 0x100... internal scissor/resource addresses before
        # that stronger check can run.
        addr=0,
        end=1 << 48,
        flags=DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE,
    )
    queue = types.SimpleNamespace(
        vm=types.SimpleNamespace(bindings=[binding]),
        usc_exec_base=USC_EXEC_BASE,
        token=None,
    )
    return G17PModernDriver(None)._resolve_render_hardware_state(
        queue, command)


def _translate_parameters():
    """Adapt the validated DRM command into the production register recipe."""
    command = _validated_drm_command()
    payload = command.payload
    state = command.hardware_state
    g17p_shim.G17P_LOAD_PIPELINE_BIND_PREFIX = 0xFFFF800000000000
    drm = types.SimpleNamespace(
        fb_width=state.width,
        fb_height=state.height,
        store_pipeline_bind=state.eot_rsrc_spec,
        load_pipeline_bind=state.bg_rsrc_spec,
        scissor_array=state.scissor_base,
        depth_bias_array=state.dbias_base,
        encoder_ptr=state.vdm_base,
        ppp_multisamplectl=state.multisample_control,
        ppp_ctrl=state.ppp_control,
        iogpu_unk_49=state.blocks_per_utile,
        samples=state.samples,
        sample_size=state.sample_size,
        layers=state.layers,
        utile_width=state.utile_width,
        utile_height=state.utile_height,
        utile_config=state.utile_config,
        tile_config=state.tile_config,
        occlusion_query_base=state.oclqry_base,
        isp_zls_pixels=int(payload.isp_zls_pixels),
        depth_buffer=state.depth_base,
        depth_aux_buffer=state.depth_comp_base,
        depth_stride=state.depth_stride,
        depth_aux_stride=state.depth_comp_stride,
        stencil_buffer=state.stencil_base,
        stencil_aux_buffer=state.stencil_comp_base,
        stencil_stride=state.stencil_stride,
        stencil_aux_stride=state.stencil_comp_stride,
        ds_flags=state.zls_ctrl,
        depth_clear_value_bits=state.bgobjdepth,
        stencil_clear_value=state.bgobjvals,
        isp_merge_upper_x=state.merge_upper_x,
        isp_merge_upper_y=state.merge_upper_y,
        partial_reload_pipeline_bind=state.partial_bg_rsrc_spec,
        partial_reload_pipeline=state.partial_bg_usc,
        partial_store_pipeline_bind=state.partial_eot_rsrc_spec,
        partial_store_pipeline=state.partial_eot_usc,
        sampler_array=state.sampler_heap,
        sampler_count=state.sampler_count,
        process_empty_tiles=bool(
            state.flags & DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES),
        aux_fb_flags=0xC000,
        emit_uapi_fields=True,
        load_pipeline=state.bg_usc,
        store_pipeline=state.eot_usc,
        usc_exec_base=USC_EXEC_BASE,
    )
    adapted = g17p_shim.command_buffer_from_drm(
        drm,
        pipeline_base=USC_EXEC_BASE,
        deflake_1=DEFLAKE_1_DVA,
        deflake_2=DEFLAKE_2_DVA,
        deflake_3=DEFLAKE_3_DVA,
        aux_fb=AUX_FB_DVA,
        heapmeta=HEAPMETA_DVA,
        shared=None,
        pools=[],
        tiling_optional={},
        fragment_optional={},
    )

    names = {field.name for field in dataclasses.fields(
        g17p_render.G17PRenderParameters)}
    values = {
        name: getattr(adapted, name)
        for name in names
        if hasattr(adapted, name)
    }
    values.update(
        context_base=CONTEXT_BASE,
        tilemap=TILEMAP_DVA,
        heapmeta=HEAPMETA_DVA,
        tpc=TPC_DVA,
        encoder=ENCODER_DVA,
        ta_status=TA_STATUS_DVA,
        fragment_status=FRAGMENT_STATUS_DVA,
        aux_fb_page_count=0x100000,
    )
    parameters = g17p_render.G17PRenderParameters(**values)
    print(
        "G17P PARTIAL OPENING translated load=(%#x,%#x) store=(%#x,%#x) "
        "partial-load=(%#x,%#x) partial-store=(%#x,%#x) TIB=%d" % (
            parameters.load_pipeline_bind,
            parameters.load_pipeline,
            parameters.store_pipeline_bind,
            parameters.store_pipeline,
            parameters.partial_load_pipeline_bind,
            parameters.partial_load_pipeline,
            parameters.partial_store_pipeline_bind,
            parameters.partial_store_pipeline,
            parameters.tib_blocks,
        ),
        flush=True,
    )
    return parameters


def _opening_hook(render_state, arena, uat, _capture):
    parameters = _translate_parameters()
    extent = render_state["extent"]

    def mapped_page(address, name):
        page = address & ~(PAGE - 1)
        pa = extent["mapped"].get(page)
        if pa is None:
            _va, pa = arena.alloc_at(
                page, PAGE, name,
                flags=dict(boot.RENDER_PAGE_FLAGS, UXN=0),
            )
            extent["mapped"][page] = pa
        return page, pa

    def write_page(address, body, name):
        if len(body) > PAGE or address & (PAGE - 1):
            raise RuntimeError("%s does not fit one aligned caller page" % name)
        body = (bytes(body) + bytes(PAGE))[:PAGE]
        page, pa = mapped_page(address, name)
        boot.iface.writemem(pa, body)
        boot.p.dc_civac(pa, PAGE)
        extent["heads"][page] = body[:32]
        record = next(
            (entry for entry in render_state["pages"]
             if entry["va"] == page),
            None,
        )
        if record is not None:
            record.update(
                body=body,
                nonzero=sum(byte != 0 for byte in body),
                source="caller-generated",
            )

    # The six generated partial-control pages stay zero through opening opcode
    # 0x20 and are published at the later control-0x84 -> work-0x83 boundary.
    # Keep this exact render state so that transition can update both memory
    # and the pre-work witness baseline without consulting captured content.
    PARTIAL_RENDER_STATE[0] = render_state

    # This generic bootstrap attachment descriptor is absent from the clean
    # first-partial graph.  Keep its render-root page independent and blank.
    write_page(
        0x10000020000, bytes(PAGE), "partial_external_attachment_blank")

    # These four low client pages are caller-owned state.  The encoder and
    # viewport are generated; the draw and bind pages are opaque compiler
    # payload from the same own-source workload as the high USC/resource pages.
    bind0 = bytearray(g17p_render.build_direct_bind0())
    struct.pack_into("<Q", bind0, 0x40, 0x2010040000)
    write_page(CONTEXT_BASE, bytes(bind0), "partial_bind0")
    write_page(ENCODER_DVA, exact_encoder(), "partial_encoder")
    write_page(
        VIEWPORT_DVA,
        g17p_render.build_viewport(parameters.width, parameters.height),
        "partial_viewport",
    )
    for address, body in load_deferred_pages(PAYLOAD).items():
        write_page(address, body, "partial_deferred_%x" % address)

    # Verify that every opaque high caller/compiler page loaded by the generic
    # manifest path is byte exact before it can become live command input.
    manifest = __import__("json").loads(PAYLOAD.read_text())
    payload_pages = {}
    for entry in manifest.get("entries", ()):
        address = int(entry["va"])
        body = (PAYLOAD.parent / entry["path"]).read_bytes()
        payload_pages[address] = body
        page, pa = mapped_page(address, "partial_payload_%x" % address)
        boot.p.dc_civac(pa, PAGE)
        if bytes(boot.iface.readmem(pa, PAGE)) != body:
            raise RuntimeError("partial caller page %#x is not exact" % page)

    # Dependency-slicing control: retain every mapping and permission but
    # replace selected own-workload payload contents with fresh zeroes.  This
    # distinguishes a content dependency from an address/topology dependency.
    # It is intentionally confined to the experiment harness and accepts only
    # pages present in the checksummed caller manifest.
    zero_pages = parse_page_selector(
        os.environ.get("G17P_PARTIAL_ZERO_PAYLOAD_PAGES", ""),
        payload_pages,
        PAGE,
    )
    for address in sorted(zero_pages):
        write_page(address, bytes(PAGE), "partial_payload_zero_%x" % address)
    if zero_pages:
        print(
            "G17P PARTIAL OPENING zeroed %d mapped caller payload pages: %s" % (
                len(zero_pages),
                ",".join("%#x" % address for address in sorted(zero_pages)),
            ),
            flush=True,
        )

    negative = os.environ.get("G17P_PARTIAL_RESOURCE_NEGATIVE") == "1"
    resource_page, resource_pa = mapped_page(
        RESOURCE_DVA, "partial_resource")
    boot.p.dc_civac(resource_pa, PAGE)
    resource = bytearray(boot.iface.readmem(resource_pa, PAGE))
    if negative:
        before = bytes(resource)
        resource[0x000:0x300] = resource[0x300:0x600]
        changed = sum(a != b for a, b in zip(before, resource))
        if changed != 5:
            raise RuntimeError(
                "partial semantic negative changed %d bytes" % changed)
        boot.iface.writemem(resource_pa, resource)
        boot.p.dc_civac(resource_pa, PAGE)
        extent["heads"][resource_page] = bytes(resource[:32])
        print(
            "G17P PARTIAL OPENING RESOURCE NEGATIVE "
            "reload+0x0 <- clear+0x300 changed=5",
            flush=True,
        )

    # Clear and record every byte of all eight output ranges before any work is
    # published.  These records make the boot's normal exact-page witness cover
    # the entire 512 KiB result, not only a maximum or an extent-page head.
    for attachment, base in enumerate(OUTPUT_DVAS):
        for page_index, address in enumerate(
                range(base, base + OUTPUT_SIZE, PAGE)):
            page, pa = mapped_page(
                address,
                "partial_output_%d_%d" % (attachment, page_index),
            )
            # The no-argument Mesa integration delays firmware bring-up until
            # its first validated render submit. Give that submit's real GEM
            # page to the proven first-partial command before the page is
            # cleared or either work producer becomes visible. The accumulated
            # R32F witness lives in page one of attachment zero.
            integration_bo = INTEGRATION_OUTPUT_BO[0]
            if (integration_bo is not None
                    and attachment == 0 and page_index == 1):
                if int(integration_bo.size) != PAGE:
                    raise RuntimeError(
                        "source-partial integration output must be one page")
                token = integration_bo.token
                if token.get("pa") not in (None, pa):
                    raise RuntimeError(
                        "source-partial integration BO already has backing")
                token["pa"] = pa
                token["alloc_size"] = PAGE
                print(
                    "G17P SOURCE PARTIAL INTEGRATION assigned caller GEM "
                    "page to attachment 0 page 1 at PA %#x" % pa,
                    flush=True,
                )
            boot.p.memset32(pa, 0, PAGE)
            boot.p.dc_civac(pa, PAGE)
            extent["heads"][page] = bytes(32)
            render_state["pages"].append({
                "name": "partial_output_%d_%d" % (
                    attachment, page_index),
                "va": page,
                "pa": pa,
                "source": "zero-output",
                "uxn": 1,
                "body": bytes(PAGE),
                "nonzero": 0,
            })

    register_overrides = {
        "tiling": {
            0x0A5A1: 0x000000E900400020,
            0x1CA10: 0x000000C4010000E8,
            0x014A1: 0x000000C4010000E8,
            0x0A349: 0x000000C4010000E8,
            0x14308: 0,
        },
        "fragment": {
            0x0A5A9: 0x000000ED00400020,
            0x160E0: 0x000000C4010000E7,
            0x01499: 0x000000C4010000E7,
            0x0A341: 0x000000C4010000E7,
            0x14048: 0,
        },
    }

    def native_first_partial_registers(kind, registers):
        overrides = register_overrides[kind]
        return [
            (number, overrides.get(number, value))
            for number, value in registers
        ]

    boot.RENDER_PARAMETERS.clear()
    boot.RENDER_PARAMETERS.update(dataclasses.asdict(parameters))
    render_state.update(
        parameters=parameters,
        registers={
            "tiling": native_first_partial_registers(
                "tiling", g17p_render.build_tiling_registers(parameters)),
            "fragment": native_first_partial_registers(
                "fragment", g17p_render.build_fragment_registers(parameters)),
        },
    )
    print(
        "G17P PARTIAL OPENING built exact first-partial register tails",
        flush=True,
    )
    uat.flush_dirty()
    print(
        "G17P PARTIAL OPENING installed the complete UAPI-derived first group",
        flush=True,
    )
    return render_state


def _publish_render_pages(prepared, pages):
    """Publish generated render-root pages and retain their audited bodies."""
    render_state = PARTIAL_RENDER_STATE[0]
    if render_state is None:
        raise RuntimeError("partial render state was not retained")
    extent = render_state["extent"]
    for address, body in sorted(pages.items()):
        pa = extent["mapped"].get(address)
        if pa is None:
            raise RuntimeError(
                "partial render-control page %#x is not mapped" % address)
        boot.iface.writemem(pa, body)
        boot.p.dc_civac(pa, PAGE)
        extent["heads"][address] = body[:32]
        render_state["bodies"][address] = body
        render_state["seeded_vas"].add(address)
    boot.u.inst("dsb sy")


def _publish_partial_primary_index(prepared):
    """Publish the primary index before first work, as the clean oracle does."""
    if PARTIAL_PRIMARY_INDEX_PUBLISHED[0]:
        return
    primary_index = (
        g17p_submission.build_context2_submission_leaf_pages()["primary_index"]
    )
    _publish_render_pages(prepared, {0x1000190000: primary_index})
    PARTIAL_PRIMARY_INDEX_PUBLISHED[0] = True
    print(
        "G17P PARTIAL OPENING published primary index before first work",
        flush=True,
    )


def _publish_partial_render_control_state(prepared):
    """Publish the generated operand directory after opening control."""
    if PARTIAL_RENDER_CONTROL_PUBLISHED[0]:
        return
    directory = g17p_submission.build_partial_operand_page_directory(
        boot.CONTROL_OPERAND_BUFFER_BASE,
        boot.PARTIAL_CONTROL_OPERAND_ENTRIES,
    )
    pages = {
        0x7000000000 + offset: directory[offset:offset + PAGE]
        for offset in range(0, len(directory), PAGE)
    }
    pages[0x7000208000] = g17p_submission.build_partial_operand_table(
        boot.CONTROL_OPERAND_BUFFER_BASE,
        boot.PARTIAL_CONTROL_OPERAND_ENTRIES,
    )
    _publish_render_pages(prepared, pages)
    PARTIAL_RENDER_CONTROL_PUBLISHED[0] = True
    print(
        "G17P PARTIAL OPENING published 28-entry render control in the "
        "post-control/pre-work interval",
        flush=True,
    )


def _read_outputs(state):
    mapping = {
        int(address, 16): int(pa, 16)
        for address, pa in state["attach"]["render_extent"].items()
    }
    outputs = []
    for base in OUTPUT_DVAS:
        body = bytearray()
        for address in range(base, base + OUTPUT_SIZE, PAGE):
            pa = mapping[address]
            boot.p.dc_civac(pa, PAGE)
            body.extend(boot.iface.readmem(pa, PAGE))
        outputs.append(bytes(body))
    return tuple(outputs)


def _validate_complete_outputs(outputs, negative):
    expected_offsets = {32508, 32512}
    values = []
    for attachment, body in enumerate(outputs):
        nonzero_words = {
            offset for offset in range(0, len(body), 4)
            if body[offset:offset + 4] != b"\0\0\0\0"
        }
        incidental = nonzero_words - expected_offsets
        # On some otherwise-identical boots the accelerator leaves exactly
        # equal small-u32 words in attachment zero.  Their observed values
        # (608 and 746), base offsets, and column count vary with partial work,
        # but their layout is stable: four identical rows at stride 0x200,
        # with aligned columns confined to the first 0x100 bytes.  As floats
        # they are subnormal metadata, not the fragment shader's finite
        # accumulated values.  Validate that complete measured shape rather
        # than accepting arbitrary nonzero padding.
        incidental_values = {
            offset: struct.unpack_from("<I", body, offset)[0]
            for offset in incidental
        }
        marker_shape = False
        marker_value = None
        if attachment == 0 and incidental:
            marker_base = min(incidental)
            marker_columns = {
                offset - marker_base
                for offset in incidental
                if offset < marker_base + 0x200
            }
            marker_offsets = {
                marker_base + row * 0x200 + column
                for row in range(4)
                for column in marker_columns
            }
            marker_values = set(incidental_values.values())
            marker_shape = (
                incidental == marker_offsets
                and marker_columns
                and all(column % 4 == 0 and column < 0x100
                        for column in marker_columns)
                and len(marker_values) == 1
                and 0 < next(iter(marker_values)) <= TRIANGLE_COUNT
            )
            if marker_shape:
                marker_value = next(iter(marker_values))
        if (expected_offsets - nonzero_words
                or (incidental and not marker_shape)):
            raise RuntimeError(
                "attachment %d changed words %r (incidental %r), expected "
                "%r plus only the structured attachment-zero marker" % (
                    attachment, sorted(nonzero_words), incidental_values,
                    sorted(expected_offsets),
                ))
        if incidental:
            print(
                "G17P PARTIAL attachment-zero metadata marker u32=%d: %s" % (
                    marker_value,
                    ",".join("%#x" % offset
                             for offset in sorted(incidental)),
                ),
                flush=True,
            )
        first, second = (
            struct.unpack_from("<f", body, offset)[0]
            for offset in sorted(expected_offsets)
        )
        expected = attachment + 1
        if negative:
            finite = [value for value in (first, second)
                      if math.isfinite(value)]
            if (not finite
                    or not all(0 < value < 0.01 * expected
                               for value in finite)
                    or any(math.isfinite(value) is False and not math.isnan(value)
                           for value in (first, second))):
                raise RuntimeError(
                    "attachment %d retained more than the final segment: "
                    "%r/%r" % (attachment, first, second))
        else:
            correct = [value for value in (first, second)
                       if math.isfinite(value)
                       and abs(value - expected) <= 0.02]
            invalid = [value for value in (first, second)
                       if math.isfinite(value)
                       and abs(value - expected) > 0.02]
            if not correct or invalid:
                raise RuntimeError(
                    "attachment %d lost partial accumulation: %r/%r" % (
                        attachment, first, second))
        values.append(max(
            value for value in (first, second) if math.isfinite(value)))
    print(
        "G17P PARTIAL OPENING COMPLETE OUTPUT PASS: %s" %
        ", ".join("%.9f" % value for value in values),
        flush=True,
    )
    return tuple(values)


def main(return_state=False, integration_output_bo=None):
    if not return_state and len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_render_uapi_partial_opening.py accepts no arguments")
    INTEGRATION_OUTPUT_BO[0] = integration_output_bo
    boot.OPENING_RENDER_STATE_HOOK[0] = _opening_hook
    boot.FINAL_26_6_PRE_0X84_AUDIT = _publish_native_pre_0x84_status
    boot.FINAL_26_6_FIRST_WORK_AUDIT = _audit_clean_first_work
    boot.FINAL_26_6_FIRST_WORK_EARLY_STATE = _enter_clean_early_3d_state
    opening_pair = int(os.environ.get("G17P_PARTIAL_OPENING_PAIR", "2"), 0)
    if opening_pair not in range(4):
        raise RuntimeError("partial opening pair must be within 0..3")
    print(
        "G17P PARTIAL OPENING using transport pair %d, descriptor pair 0" %
        opening_pair,
        flush=True,
    )
    args = [
        "--timeout", "20", "--read-crash", "--no-registers",
        "--build-dispatch", "--build-records", "--publish-after-control",
        "--no-announce",
        "--first-channel-pair", str(opening_pair),
        "--first-descriptor-pair", "0",
        "--opening", "done",
        "--macos-context-table", "--split-context", "never",
        "--graft", "none", "--no-seed", "all",
        "--require-zero-capture-pages", "--full-render-extent",
        "--fast-render-witness", "--no-first-doorbell",
        "--skip-input-completeness", "--skip-leaf-audit",
        "--render-payload-manifest", str(PAYLOAD),
    ]
    state = boot.main(args, return_state=True)
    negative = os.environ.get("G17P_PARTIAL_RESOURCE_NEGATIVE") == "1"
    deadline = time.monotonic() + 20.0
    last_error = None
    while True:
        try:
            _validate_complete_outputs(_read_outputs(state), negative)
            break
        except RuntimeError as exc:
            last_error = exc
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "partial output did not complete within 20 seconds: %s" %
                last_error)
        for asc in state["ascs"]:
            try:
                # Never drain to empty here: firmware event 0x42 can remain
                # continuously asserted in a healthy world.  Servicing at
                # most one message preserves crash visibility without
                # starving the output poll or its deadline.
                if asc.has_messages():
                    asc.work()
            except Exception:
                # Preserve the output validator as the primary result.  A
                # firmware crash is also printed and captured by its endpoint.
                pass
        time.sleep(0.05)
    print(
        "G17P PARTIAL SOURCE PASS: triangles=%d" % TRIANGLE_COUNT,
        flush=True,
    )
    return state if return_state else 0


if __name__ == "__main__":
    raise SystemExit(main())
