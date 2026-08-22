#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit the verified G17P render through the packed legacy DRM-shim UAPI.

Run this after ``agx_g17p_boot.py`` starts firmware without ringing the first
work doorbell. It intentionally enters through ``DRMAsahiShim.submit`` rather
than calling the G17P backend directly.
"""

import ctypes
import argparse
import collections
import errno
import hashlib
import json
import os
import pathlib
import re
import struct
import sys
import tempfile
import time
import types

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

# This experiment is T8140-only. UAT fixes its L0 split when imported, before
# the live ADT is opened by DRMAsahiShim.init(), so select the known generation
# before importing the AGX package. The embedded C shim uses g17p_shim_entry,
# which instead derives the same value from the live ADT.
os.environ.setdefault("AGX_GPU", "G17")

from m1n1.agx.g17p_shim import (                            # noqa: E402
    G17P_LOAD_PIPELINE_BIND_PREFIX,
    G17PUnsupported,
    command_buffer_from_drm,
    uncompressed_twiddled_size,
)
from m1n1.agx.shim import DRMAsahiShim                          # noqa: E402
from m1n1.agx.uapi import drm_asahi_cmdbuf_t                    # noqa: E402


ARTIFACTS = pathlib.Path(os.environ.get(
    "G17P_ARTIFACTS",
    os.path.expanduser("~/asahi_re/artifacts/agx_g17p")))

PAGE = 0x4000
KNOWN_TARGET = 0x10000088000
KNOWN_TARGET_EXTENT = 0x185c000
KNOWN_TARGET_DESCRIPTOR_SITES = (
    0x10000020220,
    0x10001970620,
    0x100019708e0,
)
KNOWN_ATTACHMENT = 0x10001970000
KNOWN_PIPELINE_PAGE = 0x10001990000
KNOWN_PIPELINE_PAGE_RELATIVE = KNOWN_PIPELINE_PAGE & 0xffffffff
LINEAR_ATTACHMENT_TEMPLATE = pathlib.Path(
    "~/asahi_re/public/agx-re/experiments/EXP-G1b-pbe-rt-descriptor/"
    "raw/rt_base.hex").expanduser()


def packed_cmdbuf(width=2408, height=1506,
                  load_pipeline=0x01990240, load_pipeline_bind=0x40,
                  store_pipeline=0x01990640, store_pipeline_bind=0,
                  color_attachment=None):
    attachment = color_attachment or {"type": 0, "size": 0, "pointer": 0}
    return drm_asahi_cmdbuf_t.subcon.build({
        "flags": 0,
        "encoder_ptr": 0x1000018000,
        "encoder_id": 0,
        "cmd_ta_id": 0,
        "cmd_3d_id": 0,
        "ds_flags": 0,
        "depth_buffer": 0,
        "stencil_buffer": 0,
        "scissor_array": 0x100019a0000,
        "depth_bias_array": 0x10001af8000,
        "fb_width": width,
        "fb_height": height,
        "load_pipeline": load_pipeline,
        "load_pipeline_bind": load_pipeline_bind,
        "store_pipeline": store_pipeline,
        "store_pipeline_bind": store_pipeline_bind,
        "partial_reload_pipeline": 0,
        "partial_reload_pipeline_bind": 0,
        "partial_store_pipeline": 0,
        "partial_store_pipeline_bind": 0,
        "depth_clear_value": 0.0,
        "stencil_clear_value": 0,
        "attachments": [attachment.copy() for _ in range(16)],
        "attachment_count": int(color_attachment is not None),
    })


def u32_override(text):
    try:
        offset_text, value_text = text.split("=", 1)
        offset = int(offset_text, 0)
        value = int(value_text, 0)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(
            "expected OFFSET=VALUE, with each value accepted by int(..., 0)")
    if offset < 0 or offset > 0x3ffc or offset & 3:
        raise argparse.ArgumentTypeError(
            "encoder offset must be a 32-bit-aligned value in 0..0x3ffc")
    if value < 0 or value > 0xffffffff:
        raise argparse.ArgumentTypeError("encoder value must fit in 32 bits")
    return offset, value


def newest_render_extent():
    newest = None
    for path in sorted(ARTIFACTS.glob("boot_*/boot.json")):
        try:
            attach = json.loads(path.read_text()).get("attach") or {}
        except (OSError, ValueError):
            continue
        if attach.get("render_extent"):
            newest = {
                int(address, 0): int(pa, 0)
                for address, pa in attach["render_extent"].items()
            }
    return newest or {}


def patch_native_b1_completion(backend, submission):
    """Reproduce the native post-B1 scheduler state for one causal experiment.

    B1 can physically render while its generated scheduler node remains linked.
    The native third-doorbell snapshot captures the same objects after B1 has
    fully completed. Applying those exact first-item completion fields tests
    whether stale prior-work state, rather than A2's descriptor, is the gate.
    """
    items = submission.get("items") if submission is not None else None
    if not items:
        raise RuntimeError("native B1 completion patch needs the published item graph")
    if submission.get("item_index") != 0 or submission.get("submission_ordinal") != 1:
        raise RuntimeError(
            "native B1 completion patch only describes global ordinal 1 / pair item 0")

    def read64(address):
        return struct.unpack("<Q", backend._read_dva(address, 8))[0]

    tiling = items["tiling"][0]
    pool_a = read64(tiling + 0x10)
    shared = read64(tiling + 0x20)
    pool_b = read64(tiling + 0x28)
    writes = {
        pool_a + 0x0c: 0x00000002,
        pool_a + 0x24: 0x00000001,
        pool_a + 0x94: 0x00000000,
        pool_a + 0xa8: 0x01000126,
        pool_a + 0xb0: 0x01000125,
        pool_a + 0xc0: 0x00000001,
        pool_b + 0x10: 0x00000013,
        pool_b + 0x48: 0x00000013,
        shared + 0x00: 0x00000001,
        shared + 0x04: 0x00000001,
        shared + 0x0c: 0xffffffff,
        shared + 0x14: 0x00000001,
    }
    print("EXPERIMENT: applying native post-B1 pool/progress completion state", flush=True)
    for address, value in writes.items():
        old = struct.unpack("<I", backend._read_dva(address, 4))[0]
        backend._write_dva(address, struct.pack("<I", value))
        print("  %#x: %#010x -> %#010x" % (address, old, value), flush=True)

    job_lists = {
        submission[kind]["queue"].job_list_addr
        for kind in ("tiling", "fragment")
    }
    for address in job_lists:
        old = struct.unpack("<3Q", backend._read_dva(address, 0x18))
        backend._write_dva(address, struct.pack("<3Q", 0, address, 0))
        print("  job list %#x: %s -> empty" % (address, old), flush=True)


def force_empty_executed_job_list(backend, submission):
    """Test the native empty-list precondition after physical execution."""
    addresses = {
        submission[kind]["queue"].job_list_addr
        for kind in ("tiling", "fragment")
    }
    for address in addresses:
        old = struct.unpack("<3Q", backend._read_dva(address, 0x18))
        backend._write_dva(address, struct.pack("<3Q", 0, address, 0))
        check = struct.unpack("<3Q", backend._read_dva(address, 0x18))
        if check != (0, address, 0):
            raise RuntimeError("forced-empty job list %#x did not read back" % address)
        print("EXPERIMENT: physically executed job list %#x: %s -> empty" %
              (address, old), flush=True)


def render_pages(backend, extent, invalidate_only=False):
    pages = {}
    unreadable = 0
    for path in sorted((ARTIFACTS / "render_after").glob("*.bin")):
        address = int(path.stem, 16)
        size = path.stat().st_size
        pa = extent.get(address)
        if pa is None:
            continue
        try:
            cacheop = (backend.u.proxy.dc_ivac if invalidate_only
                       else backend.u.proxy.dc_civac)
            cacheop(pa, size)
            pages[address] = bytes(backend.u.iface.readmem(pa, size))
        except Exception as error:  # noqa: BLE001
            unreadable += 1
            if unreadable <= 8:
                print("render page %#x unreadable: %s" %
                      (address, error), flush=True)
    if unreadable:
        print("%d render witness pages unreadable" % unreadable, flush=True)
    return pages


def changed_pages(before, after):
    return sum(before.get(address) != data for address, data in after.items())


def matching_reference(after):
    references = {
        int(path.stem, 16): path
        for path in (ARTIFACTS / "render_after").glob("*.bin")
    }
    matches = 0
    compared = 0
    for address, data in after.items():
        path = references.get(address)
        if path is None:
            continue
        compared += 1
        matches += data == path.read_bytes()
    return matches, compared


def differing_runs(before, after):
    runs = []
    start = None
    for offset, (left, right) in enumerate(zip(before, after)):
        if left != right and start is None:
            start = offset
        if left == right and start is not None:
            runs.append((start, offset))
            start = None
    if start is not None:
        runs.append((start, min(len(before), len(after))))
    return runs


def linear_bgra8_pbe(target, width, height):
    """Pack the hardware-verified linear BGRA8 PBE fields."""
    if width <= 0 or width > 0x4000 or height <= 0 or height > 0x4000:
        raise ValueError("linear PBE dimensions must fit the 14-bit fields")
    stride = (width * 4 + 0xff) & ~0xff
    encoded = target >> 4
    width_m1 = width - 1
    height_m1 = height - 1
    return (
        ((width_m1 & 0xff) << 24) | 0x00c60a02,
        (height_m1 << 6) | (width_m1 >> 8),
        encoded & 0xffffffff,
        (((stride // 16) - 1) << 12) | ((encoded >> 32) & 0xfff),
        0,
        0,
    ), stride


def read_bodump(path):
    """Read a clean-room address-prefixed hexadecimal BO capture."""
    lines = path.read_text().splitlines()
    if not lines:
        raise ValueError("empty BODUMP %s" % path)
    header = re.search(
        r"gpu_va=0x([0-9a-fA-F]+).*read=0x([0-9a-fA-F]+)", lines[0])
    if header is None:
        raise ValueError("BODUMP has no GPU VA/read size: %s" % path)
    address = int(header.group(1), 16)
    data = bytearray(int(header.group(2), 16))
    for line in lines[1:]:
        match = re.match(r"^([0-9a-fA-F]+):\s*(.*)$", line)
        if match is None:
            continue
        offset = int(match.group(1), 16)
        payload = b"".join(bytes.fromhex(word)
                           for word in match.group(2).split())
        if offset + len(payload) > len(data):
            raise ValueError("BODUMP line exceeds read size at %#x" % offset)
        data[offset:offset + len(payload)] = payload
    return address, data


def linear_bgra8_texture(target, width, height):
    """Pack the matching LOAD/RENDER texture-style descriptor."""
    stride = (width * 4 + 0xff) & ~0xff
    encoded = target >> 4
    width_m1 = width - 1
    height_m1 = height - 1
    return (
        0x060a0a02 | ((width_m1 & 0xf) << 28),
        (height_m1 << 10) | (width_m1 >> 4),
        encoded & 0xffffffff,
        (((stride // 16) - 1) << 14) | ((encoded >> 32) & 0xfff),
        0,
        0,
        0,
        0,
    ), stride


def install_linear_attachment(backend, extent, target, width, height,
                              template=LINEAR_ATTACHMENT_TEMPLATE):
    """Replace the retained attachment with a complete linear BGRA8 one."""
    source, data = read_bodump(template)
    destination = KNOWN_ATTACHMENT
    if len(data) > PAGE:
        raise ValueError("attachment template exceeds one GPU page")

    # The template's only full pointers are links within its three-segment object.
    # Rebase those links while leaving all non-pointer state byte-for-byte intact.
    for offset in range(0, len(data) - 7, 8):
        value = struct.unpack_from("<Q", data, offset)[0]
        if source <= value < source + len(data):
            struct.pack_into("<Q", data, offset,
                             destination + (value - source))

    texture, stride = linear_bgra8_texture(target, width, height)
    pbe, pbe_stride = linear_bgra8_pbe(target, width, height)
    if stride != pbe_stride:
        raise AssertionError("texture and PBE stride disagree")
    for offset in (0x20, 0x320):
        struct.pack_into("<8I", data, offset, *texture)
    struct.pack_into("<6I", data, 0x620, *pbe)

    # STORE metadata repeats the context-relative surface address three times.
    target_low = target & 0xffffffff
    for offset in (0x8c8, 0x8cc, 0x8d8):
        struct.pack_into("<I", data, offset, target_low)

    page = destination & ~(PAGE - 1)
    page_pa = extent.get(page)
    if page_pa is None:
        raise RuntimeError("no recorded physical page for attachment %#x" % destination)
    backend.u.proxy.dc_civac(page_pa, PAGE)
    attachment_pa = page_pa + (destination - page)
    backend.u.iface.writemem(attachment_pa, bytes(data))
    backend.u.proxy.dc_civac(page_pa, PAGE)
    check = backend.u.iface.readmem(attachment_pa, len(data))
    if check != data:
        raise RuntimeError("linear attachment did not read back")
    print("Installed complete linear BGRA8 attachment at %#x: %dx%d "
          "target=%#x stride=%#x template=%s" %
          (destination, width, height, target, stride, template), flush=True)


def uncompress_target_descriptor(words, target):
    """Rebase one texture/PBE descriptor and remove its compression metadata."""
    encoded = target >> 4
    words = list(words)
    words[1] &= ~(1 << 27)
    words[2] = encoded & 0xffffffff
    words[3] = (words[3] & ~((1 << 31) | 0xfff)) | ((encoded >> 32) & 0xfff)
    words[4] = 0
    words[5] &= ~0xfff
    return words


def install_twiddled_uncompressed_attachment(backend, extent, target):
    """Rebase every live target descriptor and disable lossless compression."""
    page = KNOWN_ATTACHMENT & ~(PAGE - 1)
    page_pa = extent.get(page)
    if page_pa is None:
        raise RuntimeError("no recorded physical page for attachment %#x" % page)

    backend.u.proxy.dc_civac(page_pa, PAGE)
    data = bytearray(backend.u.iface.readmem(page_pa, PAGE))
    changed = []

    # Texture-style and PBE records share the base and compression fields. Touch
    # only aligned records which name either the retained or relocated surface.
    for offset in range(0, PAGE - 0x20 + 1, 0x10):
        words = list(struct.unpack_from("<8I", data, offset))
        old_target = (((words[3] & 0xfff) << 32) | words[2]) << 4
        if old_target not in (KNOWN_TARGET, target):
            continue
        old_words = tuple(words)
        words = uncompress_target_descriptor(words, target)
        struct.pack_into("<8I", data, offset, *words)
        changed.append((KNOWN_ATTACHMENT + offset, old_target,
                        old_words, tuple(words)))

    if not changed:
        raise RuntimeError("retained attachment contains no descriptors for %#x" %
                           KNOWN_TARGET)

    old_low = KNOWN_TARGET & 0xffffffff
    new_low = target & 0xffffffff
    repeated = 0
    for offset in range(0, PAGE - 3, 4):
        if struct.unpack_from("<I", data, offset)[0] != old_low:
            continue
        struct.pack_into("<I", data, offset, new_low)
        repeated += 1

    backend.u.iface.writemem(page_pa, data)
    backend.u.proxy.dc_civac(page_pa, PAGE)
    check = backend.u.iface.readmem(page_pa, PAGE)
    if check != data:
        raise RuntimeError("twiddled uncompressed attachment did not read back")

    # A third STORE PBE sits outside the attachment page. The regular redirect
    # changes its base first, so it must be cleared explicitly as well.
    external = KNOWN_TARGET_DESCRIPTOR_SITES[0]
    external_page = external & ~(PAGE - 1)
    external_pa = extent.get(external_page)
    if external_pa is None:
        raise RuntimeError("no recorded physical page for PBE descriptor at %#x" % external)
    backend.u.proxy.dc_civac(external_pa, PAGE)
    descriptor_pa = external_pa + (external - external_page)
    old_words = tuple(struct.unpack(
        "<8I", backend.u.iface.readmem(descriptor_pa, 32)))
    old_target = (((old_words[3] & 0xfff) << 32) | old_words[2]) << 4
    if old_target not in (KNOWN_TARGET, target):
        raise RuntimeError("external PBE at %#x names unexpected target %#x" %
                           (external, old_target))
    words = uncompress_target_descriptor(old_words, target)
    backend.u.iface.writemem(descriptor_pa, struct.pack("<8I", *words))
    backend.u.proxy.dc_civac(external_pa, PAGE)
    check = tuple(struct.unpack(
        "<8I", backend.u.iface.readmem(descriptor_pa, 32)))
    if check != tuple(words):
        raise RuntimeError("external uncompressed PBE did not read back")
    changed.append((external, old_target, old_words, tuple(words)))

    for address, old_target, old_words, words in changed:
        print("Descriptor %#x: target %#x -> %#x, compression/aux cleared; "
              "words %s -> %s" %
              (address, old_target, target,
               " ".join("%08x" % word for word in old_words[:6]),
               " ".join("%08x" % word for word in words[:6])), flush=True)
    print("Installed twiddled uncompressed target state at %#x: %d descriptors, "
          "%d repeated target words" %
          (KNOWN_ATTACHMENT, len(changed), repeated), flush=True)


def install_pipeline_page(backend, extent, path, load_pipeline, store_pipeline):
    """Replace the retained A18 pipeline arena and verify both selected programs."""
    data = path.read_bytes()
    if len(data) != PAGE:
        raise ValueError("pipeline page must be exactly %#x bytes: %s is %#x" %
                         (PAGE, path, len(data)))
    for name, address in (("load", load_pipeline), ("store", store_pipeline)):
        if not KNOWN_PIPELINE_PAGE_RELATIVE <= address < KNOWN_PIPELINE_PAGE_RELATIVE + PAGE:
            raise ValueError(
                "%s pipeline %#x is outside retained page %#x..%#x" %
                (name, address, KNOWN_PIPELINE_PAGE_RELATIVE,
                 KNOWN_PIPELINE_PAGE_RELATIVE + PAGE))
        if address & 3:
            raise ValueError("%s pipeline %#x is not 32-bit aligned" % (name, address))

    pa = extent.get(KNOWN_PIPELINE_PAGE)
    if pa is None:
        raise RuntimeError("no recorded physical page for pipeline arena %#x" %
                           KNOWN_PIPELINE_PAGE)
    backend.u.proxy.dc_civac(pa, PAGE)
    backend.u.iface.writemem(pa, data)
    backend.u.proxy.dc_civac(pa, PAGE)
    check = backend.u.iface.readmem(pa, PAGE)
    if check != data:
        raise RuntimeError("pipeline page did not read back")
    print("Installed A18 pipeline page at %#x: sha256=%s nonzero=%d "
          "load=%#x store=%#x source=%s" %
          (KNOWN_PIPELINE_PAGE, hashlib.sha256(data).hexdigest(),
           sum(byte != 0 for byte in data), load_pipeline, store_pipeline, path),
          flush=True)


def redirect_known_target(backend, target, extent, linear=False):
    """Redirect the captured pass's three PBE records to fresh backing."""
    if target & (PAGE - 1):
        raise RuntimeError("redirect target must be page aligned")

    target, target_pa = backend.space.alloc_at(
        target, KNOWN_TARGET_EXTENT, "redirected-render-target", UXN=1)
    backend.space.flush()
    backend.space.uat.invalidate_cache()
    if backend._read_dva(target, 4) != bytes(4):
        raise RuntimeError("redirect target does not read back through the live UAT")
    # The proxy's very large host-side writemem used by alloc_at is not a useful zeroing
    # witness. Do the initialization on target, then sample it before publishing any descriptor.
    backend.u.proxy.memset32(target_pa, 0, KNOWN_TARGET_EXTENT)
    before = sample_page_heads(
        backend, {"dva": target, "pa": target_pa, "size": KNOWN_TARGET_EXTENT})
    nonzero = [(index, page) for index, page in enumerate(before) if any(page)]
    if nonzero:
        detail = ", ".join("%#x:%s" % (index * PAGE, page.hex())
                           for index, page in nonzero[:8])
        raise RuntimeError(
            "target-side clear left %d nonzero sampled pages: %s"
            % (len(nonzero), detail))

    encoded = target >> 4
    for address in KNOWN_TARGET_DESCRIPTOR_SITES:
        page = address & ~(PAGE - 1)
        page_pa = extent.get(page)
        if page_pa is None:
            raise RuntimeError("no recorded physical page for PBE descriptor at %#x" % address)
        descriptor_pa = page_pa + (address - page)
        backend.u.proxy.dc_civac(page_pa, PAGE)
        body = bytearray(backend.u.iface.readmem(descriptor_pa, 24))
        words = list(struct.unpack("<6I", body))
        old_target = (((words[3] & 0xfff) << 32) | words[2]) << 4
        width = (((words[1] & 0x3f) << 8) | (words[0] >> 24)) + 1
        height = ((words[1] >> 6) & 0x3fff) + 1
        if old_target != KNOWN_TARGET or (width, height) != (2408, 1506):
            raise RuntimeError(
                "PBE descriptor at %#x is target %#x, %dx%d; expected %#x, 2408x1506"
                % (address, old_target, width, height, KNOWN_TARGET))
        if linear:
            words, stride = linear_bgra8_pbe(target, width, height)
            words = list(words)
        else:
            words[2] = encoded & 0xffffffff
            words[3] = (words[3] & ~0xfff) | ((encoded >> 32) & 0xfff)
        backend.u.iface.writemem(descriptor_pa, struct.pack("<6I", *words))
        backend.u.proxy.dc_civac(page_pa, PAGE)
        check = struct.unpack("<6I", backend.u.iface.readmem(descriptor_pa, 24))
        check_target = (((check[3] & 0xfff) << 32) | check[2]) << 4
        if check_target != target:
            raise RuntimeError(
                "PBE redirect at %#x read back target %#x, expected %#x"
                % (address, check_target, target))
        detail = " linear BGRA8 stride=%#x words=%s" % (
            stride, " ".join("%08x" % word for word in words)
        ) if linear else ""
        print("PBE descriptor %#x: target %#x -> %#x%s" %
              (address, old_target, target, detail), flush=True)

    return {"dva": target, "pa": target_pa, "size": KNOWN_TARGET_EXTENT}, before


def sample_page_heads(backend, region, head_size=32, invalidate_only=False):
    """Read enough of each target page to catch the established render witness."""
    pages = []
    for offset in range(0, region["size"], PAGE):
        pa = region["pa"] + offset
        # Clean CPU-produced input before dispatch, but only invalidate after GPU writes. Cleaning
        # a stale CPU line after dispatch can overwrite the very device output being measured.
        cacheop = (backend.u.proxy.dc_ivac if invalidate_only
                   else backend.u.proxy.dc_civac)
        cacheop(pa, PAGE)
        pages.append(bytes(backend.u.iface.readmem(pa, head_size)))
    return pages


def save_redirected_heads(region, before, after):
    output = ARTIFACTS / ("pbe_redirect_%s" % time.strftime("%Y%m%d_%H%M%S"))
    output.mkdir(parents=True, exist_ok=True)
    changed = []
    for index, (left, right) in enumerate(zip(before, after)):
        if left == right:
            continue
        dva = region["dva"] + index * PAGE
        name = "%016x.bin" % dva
        (output / name).write_bytes(right)
        changed.append({
            "offset": index * PAGE,
            "dva": dva,
            "before": left.hex(),
            "after": right.hex(),
            "file": name,
        })
    manifest = {
        "base": region["dva"],
        "size": region["size"],
        "page_size": PAGE,
        "sample_size": len(before[0]) if before else 0,
        "changed_pages": changed,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return output


def morton2d(x, y, bits=6):
    value = 0
    for bit in range(bits):
        value |= ((x >> bit) & 1) << (2 * bit)
        value |= ((y >> bit) & 1) << (2 * bit + 1)
    return value


def save_twiddled_bgra8(backend, region, width, height):
    """Save and detile one uncompressed 32-bit surface for offline inspection."""
    tile = 64
    cols = (width + tile - 1) // tile
    rows = (height + tile - 1) // tile
    raw_size = cols * rows * tile * tile * 4
    if raw_size > region["size"]:
        raise RuntimeError("padded surface exceeds redirected allocation")

    chunks = []
    for offset in range(0, raw_size, PAGE):
        pa = region["pa"] + offset
        backend.u.proxy.dc_ivac(pa, PAGE)
        chunks.append(bytes(backend.u.iface.readmem(pa, PAGE)))
    raw = b"".join(chunks)[:raw_size]

    linear = bytearray(width * height * 4)
    for y in range(height):
        tile_y = y // tile
        local_y = y & (tile - 1)
        for x in range(width):
            tile_x = x // tile
            local_x = x & (tile - 1)
            source = (((tile_y * cols + tile_x) * tile * tile +
                       morton2d(local_x, local_y)) * 4)
            destination = (y * width + x) * 4
            linear[destination:destination + 4] = raw[source:source + 4]

    output = ARTIFACTS / ("twiddled_readback_%s" %
                          time.strftime("%Y%m%d_%H%M%S"))
    output.mkdir(parents=True, exist_ok=True)
    raw_path = output / "surface.twiddled.bin"
    linear_path = output / "surface.detiled.bgra"
    raw_path.write_bytes(raw)
    linear_path.write_bytes(linear)

    pixels = collections.Counter(
        struct.unpack_from("<I", linear, offset)[0]
        for offset in range(0, len(linear), 4))
    manifest = {
        "base": region["dva"],
        "width": width,
        "height": height,
        "bytes_per_pixel": 4,
        "tile_width": tile,
        "tile_height": tile,
        "tile_columns": cols,
        "tile_rows": rows,
        "raw_size": len(raw),
        "linear_size": len(linear),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "linear_sha256": hashlib.sha256(linear).hexdigest(),
        "top_pixel_words": [
            {"value": "0x%08x" % value, "count": count}
            for value, count in pixels.most_common(16)
        ],
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return output, manifest


def instrument_submission(backend):
    """Save and compare exactly the queue items replaced by the shim."""
    output = ARTIFACTS / ("drm_shim_items_%s" %
                          time.strftime("%Y%m%d_%H%M%S"))
    output.mkdir(parents=True, exist_ok=True)
    strides = {"tiling": (0x9c0, 0xc0, 0x40),
               "fragment": (0x2240, 0xc0, 0x40)}
    references = {}
    for kind, queue_name in (("tiling", "TA_0"), ("fragment", "3D_0")):
        _entry, queue = backend.queue_for(queue_name)
        references[kind] = []
        for index, (address, size) in enumerate(zip(queue.items(), strides[kind])):
            data = backend._read_dva(address, size)
            references[kind].append((address, data))
            (output / ("%s_%d_before.bin" % (kind, index))).write_bytes(data)

    real_build = backend.build_submission

    def build(cmdbuf):
        result = real_build(cmdbuf)
        for kind in ("tiling", "fragment"):
            registers = dict(result[kind + "_registers"])
            selected = (0x15369, 0x15371, 0x15379, 0x15381,
                        0x15109, 0x1c880)
            print("%s selected registers: %s" %
                  (kind, ", ".join("%#x=%#x" % (number, registers[number])
                                   for number in selected if number in registers)),
                  flush=True)
        return result

    real_submit_pair = backend.submit_register_pair

    def submit_pair(*args, **kwargs):
        result = real_submit_pair(*args, **kwargs)
        for kind in ("tiling", "fragment"):
            for index, (address, before) in enumerate(references[kind]):
                after = backend._read_dva(address, len(before))
                (output / ("%s_%d_after.bin" % (kind, index))).write_bytes(after)
                runs = differing_runs(before, after)
                changed = sum(end - start for start, end in runs)
                print("%s item %d: %d runs, %d bytes differ" %
                      (kind, index, len(runs), changed), flush=True)
                for start, end in runs[:16]:
                    print("  +%#06x..%#06x %s -> %s" %
                          (start, end, before[start:end].hex(), after[start:end].hex()),
                          flush=True)
        print("Saved shim item boundary to %s" % output, flush=True)
        backend.debug_submission = result
        return result

    backend.build_submission = build
    backend.submit_register_pair = submit_pair


def make_high_root_graph_dumper(backend, env_name, phase):
    """Build a one-shot dumper for the native high-root comparison pages."""
    ordinal_text = os.getenv(env_name)
    if ordinal_text is None:
        return None

    from agx_g17p_compare_live_dump import snapshot_pages

    ordinal = int(ordinal_text, 0)
    snapshot = pathlib.Path(os.getenv(
        "G17P_NATIVE_GRAPH_SNAPSHOT",
        "/Users/user/asahi_re/artifacts/agx_g17p/"
        "third_0x83_20260802_160229"))
    pages = snapshot_pages(snapshot)
    addresses = sorted(
        address for context, selector, address in pages
        if context == 64 and selector == 1)
    dumped = False

    def dump(current_ordinal):
        nonlocal dumped
        if dumped or current_ordinal != ordinal:
            return
        output = ARTIFACTS / (
            "generated_high_graph_ordinal%d_%s_%s" %
            (ordinal, phase, time.strftime("%Y%m%d_%H%M%S")))
        output.mkdir(parents=True, exist_ok=False)
        skipped = []
        for address in addresses:
            try:
                body = backend._read_dva(address, PAGE)
            except Exception as error:  # noqa: BLE001
                skipped.append((address, str(error)))
                continue
            (output / ("%016x.bin" % address)).write_bytes(body)
        if skipped:
            (output / "unmapped.txt").write_text("".join(
                "%#x %s\n" % row for row in skipped))
        print("Saved generated ordinal %d %s graph to %s: "
              "%d pages, %d unmapped" %
              (ordinal, phase, output,
               len(addresses) - len(skipped), len(skipped)),
              flush=True)
        dumped = True

    return dump


def install_pre_notify_graph_dump(backend):
    """Dump one generated high-root graph at a selected global ordinal."""
    dump_graph = make_high_root_graph_dumper(
        backend, "G17P_DUMP_GRAPH_PRE_NOTIFY_ORDINAL", "pre-notify")
    if dump_graph is None:
        return
    previous = backend.pre_notify_hook

    def dump(current, pair_index):
        if previous is not None:
            previous(current, pair_index)
        dump_graph(current.group_number)

    backend.pre_notify_hook = dump


def install_host_scalar_replay(backend):
    """Replay final non-descriptor host scalars from one live store trace."""
    trace_path = os.getenv("G17P_REPLAY_HOST_SCALARS")
    if trace_path is None:
        return

    ordinal = int(os.getenv("G17P_REPLAY_HOST_SCALARS_ORDINAL", "3"), 0)
    pages = {
        0xfffffc2000020000,
        0xfffffc200002c000,
        0xfffffc20000e0000,
        0xfffffc20015d8000,
        0xfffffc20015e0000,
        0xfffffc20015e8000,
        0xfffffc2001618000,
    }
    with open(os.path.expanduser(trace_path)) as handle:
        trace = json.load(handle)

    final_bytes = {}
    for write in trace["writes"]:
        body = int(write["data"]).to_bytes(int(write["width"]), "little")
        for address in write["dvas"]:
            page = int(address) & ~(PAGE - 1)
            if page not in pages:
                continue
            for offset, value in enumerate(body):
                final_bytes[int(address) + offset] = value

    previous = backend.pre_notify_hook
    replayed = False

    def replay(current, pair_index):
        nonlocal replayed
        if previous is not None:
            previous(current, pair_index)
        if replayed or current.group_number != ordinal:
            return

        changed = []
        for page in sorted(pages):
            current_page = bytearray(current._read_dva(page, PAGE))
            patched = bytearray(current_page)
            for address, value in final_bytes.items():
                if page <= address < page + PAGE:
                    patched[address - page] = value
            start = None
            for offset, (old, new) in enumerate(zip(current_page, patched)):
                if old != new and start is None:
                    start = offset
                if old == new and start is not None:
                    current._write_dva(page + start, patched[start:offset])
                    changed.append((page + start, offset - start))
                    start = None
            if start is not None:
                current._write_dva(page + start, patched[start:])
                changed.append((page + start, PAGE - start))
        print(
            "EXPERIMENT: replayed %d non-descriptor host-scalar runs (%d bytes) "
            "before ordinal %d notify" % (
                len(changed), sum(length for _address, length in changed), ordinal),
            flush=True,
        )
        replayed = True

    backend.pre_notify_hook = replay


def install_native_page_replay(backend):
    """Replay selected complete pages from a native snapshot before one notify."""
    page_text = os.getenv("G17P_REPLAY_NATIVE_PAGES")
    if page_text is None:
        return

    from agx_g17p_compare_live_dump import snapshot_pages

    ordinal = int(os.getenv("G17P_REPLAY_NATIVE_PAGES_ORDINAL", "3"), 0)
    snapshot = pathlib.Path(os.getenv(
        "G17P_NATIVE_GRAPH_SNAPSHOT",
        "/Users/user/asahi_re/artifacts/agx_g17p/"
        "fourth_0x83_20260803_024355"))
    addresses = [int(value.strip(), 0) for value in page_text.split(",")
                 if value.strip()]
    pages = snapshot_pages(snapshot)
    bodies = {}
    for address in addresses:
        if address & (PAGE - 1):
            raise ValueError("native replay address is not page aligned: %#x" % address)
        key = (64, 1, address)
        if key not in pages:
            raise ValueError("native snapshot has no upper-root page %#x" % address)
        bodies[address] = pages[key]

    previous = backend.pre_notify_hook
    replayed = False

    def replay(current, pair_index):
        nonlocal replayed
        if previous is not None:
            previous(current, pair_index)
        if replayed or current.group_number != ordinal:
            return
        changed = 0
        for address, body in sorted(bodies.items()):
            old = current._read_dva(address, PAGE)
            changed += sum(left != right for left, right in zip(old, body))
            current._write_dva(address, body)
        print(
            "EXPERIMENT: replayed %d native page(s), changing %d bytes, "
            "before ordinal %d notify" % (len(bodies), changed, ordinal),
            flush=True,
        )
        replayed = True

    backend.pre_notify_hook = replay


def install_native_range_replay(backend):
    """Replay selected byte ranges from a native snapshot before one notify."""
    range_text = os.getenv("G17P_REPLAY_NATIVE_RANGES")
    if range_text is None:
        return

    from agx_g17p_compare_live_dump import snapshot_pages, snapshot_read

    ordinal = int(os.getenv("G17P_REPLAY_NATIVE_RANGES_ORDINAL", "3"), 0)
    snapshot = pathlib.Path(os.getenv(
        "G17P_NATIVE_GRAPH_SNAPSHOT",
        "/Users/user/asahi_re/artifacts/agx_g17p/"
        "fourth_0x83_20260803_024355"))
    ranges = []
    for value in range_text.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            address_text, size_text = value.split(":", 1)
            address = int(address_text, 0)
            size = int(size_text, 0)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "native replay range must be ADDRESS:SIZE: %r" % value) from error
        if size <= 0:
            raise ValueError("native replay range must have positive size: %r" % value)
        ranges.append((address, size))
    if not ranges:
        raise ValueError("G17P_REPLAY_NATIVE_RANGES contains no ranges")

    pages = snapshot_pages(snapshot)
    bodies = []
    for address, size in ranges:
        body, missing = snapshot_read(pages, address, size)
        if body is None:
            raise ValueError(
                "native snapshot range %#x:%#x lacks page %#x" %
                (address, size, missing))
        bodies.append((address, body))

    previous = backend.pre_notify_hook
    replayed = False

    def replay(current, pair_index):
        nonlocal replayed
        if previous is not None:
            previous(current, pair_index)
        if replayed or current.group_number != ordinal:
            return
        changed = 0
        for address, body in bodies:
            old = current._read_dva(address, len(body))
            changed += sum(left != right for left, right in zip(old, body))
            current._write_dva(address, body)
        print(
            "EXPERIMENT: replayed %d native range(s), changing %d bytes, "
            "before ordinal %d notify" % (len(bodies), changed, ordinal),
            flush=True,
        )
        replayed = True

    backend.pre_notify_hook = replay


def install_post_submit_graph_dump(backend):
    """Return a one-shot graph dumper to call after the selected submission."""
    return make_high_root_graph_dumper(
        backend, "G17P_DUMP_GRAPH_AFTER_ORDINAL", "post-submit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--width", type=int, default=2408)
    parser.add_argument("--height", type=int, default=1506)
    parser.add_argument("--drain-staged", action="store_true",
                        help="ring the work doorbell once before any front-end submission, to "
                             "consume the group the cold boot stages and defers. Without this the "
                             "first front-end submission publishes nothing and merely dispatches "
                             "the boot's group, so every later submission is being judged as a "
                             "second group when it is really the first host-published one.")
    parser.add_argument("--rewrite-staged", action="store_true",
                        help="replace the outstanding staged group's payload with the frontend's "
                             "generated item-zero graph without rewinding its queues or publishing "
                             "a new generation; this reproduces the known working first payload "
                             "while keeping the drain/append boundary unambiguous")
    parser.add_argument("--bootstrap-render", action="store_true",
                        help="perform one uncounted frontend render into the initial color BO "
                             "before --repeat-fresh. Its target must change, but it is excluded "
                             "from the repeated-submission result because it replaces and "
                             "dispatches the cold boot's staged generation")
    parser.add_argument("--repeat-fresh", type=int, default=0, metavar="N",
                        help="issue N submissions in ONE context, each with its own freshly "
                             "allocated colour BO, and require each one to write its own target "
                             "before the next is issued. This is the only witness that proves "
                             "repeated submission: queue retirement and scheduler-list emptiness "
                             "both report success for a group the accelerator never ran.")
    parser.add_argument("--witness-pages", type=int, default=64, metavar="N",
                        help="how many leading target pages to sample as the per-submission "
                             "witness (default 64; a real render writes a contiguous run from "
                             "offset zero, so the head is sufficient and much faster)")
    parser.add_argument("--fresh-target-stride", type=lambda value: int(value, 0),
                        default=0, metavar="BYTES",
                        help="place each --repeat-fresh target in a separate device-address "
                             "window at this stride from the bootstrap target; physical backing "
                             "and the firmware execution context remain independent and unchanged")
    parser.add_argument("--seed-channel-index", type=lambda value: int(value, 0),
                        default=None, metavar="INDEX",
                        help="EXPERIMENT: after the staged group completes, move both idle work "
                             "channel consumer/producer triples to this 8-bit index; used to "
                             "exercise ring wrap without spending 256 submissions reaching it")
    parser.add_argument("--verify-channel-backpressure", action="store_true",
                        help="EXPERIMENT: after a seeded wrap run completes, represent a full "
                             "ring in both live channel triples and require publication lookup "
                             "to reject it before restoring the idle state")
    parser.add_argument("--verify-allocation-failure", action="store_true",
                        help="EXPERIMENT: force one bounded DRM BO allocation to return ENOMEM, "
                             "then require allocator recovery and an output-positive render")
    parser.add_argument("--pool-b-logical-bias", type=lambda value: int(value, 0),
                        default=0, metavar="RECORDS",
                        help="EXPERIMENT: add RECORDS to created-pair Pool-B logical indices "
                             "without changing Pool A or any submission ordinal")
    parser.add_argument("--seed-pair1-item-index", type=lambda value: int(value, 0),
                        default=None, metavar="INDEX",
                        help="EXPERIMENT: after pair one executes item zero, jump all generated "
                             "pair-one-local fields to INDEX on its next alternating turn")
    parser.add_argument("--teardown-reuse", action="store_true",
                        help="with exactly two fresh submissions, destroy the first target, "
                             "reject its stale pointer before publication, then reuse its DVA "
                             "with fresh physical backing")
    parser.add_argument("--teardown-queue-pair", action="store_true",
                        help="with exactly three fresh submissions, destroy and explicitly "
                             "recreate pair one after its first render, then require the "
                             "recreated pair to render on its next scheduled turn")
    parser.add_argument("--verify-pending-teardown", action="store_true",
                        help="with exactly one fresh submission, attempt to destroy pair one "
                             "after publication but before its doorbell; require rejection, "
                             "then require that the untouched submission renders")
    parser.add_argument("--teardown-execution-context", action="store_true",
                        help="after a successful fresh render, create a second UAT context, "
                             "prove live mappings block removal, then free it, invalidate both "
                             "roots, and reject its stale context ID")
    parser.add_argument("--submissions", type=int, default=1,
                        help="number of packed submissions to issue (default: 1); values above "
                             "one require --repeat-fresh so each submission has its own witness")
    parser.add_argument("--instrument-items", action="store_true",
                        help="save and diff queue-item bodies around live publication; disabled "
                             "by default for --repeat-fresh because those device-memory reads "
                             "occur in the post-doorbell critical section")
    parser.add_argument("--encoder-u32", action="append", type=u32_override,
                        default=[], metavar="OFFSET=VALUE",
                        help="replace one u32 in the retained tiler stream before submission")
    parser.add_argument("--indirect-indexed", action="store_true",
                        help="replace the retained indexed draw's inline counts with a pointer "
                             "to a caller-owned indirect-argument BO")
    parser.add_argument("--allow-stall", action="store_true",
                        help="report a consumed but non-retiring submission instead of raising")
    parser.add_argument("--redirect-target", type=lambda value: int(value, 0), default=None,
                        metavar="DVA",
                        help="map a fresh target at DVA and redirect the known pass's three PBE "
                             "base fields to it")
    parser.add_argument("--linear-target", action="store_true",
                        help="with --redirect-target, convert the three PBE records to linear "
                             "BGRA8 and clear their compression fields")
    parser.add_argument("--linear-attachment", action="store_true",
                        help="with --linear-target, replace the complete retained attachment "
                             "with the verified three-segment linear BGRA8 template")
    parser.add_argument("--twiddled-uncompressed-attachment", action="store_true",
                        help="with --redirect-target, preserve the retained twiddled attachment "
                             "but clear its documented compression bits and aux pointer")
    parser.add_argument("--dump-twiddled-target", action="store_true",
                        help="after submission, save and 64x64-Morton-detile the redirected "
                             "32-bit surface")
    parser.add_argument("--scissor-size", metavar="WxH",
                        help="EXPERIMENT: replace the retained 16-byte scissor record before "
                             "submission, without changing the render dimensions")
    parser.add_argument("--drm-color-attachment", action="store_true",
                        help="allocate a color BO through DRM-shim and let the backend bind it; "
                             "do not manually edit target descriptors in this harness")
    parser.add_argument("--pull-drm-attachment", action="store_true",
                        help="copy the complete DRM color BO back through the shim memfd; this "
                             "is intentionally separate because a full-screen debug-USB read "
                             "is slow")
    parser.add_argument("--pipeline-page", type=pathlib.Path,
                        help="replace the retained 0x10001990000 pipeline arena with this "
                             "exact 0x4000-byte hardware capture")
    parser.add_argument("--load-pipeline", type=lambda value: int(value, 0),
                        default=0x01990240, metavar="ADDRESS",
                        help="context-relative LOAD pipeline address")
    parser.add_argument("--load-pipeline-bind", type=lambda value: int(value, 0),
                        default=0x40, metavar="VALUE")
    parser.add_argument("--store-pipeline", type=lambda value: int(value, 0),
                        default=0x01990640, metavar="ADDRESS",
                        help="context-relative STORE pipeline address")
    parser.add_argument("--store-pipeline-bind", type=lambda value: int(value, 0),
                        default=0, metavar="VALUE")
    options = parser.parse_args()
    if options.width <= 0 or options.height <= 0:
        parser.error("render dimensions must be positive")
    if options.submissions <= 0:
        parser.error("--submissions must be positive")
    if options.submissions > 1 and not options.repeat_fresh:
        parser.error("multiple submissions require --repeat-fresh; one shared target cannot "
                     "prove which submission rendered")
    if options.repeat_fresh and not (options.drain_staged or options.bootstrap_render):
        parser.error("--repeat-fresh requires --drain-staged or --bootstrap-render so the "
                     "cold-boot group cannot be mistaken for the first frontend submission")
    if options.drain_staged and options.bootstrap_render:
        parser.error("--drain-staged and --bootstrap-render are mutually exclusive")
    if options.drain_staged and not options.repeat_fresh:
        parser.error("--drain-staged requires --repeat-fresh; otherwise the drained boot group "
                     "and frontend submission share one ambiguous target witness")
    if options.drain_staged and not options.drm_color_attachment:
        parser.error("--drain-staged requires --drm-color-attachment for its target witness")
    if options.rewrite_staged and not options.drain_staged:
        parser.error("--rewrite-staged requires --drain-staged")
    if options.bootstrap_render and not options.repeat_fresh:
        parser.error("--bootstrap-render requires --repeat-fresh")
    if options.bootstrap_render and not options.drm_color_attachment:
        parser.error("--bootstrap-render requires --drm-color-attachment for its target witness")
    if options.fresh_target_stride and not options.repeat_fresh:
        parser.error("--fresh-target-stride requires --repeat-fresh")
    if options.seed_channel_index is not None:
        if not 0 <= options.seed_channel_index < 0x100:
            parser.error("--seed-channel-index must be in [0, 255]")
        if not options.drain_staged or not options.repeat_fresh:
            parser.error("--seed-channel-index requires --drain-staged and --repeat-fresh")
    if options.verify_channel_backpressure and options.seed_channel_index is None:
        parser.error("--verify-channel-backpressure requires --seed-channel-index")
    if options.verify_allocation_failure and not (
            options.drm_color_attachment and options.repeat_fresh):
        parser.error("--verify-allocation-failure requires a repeated DRM color attachment")
    if options.pool_b_logical_bias < 0:
        parser.error("--pool-b-logical-bias must be non-negative")
    if options.pool_b_logical_bias and options.repeat_fresh < 3:
        parser.error("--pool-b-logical-bias requires at least three fresh submissions")
    if options.seed_pair1_item_index is not None:
        if options.seed_pair1_item_index < 1:
            parser.error("--seed-pair1-item-index must be at least one")
        if options.repeat_fresh < 3:
            parser.error("--seed-pair1-item-index requires at least three fresh submissions")
    if options.teardown_reuse and options.repeat_fresh != 2:
        parser.error("--teardown-reuse requires exactly two fresh submissions")
    if options.teardown_queue_pair and options.repeat_fresh != 3:
        parser.error("--teardown-queue-pair requires exactly three fresh submissions")
    if options.teardown_queue_pair and options.teardown_reuse:
        parser.error("queue-pair and BO teardown experiments are mutually exclusive")
    if options.verify_pending_teardown and options.repeat_fresh != 1:
        parser.error("--verify-pending-teardown requires exactly one fresh submission")
    if options.verify_pending_teardown and (options.teardown_reuse
                                            or options.teardown_queue_pair):
        parser.error("pending teardown cannot be combined with another queue teardown")
    if options.teardown_execution_context and options.repeat_fresh < 1:
        parser.error("--teardown-execution-context requires a fresh submission witness")
    if options.fresh_target_stride and options.fresh_target_stride & (PAGE - 1):
        parser.error("--fresh-target-stride must be page aligned")
    if (options.fresh_target_stride
            and options.fresh_target_stride < uncompressed_twiddled_size(
                options.width, options.height)):
        parser.error("--fresh-target-stride must not overlap adjacent targets")
    if options.linear_target and options.redirect_target is None:
        parser.error("--linear-target requires --redirect-target")
    if options.linear_attachment and not options.linear_target:
        parser.error("--linear-attachment requires --linear-target")
    if options.twiddled_uncompressed_attachment and options.redirect_target is None:
        parser.error("--twiddled-uncompressed-attachment requires --redirect-target")
    if options.twiddled_uncompressed_attachment and options.linear_attachment:
        parser.error("twiddled-uncompressed and linear attachment modes are exclusive")
    if options.dump_twiddled_target and options.redirect_target is None:
        if not options.drm_color_attachment:
            parser.error("--dump-twiddled-target requires --redirect-target or "
                         "--drm-color-attachment")
    if options.drm_color_attachment and options.redirect_target is not None:
        parser.error("--drm-color-attachment and --redirect-target are exclusive")
    if options.pull_drm_attachment and not options.drm_color_attachment:
        parser.error("--pull-drm-attachment requires --drm-color-attachment")
    if options.indirect_indexed and not options.drm_color_attachment:
        parser.error("--indirect-indexed requires --drm-color-attachment")

    scissor_size = None
    if options.scissor_size:
        try:
            scissor_width_text, separator, scissor_height_text = (
                options.scissor_size.lower().partition("x"))
            if not separator:
                raise ValueError
            scissor_size = (int(scissor_width_text, 0),
                            int(scissor_height_text, 0))
        except ValueError:
            parser.error("--scissor-size must be WIDTHxHEIGHT")
        if min(scissor_size) <= 0:
            parser.error("--scissor-size dimensions must be positive")

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if scissor_size is not None:
            scissor_address = 0x100019a0000
            scissor_body = struct.pack(
                "<IIIf", scissor_size[0], scissor_size[1], 0, 1.0)
            old_scissor = backend._read_dva(scissor_address, len(scissor_body))
            backend._write_dva(scissor_address, scissor_body)
            backend.space.flush()
            backend.u.inst("dsb sy")
            check = backend._read_dva(scissor_address, len(scissor_body))
            if check != scissor_body:
                raise RuntimeError("scissor override did not read back")
            print("EXPERIMENT: scissor %#x: %s -> %s" % (
                scissor_address, old_scissor.hex(), scissor_body.hex()), flush=True)
        backend.pool_b_logical_bias = options.pool_b_logical_bias
        install_pre_notify_graph_dump(backend)
        install_host_scalar_replay(backend)
        install_native_page_replay(backend)
        install_native_range_replay(backend)
        post_submit_graph_dump = install_post_submit_graph_dump(backend)
        if options.instrument_items or not options.repeat_fresh:
            instrument_submission(backend)
        extent = newest_render_extent()

        color_region = None
        color_before = None
        color_attachment = None
        fresh_targets = []
        indirect_arguments = None
        if options.drm_color_attachment:
            color_size = uncompressed_twiddled_size(
                options.width, options.height)
            target_count = 1 + options.repeat_fresh
            memfd.truncate(target_count * color_size)
            color_address = front.create_bo_from_memfd(
                memfd.fileno(), 0, color_size, 0)
            color_obj = front.bos[0]
            if options.repeat_fresh:
                color_obj._no_push = True
            color_attachment = {
                "type": 0,
                "size": color_size,
                "pointer": color_address,
            }
            color_region = {
                "dva": color_address,
                "pa": color_obj._pa,
                "size": color_size,
            }
            color_witness_region = dict(color_region)
            if options.repeat_fresh:
                color_witness_region["size"] = min(
                    color_size, options.witness_pages * PAGE)
            color_before = sample_page_heads(backend, color_witness_region)
            if options.repeat_fresh:
                witness_size = min(
                    color_size, options.witness_pages * PAGE)
                preallocate = 1 if options.teardown_reuse else options.repeat_fresh
                for index in range(preallocate):
                    offset = (index + 1) * color_size
                    if options.fresh_target_stride:
                        front.ctx.gobj.next_va = (
                            color_address
                            + (index + 1) * options.fresh_target_stride
                        )
                    address = front.create_bo_from_memfd(
                        memfd.fileno(), offset, color_size, 0)
                    obj = front.bos[offset]
                    obj._no_push = True
                    region = {"dva": address, "pa": obj._pa,
                              "size": witness_size}
                    before_heads = sample_page_heads(backend, region)
                    if any(any(page) for page in before_heads):
                        raise RuntimeError(
                            "preallocated target %d at %#x was not zero" %
                            (index + 1, address))
                    fresh_targets.append({
                        "address": address,
                        "object": obj,
                        "region": region,
                        "before": before_heads,
                    })
                print("Preallocated %d fresh submission targets before bootstrap so their "
                      "UAT mappings are published with the first render%s" %
                      (len(fresh_targets),
                       " at %#x-byte DVA intervals" % options.fresh_target_stride
                       if options.fresh_target_stride else ""), flush=True)
            if options.verify_allocation_failure:
                failure_offset = target_count * color_size
                memfd.truncate(failure_offset + PAGE)
                allocator = front.ctx.gobj
                old_limit = allocator.max_va
                failed_cursor = allocator.next_va
                old_allocator_objects = list(allocator.objects)
                old_space_objects = list(allocator.space.objects)
                old_bos = dict(front.bos)
                allocator.max_va = failed_cursor
                try:
                    try:
                        front.create_bo_from_memfd(
                            memfd.fileno(), failure_offset, PAGE, 0)
                    except OSError as exc:
                        if exc.errno != errno.ENOMEM:
                            raise
                    else:
                        raise RuntimeError("bounded BO allocation unexpectedly succeeded")
                    if (allocator.next_va != failed_cursor
                            or allocator.objects != old_allocator_objects
                            or allocator.space.objects != old_space_objects
                            or front.bos != old_bos):
                        raise RuntimeError(
                            "failed BO allocation mutated allocator, mapping, or BO state")
                finally:
                    allocator.max_va = old_limit
                recovery_address = front.create_bo_from_memfd(
                    memfd.fileno(), failure_offset, PAGE, 0)
                if recovery_address != failed_cursor:
                    raise RuntimeError(
                        "allocation recovery used %#x instead of failed cursor %#x" %
                        (recovery_address, failed_cursor))
                front.bo_free(failure_offset)
                print(
                    "ALLOCATION FAILURE WITNESS: ENOMEM left cursor %#x and all ownership "
                    "unchanged; restored allocator reused that DVA" % failed_cursor,
                    flush=True,
                )
            if options.indirect_indexed:
                from m1n1.agx import g17p_encoder

                indirect_offset = target_count * color_size
                memfd.truncate(indirect_offset + PAGE)
                front.create_bo_from_memfd(
                    memfd.fileno(), indirect_offset, PAGE, 0)
                indirect_obj = front.bos[indirect_offset]
                indirect_address = indirect_obj._addr
                indirect_body = g17p_encoder.build_indexed_indirect_arguments(
                    6, 1, 0, 0, 0)
                indirect_obj._map[:len(indirect_body)] = indirect_body
                indirect_obj.push(True)
                indirect_arguments = {
                    "address": indirect_address,
                    "object": indirect_obj,
                    "body": indirect_body,
                }
                print("Indexed-indirect argument BO: gpu=%#x pa=%#x body=%s" % (
                    indirect_address, indirect_obj._pa, indirect_body.hex()), flush=True)
            front.pull_buffers = options.pull_drm_attachment
            print("DRM color BO: gpu=%#x pa=%#x size=%#x" %
                  (color_address, color_obj._pa, color_size), flush=True)

        body = packed_cmdbuf(
            options.width, options.height,
            options.load_pipeline, options.load_pipeline_bind,
            options.store_pipeline, options.store_pipeline_bind,
            color_attachment=color_attachment)
        storage = ctypes.create_string_buffer(body)
        submit_args = types.SimpleNamespace(cmdbuf=ctypes.addressof(storage))

        if options.pipeline_page is not None:
            install_pipeline_page(
                backend, extent, options.pipeline_page,
                options.load_pipeline, options.store_pipeline)

        redirected = None
        redirected_before = None
        if options.redirect_target is not None:
            redirected, redirected_before = redirect_known_target(
                backend, options.redirect_target, extent,
                linear=options.linear_target)
            if options.linear_attachment:
                install_linear_attachment(
                    backend, extent, options.redirect_target,
                    options.width, options.height)
            elif options.twiddled_uncompressed_attachment:
                install_twiddled_uncompressed_attachment(
                    backend, extent, options.redirect_target)

        for offset, value in options.encoder_u32:
            address = 0x1000018000 + offset
            old = struct.unpack("<I", backend._read_dva(address, 4))[0]
            backend._write_dva(address, struct.pack("<I", value))
            check = struct.unpack("<I", backend._read_dva(address, 4))[0]
            if check != value:
                raise RuntimeError(
                    "encoder override at %#x read back %#x, expected %#x" %
                    (offset, check, value))
            print("encoder +%#x: %#010x -> %#010x" %
                  (offset, old, value), flush=True)

        if indirect_arguments is not None:
            from m1n1.agx import g17p_encoder

            indirect_address = indirect_arguments["address"]
            encoder_address = 0x1000018000
            direct_stream = backend._read_dva(
                encoder_address, g17p_encoder.ENCODER_SIZE)
            encoder_parameters = g17p_encoder.parse_encoder(
                direct_stream, 0x1000000000)
            encoder_parameters.indirect_args = indirect_address
            indirect_stream = g17p_encoder.build_encoder(encoder_parameters)
            backend._write_dva(encoder_address, indirect_stream)
            check = backend._read_dva(
                encoder_address, g17p_encoder.ENCODER_SIZE)
            if check != indirect_stream:
                raise RuntimeError("indexed-indirect encoder did not read back")
            changed_offsets = [
                offset for offset, (old, new) in
                enumerate(zip(direct_stream, indirect_stream)) if old != new
            ]
            print("Indexed-indirect VDM: opcode=%#x args=%#x" %
                  (g17p_encoder.DRAW_OPCODE_INDEXED_16_INDIRECT,
                   indirect_address), flush=True)
            print("  rebuilt stream; changed offsets %s" %
                  ["%#x" % offset for offset in changed_offsets], flush=True)

        if options.repeat_fresh:
            print("DRM UAPI body: %#x bytes; strict fresh-target witness: %d pages" %
                  (len(body), min(options.witness_pages,
                                  (color_size + PAGE - 1) // PAGE)), flush=True)
        else:
            before = render_pages(backend, extent)
            print("DRM UAPI body: %#x bytes; render witness: %d pages" %
                  (len(body), len(before)), flush=True)
            if not before:
                raise RuntimeError("no readable render witness pages")

        if options.repeat_fresh:
            # One context, N submissions, each into its own freshly allocated BO with its own
            # physical backing. Every iteration is judged only by whether ITS OWN target changed,
            # so a submission that firmware accepts and retires without running is a failure here
            # rather than a pass.
            if options.drain_staged:
                from m1n1.agx.g17p_shim import work_doorbell_channel

                def queue_indices():
                    out = {}
                    for name in ("TA_0", "3D_0"):
                        try:
                            _entry, queue = backend.queue_for(name)
                            out[name] = queue.indices()
                        except Exception as exc:            # noqa: BLE001
                            out[name] = "unreadable: %s" % exc
                    return out

                print("DRAIN: queue state before the boot group's doorbell: %s"
                      % queue_indices(), flush=True)
                # The boot's staged group renders wherever the shared target records point, so
                # aim it at the first BO and use that as the proof it really ran.
                backend.bind_color_attachment(
                    color_region["dva"], color_region["size"],
                    options.width, options.height)
                if options.rewrite_staged:
                    drm = drm_asahi_cmdbuf_t.parse(body)
                    cmdbuf = command_buffer_from_drm(
                        drm, pipeline_base=backend.ctx.pipeline_base,
                        **front.g17p_supplied())
                    built = backend.build_submission(cmdbuf)
                    backend.space.flush()
                    backend.prepare_submission_runtime(reset_staged=False)
                    backend.submit_register_pair(
                        built["tiling_registers"], built["fragment_registers"],
                        built["shared"], built["pools"],
                        built["tiling_optional"], built["fragment_optional"],
                        context_id=backend.primary_execution_context,
                        queue_pair=0, notify=False, publish=False,
                        parameters=built["parameters"])
                    print("DRAIN: rewrote the outstanding canonical payload without "
                          "changing its queue or channel generation", flush=True)
                    # The fresh BO was sampled before graph construction and is never CPU-written.
                    # Re-reading it here adds a proxy transaction in the critical pre-doorbell gap
                    # without providing a stronger baseline.
                    drain_before = list(color_before)
                else:
                    backend.space.flush()
                    drain_before = sample_page_heads(backend, color_witness_region)
                print("DRAIN: ringing the staged work doorbell", flush=True)
                backend.submitter.notify(work_doorbell_channel(0))
                print("DRAIN: staged work doorbell sent", flush=True)
                time.sleep(0.005)
                print("DRAIN: reading the target before acknowledging completion", flush=True)
                # The baseline clean+invalidated these lines and no CPU code has touched them
                # since. A direct physical read is therefore a valid first witness and, unlike a
                # premature control-done send, cannot wait forever on a full ASC inbox.
                drain_probe = [
                    bytes(backend.u.iface.readmem(
                        color_witness_region["pa"] + offset, 32))
                    for offset in range(0, color_witness_region["size"], PAGE)
                ]
                probe_changed = sum(
                    left != right for left, right in zip(drain_before, drain_probe))
                print("DRAIN: pre-ack target witness changed %d/%d sampled pages" %
                      (probe_changed, len(drain_probe)), flush=True)
                state = queue_indices()
                print("DRAIN: pre-ack queue state: %s" % state, flush=True)
                done = [s.get("done") if isinstance(s, dict) else None
                        for s in state.values()]
                write = [s.get("write") if isinstance(s, dict) else None
                         for s in state.values()]
                if done and done == write and backend.control_done is not None:
                    print("DRAIN: acknowledging the completed group", flush=True)
                    backend.control_done()
                    print("DRAIN: completion acknowledged", flush=True)
                elif done != write:
                    print("DRAIN: group is not complete; control-done intentionally withheld",
                          flush=True)
                drain_after = sample_page_heads(
                    backend, color_witness_region, invalidate_only=True)
                drained_changed = sum(l != r for l, r in zip(drain_before, drain_after))
                print("DRAIN: queue state after: %s" % queue_indices(), flush=True)
                print("DRAIN: boot group wrote %d/%d sampled pages -> %s"
                      % (drained_changed, len(drain_after),
                         "the boot's group executed" if drained_changed
                         else "the boot's group did NOT execute"), flush=True)
                if not drained_changed:
                    print("FAIL: the staged boot group did not write its fresh target; "
                          "no frontend publication will be attempted", flush=True)
                    return 2
                backend.adopt_completed_staged_group()
                print("DRAIN: every submission below is now a genuine host publication",
                      flush=True)

            if options.bootstrap_render:
                print("BOOTSTRAP: submitting one uncounted frontend render on the initial "
                      "pair; only a target-page change permits the counted run", flush=True)
                bootstrap_stall = None
                try:
                    bootstrap_code = front.submit(memfd.fileno(), submit_args)
                except TimeoutError as error:
                    bootstrap_code, bootstrap_stall = None, error
                if (post_submit_graph_dump is not None
                        and backend.last_submission is not None):
                    post_submit_graph_dump(
                        backend.last_submission["submission_ordinal"])
                bootstrap_after = sample_page_heads(
                    backend, color_witness_region, invalidate_only=True)
                bootstrap_changed = sum(
                    left != right for left, right in zip(color_before, bootstrap_after))
                bootstrap_nonzero = sum(any(page) for page in bootstrap_after)
                submission = getattr(backend, "last_submission", None)
                bootstrap_indices = None
                bootstrap_retired = None
                if submission is not None:
                    bootstrap_indices = {
                        kind: submission[kind]["queue"].indices()
                        for kind in ("tiling", "fragment")
                    }
                    bootstrap_retired = backend.pair_retired(submission)
                print("BOOTSTRAP: result=%r stall=%s queues=%s scheduler_drained=%s" %
                      (bootstrap_code, bootstrap_stall, bootstrap_indices,
                       bootstrap_retired), flush=True)
                print("BOOTSTRAP TARGET WITNESS: %d/%d sampled pages changed, "
                      "%d nonzero -> %s" %
                      (bootstrap_changed, len(bootstrap_after), bootstrap_nonzero,
                       "EXECUTED" if bootstrap_changed else "DID NOT EXECUTE"), flush=True)
                if not bootstrap_changed:
                    print("FAIL: the bootstrap render did not write its target; no fresh "
                          "publication will be attempted", flush=True)
                    return 2
                if options.dump_twiddled_target:
                    output, manifest = save_twiddled_bgra8(
                        backend, color_region, options.width, options.height)
                    print("BOOTSTRAP: saved full twiddled/detiled target to %s; "
                          "top pixels: %s" %
                          (output, manifest["top_pixel_words"][:4]), flush=True)
                print("BOOTSTRAP: rendered successfully but is excluded from the repeated "
                      "submission count; every target below is a fresh publication", flush=True)

            seeded_work_channels = None
            if options.seed_channel_index is not None:
                from m1n1.agx import g17p

                seed = options.seed_channel_index
                names = ("TA_0", "3D_0")
                idle = {}
                seeded_work_channels = {}
                for name in names:
                    entry, queue = backend.queue_for(name)
                    seeded_work_channels[name] = (entry, queue)
                    indices = queue.indices()
                    if not (indices["done"] == indices["read"] == indices["write"]):
                        raise RuntimeError(
                            "cannot seed active %s queue: %r" % (name, indices))
                    idle[name] = backend.channels.counters(entry)
                    for address in entry["state_addrs"]:
                        backend._write_dva(address, struct.pack("<I", seed))
                backend.space.flush()
                backend.u.inst("dsb sy")
                seeded = {
                    name: backend.channels.counters(seeded_work_channels[name][0])
                    for name in names
                }
                if any(counters != [seed, seed, seed]
                       for counters in seeded.values()):
                    raise RuntimeError(
                        "work channel seed did not stick: %r" % seeded)
                print(
                    "EXPERIMENT: moved idle work channels from %r to index %#x" %
                    (idle, seed),
                    flush=True,
                )

            # What the cold boot left on the queue before the front end submits anything. A
            # non-zero write index here means a group is already staged, so the first doorbell
            # dispatches the boot's group rather than anything the front end published.
            try:
                staged = {name: (seeded_work_channels[name][1]
                                 if seeded_work_channels is not None
                                 else backend.queue_for(name)[1]).indices()
                          for name in ("TA_0", "3D_0")}
                print("PRE-SUBMISSION queue state after bootstrap preparation: %s"
                      % staged, flush=True)
            except Exception as exc:                                # noqa: BLE001
                print("PRE-SUBMISSION queue state unreadable: %s" % exc, flush=True)
            results = []
            pair1_item_seeded = False
            teardown_replacement = None
            queue_teardown = None
            pending_teardown = None
            if options.verify_pending_teardown:
                def reject_pending_teardown(live_backend, pair):
                    nonlocal pending_teardown
                    if pair != 1:
                        raise RuntimeError(
                            "pending teardown expected pair 1, got pair %d" % pair)
                    before = {
                        kind: live_backend.muxed_queue_pairs[pair][kind][1].indices()
                        for kind in ("tiling", "fragment")
                    }
                    try:
                        live_backend.destroy_muxed_queue_pair(pair)
                    except RuntimeError as exc:
                        error = str(exc)
                    else:
                        raise RuntimeError("pending queue pair was destroyed")
                    after = {
                        kind: live_backend.muxed_queue_pairs[pair][kind][1].indices()
                        for kind in ("tiling", "fragment")
                    }
                    if before != after or pair in live_backend.destroyed_muxed_queue_pairs:
                        raise RuntimeError(
                            "rejected pending teardown mutated pair %d: %r -> %r" %
                            (pair, before, after))
                    pending_teardown = {"error": error, "indices": after}
                    live_backend.pre_notify_hook = None
                    print(
                        "PENDING TEARDOWN WITNESS: rejected before doorbell (%s); "
                        "queue state remained %r" % (error, after), flush=True)

                backend.pre_notify_hook = reject_pending_teardown
            for index in range(options.repeat_fresh):
                if (options.seed_pair1_item_index is not None
                        and not pair1_item_seeded
                        and backend.submission_queue_pair() == 1
                        and backend.queue_pair_submissions.get(1, 0) > 0):
                    previous = backend.queue_pair_submissions[1]
                    backend.queue_pair_submissions[1] = options.seed_pair1_item_index
                    pair1_item_seeded = True
                    print(
                        "EXPERIMENT: advanced pair-one local item index from %d to %d "
                        "before counted submission %d" %
                        (previous, options.seed_pair1_item_index, index + 1),
                        flush=True,
                    )
                target = fresh_targets[index]
                address = target["address"]
                obj = target["object"]
                region = target["region"]
                before_heads = sample_page_heads(backend, region)
                nonzero_before = sum(any(page) for page in before_heads)
                if nonzero_before:
                    raise RuntimeError(
                        "submission %d's fresh target %#x was not zero before the run "
                        "(%d/%d pages already nonzero); the witness would be meaningless"
                        % (index + 1, address, nonzero_before, len(before_heads)))
                if before_heads != target["before"]:
                    raise RuntimeError(
                        "submission %d's preallocated target %#x changed before its run" %
                        (index + 1, address))

                body_n = packed_cmdbuf(
                    options.width, options.height,
                    options.load_pipeline, options.load_pipeline_bind,
                    options.store_pipeline, options.store_pipeline_bind,
                    color_attachment={"type": 0, "size": color_size,
                                      "pointer": address})
                storage_n = ctypes.create_string_buffer(body_n)
                args_n = types.SimpleNamespace(cmdbuf=ctypes.addressof(storage_n))

                print("--- submission %d/%d: fresh target gpu=%#x pa=%#x"
                      % (index + 1, options.repeat_fresh, address, obj._pa), flush=True)
                ring_before = None
                if options.seed_channel_index is not None:
                    ring_before = {
                        name: backend.channels.counters(seeded_work_channels[name][0])
                        for name in ("TA_0", "3D_0")
                    }
                stall = None
                try:
                    code = front.submit(memfd.fileno(), args_n)
                except TimeoutError as error:
                    code, stall = None, error
                if (post_submit_graph_dump is not None
                        and backend.last_submission is not None):
                    post_submit_graph_dump(
                        backend.last_submission["submission_ordinal"])

                after_heads = sample_page_heads(backend, region, invalidate_only=True)
                changed_n = sum(l != r for l, r in zip(before_heads, after_heads))
                nonzero_n = sum(any(page) for page in after_heads)
                submission = getattr(backend, "last_submission", None)
                indices = None
                if submission is not None:
                    indices = {kind: submission[kind]["queue"].indices()
                               for kind in ("tiling", "fragment")}
                    if (pair1_item_seeded
                            and submission["queue_pair"] == 1
                            and submission["item_index"] == options.seed_pair1_item_index):
                        from m1n1.agx import g17p_submission

                        context_offset = (
                            g17p_submission.QUEUE_CONTEXT_ITEM_BASE
                            + submission["item_index"]
                            * g17p_submission.QUEUE_CONTEXT_ITEM_STRIDE)
                        contexts = {
                            kind: (backend.muxed_queue_pointer_sets[1][kind]
                                   ["firmware_scratch"] + context_offset)
                            for kind in ("tiling", "fragment")
                        }
                        print(
                            "    PAIR-ONE CONTEXT ITEM WITNESS: item %d at %r" %
                            (submission["item_index"], contexts),
                            flush=True,
                        )
                drained = (backend.pair_retired(submission)
                           if submission is not None else None)
                ring_after = None
                if options.seed_channel_index is not None:
                    from m1n1.agx import g17p

                    expected_slot = (
                        options.seed_channel_index + index) & g17p.PRODUCER_MASK
                    expected_next = g17p.next_producer(expected_slot)
                    ring_after = {
                        name: backend.channels.counters(seeded_work_channels[name][0])
                        for name in ("TA_0", "3D_0")
                    }
                    if any(counters != [expected_slot] * 3
                           for counters in ring_before.values()):
                        raise RuntimeError(
                            "submission %d did not begin at channel slot %#x: %r" %
                            (index + 1, expected_slot, ring_before))
                    if any(counters != [expected_next] * 3
                           for counters in ring_after.values()):
                        raise RuntimeError(
                            "submission %d did not complete channel slot %#x -> %#x: %r" %
                            (index + 1, expected_slot, expected_next, ring_after))
                print("    result=%r stall=%s queues=%s scheduler_drained=%s"
                      % (code, stall, indices, drained), flush=True)
                if ring_after is not None:
                    print("    CHANNEL WRAP WITNESS: %r -> %r" %
                          (ring_before, ring_after), flush=True)
                print("    TARGET WITNESS: %d/%d sampled pages changed, %d nonzero -> %s"
                      % (changed_n, len(after_heads), nonzero_n,
                         "EXECUTED" if changed_n else "DID NOT EXECUTE"), flush=True)
                if changed_n and options.dump_twiddled_target:
                    output, manifest = save_twiddled_bgra8(
                        backend,
                        {"dva": address, "pa": obj._pa, "size": color_size},
                        options.width, options.height)
                    print("    saved full twiddled/detiled target to %s; top pixels: %s" %
                          (output, manifest["top_pixel_words"][:4]), flush=True)
                results.append({"index": index + 1, "dva": address,
                                "changed": changed_n, "nonzero": nonzero_n,
                                "drained": drained, "stall": str(stall) if stall else None})
                if (changed_n and index == 0
                        and os.getenv("G17P_PATCH_NATIVE_B1_COMPLETION") == "1"):
                    patch_native_b1_completion(backend, submission)
                if (changed_n
                        and os.getenv("G17P_FORCE_EMPTY_EXECUTED_JOB_LIST") == "1"):
                    force_empty_executed_job_list(backend, submission)
                if not changed_n:
                    print("    (queue retirement and scheduler state above are NOT evidence; "
                          "the target did not change, so this submission did no work)",
                          flush=True)
                    break

                if options.teardown_queue_pair and index == 0:
                    if submission["queue_pair"] != 1:
                        raise RuntimeError(
                            "queue teardown expected first frontend render on pair 1, got %d" %
                            submission["queue_pair"])
                    tombstone = backend.destroy_muxed_queue_pair(1)
                    try:
                        backend.muxed_queue_pair(1)
                    except G17PUnsupported as exc:
                        destroyed_error = str(exc)
                    else:
                        raise RuntimeError("destroyed queue pair 1 remained submit-capable")
                    recreated = backend.recreate_muxed_queue_pair(1)
                    for kind in ("tiling", "fragment"):
                        expected = tombstone["queues"][kind]
                        actual = recreated["built"][
                            "TA_0" if kind == "tiling" else "3D_0"]
                        for field in ("queue", "pointers", "item_ring", "job_list"):
                            if actual[field] != expected[field]:
                                raise RuntimeError(
                                    "recreated pair-1 %s %s moved %#x -> %#x" % (
                                        kind, field, expected[field], actual[field]))
                    queue_teardown = recreated
                    print(
                        "QUEUE TEARDOWN WITNESS: pair 1 destroyed after target-verified "
                        "completion; consumed slots=%r current-job records=%r; all queue-"
                        "context aliases were unmapped; stale lookup rejected (%s); pair "
                        "explicitly recreated at the same queue slots with fresh context "
                        "PAs=%r and queue identifier %#x (generation %d)" % (
                            tombstone["cleared_slots"],
                            tombstone["cleared_current_jobs"], destroyed_error,
                            recreated["context_pas"], recreated["uuid"],
                            recreated["generation"]),
                        flush=True,
                    )

                if options.teardown_queue_pair and index == 2:
                    if submission["queue_pair"] != 1:
                        raise RuntimeError(
                            "recreated queue-pair witness ran on pair %d, expected pair 1" %
                            submission["queue_pair"])
                    final_tombstone = backend.destroy_muxed_queue_pair(1)
                    if (final_tombstone["old_context_pas"] !=
                            queue_teardown["context_pas"]):
                        raise RuntimeError(
                            "final queue teardown removed unexpected context backing: %r" %
                            final_tombstone["old_context_pas"])
                    print(
                        "QUEUE RECREATE WITNESS: recreated pair 1 changed its fresh target; "
                        "its second generation was then destroyed and all aliases removed",
                        flush=True,
                    )

                if options.verify_pending_teardown and index == 0:
                    if pending_teardown is None:
                        raise RuntimeError("pending teardown hook did not run")
                    if submission["queue_pair"] != 1:
                        raise RuntimeError(
                            "pending teardown witness rendered on pair %d" %
                            submission["queue_pair"])
                    tombstone = backend.destroy_muxed_queue_pair(1)
                    print(
                        "PENDING TEARDOWN WITNESS: the rejected submission changed its "
                        "target; completed pair 1 was then destroyed, clearing slots %r" %
                        tombstone["cleared_slots"], flush=True)

                if options.teardown_reuse and index == 0:
                    context = obj._drm_context
                    old_pa = obj._pa
                    old_offset = obj._memfd_offset
                    reset_lists = backend.quiesce_submission(
                        submission, semantic_complete=True)
                    channel_before = {
                        name: backend.channels.counters(backend.queue_for(name)[0])
                        for name in ("TA_0", "3D_0")
                    }
                    queue_before = {
                        name: backend.queue_for(name)[1].indices()
                        for name in ("TA_0", "3D_0")
                    }
                    group_before = backend.group_number
                    front.bo_free(old_offset)
                    translations = obj.space.uat.iotranslate(
                        context, address, obj._size)
                    if any(pa is not None for pa, _length in translations):
                        raise RuntimeError(
                            "destroyed target %#x still translates: %r" %
                            (address, translations))
                    try:
                        front.submit(memfd.fileno(), args_n)
                    except G17PUnsupported as exc:
                        stale_error = str(exc)
                    else:
                        raise RuntimeError(
                            "destroyed target %#x was accepted for submission" % address)
                    channel_after = {
                        name: backend.channels.counters(backend.queue_for(name)[0])
                        for name in ("TA_0", "3D_0")
                    }
                    queue_after = {
                        name: backend.queue_for(name)[1].indices()
                        for name in ("TA_0", "3D_0")
                    }
                    if (backend.group_number != group_before
                            or channel_after != channel_before
                            or queue_after != queue_before):
                        raise RuntimeError(
                            "stale-pointer rejection changed publication state: "
                            "group %d->%d channels %r->%r queues %r->%r" % (
                                group_before, backend.group_number,
                                channel_before, channel_after,
                                queue_before, queue_after))

                    replacement_offset = 2 * color_size
                    replacement_address = front.create_bo_from_memfd(
                        memfd.fileno(), replacement_offset, color_size, 0)
                    replacement = front.bos[replacement_offset]
                    replacement._no_push = True
                    if replacement_address != address:
                        raise RuntimeError(
                            "released DVA %#x was replaced at %#x" %
                            (address, replacement_address))
                    if replacement._pa == old_pa:
                        raise RuntimeError(
                            "replacement DVA %#x retained physical backing %#x" %
                            (address, old_pa))
                    replacement_region = {
                        "dva": replacement_address,
                        "pa": replacement._pa,
                        "size": min(color_size, options.witness_pages * PAGE),
                    }
                    replacement_before = sample_page_heads(
                        backend, replacement_region)
                    if any(any(page) for page in replacement_before):
                        raise RuntimeError("replacement target was not initially zero")
                    teardown_replacement = {
                        "address": replacement_address,
                        "object": replacement,
                        "region": replacement_region,
                        "before": replacement_before,
                    }
                    fresh_targets.append(teardown_replacement)
                    print(
                        "TEARDOWN WITNESS: quiesced by resetting %d stale job list(s), "
                        "unmapped %#x from PA %#x; stale submit "
                        "rejected before publication (%s); reused DVA with PA %#x" % (
                            reset_lists, address, old_pa, stale_error,
                            replacement._pa),
                        flush=True,
                    )

            executed = sum(1 for r in results if r["changed"])
            if options.teardown_reuse and executed == options.repeat_fresh:
                replacement = teardown_replacement["object"]
                reset_lists = backend.quiesce_submission(
                    backend.last_submission, semantic_complete=True)
                replacement_offset = replacement._memfd_offset
                replacement_address = replacement._addr
                replacement_context = replacement._drm_context
                front.bo_free(replacement_offset)
                translations = replacement.space.uat.iotranslate(
                    replacement_context, replacement_address,
                    replacement._size)
                if any(pa is not None for pa, _length in translations):
                    raise RuntimeError(
                        "final replacement target %#x still translates: %r" %
                        (replacement_address, translations))
                print(
                    "TEARDOWN WITNESS: final replacement %#x quiesced by resetting %d "
                    "stale job list(s) and is unmapped after its completed render" %
                    (replacement_address, reset_lists),
                    flush=True,
                )
            if (options.teardown_execution_context
                    and executed == options.repeat_fresh):
                context_id = max(backend.execution_contexts) + 1
                state = backend.create_execution_context(context_id)
                probe = state["ctx"].gobj.new(0x4000, name="context-teardown-probe")
                probe_dva = probe._addr
                probe_pa = probe._pa
                try:
                    backend.destroy_execution_context(context_id)
                except RuntimeError as exc:
                    live_error = str(exc)
                else:
                    raise RuntimeError("context with a live BO was destroyed")
                probe.free()
                tombstone = backend.destroy_execution_context(context_id)
                translations = state["space"].uat.iotranslate(
                    context_id, probe_dva, 0x4000)
                if any(pa is not None for pa, _span in translations):
                    raise RuntimeError(
                        "destroyed context %d still translates probe %#x: %r" %
                        (context_id, probe_dva, translations))
                try:
                    backend.activate_execution_context(context_id)
                except G17PUnsupported as exc:
                    stale_error = str(exc)
                else:
                    raise RuntimeError(
                        "destroyed context %d was silently recreated" % context_id)
                print(
                    "CONTEXT TEARDOWN WITNESS: context %d rejected removal while "
                    "probe %#x -> %#x was live (%s); after BO release roots %r were "
                    "unbound, translations vanished, and stale activation was rejected (%s)" %
                    (context_id, probe_dva, probe_pa, live_error,
                     tombstone["roots"], stale_error), flush=True)
            if (options.seed_pair1_item_index is not None
                    and executed == options.repeat_fresh
                    and not pair1_item_seeded):
                raise RuntimeError("pair-one item-index seed was never exercised")
            if (options.verify_channel_backpressure
                    and executed == options.repeat_fresh):
                from m1n1.agx import g17p

                idle_counters = {}
                for name, (entry, _queue) in seeded_work_channels.items():
                    counters = backend.channels.counters(entry)
                    if counters[0] != counters[1] or counters[1] != counters[2]:
                        raise RuntimeError(
                            "cannot test full-ring backpressure from non-idle %s: %r" %
                            (name, counters))
                    idle_counters[name] = counters
                    full_consumer = g17p.next_producer(counters[2])
                    backend._write_dva(
                        entry["state_addrs"][0], struct.pack("<I", full_consumer))
                    backend._write_dva(
                        entry["state_addrs"][1], struct.pack("<I", full_consumer))
                backend.space.flush()
                backend.u.inst("dsb sy")
                rejected = {}
                try:
                    for name, (entry, _queue) in seeded_work_channels.items():
                        try:
                            backend.channels.next_free_slot(entry)
                        except RuntimeError as exc:
                            rejected[name] = str(exc)
                        else:
                            raise RuntimeError(
                                "%s accepted a full channel ring" % name)
                finally:
                    for name, (entry, _queue) in seeded_work_channels.items():
                        for address, value in zip(
                                entry["state_addrs"], idle_counters[name]):
                            backend._write_dva(address, struct.pack("<I", value))
                    backend.space.flush()
                    backend.u.inst("dsb sy")
                print(
                    "CHANNEL BACKPRESSURE WITNESS: full rings rejected before publication: %r"
                    % rejected,
                    flush=True,
                )
            print("REPEAT-FRESH: %d/%d submissions wrote their own fresh target"
                  % (executed, options.repeat_fresh), flush=True)
            for r in results:
                print("  #%d %#x changed=%d nonzero=%d drained=%s%s"
                      % (r["index"], r["dva"], r["changed"], r["nonzero"], r["drained"],
                         "" if r["stall"] is None else " stall=%s" % r["stall"]), flush=True)
            if executed < options.repeat_fresh:
                print("FAIL: repeated submission in one context is not yet demonstrated",
                      flush=True)
                return 2
            print("PASS: %d successive submissions in one context each rendered into their own "
                  "fresh target" % options.repeat_fresh, flush=True)
            return 0

        stalled = False
        for index in range(options.submissions):
            try:
                result = front.submit(memfd.fileno(), submit_args)
            except TimeoutError as error:
                submission = getattr(backend, "last_submission", None)
                if submission is None or not options.allow_stall:
                    raise
                states = {
                    kind: submission[kind]["queue"].indices()
                    for kind in ("tiling", "fragment")
                }
                print("DRM submission %d stalled: %s; queues=%s; scheduler_drained=%s" %
                      (index + 1, error, states,
                       backend.pair_retired(submission)), flush=True)
                stalled = True
                break
            submission = getattr(backend, "last_submission", None)
            if result != 0 or submission is None or not backend.pair_retired(submission):
                raise RuntimeError(
                    "DRM submission %d did not retire (return %r)" %
                    (index + 1, result))
            states = {
                kind: submission[kind]["queue"].indices()
                for kind in ("tiling", "fragment")
            }
            print("DRM submission %d retired: %s" %
                  (index + 1, states), flush=True)

        after = render_pages(backend, extent, invalidate_only=True)
        changed = changed_pages(before, after)
        matches, compared = matching_reference(after)
        print("Render result: %d/%d pages changed; %d/%d match reference" %
              (changed, len(after), matches, compared), flush=True)
        redirected_changed = 0
        if redirected is not None:
            redirected_after = sample_page_heads(
                backend, redirected, invalidate_only=True)
            redirected_changed = sum(
                left != right
                for left, right in zip(redirected_before, redirected_after))
            redirected_nonzero = sum(any(page) for page in redirected_after)
            redirected_output = save_redirected_heads(
                redirected, redirected_before, redirected_after)
            print("Redirected target %#x: %d/%d sampled page heads changed, %d nonzero" %
                  (redirected["dva"], redirected_changed, len(redirected_after),
                   redirected_nonzero), flush=True)
            print("Saved redirected target heads to %s" % redirected_output, flush=True)
            if options.dump_twiddled_target:
                readback_output, readback_manifest = save_twiddled_bgra8(
                    backend, redirected, options.width, options.height)
                print("Saved full twiddled/detiled target to %s; top pixels: %s" %
                      (readback_output, readback_manifest["top_pixel_words"][:4]),
                      flush=True)
        color_changed = 0
        if color_region is not None:
            color_after = sample_page_heads(
                backend, color_witness_region, invalidate_only=True)
            color_changed = sum(
                left != right
                for left, right in zip(color_before, color_after))
            color_nonzero = sum(any(page) for page in color_after)
            print("DRM color BO %#x: %d/%d sampled page heads changed, %d nonzero" %
                  (color_region["dva"], color_changed, len(color_after),
                   color_nonzero), flush=True)
            if options.dump_twiddled_target:
                readback_output, readback_manifest = save_twiddled_bgra8(
                    backend, color_region, options.width, options.height)
                print("Saved DRM color BO to %s; top pixels: %s" %
                      (readback_output,
                       readback_manifest["top_pixel_words"][:4]), flush=True)
        if stalled:
            print("OBSERVED: packed submission was consumed but did not retire", flush=True)
            return 2
        if redirected is not None and redirected_changed == 0:
            raise RuntimeError("submission wrote no sampled redirected-target page")
        if color_region is not None and color_changed == 0:
            raise RuntimeError("submission wrote no sampled DRM color-attachment page")
        if (redirected is None and color_region is None and changed == 0):
            raise RuntimeError("DRM submission left the observed target pages unchanged")
        if (redirected is None and color_region is None and
                compared and matches == 0):
            raise RuntimeError("render output matches no working-host reference page")

        print("Verified G17P load-bind prefix: %#x" %
              G17P_LOAD_PIPELINE_BIND_PREFIX, flush=True)
        print("OBSERVED: target pages changed during the legacy aggregate path, but this mode "
              "cannot attribute the change to the frontend submission; use --drain-staged "
              "--repeat-fresh for a render result", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
