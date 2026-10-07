#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compose a visible triangle from verified G17P tile submissions."""

import argparse
import collections
import ctypes
import hashlib
import json
import os
import pathlib
import struct
import sys
import tempfile
import time
import types

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.setdefault("AGX_GPU", "G17")

from agx_g17p_shim_submit import packed_cmdbuf                 # noqa: E402
from m1n1.agx.shim import DRMAsahiShim                         # noqa: E402
from m1n1.agx.uapi import drm_asahi_cmdbuf_t                   # noqa: E402


PAGE = 0x4000
TILE = 64
ARTIFACTS = pathlib.Path(os.environ.get(
    "G17P_ARTIFACTS", "~/asahi_re/artifacts/agx_g17p")).expanduser()


def morton2d(x, y):
    value = 0
    for bit in range(6):
        value |= ((x >> bit) & 1) << (2 * bit)
        value |= ((y >> bit) & 1) << (2 * bit + 1)
    return value


def detile_page(raw):
    if len(raw) != PAGE:
        raise ValueError("a 64x64 BGRA tile must occupy one 16 KiB page")
    linear = bytearray(TILE * TILE * 4)
    for y in range(TILE):
        for x in range(TILE):
            source = morton2d(x, y) * 4
            destination = (y * TILE + x) * 4
            linear[destination:destination + 4] = raw[source:source + 4]
    return bytes(linear)


def triangle_tiles(columns, rows):
    apex_y = max(2, rows // 6)
    base_y = min(rows - 5, (rows * 3) // 4)
    apex_x = columns // 2
    left_x = columns // 4
    right_x = columns - left_x - 1

    tiles = set()
    span = base_y - apex_y
    for y in range(apex_y, base_y + 1):
        step = y - apex_y
        left = round(apex_x + (left_x - apex_x) * step / span)
        right = round(apex_x + (right_x - apex_x) * step / span)
        tiles.add((left, y))
        tiles.add((right, y))
    for x in range(left_x, right_x + 1):
        tiles.add((x, base_y))
    return sorted(tiles, key=lambda item: (item[1], item[0]))


def compose_tile(linear, tile, width, height, columns, rows, tile_x, tile_y):
    # The retained pass currently writes a 32x32 footprint in its nominal
    # 64x64 target. Pack those observed pixels on a 32-pixel grid so adjacent
    # edge samples touch; never synthesize or recolor a pixel.
    cell = TILE // 2
    origin_x = (width - columns * cell) // 2
    origin_y = (height - rows * cell) // 2
    for local_y in range(TILE):
        destination_y = origin_y + tile_y * cell + local_y
        if not 0 <= destination_y < height:
            continue
        for local_x in range(TILE):
            source = (local_y * TILE + local_x) * 4
            pixel = tile[source:source + 4]
            if not any(pixel):
                continue
            destination_x = origin_x + tile_x * cell + local_x
            if not 0 <= destination_x < width:
                continue
            destination = (destination_y * width + destination_x) * 4
            linear[destination:destination + 4] = pixel


def save_composed(linear, raw_tiles, width, height, output):
    output.mkdir(parents=True, exist_ok=False)
    raw = b"".join(raw_tiles)
    (output / "gpu_tiles.twiddled.bin").write_bytes(raw)
    (output / "surface.detiled.bgra").write_bytes(linear)

    rgb = bytearray(width * height * 3)
    for pixel in range(width * height):
        source = pixel * 4
        destination = pixel * 3
        rgb[destination:destination + 3] = (
            linear[source + 2], linear[source + 1], linear[source])
    (output / "triangle.ppm").write_bytes(
        ("P6\n%d %d\n255\n" % (width, height)).encode("ascii") + rgb)

    pixels = collections.Counter(struct.unpack_from(
        "<I", linear, offset)[0] for offset in range(0, len(linear), 4))
    return {
        "width": width,
        "height": height,
        "gpu_tile_count": len(raw_tiles),
        "gpu_tiles_sha256": hashlib.sha256(raw).hexdigest(),
        "linear_sha256": hashlib.sha256(linear).hexdigest(),
        "top_pixel_words": [
            {"value": "0x%08x" % value, "count": count}
            for value, count in pixels.most_common(8)
        ],
    }


def present(backend, linear, width, height):
    video = backend.u.ba.video
    if (width, height) != (video.width, video.height):
        raise RuntimeError("surface and boot framebuffer dimensions differ")
    stride = video.stride
    frame = bytearray(stride * height)
    row_bytes = width * 4
    for y in range(height):
        frame[y * stride:y * stride + row_bytes] = (
            linear[y * row_bytes:(y + 1) * row_bytes])
    backend.u.iface.writemem(video.base, frame)
    backend.u.proxy.dc_civac(video.base, len(frame))
    print("Presented %#x bytes at framebuffer %#x (%dx%d stride %#x)" % (
        len(frame), video.base, width, height, stride), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-present", action="store_true",
                        help="save and verify the image without changing the display")
    args = parser.parse_args()

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        width = int(backend.u.ba.video.width)
        height = int(backend.u.ba.video.height)
        columns = (width + TILE - 1) // TILE
        rows = (height + TILE - 1) // TILE

        memfd.truncate(PAGE * 2)
        bootstrap_va = front.create_bo_from_memfd(
            memfd.fileno(), 0, PAGE, 0)
        bootstrap_obj = front.bos[0]
        bootstrap_obj._no_push = True
        scratch_va = front.create_bo_from_memfd(
            memfd.fileno(), PAGE, PAGE, 0)
        scratch_obj = front.bos[PAGE]
        scratch_obj._no_push = True

        bootstrap_body = packed_cmdbuf(
            64, 64, color_attachment={
                "type": 0, "size": PAGE, "pointer": bootstrap_va})
        bootstrap_storage = ctypes.create_string_buffer(bootstrap_body)
        bootstrap_args = types.SimpleNamespace(
            cmdbuf=ctypes.addressof(bootstrap_storage))
        bootstrap_before = backend._read_dva(bootstrap_va, PAGE)
        bootstrap_result = front.submit(memfd.fileno(), bootstrap_args)
        bootstrap_after = backend._read_dva(bootstrap_va, PAGE)
        bootstrap_changed = sum(
            left != right for left, right in zip(
                bootstrap_before, bootstrap_after))
        if bootstrap_result != 0 or bootstrap_changed == 0:
            raise RuntimeError("bootstrap render did not change its target")
        print("Bootstrap rendered: %d bytes changed" % bootstrap_changed,
              flush=True)

        context_id = front.g17p_context_for_fd(memfd.fileno())
        supplied = front.g17p_supplied()
        tiles = triangle_tiles(columns, rows)
        print("Triangle outline: %d verified GPU submissions" % len(tiles),
              flush=True)
        witnesses = []
        raw_tiles = []
        linear = bytearray(width * height * 4)
        for index, (tile_x, tile_y) in enumerate(tiles, 1):
            backend._write_dva(scratch_va, bytes(PAGE))
            before = backend._read_dva(scratch_va, PAGE)
            if any(before):
                raise RuntimeError(
                    "scratch target did not clear before tile %d" % index)

            body = packed_cmdbuf(
                64, 64, color_attachment={
                    "type": 0, "size": PAGE, "pointer": scratch_va})
            drm = drm_asahi_cmdbuf_t.parse(body)
            target_obj = types.SimpleNamespace(_addr=scratch_va, _size=PAGE)
            backend.submit_drm(
                drm, (target_obj,), context_id=context_id, **supplied)

            after = backend._read_dva(scratch_va, PAGE)
            changed = sum(left != right for left, right in zip(before, after))
            nonzero = sum(value != 0 for value in after)
            submission = backend.last_submission
            retired = backend.pair_retired(submission)
            print("  tile %02d/%02d (%02d,%02d): changed=%d nonzero=%d "
                  "retired=%s" % (
                      index, len(tiles), tile_x, tile_y,
                      changed, nonzero, retired), flush=True)
            # Scheduler retirement is diagnostic only. Hardware has repeatedly
            # shown that it can remain linked after a target-changing render.
            if changed == 0 or nonzero == 0:
                raise RuntimeError("triangle tile %d did not execute" % index)

            raw_tiles.append(after)
            compose_tile(
                linear, detile_page(after), width, height,
                columns, rows, tile_x, tile_y)
            witnesses.append({
                "index": index,
                "tile_x": tile_x,
                "tile_y": tile_y,
                "scratch_dva": "0x%x" % scratch_va,
                "changed_bytes": changed,
                "nonzero_bytes": nonzero,
                "raw_sha256": hashlib.sha256(after).hexdigest(),
            })

        output = ARTIFACTS / (
            "triangle_photo_%s" % time.strftime("%Y%m%d_%H%M%S"))
        linear = bytes(linear)
        manifest = save_composed(
            linear, raw_tiles, width, height, output)
        colored_pixels = sum(
            any(linear[offset:offset + 4])
            for offset in range(0, len(linear), 4))
        if colored_pixels == 0:
            raise RuntimeError("verified tile writes disappeared from composed image")
        manifest.update({
            "composition": "host-arranged verified GPU-written 64x64 tiles",
            "scratch_dva": "0x%x" % scratch_va,
            "submission_count": len(tiles),
            "colored_pixels": colored_pixels,
            "submissions": witnesses,
        })
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n")
        print("Saved verified triangle to %s (%d colored pixels)" % (
            output, colored_pixels), flush=True)

        if not args.no_present:
            present(backend, linear, width, height)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
