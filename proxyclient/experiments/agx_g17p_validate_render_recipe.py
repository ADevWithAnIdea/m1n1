#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require the parameterized G17P render recipes to match a live capture."""

import dataclasses
import json
import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.agx import g17p_render as render  # noqa: E402


SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/pre_work_0x83_v2_20260724_193713")
PAGE_SIZE = 0x4000
DESCRIPTORS = {
    "tiling": (0xfffffc20c0018000, 0x60),
    "fragment": (0xfffffc20c00b0000, 0xa0),
}


def snapshot_reader():
    manifest = json.loads((SNAPSHOT / "manifest.json").read_text())

    def value(raw):
        return int(raw, 0) if isinstance(raw, str) else int(raw)

    pages = {
        value(mapping["va"]): value(mapping["blob_index"])
        for mapping in manifest["mappings"]
        if mapping.get("blob_index") is not None
    }
    handle = open(SNAPSHOT / manifest["ram_file"], "rb")

    def read(address, size):
        output = b""
        while size:
            page = address & ~(PAGE_SIZE - 1)
            handle.seek(pages[page] * PAGE_SIZE)
            body = handle.read(PAGE_SIZE)
            offset = address & (PAGE_SIZE - 1)
            take = min(size, PAGE_SIZE - offset)
            output += body[offset:offset + take]
            address += take
            size -= take
        return output

    return read


def captured_registers(read, kind):
    address, offset = DESCRIPTORS[kind]
    body = read(address, PAGE_SIZE)
    result = []
    empty = 0
    while offset + 12 <= len(body):
        number, value = struct.unpack_from("<IQ", body, offset)
        if number == 0 and value == 0:
            empty += 1
            if empty == 3:
                break
        else:
            empty = 0
            result.append((number, value))
        offset += 12
    return result


def compare(label, built, captured):
    if built == captured:
        print("  ok  %s: %d ordered writes" % (label, len(built)))
        return
    for index, (left, right) in enumerate(zip(built, captured)):
        if left != right:
            raise AssertionError(
                "%s differs at write %d: built %r captured %r"
                % (label, index, left, right))
    raise AssertionError(
        "%s length differs: built %d captured %d"
        % (label, len(built), len(captured)))


def main():
    params = render.G17PRenderParameters(
        width=2408,
        height=1506,
        context_base=0x1000000000,
        tilemap=0x10001b0000,
        heapmeta=0x10001b5000,
        tpc=0x1000240000,
        deflake_1=0x10000682a0,
        deflake_2=0x1000068020,
        deflake_3=0x1000068000,
        encoder=0x1000018000,
        ta_status=0x1000078000,
        store_pipeline_bind=0,
        store_pipeline=0x10001990640,
        load_pipeline_bind=0x0007800000000040,
        load_pipeline=0x10001990240,
        scissor_array=0x100019a0000,
        depth_bias_array=0x10001af8000,
        aux_fb=0x10001aa8000,
        fragment_status=0x10001a8000,
    )
    read = snapshot_reader()
    compare(
        "tiling recipe",
        render.build_tiling_registers(params),
        captured_registers(read, "tiling"),
    )
    compare(
        "fragment recipe",
        render.build_fragment_registers(params),
        captured_registers(read, "fragment"),
    )
    later = dataclasses.replace(
        params, lifecycle_ordinal=1, queue_pair=1,
        queue_item_index=0, native_cycle_registers=True,
        native_record_index_register=True,
        native_status_registers=True)
    tiling = dict(render.build_tiling_registers(later))
    fragment = dict(render.build_fragment_registers(later))
    if not all(tiling[number] == 0x000000cb01000126
               for number in (0x1ca10, 0x014a1, 0x0a349)):
        raise AssertionError("later tiling lifecycle registers disagree")
    if not all(fragment[number] == 0x000000cb01000125
               for number in (0x160e0, 0x01499, 0x0a341)):
        raise AssertionError("later fragment lifecycle registers disagree")
    print("  ok  second publication lifecycle values")
    if not (
            all(tiling[number] == 0x101
                for number in (0x10209, 0x1c9f0, 0x14320))
            and all(fragment[number] == 0x101
                    for number in (0x10211, 0x10420))):
        raise AssertionError("second publication work stamps disagree")
    native_b2 = dataclasses.replace(params, lifecycle_ordinal=3)
    if not (
            all(dict(render.build_tiling_registers(native_b2))[number] == 0x104
                for number in (0x10209, 0x1c9f0, 0x14320))
            and all(dict(render.build_fragment_registers(native_b2))[number] == 0x104
                    for number in (0x10211, 0x10420))):
        raise AssertionError("sparse work-stamp progression disagrees")
    print("  ok  sparse command-register work stamps")
    if not (
            tiling[0x1ca30] == 0x758020
            and tiling[0x16c39] == 0x758020
            and tiling[0x1c910] == 0x80145
            and tiling[0x14318] == 0x1000660001
            and fragment[0x1ca28] == 0x758020
            and fragment[0x14080] == 0x1000788001):
        raise AssertionError("pair-one item register fields disagree")
    print("  ok  pair-one item register fields")
    local_status = dataclasses.replace(params, queue_item_index=1)
    tiling = dict(render.build_tiling_registers(local_status))
    fragment = dict(render.build_fragment_registers(local_status))
    if not (
            tiling[0x14318] == 0x1000078041
            and fragment[0x14080] == 0x10001a8041):
        raise AssertionError("queue-local status slots require an experiment switch")
    print("  ok  queue-local status slots advance unconditionally")
    local = dataclasses.replace(
        params, queue_item_index=1, local_item_registers=True)
    tiling = dict(render.build_tiling_registers(local))
    fragment = dict(render.build_fragment_registers(local))
    if not (
            tiling[0x1ca30] == 0x178040
            and tiling[0x16c39] == 0x178040
            and tiling[0x1c910] == 0x80009
            and tiling[0x14318] == 0x1000078041
            and fragment[0x1ca28] == 0x178040
            and fragment[0x14080] == 0x10001a8041):
        raise AssertionError("pair-local second-item register fields disagree")
    print("  ok  pair-local second-item register fields")
    print("G17P render-register recipe gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
