#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Own-source G17P preambles used by the indirect compute experiment.

Both programs were compiled from ``g17p_native_compute.metal`` and captured
through their public GPU mappings.  They are caller workload, not firmware or
replayed GPU state.  A real Mesa client supplies equivalent compiler output.
"""

import struct


INDIRECT_ADD3_CAPTURE_DVA = 0x100000B0000
GRID_SETUP_CAPTURE_DVA = 0x100000A8000

INDIRECT_ADD3_PREAMBLE = bytes.fromhex(
    "2ca00200120880003c800200040000006ce04200020054007c80420004000000"
    "8ca0420004000c009c8042000400000067005424020000005700004026006700"
    "542c160000005104005026006700543818000000510002402600670054301800"
    "000057040040260077002a41000000007701aa0e000000020600f7002a000000"
    "000000001c8002000000000014811106000000000c800200040000009f115400"
    "020008a810051c800200040000000f1254004c004b0001045b0001040b240944"
    "1b2609042b2809043b2a09046b2c0904bb3809047b3009048b3209049b340904"
    "ab360904030007000200000060000e"
)

GRID_SETUP_PREAMBLE = bytes.fromhex(
    "2ca0020012087c003c800200040000006700542c020000005900024026006700"
    "54240200000057000040260077002a410000000077012a08000000020000f700"
    "2a000000000000001c8002000000000014811106000000000c80020004000000"
    "9f115400020008a810051c800200040000000f1254004c006b0001047b000104"
    "4b2c09445b2e09040b2401044b250f002200001400001b2601045b270f002200"
    "001400002b2801046b290f002200001400003b2a01047b2b0f00220000140000"
    "2c8c0927600000803c8e08270c8808471c8a084767205408020000001d040040"
    "220067404400000000005d04004022006b8801249f20541200100000d0260a00"
    "7b8a01049f00541400140800d0260a008b8c01049f00541600181000d0260a00"
    "0e"
)


def _relocate_allocation_field(body, capture_dva, target_dva):
    """Relocate the 0x2000-granular allocation field at preamble +0x06."""
    capture_dva = int(capture_dva)
    target_dva = int(target_dva)
    capture_chunk = capture_dva // 0x2000
    target_chunk = target_dva // 0x2000
    out = bytearray(body)
    value = struct.unpack_from("<H", out, 6)[0]
    value += target_chunk - capture_chunk
    if not 0 <= value <= 0xFFFF:
        raise ValueError("indirect preamble relocation exceeds its u16 field")
    struct.pack_into("<H", out, 6, value)
    return bytes(out)


def build_indirect_add3_preamble(shader_dva):
    return _relocate_allocation_field(
        INDIRECT_ADD3_PREAMBLE, INDIRECT_ADD3_CAPTURE_DVA, shader_dva)


def build_grid_setup_preamble(shader_dva):
    return _relocate_allocation_field(
        GRID_SETUP_PREAMBLE, GRID_SETUP_CAPTURE_DVA, shader_dva)
