#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-owned G17P code container for the add3 test kernel.

This is caller workload, not firmware or replayed GPU state.  The two short
program bodies are compiler output for our own ``a[i] + b[i]`` source.  The
container/helper prefix is constructed field by field.  Hardware proved that
the remaining 15 KiB of the original generic compiler image is not consumed by
this workload, so the executable mapping is zero outside this explicit 1 KiB
closure.
"""

import hashlib
import struct


PAGE = 0x4000
CONTAINER_SIZE = 0x400
ADD3_CODE_SHA256 = "3b02834fd67a0887f3bd4c83a188abb444ae0ca09588abd98b9bef91a1710a7c"

# The 64-byte constant program and 56-byte main program emitted for the public
# add3 source.  Naming them separately keeps executable bytes distinguishable
# from the program-container records around them.
ADD3_CONSTANT_PROGRAM = bytes.fromhex(
    "030007000200000060000e0000000600"
    "06000600060006000600060006000600"
    "06000600060006000600060006000600"
    "06000600060006000600060006000600"
)
ADD3_MAIN_PROGRAM = bytes.fromhex(
    "1ca01006671054000001200051010040"
    "46006700440401012000510100404600"
    "09051c0100c0e7005400020121001100"
    "009011000e000000"
)


def _fill_helper_table(image, base):
    """Build one of the two identical 0x80-byte helper-record tables."""
    for index, opcode in enumerate((0x60, 0x50, 0x40, 0x30, 0x20, 0x10)):
        offset = base + index * 0x10
        image[offset:offset + 0x10] = bytes.fromhex(
            "0f0054%02x000000000000060006000600" % opcode)
    terminal = bytes.fromhex("f703aa008f0254010600060006000600")
    image[base + 0x60:base + 0x70] = terminal
    image[base + 0x70:base + 0x80] = terminal


def build_add3_code_image():
    """Build the complete 16 KiB mapping from the proven 1 KiB closure."""
    image = bytearray(PAGE)

    # Leading sized block.  Its unoccupied entries carry the compiler's
    # explicit 0x0006 sentinel rather than implicit zero padding.
    struct.pack_into("<I", image, 0, 0x340)
    for offset in range(0x40, 0x340, 2):
        struct.pack_into("<H", image, offset, 0x0006)
    _fill_helper_table(image, 0x100)
    _fill_helper_table(image, 0x200)

    # Authored add3 block: 0x40-byte header, 0x40-byte constant program, then
    # the 56-byte main program and eight bytes of alignment padding.
    struct.pack_into("<I", image, 0x340, 0xC0)
    image[0x380:0x3C0] = ADD3_CONSTANT_PROGRAM
    image[0x3C0:0x3C0 + len(ADD3_MAIN_PROGRAM)] = ADD3_MAIN_PROGRAM

    if any(image[CONTAINER_SIZE:]):
        raise RuntimeError("G17P add3 code closure exceeds its 1 KiB container")
    digest = hashlib.sha256(image).hexdigest()
    if digest != ADD3_CODE_SHA256:
        raise RuntimeError("G17P add3 source-built code image hash mismatch")
    return bytes(image)
