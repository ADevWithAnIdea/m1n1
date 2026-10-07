# SPDX-License-Identifier: MIT
"""Exact full-buffer oracle for our 24-vertex producer observation shader."""
import struct
import math


OBSERVATION_SIZE = 0x4000
VERTICES = 24
WORDS_PER_VERTEX = 9


def validate_vertex_observations(before, after, *, fragment_inputs=False,
                                 triangle_varyings=False):
    """Return evidence even for missing/corrupted writes; never accept stale data."""
    if len(before) != OBSERVATION_SIZE or len(after) != OBSERVATION_SIZE:
        raise ValueError("vertex observation requires two complete 16 KiB buffers")
    if triangle_varyings and not fragment_inputs:
        raise ValueError("triangle discriminator requires both stage observers")
    def values(primitive):
        value = (primitive + 1) / 255 if triangle_varyings else 1 / 8
        return (value * component for component in range(1, 9))
    expected = b"".join(struct.pack("<9f", vertex + 1, *values(vertex // 3))
                        for vertex in range(VERTICES))
    # The mode-2 authored shader divides by 255 then multiplies in float32.
    # Permit at most 1e-7 arithmetic/interpolation error, never marker changes.
    tolerance = 1e-7 if triangle_varyings else 0
    def matches(actual, wanted, word):
        if actual == wanted:
            return True
        if not tolerance or word % 9 == 0:
            return False
        value, goal = struct.unpack("<f", actual)[0], struct.unpack("<f", wanted)[0]
        return math.isfinite(value) and abs(value - goal) <= tolerance
    bad_words = [offset // 4 for offset in range(0, len(expected), 4)
                 if not matches(after[offset:offset + 4], expected[offset:offset + 4], offset // 4)]
    fragment_expected = b"".join(struct.pack("<9f", record // 2 + 1,
                                    *values(record // 2))
                                for record in range(16)) if fragment_inputs else b""
    fragment_bad_words = [offset // 4 for offset in range(0, len(fragment_expected), 4)
        if not matches(after[0x400 + offset:0x404 + offset],
                       fragment_expected[offset:offset + 4], offset // 4)]
    outside = after[len(expected):0x400] + after[0x400 + len(fragment_expected):]
    outside_bytes = sum(byte != 0 for byte in outside)
    return dict(vertices=VERTICES, initially_zero=not any(before),
                bad_words=bad_words, outside_bytes=outside_bytes,
                values=[struct.unpack_from("<9f", after, vertex * WORDS_PER_VERTEX * 4)
                        for vertex in range(VERTICES)],
                fragment_inputs=fragment_inputs, fragment_bad_words=fragment_bad_words,
                triangle_varyings=triangle_varyings, varying_tolerance=tolerance,
                fragment_values=([struct.unpack_from("<9f", after, 0x400 + record * 36)
                                  for record in range(16)] if fragment_inputs else []),
                exact=not any(before) and not bad_words and not fragment_bad_words and not outside_bytes)
