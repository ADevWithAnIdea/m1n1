#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full native constant-pressure replay with independent full-buffer oracles."""
import argparse
import json
from pathlib import Path
import struct

from agx_g17p_replay_latest_partial import execute_replay

PAGE = 0x4000
SIZE = 0x10000


def validate(attempt, ordinal, x_shift):
    rows = json.loads((attempt / "render_watch.json").read_text())
    pages = {int(row["dva"]): row for row in rows}
    bases = tuple(0x10000058000 + index * 0x18000 for index in range(ordinal * 8))
    expected_pages = {base + offset for base in bases for offset in range(0, SIZE, PAGE)}
    if len(rows) != len(pages) or set(pages) != expected_pages:
        raise RuntimeError("constant pressure replay lost output ownership")
    physical = [int(row["pa"]) for row in rows]
    if len(set(physical)) != len(physical) or any(pa % PAGE for pa in physical):
        raise RuntimeError("constant pressure replay aliases output backing")
    for index, base in enumerate(bases):
        selected = [pages[base + offset] for offset in range(0, SIZE, PAGE)]
        before = b"".join((attempt / row["before_file"]).read_bytes() for row in selected)
        after = b"".join((attempt / row["after_file"]).read_bytes() for row in selected)
        expected = bytearray(SIZE)
        for offset in (0x7efc + x_shift * 4, 0x7f00 + x_shift * 4):
            struct.pack_into("<f", expected, offset, float((index % 8 + 1) * 16384))
        previous = index // 8 < ordinal - 1
        if before != (bytes(expected) if previous else bytes(SIZE)):
            raise RuntimeError("constant output %d has invalid prior state" % index)
        if after != bytes(expected):
            covered = [struct.unpack_from("<f", after, offset + x_shift * 4)[0]
                       for offset in (0x7efc, 0x7f00)]
            raise RuntimeError("constant output %d full image differs; covered=%r" % (index, covered))
        if previous and before != after:
            raise RuntimeError("constant replay changed a prior output")
    print("CONSTANT PRESSURE FULL-BUFFER ORACLE PASS: ordinal %d, %d whole buffers" %
          (ordinal, len(bases)), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--x-shift", type=int, choices=(0, 2), default=0)
    args = parser.parse_args()
    manifest = json.loads((args.snapshot / "manifest.json").read_text())
    if manifest.get("capture_label") != "rid1_constant_pressure_sequence":
        raise ValueError("requires the explicitly identified own constant-pressure capture")
    ordinal = int(manifest["native_sequence_ordinal"])
    if ordinal not in (1, 2):
        raise ValueError("constant pressure oracle supports two native owners")
    output_pages = tuple(0x10000058000 + index * 0x18000 + offset
                         for index in range(ordinal * 8) for offset in range(0, SIZE, PAGE))
    execute_replay(label="constant_pressure_%d" % ordinal, snapshot=args.snapshot,
                   output_dvas=output_pages,
                   validate=lambda attempt: validate(attempt, ordinal, args.x_shift))


if __name__ == "__main__":
    main()
