#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fully replay one captured partial render and check all eight output buffers."""

import argparse
import json
import math
from pathlib import Path
import struct
from functools import partial

from agx_g17p_replay_latest_partial import execute_replay
from agx_g17p_vertex_observation import validate_vertex_observations


PAGE_SIZE = 0x4000
OUTPUT_SIZE = 0x10000
OUTPUT_BASES = tuple(0x10000058000 + index * 0x18000 for index in range(8))
OUTPUT_PAGES = tuple(
    base + offset
    for base in OUTPUT_BASES
    for offset in range(0, OUTPUT_SIZE, PAGE_SIZE)
)
PIXEL_OFFSETS = (0x7EFC, 0x7F00)
AUTHORED_TRIANGLES = 48_217


def workload_controls(triangles, viewport_x_shift):
    """Patch only our authored encoder count and viewport data, not firmware."""
    if not 1 <= triangles <= 2 * AUTHORED_TRIANGLES:
        raise ValueError("triangle count outside the authored workload range")
    if viewport_x_shift not in (0, 2):
        raise ValueError("viewport discriminator must be zero or two pixels")
    translation, = struct.unpack("<I", struct.pack("<f", 64.0 + viewport_x_shift))
    return ("--patch-render-u32", "%#x=%#x" % (0x1000018068, triangles * 3),
            "--patch-render-u32", "%#x=%#x" % (0x1000068910, translation))


def validate_outputs(attempt, *, triangles=AUTHORED_TRIANGLES, viewport_x_shift=0,
                     normalization_triangles=AUTHORED_TRIANGLES, observation_dva=None,
                     output_bases=OUTPUT_BASES, fragment_inputs=False, diagnostic_pages=()):
    workload_controls(triangles, viewport_x_shift)
    if not 1 <= normalization_triangles <= 2 * AUTHORED_TRIANGLES:
        raise ValueError("invalid authored normalization triangle count")
    pixels = tuple(offset + 4 * viewport_x_shift for offset in PIXEL_OFFSETS)
    report = json.loads((attempt / "render_watch.json").read_text())
    if fragment_inputs and observation_dva is None:
        raise ValueError("fragment observation needs its explicit observer page")
    pages = {int(record["dva"]): record for record in report}
    if (len(output_bases) != 8 or any(base < 0 or base % PAGE_SIZE for base in output_bases)):
        raise ValueError("replay requires eight aligned output buffers")
    expected_pages = {base + offset for base in output_bases
                      for offset in range(0, OUTPUT_SIZE, PAGE_SIZE)}
    if len(expected_pages) != 32:
        raise ValueError("replay output buffers overlap")
    if observation_dva is not None:
        if (triangles != 8 or normalization_triangles != 8 or
                observation_dva % PAGE_SIZE or observation_dva in expected_pages):
            raise ValueError("vertex observation requires a separate page and eight triangles")
        expected_pages.add(observation_dva)
    diagnostics = []
    for address in diagnostic_pages:
        if address < 0 or address % PAGE_SIZE or address in expected_pages:
            raise ValueError("diagnostic page must be aligned and disjoint from every witness")
        expected_pages.add(address)
    if set(pages) != expected_pages or len(pages) != len(report):
        raise RuntimeError("replay did not retain every output page")
    for address in diagnostic_pages:
        record = pages[address]
        before = (attempt / record["before_file"]).read_bytes()
        after = (attempt / record["after_file"]).read_bytes()
        if len(before) != PAGE_SIZE or len(after) != PAGE_SIZE:
            raise RuntimeError("incomplete diagnostic page")
        diagnostics.append(dict(dva=address, initially_zero=not any(before),
            changed_bytes=sum(a != b for a, b in zip(before, after)),
            execution_claim="none; data-only observation, not a color witness"))
    observation = None
    if observation_dva is not None:
        record = pages[observation_dva]
        observation = validate_vertex_observations(
            (attempt / record["before_file"]).read_bytes(),
            (attempt / record["after_file"]).read_bytes(), fragment_inputs=fragment_inputs)
        observation["dva"] = observation_dva
    values, rows = [], []
    for index, base in enumerate(output_bases):
        records = [pages[base + offset]
                   for offset in range(0, OUTPUT_SIZE, PAGE_SIZE)]
        before = b"".join((attempt / record["before_file"]).read_bytes()
                          for record in records)
        after = b"".join((attempt / record["after_file"]).read_bytes()
                         for record in records)
        if len(before) != OUTPUT_SIZE or len(after) != OUTPUT_SIZE:
            raise RuntimeError("incomplete output buffer %d" % index)
        if any(before):
            raise RuntimeError("output buffer %d was not initially zero" % index)
        samples = tuple(struct.unpack_from("<f", after, offset)[0]
                        for offset in pixels)
        expected = triangles * (index + 1) / normalization_triangles
        tolerance = min(0.02, expected * 0.02)
        pixel_ok = all(math.isfinite(value) and abs(value - expected) < tolerance
                       for value in samples)
        remaining = bytearray(after)
        for offset in pixels:
            remaining[offset:offset + 4] = bytes(4)
        outside_bytes = sum(value != 0 for value in remaining)
        rows.append(dict(attachment=index, pixels=samples, expected=expected,
                         tolerance=tolerance, outside_bytes=outside_bytes,
                         exact=pixel_ok and not outside_bytes))
        values.append(samples)
    result = dict(execution_path="replay-only diagnostic", triangles=triangles,
                  normalization_triangles=normalization_triangles,
                  viewport_x_shift=viewport_x_shift, outputs=rows,
                  output_bases=output_bases, vertex_observation=observation,
                  diagnostic_pages=diagnostics)
    (attempt / "single_partial_output_oracle.json").write_text(
        json.dumps(result, indent=2) + "\n")
    if not all(row["exact"] for row in rows) or (observation is not None and not observation["exact"]):
        raise RuntimeError("full replay output mismatch: %s" % result)
    if observation is not None:
        print("VERTEX OBSERVATION FULL-BUFFER PASS: 24 vertices, zero tail", flush=True)
        if fragment_inputs:
            print("FRAGMENT OBSERVATION FULL-BUFFER PASS: 16 records, zero outside", flush=True)
    print("SINGLE PARTIAL FULL-OUTPUT PASS: %r" % values, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--triangles", type=int, default=AUTHORED_TRIANGLES)
    parser.add_argument("--viewport-x-shift", type=int, choices=(0, 2), default=0)
    parser.add_argument("--normalization-triangles", type=int, default=AUTHORED_TRIANGLES,
                        help="denominator in the captured own-source shader's uniforms")
    parser.add_argument("--no-bootstrap", action="store_true",
                        help="RID 1 was already reset and raw-chainloaded")
    args = parser.parse_args()
    if not 1 <= args.normalization_triangles <= 2 * AUTHORED_TRIANGLES:
        parser.error("invalid authored normalization triangle count")
    controls = workload_controls(args.triangles, args.viewport_x_shift)
    manifest = json.loads((args.snapshot / "manifest.json").read_text())
    if int(manifest["chip_id"]) != 0x8140 or manifest["unsupported_entries"]:
        raise RuntimeError("snapshot must contain complete T8140 mappings")
    execute_replay(
        label="rid1_single_partial",
        snapshot=args.snapshot,
        output_dvas=OUTPUT_PAGES,
        validate=partial(validate_outputs, triangles=args.triangles,
                         viewport_x_shift=args.viewport_x_shift,
                         normalization_triangles=args.normalization_triangles),
        extra_args=controls,
        bootstrap=not args.no_bootstrap,
        wait_for_work_events=1,
    )


if __name__ == "__main__":
    main()
