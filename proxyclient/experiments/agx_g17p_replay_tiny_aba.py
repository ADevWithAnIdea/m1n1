#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full-capture A2 replay diagnostic: A accumulates again, B stays unchanged.

This deliberately uses initialized A/B targets to study owner reuse. It is a
replay control, not the independent-output repeated-partial milestone.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct

from agx_g17p_replay_latest_partial import execute_replay


PAGE_SIZE = 0x4000
OUTPUT_SIZE = 0x10000
BASES = (0x10000058000, 0x10000118000)
OUTPUTS = tuple(base + index * 0x18000 for base in BASES for index in range(8))
OUTPUT_PAGES = tuple(base + offset for base in OUTPUTS
                     for offset in range(0, OUTPUT_SIZE, PAGE_SIZE))
PIXELS = (0x7EFC, 0x7F00)


def check_buffer(body, expected, label):
    if len(body) != OUTPUT_SIZE:
        raise RuntimeError(label + ": incomplete buffer")
    values = tuple(struct.unpack_from("<f", body, offset)[0] for offset in PIXELS)
    if not all(math.isfinite(value) and abs(value - expected) < 0.02 for value in values):
        raise RuntimeError("%s: expected %g, got %r" % (label, expected, values))
    remaining = bytearray(body)
    for offset in PIXELS:
        remaining[offset:offset + 4] = bytes(4)
    if any(remaining):
        raise RuntimeError(label + ": nonzero outside expected pixels")
    return values


def validate_snapshot(snapshot, *, completed=2, outputs=OUTPUTS):
    manifest = json.loads((snapshot / "manifest.json").read_text())
    if int(manifest["chip_id"]) != 0x8140 or manifest["unsupported_entries"]:
        raise RuntimeError("snapshot must contain complete T8140 mappings")
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    tables = (snapshot / manifest["tables_file"]).read_bytes()
    pending = manifest.get("held_native_producer_stores", [])
    if pending:
        raw = (snapshot / manifest["ram_before_publication_file"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest["ram_before_publication_sha256"]:
            raise RuntimeError("literal pre-publication RAM hash mismatch")
        materialized = bytearray(raw)
        indices = {int(page["original_pa"]): int(page["index"])
                   for page in manifest["blob_pages"]}
        if len(pending) != 2 or {row["channel"] for row in pending} != {"TA_2", "3D_2"}:
            raise RuntimeError("not the exact native A2 publication pair")
        for row in pending:
            if row["width"] != 32 or row["before"] != completed or row["value"] != completed + 1:
                raise RuntimeError("unexpected native publication store")
            pa = int(row["pa"])
            offset = indices[pa & ~(PAGE_SIZE - 1)] * PAGE_SIZE + (pa & (PAGE_SIZE - 1))
            if struct.unpack_from("<I", materialized, offset)[0] != row["before"]:
                raise RuntimeError("native store preimage mismatch")
            struct.pack_into("<I", materialized, offset, row["value"])
        if bytes(materialized) != ram:
            raise RuntimeError("replay image differs outside the trapped native stores")
    for data, records, digest in ((ram, manifest["blob_pages"], manifest["ram_sha256"]),
                                  (tables, manifest["table_page_records"], manifest["tables_sha256"])):
        if len(data) != PAGE_SIZE * len(records) or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError("incomplete or corrupt capture image")
        for record in records:
            start = int(record["index"]) * PAGE_SIZE
            if hashlib.sha256(data[start:start + PAGE_SIZE]).hexdigest() != record["sha256"]:
                raise RuntimeError("capture page hash mismatch")
    for region in manifest["fixed_regions"]:
        data = (snapshot / region["file"]).read_bytes()
        if len(data) != int(region["size"]) or hashlib.sha256(data).hexdigest() != region["sha256"]:
            raise RuntimeError("fixed capture region hash mismatch")
    mappings = {int(mapping["va"]): mapping for root in manifest["root_mappings"]
                if int(root["root_ctx_id"]) == 1 and int(root["selector"]) == 0
                for mapping in root["mappings"]}
    physical = set()
    for index, base in enumerate(outputs):
        body = bytearray()
        for offset in range(0, OUTPUT_SIZE, PAGE_SIZE):
            mapping = mappings[base + offset]
            pa = int(mapping["pa"])
            if pa in physical:
                raise RuntimeError("A/B outputs alias physical backing")
            physical.add(pa)
            start = int(mapping["blob_index"]) * PAGE_SIZE
            body.extend(ram[start:start + PAGE_SIZE])
        if index // 8 < completed:
            check_buffer(body, float(index % 8 + 1), "captured prefix output %d" % index)
        elif len(body) != OUTPUT_SIZE or any(body):
            raise RuntimeError("future output %d was not entirely zero" % index)
    print("FULL CAPTURE AND PREFIX OUTPUT PASS: %d RAM pages, %d buffers, completed=%d" %
          (len(manifest["blob_pages"]), len(outputs), completed), flush=True)
    return manifest


def validate_replay(attempt):
    records = json.loads((attempt / "render_watch.json").read_text())
    pages = {int(record["dva"]): record for record in records}
    if set(pages) != set(OUTPUT_PAGES) or len(records) != len(OUTPUT_PAGES):
        raise RuntimeError("replay did not retain exactly every A/B output page")
    for index, base in enumerate(OUTPUTS):
        selected = [pages[base + offset] for offset in range(0, OUTPUT_SIZE, PAGE_SIZE)]
        before = b"".join((attempt / record["before_file"]).read_bytes() for record in selected)
        after = b"".join((attempt / record["after_file"]).read_bytes() for record in selected)
        expected = float(index % 8 + 1)
        check_buffer(before, expected, "before output %d" % index)
        check_buffer(after, expected * (2 if index < 8 else 1), "after output %d" % index)
        if index < 8 and before == after:
            raise RuntimeError("A2 did not change its initialized output")
        if index >= 8 and before != after:
            raise RuntimeError("A2 modified B's completed output")
    print("TINY A2 FULL-OUTPUT REPLAY PASS: A doubled, B byte-identical", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--restore-coprocessor-data", action="store_true")
    parser.add_argument("--reapply-after-control", action="store_true")
    parser.add_argument("--replay-control-history", action="store_true")
    args = parser.parse_args()
    validate_snapshot(args.snapshot)
    if not args.check_only:
        extra = []
        if args.restore_coprocessor_data:
            extra.append("--restore-coprocessor-data-regions")
        if args.reapply_after_control:
            extra.append("--reapply-snapshot-after-control")
        if args.replay_control_history:
            extra.extend(("--prestage-control", "--control-producer", "4"))
        label = "rid1_tiny_aba_a2" + ("_coproc" if args.restore_coprocessor_data else "")
        label += "_reapply" if args.reapply_after_control else ""
        label += "_control_history" if args.replay_control_history else ""
        execute_replay(label=label, snapshot=args.snapshot, extra_args=extra,
                       output_dvas=OUTPUT_PAGES, validate=validate_replay,
                       resume_post_control=not args.replay_control_history,
                       wait_for_work_events=1)


if __name__ == "__main__":
    main()
