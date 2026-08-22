#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rank source/native differences across the command-four firmware closure."""

import argparse
import hashlib
import json
import pathlib


NATIVE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260813_052428/CL_2"
)


def load_pages(manifest_path):
    manifest = json.loads(manifest_path.read_text())
    binary = manifest.get("binary")
    binary_path = (
        manifest_path.parent / binary if binary else manifest_path.with_suffix(".bin"))
    blob = binary_path.read_bytes()
    size = int(manifest.get("page_size", 0x4000))
    return manifest, {
        int(record["dva"]): blob[
            int(record["capture_offset"]):
            int(record["capture_offset"]) + size]
        for record in manifest["pages"]
    }


def difference_runs(native, source):
    runs = []
    start = None
    for offset, (left, right) in enumerate(zip(native, source)):
        if left != right and start is None:
            start = offset
        elif left == right and start is not None:
            runs.append((start, offset))
            start = None
    if start is not None:
        runs.append((start, len(native)))
    return runs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source_manifest", type=pathlib.Path)
    args = parser.parse_args()

    native_manifest, native_pages = load_pages(NATIVE / "pages.json")
    source_manifest, source_pages = load_pages(args.source_manifest)
    report = []
    native_records = {
        int(record["dva"]): record for record in native_manifest["pages"]
    }
    for address, source in source_pages.items():
        record = native_records[address]
        native = native_pages[address]
        runs = difference_runs(native, source)
        report.append({
            "dva": address,
            "byte_exact": not runs,
            "differing_bytes": sum(
                left != right for left, right in zip(native, source)),
            "difference_runs": [
                {"start": start, "end": end}
                for start, end in runs[:64]
            ],
            "native_nonzero_bytes": sum(value != 0 for value in native),
            "source_nonzero_bytes": sum(value != 0 for value in source),
            "native_sha256": hashlib.sha256(native).hexdigest(),
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "sources": record.get("sources", []),
        })
    for missing in source_manifest.get("unmapped_firmware_pages", []):
        report.append({
            "dva": int(missing["dva"]),
            "source_missing": True,
            "sources": missing.get("sources", []),
        })

    report.sort(key=lambda item: item.get("differing_bytes", -1), reverse=True)
    output = args.source_manifest.parent / "source_command4_native_closure_diff.json"
    output.write_text(json.dumps({
        "format": "m1n1-t8140-g17p-command4-closure-diff-v1",
        "native_manifest": str(NATIVE / "pages.json"),
        "source_manifest": str(args.source_manifest),
        "page_count": len(report),
        "skipped_low_pages": source_manifest.get("skipped_low_pages", []),
        "unmapped_firmware_pages": source_manifest.get(
            "unmapped_firmware_pages", []),
        "exact_pages": sum(item.get("byte_exact", False) for item in report),
        "pages": report,
    }, indent=2, sort_keys=True) + "\n")
    for item in report:
        if item.get("byte_exact"):
            continue
        print(
            "%#018x  %5s differing bytes  %s" % (
                item["dva"],
                item.get("differing_bytes", "missing"),
                json.dumps(item.get("sources", []), sort_keys=True),
            )
        )
    print("report: %s" % output)


if __name__ == "__main__":
    main()
