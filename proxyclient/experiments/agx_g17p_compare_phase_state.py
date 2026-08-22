#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare two native/direct G17P phase-state artifacts."""

import argparse
import hashlib
import json
import pathlib


PAGE = 0x4000


def changed_ranges(before, after, limit=128):
    ranges = []
    start = None
    for offset, (left, right) in enumerate(zip(before, after)):
        if left != right and start is None:
            start = offset
        elif left == right and start is not None:
            ranges.append([start, offset])
            start = None
            if len(ranges) == limit:
                break
    if start is not None and len(ranges) < limit:
        ranges.append([start, len(before)])
    return ranges


def load(path):
    path = path.resolve()
    return path.parent, json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=pathlib.Path)
    parser.add_argument("right", type=pathlib.Path)
    parser.add_argument("-o", "--output", type=pathlib.Path)
    args = parser.parse_args()
    left_dir, left = load(args.left)
    right_dir, right = load(args.right)

    left_regions = {record["name"]: record for record in left["regions"]}
    right_regions = {record["name"]: record for record in right["regions"]}
    comparisons = []
    for name in sorted(set(left_regions) | set(right_regions)):
        lrecord = left_regions.get(name)
        rrecord = right_regions.get(name)
        if lrecord is None or rrecord is None:
            comparisons.append({"name": name, "status": "missing"})
            continue
        ldata = (left_dir / lrecord["file"]).read_bytes()
        rdata = (right_dir / rrecord["file"]).read_bytes()
        if len(ldata) != len(rdata):
            comparisons.append({
                "name": name,
                "status": "size-mismatch",
                "left_size": len(ldata),
                "right_size": len(rdata),
            })
            continue
        changed_pages = [
            page for page in range((len(ldata) + PAGE - 1) // PAGE)
            if hashlib.sha256(ldata[page * PAGE:(page + 1) * PAGE]).digest()
            != hashlib.sha256(rdata[page * PAGE:(page + 1) * PAGE]).digest()
        ]
        comparisons.append({
            "name": name,
            "status": "identical" if ldata == rdata else "different",
            "size": len(ldata),
            "changed_bytes": sum(a != b for a, b in zip(ldata, rdata)),
            "changed_pages": changed_pages,
            "first_changed_ranges": changed_ranges(ldata, rdata),
        })

    report = {
        "format": "m1n1-t8140-g17p-phase-comparison-v1",
        "left": str(args.left.resolve()),
        "right": str(args.right.resolve()),
        "left_phase": left["phase"],
        "right_phase": right["phase"],
        "sgx_registers_equal": left["sgx_registers"] == right["sgx_registers"],
        "left_sgx_registers": left["sgx_registers"],
        "right_sgx_registers": right["sgx_registers"],
        "regions": comparisons,
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    return 0 if all(item["status"] == "identical" for item in comparisons) else 1


if __name__ == "__main__":
    raise SystemExit(main())
