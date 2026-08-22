#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare two generated boundary audits against their native reference."""

import argparse
import collections
import hashlib
import json
import pathlib


PAGE = 0x4000
PTE_ATTRIBUTE_MASK = (
    (1 << 0) | (1 << 1) | (0x7 << 2) | (0x3 << 6) |
    (0x3 << 8) | (1 << 10) | (1 << 11) |
    (1 << 53) | (1 << 54) | (1 << 55)
)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("legacy", type=pathlib.Path)
    parser.add_argument("compact", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def read_generated(path):
    path = path.resolve()
    manifest = json.loads((path / "manifest.json").read_text())
    data = (path / "current_pages.bin").read_bytes()
    pages = {}
    for row in manifest["pages"]:
        identity = (
            int(row["root_context"]),
            int(row["root_selector"]),
            int(row["address"]),
        )
        blob = int(row["current_blob"])
        pages[identity] = {
            "body": data[blob * PAGE:(blob + 1) * PAGE],
            "mapped": row["current_pa"] is not None,
            "pa": row["current_pa"],
            "pte": row["current_pte"],
            "native_pa": int(row["native_pa"]),
            "native_pte": int(row["native_pte"]),
            "native_blob": int(row["native_blob"]),
            "names": list(row.get("names", [])),
            "root_label": row["root_label"],
        }
    fixed_pages = {}
    for record in manifest.get("fixed_regions", []):
        body = (path / record["current_file"]).read_bytes()
        if len(body) != int(record["size"]):
            raise ValueError("short generated fixed region %s" % record["name"])
        for offset in range(0, len(body), PAGE):
            fixed_pages[(record["name"], offset)] = body[offset:offset + PAGE]
    return manifest, pages, fixed_pages


def read_native(path):
    path = path.resolve()
    manifest = json.loads((path / "manifest.json").read_text())
    data = (path / manifest.get("ram_file", "ram.bin")).read_bytes()
    pages = {}
    for root in manifest["root_mappings"]:
        root_key = (int(root["root_ctx_id"]), int(root["selector"]))
        for mapping in root["mappings"]:
            blob = mapping.get("blob_index")
            if blob is None:
                continue
            identity = root_key + (int(mapping["va"]),)
            pages[identity] = data[int(blob) * PAGE:(int(blob) + 1) * PAGE]
    fixed_pages = {}
    for record in manifest.get("fixed_regions", []):
        if record["name"] not in {
                "gpu-region", "gfx-shared-region",
                "gfx-shared-l2-region", "gfx-handoff"}:
            continue
        body = (path / record["file"]).read_bytes()
        for offset in range(0, len(body), PAGE):
            fixed_pages[(record["name"], offset)] = body[offset:offset + PAGE]
    return pages, fixed_pages


def classification(legacy, compact, native):
    if legacy == compact == native:
        return "all-exact"
    if legacy == native:
        return "compact-only-content-difference"
    if compact == native:
        return "legacy-only-content-difference"
    if legacy == compact:
        return "common-generated-content-difference"
    return "all-content-different"


def mapping_classification(legacy, compact):
    native = legacy["native_pte"] & PTE_ATTRIBUTE_MASK
    legacy_attr = (None if legacy["pte"] is None else
                   legacy["pte"] & PTE_ATTRIBUTE_MASK)
    compact_attr = (None if compact["pte"] is None else
                    compact["pte"] & PTE_ATTRIBUTE_MASK)
    if legacy_attr == compact_attr == native:
        return "all-exact"
    if legacy_attr == native:
        return "compact-only-attribute-difference"
    if compact_attr == native:
        return "legacy-only-attribute-difference"
    if legacy_attr == compact_attr:
        return "common-generated-attribute-difference"
    return "all-attributes-different"


def changed_bytes(left, right):
    return sum(a != b for a, b in zip(left, right))


def difference_runs(left, right):
    runs = []
    start = None
    for offset, (a, b) in enumerate(zip(left, right)):
        if a != b and start is None:
            start = offset
        elif a == b and start is not None:
            runs.append([start, offset - start])
            start = None
    if start is not None:
        runs.append([start, len(left) - start])
    return runs


def aligned_values(legacy, compact, native, runs):
    offsets = set()
    for start, length in runs:
        first = start & ~7
        last = (start + length - 1) & ~7
        offsets.update(range(first, last + 1, 8))
    values = []
    for offset in sorted(offsets):
        values.append({
            "offset": offset,
            "legacy_u64": int.from_bytes(legacy[offset:offset + 8], "little"),
            "compact_u64": int.from_bytes(compact[offset:offset + 8], "little"),
            "native_u64": int.from_bytes(native[offset:offset + 8], "little"),
        })
    return values


def digest(body):
    return hashlib.sha256(body).hexdigest()


def main():
    args = parse_args()
    legacy_manifest, legacy_pages, legacy_fixed = read_generated(args.legacy)
    compact_manifest, compact_pages, compact_fixed = read_generated(args.compact)
    legacy_reference = pathlib.Path(legacy_manifest["reference"]).resolve()
    compact_reference = pathlib.Path(compact_manifest["reference"]).resolve()
    if legacy_reference != compact_reference:
        raise ValueError("generated audits use different native references")
    native_pages, native_fixed = read_native(legacy_reference)

    common = sorted(set(legacy_pages) & set(compact_pages) & set(native_pages))
    rows = []
    content_counts = collections.Counter()
    attribute_counts = collections.Counter()
    for identity in common:
        legacy = legacy_pages[identity]
        compact = compact_pages[identity]
        native = native_pages[identity]
        content_class = classification(legacy["body"], compact["body"], native)
        attribute_class = mapping_classification(legacy, compact)
        content_counts[content_class] += 1
        attribute_counts[attribute_class] += 1
        if content_class == "all-exact" and attribute_class == "all-exact":
            continue
        runs = difference_runs(legacy["body"], compact["body"])
        compact_native_runs = difference_runs(compact["body"], native)
        names = list(dict.fromkeys(legacy["names"] + compact["names"]))
        rows.append({
            "root_context": identity[0],
            "root_selector": identity[1],
            "root_label": compact["root_label"],
            "address": identity[2],
            "address_hex": "%#x" % identity[2],
            "names": names,
            "content_classification": content_class,
            "attribute_classification": attribute_class,
            "legacy_mapped": legacy["mapped"],
            "compact_mapped": compact["mapped"],
            "legacy_pa": legacy["pa"],
            "compact_pa": compact["pa"],
            "native_pa": legacy["native_pa"],
            "legacy_attributes": (None if legacy["pte"] is None else
                                  legacy["pte"] & PTE_ATTRIBUTE_MASK),
            "compact_attributes": (None if compact["pte"] is None else
                                   compact["pte"] & PTE_ATTRIBUTE_MASK),
            "native_attributes": legacy["native_pte"] & PTE_ATTRIBUTE_MASK,
            "legacy_compact_changed_bytes": changed_bytes(
                legacy["body"], compact["body"]),
            "legacy_native_changed_bytes": changed_bytes(
                legacy["body"], native),
            "compact_native_changed_bytes": changed_bytes(
                compact["body"], native),
            "legacy_sha256": digest(legacy["body"]),
            "compact_sha256": digest(compact["body"]),
            "native_sha256": digest(native),
            "legacy_compact_runs": runs,
            "compact_native_runs": compact_native_runs,
            "aligned_u64_values": aligned_values(
                legacy["body"], compact["body"], native, runs),
            "compact_native_aligned_u64_values": aligned_values(
                legacy["body"], compact["body"], native,
                compact_native_runs),
        })

    priority = {
        "compact-only-content-difference": 0,
        "all-content-different": 1,
        "common-generated-content-difference": 2,
        "legacy-only-content-difference": 3,
        "all-exact": 4,
    }
    rows.sort(key=lambda row: (
        priority[row["content_classification"]],
        0 if row["attribute_classification"] ==
        "compact-only-attribute-difference" else 1,
        row["root_context"], row["root_selector"], row["address"],
    ))

    fixed_common = sorted(set(legacy_fixed) & set(compact_fixed) & set(native_fixed))
    fixed_rows = []
    fixed_counts = collections.Counter()
    for identity in fixed_common:
        legacy = legacy_fixed[identity]
        compact = compact_fixed[identity]
        native = native_fixed[identity]
        content_class = classification(legacy, compact, native)
        fixed_counts[content_class] += 1
        if content_class == "all-exact":
            continue
        runs = difference_runs(legacy, compact)
        values = aligned_values(legacy, compact, native, runs)
        fixed_rows.append({
            "name": identity[0],
            "offset": identity[1],
            "content_classification": content_class,
            "legacy_compact_changed_bytes": changed_bytes(legacy, compact),
            "legacy_native_changed_bytes": changed_bytes(legacy, native),
            "compact_native_changed_bytes": changed_bytes(compact, native),
            "legacy_nonzero": sum(byte != 0 for byte in legacy),
            "compact_nonzero": sum(byte != 0 for byte in compact),
            "native_nonzero": sum(byte != 0 for byte in native),
            "legacy_sha256": digest(legacy),
            "compact_sha256": digest(compact),
            "native_sha256": digest(native),
            "legacy_compact_runs": runs,
            "aligned_u64_value_count": len(values),
            "aligned_u64_values": values,
        })
    fixed_rows.sort(key=lambda row: (
        priority[row["content_classification"]], row["name"], row["offset"]
    ))
    report = {
        "format": "m1n1-g17p-generated-three-way-boundary-diff-v1",
        "legacy": str(args.legacy.resolve()),
        "compact": str(args.compact.resolve()),
        "native": str(legacy_reference),
        "common_pages": len(common),
        "legacy_only_identities": len(set(legacy_pages) - set(compact_pages)),
        "compact_only_identities": len(set(compact_pages) - set(legacy_pages)),
        "content_classification_counts": dict(content_counts),
        "attribute_classification_counts": dict(attribute_counts),
        "reported_pages": len(rows),
        "pages": rows,
        "fixed_common_pages": len(fixed_common),
        "fixed_content_classification_counts": dict(fixed_counts),
        "reported_fixed_pages": len(fixed_rows),
        "fixed_pages": fixed_rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print("Generated boundary comparison: %s" % args.output)
    print("  common pages: %d" % len(common))
    for label, count in sorted(content_counts.items()):
        print("  content %-39s %d" % (label, count))
    for label, count in sorted(attribute_counts.items()):
        print("  attrs   %-39s %d" % (label, count))
    for label, count in sorted(fixed_counts.items()):
        print("  fixed   %-39s %d" % (label, count))
    for row in rows:
        if row["content_classification"] not in {
                "compact-only-content-difference", "all-content-different"}:
            continue
        print(
            "  %d:%d %#018x %-31s L/C=%-5d C/N=%-5d %s" % (
                row["root_context"], row["root_selector"], row["address"],
                row["content_classification"],
                row["legacy_compact_changed_bytes"],
                row["compact_native_changed_bytes"],
                ",".join(row["names"]) or "-",
            )
        )
    for row in fixed_rows:
        if row["content_classification"] not in {
                "compact-only-content-difference", "all-content-different"}:
            continue
        print(
            "  fixed %-22s +%#08x %-31s L/C=%-5d C/N=%-5d" % (
                row["name"], row["offset"],
                row["content_classification"],
                row["legacy_compact_changed_bytes"],
                row["compact_native_changed_bytes"],
            )
        )


if __name__ == "__main__":
    main()
