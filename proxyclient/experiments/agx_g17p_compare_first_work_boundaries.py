#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Four-way native/source comparison around the first-work publication."""

import argparse
import hashlib
import json
import pathlib


PAGE = 0x4000
ROOTS = {(0, 0), (1, 0), (64, 1)}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("native_before", type=pathlib.Path)
    parser.add_argument("native_after", type=pathlib.Path)
    parser.add_argument("source_before", type=pathlib.Path)
    parser.add_argument("source_after", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args()


def native_pages(path):
    path = path.resolve()
    manifest = json.loads((path / "manifest.json").read_text())
    ram = (path / manifest.get("ram_file", "ram.bin")).read_bytes()
    pages = {}
    for root in manifest["root_mappings"]:
        root_key = (int(root["root_ctx_id"]), int(root["selector"]))
        if root_key not in ROOTS:
            continue
        for mapping in root["mappings"]:
            if mapping.get("blob_index") is None:
                continue
            blob = int(mapping["blob_index"])
            pages[root_key + (int(mapping["va"]),)] = (
                ram[blob * PAGE:(blob + 1) * PAGE]
            )
    return pages


def generated_pages(path):
    path = path.resolve()
    manifest = json.loads((path / "manifest.json").read_text())
    ram = (path / "current_pages.bin").read_bytes()
    pages = {}
    names = {}
    for row in manifest["pages"]:
        if row["current_pa"] is None:
            continue
        root_key = (int(row["root_context"]), int(row["root_selector"]))
        blob = int(row["current_blob"])
        identity = root_key + (int(row["address"]),)
        pages[identity] = ram[blob * PAGE:(blob + 1) * PAGE]
        names[identity] = list(row.get("names", []))
    return pages, names


def changed_bytes(left, right):
    return sum(a != b for a, b in zip(left, right))


def digest(body):
    return hashlib.sha256(body).hexdigest()


def classify(native_before, native_after, source_before, source_after):
    native_changed = native_before != native_after
    source_changed = source_before != source_after
    source_before_matches = source_before == native_before
    source_after_matches = source_after == native_after
    if source_before_matches and source_after_matches:
        return "exact-lifecycle" if native_changed else "exact-stable"
    if native_changed and source_before == native_after and source_after == native_after:
        return "correct-final-written-early"
    if native_changed and source_before == native_before and source_after != native_after:
        return "correct-initial-missing-late-transition"
    if native_changed and not source_changed:
        return "wrong-stable-across-native-transition"
    if source_after_matches:
        return "correct-final-different-initial"
    if source_before_matches:
        return "correct-initial-wrong-final"
    return "different-both-boundaries"


def main():
    args = parse_args()
    native_before = native_pages(args.native_before)
    native_after = native_pages(args.native_after)
    source_before, before_names = generated_pages(args.source_before)
    source_after, after_names = generated_pages(args.source_after)
    common = sorted(
        set(native_before) & set(native_after) &
        set(source_before) & set(source_after)
    )
    rows = []
    for identity in common:
        nb = native_before[identity]
        na = native_after[identity]
        sb = source_before[identity]
        sa = source_after[identity]
        native_delta = changed_bytes(nb, na)
        source_delta = changed_bytes(sb, sa)
        initial_error = changed_bytes(sb, nb)
        final_error = changed_bytes(sa, na)
        if not (native_delta or source_delta or initial_error or final_error):
            continue
        rows.append({
            "root_context": identity[0],
            "root_selector": identity[1],
            "address": identity[2],
            "names": after_names.get(identity, before_names.get(identity, [])),
            "classification": classify(nb, na, sb, sa),
            "native_changed_bytes": native_delta,
            "source_changed_bytes": source_delta,
            "source_initial_error_bytes": initial_error,
            "source_final_error_bytes": final_error,
            "native_before_sha256": digest(nb),
            "native_after_sha256": digest(na),
            "source_before_sha256": digest(sb),
            "source_after_sha256": digest(sa),
        })
    counts = {}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    report = {
        "format": "m1n1-g17p-first-work-four-boundary-diff-v1",
        "native_before": str(args.native_before.resolve()),
        "native_after": str(args.native_after.resolve()),
        "source_before": str(args.source_before.resolve()),
        "source_after": str(args.source_after.resolve()),
        "common_pages": len(common),
        "reported_pages": len(rows),
        "classification_counts": counts,
        "pages": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("First-work four-boundary report: %s" % args.output)
    for classification, count in sorted(counts.items()):
        print("  %-46s %d" % (classification, count))
    for row in rows:
        if row["root_context"] == 1 and row["address"] >= 0x10000000000:
            continue
        print(
            "  %d:%d %#018x %-44s N=%-5d S=%-5d pre=%-5d post=%-5d %s" % (
                row["root_context"], row["root_selector"], row["address"],
                row["classification"], row["native_changed_bytes"],
                row["source_changed_bytes"], row["source_initial_error_bytes"],
                row["source_final_error_bytes"],
                ",".join(row["names"]) or "-",
            )
        )


if __name__ == "__main__":
    main()
