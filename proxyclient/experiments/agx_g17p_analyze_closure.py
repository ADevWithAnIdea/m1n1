#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Describe raw pointer relationships in a saved G17P submission closure.

This consumes a saved G17P submission-closure page image. It is strictly
offline: it neither opens a proxy connection nor reads firmware code.
The result reports raw DVA relationships and scan limits without inferring
object names or scheduler field meanings.
"""

import argparse
import json
import pathlib
import struct


PAGE_SIZE = 0x4000
VA_MASK = (1 << 43) - 1
VA_HIGH = ((1 << 64) - 1) ^ VA_MASK


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "closure",
        type=pathlib.Path,
        help="directory containing target.json, pages.json, and pages.bin",
    )
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def canonical_high_dva(value):
    low = value & VA_MASK
    if value != (low | VA_HIGH) or not (low & (1 << 42)):
        return None
    return low | VA_HIGH


def read_page(raw, page):
    start = int(page["capture_offset"])
    return raw[start : start + PAGE_SIZE]


def scan_page(raw, page, captured_pages):
    data = read_page(raw, page)
    candidates = []
    edges = []
    for offset in range(0, PAGE_SIZE, 8):
        value = struct.unpack_from("<Q", data, offset)[0]
        dva = canonical_high_dva(value)
        if dva is None:
            continue
        target_page_dva = dva & ~(PAGE_SIZE - 1)
        item = {
            "offset": offset,
            "target_dva": dva,
            "target_page_dva": target_page_dva,
        }
        candidates.append(item)
        target = captured_pages.get(target_page_dva)
        if target is not None:
            edges.append(
                item
                | {
                    "target_pa": target["pa"],
                    "target_depth": target.get("depth"),
                }
            )
    return candidates, edges


def outer_subrecords(target):
    outer = bytes.fromhex(target["outer_hex"])
    entries = []
    for offset in range(0, len(outer), 0x18):
        first, queue, tail = struct.unpack_from("<QQQ", outer, offset)
        entries.append(
            {
                "offset": offset,
                "first_u64": first,
                "queue_dva": queue,
                "tail_u64": tail,
            }
        )
    return entries


def main():
    args = parse_args()
    closure = args.closure.resolve()
    target = json.loads((closure / "target.json").read_text())
    manifest = json.loads((closure / "pages.json").read_text())
    raw = (closure / "pages.bin").read_bytes()
    pages = manifest["pages"]
    if len(raw) != len(pages) * PAGE_SIZE:
        raise ValueError("pages.bin does not match the manifest page count")

    captured = {int(page["dva"]): page for page in pages}
    page_reports = []
    candidate_count = 0
    captured_edge_count = 0
    for page in pages:
        candidates, edges = scan_page(raw, page, captured)
        candidate_count += len(candidates)
        captured_edge_count += len(edges)
        page_reports.append(
            {
                "dva": page["dva"],
                "pa": page["pa"],
                "depth": page.get("depth"),
                "sources": page.get("sources", [page.get("source")]),
                "canonical_high_dva_word_count": len(candidates),
                "captured_edge_count": len(edges),
                "captured_edges": edges,
            }
        )

    report_by_dva = {int(page["dva"]): page for page in page_reports}
    queue_pages = []
    references = target.get("outer_queue_references")
    if references is None:
        references = [
            {
                "offset": offset,
                "queue_dva": queue["queue_dva"],
            }
            for queue in target.get("queues", [])
            for offset in queue.get("outer_offsets", [])
        ]
    for reference in references:
        page_dva = int(reference["queue_dva"]) & ~(PAGE_SIZE - 1)
        page = report_by_dva.get(page_dva)
        queue_pages.append(
            {
                "outer_offset": reference["offset"],
                "queue_dva": reference["queue_dva"],
                "queue_page_dva": page_dva,
                "captured_page": page,
            }
        )

    capped = []
    for page_dva in target.get("truncated_pointer_pages", []):
        report = report_by_dva.get(int(page_dva))
        if report is not None:
            capped.append(report)

    result = {
        "format": "m1n1-t8140-g17p-closure-analysis-v1",
        "closure": str(closure),
        "target": {
            "channel": target["channel"],
            "producer_before": target["producer_before"],
            "producer_after": target["producer_after"],
            "entry_index": target["entry_index"],
            "outer_dva": target["outer_dva"],
            "outer_subrecords": outer_subrecords(target),
        },
        "page_count": len(pages),
        "canonical_high_dva_word_count": candidate_count,
        "captured_edge_count": captured_edge_count,
        "queue_pages": queue_pages,
        "capped_page_reports": capped,
        "page_reports": page_reports,
    }
    output = args.output or closure / "closure_analysis.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Closure analysis: %s" % output)
    print(
        "pages=%d high_dva_words=%d captured_edges=%d capped_pages=%d"
        % (len(pages), candidate_count, captured_edge_count, len(capped))
    )
    for page in capped:
        print(
            "capped page=%#x depth=%d high_dva_words=%d captured_edges=%d"
            % (
                page["dva"],
                page["depth"],
                page["canonical_high_dva_word_count"],
                page["captured_edge_count"],
            )
        )


if __name__ == "__main__":
    main()
