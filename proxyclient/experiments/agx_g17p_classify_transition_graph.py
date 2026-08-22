#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Classify a generated graph against one native publication transition."""

import argparse
import pathlib
import struct

from agx_g17p_compare_live_dump import PAGE, snapshot_pages


def runs(offsets):
    offsets = sorted(offsets)
    if not offsets:
        return []
    output = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset != previous + 1:
            output.append((start, previous + 1))
            start = offset
        previous = offset
    output.append((start, previous + 1))
    return output


def qword(data, offset):
    base = offset & ~7
    return struct.unpack_from("<Q", data, base)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=pathlib.Path)
    parser.add_argument("target", type=pathlib.Path)
    parser.add_argument("generated", type=pathlib.Path)
    parser.add_argument("--details", type=int, default=24,
                        help="number of highest-signal pages to expand")
    parser.add_argument("--max-runs", type=int, default=16)
    args = parser.parse_args()

    before_pages = snapshot_pages(args.before)
    target_pages = snapshot_pages(args.target)
    rows = []
    for path in sorted(args.generated.glob("*.bin")):
        address = int(path.stem, 16)
        key = (64, 1, address)
        before = before_pages.get(key)
        target = target_pages.get(key)
        if before is None or target is None:
            continue
        generated = path.read_bytes()
        if len(generated) != PAGE:
            raise ValueError("%s is %#x bytes, expected %#x" %
                             (path, len(generated), PAGE))
        changed = [index for index, (left, right) in
                   enumerate(zip(before, target)) if left != right]
        stale = [index for index in changed if generated[index] == before[index]]
        reached = [index for index in changed if generated[index] == target[index]]
        other = [index for index in changed
                 if generated[index] != before[index]
                 and generated[index] != target[index]]
        static = [index for index, (left, right, got) in
                  enumerate(zip(before, target, generated))
                  if left == right and got != right]
        if changed or static:
            rows.append({
                "address": address,
                "before": before,
                "target": target,
                "generated": generated,
                "changed": changed,
                "stale": stale,
                "reached": reached,
                "other": other,
                "static": static,
            })

    ranked = sorted(
        rows,
        key=lambda row: (len(row["stale"]) + len(row["other"]),
                         len(row["changed"]), len(row["static"])),
        reverse=True,
    )
    print("address            native  reached  stale  other  static-mismatch")
    for row in ranked:
        print("%#018x  %6d  %7d  %5d  %5d  %15d" % (
            row["address"], len(row["changed"]), len(row["reached"]),
            len(row["stale"]), len(row["other"]), len(row["static"])))

    print("\nExpanded pages:")
    for row in ranked[:args.details]:
        interesting = set(row["stale"]) | set(row["other"])
        if not interesting:
            continue
        print("%#018x: native changed %d; reached %d; stale %d; other %d; static %d" % (
            row["address"], len(row["changed"]), len(row["reached"]),
            len(row["stale"]), len(row["other"]), len(row["static"])))
        for start, end in runs(interesting)[:args.max_runs]:
            kind = "stale" if all(index in row["stale"]
                                  for index in range(start, end)) else "other"
            print("  +%#06x..+%#06x %-5s native %#018x -> %#018x; generated %#018x" % (
                start, end, kind, qword(row["before"], start),
                qword(row["target"], start), qword(row["generated"], start)))
        remaining = len(runs(interesting)) - args.max_runs
        if remaining > 0:
            print("  ... %d more runs" % remaining)

    changed_pages = sum(bool(row["changed"]) for row in rows)
    print("\nSummary: %d compared pages; %d changed in the native transition; "
          "%d native-transition bytes reached, %d stale, %d other" % (
              len(rows), changed_pages,
              sum(len(row["reached"]) for row in rows),
              sum(len(row["stale"]) for row in rows),
              sum(len(row["other"]) for row in rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
