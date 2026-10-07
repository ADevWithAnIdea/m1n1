#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize byte runs that changed between two clean-room BO snapshots."""

import argparse
from pathlib import Path

from agx_g17p_corpus_submit import bodump_va, read_bodump


def load(directory, pattern):
    result = {}
    for path in Path(directory).glob(pattern):
        key = bodump_va(path) if pattern.startswith("bo_") else path.name.split(
            "_at", 1
        )[1].split("_sz", 1)[0]
        result[key] = (read_bodump(path), path)
    return result


def changed_runs(left, right):
    changed = [
        offset for offset, values in enumerate(zip(left, right))
        if values[0] != values[1]
    ]
    if not changed:
        return []
    runs = []
    start = previous = changed[0]
    for offset in changed[1:]:
        if offset != previous + 1:
            runs.append((start, previous + 1))
            start = offset
        previous = offset
    runs.append((start, previous + 1))
    return runs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--glob", default="bo_*.hex")
    args = parser.parse_args()
    left = load(args.left, args.glob)
    right = load(args.right, args.glob)
    print("BOs left=%d right=%d" % (len(left), len(right)))
    print("new: %s" % [str(value) for value in sorted(right.keys() - left)])
    rows = []
    for address in left.keys() & right.keys():
        body_left = left[address][0]
        body_right = right[address][0]
        runs = changed_runs(body_left, body_right)
        if runs:
            rows.append((sum(end - start for start, end in runs),
                         address, len(body_right), runs))
    for count, address, size, runs in sorted(rows, reverse=True):
        summary = ",".join(
            "%#x-%#x" % values for values in runs[:16]
        )
        if len(runs) > 16:
            summary += ",...(%d runs)" % len(runs)
        shown_address = hex(address) if isinstance(address, int) else address
        print("%s size=%#x changed=%#x runs=%s" %
              (shown_address, size, count, summary))


if __name__ == "__main__":
    main()
