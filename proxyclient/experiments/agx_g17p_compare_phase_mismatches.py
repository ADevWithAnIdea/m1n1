#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Find generated/native mismatches specific to a failing submission phase."""

import argparse
import pathlib
import struct

from agx_g17p_compare_live_dump import snapshot_pages, snapshot_read


def differing_runs(mask):
    runs = []
    start = None
    for offset, differs in enumerate(mask):
        if differs and start is None:
            start = offset
        elif not differs and start is not None:
            runs.append((start, offset))
            start = None
    if start is not None:
        runs.append((start, len(mask)))
    return runs


def qword(body, offset):
    base = offset & ~7
    if base + 8 > len(body):
        return 0
    return struct.unpack_from("<Q", body, base)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_success", type=pathlib.Path)
    parser.add_argument("current_success", type=pathlib.Path)
    parser.add_argument("native_failure", type=pathlib.Path)
    parser.add_argument("current_failure", type=pathlib.Path)
    parser.add_argument("--max-pages", type=int, default=80)
    parser.add_argument("--max-runs", type=int, default=16)
    args = parser.parse_args()

    success_pages = snapshot_pages(args.native_success)
    failure_pages = snapshot_pages(args.native_failure)
    current_success = {
        int(path.stem, 16): path.read_bytes()
        for path in args.current_success.glob("*.bin")
    }
    current_failure = {
        int(path.stem, 16): path.read_bytes()
        for path in args.current_failure.glob("*.bin")
    }

    results = []
    unavailable = []
    totals = {
        "bytes": 0,
        "success_mismatch": 0,
        "failure_mismatch": 0,
        "failure_only": 0,
        "transition_mismatch": 0,
    }

    for address in sorted(current_success.keys() & current_failure.keys()):
        current_before = current_success[address]
        current_after = current_failure[address]
        size = min(len(current_before), len(current_after))
        native_before, missing_before = snapshot_read(success_pages, address, size)
        native_after, missing_after = snapshot_read(failure_pages, address, size)
        if native_before is None or native_after is None:
            unavailable.append((address, missing_before, missing_after))
            continue

        success_mismatch = [
            current_before[index] != native_before[index]
            for index in range(size)
        ]
        failure_mismatch = [
            current_after[index] != native_after[index]
            for index in range(size)
        ]
        failure_only = [
            failure_mismatch[index] and not success_mismatch[index]
            for index in range(size)
        ]
        transition_mismatch = [
            (current_before[index], current_after[index]) !=
            (native_before[index], native_after[index])
            for index in range(size)
        ]

        counts = {
            "success_mismatch": sum(success_mismatch),
            "failure_mismatch": sum(failure_mismatch),
            "failure_only": sum(failure_only),
            "transition_mismatch": sum(transition_mismatch),
        }
        totals["bytes"] += size
        for key, count in counts.items():
            totals[key] += count
        if counts["failure_only"]:
            results.append((
                counts["failure_only"],
                address,
                native_before,
                current_before,
                native_after,
                current_after,
                failure_only,
                counts,
            ))

    print(
        "Compared %d bytes: success mismatch %d, failure mismatch %d, "
        "failure-only %d, transition mismatch %d" % (
            totals["bytes"], totals["success_mismatch"],
            totals["failure_mismatch"], totals["failure_only"],
            totals["transition_mismatch"],
        )
    )
    print(
        "Failure-only means current matched native at the successful phase but "
        "did not match native at the failing phase."
    )
    if unavailable:
        print("%d current pages lacked a native view" % len(unavailable))

    results.sort(key=lambda item: (-item[0], item[1]))
    for _, address, ns, cs, nf, cf, mask, counts in results[:args.max_pages]:
        runs = differing_runs(mask)
        print(
            "%#018x: failure-only %d bytes in %d runs; success mismatch %d, "
            "failure mismatch %d, transition mismatch %d" % (
                address, counts["failure_only"], len(runs),
                counts["success_mismatch"], counts["failure_mismatch"],
                counts["transition_mismatch"],
            )
        )
        for start, end in runs[:args.max_runs]:
            print(
                "  +%#06x..+%#06x ns=%s cs=%s nf=%s cf=%s "
                "qwords %#018x/%#018x -> %#018x/%#018x" % (
                    start, end, ns[start:end].hex(), cs[start:end].hex(),
                    nf[start:end].hex(), cf[start:end].hex(),
                    qword(ns, start), qword(cs, start),
                    qword(nf, start), qword(cf, start),
                )
            )
        if len(runs) > args.max_runs:
            print("  ... %d more runs" % (len(runs) - args.max_runs))

    if len(results) > args.max_pages:
        print("... %d more pages with failure-only mismatches" %
              (len(results) - args.max_pages))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
