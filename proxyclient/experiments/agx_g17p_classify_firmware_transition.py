#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate host stores from device-written changes across two G17P snapshots."""

import argparse
import json
import pathlib
import struct

from agx_g17p_compare_live_dump import PAGE, snapshot_pages


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def byte_runs(offsets):
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
    base = min(offset & ~7, len(data) - 8)
    return struct.unpack_from("<Q", data, base)[0]


def traced_bytes(trace):
    touched = set()
    for write in trace["writes"]:
        width = integer(write["width"])
        for address in write.get("dvas", ()):
            address = integer(address)
            touched.update(range(address, address + width))
    return touched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=pathlib.Path)
    parser.add_argument("after", type=pathlib.Path)
    parser.add_argument("host_trace", type=pathlib.Path)
    parser.add_argument("--details", type=int, default=40)
    parser.add_argument("--max-runs", type=int, default=20)
    parser.add_argument(
        "--context", type=int, default=64,
        help="root context to compare (default: firmware context 64)")
    parser.add_argument(
        "--selector", type=int, default=1,
        help="root selector to compare (default: upper root 1)")
    args = parser.parse_args()

    before = snapshot_pages(args.before)
    after = snapshot_pages(args.after)
    trace = json.loads(args.host_trace.read_text())
    host_touched = traced_bytes(trace)

    rows = []
    keys = sorted(set(before) & set(after))
    for context, selector, address in keys:
        if context != args.context or selector != args.selector:
            continue
        old = before[(context, selector, address)]
        new = after[(context, selector, address)]
        changed = [offset for offset, pair in enumerate(zip(old, new))
                   if pair[0] != pair[1]]
        if not changed:
            continue
        host = [offset for offset in changed if address + offset in host_touched]
        device = [offset for offset in changed if address + offset not in host_touched]
        rows.append({
            "address": address,
            "before": old,
            "after": new,
            "changed": changed,
            "host": host,
            "device": device,
        })

    rows.sort(key=lambda row: (len(row["device"]), len(row["changed"])),
              reverse=True)
    print("page                 changed  host-touched  untraced")
    for row in rows:
        print("%#018x  %7d  %12d  %8d" % (
            row["address"], len(row["changed"]), len(row["host"]),
            len(row["device"])))

    print("\nHighest-signal untraced changes:")
    expanded = 0
    for row in rows:
        if not row["device"]:
            continue
        print("%#018x: %d untraced changed bytes in %d runs" % (
            row["address"], len(row["device"]),
            len(byte_runs(row["device"]))))
        for start, end in byte_runs(row["device"])[:args.max_runs]:
            print("  +%#06x..+%#06x  %#018x -> %#018x" % (
                start, end, qword(row["before"], start),
                qword(row["after"], start)))
        remaining = len(byte_runs(row["device"])) - args.max_runs
        if remaining > 0:
            print("  ... %d more runs" % remaining)
        expanded += 1
        if expanded >= args.details:
            break

    print("\nSummary: %d changed pages, %d changed bytes; %d host-touched, "
          "%d untraced" % (
              len(rows), sum(len(row["changed"]) for row in rows),
              sum(len(row["host"]) for row in rows),
              sum(len(row["device"]) for row in rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
