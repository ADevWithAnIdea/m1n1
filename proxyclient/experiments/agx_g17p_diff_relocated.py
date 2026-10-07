#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""What did firmware change in a work submission's own pages?

    M1N1DEVICE=/dev/m1n1-neo PYTHONPATH="$PWD/proxyclient" \
        .venv/bin/python3 proxyclient/experiments/agx_g17p_diff_relocated.py \
        --snapshot SNAPSHOT ORIGINAL_PA:LIVE_PA [...]

Run this against a live target immediately after a replay attempt that passed first
work, without rebooting. The replay relocates a submission's pages into memory this
host allocates and prints each move as ORIGINAL -> LIVE; pass those pairs here.

Why. A first submission completes and a second, published as a copy of the first,
makes the scheduler fault on a null at the second ring slot. The natural explanation
is that completing the first submission consumes something the copy still points at,
which is what per-submission allocation means in practice. That is directly
observable: the snapshot holds each page as it was before firmware ran, the live
target holds it after a completed submission, and the difference is what firmware
did to it.

A pointer-shaped field that has gone to zero is the thing to look for, because the
fault is a null dereference.

It reads host memory and a snapshot on disk. It does not touch the accelerator.
"""

import argparse
import json
import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.setup import *                       # noqa: E402,F401,F403

PAGE = 0x4000


def parse_pair(text):
    original, live = text.split(":")
    return int(original, 0), int(live, 0)


def original_page(snapshot, original_pa):
    """The page as it was before firmware ran, from the snapshot's RAM image."""
    manifest = json.loads((snapshot / "manifest.json").read_text())
    def value(raw):
        # Snapshots differ: some write these as hex strings, some as integers.
        return int(raw, 0) if isinstance(raw, str) else int(raw)

    for record in manifest["blob_pages"]:
        if value(record["original_pa"]) == original_pa:
            index = value(record["index"])
            with open(snapshot / manifest["ram_file"], "rb") as handle:
                handle.seek(index * PAGE)
                return handle.read(PAGE)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=pathlib.Path, required=True)
    parser.add_argument("pairs", nargs="+", type=parse_pair,
                        metavar="ORIGINAL_PA:LIVE_PA")
    args = parser.parse_args()

    for original_pa, live_pa in args.pairs:
        before = original_page(args.snapshot, original_pa)
        if before is None:
            print("%#x: not in the snapshot" % original_pa)
            continue
        after = bytes(iface.readmem(live_pa, PAGE))

        runs = []
        start = None
        for i in range(PAGE):
            if before[i] != after[i]:
                if start is None:
                    start = i
            elif start is not None:
                runs.append((start, i))
                start = None
        if start is not None:
            runs.append((start, PAGE))

        print("%#x -> %#x: %d changed runs" % (original_pa, live_pa, len(runs)))
        for a, b in runs:
            was = before[a:b]
            now = after[a:b]
            note = ""
            # A whole aligned 8-byte field that went to zero is the shape the fault
            # points at, so call it out rather than leaving it in a byte dump.
            if a % 8 == 0 and b - a == 8 and int.from_bytes(now, "little") == 0:
                note = "   <- u64 cleared, was %#x" % int.from_bytes(was, "little")
            elif a % 8 == 0 and b - a == 8:
                note = "   u64 %#x -> %#x" % (int.from_bytes(was, "little"),
                                              int.from_bytes(now, "little"))
            print("   +%#06x..%#06x  was %s  now %s%s"
                  % (a, b, was[:16].hex(), now[:16].hex(), note))

        # Any aligned qword that was a plausible device address and is now zero,
        # anywhere in the page, not only inside a contiguous changed run.
        cleared = []
        for off in range(0, PAGE, 8):
            old = struct.unpack_from("<Q", before, off)[0]
            new = struct.unpack_from("<Q", after, off)[0]
            if new == 0 and (old >> 40) == 0xfffffc:
                cleared.append((off, old))
        if cleared:
            print("   device addresses cleared: %d" % len(cleared))
            for off, old in cleared[:12]:
                print("     +%#06x was %#x" % (off, old))
    return 0


if __name__ == "__main__":
    sys.exit(main())
