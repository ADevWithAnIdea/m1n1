#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read all mapped pages from one root in a saved live-UAT inventory."""

import argparse
import datetime
import hashlib
import json
import pathlib
import sys
import time


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from m1n1.setup import u  # noqa: E402


PAGE = 0x4000


def read_page(pa):
    body = bytearray()
    while len(body) < PAGE:
        count = min(0x1000, PAGE - len(body))
        error = None
        for _attempt in range(4):
            try:
                chunk = bytes(u.iface.readmem(pa + len(body), count))
                if len(chunk) != count:
                    raise RuntimeError("short physical read")
                body.extend(chunk)
                break
            except Exception as current:
                error = current
                time.sleep(0.1)
        else:
            raise RuntimeError("failed to read page at %#x" % pa) from error
    return bytes(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uat", type=pathlib.Path, required=True)
    parser.add_argument("--slot", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--selector", choices=("low", "high"), required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output directory already exists: %s" % args.output)

    source = json.loads((args.uat / "manifest.json").read_text())
    roots = [root for root in source["roots"] if int(root["slot"]) == args.slot]
    if len(roots) != 1:
        parser.error("expected one slot %d record, found %d" %
                     (args.slot, len(roots)))
    mappings = roots[0][args.selector + "_mappings"]
    args.output.mkdir(parents=True)
    binary = bytearray()
    records = []
    for index, mapping in enumerate(mappings):
        body = read_page(int(mapping["pa"]))
        offset = len(binary)
        binary.extend(body)
        records.append({
            "dva": int(mapping["va"]),
            "pa": int(mapping["pa"]),
            "pte": int(mapping["pte"]),
            "capture_offset": offset,
            "nonzero_bytes": sum(value != 0 for value in body),
            "sha256": hashlib.sha256(body).hexdigest(),
        })
        if (index + 1) % 128 == 0 or index + 1 == len(mappings):
            print("  read %d/%d pages" % (index + 1, len(mappings)), flush=True)
    (args.output / "pages.bin").write_bytes(binary)
    manifest = {
        "format": "m1n1-t8140-g17p-live-uat-pages-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "page_size": PAGE,
        "source_uat": str(args.uat.resolve()),
        "slot": args.slot,
        "selector": args.selector,
        "pages": records,
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print("LIVE UAT PAGE DUMP: %d pages -> %s" %
          (len(records), args.output), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
