#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dump live modeled G17P init/config pages and compare a saved source world."""

import argparse
import datetime
import hashlib
import json
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from m1n1.setup import *  # noqa: E402,F401,F403


PAGE = 0x4000


def load_source(path):
    metadata = json.loads((path / "pages.json").read_text())
    blob = (path / "pages.bin").read_bytes()
    pages = {}
    for record in metadata["pages"]:
        address = int(record["dva"])
        offset = int(record["capture_offset"])
        pages[address] = blob[offset:offset + PAGE]
    return metadata, pages


def difference_runs(before, after):
    runs = []
    start = None
    for offset, (left, right) in enumerate(zip(before, after)):
        if left != right and start is None:
            start = offset
        if left == right and start is not None:
            runs.append((start, offset))
            start = None
    if start is not None:
        runs.append((start, len(before)))
    return runs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--boot", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--modeled-attempt", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    boot = json.loads(args.boot.read_text())
    attempt = json.loads(args.modeled_attempt.read_text())
    source_metadata, source_pages = load_source(args.source)
    addresses = sorted(
        int(record["dva"])
        for record in attempt["grafted_source_config_pages"]["pages"]
    )
    allocations = list(boot["allocations"])
    args.output.mkdir(parents=True, exist_ok=False)

    raw = bytearray()
    records = []
    summary = []
    for address in addresses:
        candidates = [
            record for record in allocations
            if int(record["va"]) <= address
            and address < int(record["va"]) + int(record["size"])
        ]
        if not candidates:
            raise RuntimeError("no physical allocation covers DVA %#x" % address)
        allocation = min(candidates, key=lambda record: int(record["size"]))
        pa = int(allocation["pa"]) + address - int(allocation["va"])
        p.dc_civac(pa, PAGE)
        body = bytes(iface.readmem(pa, PAGE))
        source = source_pages[address]
        runs = difference_runs(source, body)
        differing = sum(end - start for start, end in runs)
        record = {
            "allocation": allocation["name"],
            "capture_offset": len(raw),
            "different_bytes": differing,
            "difference_runs": [
                {
                    "offset": start,
                    "size": end - start,
                    "source": source[start:end].hex(),
                    "live": body[start:end].hex(),
                }
                for start, end in runs
            ],
            "dva": address,
            "pa": pa,
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        records.append(record)
        raw.extend(body)
        summary.append(
            "%#018x  %-24s  %5d byte(s), %3d run(s)" %
            (address, allocation["name"], differing, len(runs))
        )

    report = {
        "format": "m1n1-t8140-g17p-live-modeled-config-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "boot": str(args.boot),
        "source": str(args.source),
        "source_phase": source_metadata.get("phase"),
        "modeled_attempt": str(args.modeled_attempt),
        "page_size": PAGE,
        "pages": records,
    }
    (args.output / "pages.bin").write_bytes(bytes(raw))
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")
    (args.output / "summary.txt").write_text("\n".join(summary) + "\n")
    print("LIVE MODELED CONFIG: %s" % args.output)
    print("\n".join(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
