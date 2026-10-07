#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read one focused physical-memory region from a live m1n1 target.

This is a postmortem helper: it performs proxy reads only and never writes to
the target or rings an ASC doorbell.
"""

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


def integer(value):
    return int(value, 0)


def read_region(address, size):
    body = bytearray()
    while len(body) < size:
        chunk_size = min(0x1000, size - len(body))
        error = None
        for _attempt in range(4):
            try:
                chunk = bytes(u.iface.readmem(
                    address + len(body), chunk_size))
                if len(chunk) != chunk_size:
                    raise RuntimeError(
                        "short read at %#x: %#x != %#x" % (
                            address + len(body), len(chunk), chunk_size))
                body.extend(chunk)
                break
            except Exception as current:
                error = current
                time.sleep(0.1)
        else:
            raise RuntimeError(
                "failed to read %#x bytes at %#x" % (
                    chunk_size, address + len(body))) from error
    return bytes(body)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", type=integer)
    parser.add_argument("--size", type=integer)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--boot-json", type=pathlib.Path)
    parser.add_argument("--output-dir", type=pathlib.Path)
    args = parser.parse_args(argv)

    bulk = args.boot_json is not None or args.output_dir is not None
    if bulk:
        if args.boot_json is None or args.output_dir is None:
            parser.error("--boot-json and --output-dir must be used together")
        if any(value is not None for value in
               (args.address, args.size, args.output)):
            parser.error("bulk and single-region arguments cannot be mixed")
        if args.output_dir.exists():
            parser.error("output directory already exists: %s" %
                         args.output_dir)
        boot = json.loads(args.boot_json.read_text())
        pages = boot.get("render_context", {}).get("pages", ())
        if not pages:
            parser.error("boot JSON has no render-context page inventory")
        args.output_dir.mkdir(parents=True)
        records = []
        for index, page in enumerate(pages):
            address = int(page["pa"])
            body = read_region(address, 0x4000)
            filename = "%012x.bin" % int(page["va"])
            (args.output_dir / filename).write_bytes(body)
            records.append({
                "name": page["name"],
                "dva": int(page["va"]),
                "pa": address,
                "file": filename,
                "sha256": hashlib.sha256(body).hexdigest(),
                "nonzero_bytes": sum(value != 0 for value in body),
            })
            print("  [%3d/%3d] %-30s DVA %#x PA %#x" %
                  (index + 1, len(pages), page["name"], int(page["va"]),
                   address), flush=True)
        manifest = {
            "format": "m1n1-g17p-live-render-pages-v1",
            "captured_utc": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            "boot_json": str(args.boot_json.resolve()),
            "page_size": 0x4000,
            "pages": records,
        }
        (args.output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print("RENDER PAGE DUMP: %d pages -> %s" %
              (len(records), args.output_dir), flush=True)
        return 0

    if args.address is None or args.size is None or args.output is None:
        parser.error("--address, --size, and --output are required together")
    if args.address < 0 or args.size <= 0:
        parser.error("address must be non-negative and size must be positive")
    if args.output.exists():
        parser.error("output already exists: %s" % args.output)

    body = read_region(args.address, args.size)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(body)
    manifest = {
        "format": "m1n1-focused-physical-dump-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "address": args.address,
        "size": args.size,
        "file": args.output.name,
        "sha256": hashlib.sha256(body).hexdigest(),
        "nonzero_bytes": sum(value != 0 for value in body),
    }
    manifest_path = args.output.with_suffix(args.output.suffix + ".json")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(
        "PHYSICAL DUMP: %#x bytes at %#x -> %s (%s)" % (
            args.size, args.address, args.output, manifest["sha256"]),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
