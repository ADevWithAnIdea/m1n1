#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture live source-built firmware pages named by a native snapshot.

This is a post-timeout tool. It attaches to the UAT tables that are still live
after a direct experiment exits, reads only firmware-high pages present in the
reference snapshot, and records unmapped pages instead of modifying anything.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

os.environ.setdefault("M1N1HEAP_RESERVE", "1")
os.environ.setdefault("AGX_GPU", "G17")

from m1n1.setup import u  # noqa: E402
from m1n1.constructutils import Ver  # noqa: E402

Ver.set_version(u)
if Ver._version.get("V") is None:
    Ver.set_version_key("V", Ver.MATRIX["V"][-1])

from m1n1.agx.g17p_device import G17PAddressSpace  # noqa: E402


PAGE = 0x4000
FIRMWARE_CONTEXT = 64
FIRMWARE_SELECTOR = 1
SOURCE_CONTEXT = 1
SOURCE_BASE = 0x7000000000


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def reference_pages(snapshot):
    manifest = json.loads((snapshot / "manifest.json").read_text())
    for root in manifest["root_mappings"]:
        if (integer(root["root_ctx_id"]) == FIRMWARE_CONTEXT and
                integer(root["selector"]) == FIRMWARE_SELECTOR):
            return sorted({
                integer(mapping["va"])
                for mapping in root["mappings"]
                if mapping.get("blob_index") is not None
            })
    raise RuntimeError("reference snapshot has no firmware-high UAT root")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--root-pa", type=integer, required=True)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)

    space = G17PAddressSpace(u, SOURCE_CONTEXT, SOURCE_BASE)
    pages = reference_pages(args.reference)
    records = []
    errors = []
    raw = bytearray()
    for address in pages:
        try:
            body = bytes(space.uat.ioread_root(args.root_pa, address, PAGE))
        except Exception as error:
            errors.append({"dva": address, "error": str(error)})
            continue
        records.append({
            "dva": address,
            "capture_offset": len(raw),
            "nonzero_bytes": sum(value != 0 for value in body),
            "sha256": hashlib.sha256(body).hexdigest(),
        })
        raw.extend(body)

    binary = args.output / "pages.bin"
    binary.write_bytes(raw)
    manifest = {
        "format": "m1n1-t8140-g17p-live-source-firmware-pages-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "reference": str(args.reference),
        "page_size": PAGE,
        "pages": records,
        "read_errors": errors,
        "binary": binary.name,
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (args.output / "summary.txt").write_text(
        "%d pages captured, %d unmapped/read errors, %#x bytes\n" %
        (len(records), len(errors), len(raw)))
    print("LIVE SOURCE FIRMWARE: %d/%d pages, %d errors, %#x bytes -> %s" % (
        len(records), len(pages), len(errors), len(raw), args.output),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
