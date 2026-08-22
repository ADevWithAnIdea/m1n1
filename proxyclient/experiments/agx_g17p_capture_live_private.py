#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture G17P firmware-private and source-owned state after an experiment.

This helper is deliberately read-only.  A direct experiment may exit after a
timeout while both firmware instances and their allocations remain live; this
tool attaches to that state and records it without another mailbox write.
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
    return int(value, 0) if isinstance(value, str) else int(value)


def read_region(address, size):
    body = bytearray()
    while len(body) < size:
        # Firmware updates some private pages continuously.  A 16 KiB proxy
        # read can therefore change between its data and checksum phases; 4 KiB
        # chunks are short enough to obtain a coherent transport record.
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


def save_region(output, name, address, size, address_space):
    body = read_region(address, size)
    filename = name + ".bin"
    (output / filename).write_bytes(body)
    return {
        "name": name,
        "address": address,
        "size": size,
        "address_space": address_space,
        "file": filename,
        "sha256": hashlib.sha256(body).hexdigest(),
        "nonzero_bytes": sum(value != 0 for value in body),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--boot", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)

    boot = json.loads(args.boot.read_text())
    sgx = u.adt["/arm-io/sgx"]
    regions = []
    errors = []

    def capture(name, address, size, address_space):
        try:
            regions.append(save_region(
                args.output, name, address, size, address_space))
        except Exception as error:
            errors.append({
                "name": name,
                "address": address,
                "size": size,
                "address_space": address_space,
                "error": repr(error),
            })

    capture(
        "primary_private",
        integer(sgx.gfx_data_base), integer(sgx.gfx_data_size),
        "physical-firmware-private",
    )
    capture(
        "secondary_private",
        integer(sgx.gfx1_data_base), integer(sgx.gfx1_data_size),
        "physical-firmware-private",
    )

    selected = {
        "native_private_state",
        "firmware_control_ring",
        "hwdata_bundle",
        "hwdata_region_0",
        "hwdata_region_1",
        "root0",
        "root1",
        "region_c",
        "region_a",
        "primary_computed_page",
        "primary_region_1",
        "primary_region_2",
    }
    allocations = {record["name"]: record for record in boot["allocations"]}
    for name in sorted(selected):
        record = allocations.get(name)
        if record is None:
            continue
        capture(
            "source_" + name,
            integer(record["pa"]), integer(record["size"]),
            "physical-source-allocation",
        )

    manifest = {
        "format": "m1n1-t8140-g17p-live-private-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "boot": str(args.boot),
        "regions": regions,
        "read_errors": errors,
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(
        "LIVE PRIVATE: %d regions, %d errors, %#x bytes -> %s" % (
            len(regions), len(errors),
            sum(record["size"] for record in regions),
            args.output,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
