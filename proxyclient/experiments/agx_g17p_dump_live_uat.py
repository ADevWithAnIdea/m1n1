#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dump live G17P hardware-context UAT roots without modifying the device."""

import argparse
import datetime
import hashlib
import json
import pathlib
import struct
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from m1n1.setup import *  # noqa: E402,F401,F403


PAGE = 0x4000
TABLE_MASK = 0x0000FFFFFFFFC000
VA_SHIFT = 42
L1_ENTRIES = 1 << (VA_SHIFT - 36)
L2_ENTRIES = 0x800
L3_ENTRIES = 0x800


def read_page(pa):
    pa = int(pa)
    p.dc_civac(pa, PAGE)
    body = bytes(iface.readmem(pa, PAGE))
    if len(body) != PAGE:
        raise RuntimeError("short table read at %#x" % pa)
    return body


def canonicalize(va):
    va &= (1 << (VA_SHIFT + 1)) - 1
    if va & (1 << VA_SHIFT):
        va |= ((1 << 64) - 1) ^ ((1 << (VA_SHIFT + 1)) - 1)
    return va


def walk(root_pa, selector, tables):
    mappings = []
    if not root_pa:
        return mappings
    root = tables.setdefault(root_pa, read_page(root_pa))
    for l1_index in range(L1_ENTRIES):
        l1 = struct.unpack_from("<Q", root, l1_index * 8)[0]
        if (l1 & 3) != 3:
            continue
        l2_pa = l1 & TABLE_MASK
        l2 = tables.setdefault(l2_pa, read_page(l2_pa))
        for l2_index in range(L2_ENTRIES):
            l2_entry = struct.unpack_from("<Q", l2, l2_index * 8)[0]
            if (l2_entry & 3) != 3:
                continue
            l3_pa = l2_entry & TABLE_MASK
            l3 = tables.setdefault(l3_pa, read_page(l3_pa))
            for l3_index in range(L3_ENTRIES):
                leaf = struct.unpack_from("<Q", l3, l3_index * 8)[0]
                if (leaf & 3) != 3:
                    continue
                va = canonicalize(
                    (int(selector) << VA_SHIFT)
                    | (l1_index << 36)
                    | (l2_index << 25)
                    | (l3_index << 14)
                )
                mappings.append({
                    "va": va,
                    "pa": leaf & TABLE_MASK,
                    "pte": leaf,
                    "l1_index": l1_index,
                    "l2_index": l2_index,
                    "l3_index": l3_index,
                    "l2_pa": l2_pa,
                    "l3_pa": l3_pa,
                })
    return mappings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--slots", default="0,1,2")
    args = parser.parse_args()
    slots = [int(value, 0) for value in args.slots.split(",") if value]
    args.output.mkdir(parents=True, exist_ok=False)

    sgx = u.adt["/arm-io/sgx"]
    gpu_region = int(sgx.gpu_region_base)
    p.dc_civac(gpu_region, PAGE)
    table = bytes(iface.readmem(gpu_region, PAGE))
    tables = {}
    roots = []
    for slot in slots:
        low, high = struct.unpack_from("<QQ", table, slot * 16)
        root = {
            "slot": slot,
            "low_ttbr": low,
            "high_ttbr": high,
            "low_asid": (low >> 48) & 0xFFFF,
            "high_asid": (high >> 48) & 0xFFFF,
            "low_root_pa": low & TABLE_MASK,
            "high_root_pa": high & TABLE_MASK,
        }
        root["low_mappings"] = walk(root["low_root_pa"], 0, tables)
        root["high_mappings"] = walk(root["high_root_pa"], 1, tables)
        roots.append(root)

    records = []
    blob = bytearray()
    for index, (pa, body) in enumerate(sorted(tables.items())):
        records.append({
            "index": index,
            "pa": pa,
            "sha256": hashlib.sha256(body).hexdigest(),
        })
        blob.extend(body)
    (args.output / "tables.bin").write_bytes(blob)
    (args.output / "gpu_region_head.bin").write_bytes(table)
    manifest = {
        "format": "m1n1-t8140-g17p-live-hardware-uat-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "gpu_region": gpu_region,
        "page_size": PAGE,
        "va_shift": VA_SHIFT,
        "roots": roots,
        "table_pages": records,
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    lines = []
    for root in roots:
        lines.append(
            "slot %d asid %d/%d roots %#x/%#x mappings %d/%d" % (
                root["slot"], root["low_asid"], root["high_asid"],
                root["low_root_pa"], root["high_root_pa"],
                len(root["low_mappings"]), len(root["high_mappings"]),
            )
        )
    lines.append("%d unique table pages" % len(records))
    (args.output / "summary.txt").write_text("\n".join(lines) + "\n")
    print("LIVE HARDWARE UAT: %s" % args.output)
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
