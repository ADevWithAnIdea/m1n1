#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Non-atomic diagnostic of two explicitly recorded caller BOs after failure."""
import argparse
import json
import os
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ownership", type=Path)
    args = parser.parse_args()
    if not os.getenv("M1N1DEVICE", "").startswith("/dev/ttys"):
        parser.error("use the current verified RID 1 raw PTY")
    os.environ["M1N1HEAP_RESERVE"] = "1"
    from m1n1.setup import iface, p, u
    if u.adt["/chosen"].chip_id != 0x8140:
        raise RuntimeError("not the authorized T8140 target")
    ownership = json.loads(args.ownership.read_text())
    result = {"diagnostic_nonatomic": True}
    for name in ("output", "timestamp"):
        pa, size = ownership[name]["pa"], ownership[name]["size"]
        if size != 0x4000 or not 0x10000000000 <= pa < pa + size <= 0x10100000000:
            raise ValueError("recorded BO is not one complete owned normal-RAM page")
        scratch = u.memalign(0x4000, size)
        p.dc_ivac(pa, size)
        p.memcpy8(scratch, pa, size)
        p.dc_civac(scratch, size)
        body = bytes(iface.readmem(scratch, size))
        destination = args.ownership.with_name(args.ownership.stem + "_physical_" + name + ".bin")
        destination.write_bytes(body)
        result[name] = dict(pa=pa, bytes=size, nonzero=sum(x != 0 for x in body),
            head=list(struct.unpack_from("<4f" if name == "output" else "<4Q", body)))
    args.ownership.with_name(args.ownership.stem + "_physical.json").write_text(
        json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
