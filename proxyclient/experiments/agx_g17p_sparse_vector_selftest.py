#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only exact sparse-vector test on freshly allocated, host-owned RAM."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refuse to overwrite an existing diagnostic")
    if not os.environ.get("M1N1DEVICE", "").startswith("/dev/ttys"):
        parser.error("use the current owned RID 1 relay's exact raw PTY")
    os.environ["M1N1HEAP_RESERVE"] = "1"
    from m1n1.setup import iface, p, u
    from m1n1.agx.g17p_sparse_read import SparseRead
    if int(u.adt["/chosen"].chip_id) != 0x8140:
        raise RuntimeError("only the authorized T8140 target is permitted")
    reader = SparseRead(u, iface)
    pa = u.memalign(0x4000, 0x10000)
    patterns = (bytes(0x4000), bytes(range(256)) * 64,
        b"".join(bytes(64) if i % 3 else bytes([i % 255 + 1]) * 64 for i in range(256)),
        b"".join(bytes(i % 64) + b"\x80" + bytes(63 - i % 64) for i in range(256)))
    for index, body in enumerate(patterns):
        iface.writemem(pa + index * 0x4000, body)
        p.dc_civac(pa + index * 0x4000, len(body))
    vectors = (
        ((0, 0x4000), (0xc000, 0x4000), (0x4000, 0x4000), (0x8000, 0x4000)),
        ((0x3fc0, 128), (0xbfc0, 128), (0x4040, 64), (0, 64)),
        ((0, 0x10000),),
    )
    complete = b"".join(patterns)
    for vector in vectors:
        ranges = [(pa + offset, size) for offset, size in vector]
        expected = [complete[offset:offset + size] for offset, size in vector]
        dense = []
        for address, size in ranges:
            p.dc_ivac(address, size)
            dense.append(bytes(iface.readmem(address, size)))
        actual = reader.read_many(ranges)
        if actual != expected or actual != dense:
            raise RuntimeError("sparse vector differs from full dense readback")
    report = dict(execution_claim="none; own RAM transport self-test", exact=True,
                  vectors=len(vectors), allocated_pa=pa, allocated_size=0x10000,
                  source_bytes=reader.source_bytes, wire_bytes=reader.wire_bytes,
                  calls=reader.calls)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("SPARSE VECTOR SELFTEST PASS %s" % report, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
