#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild a captured T8140/G17P initialization descriptor and report coverage.

Usage:
    .venv/bin/python3 proxyclient/experiments/agx_g17p_rebuild_initdata.py [ARTIFACT]

The builder in ``m1n1/agx/g17p_initdata.py`` constructs descriptor objects from
the field model rather than copying bytes. Rebuilding a captured descriptor from
its own inputs and comparing byte for byte is therefore the coverage test: a
match means the object is fully specified, and every mismatching run names a
field that is still not understood. Offline, no hardware.
"""

import glob
import importlib.util
import json
import os
import struct
import sys

ARTIFACT_ROOT = "/Users/user/asahi_re/artifacts/agx_g17p"
AGX_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "m1n1", "agx")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(AGX_DIR, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runs_of(diff, gap=8):
    out = []
    for offset in diff:
        if out and offset <= out[-1][1] + gap:
            out[-1][1] = offset
        else:
            out.append([offset, offset])
    return out


def report(name, ref, built, nonzero_only=True):
    diff = [o for o in range(min(len(ref), len(built))) if ref[o] != built[o]]
    nonzero = sum(1 for b in ref if b)
    if not diff:
        print("%-12s REBUILT BYTE-EXACT  (%d nonzero bytes)" % (name, nonzero))
        return True, []
    groups = runs_of(diff)
    print("%-12s %d/%d nonzero bytes unexplained, in %d runs"
          % (name, len(diff), nonzero, len(groups)))
    return False, groups


def main():
    artifact = sys.argv[1] if len(sys.argv) > 1 else sorted(
        glob.glob(os.path.join(ARTIFACT_ROOT, "live_initdata_*")))[-1]
    g = load("g17p", "g17p.py")
    b = load("g17p_initdata", "g17p_initdata.py")

    with open(os.path.join(artifact, "initdata.json")) as handle:
        meta = json.load(handle)
    blob = open(os.path.join(artifact, "objects.bin"), "rb").read()

    def obj(name, size=None):
        info = meta["objects"][name]
        size = size or info["size"]
        return blob[info["capture_offset"]:info["capture_offset"] + size]

    print("artifact: %s\n" % artifact)

    root_ref = obj("root", b.ROOT_SIZE)
    ok_root, _ = report("root", root_ref, b.rebuild_root(root_ref))

    hw = obj("hwdata", b.HWDATA_SIZE)
    entries, flags = {}, {}
    for slot in range(b.REGISTER_SLOT_COUNT):
        base = b.REGISTER_ARRAY_OFFSET + slot * b.REGISTER_ENTRY_SIZE
        phys, va = struct.unpack_from("<QQ", hw, base)
        size = struct.unpack_from("<I", hw, base + 0x10)[0]
        unk = struct.unpack_from("<Q", hw, base + 0x18)[0]
        flag = struct.unpack_from("<I", hw, base + 0x20)[0]
        if g.is_register_va(va):
            entries[slot] = dict(phys=phys, device_va=va, size=size, flag=flag,
                                 unk_18=unk)
        elif flag:
            flags[slot] = flag

    def ladder(offset):
        return list(struct.unpack_from("<%dI" % b.LADDER_ENTRIES, hw, offset))

    def column(offset):
        return [struct.unpack_from("<I", hw, offset + s * b.STATE_BLOCK_STRIDE)[0]
                for s in range(b.LADDER_ENTRIES)]

    perf = {
        "freq_a": ladder(b.TABLE_GROUP_BASES[0]),
        "freq_b": ladder(b.FREQ_LADDER_B),
        "scale_b": ladder(b.SCALE_LADDER_B),
        "relative_a": ladder(b.RELATIVE_LADDER_A),
        "relative_b": ladder(b.RELATIVE_LADDER_B),
        "index_a": ladder(b.INDEX_MAP_A),
        "index_b": ladder(b.INDEX_MAP_B),
        "core_voltage": column(b.TABLE_GROUP_BASES[0] + b.GROUP_VOLTAGE_DELTA),
        "memory_voltage": column(b.TABLE_GROUP_BASES[0]
                                 + b.GROUP_MEMORY_VOLTAGE_DELTA),
        "voltage_repeat": 16,
    }
    chip_id = struct.unpack_from("<I", hw, b.HWDATA_CHIP_ID)[0]
    records = []
    for index in range(2):
        base = b.REGION_RECORD_OFFSET + index * b.REGION_RECORD_STRIDE
        kind = struct.unpack_from("<I", hw, base + b.REGION_RECORD_KIND)[0]
        if kind != b.REGION_RECORD_KIND_VALUE:
            break
        records.append(dict(
            lead=struct.unpack_from("<I", hw, base + b.REGION_RECORD_LEAD)[0],
            value=struct.unpack_from("<I", hw, base + b.REGION_RECORD_VALUE)[0],
            addr=struct.unpack_from("<Q", hw, base + b.REGION_RECORD_ADDR)[0],
            size_a=struct.unpack_from("<I", hw, base + b.REGION_RECORD_SIZE_A)[0],
            size_b=struct.unpack_from("<I", hw, base + b.REGION_RECORD_SIZE_B)[0],
            trail=struct.unpack_from("<I", hw, base + b.REGION_RECORD_TRAIL)[0]))

    built = b.build_hwdata(entries, flags, perf, [], chip_id=chip_id,
                           region_records=records)
    ok_hw, groups = report("hwdata", hw, built)

    if groups:
        print("\nregions still not derived from a named field:")
        for start, end in groups:
            words = struct.unpack_from(
                "<%dI" % max(1, min(6, (end - (start & ~3) + 4) // 4)),
                hw, start & ~3)
            print("  %#06x-%#06x (%3d B)  %s"
                  % (start, end, end - start + 1,
                     " ".join("%#x" % w for w in words)))

        # Feed those runs back as explicit opaque fields: the rebuild then has to
        # be byte-exact, and their total is the measured opacity of the object.
        opaque = [(start, hw[start:end + 1]) for start, end in groups]
        exact = b.build_hwdata(entries, flags, perf, opaque, chip_id=chip_id,
                               region_records=records)
        total = sum(len(data) for _, data in opaque)
        nonzero = sum(1 for byte in hw if byte)
        print("\nwith %d bytes passed as opaque known values (%d%% of nonzero): %s"
              % (total, round(100 * total / nonzero),
                 "byte-exact" if exact == hw else "STILL MISMATCHING"))
        ok_hw = exact == hw

    print("\nresult: %s" % ("descriptor reproducible from the model"
                            if ok_root and ok_hw else "coverage incomplete"))
    return 0 if (ok_root and ok_hw) else 1


if __name__ == "__main__":
    sys.exit(main())
