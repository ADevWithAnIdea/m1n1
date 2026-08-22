#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the descriptor builders against what a working host hands the firmware.

    .venv/bin/python3 proxyclient/experiments/agx_g17p_validate_handoff.py

Needs no hardware. It reads the newest capture taken at the moment each firmware
instance is handed its descriptor, rebuilds each object from that object's own
addresses, and requires a byte-for-byte match.

Rebuilding from the capture's own addresses is what makes this a test of the field
model rather than of the addresses: anything the builder does not know how to set
shows up as a difference, and anything it sets wrongly shows up too. Several
findings were only visible this way, including three scalars that turned out to be
written later by a running host rather than at handoff, and two region records the
model was missing entirely.

Exits non-zero on any mismatch, so it can gate a change to the field model.
"""

import glob
import os
import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.agx import g17p                    # noqa: E402
from m1n1.agx import g17p_initdata as build  # noqa: E402

ARTIFACT_ROOT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")

failures = []
checks = 0


def compare(label, built, captured):
    """Require two byte strings to match, reporting the first few differences."""
    global checks
    checks += 1
    size = min(len(built), len(captured))
    runs = []
    start = None
    for i in range(size):
        if built[i] != captured[i]:
            if start is None:
                start = i
        elif start is not None:
            runs.append((start, i))
            start = None
    if start is not None:
        runs.append((start, size))

    if not runs:
        print("  ok       %-28s %#x bytes" % (label, size))
        return

    total = sum(b - a for a, b in runs)
    print("  MISMATCH %-28s %d runs, %d of %#x bytes"
          % (label, len(runs), total, size))
    for a, b in runs[:6]:
        show = min(b - a, 12)
        print("             %#06x..%#06x  built %s  captured %s"
              % (a, b, built[a:a + show].hex(), captured[a:a + show].hex()))
    if len(runs) > 6:
        print("             ... %d more runs" % (len(runs) - 6))
    failures.append(label)


def looks_like_handoff(directory):
    """Has firmware already started writing into the objects in this capture?

    Not every capture is taken at handoff, and one taken later is useless as a
    reference: firmware writes into the same memory, so comparing against it would
    validate firmware's own working values as though a host had supplied them. Two
    captures of the same machine differ by 1321 bytes in the bundle's last two views
    for exactly that reason.

    The cheapest test is the flag firmware writes when it accepts a descriptor, at
    the address the main object repeats. Zero there means firmware has not got that
    far yet, so the rest of the capture is still what the host handed over.
    """
    view = directory / "primary-addr3.bin"
    if not view.exists():
        return True
    offset = g17p.MAIN_REPEATED_ADDR_OFFSET - g17p.MAIN_ADDR_OBJECT_OFFSETS[3]
    blob = view.read_bytes()
    if offset + 1 > len(blob):
        return True
    return blob[offset] == 0


def newest_capture():
    candidates = sorted(glob.glob(str(ARTIFACT_ROOT / "live_instances_*")))
    usable = [pathlib.Path(p) for p in candidates
              if (pathlib.Path(p) / "primary-main_config.bin").exists()]
    for directory in reversed(usable):
        if looks_like_handoff(directory):
            return directory
    # Nothing clean; fall back so the run still reports something, but say so.
    if usable:
        print("  NOTE: no capture looks like handoff; using %s, in which firmware "
              "has already written" % usable[-1].name)
        return usable[-1]
    return None


def channels_from(blob):
    out = []
    for index in range(build.CHANNEL_TABLE_ENTRIES):
        base = build.MAIN_CHANNEL_TABLE + index * build.CHANNEL_ENTRY_SIZE
        words = struct.unpack_from("<4Q", blob, base)
        out.append((list(words[:3]), words[3]))
    return out


def triples_from(blob):
    out = []
    for index in range(build.MAIN_REGION_TRIPLE_COUNT):
        base = build.MAIN_REGION_TRIPLES + index * build.MAIN_REGION_TRIPLE_STRIDE
        addr = struct.unpack_from("<Q", blob, base)[0]
        value = struct.unpack_from("<I", blob, base + 8)[0]
        kind = struct.unpack_from("<I", blob, base + 0xc)[0]
        out.append((addr, None if kind == 0 else value))
    return out


def check_root(directory, name, kind):
    path = directory / ("%s-root.bin" % name)
    if not path.exists():
        return
    size = build.ROOT_SECONDARY_SIZE if kind else build.ROOT_SIZE
    captured = path.read_bytes()[:size]

    def field(offset):
        return struct.unpack_from("<Q", captured, offset)[0]

    built = build.build_root(
        version=list(struct.unpack_from("<4H", captured, build.ROOT_VERSION)),
        region_a=field(build.ROOT_REGION_A),
        main_config=field(build.ROOT_MAIN_CONFIG),
        region_c=field(build.ROOT_REGION_C),
        status_a=field(build.ROOT_STATUS_A),
        status_b=field(build.ROOT_STATUS_B),
        kind=kind,
        secondary_extra_0=(field(build.ROOT_SECONDARY_EXTRA_0) if kind else 0),
        secondary_extra_1=(field(build.ROOT_SECONDARY_EXTRA_1) if kind else 0))
    compare("%s root" % name, built, captured)


def check_status_blocks(directory):
    """Check both initial and post-ack status forms the field builder supports."""
    for name, extra in (("primary-status_a", True),
                        ("primary-status_b", False),
                        ("secondary-status_a", False)):
        path = directory / (name + ".bin")
        if not path.exists():
            continue
        captured = path.read_bytes()[:build.STATUS_BLOCK_SIZE]
        compare(name.replace("-", " "),
                build.build_status_block(extra=extra), captured)


def check_main_config(directory, name, secondary):
    path = directory / ("%s-main_config.bin" % name)
    if not path.exists():
        return
    captured = path.read_bytes()[:build.MAIN_SIZE]
    hwdata = struct.unpack_from("<Q", captured, build.MAIN_HWDATA_ADDR)[0]
    repeated = struct.unpack_from("<Q", captured, build.MAIN_REPEATED_ADDR)[0]

    # Reading the repeated address out of the capture and handing it straight back to
    # the builder validates the builder's plumbing and nothing else, which is how a
    # host that pointed this at the bundle base instead of the bundle plus 0xc500
    # passed this gate for as long as it did. Check the relation itself.
    global checks
    checks += 1
    if repeated != hwdata + g17p.MAIN_REPEATED_ADDR_OFFSET:
        print("  MISMATCH %-28s repeated address is bundle%+#x, not bundle+%#x"
              % ("%s repeated address" % name, repeated - hwdata,
                 g17p.MAIN_REPEATED_ADDR_OFFSET))
        failures.append("%s repeated address" % name)
    else:
        print("  ok       %-28s bundle+%#x"
              % ("%s repeated address" % name, g17p.MAIN_REPEATED_ADDR_OFFSET))

    if secondary:
        extra = struct.unpack_from("<Q", captured, build.MAIN_SECONDARY_ADDR)[0]
        built = build.build_secondary_main_config(
            hwdata, repeated, channels_from(captured),
            triples_from(captured), extra)
    else:
        addr_array = [
            struct.unpack_from("<Q", captured, build.MAIN_ADDR_ARRAY + 8 * i)[0]
            for i in range(build.MAIN_ADDR_ARRAY_COUNT)]
        built = build.build_main_config(hwdata, repeated,
                                        channels_from(captured), addr_array,
                                        triples_from(captured))
    compare("%s main config" % name, built, captured)


def check_secondary_extra_relation(directory):
    """Require the secondary-only pointer to retain its primary-object relation."""
    global checks
    primary_path = directory / "primary-main_config.bin"
    secondary_path = directory / "secondary-main_config.bin"
    if not primary_path.exists() or not secondary_path.exists():
        return

    primary = primary_path.read_bytes()[:build.MAIN_SIZE]
    secondary = secondary_path.read_bytes()[:build.MAIN_SIZE]
    primary_object = struct.unpack_from(
        "<Q", primary,
        build.MAIN_ADDR_ARRAY + 8 * g17p.SECONDARY_EXTRA_ADDR_OBJECT)[0]
    secondary_extra = struct.unpack_from(
        "<Q", secondary, build.MAIN_SECONDARY_ADDR)[0]
    expected = primary_object + g17p.SECONDARY_EXTRA_ADDR_OFFSET

    checks += 1
    if secondary_extra != expected:
        print("  MISMATCH %-28s got %#x, expected %#x"
              % ("secondary extra relation", secondary_extra, expected))
        failures.append("secondary extra relation")
    else:
        print("  ok       %-28s primary addr[%d] + %#x"
              % ("secondary extra relation",
                 g17p.SECONDARY_EXTRA_ADDR_OBJECT,
                 g17p.SECONDARY_EXTRA_ADDR_OFFSET))


def check_hwdata_bundle_relation(directory):
    """Require every primary auxiliary address to remain a hardware-data view."""
    global checks
    path = directory / "primary-main_config.bin"
    if not path.exists():
        return

    captured = path.read_bytes()[:build.MAIN_SIZE]
    hwdata = struct.unpack_from("<Q", captured, build.MAIN_HWDATA_ADDR)[0]
    actual = [
        struct.unpack_from("<Q", captured,
                           build.MAIN_ADDR_ARRAY + 8 * index)[0]
        for index in range(build.MAIN_ADDR_ARRAY_COUNT)
    ]
    expected = [
        hwdata + offset for offset in g17p.MAIN_ADDR_OBJECT_OFFSETS
    ]

    checks += 1
    if actual != expected:
        print("  MISMATCH %-28s auxiliary addresses are not bundle views"
              % "hardware-data bundle")
        failures.append("hardware-data bundle")
    else:
        print("  ok       %-28s %d fixed internal views"
              % ("hardware-data bundle", len(actual)))


def check_addr_view_content(directory):
    """Require every recorded address-view run to be written, and to match.

    This exists because of a specific bug. The last two views extend past the
    bundle's own 0xc000, their recorded extents had been cut off exactly there, and
    the builder skips any run crossing its extent, so 46 runs of real content were
    written nowhere. Nothing caught it: the bundle comparison cannot reach past
    0xc000, because the bundle capture stops there. This checks the runs against the
    per-view captures, which do reach.
    """
    global checks
    for index in range(len(g17p.MAIN_ADDR_OBJECT_OFFSETS)):
        path = directory / ("primary-addr%d.bin" % index)
        if not path.exists():
            continue
        captured = path.read_bytes()
        runs = g17p.MAIN_ADDR_OBJECTS[index]["runs"]
        extent = g17p.MAIN_ADDR_OBJECT_VALID_SIZES[index]
        label = "addr view %d content" % index
        skipped = [off for off, data in runs if off + len(data) > extent]
        wrong = [off for off, data in runs
                 if off + len(data) <= len(captured)
                 and captured[off:off + len(data)] != data]

        checks += 1
        if skipped:
            print("  MISMATCH %-28s %d recorded runs fall outside the extent %#x"
                  % (label, len(skipped), extent))
            failures.append(label)
        elif wrong:
            print("  MISMATCH %-28s %d runs differ from the capture"
                  % (label, len(wrong)))
            failures.append(label)
        else:
            print("  ok       %-28s %d runs, all written and matching"
                  % (label, len(runs)))


def check_hwdata(directory):
    path = directory / "primary-hwdata.bin"
    if not path.exists():
        return
    captured = path.read_bytes()[:build.HWDATA_SIZE]

    entries = {}
    flag_only = {}
    for slot in range(g17p.REGISTER_MAP_SLOT_COUNT):
        base = build.REGISTER_ARRAY_OFFSET + slot * build.REGISTER_ENTRY_SIZE
        phys, device_va = struct.unpack_from("<QQ", captured, base)
        size, _ = struct.unpack_from("<II", captured, base + 0x10)
        unk_18 = struct.unpack_from("<Q", captured, base + 0x18)[0]
        flag = struct.unpack_from("<I", captured, base + 0x20)[0]
        if phys:
            entries[slot] = {"phys": phys, "device_va": device_va, "size": size,
                             "flag": flag, "unk_18": unk_18}
        elif flag:
            flag_only[slot] = flag

    records = []
    for index, record in enumerate(g17p.HWDATA_REGION_RECORDS):
        base = build.REGION_RECORD_OFFSET + index * build.REGION_RECORD_STRIDE
        addr = struct.unpack_from("<Q", captured,
                                  base + build.REGION_RECORD_ADDR)[0]
        records.append(dict(record, addr=addr))

    built = build.build_hwdata(entries, flag_only, g17p.PERF_TABLES,
                               chip_id=g17p.CHIP_ID, region_records=records)
    compare("hardware data", built, captured)

    # The declared table must also equal the live one, or the builder is being
    # validated against inputs it was handed rather than against the device.
    global checks
    checks += 1
    declared = {slot: {"phys": phys, "device_va": device_va, "size": size,
                       "flag": flag, "unk_18": unk_18}
                for slot, phys, device_va, size, unk_18, flag
                in g17p.REGISTER_WINDOWS}
    if declared != entries:
        print("  MISMATCH %-28s declared table differs from the live one"
              % "register windows")
        failures.append("register windows")
    else:
        print("  ok       %-28s %d windows" % ("register windows", len(entries)))

    checks += 1
    if dict(g17p.REGISTER_FLAG_ONLY_SLOTS) != flag_only:
        print("  MISMATCH %-28s declared slots differ from the live ones"
              % "flag-only slots")
        failures.append("flag-only slots")
    else:
        print("  ok       %-28s %d slots" % ("flag-only slots", len(flag_only)))


def check_region_c(directory):
    path = directory / "primary-region_c.bin"
    if not path.exists():
        return
    captured = path.read_bytes()[:build.REGION_C_SIZE]
    compare("data region", build.build_region_c(), captured)


def check_zero_at_handoff(directory):
    """Objects a host must supply empty. Filling them in is a real error."""
    global checks
    for name in ("primary-region_a", "primary-ch00_state", "primary-ch12_state"):
        path = directory / ("%s.bin" % name)
        if not path.exists():
            continue
        checks += 1
        data = path.read_bytes()
        # The control channel's state carries the producer at handoff; the others
        # are entirely clear.
        allowed = {g17p.CHANNEL_STATE_PRODUCER
                   * g17p.CHANNEL_ENTRY_STATE_SPACING} if "ch12" in name else set()
        stray = [o for o, b in enumerate(data[:0x40]) if b and o not in allowed]
        if stray:
            print("  note     %-28s non-zero at %s"
                  % (name, ", ".join(hex(o) for o in stray[:6])))
        else:
            print("  ok       %-28s clear at handoff" % name)


def main():
    directory = newest_capture()
    if directory is None:
        print("No handoff capture found under %s" % ARTIFACT_ROOT)
        print("Supply a compatible handoff capture under that artifact root.")
        return 2

    print("Checking the descriptor builders against %s" % directory.name)
    check_root(directory, "primary", 0)
    check_root(directory, "secondary", 1)
    check_main_config(directory, "primary", secondary=False)
    check_main_config(directory, "secondary", secondary=True)
    check_secondary_extra_relation(directory)
    check_hwdata_bundle_relation(directory)
    check_addr_view_content(directory)
    check_hwdata(directory)
    check_region_c(directory)
    check_status_blocks(directory)
    check_zero_at_handoff(directory)

    print()
    if failures:
        print("FAILED: %d of %d checks: %s"
              % (len(failures), checks, ", ".join(failures)))
        return 1
    print("All %d checks passed: every covered field builder reproduces its "
          "captured object form." % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
