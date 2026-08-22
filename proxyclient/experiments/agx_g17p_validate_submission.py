#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the submission builders against a captured submission.

    .venv/bin/python3 proxyclient/experiments/agx_g17p_validate_submission.py

Needs no hardware. It rebuilds each part of a captured submission from the model in
``m1n1/agx/g17p_submission.py``, using the capture's own addresses, and requires a
byte-for-byte match.

This is the same discipline as the descriptor gate: feeding the builder the capture's
addresses makes it a test of the model rather than of the addresses, so anything the
model does not know how to produce shows up as a difference.

Exits non-zero on any mismatch.
"""

import json
import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.agx import g17p_submission as build     # noqa: E402

SNAPSHOT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p/"
                        "pre_work_0x83_v2_20260724_193713")
ARRAY_A_DVA = 0xfffffc20c0828100
ARRAY_B_DVA = 0xfffffc20c0838080
DESCRIPTORS = (("tiling", 0xfffffc20c0018000),
               ("fragment", 0xfffffc20c00b0000))
OPTIONAL_ITEMS = {
    "tiling": 0xfffffc20c06000c0,
    "fragment": 0xfffffc20c0600000,
}
EVENT_ITEMS = {
    "tiling": 0xfffffc20c05e8040,
    "fragment": 0xfffffc20c05e8000,
}
SHARED_OBJECT = 0xfffffc20c0868000
ZERO_SHARED_OBJECT = 0xfffffc20c083a800
LEAF_PAGES = {
    "primary_index": 0xfffffc20c0850000,
    "secondary_index": 0xfffffc20c0840000,
    "pool_a_slots": 0xfffffc2001600000,
    "pool_b_slots": 0xfffffc2001620000,
    "shared_slots": 0xfffffc2001618000,
    "flag": 0xfffffc2001628000,
}
PAGE = 0x4000

failures = []
checks = 0


def reader(snapshot):
    manifest = json.loads((snapshot / "manifest.json").read_text())

    def value(raw):
        return int(raw, 0) if isinstance(raw, str) else int(raw)

    index = {}
    for mapping in manifest["mappings"]:
        if mapping.get("blob_index") is None:
            continue
        index[value(mapping["va"])] = value(mapping["blob_index"])
    handle = open(snapshot / manifest["ram_file"], "rb")

    def read(dva, size):
        out = b""
        while size:
            page = dva & ~(PAGE - 1)
            if page not in index:
                raise RuntimeError("DVA %#x is not captured" % dva)
            handle.seek(index[page] * PAGE)
            blob = handle.read(PAGE)
            offset = dva & (PAGE - 1)
            take = min(size, PAGE - offset)
            out += blob[offset:offset + take]
            dva += take
            size -= take
        return out

    return read


def compare(label, built, captured):
    global checks
    checks += 1
    size = min(len(built), len(captured))
    bad = [i for i in range(size) if built[i] != captured[i]]
    if not bad:
        print("  ok       %-30s %#x bytes" % (label, size))
        return
    print("  MISMATCH %-30s %d of %#x bytes differ, first at +%#x"
          % (label, len(bad), size, bad[0]))
    print("             built %s  captured %s"
          % (built[bad[0]:bad[0] + 8].hex(), captured[bad[0]:bad[0] + 8].hex()))
    failures.append(label)


def main():
    read = reader(SNAPSHOT)
    print("Checking the submission builders against %s" % SNAPSHOT.name)

    # The record arrays, from the capture's own slot bases.
    captured = read(ARRAY_A_DVA, build.ARRAY_A_RECORDS * build.ARRAY_A_STRIDE)
    slot_base = struct.unpack_from("<Q", captured, 0)[0]
    compare("record array A", build.build_record_array_a(slot_base), captured)

    captured = read(ARRAY_B_DVA, build.ARRAY_B_RECORDS * build.ARRAY_B_STRIDE)
    slot_base = struct.unpack_from("<Q", captured, build.ARRAY_B_SLOT_OFFSET)[0]
    shared = struct.unpack_from("<Q", captured, build.ARRAY_B_SHARED_OFFSET)[0]
    compare("record array B",
            build.build_record_array_b(slot_base, shared), captured)

    captured = read(SHARED_OBJECT, build.SHARED_OBJECT_SIZE)
    addresses = [
        struct.unpack_from("<Q", captured, offset)[0]
        for offset in build.SHARED_OBJECT_POINTER_OFFSETS
    ]
    compare("packed shared object",
            build.build_shared_object(addresses), captured)
    compare("zero shared object",
            build.build_zero_shared_object(),
            read(ZERO_SHARED_OBJECT, build.ZERO_SHARED_OBJECT_SIZE))
    for name, body in build.build_submission_leaf_pages().items():
        compare("%s leaf page" % name, body, read(LEAF_PAGES[name], PAGE))

    # The native first group's selector-0x0f items, constructed from their pointer
    # fields and the kind-specific scalar recipe.
    for kind, dva in OPTIONAL_ITEMS.items():
        captured = read(dva, build.OPTIONAL_ITEM_SIZE)
        pointers = {
            name: struct.unpack_from("<Q", captured, offset)[0]
            for name, offset in build.OPTIONAL_ITEM_POINTER_OFFSETS.items()
            if name != "tiling_shared_object"
        }
        if kind == "tiling":
            pointers["tiling_shared_object"] = struct.unpack_from(
                "<Q", captured,
                build.OPTIONAL_ITEM_POINTER_OFFSETS["tiling_shared_object"])[0]
        compare(
            "%s optional item" % kind,
            build.build_optional_item(kind, **pointers),
            captured,
        )

    for kind, dva in EVENT_ITEMS.items():
        captured = read(dva, build.EVENT_RECORD_SIZE)
        subtype = struct.unpack_from("<I", captured, 0x04)[0]
        group_number = (
            struct.unpack_from("<I", captured, 0x08)[0]
            >> build.EVENT_COUNTER_SHIFT
        )
        unk_10 = struct.unpack_from("<I", captured, 0x10)[0]
        compare(
            "%s event record" % kind,
            build.build_event_record(group_number, subtype, unk_10),
            captured,
        )

    # The pointer block and register array of each descriptor, rebuilt from the
    # capture's own addresses and register values.
    for kind, dva in DESCRIPTORS:
        page = read(dva & ~(PAGE - 1), PAGE)
        base = dva & (PAGE - 1)
        layout = build.DESCRIPTOR_LAYOUT[kind]
        register_start = layout["registers"]

        offset = base + layout["pointers"]
        objects = [struct.unpack_from("<Q", page, offset)[0]]
        offset += 8 + layout["pointer_gap"]
        for _ in range(3):
            objects.append(struct.unpack_from("<Q", page, offset)[0])
            offset += 8

        registers = []
        cursor = base + register_start
        empties = 0
        while cursor + build.REGISTER_ENTRY_SIZE <= PAGE:
            number = struct.unpack_from("<I", page, cursor)[0]
            data = struct.unpack_from("<Q", page, cursor + 4)[0]
            if number == 0 and data == 0:
                empties += 1
                if empties >= 3:
                    break
            else:
                empties = 0
                registers.append((number, data))
            cursor += build.REGISTER_ENTRY_SIZE

        end = base + register_start + len(registers) * build.REGISTER_ENTRY_SIZE
        submit_sequence = struct.unpack_from("<Q", page, base + 4)[0]
        context_id = struct.unpack_from("<I", page, base + 0xc)[0]
        built = build.build_descriptor(
            kind, objects, registers, size=end - base,
            submit_sequence=submit_sequence, context_id=context_id)
        captured_body = page[base:end]

        # Compare only the regions the model claims to build. Comparing the whole
        # descriptor would fail permanently on fields the model deliberately leaves
        # alone, which makes a gate useless; those are enumerated below instead so the
        # remaining gap is measured rather than hidden.
        compare("%s common header" % kind, built[:0x10], captured_body[:0x10])
        pointer_end = layout["pointers"] + 8 + layout["pointer_gap"] + 24
        compare("%s pointer block" % kind,
                built[layout["pointers"]:pointer_end],
                captured_body[layout["pointers"]:pointer_end])
        compare("%s register array" % kind,
                built[register_start:], captured_body[register_start:])

        runs = []
        index = 0
        while index < len(captured_body):
            if built[index] != captured_body[index]:
                stop = index
                while stop < len(captured_body) and built[stop] != captured_body[stop]:
                    stop += 1
                runs.append((index, stop))
                index = stop
            else:
                index += 1
        total = sum(stop - start for start, stop in runs)
        print("  gap      %-30s %d bytes the model does not build, in %d runs"
              % ("%s descriptor" % kind, total, len(runs)))
        for start, stop in runs:
            print("             +%#05x..%#05x  %s"
                  % (start, stop, captured_body[start:stop].hex()))

    print()
    if failures:
        print("FAILED: %d of %d checks: %s"
              % (len(failures), checks, ", ".join(failures)))
        return 1
    print("All %d checks passed: the submission model reproduces a captured "
          "submission" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
