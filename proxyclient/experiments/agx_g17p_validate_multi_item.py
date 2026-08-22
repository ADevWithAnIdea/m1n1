#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the multi-item submission model against a three-item capture.

    .venv/bin/python3 proxyclient/experiments/agx_g17p_validate_multi_item.py

Needs no hardware. It reads a captured submission that carries three work items, and
requires the model in ``m1n1/agx/g17p_submission.py`` to reproduce its structure: the
inner entry array, each item's pool records, and each item's common header.

This is a different capture from the one the other gates use. That one is the first
submission after initialisation and carries a single item, which cannot exercise any of
the per-item rules; this one is the thirteenth and carries three.

Exits non-zero on any mismatch.
"""

import json
import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.agx import g17p_submission as build     # noqa: E402

CAPTURE = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p/"
                       "live_submission_closure_20260727_103051")

failures = []
checks = 0


def check(label, got, want):
    global checks
    checks += 1
    if got == want:
        print("  ok       %-34s %s" % (label, want if isinstance(want, int)
                                       else ""))
        return
    print("  MISMATCH %-34s got %s want %s" % (label, got, want))
    failures.append(label)


def main():
    pages = json.loads((CAPTURE / "pages.json").read_text())
    target = json.loads((CAPTURE / "target.json").read_text())
    blob = (CAPTURE / "pages.bin").read_bytes()
    size = pages["page_size"]

    def value(raw):
        return int(raw, 0) if isinstance(raw, str) else int(raw)

    index = {value(r["dva"]): value(r["capture_offset"]) for r in pages["pages"]}

    def read(dva, count):
        out = b""
        while count:
            page = dva & ~(size - 1)
            if page not in index:
                raise RuntimeError("DVA %#x is not captured" % dva)
            offset = index[page] + (dva & (size - 1))
            take = min(count, size - (dva & (size - 1)))
            out += blob[offset:offset + take]
            dva += take
            count -= take
        return out

    print("Checking the multi-item model against %s" % CAPTURE.name)

    outer = bytes.fromhex(target["outer_hex"])
    queue = struct.unpack_from("<Q", outer, 8)[0]
    flags_head = struct.unpack_from("<I", outer, 0x14)[0]
    count = flags_head & 0xffff
    _, entry_array = struct.unpack("<QQ", read(queue, 0x10))
    captured_entries = list(struct.unpack("<%dQ" % count,
                                          read(entry_array, count * 8)))

    # The count is three an item, so the model's grouping has to divide it.
    check("entry count divides into items",
          count % build.INNER_ENTRIES_PER_ITEM, 0)
    items = count // build.INNER_ENTRIES_PER_ITEM
    print("           %d entries, %d work items" % (count, items))

    # The inner batch rebuilt from the captured triples must match byte for byte.
    triples = [tuple(captured_entries[i * 3:(i + 1) * 3]) for i in range(items)]
    built = build.build_inner_batch(triples)
    check("inner batch bytes", built, read(entry_array, count * 8))

    # Each item's advancing pointers must be the next record of each pool, and its
    # submit sequence must follow the observed odd tiling stream.
    first = triples[0][0]
    header = read(first, 0x40)
    layout = build.DESCRIPTOR_LAYOUT["tiling"]
    offset = layout["pointers"]
    pointers = [struct.unpack_from("<Q", header, offset)[0]]
    offset += 8 + layout["pointer_gap"]
    for _ in range(3):
        pointers.append(struct.unpack_from("<Q", header, offset)[0])
        offset += 8
    array_a_base, shared_one, array_b_base, shared_two = pointers

    for item in range(items):
        descriptor = read(triples[item][0], 0x40)
        got = [struct.unpack_from("<Q", descriptor, layout["pointers"])[0]]
        cursor = layout["pointers"] + 8 + layout["pointer_gap"]
        for _ in range(3):
            got.append(struct.unpack_from("<Q", descriptor, cursor)[0])
            cursor += 8
        want_a, want_b = build.item_pool_records(item, array_a_base, array_b_base)
        check("item %d first pool record" % item, got[0], want_a)
        check("item %d second pool record" % item, got[2], want_b)
        check("item %d shared pointers" % item, (got[1], got[3]),
              (shared_one, shared_two))
        submit_sequence = struct.unpack_from(
            "<Q", descriptor, build.SUBMIT_SEQUENCE_OFFSET)[0]
        context_id = struct.unpack_from(
            "<I", descriptor, build.CONTEXT_ID_OFFSET)[0]
        check("item %d selector" % item,
              struct.unpack_from("<I", descriptor, 0)[0],
              build.DESCRIPTOR_SELECTOR["tiling"])
        check("item %d submit sequence" % item, submit_sequence,
              build.item_submit_sequence("tiling", item))

        # Rebuild this item's whole descriptor, pointer block and register array, and
        # require the regions the model claims to match byte for byte. The other gate
        # does this for one degenerate descriptor; these three are from a submission
        # that carries real work, so they exercise register values the other cannot.
        full = read(triples[item][0], 0x960)
        registers = []
        cursor = layout["registers"]
        empties = 0
        while cursor + build.REGISTER_ENTRY_SIZE <= 0x960:
            number = struct.unpack_from("<I", full, cursor)[0]
            data = struct.unpack_from("<Q", full, cursor + 4)[0]
            if number == 0 and data == 0:
                empties += 1
                if empties >= 3:
                    break
            else:
                empties = 0
                registers.append((number, data))
            cursor += build.REGISTER_ENTRY_SIZE
        end = layout["registers"] + len(registers) * build.REGISTER_ENTRY_SIZE
        rebuilt = build.build_item_descriptor(
            "tiling", item, array_a_base, array_b_base,
            (shared_one, shared_two), registers, size=end,
            context_id=context_id)
        check("item %d common header bytes" % item,
              rebuilt[:0x10], full[:0x10])
        check("item %d register array bytes" % item,
              rebuilt[layout["registers"]:end], full[layout["registers"]:end])
        pointer_end = layout["pointers"] + 8 + layout["pointer_gap"] + 24
        check("item %d pointer block bytes" % item,
              rebuilt[layout["pointers"]:pointer_end],
              full[layout["pointers"]:pointer_end])
        print("           item %d: %d registers" % (item, len(registers)))

    print()
    if failures:
        print("FAILED: %d of %d checks: %s"
              % (len(failures), checks, ", ".join(failures)))
        return 1
    print("All %d checks passed: the multi-item model reproduces a three-item "
          "submission" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
