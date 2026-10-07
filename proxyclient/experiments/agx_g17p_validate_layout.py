#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the T8140/G17P layout constants against a live probe artifact.

Usage:
    .venv/bin/python3 proxyclient/experiments/agx_g17p_validate_layout.py [ARTIFACT_DIR]

``m1n1/agx/g17p.py`` holds only hardware-confirmed facts. This checks every one
of them against an artifact produced by ``proxyclient/hv/probe_agx_g17p_items.py``
so the backend constants cannot drift away from the captured evidence. It reads
saved artifacts only and never touches hardware.

The module is loaded by path rather than as ``m1n1.agx.g17p`` because importing
the package pulls in the full AGX stack, which needs a configured session.
"""

import collections
import glob
import importlib.util
import json
import os
import struct
import sys

ARTIFACT_ROOT = "/Users/user/asahi_re/artifacts/agx_g17p"
MODULE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "m1n1", "agx", "g17p.py",
)


def load_module():
    spec = importlib.util.spec_from_file_location("g17p_layout", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def latest_probe():
    candidates = sorted(glob.glob(os.path.join(ARTIFACT_ROOT, "live_probe_*")))
    if not candidates:
        raise SystemExit("no live_probe_* artifact under %s" % ARTIFACT_ROOT)
    return candidates[-1]


def check(label, condition, detail=""):
    print("%-4s %s%s" % ("ok" if condition else "FAIL", label,
                         "" if not detail else "  [%s]" % detail))
    return bool(condition)


def main():
    artifact = sys.argv[1] if len(sys.argv) > 1 else latest_probe()
    g = load_module()
    with open(os.path.join(artifact, "probe.json")) as handle:
        report = json.load(handle)
    with open(os.path.join(artifact, "items.bin"), "rb") as handle:
        items_raw = handle.read()

    print("artifact: %s" % artifact)
    print("channel %s producer %d -> %d, %d live items of %d slots\n" % (
        report["channel"], report["producer_before"], report["producer_after"],
        report["live_item_count"], report["inner_slot_total"]))

    passed = True

    outer = bytes.fromhex(report["live_structures"]["outer"])
    queue_refs = list(g.outer_queue_pointers(outer))
    passed &= check("outer record decodes to populated subrecords",
                    queue_refs, "%d refs" % len(queue_refs))

    selectors = {int(k): v for k, v in report["items_by_type"].items()}
    known = {g.SELECTOR_GEOMETRY, g.SELECTOR_RENDER,
             g.SELECTOR_EVENT, g.SELECTOR_OPTIONAL}
    passed &= check("every observed selector is a known constant",
                    set(selectors) <= known, str(selectors))

    # The 0x2240 record is the render item, selector 1.
    geometry = [i for i in report["items"] if i["type"] == g.SELECTOR_RENDER]
    if geometry:
        deltas = {geometry[i + 1]["dva"] - geometry[i]["dva"]
                  for i in range(len(geometry) - 1)}
        passed &= check(
            "record addresses lie on the %#x pool stride" % g.RENDER_ITEM_SIZE,
            all(d % g.RENDER_ITEM_SIZE == 0 for d in deltas),
            " ".join(hex(d) for d in sorted(deltas)))

        required = set(g.RENDER_ITEM_POINTER_OFFSETS)
        optional = set(g.RENDER_ITEM_OPTIONAL_POINTER_OFFSETS)
        missing, unexpected, optional_seen = [], [], 0
        for item in geometry:
            # A probe may have used a window narrower than the record, so only
            # require the offsets the artifact actually read.
            window = min(
                item.get("bytes_read",
                         report.get("item_stride_captured", g.RENDER_ITEM_SIZE)),
                g.RENDER_ITEM_SIZE)
            offsets = {f["offset"] for f in item["pointer_fields"]
                       if f["offset"] < window}
            if not {o for o in required if o < window} <= offsets:
                missing.append(item["dva"])
            extra = offsets - required
            if not extra <= optional:
                unexpected.append(item["dva"])
            optional_seen += len(extra)
        passed &= check("all records carry the required pointer offsets",
                        not missing, "%d missing" % len(missing))
        passed &= check("extra pointer offsets are declared optional",
                        not unexpected,
                        "optional present in %d/%d" % (optional_seen, len(geometry)))

        contexts = {struct.unpack_from(
            "<I", items_raw,
            item["capture_offset"] + g.RENDER_ITEM_CONTEXT_OFFSET)[0]
            for item in geometry}
        passed &= check("context value is constant across records",
                        len(contexts) == 1, str(contexts))

        progress = [f for item in geometry for f in item["pointer_fields"]
                    if f["offset"] in g.RENDER_ITEM_PROGRESS_OFFSETS]
        passed &= check("progress group is fully populated and mapped",
                        len(progress) == len(g.RENDER_ITEM_PROGRESS_OFFSETS)
                        * len(geometry) and all(f["mapped"] for f in progress),
                        "%d pointers" % len(progress))

    array_items = [i for i in report["items"] if i["type"] == g.SELECTOR_OPTIONAL]
    if array_items:
        base = set(g.ARRAY_ITEM_SUBRECORD_POINTER_OFFSETS)
        total = sum(len(i["pointer_fields"]) for i in array_items)
        hits = sum(1 for i in array_items for f in i["pointer_fields"]
                   if f["offset"] % g.ARRAY_ITEM_SUBRECORD_SIZE in base)
        passed &= check(
            "most array pointers fall on the %#x subrecord repeat"
            % g.ARRAY_ITEM_SUBRECORD_SIZE,
            total and hits * 100 >= total * 80, "%d/%d" % (hits, total))

    data_items = [i for i in report["items"] if i["type"] == g.SELECTOR_EVENT]
    if data_items:
        passed &= check("data records carry no pointer fields",
                        all(not i["pointer_fields"] for i in data_items),
                        "%d records" % len(data_items))

    unmapped = report["unmapped_pointer_targets"]
    passed &= check("the all-ones sentinel is rejected as an address",
                    not g.is_dva(g.SENTINEL_ALL_ONES),
                    "%d unmapped refs recorded" % len(unmapped))
    passed &= check("mailbox helpers round-trip",
                    g.mbox_selector(g.work_doorbell()) == g.MSG_WORK_DOORBELL
                    and g.next_producer(0xff) == 0)

    counts = collections.Counter(i["type"] for i in report["items"])
    print("\nselector counts: %s" % dict(sorted(counts.items())))
    print("result: %s" % ("PASS" if passed else "FAIL"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
