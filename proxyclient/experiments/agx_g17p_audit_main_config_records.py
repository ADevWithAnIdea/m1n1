#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the main-config scheduler-record closure at a native CL2 boundary."""

import argparse
import hashlib
import json
import pathlib
import struct
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import agx_g17p_compute as current  # noqa: E402


PAGE = 0x4000
ROOT = 0xFFFFFC20001A8000
MAIN_PAGE = 0xFFFFFC20C07A4000
MAIN_OBJECT = 0xFFFFFC20C07A65C0
PREDECESSOR = current.PRIMARY_RECORD_PREDECESSOR
SENTINEL = current.PRIMARY_RECORD_SENTINEL
A_HIGH = current.PRIMARY_RECORD_A_HIGH
A_LOW = current.PRIMARY_RECORD_A_LOW
B_HIGH = current.PRIMARY_RECORD_B_HIGH
B_LOW = current.PRIMARY_RECORD_B_LOW
OUTPUT = 0x1000018000

DEFAULT_CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_outer_submit_20260810_192452/CL_2"
)
DEFAULT_AUG6 = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260806_085451/CL_2"
)


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def u32(body, offset):
    return struct.unpack_from("<I", body, offset)[0]


def u64(body, offset):
    return struct.unpack_from("<Q", body, offset)[0]


def difference_runs(left, right):
    runs = []
    offset = 0
    while offset < min(len(left), len(right)):
        if left[offset] == right[offset]:
            offset += 1
            continue
        end = offset + 1
        while end < min(len(left), len(right)) and left[end] != right[end]:
            end += 1
        runs.append({
            "start": offset,
            "end": end,
            "left_hex": left[offset:end].hex(),
            "right_hex": right[offset:end].hex(),
        })
        offset = end
    return runs


def comparison(left, right):
    runs = difference_runs(left, right)
    return {
        "byte_exact": not runs and len(left) == len(right),
        "differing_bytes": sum(run["end"] - run["start"] for run in runs),
        "runs": runs,
        "left_sha256": sha256(left),
        "right_sha256": sha256(right),
    }


class Capture:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        manifest = json.loads((self.path / "pages.json").read_text())
        raw = (self.path / "pages.bin").read_bytes()
        self.records = {}
        self.pages = {}
        for record in manifest["pages"]:
            dva = int(record["dva"])
            offset = int(record["capture_offset"])
            body = raw[offset:offset + PAGE]
            if len(body) != PAGE:
                raise RuntimeError("short page %#x in %s" % (dva, path))
            self.records[dva] = record
            self.pages[dva] = body

    def page(self, dva):
        try:
            return self.pages[dva]
        except KeyError as error:
            raise RuntimeError("%s lacks page %#x" % (self.path, dva)) from error

    def read(self, address, size):
        page = address & ~(PAGE - 1)
        offset = address - page
        if offset + size > PAGE:
            raise RuntimeError("cross-page read not implemented")
        return self.page(page)[offset:offset + size]


def expected_pages(final_26_6=False):
    predecessor_u32 = (
        current.FINAL_26_6_COMPUTE_PREDECESSOR_U32
        if final_26_6 else current.NATIVE_COMPUTE_PREDECESSOR_U32)
    predecessor_u64 = (
        current.FINAL_26_6_COMPUTE_PREDECESSOR_U64
        if final_26_6 else current.NATIVE_COMPUTE_PREDECESSOR_U64)
    records_a = (
        current.FINAL_26_6_COMPUTE_RECORDS_A
        if final_26_6 else current.NATIVE_COMPUTE_RECORDS_A)
    records_b = (
        current.FINAL_26_6_COMPUTE_RECORDS_B
        if final_26_6 else current.NATIVE_COMPUTE_RECORDS_B)
    predecessor = bytearray(PAGE)
    for offset, value in predecessor_u32:
        struct.pack_into("<I", predecessor, offset, value)
    for offset, value in predecessor_u64:
        struct.pack_into("<Q", predecessor, offset, value)

    page_a = bytearray(PAGE)
    for index, record in enumerate(records_a):
        struct.pack_into("<4I", page_a, index * 0x10, *record)

    page_b = bytearray(PAGE)
    for index, record in enumerate(records_b):
        struct.pack_into("<5I", page_b, index * 0x20, *record)

    return {
        PREDECESSOR: bytes(predecessor),
        SENTINEL: bytes(PAGE),
        A_HIGH: bytes(page_a),
        B_HIGH: bytes(page_b),
    }


def nonzero_words(body):
    return [
        {"offset": offset, "value": u32(body, offset)}
        for offset in range(0, PAGE, 4)
        if u32(body, offset)
    ]


def decode_records_a(body):
    records = []
    for index in range(PAGE // 0x10):
        values = struct.unpack_from("<4I", body, index * 0x10)
        if not any(values):
            continue
        records.append({"index": index, "offset": index * 0x10,
                        "u32": list(values)})
    return records


def decode_records_b(body):
    records = []
    for index in range(PAGE // 0x20):
        values = struct.unpack_from("<8I", body, index * 0x20)
        if not any(values):
            continue
        records.append({"index": index, "offset": index * 0x20,
                        "u32": list(values)})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", nargs="?", type=pathlib.Path,
                        default=DEFAULT_CAPTURE)
    parser.add_argument("--aug6", type=pathlib.Path, default=DEFAULT_AUG6)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    capture = Capture(args.capture)
    aug6 = Capture(args.aug6)
    expected = expected_pages()
    expected_final = expected_pages(final_26_6=True)
    target = json.loads((args.capture / "target.json").read_text())

    root_main = u64(capture.page(ROOT), 0x18)
    if root_main != MAIN_OBJECT:
        raise RuntimeError("root +0x18 is %#x, expected %#x" %
                           (root_main, MAIN_OBJECT))
    main = capture.read(root_main, 0x600)
    main_region = [u64(main, 0x2D0 + index * 8) for index in range(6)]

    topology = {
        "root": ROOT,
        "root_main_config_offset": 0x18,
        "root_main_config": root_main,
        "main_config_page": MAIN_PAGE,
        "main_config_page_offset": root_main - MAIN_PAGE,
        "main_region_offset": 0x2D0,
        "main_region_qwords": main_region,
        "expected_main_region_qwords": [
            SENTINEL, A_LOW, A_HIGH, B_LOW, B_HIGH, 0,
        ],
        "a_alias": {
            "high_dva": A_HIGH,
            "low_dva": A_LOW,
            "high_pa": int(capture.records[A_HIGH]["pa"]),
            "low_pa": int(capture.records[A_LOW]["pa"]),
            "same_pa": (int(capture.records[A_HIGH]["pa"]) ==
                        int(capture.records[A_LOW]["pa"])),
            "same_bytes": capture.page(A_HIGH) == capture.page(A_LOW),
        },
        "b_alias": {
            "high_dva": B_HIGH,
            "low_dva": B_LOW,
            "high_pa": int(capture.records[B_HIGH]["pa"]),
            "low_pa": int(capture.records[B_LOW]["pa"]),
            "same_pa": (int(capture.records[B_HIGH]["pa"]) ==
                        int(capture.records[B_LOW]["pa"])),
            "same_bytes": capture.page(B_HIGH) == capture.page(B_LOW),
        },
    }

    pages = {}
    labels = {
        PREDECESSOR: "predecessor",
        SENTINEL: "sentinel",
        A_HIGH: "record_a",
        B_HIGH: "record_b",
    }
    for dva, generated in expected.items():
        native = capture.page(dva)
        entry = {
            "dva": dva,
            "pa": int(capture.records[dva]["pa"]),
            "nonzero_u32": nonzero_words(native),
            "against_current_constructor": comparison(native, generated),
            "against_final_26_6_constructor": comparison(
                native, expected_final[dva]),
        }
        if dva in aug6.pages:
            entry["against_aug6_positive"] = comparison(
                native, aug6.page(dva))
        pages[labels[dva]] = entry

    pages["record_a"]["records_0x10"] = decode_records_a(
        capture.page(A_HIGH))
    pages["record_b"]["records_0x20"] = decode_records_b(
        capture.page(B_HIGH))

    settled_path = args.capture / "target_after_settled.bin"
    witness = None
    if settled_path.exists():
        before = capture.page(OUTPUT)
        after = settled_path.read_bytes()
        witness = comparison(before, after)
        witness.update({
            "dva": OUTPUT,
            "pa": int(capture.records[OUTPUT]["pa"]),
        })

    report = {
        "format": "m1n1-t8140-g17p-main-config-record-audit-v1",
        "capture": str(args.capture),
        "capture_target": {
            key: target[key] for key in (
                "channel", "producer_before", "producer_after",
                "entry_index", "outer_dva")
        },
        "aug6_capture": str(args.aug6),
        "topology": topology,
        "topology_exact": (
            main_region == topology["expected_main_region_qwords"] and
            topology["a_alias"]["same_pa"] and
            topology["a_alias"]["same_bytes"] and
            topology["b_alias"]["same_pa"] and
            topology["b_alias"]["same_bytes"]
        ),
        "pages": pages,
        "physical_output_witness": witness,
    }

    output = args.output or (args.capture / "main_config_record_audit.json")
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print("capture", args.capture)
    print("output", output)
    print("topology_exact", report["topology_exact"])
    for label, entry in pages.items():
        generated = entry["against_current_constructor"]
        final = entry["against_final_26_6_constructor"]
        aug6_result = entry.get("against_aug6_positive")
        print(
            "%s nonzero_u32=%d aug6_constructor_diff=%d "
            "final_26_6_constructor_diff=%d aug6_capture_diff=%s" % (
                label,
                len(entry["nonzero_u32"]),
                generated["differing_bytes"],
                final["differing_bytes"],
                (aug6_result["differing_bytes"]
                 if aug6_result is not None else "missing"),
            )
        )
    if witness is not None:
        print("physical_output_changed", witness["differing_bytes"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
