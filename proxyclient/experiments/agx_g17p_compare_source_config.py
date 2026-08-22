#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare a source-built pre-CL2 config snapshot with native state."""

import argparse
import hashlib
import json
import pathlib
import struct


PAGE = 0x4000
DEFAULT_NATIVE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_add3_full_positive_20260811_230235"
)


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def runs(mask):
    result = []
    start = None
    for offset, value in enumerate(mask):
        if value and start is None:
            start = offset
        elif not value and start is not None:
            result.append((start, offset))
            start = None
    if start is not None:
        result.append((start, len(mask)))
    return result


def describe_runs(spans, source, native):
    return [{
        "start": start,
        "end": end,
        "size": end - start,
        "source_head": source[start:min(end, start + 32)].hex(),
        "native_head": native[start:min(end, start + 32)].hex(),
    } for start, end in spans]


def region(translation, address):
    if translation == "firmware-high":
        if 0xFFFFFC20C0788000 <= address < 0xFFFFFC20C07B0000:
            return "hardware-data/main-config bundle"
        if 0xFFFFFC2000020000 <= address < 0xFFFFFC2000198000:
            return "private config/state cluster"
        if address == 0xFFFFFC20001A8000:
            return "primary initdata root"
        if address == 0xFFFFFC20001B0000:
            return "secondary initdata root"
    return "root pointer closure"


def location(translation, page, offset):
    absolute = page + offset
    result = {"absolute": absolute, "page_offset": offset}
    if translation == "firmware-high":
        if 0xFFFFFC20C0788000 <= absolute < 0xFFFFFC20C07B0000:
            result["hwdata_bundle_offset"] = absolute - 0xFFFFFC20C0788000
        main = 0xFFFFFC20C07A65C0
        if main <= absolute < main + 0x600:
            result["main_config_offset"] = absolute - main
        if 0xFFFFFC2000020000 <= absolute < 0xFFFFFC2000198000:
            result["private_cluster_offset"] = absolute - 0xFFFFFC2000020000
    return result


class Native:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.manifest = json.loads((self.path / "manifest.json").read_text())
        self.ram = (self.path / self.manifest["ram_file"]).read_bytes()
        self.roots = {}
        for group in self.manifest["root_mappings"]:
            key = (integer(group["root_ctx_id"]), integer(group["selector"]))
            self.roots[key] = {
                integer(mapping["va"]): mapping
                for mapping in group["mappings"]
            }

    def blob(self, index):
        start = integer(index) * PAGE
        body = self.ram[start:start + PAGE]
        if len(body) != PAGE:
            raise RuntimeError("short native blob %d" % integer(index))
        return body

    def pointer_target(self, value):
        page = value & ~(PAGE - 1)
        if value >= 0xFFFF000000000000:
            roots = ((64, 1),)
        else:
            roots = ((0, 0),)
        for root in roots:
            if page in self.roots.get(root, {}):
                return {
                    "root_context": root[0],
                    "root_selector": root[1],
                    "page": page,
                    "page_offset": value - page,
                }
        return None


class Source:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.manifest = json.loads((self.path / "pages.json").read_text())
        self.raw = (self.path / "pages.bin").read_bytes()

    def pages(self):
        for record in self.manifest["pages"]:
            start = integer(record["capture_offset"])
            body = self.raw[start:start + PAGE]
            if len(body) != PAGE:
                raise RuntimeError("short source page at offset %#x" % start)
            yield record, body


def compare_page(native, record, source_body):
    native_body = native.blob(record["native_blob_index"])
    different = [left != right
                 for left, right in zip(source_body, native_body)]
    native_missing = [left == 0 and right != 0
                      for left, right in zip(source_body, native_body)]
    source_extra = [left != 0 and right == 0
                    for left, right in zip(source_body, native_body)]
    translation = record["translation"]
    address = integer(record["dva"])

    pointers = []
    for offset in range(0, PAGE - 7, 4):
        native_value = struct.unpack_from("<Q", native_body, offset)[0]
        target = native.pointer_target(native_value)
        if target is None:
            continue
        source_value = struct.unpack_from("<Q", source_body, offset)[0]
        if source_value == native_value:
            continue
        pointers.append({
            "location": location(translation, address, offset),
            "source": source_value,
            "native": native_value,
            "source_is_zero": source_value == 0,
            "native_target": target,
            "source_target": native.pointer_target(source_value),
        })

    diff_spans = runs(different)
    missing_spans = runs(native_missing)
    extra_spans = runs(source_extra)
    return {
        "translation": translation,
        "dva": address,
        "pa": integer(record["pa"]),
        "region": region(translation, address),
        "source_sha256": sha256(source_body),
        "native_sha256": sha256(native_body),
        "differing_bytes": sum(different),
        "differing_runs": describe_runs(diff_spans, source_body, native_body),
        "native_nonzero_source_zero_bytes": sum(native_missing),
        "native_nonzero_source_zero_runs": describe_runs(
            missing_spans, source_body, native_body),
        "source_nonzero_native_zero_bytes": sum(source_extra),
        "source_nonzero_native_zero_runs": describe_runs(
            extra_spans, source_body, native_body),
        "differing_native_pointers": pointers,
        "native_pointer_source_zero_count": sum(
            pointer["source_is_zero"] for pointer in pointers),
    }


def markdown(report):
    lines = [
        "# Source vs native pre-CL2 config delta",
        "",
        "The source world has completed 62 output-positive renders and is at "
        "primary control `[67, 67, 67]`. No CL2 client or firmware object has "
        "been built. The native reference is immediately before its known-good "
        "add3 compute publication.",
        "",
        "## Totals",
        "",
        "- Compared pages: %d" % report["totals"]["compared_pages"],
        "- Byte-identical pages: %d" % report["totals"]["identical_pages"],
        "- Differing bytes: %d" % report["totals"]["differing_bytes"],
        "- Native-nonzero/source-zero bytes: %d" %
        report["totals"]["native_nonzero_source_zero_bytes"],
        "- Native pointers differing from source: %d" %
        report["totals"]["differing_native_pointers"],
        "- Native pointers whose source field is zero: %d" %
        report["totals"]["native_pointer_source_zero_count"],
        "",
        "## Highest-signal pages",
        "",
        "| rank | translation | DVA | region | missing bytes | missing pointers | total diff |",
        "|---:|---|---:|---|---:|---:|---:|",
    ]
    for index, page in enumerate(report["ranked_pages"][:50], 1):
        lines.append(
            "| %d | %s | `0x%x` | %s | %d | %d | %d |" % (
                index, page["translation"], page["dva"], page["region"],
                page["native_nonzero_source_zero_bytes"],
                page["native_pointer_source_zero_count"],
                page["differing_bytes"]))
    lines.extend(["", "## Missing native pointers", ""])
    missing = report["native_pointers_source_zero"]
    if not missing:
        lines.append("None.")
    else:
        lines.extend([
            "| source page | offset | decoded offset | native target |",
            "|---:|---:|---|---:|",
        ])
        for pointer in missing:
            where = pointer["location"]
            decoded = ", ".join(
                "%s=0x%x" % (key, value) for key, value in where.items()
                if key not in ("absolute", "page_offset")) or "unlabeled"
            lines.append("| `0x%x` | `0x%x` | %s | `0x%x` |" % (
                pointer["page"], where["page_offset"], decoded,
                pointer["native"]))
    lines.extend([
        "",
        "`report.json` contains every differing byte run and pointer delta; "
        "this summary is only the ranked index.",
        "",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("--native", type=pathlib.Path, default=DEFAULT_NATIVE)
    args = parser.parse_args()

    source = Source(args.source)
    native = Native(args.native)
    pages = [compare_page(native, record, body)
             for record, body in source.pages()]
    ranked = sorted(
        pages,
        key=lambda page: (
            page["native_pointer_source_zero_count"],
            page["native_nonzero_source_zero_bytes"],
            page["differing_bytes"]),
        reverse=True,
    )
    missing_pointers = []
    for page in pages:
        for pointer in page["differing_native_pointers"]:
            if pointer["source_is_zero"]:
                missing_pointers.append({
                    **pointer,
                    "page": page["dva"],
                    "translation": page["translation"],
                    "region": page["region"],
                })
    report = {
        "format": "m1n1-t8140-g17p-source-native-config-delta-v1",
        "source": str(args.source),
        "native": str(args.native),
        "source_phase": source.manifest["phase"],
        "totals": {
            "compared_pages": len(pages),
            "identical_pages": sum(page["differing_bytes"] == 0
                                    for page in pages),
            "differing_bytes": sum(page["differing_bytes"] for page in pages),
            "native_nonzero_source_zero_bytes": sum(
                page["native_nonzero_source_zero_bytes"] for page in pages),
            "source_nonzero_native_zero_bytes": sum(
                page["source_nonzero_native_zero_bytes"] for page in pages),
            "differing_native_pointers": sum(
                len(page["differing_native_pointers"]) for page in pages),
            "native_pointer_source_zero_count": len(missing_pointers),
        },
        "native_pointers_source_zero": missing_pointers,
        "ranked_pages": ranked,
    }
    (args.source / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")
    (args.source / "summary.md").write_text(markdown(report))
    print(json.dumps(report["totals"], indent=2, sort_keys=True))
    print("Wrote %s and %s" % (
        args.source / "report.json", args.source / "summary.md"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
