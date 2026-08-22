#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare a native G17P closure with generated pre-submit pages offline."""

import argparse
import json
import pathlib
import struct


PAGE = 0x4000
VA_MASK = (1 << 43) - 1
VA_HIGH = ((1 << 64) - 1) ^ VA_MASK


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def load_capture(path):
    manifest = json.loads((path / "pages.json").read_text())
    page_size = integer(manifest.get("page_size", PAGE))
    if page_size != PAGE:
        raise ValueError("unsupported page size %#x in %s" % (page_size, path))
    raw = (path / "pages.bin").read_bytes()
    pages = {}
    for record in manifest["pages"]:
        address = integer(record["dva"])
        offset = integer(record["capture_offset"])
        body = raw[offset:offset + PAGE]
        if len(body) != PAGE:
            raise ValueError("truncated page %#x in %s" % (address, path))
        pages[address] = (record, body)
    return manifest, pages


def source_kinds(record):
    sources = record.get("sources")
    if sources is None:
        source = record.get("source")
        sources = [] if source is None else [source]
    kinds = []
    for source in sources:
        kind = source.get("kind") if isinstance(source, dict) else str(source)
        if kind and kind not in kinds:
            kinds.append(kind)
    return kinds


def source_records(record):
    sources = record.get("sources")
    if sources is None:
        source = record.get("source")
        sources = [] if source is None else [source]
    return sources


def difference_runs(native, generated):
    runs = []
    offset = 0
    while offset < PAGE:
        if native[offset] == generated[offset]:
            offset += 1
            continue
        end = offset + 1
        while end < PAGE and native[end] != generated[end]:
            end += 1
        runs.append({
            "start": offset,
            "end": end,
            "native_hex": native[offset:end].hex(),
            "generated_hex": generated[offset:end].hex(),
        })
        offset = end
    return runs


def canonical_page(value):
    low = value & VA_MASK
    if value == (low | VA_HIGH) and (low & (1 << 42)):
        return value & ~(PAGE - 1)
    if 0x1000000000 <= value < 0x80000000000:
        return value & ~(PAGE - 1)
    return None


def pointer_pages(body):
    targets = set()
    for offset in range(0, PAGE, 8):
        target = canonical_page(struct.unpack_from("<Q", body, offset)[0])
        if target is not None:
            targets.add(target)
    return targets


def changed_pointer_words(native, generated):
    changes = []
    for offset in range(0, PAGE, 8):
        native_value = struct.unpack_from("<Q", native, offset)[0]
        generated_value = struct.unpack_from("<Q", generated, offset)[0]
        if native_value == generated_value:
            continue
        native_page = canonical_page(native_value)
        generated_page = canonical_page(generated_value)
        if native_page is None and generated_page is None:
            continue
        changes.append({
            "offset": offset,
            "native_value": native_value,
            "native_page": native_page,
            "generated_value": generated_value,
            "generated_page": generated_page,
        })
    return changes


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native", type=pathlib.Path)
    parser.add_argument("generated", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--max-pages", type=int, default=40)
    parser.add_argument("--max-runs", type=int, default=8)
    return parser.parse_args()


def main():
    args = parse_args()
    native_manifest, native_pages = load_capture(args.native)
    generated_manifest, generated_pages = load_capture(args.generated)
    native_addresses = set(native_pages)
    generated_addresses = set(generated_pages)
    shared_addresses = native_addresses & generated_addresses

    reports = []
    identical = 0
    for address in sorted(native_addresses):
        native_record, native_body = native_pages[address]
        generated = generated_pages.get(address)
        report = {
            "dva": address,
            "sources": source_kinds(native_record),
            "source_records": source_records(native_record),
            "native_nonzero_bytes": sum(byte != 0 for byte in native_body),
            "native_pointer_pages": sorted(pointer_pages(native_body)),
        }
        if generated is None:
            report["status"] = "missing"
            reports.append(report)
            continue

        generated_record, generated_body = generated
        report["translation"] = generated_record.get("translation")
        report["generated_nonzero_bytes"] = sum(
            byte != 0 for byte in generated_body)
        report["generated_pointer_pages"] = sorted(pointer_pages(generated_body))
        report["changed_pointer_words"] = changed_pointer_words(
            native_body, generated_body)
        if native_body == generated_body:
            report["status"] = "identical"
            report["differing_bytes"] = 0
            report["difference_runs"] = []
            identical += 1
        else:
            runs = difference_runs(native_body, generated_body)
            report["status"] = "different"
            report["differing_bytes"] = sum(
                run["end"] - run["start"] for run in runs)
            report["difference_runs"] = runs
        reports.append(report)

    missing = [report for report in reports if report["status"] == "missing"]
    different = [report for report in reports if report["status"] == "different"]
    different.sort(key=lambda report: (
        -report["differing_bytes"], report["dva"]))

    referenced_native = set()
    referenced_generated = set()
    for report in reports:
        referenced_native.update(report["native_pointer_pages"])
        referenced_generated.update(report.get("generated_pointer_pages", []))

    result = {
        "format": "m1n1-t8140-g17p-compute-state-comparison-v1",
        "native": str(args.native.resolve()),
        "generated": str(args.generated.resolve()),
        "native_page_count": len(native_pages),
        "generated_page_count": len(generated_pages),
        "same_address_page_count": len(shared_addresses),
        "identical_page_count": identical,
        "different_page_count": len(different),
        "missing_native_address_page_count": len(missing),
        "generated_only_page_count": len(generated_addresses - native_addresses),
        "native_pointer_targets_not_generated": sorted(
            referenced_native - generated_addresses),
        "generated_pointer_targets_not_generated": sorted(
            referenced_generated - generated_addresses),
        "generated_manifest_reference_bytes_read": generated_manifest.get(
            "reference_bytes_read"),
        "pages": reports,
    }
    output = args.output or args.generated / "native_comparison.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    print("comparison=%s" % output)
    print(
        "native=%d generated=%d shared=%d identical=%d different=%d "
        "missing=%d generated_only=%d" % (
            len(native_pages), len(generated_pages), len(shared_addresses),
            identical, len(different), len(missing),
            len(generated_addresses - native_addresses)))
    print("\nLargest same-address differences:")
    for report in different[:args.max_pages]:
        print("  %#018x diff=%5d runs=%4d nonzero=%5d/%5d sources=%s" % (
            report["dva"], report["differing_bytes"],
            len(report["difference_runs"]), report["native_nonzero_bytes"],
            report["generated_nonzero_bytes"],
            ",".join(report["sources"]) or "-"))
        for run in report["difference_runs"][:args.max_runs]:
            print("    +%#06x..+%#06x native=%s generated=%s" % (
                run["start"], run["end"], run["native_hex"],
                run["generated_hex"]))
        omitted = len(report["difference_runs"]) - args.max_runs
        if omitted > 0:
            print("    ... %d more runs" % omitted)

    print("\nMissing native-address pages:")
    for report in missing[:args.max_pages]:
        print("  %#018x nonzero=%5d pointers=%3d sources=%s" % (
            report["dva"], report["native_nonzero_bytes"],
            len(report["native_pointer_pages"]),
            ",".join(report["sources"]) or "-"))
    if len(missing) > args.max_pages:
        print("  ... %d more pages" % (len(missing) - args.max_pages))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
