#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare firmware-owned peer transitions between native and source compute.

Both captures use offsets relative to the ADT private carveouts and the common
firmware UAT base.  This tool compares transitions rather than absolute state,
so unrelated allocation addresses do not hide a missing lifecycle update.
"""

import argparse
import json
import pathlib
import struct


PAGE = 0x4000
NATIVE_ROOT_OFFSET = 0x1A8000
SECONDARY_ROOT_DELTA = 0x8000

DEFAULT_NATIVE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_compute_peer_boundaries_20260813_112831"
)
DEFAULT_SOURCE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "boot_20260813_113706"
)


def _u64(data, offset):
    start = offset & ~7
    return struct.unpack_from("<Q", data, start)[0]


def _hex(value):
    return "0x%016x" % value


def _load_native(root):
    manifest = json.loads((root / "manifest.json").read_text())
    snapshots = {record["ordinal"]: record for record in manifest["snapshots"]}
    shared_base = (
        int(manifest["instances"]["secondary"]["initdata"])
        - NATIVE_ROOT_OFFSET
        - SECONDARY_ROOT_DELTA
    )

    def load(ordinal):
        record = snapshots[ordinal]
        directory = root / ("kick_%02d" % ordinal)
        regions = {}
        for name in ("primary", "secondary"):
            path = directory / record["files"][name]["path"]
            regions[name] = {offset: body for offset, body in _pages(path.read_bytes())}
        shared_record = record["files"]["shared"]
        shared_offset = int(shared_record["dva"]) - shared_base
        shared = (directory / shared_record["path"]).read_bytes()
        regions["shared"] = {
            shared_offset + offset: body for offset, body in _pages(shared)
        }
        return regions

    return manifest, load(3), load(4)


def _pages(data):
    for offset in range(0, len(data), PAGE):
        body = data[offset:offset + PAGE]
        if len(body) == PAGE:
            yield offset, body


def _load_source(root, ordinal):
    directory = root / ("source_peer_kick_%02d" % ordinal)
    manifest = json.loads((directory / "manifest.json").read_text())
    regions = {"primary": {}, "secondary": {}, "shared": {}}
    for record in manifest["pages"]:
        regions[record["name"]][int(record["offset"])] = (
            directory / record["file"]
        ).read_bytes()
    return manifest, regions


def _changed_offsets(before, after):
    return [index for index, (left, right) in enumerate(zip(before, after))
            if left != right]


def _relation(before_a, after_a, before_b, after_b):
    if (before_a, after_a) == (before_b, after_b):
        return "exact_transition"
    if after_a == after_b:
        return "same_after"
    if (before_a ^ after_a) == (before_b ^ after_b):
        return "same_xor"
    if ((after_a - before_a) & 0xFFFFFFFFFFFFFFFF) == (
            (after_b - before_b) & 0xFFFFFFFFFFFFFFFF):
        return "same_delta"
    return "different_transition"


def _field_record(region, page_offset, local_offset, native_before,
                  native_after, source_success_before, source_success_after,
                  source_failed_before, source_failed_after):
    aligned = local_offset & ~7
    absolute = page_offset + aligned
    nb = _u64(native_before, aligned)
    na = _u64(native_after, aligned)
    ssb = _u64(source_success_before, aligned)
    ssa = _u64(source_success_after, aligned)
    sfb = _u64(source_failed_before, aligned)
    sfa = _u64(source_failed_after, aligned)
    native_changed = nb != na
    source_success_changed = ssb != ssa
    source_failed_changed = sfb != sfa
    lifecycle_bits = (
        ("N" if native_changed else "-")
        + ("S" if source_success_changed else "-")
        + ("F" if source_failed_changed else "-")
    )
    if native_changed and source_success_changed and not source_failed_changed:
        lifecycle_classification = "success_only"
    elif native_changed and not source_success_changed and not source_failed_changed:
        lifecycle_classification = "native_only"
    elif not native_changed and source_success_changed and not source_failed_changed:
        lifecycle_classification = "source_success_only"
    else:
        lifecycle_classification = lifecycle_bits

    if native_changed and not source_failed_changed:
        classification = "native_only"
    elif source_failed_changed and not native_changed:
        classification = "source_only"
    else:
        classification = _relation(nb, na, sfb, sfa)
    return {
        "region": region,
        "offset": absolute,
        "classification": classification,
        "lifecycle_classification": lifecycle_classification,
        "lifecycle_bits": lifecycle_bits,
        "native_before": nb,
        "native_after": na,
        "native_xor": nb ^ na,
        "native_delta": (na - nb) & 0xFFFFFFFFFFFFFFFF,
        "source_success_before": ssb,
        "source_success_after": ssa,
        "source_success_xor": ssb ^ ssa,
        "source_success_delta": (ssa - ssb) & 0xFFFFFFFFFFFFFFFF,
        "source_success_relation": _relation(nb, na, ssb, ssa),
        "source_failed_before": sfb,
        "source_failed_after": sfa,
        "source_failed_xor": sfb ^ sfa,
        "source_failed_delta": (sfa - sfb) & 0xFFFFFFFFFFFFFFFF,
    }


def _compare(native_before, native_after, source_success_before,
             source_success_after, source_failed_before, source_failed_after):
    pages = []
    fields = []
    for region in ("primary", "secondary", "shared"):
        native_offsets = set(native_before[region]) & set(native_after[region])
        source_success_offsets = (
            set(source_success_before[region]) & set(source_success_after[region]))
        source_failed_offsets = (
            set(source_failed_before[region]) & set(source_failed_after[region]))
        source_offsets = source_success_offsets & source_failed_offsets
        for page_offset in sorted(native_offsets | source_offsets):
            nb = native_before[region].get(page_offset)
            na = native_after[region].get(page_offset)
            ssb = source_success_before[region].get(page_offset)
            ssa = source_success_after[region].get(page_offset)
            sfb = source_failed_before[region].get(page_offset)
            sfa = source_failed_after[region].get(page_offset)
            native_changed = bool(nb is not None and na is not None and nb != na)
            source_success_changed = bool(
                ssb is not None and ssa is not None and ssb != ssa)
            source_failed_changed = bool(
                sfb is not None and sfa is not None and sfb != sfa)
            if not native_changed and not source_success_changed and not source_failed_changed:
                continue
            page = {
                "region": region,
                "offset": page_offset,
                "native_observed": nb is not None and na is not None,
                "source_observed": all(
                    body is not None for body in (ssb, ssa, sfb, sfa)),
                "native_changed_bytes": (
                    len(_changed_offsets(nb, na)) if native_changed else 0),
                "source_success_changed_bytes": (
                    len(_changed_offsets(ssb, ssa))
                    if source_success_changed else 0),
                "source_failed_changed_bytes": (
                    len(_changed_offsets(sfb, sfa))
                    if source_failed_changed else 0),
            }
            pages.append(page)
            if any(body is None for body in (nb, na, ssb, ssa, sfb, sfa)):
                continue
            changed = set(_changed_offsets(nb, na))
            changed.update(_changed_offsets(ssb, ssa))
            changed.update(_changed_offsets(sfb, sfa))
            for aligned in sorted({offset & ~7 for offset in changed}):
                fields.append(_field_record(
                    region, page_offset, aligned, nb, na,
                    ssb, ssa, sfb, sfa))
    return pages, fields


def _format_field(record):
    return (
        "%-9s +%#08x %-20s native %s -> %s  good %s -> %s  bad %s -> %s" % (
            record["region"], record["offset"],
            record["lifecycle_classification"],
            _hex(record["native_before"]), _hex(record["native_after"]),
            _hex(record["source_success_before"]),
            _hex(record["source_success_after"]),
            _hex(record["source_failed_before"]),
            _hex(record["source_failed_after"]),
        )
    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", type=pathlib.Path, default=DEFAULT_NATIVE)
    parser.add_argument("--source", type=pathlib.Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args(argv)

    native_manifest, native_before, native_after = _load_native(args.native)
    source_manifest2, source2 = _load_source(args.source, 2)
    source_manifest3, source3 = _load_source(args.source, 3)
    source_manifest4, source4 = _load_source(args.source, 4)
    pages, fields = _compare(
        native_before, native_after, source2, source3, source3, source4)
    counts = {}
    for record in fields:
        key = record["classification"]
        counts[key] = counts.get(key, 0) + 1
    lifecycle_counts = {}
    for record in fields:
        key = record["lifecycle_classification"]
        lifecycle_counts[key] = lifecycle_counts.get(key, 0) + 1

    report = {
        "format": "m1n1-t8140-g17p-peer-lifecycle-diff-v1",
        "native": str(args.native),
        "source": str(args.source),
        "native_controls": {
            str(record["ordinal"]): record["control"]
            for record in native_manifest["snapshots"]
        },
        "source_controls": {
            "2": source_manifest2["control"],
            "3": source_manifest3["control"],
            "4": source_manifest4["control"],
        },
        "classification_counts": counts,
        "lifecycle_classification_counts": lifecycle_counts,
        "pages": pages,
        "fields": fields,
    }
    output = args.output or args.source / "peer_lifecycle_native_source_diff.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print("field classifications: %s" % json.dumps(counts, sort_keys=True))
    print("lifecycle classifications: %s" % json.dumps(
        lifecycle_counts, sort_keys=True))
    print("changed pages: %d; aligned fields: %d" % (len(pages), len(fields)))
    print("\nTransitions shared by both successful paths but absent on failure:")
    for record in fields:
        if record["lifecycle_classification"] == "success_only":
            print(_format_field(record))
    print("report: %s" % output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
