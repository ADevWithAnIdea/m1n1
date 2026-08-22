#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import datetime
import hashlib
import json
import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.setup import iface, u


PAGE_SIZE = 0x4000
SAFE_FIXED_REGIONS = {
    "gpu-region",
    "gfx-shared-region",
    "gfx-shared-l2-region",
    "gfx-handoff",
    "gfx-data",
    "gfx1-data",
}
DEFAULT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "initdata_pre_submit_all_uat_roots_v2_20260724_150935"
)
DEFAULT_OUTPUT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")


def changed_ranges(before, after):
    ranges = []
    start = None
    for offset, (old, new) in enumerate(zip(before, after)):
        if old != new and start is None:
            start = offset
        elif old == new and start is not None:
            ranges.append([start, offset])
            start = None
    if start is not None:
        ranges.append([start, len(before)])
    return ranges


def main():
    parser = argparse.ArgumentParser(
        description="Dump captured G17P shared-memory pages and replay relocations"
    )
    parser.add_argument("--snapshot", type=pathlib.Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--output-root", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--label",
        default="live_memory",
        help="descriptive prefix for the output directory",
    )
    parser.add_argument(
        "--attempt",
        type=pathlib.Path,
        help="replay attempt.json whose relocated pages should also be captured",
    )
    parser.add_argument(
        "--only-relocated-pages",
        action="store_true",
        help="capture only pages listed by --attempt, not the whole snapshot",
    )
    args = parser.parse_args()
    if args.only_relocated_pages and args.attempt is None:
        parser.error("--only-relocated-pages requires --attempt")

    snapshot = args.snapshot.resolve()
    manifest = json.loads((snapshot / "manifest.json").read_text())
    before_ram = (snapshot / manifest["ram_file"]).read_bytes()
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = (args.output_root / ("%s_%s" % (args.label, stamp))).resolve()
    out.mkdir(parents=True, exist_ok=False)

    post_ram = bytearray(len(before_ram))
    changed_pages = []
    if not args.only_relocated_pages:
        for page in manifest["blob_pages"]:
            index = int(page["index"])
            pa = int(page["original_pa"])
            before = before_ram[index * PAGE_SIZE : (index + 1) * PAGE_SIZE]
            after = bytes(iface.readmem(pa, PAGE_SIZE))
            post_ram[index * PAGE_SIZE : (index + 1) * PAGE_SIZE] = after
            ranges = changed_ranges(before, after)
            if ranges:
                changed_pages.append(
                    {
                        "index": index,
                        "pa": pa,
                        "changed_bytes": sum(end - start for start, end in ranges),
                        "changed_ranges": ranges,
                        "before_sha256": hashlib.sha256(before).hexdigest(),
                        "after_sha256": hashlib.sha256(after).hexdigest(),
                    }
                )

        post_ram_path = out / "post_memory.bin"
        post_ram_path.write_bytes(post_ram)
    else:
        post_ram_path = None

    original_pages = {
        int(page["original_pa"]): page for page in manifest["blob_pages"]
    }
    relocated_pages = []
    if args.attempt is not None:
        attempt_path = args.attempt.resolve()
        attempt = json.loads(attempt_path.read_text())
        for relocation in attempt.get("initdata_relocations", []):
            original_pa = int(relocation["original_pa"])
            page = original_pages.get(original_pa)
            if page is None:
                raise ValueError(
                    "relocation source %#x is absent from snapshot" % original_pa
                )
            before = before_ram[
                int(page["index"]) * PAGE_SIZE : (int(page["index"]) + 1) * PAGE_SIZE
            ]
            after = bytes(iface.readmem(int(relocation["relocated_pa"]), PAGE_SIZE))
            label = str(relocation["label"])
            filename = "post_relocated_%s.bin" % label.replace("/", "_")
            (out / filename).write_bytes(after)
            ranges = changed_ranges(before, after)
            relocated_pages.append(
                {
                    "label": label,
                    "dva": int(relocation["dva"]),
                    "original_pa": original_pa,
                    "relocated_pa": int(relocation["relocated_pa"]),
                    "file": filename,
                    "changed_bytes": sum(end - start for start, end in ranges),
                    "changed_ranges": ranges,
                    "before_sha256": hashlib.sha256(before).hexdigest(),
                    "after_sha256": hashlib.sha256(after).hexdigest(),
                }
            )

    changed_fixed = []
    if not args.only_relocated_pages:
        for region in manifest["fixed_regions"]:
            if region["name"] not in SAFE_FIXED_REGIONS:
                continue
            pa = int(region["pa"])
            size = int(region["size"])
            before = (snapshot / region["file"]).read_bytes()
            after = bytes(iface.readmem(pa, size))
            name = "post_" + region["file"]
            (out / name).write_bytes(after)
            ranges = changed_ranges(before, after)
            if ranges:
                changed_fixed.append(
                    {
                        "name": region["name"],
                        "pa": pa,
                        "size": size,
                        "file": name,
                        "changed_bytes": sum(end - start for start, end in ranges),
                        "changed_ranges": ranges,
                        "before_sha256": hashlib.sha256(before).hexdigest(),
                        "after_sha256": hashlib.sha256(after).hexdigest(),
                    }
                )

    report = {
        "format": "m1n1-agx-g17p-live-memory-diff-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_snapshot": str(snapshot),
        "post_memory_file": None if post_ram_path is None else post_ram_path.name,
        "post_memory_sha256": (
            None if post_ram_path is None else hashlib.sha256(post_ram).hexdigest()
        ),
        "page_count": 0 if args.only_relocated_pages else len(manifest["blob_pages"]),
        "changed_page_count": len(changed_pages),
        "changed_pages": changed_pages,
        "changed_fixed_region_count": len(changed_fixed),
        "changed_fixed_regions": changed_fixed,
        "relocated_pages": relocated_pages,
    }
    (out / "diff_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print("Live memory dump: %s" % out)
    print(
        "Changed RAM pages: %d/%d; changed fixed regions: %d; relocated pages: %d"
        % (
            len(changed_pages),
            report["page_count"],
            len(changed_fixed),
            len(relocated_pages),
        )
    )
    if post_ram_path is not None:
        print("Post-memory RAM SHA-256: %s" % report["post_memory_sha256"])


if __name__ == "__main__":
    main()
