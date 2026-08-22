#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare two clean-room G17P snapshots at adjacent lifecycle boundaries."""

import argparse
import datetime
import hashlib
import json
import pathlib
import struct


PAGE = 0x4000
PTE_ATTRIBUTE_MASK = (
    (1 << 0) | (1 << 1) | (0x7 << 2) | (0x3 << 6) |
    (0x3 << 8) | (1 << 10) | (1 << 11) |
    (1 << 53) | (1 << 54) | (1 << 55)
)


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare complete G17P snapshot state by logical mapping"
    )
    parser.add_argument("before", type=pathlib.Path)
    parser.add_argument("after", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def difference_runs(before, after):
    runs = []
    start = None
    for offset, (old, new) in enumerate(zip(before, after)):
        if old != new and start is None:
            start = offset
        elif old == new and start is not None:
            runs.append([start, offset - start])
            start = None
    if start is not None:
        runs.append([start, len(before) - start])
    return runs


def word_differences(before, after, limit=256):
    rows = []
    for offset in range(0, min(len(before), len(after)), 8):
        old = struct.unpack_from("<Q", before, offset)[0]
        new = struct.unpack_from("<Q", after, offset)[0]
        if old != new:
            rows.append({"offset": offset, "before": old, "after": new})
            if len(rows) == limit:
                break
    return rows


class Snapshot:
    def __init__(self, path):
        self.path = pathlib.Path(path).resolve()
        self.manifest = json.loads((self.path / "manifest.json").read_text())
        self.ram = (self.path / self.manifest.get("ram_file", "ram.bin")).read_bytes()
        self.pages = {}
        self.aliases = {}
        for root in self.manifest["root_mappings"]:
            root_key = (
                integer(root["root_index"]),
                integer(root["root_ctx_id"]),
                integer(root["selector"]),
            )
            for mapping in root["mappings"]:
                identity = root_key + (integer(mapping["va"]),)
                if identity in self.pages:
                    raise RuntimeError("duplicate mapping identity %r" % (identity,))
                entry = dict(mapping)
                entry["pa"] = integer(entry["pa"])
                entry["pte"] = integer(entry["pte"])
                if entry.get("blob_index") is not None:
                    entry["blob_index"] = integer(entry["blob_index"])
                    self.aliases.setdefault(entry["pa"], []).append(identity)
                self.pages[identity] = entry

    def body(self, mapping):
        blob = mapping.get("blob_index")
        if blob is None:
            return None
        offset = integer(blob) * PAGE
        body = self.ram[offset:offset + PAGE]
        if len(body) != PAGE:
            raise RuntimeError("short blob %d in %s" % (integer(blob), self.path))
        return body

    def fixed_regions(self):
        regions = {}
        for region in self.manifest.get("fixed_regions", []):
            body = (self.path / region["file"]).read_bytes()
            regions[region["name"]] = {
                "metadata": region,
                "body": body,
            }
        return regions


def format_identity(identity):
    root_index, context, selector, address = identity
    return "%d:%d:%d@%#x" % (root_index, context, selector, address)


def alias_partition(snapshot):
    groups = set()
    for identities in snapshot.aliases.values():
        if len(identities) > 1:
            groups.add(tuple(sorted(identities)))
    return groups


def content_delta(identity, before_mapping, after_mapping, before_body, after_body):
    runs = difference_runs(before_body, after_body)
    return {
        "root_index": identity[0],
        "root_context": identity[1],
        "root_selector": identity[2],
        "address": identity[3],
        "before_pa": before_mapping["pa"],
        "after_pa": after_mapping["pa"],
        "before_sha256": hashlib.sha256(before_body).hexdigest(),
        "after_sha256": hashlib.sha256(after_body).hexdigest(),
        "changed_bytes": sum(a != b for a, b in zip(before_body, after_body)),
        "before_nonzero_after_zero": sum(
            a != 0 and b == 0 for a, b in zip(before_body, after_body)
        ),
        "before_zero_after_nonzero": sum(
            a == 0 and b != 0 for a, b in zip(before_body, after_body)
        ),
        "different_nonzero": sum(
            a != 0 and b != 0 and a != b for a, b in zip(before_body, after_body)
        ),
        "runs": runs,
        "qword_differences": word_differences(before_body, after_body),
    }


def compare(before, after):
    before_keys = set(before.pages)
    after_keys = set(after.pages)
    common = sorted(before_keys & after_keys)
    added = sorted(after_keys - before_keys)
    removed = sorted(before_keys - after_keys)
    attribute_changes = []
    backing_kind_changes = []
    content_changes = []

    for identity in common:
        old_mapping = before.pages[identity]
        new_mapping = after.pages[identity]
        old_attributes = old_mapping["pte"] & PTE_ATTRIBUTE_MASK
        new_attributes = new_mapping["pte"] & PTE_ATTRIBUTE_MASK
        if old_attributes != new_attributes:
            attribute_changes.append({
                "identity": format_identity(identity),
                "before": old_attributes,
                "after": new_attributes,
            })
        old_body = before.body(old_mapping)
        new_body = after.body(new_mapping)
        if (old_body is None) != (new_body is None):
            backing_kind_changes.append({
                "identity": format_identity(identity),
                "before_has_ram": old_body is not None,
                "after_has_ram": new_body is not None,
                "before_fixed_region": old_mapping.get("fixed_region"),
                "after_fixed_region": new_mapping.get("fixed_region"),
            })
        elif old_body is not None and old_body != new_body:
            content_changes.append(content_delta(
                identity, old_mapping, new_mapping, old_body, new_body
            ))

    before_aliases = alias_partition(before)
    after_aliases = alias_partition(after)
    alias_groups_removed = [
        [format_identity(identity) for identity in group]
        for group in sorted(before_aliases - after_aliases)
    ]
    alias_groups_added = [
        [format_identity(identity) for identity in group]
        for group in sorted(after_aliases - before_aliases)
    ]

    fixed_changes = []
    old_fixed = before.fixed_regions()
    new_fixed = after.fixed_regions()
    for name in sorted(set(old_fixed) | set(new_fixed)):
        old = old_fixed.get(name)
        new = new_fixed.get(name)
        if old is None or new is None:
            fixed_changes.append({
                "name": name,
                "before_present": old is not None,
                "after_present": new is not None,
            })
            continue
        if old["body"] == new["body"]:
            continue
        fixed_changes.append({
            "name": name,
            "before_pa": integer(old["metadata"]["pa"]),
            "after_pa": integer(new["metadata"]["pa"]),
            "size": len(old["body"]),
            "changed_bytes": sum(
                a != b for a, b in zip(old["body"], new["body"])
            ) + abs(len(old["body"]) - len(new["body"])),
            "runs": difference_runs(old["body"], new["body"]),
            "qword_differences": word_differences(old["body"], new["body"]),
        })

    return {
        "format": "m1n1-g17p-lifecycle-snapshot-diff-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "before": str(before.path),
        "after": str(after.path),
        "before_boundary": {
            "label": before.manifest.get("capture_label"),
            "trigger_endpoint": before.manifest.get("trigger_endpoint"),
            "trigger_type": before.manifest.get("trigger_type"),
            "trigger_message": before.manifest.get("trigger_message"),
        },
        "after_boundary": {
            "label": after.manifest.get("capture_label"),
            "trigger_endpoint": after.manifest.get("trigger_endpoint"),
            "trigger_type": after.manifest.get("trigger_type"),
            "trigger_message": after.manifest.get("trigger_message"),
        },
        "summary": {
            "before_mapping_count": len(before_keys),
            "after_mapping_count": len(after_keys),
            "common_mapping_count": len(common),
            "added_mappings": len(added),
            "removed_mappings": len(removed),
            "attribute_changes": len(attribute_changes),
            "backing_kind_changes": len(backing_kind_changes),
            "content_changed_mappings": len(content_changes),
            "content_changed_physical_pages_before": len({
                item["before_pa"] for item in content_changes
            }),
            "content_changed_physical_pages_after": len({
                item["after_pa"] for item in content_changes
            }),
            "alias_groups_removed": len(alias_groups_removed),
            "alias_groups_added": len(alias_groups_added),
            "fixed_regions_changed": len(fixed_changes),
        },
        "added_mappings": [format_identity(identity) for identity in added],
        "removed_mappings": [format_identity(identity) for identity in removed],
        "attribute_changes": attribute_changes,
        "backing_kind_changes": backing_kind_changes,
        "alias_groups_removed": alias_groups_removed,
        "alias_groups_added": alias_groups_added,
        "content_changes": content_changes,
        "fixed_region_changes": fixed_changes,
    }


def main():
    args = parse_args()
    before = Snapshot(args.before)
    after = Snapshot(args.after)
    report = compare(before, after)
    output = args.output
    if output is None:
        output = after.path / "lifecycle_from_pre_0x84.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    summary = report["summary"]
    print("G17P lifecycle comparison: %s" % output)
    for key, value in summary.items():
        print("  %-40s %d" % (key, value))
    print("  changed mapped pages:")
    for item in report["content_changes"]:
        print(
            "    %d:%d:%d %#018x changed=%-5d runs=%-3d %s -> %s" % (
                item["root_index"], item["root_context"],
                item["root_selector"], item["address"],
                item["changed_bytes"], len(item["runs"]),
                item["before_sha256"][:12], item["after_sha256"][:12],
            )
        )
    print("  fixed regions:")
    for item in report["fixed_region_changes"]:
        print("    %-24s changed=%s" % (item["name"], item.get("changed_bytes")))


if __name__ == "__main__":
    main()
