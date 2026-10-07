#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline analysis of the first G17P TA/3D submission capture.

This operates only on saved shared-memory artifacts. It deliberately does not
open a proxy connection or read firmware code segments.
"""

import argparse
import hashlib
import json
import pathlib
import struct


PAGE_SIZE = 0x4000
CHANNEL_LABELS = (
    "TA_0", "3D_0", "CL_0",
    "TA_1", "3D_1", "CL_1",
    "TA_2", "3D_2", "CL_2",
    "TA_3", "3D_3", "CL_3",
)
DEFAULT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "pre_work_0x83_v2_20260724_193713"
)
DEFAULT_POST = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "post_first_work_memory_20260724_195845"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze saved G17P first-work shared-memory artifacts"
    )
    parser.add_argument("--snapshot", type=pathlib.Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--post", type=pathlib.Path, default=DEFAULT_POST)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def canonicalize(addr, shift):
    addr &= (1 << (shift + 1)) - 1
    if addr & (1 << shift):
        addr |= ((1 << 64) - 1) ^ ((1 << (shift + 1)) - 1)
    return addr


class SnapshotAddressSpace:
    def __init__(self, manifest, ram):
        self.shift = int(manifest["vaddr_shift"])
        self.ram = ram
        selected = int(manifest["selected_root"]["index"])
        self.pages = {}
        for root in manifest["root_mappings"]:
            if int(root["root_index"]) != selected:
                continue
            for mapping in root["mappings"]:
                va = int(mapping["va"]) & ~(PAGE_SIZE - 1)
                previous = self.pages.get(va)
                if previous is not None and previous != mapping:
                    raise ValueError("conflicting mapping for %#x" % va)
                self.pages[va] = mapping

    def mapping(self, addr):
        return self.pages.get(canonicalize(addr, self.shift) & ~(PAGE_SIZE - 1))

    def read(self, addr, size):
        chunks = []
        while size:
            normalized = canonicalize(addr, self.shift)
            mapping = self.mapping(normalized)
            if mapping is None or mapping.get("blob_index") is None:
                raise ValueError("unavailable shared page for DVA %#x" % normalized)
            offset = normalized & (PAGE_SIZE - 1)
            length = min(size, PAGE_SIZE - offset)
            index = int(mapping["blob_index"])
            start = index * PAGE_SIZE + offset
            chunks.append(self.ram[start : start + length])
            addr += length
            size -= length
        return b"".join(chunks)

    def u32(self, addr):
        return struct.unpack("<I", self.read(addr, 4))[0]

    def u64(self, addr):
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def pointer(self, addr):
        mapping = self.mapping(addr)
        if mapping is None:
            return None
        return {
            "dva": int(canonicalize(addr, self.shift)),
            "page_dva": int(canonicalize(addr, self.shift) & ~(PAGE_SIZE - 1)),
            "pa": int(mapping["pa"]),
            "blob_index": mapping.get("blob_index"),
            "fixed_region": mapping.get("fixed_region"),
        }


def load_post_ram(post, report):
    filename = report.get("post_memory_file") or report.get("post_init_ram_file")
    if not filename:
        raise ValueError("post-memory report has no RAM image")
    return (post / filename).read_bytes()


def mapped_pointer_words(space, data):
    pointers = []
    for offset in range(0, len(data) - 7, 8):
        value = struct.unpack_from("<Q", data, offset)[0]
        target = space.pointer(value)
        if target is not None:
            pointers.append({"offset": offset, "target": target})
    return pointers


def u32_words(data):
    return list(struct.unpack("<%dI" % (len(data) // 4), data))


def describe_command_queue(space, post_space, notification):
    queue_addr = struct.unpack_from("<Q", notification, 8)[0]
    queue_mapping = space.pointer(queue_addr)
    if queue_mapping is None:
        return {"dva": queue_addr, "mapping": None}

    queue_prefix = space.read(queue_addr, 0x10)
    pointer_state = struct.unpack_from("<Q", queue_prefix, 0)[0]
    entry_array = struct.unpack_from("<Q", queue_prefix, 8)[0]
    state_data = space.read(pointer_state, 0x60)
    post_state_data = post_space.read(pointer_state, 0x60)
    entries = []
    for index, work_addr in enumerate(struct.unpack("<8Q", space.read(entry_array, 0x40))):
        if work_addr == 0:
            continue
        work_mapping = space.pointer(work_addr)
        entry = {
            "index": index,
            "work_dva": work_addr,
            "work_mapping": work_mapping,
        }
        if work_mapping is not None:
            entry["work_prefix_u32"] = u32_words(space.read(work_addr, 0x20))
        entries.append(entry)
    return {
        "dva": queue_addr,
        "mapping": queue_mapping,
        "pointer_state_dva": pointer_state,
        "pointer_state_u32": u32_words(state_data),
        "post_pointer_state_u32": u32_words(post_state_data),
        "entry_array_dva": entry_array,
        "work_items": entries,
    }


def changed_page_summary(manifest, diff):
    changed_pas = {int(page["pa"]) for page in diff["changed_pages"]}
    result = []
    for root in manifest["root_mappings"]:
        changed = [
            mapping
            for mapping in root["mappings"]
            if int(mapping["pa"]) in changed_pas
        ]
        if not changed:
            continue
        result.append(
            {
                "root_index": int(root["root_index"]),
                "ctx_id": int(root["root_ctx_id"]),
                "selector": int(root["selector"]),
                "changed_mapped_pages": len(changed),
            }
        )
    return result


def main():
    args = parse_args()
    snapshot = args.snapshot.resolve()
    post = args.post.resolve()
    manifest = json.loads((snapshot / "manifest.json").read_text())
    pre_ram = (snapshot / manifest["ram_file"]).read_bytes()
    report = json.loads((post / "diff_report.json").read_text())
    post_ram = load_post_ram(post, report)
    if len(pre_ram) != len(post_ram):
        raise ValueError("pre/post RAM images have different sizes")

    pre = SnapshotAddressSpace(manifest, pre_ram)
    after = SnapshotAddressSpace(manifest, post_ram)
    init_addr = canonicalize(
        int(manifest["init_message"]) & ((1 << 44) - 1), pre.shift
    )
    region_b = pre.u64(init_addr + 0x18)
    channels = []
    for index, label in enumerate(CHANNEL_LABELS):
        record = region_b + 0x20 + index * 0x20
        states = [pre.u64(record + offset) for offset in (0, 8, 0x10)]
        ring = pre.u64(record + 0x18)
        before = [pre.u32(pointer) for pointer in states]
        after_values = [after.u32(pointer) for pointer in states]
        ring_data = pre.read(ring, 0x40)
        entry = {
            "index": index,
            "label": label,
            "state_dvas": states,
            "pre_counters": before,
            "post_counters": after_values,
            "ring_dva": ring,
            "ring_mapping": pre.pointer(ring),
            "ring_prefix_sha256": hashlib.sha256(ring_data).hexdigest(),
            "ring_prefix_u32": u32_words(ring_data),
            "ring_prefix_mapped_pointers": mapped_pointer_words(pre, ring_data),
            "command_queue": describe_command_queue(pre, after, ring_data),
        }
        if before != after_values or before[2] != before[0] or before[2] != before[1]:
            channels.append(entry)

    result = {
        "format": "m1n1-agx-g17p-first-work-analysis-v1",
        "snapshot": str(snapshot),
        "post_memory": str(post),
        "init_dva": init_addr,
        "region_b_dva": region_b,
        "active_or_changed_channels": channels,
        "changed_page_summary": changed_page_summary(manifest, report),
        "changed_page_count": int(report["changed_page_count"]),
    }
    output = args.output or (post / "first_work_analysis.json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("First-work analysis: %s" % output)
    for channel in channels:
        print(
            "%s %r -> %r ring=%#x"
            % (
                channel["label"],
                channel["pre_counters"],
                channel["post_counters"],
                channel["ring_dva"],
            )
        )


if __name__ == "__main__":
    main()
