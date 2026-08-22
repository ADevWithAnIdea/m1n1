#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a pointer graph from captured T8140/G17P shared runtime data.

This is deliberately an offline tool. It scans only captured RAM pages and
does not read fixed firmware text regions or connect to a target.
"""

import argparse
import collections
import datetime
import hashlib
import json
import pathlib
import struct


PAGE_SIZE = 0x4000
DEFAULT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "pre_work_0x83_v2_20260724_193713"
)
DEFAULT_OUTPUT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build a pointer graph from captured G17P initdata RAM"
    )
    parser.add_argument("--snapshot", type=pathlib.Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--output-root", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--max-pages",
        type=int,
        default=1024,
        help="maximum captured RAM pages to visit",
    )
    return parser.parse_args()


def canonicalize(addr, shift):
    addr &= (1 << (shift + 1)) - 1
    if addr & (1 << shift):
        addr |= ((1 << 64) - 1) ^ ((1 << (shift + 1)) - 1)
    return addr


def load_snapshot(snapshot):
    snapshot = snapshot.resolve()
    manifest_bytes = (snapshot / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("format") != "m1n1-agx-g17p-initdata-v2":
        raise RuntimeError("snapshot is not the all-roots v2 format")

    ram = (snapshot / manifest["ram_file"]).read_bytes()
    if hashlib.sha256(ram).hexdigest() != manifest["ram_sha256"]:
        raise RuntimeError("RAM blob checksum mismatch")
    return snapshot, manifest, ram


def selected_mappings(manifest):
    selected_index = int(manifest["selected_root"]["index"])
    mappings = {}
    for mapping_set in manifest["root_mappings"]:
        if int(mapping_set["root_index"]) != selected_index:
            continue
        for mapping in mapping_set["mappings"]:
            va = int(mapping["va"]) & ~(PAGE_SIZE - 1)
            previous = mappings.get(va)
            if previous is not None and previous != mapping:
                raise RuntimeError("conflicting selected-root mapping at %#x" % va)
            mappings[va] = mapping
    return mappings


def node_for(mapping):
    return {
        "dva": int(mapping["va"]) & ~(PAGE_SIZE - 1),
        "pa": int(mapping["pa"]) & ~(PAGE_SIZE - 1),
        "blob_index": mapping.get("blob_index"),
        "fixed_region": mapping.get("fixed_region"),
    }


def main():
    args = parse_args()
    if args.max_pages <= 0:
        raise ValueError("--max-pages must be positive")

    snapshot, manifest, ram = load_snapshot(args.snapshot)
    mappings = selected_mappings(manifest)
    blob_pages = {int(page["index"]): page for page in manifest["blob_pages"]}
    shift = int(manifest["vaddr_shift"])
    init_addr = int(manifest["init_addr"])
    init_page = init_addr & ~(PAGE_SIZE - 1)
    if init_page not in mappings:
        raise RuntimeError("initdata is absent from the selected root")

    nodes = {}
    edges = []
    queue = collections.deque([(init_page, 0)])
    queued = {init_page}
    truncated = False

    while queue:
        page_dva, depth = queue.popleft()
        if len(nodes) >= args.max_pages:
            truncated = True
            break

        mapping = mappings[page_dva]
        node = node_for(mapping)
        node["depth"] = depth
        nodes[page_dva] = node

        blob_index = node["blob_index"]
        if blob_index is None:
            continue
        if blob_index not in blob_pages:
            raise RuntimeError("mapped RAM page has unknown blob index %r" % blob_index)

        data = ram[blob_index * PAGE_SIZE : (blob_index + 1) * PAGE_SIZE]
        for offset in range(0, PAGE_SIZE, 8):
            value = struct.unpack_from("<Q", data, offset)[0]
            candidate = canonicalize(value & ((1 << 44) - 1), shift)
            target_page = candidate & ~(PAGE_SIZE - 1)
            target_mapping = mappings.get(target_page)
            if target_mapping is None:
                continue

            target = node_for(target_mapping)
            edges.append(
                {
                    "source_dva": page_dva,
                    "source_offset": offset,
                    "value": value,
                    "target_dva": target_page,
                    "target_blob_index": target["blob_index"],
                    "target_fixed_region": target["fixed_region"],
                }
            )
            if (
                target["blob_index"] is not None
                and target_page not in queued
            ):
                queue.append((target_page, depth + 1))
                queued.add(target_page)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output = (
        args.output_root
        / ("initdata_pointer_graph_%s" % stamp)
    ).resolve()
    output.mkdir(parents=True, exist_ok=False)
    graph = {
        "format": "m1n1-agx-g17p-initdata-pointer-graph-v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snapshot": str(snapshot),
        "snapshot_manifest_sha256": hashlib.sha256(
            (snapshot / "manifest.json").read_bytes()
        ).hexdigest(),
        "init_addr": init_addr,
        "init_page_dva": init_page,
        "selected_root": manifest["selected_root"],
        "selected_mapping_count": len(mappings),
        "visited_ram_page_count": len(nodes),
        "edge_count": len(edges),
        "max_pages": args.max_pages,
        "truncated": truncated,
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": edges,
    }
    graph_path = output / "graph.json"
    graph_path.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n")
    print("Initdata pointer graph: %s" % graph_path)
    print(
        "Visited %d RAM pages with %d mapped-pointer edges%s"
        % (
            len(nodes),
            len(edges),
            " (truncated)" if truncated else "",
        )
    )


if __name__ == "__main__":
    main()
