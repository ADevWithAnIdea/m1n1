#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the T8140/G17P initdata object tree from captured hardware state.

Usage:
    .venv/bin/python3 proxyclient/experiments/agx_g17p_decode_initdata.py \
        [SNAPSHOT_DIR] [GRAPH_DIR]

This works bottom-up from bytes. It resolves every object the captured initdata
root reaches, classifies each one from its own contents, and reports the pointer
field offsets that link them. It does not assume any older generation's struct
layout; where a decoding is asserted, the evidence is printed alongside it.

Inputs are two offline artifacts: a snapshot directory holding ``ram.bin`` plus
``manifest.json`` with the address mappings, and a pointer-graph directory whose
``graph.json`` records which offsets in which object held resolvable addresses.
Neither hardware nor a live target is required.
"""

import collections
import json
import os
import struct
import sys

ARTIFACTS = "/Users/user/asahi_re/artifacts/agx_g17p"
DEFAULT_SNAPSHOT = os.path.join(ARTIFACTS, "pre_work_0x83_v2_20260724_193713")
DEFAULT_GRAPH = os.path.join(ARTIFACTS, "initdata_pointer_graph_20260724_212611")
PAGE = 0x4000


def as_int(value):
    return int(value, 16) if isinstance(value, str) else value


class Snapshot:
    def __init__(self, path):
        with open(os.path.join(path, "manifest.json")) as handle:
            self.manifest = json.load(handle)
        self.ram = open(os.path.join(path, "ram.bin"), "rb")
        self.by_va = {}
        for entry in self.manifest["mappings"]:
            self.by_va[as_int(entry["va"])] = entry

    def read(self, dva, size):
        page = dva & ~(PAGE - 1)
        entry = self.by_va.get(page)
        # A mapped page with no blob index is backed by device registers rather
        # than by memory, so there is nothing to read out of the snapshot.
        if entry is None or entry.get("blob_index") is None:
            return None
        offset = entry["blob_index"] * PAGE + (dva & (PAGE - 1))
        self.ram.seek(offset)
        return self.ram.read(min(size, PAGE - (dva & (PAGE - 1))))

    def is_register_page(self, dva):
        entry = self.by_va.get(dva & ~(PAGE - 1))
        return bool(entry) and entry.get("blob_index") is None

    def page_pa(self, dva):
        entry = self.by_va.get(dva & ~(PAGE - 1))
        return as_int(entry["pa"]) if entry else None


def is_dva(value):
    return (value >> 40) == 0xfffffc and (value & 0xfff) != 0xfff


def classify(data, pointer_offsets):
    """Describe an object from its own bytes."""
    nonzero = sum(1 for b in data if b)
    if not nonzero:
        return "all zero", {}
    words = len(data) // 8
    dvas = sum(1 for i in range(words)
               if is_dva(struct.unpack_from("<Q", data, i * 8)[0]))
    extent = len(data)
    while extent and data[extent - 1] == 0:
        extent -= 1
    detail = {
        "nonzero_bytes": nonzero,
        "nonzero_extent": extent,
        "dva_words": dvas,
    }
    # Look for a regular stride among the pointer field offsets, which indicates
    # an array of like-sized records rather than a struct.
    if len(pointer_offsets) >= 3:
        deltas = collections.Counter(
            b - a for a, b in zip(sorted(pointer_offsets), sorted(pointer_offsets)[1:]))
        stride, count = deltas.most_common(1)[0]
        if count >= len(pointer_offsets) // 2 and stride:
            detail["pointer_stride"] = stride
            detail["stride_hits"] = count
    if dvas * 8 > nonzero // 2:
        return "pointer dense", detail
    if nonzero < len(data) // 32:
        return "sparse scalars", detail
    return "packed data", detail


def main():
    snap_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SNAPSHOT
    graph_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_GRAPH

    snap = Snapshot(snap_path)
    with open(os.path.join(graph_path, "graph.json")) as handle:
        graph = json.load(handle)

    root = as_int(graph["init_page_dva"])
    outgoing = collections.defaultdict(list)
    incoming = collections.defaultdict(list)
    for edge in graph["edges"]:
        src, off = as_int(edge["source_dva"]), as_int(edge["source_offset"])
        val, tgt = as_int(edge["value"]), as_int(edge["target_dva"])
        outgoing[src].append((off, val, tgt))
        incoming[tgt].append((src, off))

    nodes = {as_int(n["dva"]): n for n in graph["nodes"]}
    print("snapshot: %s" % snap_path)
    print("graph   : %s" % graph_path)
    print("root    : %#x   %d objects, %d pointer edges\n"
          % (root, len(nodes), len(graph["edges"])))

    report = {"root": root, "objects": []}
    order, seen = [], set()
    queue = collections.deque([(root, 0)])
    while queue:
        dva, depth = queue.popleft()
        if dva in seen:
            continue
        seen.add(dva)
        order.append((dva, depth))
        for _, _, tgt in sorted(outgoing.get(dva, [])):
            if tgt not in seen:
                queue.append((tgt, depth + 1))

    for dva, depth in order:
        data = snap.read(dva, PAGE)
        edges = sorted(outgoing.get(dva, []))
        offsets = [off for off, _, _ in edges]
        if snap.is_register_page(dva):
            kind, detail = "mapped device registers", {
                "register_pa": hex(snap.page_pa(dva) or 0)}
        elif data is None:
            kind, detail = "not in snapshot", {}
        else:
            kind, detail = classify(data, offsets)
        refs = incoming.get(dva, [])
        print("%s%#018x  pa %s  depth %d" % ("  " * min(depth, 6), dva,
              hex(snap.page_pa(dva)) if snap.page_pa(dva) else "?", depth))
        print("%s    %s%s" % ("  " * min(depth, 6), kind,
              "" if not detail else "  " + ", ".join(
                  "%s=%s" % (k, hex(v) if k.endswith(("stride", "extent")) else v)
                  for k, v in detail.items())))
        if refs:
            print("%s    referenced by: %s" % ("  " * min(depth, 6),
                  ", ".join("%#x+%#x" % (s, o) for s, o in refs[:4])))
        if edges:
            shown = ", ".join("+%#x->%#x" % (o, v) for o, v, _ in edges[:8])
            print("%s    %d pointers: %s%s" % ("  " * min(depth, 6), len(edges),
                  shown, " ..." if len(edges) > 8 else ""))
        print()
        report["objects"].append({
            "dva": dva, "depth": depth, "kind": kind, "detail": detail,
            "pointer_offsets": offsets,
            "referenced_by": [{"dva": s, "offset": o} for s, o in refs],
        })

    kinds = collections.Counter(o["kind"] for o in report["objects"])
    print("object classes: %s" % dict(kinds))
    unreached = set(nodes) - seen
    if unreached:
        print("graph nodes not reachable from the root: %d" % len(unreached))
    out = os.path.join(graph_path, "decoded_tree.json")
    with open(out, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
