# SPDX-License-Identifier: MIT
"""How a live host's item ring is actually divided into submission groups.

The publisher here always writes three entries a group. If a host's groups are not all three
entries, a second submission would be laid out wrongly in a way the first could not reveal.
"""
import json
import pathlib
import struct
import sys

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                 "/Users/user/asahi_re/artifacts/agx_g17p/"
                 "live_submission_targeted_20260728_003032")

NAMES = {0x00: "tiling", 0x01: "fragment", 0x0e: "EVENT", 0x0f: "optional"}


def load(channel):
    index = json.load(open(D / channel / "pages.json"))
    blob = (D / channel / "pages.bin").read_bytes()
    size = int(index["page_size"])
    return {int(p["dva"]): int(p["capture_offset"]) for p in index["pages"]}, blob, size


def read(pages, blob, size, dva, length):
    page = dva & ~(size - 1)
    if page not in pages:
        return None
    start = pages[page] + (dva - page)
    out = blob[start:start + length]
    return out if len(out) == length else None


for channel in ("TA_0", "3D_0"):
    target = json.load(open(D / channel / "target.json"))
    pages, blob, size = load(channel)
    for queue in target["queues"]:
        flat = [dva for triple in queue["inner_entries"] for dva in triple]
        print("== %s  queue %#x  write index %s  flat items %d"
              % (channel, queue["queue_dva"], queue["state_u32"].get("0x40"), len(flat)))
        kinds = []
        for position, dva in enumerate(flat):
            head = read(pages, blob, size, dva, 4)
            if head is None:
                kinds.append((position, dva, None, "unreadable"))
                continue
            selector = struct.unpack("<I", head)[0]
            kinds.append((position, dva, selector,
                          NAMES.get(selector, "sel %#x" % selector)))
        line = " ".join(entry[3][:4] for entry in kinds)
        print("   sequence: %s" % line)
        sizes, current = [], 0
        for _, _, selector, _ in kinds:
            current += 1
            if selector == 0x0e:
                sizes.append(current)
                current = 0
        if current:
            sizes.append("%d(open)" % current)
        print("   group sizes: %s" % sizes)
    print()
