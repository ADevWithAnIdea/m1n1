# SPDX-License-Identifier: MIT
"""Which descriptor fields a live host varies between successive submissions.

Everything that differs between one submission's descriptor and the next is per-submission state.
A generated second submission that leaves any of it at the first submission's value is wrong in a
way the first submission could never reveal.
"""
import json
import pathlib
import struct
import sys

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                 "/Users/user/asahi_re/artifacts/agx_g17p/"
                 "live_submission_targeted_20260728_003032")

LAYOUT = {0x00: ("tiling", 0x60), 0x01: ("fragment", 0xa0)}


def load(channel):
    index = json.load(open(D / channel / "pages.json"))
    blob = (D / channel / "pages.bin").read_bytes()
    size = int(index["page_size"])
    pages = {int(p["dva"]): int(p["capture_offset"]) for p in index["pages"]}
    return pages, blob, size


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
    descriptors = []
    for queue in target["queues"]:
        for triple in queue["inner_entries"]:
            head = read(pages, blob, size, triple[0], 4)
            if head is None:
                continue
            selector = struct.unpack("<I", head)[0]
            if selector not in LAYOUT:
                continue
            kind, registers_at = LAYOUT[selector]
            body = read(pages, blob, size, triple[0], registers_at)
            if body is None:
                continue
            descriptors.append((kind, triple[0], body))

    print("== %s: %d descriptors, comparing the header and pointer region (%#x bytes)"
          % (channel, len(descriptors), len(descriptors[0][2]) if descriptors else 0))
    for i in range(1, len(descriptors)):
        prev, cur = descriptors[i - 1][2], descriptors[i][2]
        diffs = [off for off in range(0, len(cur), 4)
                 if prev[off:off + 4] != cur[off:off + 4]]
        print("   submission %d -> %d differs at %d words: %s"
              % (i - 1, i, len(diffs), ["+%#04x" % o for o in diffs]))
        for off in diffs:
            print("        +%#04x  %08x -> %08x"
                  % (off, struct.unpack_from("<I", prev, off)[0],
                     struct.unpack_from("<I", cur, off)[0]))
    print()
