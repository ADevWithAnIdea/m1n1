# SPDX-License-Identifier: MIT
"""Which register values a live host varies between successive submissions.

The header diff covered only the header and pointer region. The register program is the rest of the
descriptor, and it is what names the render-context objects a submission works on. A second
submission that reuses the first's register values is pointing at objects the first already
consumed.
"""
import json
import pathlib
import struct
import sys

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                 "/Users/user/asahi_re/artifacts/agx_g17p/"
                 "live_submission_targeted_20260728_003032")

LAYOUT = {0x00: ("tiling", 0x60, 73), 0x01: ("fragment", 0xa0, 89)}
STRIDE = 0xc


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
    programs = []
    for queue in target["queues"]:
        for triple in queue["inner_entries"]:
            head = read(pages, blob, size, triple[0], 4)
            if head is None:
                continue
            selector = struct.unpack("<I", head)[0]
            if selector not in LAYOUT:
                continue
            kind, at, count = LAYOUT[selector]
            body = read(pages, blob, size, triple[0] + at, count * STRIDE)
            if body is None:
                continue
            program = {}
            for i in range(count):
                number = struct.unpack_from("<I", body, i * STRIDE)[0]
                value = struct.unpack_from("<Q", body, i * STRIDE + 4)[0]
                program[number] = value
            programs.append(program)

    print("== %s  %d register programs of %d entries"
          % (channel, len(programs), len(programs[0]) if programs else 0))
    for i in range(1, len(programs)):
        prev, cur = programs[i - 1], programs[i]
        changed = {n: (prev.get(n), v) for n, v in cur.items() if prev.get(n) != v}
        print("   submission %d -> %d: %d of %d registers change"
              % (i - 1, i, len(changed), len(cur)))
        for number, (was, now) in sorted(changed.items()):
            delta = now - was if was is not None else None
            print("      reg %#07x  %#018x -> %#018x   delta %s"
                  % (number, was or 0, now,
                     ("%+#x" % delta) if delta is not None else "n/a"))
    print()
