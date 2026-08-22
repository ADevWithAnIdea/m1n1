# SPDX-License-Identifier: MIT
import json
import pathlib
import struct
import sys

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                 "/Users/user/asahi_re/artifacts/agx_g17p/"
                 "live_submission_targeted_20260728_003032")


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
    print("== %s" % channel)
    for queue in target["queues"]:
        for position, triple in enumerate(queue["inner_entries"]):
            for slot, dva in enumerate(triple):
                body = read(pages, blob, size, dva, 0x40)
                if body is None:
                    continue
                selector = struct.unpack_from("<I", body, 0)[0]
                if selector != 0x0e:
                    continue
                subtype = struct.unpack_from("<I", body, 4)[0]
                counter = struct.unpack_from("<I", body, 8)[0]
                unk10 = struct.unpack_from("<I", body, 0x10)[0]
                tail = body[0x14:0x40]
                print("   entry %2d slot %d  %#014x  subtype %08x  counter %08x (group %d)  "
                      "+0x10 %08x  rest nonzero %s"
                      % (position, slot, dva, subtype, counter, counter >> 8, unk10,
                         any(tail)))
    print()
