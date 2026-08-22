# SPDX-License-Identifier: MIT
"""Are the buffers the operand table names mapped, and is the slot after them?

A 0x20 entry names a slot in that table, so publishing one of this host's own needs a buffer at the
next slot that firmware can actually reach.
"""
import json
import pathlib

SNAP = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p/"
                    "pre_control_0x84_v3_20260724_183150")
manifest = json.load(open(SNAP / "manifest.json"))

mapped = set()
for group in manifest.get("root_mappings", []):
    for m in group.get("mappings", []):
        mapped.add(int(m["va"]) & ~0x3fff)
for m in manifest.get("mappings", []):
    mapped.add(int(m["va"]) & ~0x3fff)

base = 0x70012a0000
stride = 0x108000
print("table entries and the slots after them:")
for i in range(9):
    dva = base + i * stride
    print("  slot %d  %#014x  %s"
          % (i, dva, "mapped" if (dva & ~0x3fff) in mapped else "ABSENT"))

# How much of each buffer is mapped, for the ones that are.
for i in (0, 1, 5, 6):
    dva = base + i * stride
    pages = sum(1 for off in range(0, stride, 0x4000)
                if ((dva + off) & ~0x3fff) in mapped)
    print("  slot %d spans %d of %d pages mapped"
          % (i, pages, stride // 0x4000))
