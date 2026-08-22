# SPDX-License-Identifier: MIT
"""Which of the objects a submission needs exist in each snapshot.

The pre-control snapshot is the only world whose control channel stays live, but it was taken before
the guest submitted anything. Whether the render-context objects a submission names already exist
there decides whether work can be built on it at all.
"""
import json
import pathlib

SNAPSHOTS = {
    "pre_control_0x84_v3": "/Users/user/asahi_re/artifacts/agx_g17p/"
                           "pre_control_0x84_v3_20260724_183150",
    "pre_work_0x83_v2": "/Users/user/asahi_re/artifacts/agx_g17p/"
                        "pre_work_0x83_v2_20260724_193713",
}

# The render-context objects the working submission names, and the firmware-context pools it uses.
WANTED = {
    "encoder": 0x1000018000,
    "ta_status": 0x1000078000,
    "render_target": 0x10000088000,
    "fragment_status": 0x10001a8000,
    "tilemap": 0x10001b0000,
    "heapmeta": 0x10001b4000,
    "depth_bias": 0x10001af8000,
    "tpc": 0x1000240000,
    "ta_output": 0x7000008000,
    "pool_page": 0xfffffc20c0828000,
    "pool_b_page": 0xfffffc20c0838000,
    "shared_page": 0xfffffc20c0868000,
}

for label, path in SNAPSHOTS.items():
    manifest = json.load(open(pathlib.Path(path) / "manifest.json"))
    mapped = set()
    for group in manifest.get("root_mappings", []):
        for mapping in group.get("mappings", []):
            mapped.add(int(mapping["va"]) & ~0x3fff)
    for mapping in manifest.get("mappings", []):
        mapped.add(int(mapping["va"]) & ~0x3fff)
    print("== %s: %d mapped pages" % (label, len(mapped)))
    for name, dva in WANTED.items():
        page = dva & ~0x3fff
        print("   %-16s %#014x  %s"
              % (name, dva, "present" if page in mapped else "ABSENT"))
