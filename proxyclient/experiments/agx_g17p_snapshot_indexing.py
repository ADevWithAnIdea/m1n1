# SPDX-License-Identifier: MIT
"""Do the two snapshots index their RAM blobs the same way?

If they do, one image's page contents can be restored while the other's are read for the work model,
by substituting the blob array alone instead of threading a second snapshot through every reader.
"""
import json
import pathlib

A = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p/"
                 "pre_control_0x84_v3_20260724_183150")
B = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p/"
                 "pre_work_0x83_v2_20260724_193713")

a = json.load(open(A / "manifest.json"))
b = json.load(open(B / "manifest.json"))

print("top-level keys equal:", set(a) == set(b))
for key in ("init_message", "vaddr_shift"):
    print("  %-14s %s vs %s  %s"
          % (key, a.get(key), b.get(key), "same" if a.get(key) == b.get(key) else "DIFFER"))

for name in ("mappings", "root_mappings"):
    if name not in a:
        continue
    if name == "mappings":
        la = [(int(m["va"]), m.get("blob_index")) for m in a[name]]
        lb = [(int(m["va"]), m.get("blob_index")) for m in b[name]]
    else:
        la = [(int(m["va"]), m.get("blob_index"))
              for g in a[name] for m in g["mappings"]]
        lb = [(int(m["va"]), m.get("blob_index"))
              for g in b[name] for m in g["mappings"]]
    print("%s: %d vs %d entries, identical order and indices: %s"
          % (name, len(la), len(lb), la == lb))
    if la != lb:
        same_va = [x[0] for x in la] == [x[0] for x in lb]
        print("   same VA sequence: %s" % same_va)
        diffs = [(x, y) for x, y in zip(la, lb) if x != y]
        print("   first differing pairs: %s" % diffs[:4])

ram_a = (A / "ram.bin").stat().st_size
ram_b = (B / "ram.bin").stat().st_size
print("ram.bin sizes: %d vs %d  %s"
      % (ram_a, ram_b, "same" if ram_a == ram_b else "DIFFER"))
