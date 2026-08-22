# SPDX-License-Identifier: MIT
"""Did the marker survive the completed submission?

Each grafted render page was filled with 0xa5 after grafting and before the doorbell. Bytes that
are still 0xa5 were not written by anything between then and now.
"""
import json
import sys

sys.path.insert(0, "proxyclient")

from m1n1.setup import *  # noqa: F401,F403

PAGE = 0x4000
manifest = json.load(open(sys.argv[1]))
poisoned = manifest.get("poisoned_render_pages") or []
print("poisoned pages recorded: %d" % len(poisoned))

total_written = 0
for entry in poisoned:
    pa = int(entry["pa"])
    p.dc_civac(pa, PAGE)
    now = iface.readmem(pa, PAGE)
    changed = sum(1 for b in now if b != 0xA5)
    total_written += changed
    print("  %s render %#014x pa %#x: %d of %d bytes are no longer 0xa5"
          % (entry["half"], int(entry["dva"]), pa, changed, PAGE))

print("\nTOTAL bytes written over the marker: %d" % total_written)
print("m1n1 base now: %#x  (must match the replay run for this to mean anything)" % u.base)
