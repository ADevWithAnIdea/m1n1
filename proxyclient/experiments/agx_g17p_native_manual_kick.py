#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replace XNU's first native CL_0 doorbell while the guest is stopped.

Load this from the hypervisor capture shell with::

    __import__('runpy').run_path(
        'proxyclient/experiments/agx_g17p_native_manual_kick.py',
        init_globals=globals())

The caller must provide the shell globals ``g17p``, ``uat``, ``root``, ``hv``,
``u``, and ``p``.  The script deliberately changes no submission memory; it only writes
the native work mailbox and records physical client-page deltas.
"""

import datetime
import json
import os
import pathlib
import struct
import time

from m1n1.fw.asc.base import ASCMessage1
from m1n1.hw.asc import ASC


PAGE_SIZE = 0x4000
WORK_MESSAGE = int(globals().get("g17p_mailbox_message", 0x0083000000000002))
WORK_ENDPOINT = int(globals().get("g17p_mailbox_endpoint", 0x21))
OUTPUT_DVA = int(os.environ.get("G17P_MANUAL_OUTPUT_DVA", "0x1000000000"), 0)
OUTPUT_ROOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/native_manual_compute_kick"
)


required = ("g17p", "uat", "root", "hv", "u", "p")
missing = [name for name in required if name not in globals()]
if missing:
    raise RuntimeError("missing hypervisor shell globals: %s" % ", ".join(missing))

capture = pathlib.Path(g17p.output) / "CL_0"
page_manifest = json.loads((capture / "pages.json").read_text())
target_manifest = json.loads((capture / "target.json").read_text())
client_pages = [
    record
    for record in page_manifest["pages"]
    if not ((int(record["dva"]) >> 42) & 1)
]
if not any(int(record["dva"]) == OUTPUT_DVA for record in client_pages):
    raise RuntimeError("physical output witness %#x is absent" % OUTPUT_DVA)


def read_physical_page(pa):
    pa = int(pa) & ~(PAGE_SIZE - 1)
    p.dc_civac(pa, PAGE_SIZE)
    return bytes(hv.iface.readmem(pa, PAGE_SIZE))


channel = next(item for item in g17p.channels if item["name"] == "CL_0")


def read_counters():
    return [
        struct.unpack("<I", uat.ioread_root(root, address, 4))[0]
        for address in channel["state_addrs"]
    ]


producer_before = int(target_manifest["producer_before"])
producer_after = int(target_manifest["producer_after"])
before_counters = read_counters()
intercepted_precommit = before_counters == [
    producer_before,
    producer_before,
    producer_before,
]
if intercepted_precommit:
    producer_pa = int(channel["producer_pa"])
    p.write32(producer_pa, producer_after)
    p.dc_civac(producer_pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
    u.inst("dsb sy")
    before_counters = read_counters()
expected_published = [producer_before, producer_before, producer_after]
if before_counters != expected_published:
    raise RuntimeError("CL_0 is not published exactly once: %r" % before_counters)

before_pages = {
    int(record["dva"]): read_physical_page(record["pa"])
    for record in client_pages
}

asc_base = int(hv.adt["/arm-io/gfx-asc"].get_reg(0)[0])
ASC(u, asc_base).send(WORK_MESSAGE, ASCMessage1(EP=WORK_ENDPOINT))

deadline = time.monotonic() + 2.0
after_counters = read_counters()
while (
    time.monotonic() < deadline
    and after_counters[:2] != [producer_after, producer_after]
):
    time.sleep(0.001)
    after_counters = read_counters()

time.sleep(0.005)
stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output = OUTPUT_ROOT / stamp
output.mkdir(parents=True, exist_ok=False)

page_results = []
for record in client_pages:
    dva = int(record["dva"])
    pa = int(record["pa"])
    after = read_physical_page(pa)
    changed = [
        offset
        for offset, (old, new) in enumerate(zip(before_pages[dva], after))
        if old != new
    ]
    if changed:
        stem = "%x" % dva
        (output / (stem + "_before.bin")).write_bytes(before_pages[dva])
        (output / (stem + "_after.bin")).write_bytes(after)
    page_results.append(
        {
            "dva": dva,
            "pa": pa,
            "changed_bytes": len(changed),
            "first_changed_offsets": changed[:128],
            "sources": record.get("sources", []),
        }
    )
    print("DVA %#x PA %#x: %d physical bytes changed" % (dva, pa, len(changed)))

output_result = next(
    record for record in page_results if record["dva"] == OUTPUT_DVA
)
result = {
    "format": "m1n1-agx-g17p-native-manual-compute-kick-v1",
    "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "capture": str(capture),
    "message": WORK_MESSAGE,
    "endpoint": WORK_ENDPOINT,
    "counters_before": before_counters,
    "counters_after": after_counters,
    "committed_intercepted_producer": intercepted_precommit,
    "output_dva": OUTPUT_DVA,
    "output_changed_bytes": output_result["changed_bytes"],
    "pages": page_results,
}
(output / "result.json").write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n"
)
print("CL_0 counters: %r -> %r" % (before_counters, after_counters))
print("Physical output changed bytes: %d" % output_result["changed_bytes"])
print("Artifacts: %s" % output)
