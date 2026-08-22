# SPDX-License-Identifier: MIT
"""Capture ASC register programming before G17P initdata handoff.

The bare-metal path starts each coprocessor by setting only CPU_CONTROL.RUN. The
documented native boot contract may also pass shared transport descriptors through
the ASC control page. This trace records every guest write to the first 4 KiB of
each ASC register block until both initdata messages are handed over. It persists
only register offsets, access widths, and values; it does not read or inspect
guest code or firmware memory.

Load with ``run_guest.py -m proxyclient/hv/trace_agx_g17p_asc_boot.py``. The
trace persists its report after the second initdata handoff; stop the guest from
the host once the report is written. It has an internal 150-second guard, below
the global 180-second maximum.
"""

import datetime
import json
import pathlib
import struct
import threading

from m1n1.hv import TraceMode
from m1n1.utils import irange


ASC_PAGE_SIZE = 0x1000
INITDATA_TYPE = 0x81
INITDATA_ENDPOINT = 0x20
WATCHDOG_SECONDS = 150
ARTIFACT_ROOT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
INSTANCES = (("primary", "/arm-io/gfx-asc"),
             ("secondary", "/arm-io/gfx1-asc"))


class AscBootTrace:
    def __init__(self):
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output = ARTIFACT_ROOT / ("asc_boot_regs_%s" % stamp)
        self.output.mkdir(parents=True, exist_ok=True)
        self.records = {name: [] for name, _path in INSTANCES}
        self.payloads = {name: 0 for name, _path in INSTANCES}
        self.initdata = {}
        self.done = False
        self.bases = {
            name: int(hv.adt[path].get_reg(0)[0])
            for name, path in INSTANCES
        }
        self.gpu_region = int(hv.adt["/arm-io/sgx"].gpu_region_base)
        self.uat_context_pairs = None
        self.uat_context0_walks = None
        print("G17P ASC boot-register trace -> %s" % self.output)

    def write(self, name, event):
        if self.done:
            return
        self.records[name].append({
            "offset": int(event.addr) - self.bases[name],
            "width": int(event.flags.WIDTH),
            "value": int(event.data),
        })

    def mailbox(self, name, event):
        if self.done:
            return
        offset = int(event.addr) - self.bases[name]
        if offset == 0x8800:
            self.payloads[name] = int(event.data)
            return
        if offset != 0x8808 or (int(event.data) & 0xff) != INITDATA_ENDPOINT:
            return
        message = self.payloads[name]
        if ((message >> 48) & 0xff) != INITDATA_TYPE:
            return
        self.initdata[name] = message & ((1 << 44) - 1)
        print("G17P %s initdata %#x" % (name, self.initdata[name]))
        if len(self.initdata) == len(INSTANCES):
            self.snapshot_uat()
            self.finish("both-initdata")

    def snapshot_uat(self):
        raw = bytes(hv.iface.readmem(self.gpu_region, 64 * 16))
        self.uat_context_pairs = [
            list(struct.unpack_from("<2Q", raw, context * 16))
            for context in range(64)
        ]
        self.uat_context0_walks = {
            name: self.walk_context_zero(dva)
            for name, dva in self.initdata.items()
        }

    @staticmethod
    def entry_pa(entry):
        return entry & (((1 << 48) - 1) & ~0x3fff)

    def walk_context_zero(self, dva):
        """Record only the native context-0 PTEs used by an initdata DVA."""
        levels = ((42, 2), (36, 64), (25, 2048), (14, 2048))
        table_pa = self.gpu_region
        walk = []
        for level, (shift, count) in enumerate(levels):
            index = (dva >> shift) & (count - 1)
            entry = int(hv.p.read64(table_pa + 8 * index))
            walk.append({
                "level": level,
                "table_pa": table_pa,
                "index": index,
                "entry": entry,
            })
            if not entry & 1:
                break
            table_pa = self.entry_pa(entry)
        return walk

    def finish(self, reason):
        if self.done:
            return
        self.done = True
        report = {
            "format": "m1n1-t8140-g17p-asc-boot-v1",
            "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reason": reason,
            "asc_bases": self.bases,
            "gpu_region": self.gpu_region,
            "initdata": self.initdata,
            "writes": self.records,
            "uat_context_pairs": self.uat_context_pairs,
            "uat_context0_walks": self.uat_context0_walks,
        }
        path = self.output / "asc_boot_register_writes.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("G17P ASC boot-register trace wrote %s" % path)


trace = AscBootTrace()

for instance_name, _path in INSTANCES:
    base = trace.bases[instance_name]
    hv.add_tracer(
        irange(base, ASC_PAGE_SIZE),
        "G17PAscBootRegs-%s" % instance_name,
        mode=TraceMode.SYNC,
        write=lambda event, name=instance_name: trace.write(name, event),
    )
    hv.add_tracer(
        irange(base + 0x8800, 0x10),
        "G17PAscBootMailbox-%s" % instance_name,
        mode=TraceMode.SYNC,
        write=lambda event, name=instance_name: trace.mailbox(name, event),
    )


def timeout():
    trace.finish("timeout")


guard = threading.Timer(WATCHDOG_SECONDS, timeout)
guard.daemon = True
guard.start()
print("G17P tracing ASC control pages for at most %d seconds" % WATCHDOG_SECONDS)
