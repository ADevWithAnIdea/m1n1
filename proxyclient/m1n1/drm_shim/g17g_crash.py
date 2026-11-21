# SPDX-License-Identifier: GPL-2.0-only
"""Data-only M5 crash evidence. Never dereference firmware code/stack pointers."""
import hashlib
import json
from pathlib import Path

from m1n1.fw.asc.crash import ASCCrashLogEndpoint, CrashLog
from m1n1.g17g_adt import exclusion_ranges, segment_metadata
from .g17g_sync import G17GPublishedFault, G17GWorkError


def crash_metadata(data):
    records = []
    for entry in CrashLog.parse(data).entries:
        record = dict(type=entry.type)
        if entry.type == "Crg8":
            ctx = entry.payload
            record.update(pc=int(ctx.pc), far=int(ctx.far), sp=int(ctx.sp),
                          esr=int(ctx.esr), psr=int(ctx.psr),
                          regs=[int(r) for r in ctx.regs])
        elif entry.type == "Ctim":
            record["time"] = int(entry.payload.time)
        # The raw crash-data record is preserved separately. Do not follow
        # Ccdp mappings or use generic Crg8's disassembly/stack reads.
        records.append(record)
    return dict(format="m1n1-g17g-data-only-crash-v1", records=records,
                sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                firmware_pointer_reads=False)


class G17GDataOnlyCrashEndpoint(ASCCrashLogEndpoint):
    def handle_getbuf(self, msg):
        self.buffer_size = int(msg.SIZE) * 0x1000
        return super().handle_getbuf(msg)

    def handle_crashed(self, msg):
        if int(self.asc.u.adt["/chosen"].chip_id) != 0x8142:
            raise RuntimeError("data-only crash endpoint requires T8142")
        size, address = int(msg.SIZE) * 0x1000, int(msg.DVA)
        if address != self.iobuffer_dva or not 0 < size <= self.buffer_size <= 0x40000:
            raise RuntimeError("unexpected M5 crash-data buffer extent")
        exclusions = exclusion_ranges(segment_metadata(self.asc.u.adt))
        spans = self.asc.iotranslate(address, size)
        if (sum(length for _pa, length in spans) != size or
            any(pa is None or pa <= 0 or any(pa < e["end"] and e["start"] < pa + length
                for e in exclusions) for pa, length in spans)):
            raise RuntimeError("crash buffer is unmapped or overlaps firmware code")
        data = bytes(self.asc.ioread(address, size))
        output = Path(self.asc.crash_output_directory)
        name = getattr(self.asc, "coldboot_name", getattr(self.asc, "name", "asc"))
        (output / (name + "_crash.bin")).write_bytes(data)
        metadata = crash_metadata(data)
        (output / (name + "_crash.json")).write_text(json.dumps(metadata, indent=2) + "\n")
        self.log("Crash-data evidence only: " + json.dumps(metadata))
        raise G17GPublishedFault("firmware-crash", G17GWorkError.DEVICE_LOST,
            fatal=True, metadata=dict(asc=name, evidence_saved=True,
                crash_file=str(output / (name + "_crash.bin")),
                sha256=metadata["sha256"], firmware_pointer_reads=False))
