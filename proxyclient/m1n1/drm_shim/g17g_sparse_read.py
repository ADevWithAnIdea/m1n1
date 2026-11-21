# SPDX-License-Identifier: GPL-2.0-only
"""Losslessly omit zero cache lines from diagnostic physical-memory transfers.

The caller must validate the source's RAM and firmware-code exclusion bounds.
Only host-owned, GPU-unmapped scratch and the usual proxy code buffer are
written. This is transport packing, not synthesized capture content: the
target reads every source byte and copies each nonzero 64-byte line once.
"""
import struct


# x0 source, x1 scratch destination, x2 cache-line count. Return packed length.
# Caller-saved registers only. No source stores, cache maintenance, or MMIO.
PACK_ASM = """
    mov x3, x1
    mov x4, #0
1:
    ldp x5, x6, [x0, #0]
    ldp x7, x8, [x0, #16]
    ldp x9, x10, [x0, #32]
    ldp x11, x12, [x0, #48]
    orr x13, x5, x6
    orr x14, x7, x8
    orr x13, x13, x14
    orr x14, x9, x10
    orr x13, x13, x14
    orr x14, x11, x12
    orr x13, x13, x14
    cbz x13, 2f
    str x4, [x1], #8
    stp x5, x6, [x1], #16
    stp x7, x8, [x1], #16
    stp x9, x10, [x1], #16
    stp x11, x12, [x1], #16
2:
    add x0, x0, #64
    add x4, x4, #1
    subs x2, x2, #1
    b.ne 1b
    sub x0, x1, x3
"""


def unpack_lines(packed, size):
    if size <= 0 or size % 64 or len(packed) % 72 or len(packed) > size // 64 * 72:
        raise ValueError("invalid sparse transfer size")
    result = bytearray(size)
    previous = -1
    for offset in range(0, len(packed), 72):
        index = struct.unpack_from("<Q", packed, offset)[0]
        if not previous < index < size // 64:
            raise ValueError("sparse line index is not strictly increasing/in bounds")
        result[index * 64:(index + 1) * 64] = packed[offset + 8:offset + 72]
        previous = index
    return bytes(result)


class SparseRead:
    def __init__(self, util, iface):
        self.util, self.iface = util, iface
        self.source_bytes = self.wire_bytes = self.calls = 0

    def read(self, source, size):
        if source % 8 or size <= 0 or size % 64 or size > 0x100000:
            raise ValueError("sparse source must be aligned and at most one MiB")
        maximum = size // 64 * 72
        with self.util.heap.guarded_malloc(maximum) as scratch:
            used = int(self.util.exec(PACK_ASM, source, scratch, size // 64))
            if not 0 <= used <= maximum or used % 72:
                raise RuntimeError("target returned invalid sparse length")
            # The scratch copy is stable while transferring/checksumming it.
            packed = b"".join(bytes(self.iface.readmem(scratch + offset,
                min(0x100000, used - offset))) for offset in range(0, used, 0x100000))
            result = unpack_lines(packed, size)
        self.calls += 1
        self.source_bytes += size
        self.wire_bytes += used
        return result

    def self_test(self):
        # All-zero, all-nonzero, and sparse lines; vary every byte position.
        patterns = (bytes(4096), bytes(range(256)) * 16,
                    b"".join(bytes(64) if i % 3 else bytes([i + 1]) * 64
                             for i in range(64)))
        with self.util.heap.guarded_malloc(4096) as scratch:
            for expected in patterns:
                self.iface.writemem(scratch, expected)
                if self.read(scratch, len(expected)) != expected:
                    raise RuntimeError("sparse target transfer self-test failed")
        return {"patterns": len(patterns), "bytes_each": 4096, "exact": True}
