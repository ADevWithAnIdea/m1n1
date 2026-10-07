# SPDX-License-Identifier: MIT
"""Lossless diagnostic RAM transport, adapted from the M5 sparse reader.

Every source byte is read on target. Only zero 64-byte lines are omitted from
the wire; the ordinary full-size capture is reconstructed on the host. Source
ranges must be explicit normal RAM, never MMIO or Apple firmware code.
"""
import struct


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

# x0: explicit (physical address, 64-byte line count) vector; x1: output;
# x2: vector length. Read every source byte after cache invalidation. Use only
# caller-saved registers; the host bounds both vector and worst-case output.
PACK_VECTOR_ASM = """
    mov x3, x1
    mov x4, #0
1:
    ldp x15, x16, [x0], #16
    mov x17, x15
    mov x14, x16
2:
    dc ivac, x17
    add x17, x17, #64
    subs x14, x14, #1
    b.ne 2b
    dsb sy
3:
    ldp x5, x6, [x15, #0]
    ldp x7, x8, [x15, #16]
    ldp x9, x10, [x15, #32]
    ldp x11, x12, [x15, #48]
    orr x13, x5, x6
    orr x14, x7, x8
    orr x13, x13, x14
    orr x14, x9, x10
    orr x13, x13, x14
    orr x14, x11, x12
    orr x13, x13, x14
    cbz x13, 4f
    str x4, [x1], #8
    stp x5, x6, [x1], #16
    stp x7, x8, [x1], #16
    stp x9, x10, [x1], #16
    stp x11, x12, [x1], #16
4:
    add x15, x15, #64
    add x4, x4, #1
    subs x16, x16, #1
    b.ne 3b
    subs x2, x2, #1
    b.ne 1b
    sub x0, x1, x3
"""


def validate_vector(ranges):
    """Bounds for explicit owned RAM, never arbitrary address-space scanning."""
    ranges = tuple((int(address), int(size)) for address, size in ranges)
    if not ranges or len(ranges) > 1024:
        raise ValueError("sparse vector requires 1..1024 owned RAM ranges")
    for address, size in ranges:
        if (address % 64 or size <= 0 or size % 64
                or not 0x10000000000 <= address < address + size <= 0x10100000000):
            raise ValueError("sparse vector requires cache-line-aligned normal RAM")
    total = sum(size for _address, size in ranges)
    if total > 0x400000:
        raise ValueError("sparse vector is limited to four MiB")
    return ranges, total


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
        if source <= 0 or source % 8 or size <= 0 or size % 64 or size > 0x100000:
            raise ValueError("sparse source must be aligned and at most one MiB")
        maximum = size // 64 * 72
        with self.util.heap.guarded_malloc(maximum) as scratch:
            if source < scratch + maximum and scratch < source + size:
                raise RuntimeError("capture source overlaps host-owned scratch")
            used = int(self.util.exec(PACK_ASM, source, scratch, size // 64))
            if not 0 <= used <= maximum or used % 72:
                raise RuntimeError("target returned invalid sparse length")
            packed = b"".join(bytes(self.iface.readmem(scratch + offset,
                min(0x100000, used - offset))) for offset in range(0, used, 0x100000))
            if len(packed) != used:
                raise RuntimeError("short sparse transfer")
            result = unpack_lines(packed, size)
        self.calls += 1
        self.source_bytes += size
        self.wire_bytes += used
        return result

    def read_many(self, ranges):
        """Losslessly read an explicit vector of owned GPU-writable RAM spans."""
        ranges, total = validate_vector(ranges)
        vector = b"".join(struct.pack("<QQ", address, size // 64)
                          for address, size in ranges)
        maximum = total // 64 * 72
        with self.util.heap.guarded_malloc(len(vector)) as vector_pa, \
                self.util.heap.guarded_malloc(maximum) as scratch:
            for address, size in ranges:
                for temporary, length in ((vector_pa, len(vector)), (scratch, maximum)):
                    if address < temporary + length and temporary < address + size:
                        raise RuntimeError("owned GPU RAM overlaps sparse transfer scratch")
            self.iface.writemem(vector_pa, vector)
            used = int(self.util.exec(PACK_VECTOR_ASM, vector_pa, scratch, len(ranges)))
            if not 0 <= used <= maximum or used % 72:
                raise RuntimeError("target returned invalid sparse vector length")
            chunks = []
            for offset in range(0, used, 0x100000):
                length = min(0x100000, used - offset)
                chunk = bytes(self.iface.readmem(scratch + offset, length))
                if len(chunk) != length:
                    raise RuntimeError("short sparse vector transfer")
                chunks.append(chunk)
            decoded = unpack_lines(b"".join(chunks), total)
        bodies, cursor = [], 0
        for _address, size in ranges:
            bodies.append(decoded[cursor:cursor + size])
            cursor += size
        self.calls += 1
        self.source_bytes += total
        self.wire_bytes += used
        return bodies

    def self_test(self):
        patterns = (bytes(4096), bytes(range(256)) * 16,
                    b"".join(bytes(64) if i % 3 else bytes([i + 1]) * 64
                             for i in range(64)),
                    b"".join(bytes(i) + b"\x80" + bytes(63 - i)
                             for i in range(64)))
        with self.util.heap.guarded_malloc(4096) as scratch:
            for expected in patterns:
                self.iface.writemem(scratch, expected)
                if self.read(scratch, len(expected)) != expected:
                    raise RuntimeError("sparse target transfer self-test failed")
        return {"patterns": len(patterns), "bytes_each": 4096, "exact": True}
