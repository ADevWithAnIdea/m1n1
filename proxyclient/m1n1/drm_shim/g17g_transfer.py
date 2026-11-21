# SPDX-License-Identifier: GPL-2.0-only
"""Lossless zero-run encoding for ordered writes to explicitly owned RAM.

Every byte is still written, in the original publication order. Only its wire
representation changes; zero runs are stores from xzr instead of uploaded data.
The caller owns cache publication and must exclude MMIO and firmware code.
"""
import struct


COPY_ASM = """
    cbz x1, 6f
1:  ldp x2, x3, [x0]
    ldr x4, [x0, #16]
    add x0, x0, #24
2:  cmp x4, #8
    b.lo 4f
    mov x5, #0
    cbz x3, 3f
    ldr x5, [x3], #8
3:  str x5, [x2], #8
    sub x4, x4, #8
    b 2b
4:  cbz x4, 5f
    mov w5, #0
    cbz x3, 7f
    ldrb w5, [x3], #1
7:  strb w5, [x2], #1
    sub x4, x4, #1
    b 4b
5:  subs x1, x1, #1
    b.ne 1b
6:  dsb sy
    mov x0, #0
"""

# Invalidate only the explicitly owned source ranges, then gather their exact
# bytes into private host scratch. No firmware pointers are followed.
def _invalidate_asm(address_offset):
    return """
    mov x9, x0
    mov x10, x1
    cbz x10, 3f
1:  ldr x3, [x9, #%d]
    ldr x4, [x9, #16]
    add x4, x3, x4
    and x3, x3, #-64
2:  dc ivac, x3
    add x3, x3, #64
    cmp x3, x4
    b.lo 2b
    add x9, x9, #24
    subs x10, x10, #1
    b.ne 1b
3:  dsb sy
""" % address_offset


READ_ASM = _invalidate_asm(8) + COPY_ASM

# Full byte comparison against the expected zero/nonzero runs. This does not
# use the sparse reader and never writes to any compared source range.
COMPARE_ASM = _invalidate_asm(0) + """
    cbz x1, 6f
    mov x7, #1
1:  ldp x2, x3, [x0]
    ldr x4, [x0, #16]
    add x0, x0, #24
2:  cmp x4, #8
    b.lo 4f
    mov x5, #0
    cbz x3, 3f
    ldr x5, [x3], #8
3:  ldr x6, [x2], #8
    cmp x5, x6
    b.ne 8f
    sub x4, x4, #8
    b 2b
4:  cbz x4, 5f
    mov w5, #0
    cbz x3, 7f
    ldrb w5, [x3], #1
7:  ldrb w6, [x2], #1
    cmp w5, w6
    b.ne 8f
    sub x4, x4, #1
    b 4b
5:  subs x1, x1, #1
    add x7, x7, #1
    b.ne 1b
6:  mov x0, #0
    b 9f
8:  mov x0, x7
9:  dsb sy
"""


def read_ranges(util, proxy, iface, ranges):
    """One target gather/read for disjoint known RAM ranges, no gap reads."""
    ranges = tuple(ranges)
    for pa, size in ranges:
        if type(pa) is not int or type(size) is not int or size <= 0 or not 0 < pa < pa + size < (1 << 42):
            raise ValueError("invalid owned physical read range")
    total = sum(size for _pa, size in ranges)
    if total > 0x100000:
        raise ValueError("owned range gather exceeds one MiB")
    if not ranges:
        return ()
    table_size = 24 * len(ranges)
    with util.heap.guarded_malloc(table_size + total) as staging:
        offset, table = table_size, []
        for pa, size in ranges:
            table.append(struct.pack("<3Q", staging + offset, pa, size))
            offset += size
        iface.writemem(staging, b"".join(table))
        proxy.dc_civac(staging, table_size)
        util.exec(READ_ASM, staging, len(ranges))
        body = bytes(iface.readmem(staging + table_size, total))
    if len(body) != total:
        raise RuntimeError("short owned range gather read")
    offset, result = 0, []
    for _pa, size in ranges:
        result.append(body[offset:offset + size])
        offset += size
    return tuple(result)


def zero_runs(publications):
    """Return (PA, length, bytes-or-None) records without reordering stores."""
    records = []
    for address, body in publications:
        body = bytes(body)
        if type(address) is not int or not 0 < address <= address + len(body) < (1 << 42):
            raise ValueError("invalid owned physical write range")
        if not body:
            continue
        start, is_zero = 0, None
        for offset in range(0, len(body), 64):
            chunk = body[offset:offset + 64]
            zero = chunk == bytes(len(chunk))
            if is_zero is not None and zero != is_zero:
                records.append((address + start, offset - start,
                                None if is_zero else body[start:offset]))
                start = offset
            is_zero = zero
        records.append((address + start, len(body) - start,
                        None if is_zero else body[start:]))
    return tuple(records)


def write_publications(util, proxy, iface, publications):
    publications = tuple((int(address), bytes(body)) for address, body in publications if len(body))
    records = zero_runs(publications)
    if not records:
        return 0
    _run_zero_records(util, proxy, iface, records, COPY_ASM)
    return len(publications)


def compare_publications(util, proxy, iface, publications):
    """Compare every byte on target, returning the first unequal run, if any."""
    records = zero_runs(publications)
    if not records:
        return dict(exact=True, bytes=0, unequal_run=None)
    index = int(_run_zero_records(util, proxy, iface, records, COMPARE_ASM))
    if not 0 <= index <= len(records):
        raise RuntimeError("target returned invalid comparison index")
    return dict(exact=(index == 0), bytes=sum(size for _pa, size, _body in records),
                unequal_run=None if index == 0 else dict(pa=records[index - 1][0], size=records[index - 1][1]))


def _run_zero_records(util, proxy, iface, records, assembly):
    table_size = 24 * len(records)
    size = table_size + sum(len(body) for _pa, _size, body in records if body is not None)
    with util.heap.guarded_malloc(size) as staging:
        table, payload = [], bytearray()
        for address, length, body in records:
            source = 0 if body is None else staging + table_size + len(payload)
            table.append(struct.pack("<3Q", address, source, length))
            if body is not None:
                payload.extend(body)
        encoded = b"".join(table) + payload
        iface.writemem(staging, encoded)
        proxy.dc_civac(staging, len(encoded))
        return util.exec(assembly, staging, len(records))


def self_test(util):
    """Bounded target test, using raw reads independent of the sparse reader."""
    expected = bytes(range(256)) * 16
    with util.heap.guarded_malloc(4096) as scratch:
        writes = ((scratch, expected), (scratch + 1, bytes(135)),
                  (scratch + 1024, b"Z" * 65 + bytes(129)), (scratch + 4095, b"!"))
        result = bytearray(expected)
        for address, body in writes:
            result[address - scratch:address - scratch + len(body)] = body
        write_publications(util, util.proxy, util.iface, writes)
        if bytes(util.iface.readmem(scratch, 4096)) != result:
            raise RuntimeError("zero-run upload failed exact scratch comparison")
        ranges = ((scratch + 4095, 1), (scratch + 1023, 201), (scratch + 1, 135))
        actual = read_ranges(util, util.proxy, util.iface, ranges)
        if actual != tuple(bytes(result[pa - scratch:pa - scratch + size]) for pa, size in ranges):
            raise RuntimeError("owned range gather failed exact scratch comparison")
        comparisons = ((scratch, bytes(result)),)
        if not compare_publications(util, util.proxy, util.iface, comparisons)["exact"]:
            raise RuntimeError("target comparison rejected equal scratch")
        # Negative controls in both zero/nonzero runs and the last byte.
        for offset in (0, 72, 4095):
            unequal = bytearray(result)
            unequal[offset] ^= 1
            if compare_publications(util, util.proxy, util.iface, ((scratch, unequal),))["exact"]:
                raise RuntimeError("target comparison accepted unequal scratch")
    return dict(exact=True, bytes=4096, overlapping_writes=len(writes), gathered_ranges=len(ranges),
                comparison_negative_controls=3)
