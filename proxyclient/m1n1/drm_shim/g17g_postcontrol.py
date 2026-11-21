# SPDX-License-Identifier: GPL-2.0-only
"""Source builders for the observed T8142/G17G post-control package.

Two independent pre-type-0x84 snapshots, normalized against two independent
pre-init snapshots, expose the same 43 newly mapped context-64 pages.  This
module builds every byte of that package from numeric formulas.  Twenty-nine
pages are zero; the only cross-boot input is the u32 queue-generation value
stored in both exact-stride queue records.

Names remain numeric or size-based.  The package is host-publication state,
not evidence that type 0x89 created it, and none of these builders implies a
work/completion or execution role.
"""

import struct

from . import g17g


PAGE_SIZE = 0x4000

POSTCONTROL_PAGE_DVAS = (
    0xFFFFFC2000000000,
    0xFFFFFC2000010000,
    0xFFFFFC2000014000,
    0xFFFFFC20001D8000,
    0xFFFFFC20001DC000,
    0xFFFFFC20001E0000,
    0xFFFFFC20001E4000,
    0xFFFFFC20001E8000,
    0xFFFFFC20001EC000,
    0xFFFFFC20001F0000,
    0xFFFFFC20001F4000,
    0xFFFFFC2000200000,
    0xFFFFFC2000204000,
    0xFFFFFC2000208000,
    0xFFFFFC200020C000,
    0xFFFFFC2000210000,
    0xFFFFFC2000214000,
    0xFFFFFC2000218000,
    0xFFFFFC200021C000,
    0xFFFFFC20015F8000,
    0xFFFFFC2001600000,
    0xFFFFFC2001608000,
    0xFFFFFC2001610000,
    0xFFFFFC2001618000,
    0xFFFFFC2001620000,
    0xFFFFFC2001628000,
    0xFFFFFC2001630000,
    0xFFFFFC20C0000000,
    0xFFFFFC20C0008000,
    0xFFFFFC20C000C000,
    0xFFFFFC20C07C0000,
    0xFFFFFC20C07E0000,
    0xFFFFFC20C08A8000,
    0xFFFFFC20C08B0000,
    0xFFFFFC20C08B8000,
    0xFFFFFC20C08C0000,
    0xFFFFFC20C08C8000,
    0xFFFFFC20C08CC000,
    0xFFFFFC20C08D0000,
    0xFFFFFC20C08D4000,
    0xFFFFFC20C08D8000,
    0xFFFFFC20C08DC000,
    0xFFFFFC20C08E8000,
)

QUEUE_PAGE = 0xFFFFFC20C0000000
QUEUE_POINTER_PAGE = 0xFFFFFC2000010000
QUEUE_ITEM_RING_PAGE = 0xFFFFFC20C0008000
QUEUE_ADDRESS_10_PAGE = 0xFFFFFC2000000000
QUEUE_ADDRESS_70_PAGE = 0xFFFFFC20C07C0000

FLAG_CLASS_SHARED_UXN = "shared_uxn"
FLAG_CLASS_SHARED_EXECUTABLE = "shared_executable"
FLAG_CLASS_NORMAL_UXN = "normal_uxn"

# This all-zero global is the sole package leaf in the observed shared
# executable/read-only class.  It has the same class in independent native
# pre-type-0x84 captures and at the accepted pre-first-work boundary.
SHARED_EXECUTABLE_PAGE_DVAS = (0xFFFFFC2001610000,)

QUEUE_ADDRESSES = (QUEUE_PAGE, QUEUE_PAGE + g17g.QUEUE_RECORD_STRIDE)
POINTER_BLOCK_ADDRESSES = (
    QUEUE_POINTER_PAGE,
    QUEUE_POINTER_PAGE + 0x2870,
)
ITEM_RING_ADDRESSES = (
    QUEUE_ITEM_RING_PAGE,
    QUEUE_ITEM_RING_PAGE + 0x2870,
)

ADDRESS_TABLE_PAGE = 0xFFFFFC20C08A8000
ADDRESS_TABLE_COUNT = 36
ADDRESS_TABLE_STRIDE = 0x100
ADDRESS_TABLE_TARGET = 0xFFFFFC2001600000

TARGET_RECORD_ARRAY_PAGE = 0xFFFFFC20C08B8000
TARGET_RECORD_ARRAY_COUNT = 80
TARGET_RECORD_ADDRESS_00 = 0x1000080000
TARGET_RECORD_ADDRESS_08 = 0xFFFFFC2001620000
TARGET_RECORD_WORD_28 = 0x220000
TARGET_RECORD_ADDRESS_40 = 0xFFFFFC2001618040

SELECTOR15_RECORD_PAGE = 0xFFFFFC20C0600000
SELECTOR15_RECORD_SIZE = g17g.ITEM_RECORD_SIZE[g17g.SELECTOR_15]

CHANNEL12_ENTRY_SIZE = 0x40
CHANNEL12_ENTRY_OPCODE = 0x20
CHANNEL12_DESCRIPTOR_ADDRESS = 0xFFFFFC20C08B0000
CHANNEL12_TAGGED_ADDRESS = 0x7200408000

# The same 16 fresh pages in the two contiguous low-DVA groups are also
# visible through native context zero before type 0x84.  They alias package
# pages exactly; they are not a second allocation or imported page content.
CONTEXT0_ALIAS_RUNS = (
    (0x7200438000, 0xFFFFFC20001D8000, 8),
    (0x7200460000, 0xFFFFFC2000200000, 8),
)

# Four already-mapped pages gain the same sparse numeric qwords between the
# native pre-init and pre-type-0x84 boundaries in two independent boots.  The
# containing pages are otherwise not copied: callers patch these fields into
# their live source-owned backing after control startup.
EXISTING_POSTCONTROL_QWORDS = {
    0xFFFFFC2000024000: (
        (0x358, 0x00080A0100000000),
        (0x360, 0x3BD),
        (0x5D0, 0x5),
    ),
    0xFFFFFC20015E8000: (
        (0x000, 0x3000023800),
    ),
    0xFFFFFC20015F0000: (
        (0x000, 0xE4000000),
        (0x008, 0x1A0000000000),
        (0x010, 0x8000000001A00),
    ),
    0xFFFFFC20C00B0000: (
        (0x000, 0x1),
        (0x008, 0x100000000),
        (0x2100, 0x1),
        (0x21D0, 0x1000000000000),
        (0x21D8, 0xB180),
        (0x21E0, 0x200000000000000),
        (0x21E8, 0x4000000000000),
    ),
}

# The small record at 0xfffffc20015e8000 selects one of the adjacent
# context-1/post-control alias families.  Ordinary first work uses the page at
# 0x1000238000, while every coherent native mixed witness uses the next family
# at 0x1000240000.  The numeric value is the firmware's observed encoded form;
# keeping the two proven variants explicit avoids assigning an unverified bit
# layout to it.
POSTCONTROL_ALLOCATION_FAMILY_QWORDS = {
    0: 0x0000003000023800,
    1: 0x0000003000024000,
    2: 0x0000003000024800,
}


def _put(data, offset, body):
    end = offset + len(body)
    if offset < 0 or end > len(data):
        raise ValueError("post-control object crosses its numeric page")
    data[offset:end] = body


def flag_class_for_address(address):
    """Return the exact observed leaf-attribute class for one package DVA."""
    if address not in POSTCONTROL_PAGE_DVAS:
        raise ValueError("address is absent from the post-control package")
    if address in SHARED_EXECUTABLE_PAGE_DVAS:
        return FLAG_CLASS_SHARED_EXECUTABLE
    if address < QUEUE_PAGE:
        return FLAG_CLASS_SHARED_UXN
    return FLAG_CLASS_NORMAL_UXN


def build_context0_aliases():
    """Return the observed low-DVA to post-control-page alias map."""
    aliases = {}
    package = set(POSTCONTROL_PAGE_DVAS)
    for low_base, high_base, page_count in CONTEXT0_ALIAS_RUNS:
        for index in range(page_count):
            low_va = low_base + index * PAGE_SIZE
            high_va = high_base + index * PAGE_SIZE
            if high_va not in package:
                raise ValueError(
                    "context-zero alias target is absent from package"
                )
            if low_va in aliases:
                raise ValueError("context-zero alias runs overlap")
            aliases[low_va] = high_va
    return aliases


def build_existing_postcontrol_qwords(allocation_family=0,
                                      resource_units=0x1A):
    """Return stable sparse qwords for one allocation/resource family.

    Allocation-family selection controls the adjacent backing-window selector,
    while ``resource_units`` controls the independent allocator endpoint.  The
    ordinary first-work captures use 0x1a units; the earliest mixed-compute
    captures use 0x16 with allocation family one.
    """
    try:
        allocation_qword = POSTCONTROL_ALLOCATION_FAMILY_QWORDS[
            int(allocation_family)
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("unsupported post-control allocation family") from exc
    resource_units = int(resource_units)
    if not 0 <= resource_units < (1 << 24):
        raise ValueError("post-control resource units do not fit in 24 bits")
    result = {}
    for va, entries in EXISTING_POSTCONTROL_QWORDS.items():
        if va == 0xFFFFFC20015E8000:
            entries = ((0x000, allocation_qword),)
        elif va == 0xFFFFFC20015F0000:
            entries = (
                (0x000, 0xE4000000),
                (0x008, resource_units << 40),
                (0x010, 0x0008000000000000 | (resource_units << 8)),
            )
        checked = []
        for offset, value in entries:
            if offset & 7 or not 0 <= offset <= PAGE_SIZE - 8:
                raise ValueError("existing post-control qword is unaligned")
            if not 0 <= value < (1 << 64):
                raise ValueError("existing post-control value does not fit u64")
            checked.append((offset, value))
        if len({offset for offset, _value in checked}) != len(checked):
            raise ValueError("existing post-control qword is duplicated")
        result[va] = tuple(checked)
    return result


def build_selector15_record(queue_generation):
    """Build the complete observed numeric selector-15 record at group zero."""
    if not 0 <= queue_generation < (1 << 8):
        raise ValueError("selector-15 queue generation must fit in u8")
    qwords = (
        0xF,
        0x7200460000,
        0xFFFFFC2000200000,
        0x10001,
        0x1000000010000,
        0,
        0x10000,
        0xFFFFFC20C08B,
        0,
        0xFC20C07C00000000,
        0x1FFFF,
        (1 << 48) | (queue_generation << 16),
        0x1000000010000,
        0,
        0xFFFF000000000000,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFF,
    )
    record = bytearray(SELECTOR15_RECORD_SIZE)
    struct.pack_into("<%dQ" % len(qwords), record, 0, *qwords)
    return bytes(record)


def build_channel12_entry20():
    """Build the complete native numeric opcode-0x20 channel-12 entry."""
    return g17g.build_service_opcode20_record(
        CHANNEL12_DESCRIPTOR_ADDRESS,
        CHANNEL12_TAGGED_ADDRESS,
    )


def _queue_page(queue_generation):
    if not 0 <= queue_generation < (1 << 32):
        raise ValueError("queue generation does not fit in u32")
    word_40 = (queue_generation << 32) | 0xFFFFFFFF
    page = bytearray(PAGE_SIZE)
    for index in range(2):
        record = g17g.build_queue_record(
            POINTER_BLOCK_ADDRESSES[index],
            ITEM_RING_ADDRESSES[index],
            QUEUE_ADDRESS_10_PAGE,
            QUEUE_ADDRESS_70_PAGE,
            word_40=word_40,
        )
        _put(page, index * g17g.QUEUE_RECORD_STRIDE, record)
    return bytes(page)


def _pointer_page():
    page = bytearray(PAGE_SIZE)
    _put(page, 0, g17g.build_pointer_block())
    _put(page, 0x2870, g17g.build_pointer_block(field_40=1))
    return bytes(page)


def _item_ring_page():
    page = bytearray(PAGE_SIZE)
    struct.pack_into("<Q", page, 0x2870, 0xFFFFFC20C0600000)
    return bytes(page)


def _address_table_page():
    page = bytearray(PAGE_SIZE)
    for index in range(ADDRESS_TABLE_COUNT):
        struct.pack_into(
            "<Q", page, index * ADDRESS_TABLE_STRIDE,
            ADDRESS_TABLE_TARGET + index * 4,
        )
    struct.pack_into("<Q", page, ADDRESS_TABLE_STRIDE + 0x10, 0x50)
    return bytes(page)


def _numeric_descriptor_page():
    return g17g.build_opcode20_first_object(
        0x7200000000,
        CHANNEL12_TAGGED_ADDRESS,
        0xFFFFFC2001608000,
    )


def _target_record_array_page():
    page = bytearray(PAGE_SIZE)
    for index in range(TARGET_RECORD_ARRAY_COUNT):
        record = g17g.build_target_record_80(
            TARGET_RECORD_ADDRESS_00 + index * 0x40,
            TARGET_RECORD_ADDRESS_08 + index * 0x40,
            TARGET_RECORD_WORD_28 + (index % 36) * 0x40,
            TARGET_RECORD_ADDRESS_40,
            word_48=(1 << 32) if index == 1 else 0,
        )
        _put(page, index * g17g.TARGET_RECORD_80_STRIDE, record)
    return bytes(page)


def _three_word_page():
    page = bytearray(PAGE_SIZE)
    for offset, value in ((0x00, 0x11), (0x08, 0x22), (0x10, 0x33)):
        struct.pack_into("<I", page, offset, value)
    return bytes(page)


def _sequence_page():
    page = bytearray(PAGE_SIZE)
    values = tuple(range(0x11, 0x21)) + tuple(range(0x22, 0x32)) + tuple(
        range(0x33, 0x43)
    )
    struct.pack_into("<%dI" % len(values), page, 0, *values)
    return bytes(page)


def _trailing_descriptor_page():
    values = (
        0, 0, 0, 0, 0, 0, 0, 0,
        0xC08C8000, 0xFFFFFC20, 0x238000, 0x10,
        0x18000, 0x30, 0x5CD, 0x3,
        0, 0xC08C0000, 0xFFFFFC20, 0x1618000,
        0xFFFFFC20, 0x2F, 0x80000, 0,
        0, 0x1628000, 0xFFFFFC20, 0,
        0, 0, 0, 0x5CD0,
        0x1EF0, 0x228000, 0, 0,
        0, 0, 0, 0,
    )
    page = bytearray(PAGE_SIZE)
    struct.pack_into("<%dI" % len(values), page, 0, *values)
    return bytes(page)


def build_postcontrol_pages(queue_generation):
    """Build all 43 observed newly mapped firmware-context pages."""
    pages = {address: bytearray(PAGE_SIZE) for address in POSTCONTROL_PAGE_DVAS}

    struct.pack_into(
        "<Q", pages[QUEUE_ADDRESS_10_PAGE], 0x08, QUEUE_ADDRESS_10_PAGE
    )
    pages[QUEUE_POINTER_PAGE][:] = _pointer_page()
    pages[0xFFFFFC2001600000][0x04] = 1
    pages[0xFFFFFC2001608000][0x00] = 1
    pages[0xFFFFFC2001618000][0x00] = 3
    pages[0xFFFFFC2001618000][0x04] = 3
    pages[0xFFFFFC2001618000][0x60] = 1

    pages[QUEUE_PAGE][:] = _queue_page(queue_generation)
    pages[QUEUE_ITEM_RING_PAGE][:] = _item_ring_page()
    struct.pack_into("<Q", pages[QUEUE_ADDRESS_70_PAGE], 0x00, 0x1000000FFFF)
    struct.pack_into("<Q", pages[QUEUE_ADDRESS_70_PAGE], 0x20, 0x2000000000000)
    struct.pack_into("<Q", pages[QUEUE_ADDRESS_70_PAGE], 0x30, 0xFF000000)

    pages[ADDRESS_TABLE_PAGE][:] = _address_table_page()
    pages[0xFFFFFC20C08B0000][:] = _numeric_descriptor_page()
    pages[TARGET_RECORD_ARRAY_PAGE][:] = _target_record_array_page()
    pages[0xFFFFFC20C08C0000][:] = _three_word_page()
    pages[0xFFFFFC20C08C8000][:] = _sequence_page()
    pages[0xFFFFFC20C08E8000][:] = _trailing_descriptor_page()

    return {address: bytes(data) for address, data in pages.items()}
