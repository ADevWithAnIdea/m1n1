# SPDX-License-Identifier: GPL-2.0-only
"""Observed T8142/G17G numeric submission-path layouts.

This module contains only byte layouts reproduced by passive snapshots of a
live T8142.  Numeric channel and selector IDs are intentionally retained.  It
does not inherit semantic names or builders from the T8140/G17P backend, and it
does not claim that a consumed group rendered.

The evidence is recorded in ``docs/t8142-g17g-firmware-abi.md``.  Parsers are
strict about the observed bounds so future experiments fail visibly if a
layout changes.
"""

import struct


CHIP_ID = 0x8142

# Mailbox words observed at the passive boundaries.  Only the numeric encoding
# is established here; types 0x42, 0x84 and 0x89 keep numeric names because
# their semantic roles are unresolved.
MBOX_TYPE_SHIFT = 48
MBOX_TYPE_MASK = 0xFF
MBOX_ADDR_MASK = (1 << 48) - 1
ENDPOINT_INIT = 0x20
ENDPOINT_WORK = 0x21
MSG_INITDATA = 0x81
MSG_WORK_KICK = 0x83
MSG_TYPE_84 = 0x84
MSG_TYPE_89 = 0x89
MSG_TYPE_42 = 0x42

# Primary initdata root and the numeric table reached through root +0x18.
INITDATA_MAIN_POINTER_OFFSET = 0x18
CHANNEL_TABLE_OFFSET = 0x20
CHANNEL_ENTRY_SIZE = 0x20
CHANNEL_ENTRY_COUNT = 17
CHANNEL_POPULATED_COUNT = 16
CHANNEL_TRAILING_ZERO_INDEX = 16
CHANNEL_STATE_COUNT = 3
CHANNEL_STATE_ADDRESS_OFFSETS = (0x00, 0x08, 0x10)
CHANNEL_RING_ADDRESS_OFFSET = 0x18

# Historical fixture-only first-record values, NOT a general status API.
# The native memoryless first-work oracle has 0x48-byte records here: initial
# type 13, fifteen type 6 requests, then type 1 on exact completion. Its first
# u32 remains 13. Never infer current job completion from slot zero alone.
# Earlier source controls establish only their first u32: a tiny direct
# draw reports 1 with exact output, while a draw with an intentionally reduced
# operand table reports 4 and leaves truncated attachment output. That table
# is not the TVB backing list identified by the native growth capture. Its
# artificial starvation is not evidence that record type 4 means ENOMEM.
# The remaining object bytes are deliberately not assigned a layout here.
RENDER_REPORT_STATUS_SIZE = 4
RENDER_REPORT_FIXTURE_TYPE_1 = 1
RENDER_REPORT_FIXTURE_TYPE_4 = 4

# Channel 12 is a 0x40-byte service ring, not a normal 0x18-byte work ring.
# The beta-5 first-compute boundary has three opcode-0x15 records followed by
# six opcode-0x1a records.  Slot zero's opcode-0x15 is part of initdata and is
# consumed by the initial type-0x89 pair.  Before the first of six type-0x84
# writes, slots one and two contain the other two opcode-0x15 records and slot
# three contains opcode-0x1a `(0, 1)`; the following five type-0x84 boundaries
# publish one opcode-0x1a record apiece.  Names remain numeric because their
# semantics are not established.
SERVICE_RECORD_SIZE = 0x40
SERVICE_OPCODE_15 = 0x15
SERVICE_OPCODE_2E = 0x2E
TYPE84_PREFIX_OPCODE = 0x1A
TYPE84_PREFIX_FIRST_U32_PAIR = (0, 1)
TYPE84_PREFIX_U32_PAIRS = (
    (0, 2),
    (1, 1),
    (1, 2),
    (2, 1),
    (2, 2),
)

# One complete opcode-0x20 transaction and the page it names were captured
# immediately before the native beta-4 type-0x84 boundary.  These constants
# retain numeric names because the A18 class/resource terminology has not been
# established on G17G.
SERVICE_OPCODE_20 = 0x20
SERVICE_OPCODE_20_WORD_04 = 1
SERVICE_OPCODE_20_WORD_08 = 0x3F
SERVICE_OPCODE_20_ADDRESS_24_DELTA = 0x340
SERVICE_OPCODE_20_COUNT = 8
SERVICE_OPCODE_20_WORD_30 = 0
SERVICE_OPCODE_20_WORD_34 = 1
OPCODE20_FIRST_OBJECT_CURSOR = 0x68
OPCODE20_FIRST_OBJECT_RESOURCE = 0x1A
OPCODE20_FIRST_OBJECT_WORD_60 = 2

# A channel ring slot.  Capacity and wrap behavior are not established.
RING_SLOT_SIZE = 0x18
RING_SLOT_ZERO_OFFSET = 0x00
RING_SLOT_QUEUE_ADDRESS_OFFSET = 0x08
RING_SLOT_WORD_10_OFFSET = 0x10
RING_SLOT_WORD_14_OFFSET = 0x14
RING_SLOT_LIMIT_MASK = 0xFFFF
RING_SLOT_QUEUE_INDEX_SHIFT = 16
RING_SLOT_QUEUE_INDEX_MASK = 0xFF

# Two observed queue addresses are exactly one record apart.  The full 0x80
# bytes were captured and the following record begins at this stride.
QUEUE_RECORD_SIZE = 0x80
QUEUE_RECORD_STRIDE = 0x80
QUEUE_POINTER_BLOCK_ADDRESS_OFFSET = 0x00
QUEUE_ITEM_RING_ADDRESS_OFFSET = 0x08
QUEUE_ADDRESS_10_OFFSET = 0x10
QUEUE_LIMIT_OFFSET = 0x1C
QUEUE_WORD_20_OFFSET = 0x20
QUEUE_WORD_28_OFFSET = 0x28
QUEUE_WORD_30_OFFSET = 0x30
QUEUE_WORD_38_OFFSET = 0x38
QUEUE_WORD_40_OFFSET = 0x40
QUEUE_ACCUMULATOR_OFFSET = 0x68
QUEUE_ADDRESS_70_OFFSET = 0x70

# The five priority-dependent fields use the same encoding family as the
# clean-room G17P model, but G17G packs the final selector at +0x3c.  The
# following +0x40 qword remains G17G's (-1, queue-generation) pair and must
# not be rewritten as part of a priority change.
QUEUE_PRIORITY_OFFSET = 0x28
QUEUE_PRIORITY_MIRROR_OFFSET = 0x2C
QUEUE_PRIORITY_MASK_OFFSET = 0x30
QUEUE_PRIORITY_MODE_OFFSET = 0x38
QUEUE_PRIORITY_SELECTOR_OFFSET = 0x3C
QUEUE_PRIORITY_PROFILES = {
    0: (0, 0, 0xFFFFFFFFFFFF0000, 1, 1),
    1: (1, 1, 0xFFFFFFFF00000000, 0, 0),
    2: (2, 2, 0xFFFF000000000000, 0, 2),
    3: (3, 3, 0x0000000000000000, 0, 3),
}

# The public Asahi queue-priority enum is ordered from LOW to REALTIME, while
# firmware pipe/profile indices are ordered in the opposite direction.  The
# public ABI currently admits only LOW and MEDIUM, which select profiles 3 and
# 2 respectively.  Keep this conversion separate from the raw profile parser:
# profile numbers are useful clean-room diagnostics but are not UAPI values.
UAPI_QUEUE_PRIORITY_LOW = 0
UAPI_QUEUE_PRIORITY_MEDIUM = 1
UAPI_FEATURE_SOFT_FAULTS = 1 << 0
UAPI_QUEUE_PRIORITY_TO_FIRMWARE = {
    UAPI_QUEUE_PRIORITY_LOW: 3,
    UAPI_QUEUE_PRIORITY_MEDIUM: 2,
}

# The passive decoder captured through the last nonzero observed scalar.  This
# is a proven readable prefix, not a proven allocation size.
POINTER_BLOCK_OBSERVED_SIZE = 0x68
POINTER_FIELD_00 = 0x00
POINTER_FIELD_30 = 0x30
POINTER_FIELD_40 = 0x40
POINTER_FIELD_50 = 0x50
POINTER_FIELD_60 = 0x60

ITEM_RING_ENTRY_SIZE = 0x08
SELECTOR_0 = 0
SELECTOR_1 = 1
SELECTOR_14 = 14
SELECTOR_15 = 15
CONSUMED_SELECTOR_SEQUENCES = (
    (SELECTOR_15, SELECTOR_0, SELECTOR_14),
    (SELECTOR_15, SELECTOR_1, SELECTOR_14),
)

# Exact adjacent allocation strides bound the records in two native groups.
ITEM_RECORD_SIZE = {
    SELECTOR_0: 0x9C0,
    SELECTOR_1: 0x2240,
    SELECTOR_14: 0x40,
    SELECTOR_15: 0xC0,
}

# Three consecutive native groups establish the distance between records for
# the same numeric channel.  Selector-14/15 pools are interleaved between the
# two channels, while selector-0 and selector-1 use distinct pools.
ITEM_SAME_CHANNEL_GROUP_STRIDE = {
    SELECTOR_0: ITEM_RECORD_SIZE[SELECTOR_0],
    SELECTOR_1: ITEM_RECORD_SIZE[SELECTOR_1],
    SELECTOR_14: 2 * ITEM_RECORD_SIZE[SELECTOR_14],
    SELECTOR_15: 2 * ITEM_RECORD_SIZE[SELECTOR_15],
}

# Selector-0/1 common numeric header.
ITEM_SELECTOR_OFFSET = 0x00
ITEM_SEQUENCE_OFFSET = 0x04       # unaligned u64
ITEM_CONTEXT_OFFSET = 0x0C        # u32, observed as 1 in both groups

# The first two captured intervals populated two identical copies of a
# little-endian 40-bit endpoint pair.  At the third bounded after-image only
# the first copy was populated and the second remained zero.  These offsets are
# starts of five-byte values, not aligned integer fields.
ITEM_ENDPOINT_OFFSETS = {
    SELECTOR_0: ((0x87A, 0x882), (0x95D, 0x965)),
    SELECTOR_1: ((0x2114, 0x211C), (0x21F7, 0x21FF)),
}
ITEM_ENDPOINT_WIDTH = 5

# Selector-14's first record only.  No semantic field names are assigned.
SELECTOR_14_WORD_00 = 0x00
SELECTOR_14_WORD_04 = 0x04
SELECTOR_14_WORD_08 = 0x08
SELECTOR_14_WORD_10 = 0x10

# Two numeric target-record shapes reached directly from selector-0/1 items.
# Names remain size-based because their roles and writers are not established.
TARGET_RECORD_40_SIZE = 0x40
TARGET_RECORD_40_STRIDE = 0x40
TARGET_RECORD_40_WORD_00 = 0x00
TARGET_RECORD_40_WORD_10 = 0x10

TARGET_RECORD_80_SIZE = 0x80
TARGET_RECORD_80_STRIDE = 0x80
TARGET_RECORD_80_WORD_00 = 0x00
TARGET_RECORD_80_ADDRESS_08 = 0x08
TARGET_RECORD_80_WORD_10 = 0x10
TARGET_RECORD_80_WORD_28 = 0x28
TARGET_RECORD_80_ADDRESS_40 = 0x40
TARGET_RECORD_80_WORD_48 = 0x48

# A third direct selector-1 target advances by this exact stride and is zero
# before each bounded interval.  Its internal layout remains unresolved.
TARGET_BUFFER_2200_SIZE = 0x2200
TARGET_BUFFER_2200_STRIDE = 0x2200


def _require_size(data, size, name):
    if len(data) != size:
        raise ValueError(
            "%s must be exactly %#x bytes, got %#x"
            % (name, size, len(data))
        )


def mailbox_type(value):
    """Return the numeric message type from an observed 64-bit mailbox word."""
    return (value >> MBOX_TYPE_SHIFT) & MBOX_TYPE_MASK


def mailbox_payload(value):
    """Return the low 48 bits of an observed 64-bit mailbox word."""
    return value & MBOX_ADDR_MASK


def parse_channel_entry(data):
    """Decode one 0x20-byte numeric channel-table entry."""
    _require_size(data, CHANNEL_ENTRY_SIZE, "channel entry")
    state_addresses = struct.unpack_from("<3Q", data, 0)
    ring_address = struct.unpack_from(
        "<Q", data, CHANNEL_RING_ADDRESS_OFFSET
    )[0]
    return {
        "state_addresses": state_addresses,
        "ring_address": ring_address,
        "all_zero": not any(data),
    }


def parse_render_report_status(data):
    """Legacy first-record fixture parser, not a live ring/status consumer.

    Native memoryless jobs can finish with type 13 still in slot zero and a
    later type-1 record. The old fixtures identify record types, not complete
    jobs or an errno. In particular type 4 alone cannot establish ENOMEM.
    """
    if len(data) < RENDER_REPORT_STATUS_SIZE:
        raise ValueError(
            "render report status needs at least %#x bytes, got %#x"
            % (RENDER_REPORT_STATUS_SIZE, len(data))
        )
    status = struct.unpack_from("<I", data, 0)[0]
    return {
        "status": status,
        "first_record_type_1": status == RENDER_REPORT_FIXTURE_TYPE_1,
        "first_record_type_4": status == RENDER_REPORT_FIXTURE_TYPE_4,
        "execution_claim": "none; first record is not job completion",
        "fault_error": None,
    }


def build_channel_entry(state_addresses, ring_address):
    """Build one complete observed 0x20-byte numeric channel entry."""
    if len(state_addresses) != CHANNEL_STATE_COUNT:
        raise ValueError("channel entry requires three state addresses")
    values = tuple(state_addresses) + (ring_address,)
    if any(not 0 <= value < (1 << 64) for value in values):
        raise ValueError("channel-entry address does not fit in u64")
    return struct.pack("<4Q", *values)


def parse_channel_table(data, require_observed_shape=True):
    """Decode the 17-entry numeric channel table.

    The observed primary table has entries 0..15 populated and entry 16 all
    zero.  ``require_observed_shape=False`` is useful for bounded intermediate
    states while retaining the exact table size.
    """
    size = CHANNEL_ENTRY_COUNT * CHANNEL_ENTRY_SIZE
    _require_size(data, size, "channel table")
    entries = [
        parse_channel_entry(
            data[index * CHANNEL_ENTRY_SIZE:(index + 1) * CHANNEL_ENTRY_SIZE]
        )
        for index in range(CHANNEL_ENTRY_COUNT)
    ]
    if require_observed_shape:
        if any(entry["all_zero"] for entry in entries[:CHANNEL_POPULATED_COUNT]):
            raise ValueError("an observed populated channel entry is all zero")
        if not entries[CHANNEL_TRAILING_ZERO_INDEX]["all_zero"]:
            raise ValueError("numeric channel table entry 16 is not all zero")
    return entries


def build_channel_table(entries, require_observed_shape=True):
    """Build the complete seventeen-entry numeric channel table."""
    if len(entries) != CHANNEL_ENTRY_COUNT:
        raise ValueError("channel table requires exactly seventeen entries")
    data = b"".join(
        build_channel_entry(state_addresses, ring_address)
        for state_addresses, ring_address in entries
    )
    parse_channel_table(data, require_observed_shape=require_observed_shape)
    return data


def build_type84_prefix_record(first, second):
    """Build one observed numeric opcode-0x1a channel-12 record."""
    if not 0 <= first < (1 << 32) or not 0 <= second < (1 << 32):
        raise ValueError("type-0x84 prefix field does not fit in u32")
    data = bytearray(SERVICE_RECORD_SIZE)
    struct.pack_into("<III", data, 0, TYPE84_PREFIX_OPCODE, first, second)
    return bytes(data)


def build_service_opcode15_record():
    """Build one complete observed numeric opcode-0x15 service record."""
    data = bytearray(SERVICE_RECORD_SIZE)
    struct.pack_into("<I", data, 0, SERVICE_OPCODE_15)
    return bytes(data)


def build_service_opcode2e_record(word_04=1, word_0c=0):
    """Build the complete observed numeric opcode-0x2e service record."""
    for value, name in (
        (word_04, "+0x04"),
        (word_0c, "+0x0c"),
    ):
        if not 0 <= int(value) < (1 << 32):
            raise ValueError(
                "opcode-0x2e word %s does not fit in u32" % name
            )
    data = bytearray(SERVICE_RECORD_SIZE)
    struct.pack_into(
        "<IIII", data, 0,
        SERVICE_OPCODE_2E, int(word_04), 0, int(word_0c),
    )
    return bytes(data)


def build_type84_prefix_records():
    """Build the five records observed after the first native type-0x84."""
    return tuple(
        build_type84_prefix_record(first, second)
        for first, second in TYPE84_PREFIX_U32_PAIRS
    )


def build_first_compute_service_records():
    """Build slots one through eight at the beta-5 first-compute boundary."""
    return (
        build_service_opcode15_record(),
        build_service_opcode15_record(),
        build_type84_prefix_record(*TYPE84_PREFIX_FIRST_U32_PAIR),
        *build_type84_prefix_records(),
    )


def build_service_opcode20_record(
    first_object,
    tagged_address,
    *,
    sequence=0,
    cursor_delta=SERVICE_OPCODE_20_ADDRESS_24_DELTA,
    count=SERVICE_OPCODE_20_COUNT,
    word_30=SERVICE_OPCODE_20_WORD_30,
    word_34=SERVICE_OPCODE_20_WORD_34,
):
    """Build the captured numeric opcode-0x20 service-ring record."""
    values = (int(first_object), int(tagged_address))
    if any(not 0 <= value < (1 << 64) for value in values):
        raise ValueError("opcode-0x20 address does not fit in u64")
    if not 0 <= int(sequence) < (1 << 32):
        raise ValueError("opcode-0x20 sequence does not fit in u32")
    if not 0 <= int(cursor_delta) < (1 << 64):
        raise ValueError("opcode-0x20 cursor delta does not fit in u64")
    if values[1] + int(cursor_delta) >= (1 << 64):
        raise ValueError("opcode-0x20 cursor address does not fit in u64")
    for value, name in (
        (count, "count"), (word_30, "word +0x30"),
        (word_34, "word +0x34"),
    ):
        if not 0 <= int(value) < (1 << 32):
            raise ValueError("opcode-0x20 %s does not fit in u32" % name)
    data = bytearray(SERVICE_RECORD_SIZE)
    struct.pack_into(
        "<III",
        data,
        0,
        SERVICE_OPCODE_20,
        SERVICE_OPCODE_20_WORD_04,
        SERVICE_OPCODE_20_WORD_08,
    )
    struct.pack_into("<I", data, 0x0C, int(sequence))
    struct.pack_into("<Q", data, 0x14, values[0])
    struct.pack_into("<Q", data, 0x1C, values[1])
    struct.pack_into(
        "<Q",
        data,
        0x24,
        values[1] + int(cursor_delta),
    )
    struct.pack_into("<I", data, 0x2C, int(count))
    struct.pack_into("<I", data, 0x30, int(word_30))
    struct.pack_into("<I", data, 0x34, int(word_34))
    return bytes(data)


def build_opcode20_first_object(
    buffer_address,
    tagged_address,
    state_address,
    *,
    word_00=1,
    cursor=OPCODE20_FIRST_OBJECT_CURSOR,
    resource_units=OPCODE20_FIRST_OBJECT_RESOURCE,
    word_08=0,
    word_10=1,
    word_54=0,
    word_60=OPCODE20_FIRST_OBJECT_WORD_60,
):
    """Build the complete page named by the captured opcode-0x20 record.

    The 40-bit ``buffer_address`` is split across u32 ``+0x14`` and the low
    u32 of qword ``+0x18`` in the observed layout.  It is not a conventional
    aligned pointer field.
    """
    buffer_address = int(buffer_address)
    tagged_address = int(tagged_address)
    state_address = int(state_address)
    cursor = int(cursor)
    resource_units = int(resource_units)
    if not 0 <= buffer_address < (1 << 40):
        raise ValueError("opcode-0x20 buffer address must fit in 40 bits")
    if any(
        not 0 <= value < (1 << 64)
        for value in (tagged_address, state_address)
    ):
        raise ValueError("opcode-0x20 object address does not fit in u64")
    for value, name in (
        (word_00, "word +0x00"), (cursor, "cursor"),
        (word_08, "word +0x08"),
        (resource_units, "resource units"),
        (word_10, "word +0x10"), (word_54, "word +0x54"),
        (word_60, "word +0x60"),
    ):
        if not 0 <= int(value) < (1 << 32):
            raise ValueError("opcode-0x20 %s does not fit in u32" % name)
    if resource_units >= 1 << 24:
        raise ValueError("opcode-0x20 resource units do not fit at bit 40")

    data = bytearray(0x4000)
    struct.pack_into("<I", data, 0x00, int(word_00))
    struct.pack_into("<I", data, 0x08, int(word_08))
    struct.pack_into("<I", data, 0x10, int(word_10))
    struct.pack_into("<I", data, 0x14, buffer_address & 0xFFFFFFFF)
    struct.pack_into(
        "<Q",
        data,
        0x18,
        0x0008000000000000 | (buffer_address >> 32),
    )
    resource = resource_units << 40
    struct.pack_into("<Q", data, 0x20, resource)
    struct.pack_into("<Q", data, 0x28, resource)
    struct.pack_into("<Q", data, 0x30, tagged_address)
    struct.pack_into("<I", data, 0x48, cursor)
    struct.pack_into("<Q", data, 0x4C, state_address)
    struct.pack_into("<I", data, 0x54, int(word_54))
    struct.pack_into("<I", data, 0x60, int(word_60))
    return bytes(data)


def decode_slot_word_14(value):
    """Split the two established portions of ring-slot u32 +0x14."""
    return {
        "limit": value & RING_SLOT_LIMIT_MASK,
        "queue_index": (
            value >> RING_SLOT_QUEUE_INDEX_SHIFT
        ) & RING_SLOT_QUEUE_INDEX_MASK,
        "unresolved_bits": value & ~(
            RING_SLOT_LIMIT_MASK
            | (RING_SLOT_QUEUE_INDEX_MASK << RING_SLOT_QUEUE_INDEX_SHIFT)
        ),
    }


def parse_ring_slot(data):
    """Decode one observed 0x18-byte numeric channel-ring slot."""
    _require_size(data, RING_SLOT_SIZE, "ring slot")
    zero, queue_address, word_10, word_14 = struct.unpack("<QQII", data)
    return {
        "word_00": zero,
        "queue_address": queue_address,
        "word_10": word_10,
        "word_14": word_14,
        **decode_slot_word_14(word_14),
        "all_zero": not any(data),
    }


def build_ring_slot(queue_address, word_10, word_14, word_00=0):
    """Build one complete observed 0x18-byte numeric channel-ring slot."""
    values = (word_00, queue_address)
    if any(not 0 <= value < (1 << 64) for value in values):
        raise ValueError("ring-slot qword does not fit in u64")
    if not 0 <= word_10 < (1 << 32) or not 0 <= word_14 < (1 << 32):
        raise ValueError("ring-slot word does not fit in u32")
    return struct.pack("<QQII", word_00, queue_address, word_10, word_14)


def parse_queue_record(data):
    """Decode only established fields in one exact-stride queue record."""
    _require_size(data, QUEUE_RECORD_SIZE, "queue record")
    return {
        "pointer_block_address": struct.unpack_from(
            "<Q", data, QUEUE_POINTER_BLOCK_ADDRESS_OFFSET
        )[0],
        "item_ring_address": struct.unpack_from(
            "<Q", data, QUEUE_ITEM_RING_ADDRESS_OFFSET
        )[0],
        "address_10": struct.unpack_from(
            "<Q", data, QUEUE_ADDRESS_10_OFFSET
        )[0],
        "limit_1c": struct.unpack_from(
            "<I", data, QUEUE_LIMIT_OFFSET
        )[0],
        "word_20": struct.unpack_from(
            "<Q", data, QUEUE_WORD_20_OFFSET
        )[0],
        "word_28": struct.unpack_from(
            "<Q", data, QUEUE_WORD_28_OFFSET
        )[0],
        "word_30": struct.unpack_from(
            "<Q", data, QUEUE_WORD_30_OFFSET
        )[0],
        "word_38": struct.unpack_from(
            "<Q", data, QUEUE_WORD_38_OFFSET
        )[0],
        "word_40": struct.unpack_from(
            "<Q", data, QUEUE_WORD_40_OFFSET
        )[0],
        "accumulator_68": struct.unpack_from(
            "<Q", data, QUEUE_ACCUMULATOR_OFFSET
        )[0],
        "address_70": struct.unpack_from(
            "<Q", data, QUEUE_ADDRESS_70_OFFSET
        )[0],
    }


def build_queue_record(
    pointer_block_address,
    item_ring_address,
    address_10,
    address_70,
    *,
    limit_1c=0,
    word_20=0xFFFFFFFF00000000,
    word_28=0,
    word_30=0xFFFFFFFFFFFF0000,
    word_38=0x100000001,
    word_40=0,
    accumulator_68=0,
):
    """Build the complete exact-stride numeric queue record.

    The four ``word_*`` fields keep numeric names because their semantics are
    unresolved.  Requiring callers to supply the boot-varying ``word_40``
    makes that uncertainty explicit instead of hiding captured template bytes.
    """
    qwords = (
        pointer_block_address, item_ring_address, address_10,
        word_20, word_28, word_30, word_38, word_40, accumulator_68,
        address_70,
    )
    if any(not 0 <= value < (1 << 64) for value in qwords):
        raise ValueError("queue-record qword does not fit in u64")
    if not 0 <= limit_1c < (1 << 32):
        raise ValueError("queue-record limit does not fit in u32")
    data = bytearray(QUEUE_RECORD_SIZE)
    for offset, value in (
        (QUEUE_POINTER_BLOCK_ADDRESS_OFFSET, pointer_block_address),
        (QUEUE_ITEM_RING_ADDRESS_OFFSET, item_ring_address),
        (QUEUE_ADDRESS_10_OFFSET, address_10),
        (QUEUE_WORD_20_OFFSET, word_20),
        (QUEUE_WORD_28_OFFSET, word_28),
        (QUEUE_WORD_30_OFFSET, word_30),
        (QUEUE_WORD_38_OFFSET, word_38),
        (QUEUE_WORD_40_OFFSET, word_40),
        (QUEUE_ACCUMULATOR_OFFSET, accumulator_68),
        (QUEUE_ADDRESS_70_OFFSET, address_70),
    ):
        struct.pack_into("<Q", data, offset, value)
    struct.pack_into("<I", data, QUEUE_LIMIT_OFFSET, limit_1c)
    return bytes(data)


def queue_priority_profile(priority):
    """Return the coherent five-field G17G queue-priority profile."""
    try:
        values = QUEUE_PRIORITY_PROFILES[int(priority)]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("G17G queue priority must be in 0..3") from exc
    return {
        "priority": values[0],
        "mirror": values[1],
        "mask": values[2],
        "mode": values[3],
        "selector": values[4],
    }


def uapi_queue_priority_profile(priority):
    """Translate a public LOW/MEDIUM priority to its firmware profile."""
    try:
        firmware_priority = UAPI_QUEUE_PRIORITY_TO_FIRMWARE[int(priority)]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "G17G UAPI queue priority must be LOW (0) or MEDIUM (1)"
        ) from exc
    profile = queue_priority_profile(firmware_priority)
    profile.update({
        "uapi_priority": int(priority),
        "firmware_priority": firmware_priority,
    })
    return profile


def apply_queue_priority(record, priority):
    """Return one queue record with only its coherent priority family set."""
    _require_size(record, QUEUE_RECORD_SIZE, "queue record")
    data = bytearray(record)
    profile = queue_priority_profile(priority)
    struct.pack_into("<I", data, QUEUE_PRIORITY_OFFSET, profile["priority"])
    struct.pack_into(
        "<I", data, QUEUE_PRIORITY_MIRROR_OFFSET, profile["mirror"]
    )
    struct.pack_into("<Q", data, QUEUE_PRIORITY_MASK_OFFSET, profile["mask"])
    struct.pack_into("<I", data, QUEUE_PRIORITY_MODE_OFFSET, profile["mode"])
    struct.pack_into(
        "<I", data, QUEUE_PRIORITY_SELECTOR_OFFSET, profile["selector"]
    )
    return bytes(data)


def queue_priority_write(address, priority):
    """Retarget only the five-field family at a retired queue boundary."""
    body = apply_queue_priority(bytes(QUEUE_RECORD_SIZE), priority)
    return address + QUEUE_PRIORITY_OFFSET, body[QUEUE_PRIORITY_OFFSET:0x40]


def parse_queue_priority(record):
    """Decode and validate the complete priority family in a queue record."""
    _require_size(record, QUEUE_RECORD_SIZE, "queue record")
    observed = (
        struct.unpack_from("<I", record, QUEUE_PRIORITY_OFFSET)[0],
        struct.unpack_from("<I", record, QUEUE_PRIORITY_MIRROR_OFFSET)[0],
        struct.unpack_from("<Q", record, QUEUE_PRIORITY_MASK_OFFSET)[0],
        struct.unpack_from("<I", record, QUEUE_PRIORITY_MODE_OFFSET)[0],
        struct.unpack_from("<I", record, QUEUE_PRIORITY_SELECTOR_OFFSET)[0],
    )
    matches = [
        priority for priority, profile in QUEUE_PRIORITY_PROFILES.items()
        if profile == observed
    ]
    return {
        "priority": matches[0] if len(matches) == 1 else None,
        "fields": observed,
        "coherent": len(matches) == 1,
    }


def parse_pointer_block(data):
    """Decode the five numeric fields in the observed 0x68-byte prefix."""
    _require_size(data, POINTER_BLOCK_OBSERVED_SIZE, "pointer-block prefix")
    return {
        "field_00": struct.unpack_from("<I", data, POINTER_FIELD_00)[0],
        "field_30": struct.unpack_from("<I", data, POINTER_FIELD_30)[0],
        "field_40": struct.unpack_from("<I", data, POINTER_FIELD_40)[0],
        "field_50": struct.unpack_from("<I", data, POINTER_FIELD_50)[0],
        "field_60": struct.unpack_from("<I", data, POINTER_FIELD_60)[0],
    }


def build_pointer_block(
    field_00=0, field_30=0, field_40=0,
    field_50=0xFFFFFFFF, field_60=0x500,
):
    """Build the complete observed 0x68-byte pointer/index-block prefix."""
    values = (field_00, field_30, field_40, field_50, field_60)
    if any(not 0 <= value < (1 << 32) for value in values):
        raise ValueError("pointer-block field does not fit in u32")
    data = bytearray(POINTER_BLOCK_OBSERVED_SIZE)
    for offset, value in zip(
        (POINTER_FIELD_00, POINTER_FIELD_30, POINTER_FIELD_40,
         POINTER_FIELD_50, POINTER_FIELD_60),
        values,
    ):
        struct.pack_into("<I", data, offset, value)
    return bytes(data)


def parse_item_header(data):
    """Decode the common numeric header of a selector-0 or selector-1 item."""
    if len(data) < 0x10:
        raise ValueError("item header requires at least 0x10 bytes")
    selector = struct.unpack_from("<I", data, ITEM_SELECTOR_OFFSET)[0]
    if selector not in (SELECTOR_0, SELECTOR_1):
        raise ValueError("item does not have numeric selector 0 or 1")
    return {
        "selector": selector,
        "sequence": struct.unpack_from("<Q", data, ITEM_SEQUENCE_OFFSET)[0],
        "context": struct.unpack_from("<I", data, ITEM_CONTEXT_OFFSET)[0],
    }


def build_item_header(selector, sequence, context=1):
    """Build the exact 0x10-byte numeric selector-0/1 header.

    This is deliberately a header builder rather than a complete work-item
    constructor: the remainder of both records still contains unresolved
    fields.
    """
    if selector not in (SELECTOR_0, SELECTOR_1):
        raise ValueError("numeric item header selector must be 0 or 1")
    if not 0 <= sequence < (1 << 64):
        raise ValueError("numeric item sequence does not fit in u64")
    if not 0 <= context < (1 << 32):
        raise ValueError("numeric item context does not fit in u32")
    return struct.pack("<IQI", selector, sequence, context)


def _read_u40(data, offset):
    end = offset + ITEM_ENDPOINT_WIDTH
    if end > len(data):
        raise ValueError("40-bit endpoint lies outside item capture")
    return int.from_bytes(data[offset:end], "little")


def parse_item_endpoints(data, require_repeated=False):
    """Decode the two observed copies of a selector-0/1 endpoint pair."""
    header = parse_item_header(data)
    expected_size = ITEM_RECORD_SIZE[header["selector"]]
    _require_size(data, expected_size, "selector item")
    copies = tuple(
        tuple(_read_u40(data, offset) for offset in pair)
        for pair in ITEM_ENDPOINT_OFFSETS[header["selector"]]
    )
    repeated = copies[0] == copies[1]
    if require_repeated and not repeated:
        raise ValueError("the two observed 40-bit endpoint copies disagree")
    endpoint_a, endpoint_b = copies[0]
    return {
        **header,
        "copies": copies,
        "repeated": repeated,
        "endpoint_a": endpoint_a,
        "endpoint_b": endpoint_b,
        "difference": endpoint_b - endpoint_a,
    }


def parse_selector_14(data):
    """Decode the four observed u32 values in a selector-14 record."""
    _require_size(data, ITEM_RECORD_SIZE[SELECTOR_14], "selector-14 record")
    selector, word_04, word_08 = struct.unpack_from("<3I", data, 0)
    if selector != SELECTOR_14:
        raise ValueError("item does not have numeric selector 14")
    return {
        "selector": selector,
        "word_04": word_04,
        "word_08": word_08,
        "word_10": struct.unpack_from("<I", data, SELECTOR_14_WORD_10)[0],
    }


def build_selector_14(channel_index, group_number):
    """Build the complete 0x40-byte selector-14 record seen natively.

    ``channel_index`` is limited to the two numeric work channels and
    ``group_number`` is one-based, matching the three observed native groups.
    No semantic role is assigned to any of the four populated words.
    """
    if channel_index not in (0, 1):
        raise ValueError("selector-14 numeric channel must be 0 or 1")
    if not 1 <= group_number < (1 << 24):
        raise ValueError("selector-14 group number does not fit observed word")
    data = bytearray(ITEM_RECORD_SIZE[SELECTOR_14])
    struct.pack_into("<I", data, SELECTOR_14_WORD_00, SELECTOR_14)
    struct.pack_into(
        "<I", data, SELECTOR_14_WORD_04, 0x10000 | channel_index
    )
    struct.pack_into("<I", data, SELECTOR_14_WORD_08, group_number << 8)
    struct.pack_into("<I", data, SELECTOR_14_WORD_10, channel_index << 8)
    return bytes(data)


def parse_target_record_40(data, require_observed_shape=False):
    """Decode the two numeric qwords in an observed 0x40 target record."""
    _require_size(data, TARGET_RECORD_40_SIZE, "target record 0x40")
    word_00 = struct.unpack_from("<Q", data, TARGET_RECORD_40_WORD_00)[0]
    word_10 = struct.unpack_from("<Q", data, TARGET_RECORD_40_WORD_10)[0]
    remainder = bytearray(data)
    remainder[TARGET_RECORD_40_WORD_00:TARGET_RECORD_40_WORD_00 + 8] = b"\0" * 8
    remainder[TARGET_RECORD_40_WORD_10:TARGET_RECORD_40_WORD_10 + 8] = b"\0" * 8
    if require_observed_shape and (word_00 != word_10 or any(remainder)):
        raise ValueError("target record 0x40 differs from observed shape")
    return {
        "word_00": word_00,
        "word_10": word_10,
        "words_equal": word_00 == word_10,
        "other_bytes_all_zero": not any(remainder),
        "all_zero": not any(data),
    }


def build_target_record_40(value=0):
    """Build the complete observed 0x40 numeric target-record shape."""
    if not 0 <= value < (1 << 64):
        raise ValueError("target-record value does not fit in u64")
    data = bytearray(TARGET_RECORD_40_SIZE)
    struct.pack_into("<Q", data, TARGET_RECORD_40_WORD_00, value)
    struct.pack_into("<Q", data, TARGET_RECORD_40_WORD_10, value)
    return bytes(data)


def parse_target_record_80(data):
    """Decode the six populated qwords in an observed 0x80 target record."""
    _require_size(data, TARGET_RECORD_80_SIZE, "target record 0x80")
    offsets = (
        TARGET_RECORD_80_WORD_00,
        TARGET_RECORD_80_ADDRESS_08,
        TARGET_RECORD_80_WORD_10,
        TARGET_RECORD_80_WORD_28,
        TARGET_RECORD_80_ADDRESS_40,
        TARGET_RECORD_80_WORD_48,
    )
    fields = {
        "word_%02x" % offset: struct.unpack_from("<Q", data, offset)[0]
        for offset in offsets
    }
    remainder = bytearray(data)
    for offset in offsets:
        remainder[offset:offset + 8] = b"\0" * 8
    fields["other_bytes_all_zero"] = not any(remainder)
    return fields


def build_target_record_80(
    word_00, address_08, word_28, address_40, word_48=1 << 32,
    word_10=0,
):
    """Build the complete observed 0x80 numeric target-record shape."""
    values = (
        (TARGET_RECORD_80_WORD_00, word_00),
        (TARGET_RECORD_80_ADDRESS_08, address_08),
        (TARGET_RECORD_80_WORD_10, word_10),
        (TARGET_RECORD_80_WORD_28, word_28),
        (TARGET_RECORD_80_ADDRESS_40, address_40),
        (TARGET_RECORD_80_WORD_48, word_48),
    )
    if any(not 0 <= value < (1 << 64) for _offset, value in values):
        raise ValueError("target-record field does not fit in u64")
    data = bytearray(TARGET_RECORD_80_SIZE)
    for offset, value in values:
        struct.pack_into("<Q", data, offset, value)
    return bytes(data)


def validate_consumption_arithmetic(queue_before, queue_after, item_after):
    """Validate the exact two-run relation without assigning semantics.

    Returns the parsed records if queue +0x68 advanced by the endpoint
    difference and queue +0x1c did not move backwards.
    """
    before = parse_queue_record(queue_before)
    after = parse_queue_record(queue_after)
    endpoints = parse_item_endpoints(item_after)
    if endpoints["copies"][1] not in ((0, 0), endpoints["copies"][0]):
        raise ValueError(
            "second 40-bit endpoint copy is neither zero nor identical"
        )
    if endpoints["difference"] < 0:
        raise ValueError("40-bit endpoint B precedes endpoint A")
    if (
        after["accumulator_68"]
        != before["accumulator_68"] + endpoints["difference"]
    ):
        raise ValueError("queue +0x68 arithmetic relation does not hold")
    if after["limit_1c"] < before["limit_1c"]:
        raise ValueError("queue +0x1c moved backwards")
    return {
        "queue_before": before,
        "queue_after": after,
        "endpoints": endpoints,
    }
