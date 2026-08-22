# SPDX-License-Identifier: MIT
"""Build a T8140/G17P submission's object graph from the decoded model.

This is the piece ``g17p_backend`` says it does not do: it constructs the memory a
work item describes, rather than taking addresses a caller found in a capture. Every
structure here is recorded in ``docs/t8140-g17p-firmware-abi-spec.md`` and was measured
from a capture of a working host, with the record arrays checked by regenerating them
byte for byte.

What is built, and what a caller still supplies.

Built from nothing: the two record arrays, because every non-zero word in a record is
known and the rest is zero, so no captured template is needed; the register array,
from a caller's sequence of register number/value pairs; and the descriptor's common
selector, submit sequence, context ID, and pointer block.

Supplied by the caller: the register values themselves, and the render-context
addresses they contain. Those live in a different translation context from everything
firmware reads, which is the caller's to allocate in.

Not built: the descriptor's remaining kind-specific fields outside the pointer block
and register array. A caller wanting to reproduce a captured submission exactly must
still supply those.

The register names this model uses are borrowed from the M1 and M2 backend by way of
a ninety-nine number overlap. They are unconfirmed on this part, and cannot be
confirmed until something observable is rendered, so nothing here depends on a name
being right; the numbers are passed through as given.
"""

import struct

# Deliberately no other imports. The version-dependent construct definitions in the
# rest of this package raise when a version key is unset, which makes them unusable
# from tools that do not set one, and this model needs nothing from them: every
# structure here is plain bytes at measured offsets. Keeping it dependency-free is what
# lets the replay harness build a descriptor without pulling that chain in.

# A register array entry, matching the M1 and M2 backend's RegisterDefinition: a
# 32-bit number then a 64-bit value, twelve bytes, uniform across the array.
REGISTER_ENTRY_SIZE = 0xc
REGISTER_ARRAY_LIMIT = 128

# Where each descriptor kind puts things. Both carry the same four addresses in the
# same order. The starts were checked over ten consecutive live descriptors; +0x60
# and +0xa0 are register definitions, not trailing header bytes.
DESCRIPTOR_LAYOUT = {
    "tiling": {"pointers": 0x10, "registers": 0x60, "pointer_gap": 0x08},
    "fragment": {"pointers": 0x20, "registers": 0xa0, "pointer_gap": 0x00},
}

# The first word selects which descriptor layout firmware parses. Leaving a fragment
# descriptor zero made firmware parse its pointer block as geometry and fault on a
# required pointer; setting only this word to one made the same descriptor execute and
# reproduce the native render-page writes.
DESCRIPTOR_SELECTOR = {"tiling": 0x00, "fragment": 0x01}

# Descriptor scheduling metadata. The pair fields identify the queue grid, while
# the work field and stamps follow a separate sequence. The first seven valid
# native records carry 0, 1, 3, 4, 6, 7, 9: every two global submissions reserve
# one additional value outside this descriptor stream.
DESCRIPTOR_ORDINAL_FIELDS = {
    "tiling": {
        "pair": (0x18, 0x304),
        "work": (0x48,),
        "stamps": (0x370, 0x37c, 0x388),
    },
    "fragment": {
        "pair": (0x458,),
        "work": (),
        "stamps": (0x470, 0x47c),
    },
}
DESCRIPTOR_STAMP_BASE = 0x100


def descriptor_work_ordinal(submission_ordinal):
    return submission_ordinal + submission_ordinal // 2

# Both descriptor kinds draw from one submit sequence. In every captured pair the
# fragment item has the even value and the matching tiling item the following odd
# value. The field is 64 bits; the context ID immediately follows it.
SUBMIT_SEQUENCE_OFFSET = 0x04
CONTEXT_ID_OFFSET = 0x0c
SUBMIT_SEQUENCE_BASE = {"tiling": 1, "fragment": 0}
SUBMIT_SEQUENCE_STEP = 2

# The first record array: 35 records of 0x100, each holding one device address that
# advances by four, and a marker in the first record only.
ARRAY_A_RECORDS = 35
ARRAY_A_STRIDE = 0x100
ARRAY_A_SLOT_STEP = 4
ARRAY_A_FIRST_MARKER_OFFSET = 0x10
ARRAY_A_FIRST_MARKER = 0x50

# The second: 79 records of 0x80, two advancing fields, a constant, a cycle of 36 and
# a marker in the first record only.
ARRAY_B_RECORDS = 79
ARRAY_B_STRIDE = 0x80
ARRAY_B_INDEX_BASE = 0x80004
ARRAY_B_PAIR_INDEX_STEP = 0x140
ARRAY_B_CONSTANT_OFFSET = 0x04
ARRAY_B_CONSTANT = 0x10
ARRAY_B_SLOT_OFFSET = 0x08
ARRAY_B_CYCLE_OFFSET = 0x28
ARRAY_B_CYCLE_BASE = 0x178020
ARRAY_B_CYCLE_STEP = 0x20
ARRAY_B_CYCLE_LENGTH = 36
ARRAY_B_CYCLE_WRAP = 0x178000
ARRAY_B_PAIR_CYCLE_STEP = 0x5e0000
ARRAY_B_SHARED_OFFSET = 0x40
ARRAY_B_FIRST_MARKER_OFFSET = 0x4c
ARRAY_B_FIRST_MARKER = 1


def wrap_pool_record_indices(index_a, index_b):
    """Map monotonically allocated record numbers onto the two finite pools."""
    if index_a < 0 or index_b < 0:
        raise ValueError("pool record indices must be non-negative")
    return index_a % ARRAY_A_RECORDS, index_b % ARRAY_B_RECORDS


def paired_item_pool_record_indices(index, record_indices=None):
    """Select one paired item's physical Pool-A and Pool-B records.

    The paired queue advances Pool A twice and Pool B once per logical item.
    Keep this selection in one helper so descriptor construction and the
    scheduler lifecycle publication wrap at exactly the same boundary.
    """
    if record_indices is None:
        record_indices = (2 * index, index)
    return wrap_pool_record_indices(*record_indices)

# The two small objects shared by both descriptor halves. The first is packed and
# ends with a u32 at +0x84, so its constructible extent is 0x88 even though its last
# nonzero byte is at +0x86. The other object is all zero at handover; 0x100 bytes
# covers the extent compared in the capture and leaves space for firmware use.
SHARED_OBJECT_SIZE = 0x88
SHARED_OBJECT_POINTER_OFFSETS = (0x20, 0x44, 0x4c, 0x64)
SHARED_OBJECT_U32 = {
    0x28: 0x00190000,
    0x2c: 0x00000010,
    0x30: 0x00010000,
    0x34: 0x00000080,
    0x38: 0x00000c18,
    0x3c: 0x00000020,
    0x54: 0x0000007f,
    0x58: 0x00020000,
    0x7c: 0x00003060,
    0x80: 0x00001020,
    0x84: 0x00180000,
}
SHARED_OBJECT_PAIR_INDEX_OFFSET = 0x0c
SHARED_OBJECT_INDEX_PAIR_STEP = 0x5e
ZERO_SHARED_OBJECT_SIZE = 0x100

# Six leaf pages are named by the pools and packed shared object. Two hold one
# partition of the same 160 numeric values: 32 group bases, and four consecutive
# values from every group. The remaining pages have only the listed initial words.
FIRMWARE_PAGE_SIZE = 0x4000
INDEX_GROUP_RANGES = ((0x11, 6), (0x4a, 26))
INDEX_GROUP_PAIR_STEP = 0xbc
POOL_A_SLOT_OFFSET = 0x04
POOL_B_SLOT_OFFSET = 0x04
SHARED_SLOT_OFFSET = 0x40

# A partial render's render context contains a GPU-page directory for the
# buffers registered through device-control opcode 0x20.  The table points at
# 28 one-megabyte buffers on a 0x108000 stride.  The directory then enumerates
# each buffer as 256 4-KiB accelerator pages, omitting the 0x8000 gap between
# adjacent buffers.  Four 16-KiB host pages hold the resulting 7,168 qwords;
# the unused tail of the fourth page is zero.
PARTIAL_OPERAND_BUFFER_COUNT = 28
PARTIAL_OPERAND_BUFFER_SIZE = 0x100000
PARTIAL_OPERAND_BUFFER_STRIDE = 0x108000
PARTIAL_OPERAND_GPU_PAGE_SIZE = 0x1000
PARTIAL_OPERAND_TABLE_ENTRY_STRIDE = 0x40
PARTIAL_OPERAND_TABLE_FLAG = 1 << 60

# Selector-0x0f records used by the native first paired submission. They are packed:
# three firmware addresses are not naturally aligned. Every nonzero scalar in the
# host-written first record is enumerated here; later records receive firmware output
# and are not templates for construction.
OPTIONAL_ITEM_SIZE = 0xc0
OPTIONAL_ITEM_SELECTOR = 0x0f
OPTIONAL_ITEM_POINTER_OFFSETS = {
    "context_scratch": 0x08,
    "firmware_scratch": 0x10,
    "shared_control": 0x36,
    "channel_control": 0x4a,
    "tiling_shared_object": 0x6e,
}
OPTIONAL_ITEM_U16 = {
    "tiling": {
        0x1a: 1,
        0x26: 1,
        0x32: 1,
        0x52: 1,
        0x5a: 0x00a6,
        0x5e: 1,
        0x62: 1,
        0x66: 1,
        0x82: 1,
    },
    "fragment": {
        0x18: 1,
        0x1a: 1,
        0x22: 1,
        0x26: 1,
        0x32: 1,
        0x52: 1,
        0x5a: 0x00a6,
        0x5e: 1,
        0x62: 1,
        0x66: 1,
    },
}
OPTIONAL_FRAGMENT_SENTINEL_OFFSET = 0x76
OPTIONAL_FRAGMENT_SENTINEL_SIZE = 0x10

# A queue pair has one context page per stage, visible through a low render-context
# address and a high firmware-context alias. The second native pair proves these are
# per-pair objects and that several words encode pair-local state; they are not fixed
# copies of pair zero. Pair one is recorded explicitly until more pairs establish the
# encoding rather than extrapolating bitfields from one delta.
QUEUE_CONTEXT_DESCRIPTOR_OFFSET = 0x210
QUEUE_CONTEXT_QUEUE_OFFSET = 0x218
QUEUE_CONTEXT_ITEM_BASE = 0x200
QUEUE_CONTEXT_ITEM_STRIDE = 0x200
QUEUE_CONTEXT_ITEM_SIZE = 0x180
QUEUE_CONTEXT_WORDS = {
    "tiling": (
        (0x200, 0x0000000000000004),
        (0x220, 0xffff0c0000000001),
        (0x350, 0x0002380380000003),
        (0x378, 0x003fffffffffffff),
    ),
    "fragment": (
        (0x200, 0x0400040000000004),
        (0x208, 0x004000e000130d40),
        (0x220, 0xffff180000000003),
        (0x228, 0x0000000000000001),
        (0x230, 0x0000010000000000),
        (0x350, 0x0002b00380004c05),
        (0x358, 0x0000100380004c3e),
        (0x360, 0x0000100380004c77),
        (0x368, 0x0000100380004cb0),
        (0x378, 0x003fffffffffffff),
    ),
}
QUEUE_CONTEXT_PAIR_WORDS = {
    1: {
        "tiling": (
            (0x200, 0x0000080000000004),
            (0x220, 0xffff0c0100000001),
            (0x228, 0x0000020000000000),
            (0x350, 0x0002380380000051),
        ),
        "fragment": (
            (0x200, 0x04000c0000000004),
            (0x208, 0x004000e0001351c0),
            (0x220, 0xffff180100000003),
            (0x228, 0x0000020000000001),
            (0x230, 0x0000030000000000),
            (0x350, 0x0002b00380004d17),
            (0x358, 0x0000100380004d50),
            (0x360, 0x0000100380004d89),
            (0x368, 0x0000100380004dc2),
        ),
    },
}

QUEUE_CONTEXT_ITEM_INCREMENTS = {
    "tiling": {
        0x200: 0x4,
        0x228: 0x1,
        0x350: 0x9c,
    },
    "fragment": {
        0x200: 0x4,
        0x208: 0x8900,
        0x228: 0x1,
        0x230: 0x1,
        0x350: 0x224,
        0x358: 0x224,
        0x360: 0x224,
        0x368: 0x224,
    },
}

# Event items are 0x40-byte records. The host writes only the first, but firmware
# appends records through at least +0x3d2, so reserve the measured 0x400-byte extent.
EVENT_ITEM_SIZE = 0x400
EVENT_RECORD_SIZE = 0x40
EVENT_SELECTOR = 0x0e
EVENT_COUNTER_SHIFT = 8


def build_event_record(group_number, subtype, unk_10=0):
    """Build the host-written first 0x40-byte event record."""
    out = bytearray(EVENT_RECORD_SIZE)
    struct.pack_into("<I", out, 0x00, EVENT_SELECTOR)
    struct.pack_into("<I", out, 0x04, subtype)
    struct.pack_into("<I", out, 0x08, group_number << EVENT_COUNTER_SHIFT)
    struct.pack_into("<I", out, 0x10, unk_10)
    return bytes(out)


def build_record_array_a(slot_base):
    """The 35-record array, from nothing.

    ``slot_base`` is the address of the first record's four-byte slot; each later
    record names the next one along. Every other byte of a record is zero, which is
    why no template is needed.
    """
    out = bytearray(ARRAY_A_RECORDS * ARRAY_A_STRIDE)
    for index in range(ARRAY_A_RECORDS):
        base = index * ARRAY_A_STRIDE
        struct.pack_into("<Q", out, base,
                         slot_base + index * ARRAY_A_SLOT_STEP)
        if index == 0:
            struct.pack_into("<I", out, base + ARRAY_A_FIRST_MARKER_OFFSET,
                             ARRAY_A_FIRST_MARKER)
    return bytes(out)


def build_record_array_b(slot_base, shared_addr, pair_index=0):
    """The 79-record array, from nothing.

    ``slot_base`` advances by four a record as in the other array. ``shared_addr`` is
    one address every record carries unchanged. Later queue pairs continue both the
    record-index and cycle namespaces measured in native submissions.
    """
    out = bytearray(ARRAY_B_RECORDS * ARRAY_B_STRIDE)
    for index in range(ARRAY_B_RECORDS):
        base = index * ARRAY_B_STRIDE
        pair_index_delta = pair_index * ARRAY_B_PAIR_INDEX_STEP
        pair_cycle_delta = pair_index * ARRAY_B_PAIR_CYCLE_STEP
        struct.pack_into("<I", out, base,
                         ARRAY_B_INDEX_BASE + pair_index_delta
                         + index * ARRAY_A_SLOT_STEP)
        struct.pack_into("<I", out, base + ARRAY_B_CONSTANT_OFFSET,
                         ARRAY_B_CONSTANT)
        struct.pack_into("<Q", out, base + ARRAY_B_SLOT_OFFSET,
                         slot_base + pair_index_delta
                         + index * ARRAY_A_SLOT_STEP)
        phase = index % ARRAY_B_CYCLE_LENGTH
        cycle = (ARRAY_B_CYCLE_WRAP
                 if phase == ARRAY_B_CYCLE_LENGTH - 1
                 else ARRAY_B_CYCLE_BASE + ARRAY_B_CYCLE_STEP * phase)
        struct.pack_into("<I", out, base + ARRAY_B_CYCLE_OFFSET,
                         cycle + pair_cycle_delta)
        struct.pack_into("<Q", out, base + ARRAY_B_SHARED_OFFSET, shared_addr)
        if index == 0:
            struct.pack_into("<I", out, base + ARRAY_B_FIRST_MARKER_OFFSET,
                             ARRAY_B_FIRST_MARKER)
    return bytes(out)


def build_shared_object(addresses, pair_index=0, group_count=0x20):
    """Build the packed second object named by both descriptor halves."""
    if len(addresses) != len(SHARED_OBJECT_POINTER_OFFSETS):
        raise ValueError("shared object names four addresses")
    if pair_index < 0:
        raise ValueError("queue pair must be non-negative")
    group_count = int(group_count)
    if not 0 < group_count <= 0x20:
        raise ValueError("shared object group count must be in 1..32")
    out = bytearray(SHARED_OBJECT_SIZE)
    for offset, address in zip(SHARED_OBJECT_POINTER_OFFSETS, addresses):
        struct.pack_into("<Q", out, offset, address)
    for offset, value in SHARED_OBJECT_U32.items():
        struct.pack_into("<I", out, offset, value)
    struct.pack_into("<I", out, SHARED_OBJECT_PAIR_INDEX_OFFSET, pair_index)
    # The bootstrap pair carries 16 index groups while created pairs carry 32.
    # These three fields scale directly with that measured group inventory.
    struct.pack_into("<I", out, 0x34, group_count * 4)
    struct.pack_into("<I", out, 0x3c, group_count)
    struct.pack_into("<I", out, 0x54, group_count * 4 - 1)
    index_delta = pair_index * SHARED_OBJECT_INDEX_PAIR_STEP << 16
    for offset in (0x28, 0x84):
        value = struct.unpack_from("<I", out, offset)[0]
        struct.pack_into("<I", out, offset, value + index_delta)
    return bytes(out)


def build_context2_shared_object(addresses, context_id=2):
    """Build context 2's packed descriptor object from explicit leaf pointers."""
    out = bytearray(build_shared_object(addresses, pair_index=0))
    struct.pack_into("<I", out, SHARED_OBJECT_PAIR_INDEX_OFFSET, int(context_id))
    for offset, value in ((0x34, 0x20), (0x3c, 8), (0x54, 0x1f)):
        struct.pack_into("<I", out, offset, value)
    return bytes(out)


def build_zero_shared_object():
    """Build the fourth descriptor object as observed before first work."""
    return bytes(ZERO_SHARED_OBJECT_SIZE)


def _index_group_bases(pair_index=0, index_group_ranges=None):
    if pair_index < 0:
        raise ValueError("queue pair must be non-negative")
    ranges = (INDEX_GROUP_RANGES if index_group_ranges is None
              else tuple(index_group_ranges))
    delta = pair_index * INDEX_GROUP_PAIR_STEP
    return [
        start + delta + group * 5
        for start, groups in ranges
        for group in range(groups)
    ]


def build_submission_leaf_pages(pair_index=0, index_group_ranges=None,
                                shared_count=0x20):
    """Build the six pages directly named by pools and shared object."""
    primary = bytearray(FIRMWARE_PAGE_SIZE)
    secondary = bytearray(FIRMWARE_PAGE_SIZE)
    for index, base in enumerate(_index_group_bases(
            pair_index, index_group_ranges=index_group_ranges)):
        for member in range(4):
            struct.pack_into("<I", primary, (index * 4 + member) * 4,
                             base + member)
        struct.pack_into("<Q", secondary, index * 8, base)

    pool_a_slots = bytearray(FIRMWARE_PAGE_SIZE)
    struct.pack_into("<I", pool_a_slots, POOL_A_SLOT_OFFSET, 2)
    pool_b_slots = bytearray(FIRMWARE_PAGE_SIZE)

    shared_slots = bytearray(FIRMWARE_PAGE_SIZE)
    struct.pack_into("<I", shared_slots, 0x00, int(shared_count))
    struct.pack_into("<I", shared_slots, 0x04, int(shared_count))
    struct.pack_into("<I", shared_slots, 0x60, 1)

    flag = bytearray(FIRMWARE_PAGE_SIZE)
    struct.pack_into("<I", flag, 0x00, 1)
    return {
        "primary_index": bytes(primary),
        "secondary_index": bytes(secondary),
        "pool_a_slots": bytes(pool_a_slots),
        "pool_b_slots": bytes(pool_b_slots),
        "shared_slots": bytes(shared_slots),
        "flag": bytes(flag),
    }


def build_context2_submission_leaf_pages():
    """Build the smaller index/slot graph owned by native render context 2."""
    return build_submission_leaf_pages(
        pair_index=0,
        index_group_ranges=((0x11, 6), (0x3c, 2)),
        shared_count=8,
    )


def build_partial_operand_table(buffer_base,
                                buffer_count=PARTIAL_OPERAND_BUFFER_COUNT):
    """Build the render-root operand table registered by opcode 0x20."""
    if buffer_count < 0:
        raise ValueError("operand buffer count must not be negative")
    if buffer_count * PARTIAL_OPERAND_TABLE_ENTRY_STRIDE > FIRMWARE_PAGE_SIZE:
        raise ValueError("operand table does not fit one firmware page")
    table = bytearray(FIRMWARE_PAGE_SIZE)
    for index in range(buffer_count):
        struct.pack_into(
            "<Q", table, index * PARTIAL_OPERAND_TABLE_ENTRY_STRIDE,
            (int(buffer_base) + index * PARTIAL_OPERAND_BUFFER_STRIDE)
            | PARTIAL_OPERAND_TABLE_FLAG,
        )
    return bytes(table)


def build_partial_operand_page_directory(
        buffer_base, buffer_count=PARTIAL_OPERAND_BUFFER_COUNT):
    """Build the four-page accelerator-page directory for partial buffers."""
    if buffer_count < 0:
        raise ValueError("operand buffer count must not be negative")
    pages_per_buffer = (
        PARTIAL_OPERAND_BUFFER_SIZE // PARTIAL_OPERAND_GPU_PAGE_SIZE)
    qword_count = buffer_count * pages_per_buffer
    size = ((qword_count * 8 + FIRMWARE_PAGE_SIZE - 1)
            // FIRMWARE_PAGE_SIZE * FIRMWARE_PAGE_SIZE)
    directory = bytearray(size)
    qword = 0
    for buffer_index in range(buffer_count):
        base = (int(buffer_base)
                + buffer_index * PARTIAL_OPERAND_BUFFER_STRIDE)
        for page_index in range(pages_per_buffer):
            struct.pack_into(
                "<Q", directory, qword * 8,
                base + page_index * PARTIAL_OPERAND_GPU_PAGE_SIZE,
            )
            qword += 1
    return bytes(directory)


def build_optional_item(kind, context_scratch, firmware_scratch,
                        shared_control, channel_control,
                        tiling_shared_object=None, grid_index=None,
                        item_index=0, submission_ordinal=0,
                        context_id=None, uuid=None, scheduler_class=None,
                        queue_context_index=None, queue_context_phase=None,
                        first_record=None, lifecycle_ordinal=None,
                        queue_namespace=None, u16_overrides=None):
    """Build the selector-0x0f item paired with a first-work descriptor.

    The pointer names reflect their address spaces and sharing relationships, not
    unverified functional roles. The tiling form carries one additional pointer,
    which equals the descriptor pointer block's second object in every checked pair.
    """
    if kind not in OPTIONAL_ITEM_U16:
        raise ValueError("kind must be one of %s" % sorted(OPTIONAL_ITEM_U16))
    if kind == "tiling" and tiling_shared_object is None:
        raise ValueError("tiling optional item requires its shared object")
    if kind == "fragment" and tiling_shared_object is not None:
        raise ValueError("fragment optional item has no tiling shared object")
    if grid_index is None:
        grid_index = 0 if kind == "tiling" else 1
    pair_index = grid_index // 2

    out = bytearray(OPTIONAL_ITEM_SIZE)
    struct.pack_into("<I", out, 0, OPTIONAL_ITEM_SELECTOR)
    for name, value in (
        ("context_scratch", context_scratch),
        ("firmware_scratch", firmware_scratch),
        ("shared_control", shared_control),
        ("channel_control", channel_control),
    ):
        struct.pack_into("<Q", out, OPTIONAL_ITEM_POINTER_OFFSETS[name], value)
    if kind == "tiling":
        struct.pack_into(
            "<Q", out, OPTIONAL_ITEM_POINTER_OFFSETS["tiling_shared_object"],
            tiling_shared_object)
    else:
        start = OPTIONAL_FRAGMENT_SENTINEL_OFFSET
        out[start:start + OPTIONAL_FRAGMENT_SENTINEL_SIZE] = (
            b"\xff" * OPTIONAL_FRAGMENT_SENTINEL_SIZE)
    for offset, value in OPTIONAL_ITEM_U16[kind].items():
        struct.pack_into("<H", out, offset, value)
    # A queue's first optional record has three one-shot flags. Queue-context
    # placement is an independent namespace: native context 4 starts a queue
    # with record index 2 while retaining all three first-record flags.
    if first_record is None:
        first_record = item_index == 0
    if not first_record:
        for offset in (0x1a, 0x52, 0x62):
            struct.pack_into("<H", out, offset, 0)
    if queue_context_index is None:
        queue_context_index = item_index
    if queue_context_phase is None:
        queue_context_phase = item_index << 8
    struct.pack_into("<H", out, 0x2a, queue_context_index)
    struct.pack_into("<H", out, 0x2e, queue_context_phase)

    # Grid and pair fields follow the queue, while these two ordinal fields
    # follow the global order in which channel-ring entries are published.
    struct.pack_into("<H", out, 0x18, grid_index)
    struct.pack_into("<H", out, 0x3e, submission_ordinal)
    if context_id is None:
        context_id = pair_index
    legacy_scheduler_class = scheduler_class is None
    if scheduler_class is None:
        scheduler_class = context_id
    if not legacy_scheduler_class or context_id == 2:
        struct.pack_into("<H", out, 0x1e, scheduler_class)
        struct.pack_into("<H", out, 0x46, scheduler_class)
    for offset in (0x32, 0x56):
        struct.pack_into("<H", out, offset, context_id)
    struct.pack_into("<H", out, 0x5e, scheduler_class)
    if uuid is not None:
        struct.pack_into("<H", out, 0x5a, uuid)
    if kind == "tiling":
        if lifecycle_ordinal is None:
            lifecycle_ordinal = submission_ordinal
        if queue_namespace is None:
            queue_namespace = pair_index
        struct.pack_into("<H", out, 0x76, lifecycle_ordinal)
        struct.pack_into("<H", out, 0x7e, queue_namespace)
        struct.pack_into("<H", out, 0x82, grid_index + 1)
    for offset, value in (u16_overrides or {}).items():
        offset = int(offset)
        value = int(value)
        if offset < 0 or offset + 2 > OPTIONAL_ITEM_SIZE or offset & 1:
            raise ValueError(
                "optional u16 override offset %#x is invalid" % offset)
        if value < 0 or value > 0xffff:
            raise ValueError(
                "optional u16 override value %#x does not fit" % value)
        struct.pack_into("<H", out, offset, value)
    return bytes(out)


def build_queue_context_item(kind, descriptor=0, queue=0, pair=0,
                             item_index=0, context_id=None, grid_index=None,
                             locator_context_id=None):
    """Build one item slot in a stage's per-queue context page."""
    if kind not in QUEUE_CONTEXT_WORDS:
        raise ValueError("kind must be one of %s" % sorted(QUEUE_CONTEXT_WORDS))
    if item_index < 0:
        raise ValueError("item index must not be negative")
    if context_id is not None and context_id >= 2 and (
            pair >= 2 or grid_index is not None):
        if not descriptor:
            raise ValueError("context queue item requires a descriptor")
        grid = (pair * 2 + (1 if kind == "fragment" else 0)
                if grid_index is None else int(grid_index))
        words = {
            0x200: (0x1000000000000000
                    | ((grid * 0x400) << 32) | (4 + item_index * 4)),
            0x220: ((0xffff180000000003 if kind == "fragment"
                     else 0xffff0c0000000001)
                    | (int(context_id) << 32)),
            0x228: (((grid - 1 if kind == "fragment" else grid) << 40)
                    | ((context_id - 1) if kind == "fragment" else item_index)),
            0x378: 0x003fffffffffffff,
        }
        if kind == "fragment":
            words[0x230] = (grid << 40) | item_index
            base = 0xfffffc20c00b0000
            # The locator family follows the descriptor/render context, while
            # +0x220/+0x228 follow the graph/queue context.  The forced-partial
            # render proves these can differ: graph context 2 uses the extended
            # locator family of descriptor context 3.
            if (context_id if locator_context_id is None
                    else int(locator_context_id)) >= 3:
                locators = (
                    (0x350, 0x0002b00380004c05),
                    (0x358, 0x0000800380004c3e),
                    (0x360, 0x0000b80380004c77),
                    (0x368, 0x0000500380004cb0),
                )
            else:
                locators = (
                    (0x350, 0x0002b00380004c05),
                    (0x358, 0x0000100380004c3e),
                    (0x360, 0x0000100380004c77),
                    (0x368, 0x0000100380004cb0),
                )
        else:
            base = 0xfffffc20c0018000
            locators = ((0x350, 0x0002380380000003),)
        delta = descriptor - base
        if delta < 0 or delta % 0x20:
            raise ValueError(
                "%s descriptor %#x has no aligned context locator" %
                (kind, descriptor))
        for offset, locator in locators:
            words[offset] = locator + delta // 0x20
    else:
        pair_words = QUEUE_CONTEXT_PAIR_WORDS.get(pair)
        if pair_words is None and pair:
            raise ValueError("queue context encoding is unknown for pair %d" % pair)

        words = dict(QUEUE_CONTEXT_WORDS[kind])
        words.update((pair_words or {}).get(kind, ()))
        for offset, increment in QUEUE_CONTEXT_ITEM_INCREMENTS[kind].items():
            words[offset] = words.get(offset, 0) + item_index * increment

        # The locator family follows the descriptor DVA, not the queue-local
        # context slot.  Those ordinals happened to advance together in the
        # alternating-queue capture from which the increments above were first
        # inferred.  The final-26.6 opening keeps publishing on grid 0/1 while
        # advancing to the next descriptor: its item-one record retains the
        # item-one queue words but has the locators for descriptor array slot
        # one, rather than descriptor slot two.  Derive the live locators from
        # the pointer whenever a descriptor is present; retain the captured
        # pair defaults only for an empty, pre-created context page.
        if descriptor:
            base = (0xfffffc20c00b0000 if kind == "fragment"
                    else 0xfffffc20c0018000)
            delta = descriptor - base
            if delta < 0 or delta % 0x20:
                raise ValueError(
                    "%s descriptor %#x has no aligned context locator" %
                    (kind, descriptor))
            locator_delta = delta // 0x20
            if kind == "fragment":
                # Bit 54 is a first-record bit on the fixed fragment queue;
                # native slots one and later clear it while retaining the
                # address-derived low locator.
                words[0x208] = (
                    (0x004000e000130d40 if item_index == 0
                     else 0x000000e000130d40)
                    + 2 * delta)
                for offset, locator in (
                        (0x350, 0x0002b00380004c05),
                        (0x358, 0x0000100380004c3e),
                        (0x360, 0x0000100380004c77),
                        (0x368, 0x0000100380004cb0)):
                    words[offset] = locator + locator_delta
            else:
                words[0x350] = 0x0002380380000003 + locator_delta

    out = bytearray(QUEUE_CONTEXT_ITEM_SIZE)
    for offset, value in words.items():
        struct.pack_into("<Q", out, offset - QUEUE_CONTEXT_ITEM_BASE, value)
    struct.pack_into(
        "<Q", out, QUEUE_CONTEXT_DESCRIPTOR_OFFSET - QUEUE_CONTEXT_ITEM_BASE,
        descriptor)
    struct.pack_into(
        "<Q", out, QUEUE_CONTEXT_QUEUE_OFFSET - QUEUE_CONTEXT_ITEM_BASE,
        queue)
    return bytes(out)


def build_queue_context(kind, descriptor=0, queue=0, size=FIRMWARE_PAGE_SIZE,
                        pair=0, context_id=None):
    """Build one stage's per-queue context page.

    This is the firmware-visible high object. Native context 4 proves that its
    low context-side companion may have distinct zero backing. ``descriptor``
    and ``queue`` are written when a submission is built, because a newly
    created pair exists before its first descriptor does.
    """
    out = bytearray(size)
    item = build_queue_context_item(
        kind, descriptor, queue, pair=pair, context_id=context_id)
    out[QUEUE_CONTEXT_ITEM_BASE:
        QUEUE_CONTEXT_ITEM_BASE + len(item)] = item
    return bytes(out)


def build_register_array(registers):
    """Serialise a sequence of (number, value) pairs.

    A sequence rather than a mapping, deliberately. A captured array holds the same
    register number more than once, seventy-one entries against sixty-nine distinct
    numbers in one descriptor and eighty-eight against eighty-five in the other, so a
    mapping loses entries and shifts everything after them. Order is preserved for the
    same reason: the captured arrays are not sorted and nothing establishes that order
    is free.
    """
    pairs = list(registers.items()) if hasattr(registers, "items") else list(registers)
    if len(pairs) > REGISTER_ARRAY_LIMIT:
        raise ValueError("register array holds at most %d entries"
                         % REGISTER_ARRAY_LIMIT)
    out = bytearray()
    for number, value in pairs:
        out += struct.pack("<IQ", number, value)
    return bytes(out)


# Header fields that repeat a register value rather than carrying anything of their
# own. These correlations hold across every captured fragment item. The format is
# explicit because the tile-map address is 64 bits while the other mirrors are 32.
MIRRORED_FIELDS = {
    "tiling": {},
    "fragment": {
        0x040: (0x16429, "Q"),  # tile-map DVA
        0x048: (0x10019, "Q"),  # multisample control
        0x054: (0x100b1, "I"),  # macro-tile Y/X dimensions
        0x068: (0x15131, "I"),  # merge upper X
        0x06c: (0x15139, "I"),  # merge upper Y
    },
}


def build_descriptor(kind, objects, registers, size=None, submit_sequence=0,
                     context_id=0, submission_ordinal=0, queue_pair=0):
    """Assemble a work descriptor's common header, pointer block, and registers.

    ``objects`` is the four addresses in the order both descriptors carry them.
    Kind-specific fields outside these regions are left zero.
    """
    if kind not in DESCRIPTOR_LAYOUT:
        raise ValueError("kind must be one of %s" % sorted(DESCRIPTOR_LAYOUT))
    if submission_ordinal < 0:
        raise ValueError("submission ordinal must be non-negative")
    if len(objects) != 4:
        raise ValueError("a descriptor names four objects")
    layout = DESCRIPTOR_LAYOUT[kind]
    body = build_register_array(registers)
    total = size or (layout["registers"] + len(body))
    out = bytearray(total)

    struct.pack_into("<IQI", out, 0, DESCRIPTOR_SELECTOR[kind],
                     submit_sequence, context_id)

    # The tiling descriptor has a gap after its first address; the fragment one does
    # not, which is the whole of the difference between the two blocks.
    offset = layout["pointers"]
    struct.pack_into("<Q", out, offset, objects[0])
    offset += 8 + layout["pointer_gap"]
    for address in objects[1:]:
        struct.pack_into("<Q", out, offset, address)
        offset += 8

    out[layout["registers"]:layout["registers"] + len(body)] = body

    # Mirror the header fields that repeat a register value.
    lookup = dict(registers.items() if hasattr(registers, "items") else registers)
    for offset, (number, fmt) in MIRRORED_FIELDS[kind].items():
        width = struct.calcsize(fmt)
        if number in lookup and offset + width <= len(out):
            mask = (1 << (width * 8)) - 1
            struct.pack_into("<" + fmt, out, offset, lookup[number] & mask)

    # TE_SCREEN encodes (tiles_y - 1, tiles_x - 1). The descriptor carries the
    # resulting total tile count separately.
    if kind == "fragment" and 0x100d9 in lookup and 0x80 <= len(out):
        screen = lookup[0x100d9]
        tiles_x = (screen & 0xfff) + 1
        tiles_y = ((screen >> 12) & 0xfff) + 1
        struct.pack_into("<Q", out, 0x78, tiles_x * tiles_y)

    ordinal = DESCRIPTOR_ORDINAL_FIELDS[kind]
    work_ordinal = descriptor_work_ordinal(submission_ordinal)
    for offset in ordinal["pair"]:
        if offset + 4 <= len(out):
            struct.pack_into("<I", out, offset, queue_pair)
    for offset in ordinal["work"]:
        if offset + 4 <= len(out):
            struct.pack_into("<I", out, offset, work_ordinal)
    # The high byte is the render context's scheduler namespace.  The bootstrap
    # context is namespace one; native context-2/3 descriptors carry 0x200/0x300
    # before their local work ordinal is added.
    stamp_base = (max(1, int(context_id)) << 8)
    for offset in ordinal["stamps"]:
        if offset + 4 <= len(out):
            struct.pack_into("<I", out, offset, stamp_base + work_ordinal)

    return bytes(out)

# A work item's three inner entries, and how a submission's items draw from the pools.
# Measured across a three-item submission: the entries come in groups of three and the
# two advancing pointers take the next record of each pool. The other two pointers are
# shared by every item.
INNER_ENTRIES_PER_ITEM = 3


def item_submit_sequence(kind, index):
    """Return the shared submit-sequence value for one side of item ``index``."""
    if kind not in SUBMIT_SEQUENCE_BASE:
        raise ValueError("kind must be one of %s" % sorted(SUBMIT_SEQUENCE_BASE))
    return SUBMIT_SEQUENCE_BASE[kind] + index * SUBMIT_SEQUENCE_STEP


def build_inner_batch(items):
    """The inner entry array for a submission, three entries an item.

    ``items`` is a sequence of (descriptor, support_a, support_b) address triples. The
    count a ring entry carries in its low 16 bits is the length of what this returns,
    which is three times the number of items.
    """
    out = bytearray()
    for entry in items:
        if len(entry) != INNER_ENTRIES_PER_ITEM:
            raise ValueError("a work item names %d entries"
                             % INNER_ENTRIES_PER_ITEM)
        for address in entry:
            out += struct.pack("<Q", address)
    return bytes(out)


def item_pool_records(index, array_a_base, array_b_base, record_indices=None):
    """Which pool records work item ``index`` uses.

    Each item takes the next record of each pool, so an implementation advances these
    rather than allocating anything per submission.

    ``record_indices`` overrides the two record numbers independently. A live host's successive
    submissions advance the two pools at different rates: both halves of a pair name one record of
    each, and the next pair's pool A record is two records further on while its pool B record is
    one. Deriving both from a single item number is right for the first submission, where every
    index is zero, and wrong afterwards.
    """
    if record_indices is not None:
        index_a, index_b = record_indices
    else:
        index_a = index_b = index
    index_a, index_b = wrap_pool_record_indices(index_a, index_b)
    return (array_a_base + index_a * ARRAY_A_STRIDE,
            array_b_base + index_b * ARRAY_B_STRIDE)


def build_item_descriptor(kind, index, array_a_base, array_b_base, shared,
                          registers, size=None, context_id=0,
                          submit_sequence=None, record_indices=None,
                          submission_ordinal=None, queue_pair=0):
    """A work item's descriptor, with pool records and common header filled in.

    ``shared`` is the two addresses every item in a submission carries unchanged, in
    the order they appear in the pointer block: the second and the fourth.
    """
    record_a, record_b = item_pool_records(
        index, array_a_base, array_b_base, record_indices)
    objects = [record_a, shared[0], record_b, shared[1]]
    if submit_sequence is None:
        submit_sequence = item_submit_sequence(kind, index)
    if submission_ordinal is None:
        submission_ordinal = index
    return build_descriptor(kind, objects, registers, size=size,
                            submit_sequence=submit_sequence,
                            context_id=context_id,
                            submission_ordinal=submission_ordinal,
                            queue_pair=queue_pair)
