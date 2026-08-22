# SPDX-License-Identifier: MIT
"""T8140/G17P submission-path layout, as confirmed on hardware.

This module is deliberately declarative. It holds only facts observed on a live
T8140 and recorded in ``docs/t8140-g17p-firmware-abi-spec.md``; it does not implement
firmware startup and does not guess at unresolved fields. The backend can build
on these constants without carrying the experiment tooling that produced them.

The observations come from two places: the initial submission inherited from a
captured pre-work state, and a steady-state geometry-channel publication halted
at its producer write before the doorbell.

Everything here is verified against hardware. Where a value's meaning is not
established, the name describes what was observed rather than what it means.
"""

CHIP_ID = 0x8140

# The four 16-bit values at the start of the descriptor root. Their meaning is
# not established, so they are recorded rather than derived, and both instances
# carry the same four.
ROOT_VERSION_VALUES = (0x04c0, 0x0396, 0xa322, 0x0c8a)

# --- Mailbox and doorbells ---------------------------------------------------
# The message selector occupies bits 48..55 of the 64-bit mailbox word. Note
# this differs from external notes that place the tag in bits 56..63.
MBOX_TYPE_SHIFT = 48
MBOX_TYPE_MASK = 0xff
MBOX_ADDR_MASK = (1 << 48) - 1

# Two firmware instances are present and the start sequence addresses both. The
# secondary's initialisation message carries the primary's address plus the delta
# below in the same field, so the two descriptor roots are not placed freely.
COPROCESSOR_NODES = ("/arm-io/gfx-asc", "/arm-io/gfx1-asc")
COPROCESSOR_NAMES = ("primary", "secondary")
SECONDARY_ROOT_DELTA = 0x8000

# Each instance owns half of the shared region and roots the upper half of the
# address space in its own copy of the top table. Read out of the two instances'
# own mapping lists at a fault: where the primary maps the shared region from the
# base, the secondary maps it from the base plus this delta, and the top table it
# walks sits at the same offset into its half. A host that installs its mappings
# only in the primary's table leaves the secondary unable to translate anything it
# is handed, including its own descriptor.
SECONDARY_SHARED_DELTA = 0x40000

# Top-table entries below this index describe an instance's own code and data and
# differ between the two, so a host mirroring its mappings from one instance's
# table to the other must start above them.
SHARED_FIRMWARE_ENTRIES = 2

# The control-only instance's region triples carry these values with no addresses
# at all, so the values are not properties of any region. Read at the moment the
# instance is handed its descriptor.
SECONDARY_REGION_TRIPLES = ((0, 0x01838000), (0, 0x01840000), (0, None))

# Two region records inside the hardware-data object, each naming a 16 KiB region.
# Read at the moment the first instance is handed its descriptor; the second
# instance shares the same object. The leading and trailing scalars differ between
# the two records, so they are recorded per record rather than assumed uniform.
HWDATA_REGION_RECORDS = (
    {"lead": 0x100, "value": 0x1848000, "trail": 0},
    {"lead": 0x000, "value": 0x1870000, "trail": 2},
)

ENDPOINT_INIT = 0x20
ENDPOINT_WORK = 0x21

MSG_INITDATA = 0x81      # carries the initial descriptor address in bits 0..47
MSG_CONTROL_START = 0x89
MSG_CONTROL_DONE = 0x84
MSG_WORK_DOORBELL = 0x83  # "inspect the work rings"

# --- Work channels ----------------------------------------------------------
# Twelve channels, three workload classes across four slots each.
WORK_CHANNELS = (
    "TA_0", "3D_0", "CL_0",
    "TA_1", "3D_1", "CL_1",
    "TA_2", "3D_2", "CL_2",
    "TA_3", "3D_3", "CL_3",
)

# --- Work-channel rings -----------------------------------------------------
# Each channel owns a ring of 0x100 slots of 0x18 bytes, so a ring spans 0x1800.
# The twelve rings are contiguous at that stride, and the ring base addresses are
# identical across every observed boot.
#
# Three independent facts fix the slot size at 0x18: adjacent ring bases differ
# by exactly 0x1800, the captured initialization descriptor holds exactly one
# address per ring page at ring_base+0x8, and reading captured rings at that
# stride yields coherent slots in every channel. An earlier 0x60 value treated
# four consecutive slots as a single record with four subrecords, which also made
# slot indexing four times too large.
RING_SLOT_SIZE = 0x18
RING_SLOT_COUNT = 0x100
RING_STRIDE = 0x1800

# Slot field offsets, confirmed against captured rings.
RING_SLOT_QUEUE_PTR = 0x08     # command-queue pointer
RING_SLOT_KIND = 0x10          # u32, 0=tiling, 1=fragment, 2=compute
RING_SLOT_FLAGS_HEAD = 0x14    # packed, see the masks below

# The word at RING_SLOT_KIND is not part of the packed field below and is not a head or an index. It
# is zero in every observed tiling-channel slot and one in every observed fragment-channel slot, on
# a live host's thirteenth submission and on the slot a first submission is found in.
RING_SLOT_KIND_BY_KIND = {"tiling": 0, "fragment": 1, "compute": 2}
# +0x00 was zero in every observed slot.

# The 32-bit word at RING_SLOT_FLAGS_HEAD packs three things. The low half rises
# monotonically across consecutive slots. Bits 16..23 equal the referenced queue's
# index on the queue grid, which is what identifies this field: one channel's
# slots referenced queue indices 0 and 2 and carried 0x00 and 0x02 here, while
# another referenced index 5 and carried 0x05. Bit 24 is set only on a queue's
# first slot.
RING_HEAD_MASK = 0x0000ffff
RING_QUEUE_INDEX_SHIFT = 16
RING_QUEUE_INDEX_MASK = 0xff
RING_FIRST_SUBMIT_BIT = 1 << 24


def decode_slot_flags(value):
    """Split the packed slot word into head, queue index and first-submit flag."""
    return {
        "head": value & RING_HEAD_MASK,
        "queue_index": (value >> RING_QUEUE_INDEX_SHIFT) & RING_QUEUE_INDEX_MASK,
        "first_submit": bool(value & RING_FIRST_SUBMIT_BIT),
    }

# Command queues referenced by ring slots lie on a 0xc0 grid from a common base,
# which is also the queue record size. Observed references were at grid indices
# 0, 2 and 5, so the array is not densely used. One channel's slots may alternate
# between several queues: one channel used two, another used one for every slot.
QUEUE_RECORD_STRIDE = 0xc0

# Retained for callers that still speak the old name.
OUTER_RECORD_SIZE = RING_SLOT_SIZE
OUTER_RECORD_COUNT = RING_SLOT_COUNT
OUTER_SUBRECORD_QUEUE_PTR = RING_SLOT_QUEUE_PTR

# Producer counters are 8-bit wrapping ring indexes despite occupying 32-bit
# words, so a publication is (producer + 1) & 0xff.
PRODUCER_MASK = 0xff

# --- Command queue ----------------------------------------------------------
QUEUE_DESCRIPTOR_SIZE = 0xc0
QUEUE_STATE_SIZE = 0x80
# These three state words held the live item count in every observed capture.
QUEUE_STATE_COUNT_OFFSETS = (0x00, 0x30, 0x40)

# --- Inner item ring --------------------------------------------------------
# Consecutive 24-byte entries, each with three pointer slots. The ring is
# sparse: only a minority of slots are populated, so the queue-state count
# describes live items rather than ring capacity.
INNER_ENTRY_SIZE = 0x18
INNER_ENTRY_SLOTS = 3

# --- Command queue record ----------------------------------------------------
# The record is the earlier-generation layout with the per-queue buffer address
# at 0x18 removed, so every field from that point on sits 8 bytes earlier, and
# with the version-gated 32-bit field before the context address present.
#
# The alignment is established by sentinel values rather than by assumption. At
# the offsets below, three independently created queues carry exactly the values
# the earlier generation's model documents: an all-ones event id, an all-ones
# field at 0x44, 1 at 0x38 with 0 at 0x3c, a priority-like value of 1 or 2 at
# 0x40, a counter at 0x48 that differs per queue, and zeros where zeros are
# expected. Ten fields agree across all three queues.
QUEUE_POINTERS_ADDR = 0x00      # -> queue pointer block
QUEUE_RING_ADDR = 0x08          # -> item ring
QUEUE_JOB_LIST_ADDR = 0x10      # -> job list, 0x18 bytes
QUEUE_GPU_RPTR1 = 0x18          # zero in all observed queues
QUEUE_GPU_RPTR2 = 0x1c          # mirrors the pointer block's done index
QUEUE_GPU_RPTR3 = 0x20          # zero in all observed queues
QUEUE_EVENT_ID = 0x24           # signed, -1 in all observed queues
QUEUE_PRIORITY = 0x28
QUEUE_UNK_2C = 0x2c
QUEUE_UNK_30 = 0x30             # u64
QUEUE_SENTINEL = 0x32           # start of the widest observed trailing sentinel
QUEUE_SENTINEL_SIZE = 6         # ordinary queues; the first pair-3 queues use 2
QUEUE_UNK_38 = 0x38             # 1 in two queues, 0 in the third
QUEUE_UNK_3C = 0x3c             # zero
QUEUE_PRIO5 = 0x40              # 1 or 2
QUEUE_UNK_44 = 0x44             # signed, -1
QUEUE_UUID = 0x48               # counts up per queue
QUEUE_UNK_4C = 0x4c
QUEUE_UNK_50 = 0x50             # u64
QUEUE_BUSY = 0x58
QUEUE_UNK_78 = 0x78
QUEUE_HAS_COMMANDS = 0x7c
QUEUE_INFLIGHT = 0x90
QUEUE_UNK_94 = 0x94             # large per-queue counter
QUEUE_UNK_98 = 0x98             # version-gated field, zero here
QUEUE_CONTEXT_ADDR = 0x9c       # -> per-queue context object

# CommandQueueInfo::set_prio() uses one coherent field family.  G17P removes
# the older generation's gpu_buf_addr at +0x18, shifting this family eight
# bytes earlier without changing its encoding.  The public UAPI currently
# exposes only the first two profiles.
QUEUE_PRIORITY_PROFILES = {
    0: {
        "priority": 0,
        "unk_2c": 0,
        "unk_30": 0xffffffffffff0000,
        "unk_38": 1,
        "prio5": 1,
    },
    1: {
        "priority": 1,
        "unk_2c": 1,
        "unk_30": 0xffffffff00000000,
        "unk_38": 0,
        "prio5": 0,
    },
    2: {
        "priority": 2,
        "unk_2c": 2,
        "unk_30": 0xffff000000000000,
        "unk_38": 0,
        "prio5": 2,
    },
    3: {
        "priority": 3,
        "unk_2c": 3,
        "unk_30": 0,
        "unk_38": 0,
        "prio5": 3,
    },
}


def queue_priority_profile(priority):
    """Return the complete priority-dependent queue-record field family."""
    try:
        return dict(QUEUE_PRIORITY_PROFILES[int(priority)])
    except (KeyError, ValueError) as exc:
        raise ValueError("queue priority must be in 0..3") from exc
QUEUE_RECORD_SIZE = 0xac

# The pointer block is unchanged from earlier generations: 32-bit indices on a
# 0x10 spacing. One observed queue had a write index two ahead of its read
# index, which is what identifies the pair.
QUEUE_PTR_DONE = 0x00
QUEUE_PTR_UNK_10 = 0x10
QUEUE_PTR_UNK_20 = 0x20
QUEUE_PTR_READ = 0x30
QUEUE_PTR_WRITE = 0x40
QUEUE_PTR_RING_SIZE = 0x50      # all ones in every observed queue
QUEUE_PTR_BLOCK_SIZE = 0x60

# The job list is an intrusive list of three 64-bit words. When empty, the second
# word points at the list itself, which is how the empty state is recognised. One
# observed queue held two jobs.
JOB_LIST_FIRST = 0x00
JOB_LIST_LAST = 0x08
JOB_LIST_UNK_10 = 0x10
JOB_LIST_SIZE = 0x18

# Per-queue context objects lie on a 0x40 grid. Their first two bytes were both
# all-ones before any work was submitted, matching the unassigned table indices
# earlier generations place there.
QUEUE_CONTEXT_STRIDE = 0x40


def parse_queue_record(data):
    """Decode a command queue record."""
    import struct

    def u32(off):
        return struct.unpack_from("<I", data, off)[0]

    def s32(off):
        return struct.unpack_from("<i", data, off)[0]

    def u64(off):
        return struct.unpack_from("<Q", data, off)[0]

    return {
        "pointers_addr": u64(QUEUE_POINTERS_ADDR),
        "ring_addr": u64(QUEUE_RING_ADDR),
        "job_list_addr": u64(QUEUE_JOB_LIST_ADDR),
        "gpu_rptr1": u32(QUEUE_GPU_RPTR1),
        "gpu_rptr2": u32(QUEUE_GPU_RPTR2),
        "gpu_rptr3": u32(QUEUE_GPU_RPTR3),
        "event_id": s32(QUEUE_EVENT_ID),
        "priority": u32(QUEUE_PRIORITY),
        "prio5": u32(QUEUE_PRIO5),
        "unk_44": s32(QUEUE_UNK_44),
        "uuid": u32(QUEUE_UUID),
        "busy": u32(QUEUE_BUSY),
        "has_commands": u32(QUEUE_HAS_COMMANDS),
        "inflight": u32(QUEUE_INFLIGHT),
        "unk_94": u32(QUEUE_UNK_94),
        "context_addr": u64(QUEUE_CONTEXT_ADDR),
    }


def parse_queue_pointers(data):
    """Decode a queue pointer block."""
    import struct

    return {
        "done": struct.unpack_from("<I", data, QUEUE_PTR_DONE)[0],
        "read": struct.unpack_from("<I", data, QUEUE_PTR_READ)[0],
        "write": struct.unpack_from("<I", data, QUEUE_PTR_WRITE)[0],
        "ring_size": struct.unpack_from("<I", data, QUEUE_PTR_RING_SIZE)[0],
    }


def parse_job_list(data, own_address=None):
    """Decode a job list, reporting whether it is empty."""
    import struct

    first, last = struct.unpack_from("<QQ", data, JOB_LIST_FIRST)
    empty = last == own_address if own_address is not None else first == 0
    return {"first": first, "last": last, "empty": empty}


# --- Queue items ------------------------------------------------------------
# Every item begins with a 32-bit selector that the scheduler uses to choose a
# layout: substituting one selector for another faults the scheduler rather
# than being stored verbatim.
# The queue's item ring is an array of 64-bit pointers, one per item, matching
# earlier generations. The write index names the next entry to fill, so entries
# below it hold pointers and entries from it on are zero.
ITEM_RING_ENTRY_SIZE = 0x08

# A submission is a group of consecutive item-ring entries: a work item, then an
# optional 0x0f item, then a 0x0e item that terminates the group. Reading all 73
# live entries of one channel showed only the two shapes below.
SUBMISSION_SHAPES = ((0x00, 0x0f, 0x0e), (0x00, 0x0e))

# The group's first item carries this header. The field at 0x04 is 64-bit on a
# 4-byte boundary and advances between groups; the field at 0x0c was identical
# across groups of the same queue. The 0x0f and 0x0e items do not share it.
ITEM_HEADER_SELECTOR = 0x00
ITEM_HEADER_SEQUENCE = 0x04     # u64, unaligned
ITEM_HEADER_CONTEXT = 0x0c      # u32
ITEM_HEADER_POINTER = 0x10      # u64

ITEM_SELECTOR_OFFSET = 0x00

SELECTOR_GEOMETRY = 0x00          # geometry work item
SELECTOR_RENDER = 0x01            # render work item
SELECTOR_EVENT = 0x0e             # event ring, terminates a submission group
SELECTOR_OPTIONAL = 0x0f          # optional item within a group

# Retained for callers that used the earlier, less accurate names.
SELECTOR_INITIAL_GEOMETRY = SELECTOR_GEOMETRY
SELECTOR_DATA = SELECTOR_EVENT
SELECTOR_ARRAY = SELECTOR_OPTIONAL

# Record size per selector, measured from the pool stride of live items: every
# observed distance between two records of a selector is an exact multiple.
ITEM_RECORD_SIZE = {
    SELECTOR_GEOMETRY: 0x9c0,
    SELECTOR_RENDER: 0x2240,
}

# Geometry items are entirely host-written. The event item is not: the host writes
# only its first record and firmware appends more, which is how the two writers
# were separated, by comparing the newest group of a queue against an older one
# while the guest is halted before the doorbell.
GEOMETRY_ITEM_EXTENT = 0x94e

# Address fields of a geometry item, present in all 32 live items of one queue.
# The three at 0x20, 0x28 and 0x30 are the progress group: the first target held
# two equal counters, and the third was entirely zero before the doorbell, which
# is consistent with a location firmware writes on completion.
GEOMETRY_ITEM_POINTER_OFFSETS = (0x10, 0x20, 0x28, 0x30, 0x934)
GEOMETRY_ITEM_PROGRESS_OFFSETS = (0x20, 0x28, 0x30)

# The event item is a ring of 0x40-byte records. The host writes the first record
# only, ten bytes in total.
EVENT_RECORD_SIZE = 0x40
EVENT_RECORD_TYPE = 0x00          # u32, equals the selector
EVENT_RECORD_SUBTYPE = 0x04       # u32, 0x00010000 | queue grid index
EVENT_RECORD_COUNTER = 0x08       # u32, the group number shifted left by 8
EVENT_RECORD_UNK_10 = 0x10
# A work-channel event record's subtype is this base with the queue's index on the queue grid in its
# low half. Two independent captures agree: one whose queues sit at grid indices 2 and 3 carries
# 0x00010002 and 0x00010003, and one whose queues sit at 0 and 1 carries 0x00010000 and 0x00010001.
# It is neither a fixed constant nor a per-kind one, and reading it as either matches only the
# capture it was read from.
EVENT_RECORD_UNK10 = 0x10
EVENT_SUBTYPE_BASE = 0x00010000
EVENT_UNK10_BY_KIND = {
    "tiling": 0x00000000,
    "fragment": 0x00000100,
    "compute": 0x00000200,
}
EVENT_COUNTER_SHIFT = 8

# Optional items carry addresses on this stride from offset 0x10, the same stride
# as the command queue grid.
OPTIONAL_ITEM_POINTER_OFFSET = 0x10
OPTIONAL_ITEM_POINTER_STRIDE = 0xc0


# --- Publishing work ---------------------------------------------------------
# Established by publishing host-constructed submissions into a live queue and
# watching firmware consume them, with the guest CPU halted so it could not
# participate. See docs/t8140-g17p-firmware-abi-spec.md for the resulting ABI.
#
# Order matters:
#   1. item addresses into consecutive item-ring entries at the write index
#   2. the event item's first record, with the group counter
#   3. advance the queue write index
#   4. the channel ring slot: queue address and packed head plus queue index
#   5. the channel producer, the third state counter, to slot index + 1
#   6. clear then set the queue's has_commands field
#   7. ring the work doorbell, twice with an interval
PUBLISH_DOORBELL = MSG_WORK_DOORBELL << MBOX_TYPE_SHIFT

# The producer is the next ring slot. Publishing that slot advances the 8-bit
# counter once, including 0xff -> 0x00 wrap.
def producer_for_slot(slot_index):
    """Producer counter value that publishes ``slot_index``."""
    if not 0 <= slot_index < RING_SLOT_COUNT:
        raise ValueError("channel slot index out of range: %d" % slot_index)
    return next_producer(slot_index)


def producer_reached(start, current, target):
    """Whether an 8-bit consumer advanced from ``start`` through ``target``."""
    values = (start, current, target)
    if any(value & ~PRODUCER_MASK for value in values):
        raise ValueError("channel counter outside 8-bit range: %r" % (values,))
    return ((current - start) & PRODUCER_MASK) >= ((target - start) & PRODUCER_MASK)


# This field is not required, and the claim that once stood here, that firmware will not scan
# the channel unless it transitions from clear to set, is withdrawn. Measured: publishing a
# group without writing it at all, firmware still takes the entries off the ring and retires
# the group. A working host leaves it zero on every queue, including one well into its stream.
# The sequence is kept for callers that want to reproduce a transition, not because one is
# needed.
PUBLISH_ANNOUNCE_OFFSET = QUEUE_HAS_COMMANDS
PUBLISH_ANNOUNCE_SEQUENCE = (0, 1)

# A world that renders sends exactly one work doorbell, on the first instance, with a zero
# channel field; its mailbox trace shows no second. The reading that once stood here, that an
# idle firmware treats the first as a wake-up and acts on the second, is not supported by
# anything measured.
PUBLISH_DOORBELL_RINGS = 1


def build_ring_slot(queue_addr, write_index, queue_index, first_submit=False,
                    kind=None):
    """Build a channel ring slot publishing ``write_index`` on a queue.

    ``first_submit`` sets bit 24, which captures show set only on a queue's first slot. A caller
    can set it anyway: the only submission this part has been seen to execute is a queue's first,
    and whether the bit is a description of that or a condition for it is not established.

    ``kind`` selects the word at ``RING_SLOT_KIND``, which a fragment channel's slots carry as one
    and a tiling channel's as zero. Omitting it leaves that word zero, which is right for a tiling
    channel and wrong for a fragment one.
    """
    import struct

    slot = bytearray(RING_SLOT_SIZE)
    struct.pack_into("<Q", slot, RING_SLOT_QUEUE_PTR, queue_addr)
    struct.pack_into("<I", slot, RING_SLOT_KIND,
                     RING_SLOT_KIND_BY_KIND.get(kind, 0))
    struct.pack_into("<I", slot, RING_SLOT_FLAGS_HEAD,
                     (write_index & RING_HEAD_MASK)
                     | ((queue_index & RING_QUEUE_INDEX_MASK)
                        << RING_QUEUE_INDEX_SHIFT)
                     | (RING_FIRST_SUBMIT_BIT if first_submit else 0))
    return bytes(slot)


def build_queue_record(pointers_addr, ring_addr, job_list_addr, context_addr,
                       uuid=0, priority=0, prio5=1, unk_2c=0, unk_38=1,
                       unk_30=None, unk_94=0,
                       sentinel_size=QUEUE_SENTINEL_SIZE):
    """Build a command queue record.

    A channel table alone leaves a channel with nothing to service: the ring slot's queue pointer
    is zero until a record like this exists and is named from it. Every field here was decoded by
    diffing live queues; the ones whose meaning is not established keep their observed values as
    named arguments rather than being written as anonymous constants, so a caller can see exactly
    what is being asserted and change one.
    """
    import struct

    record = bytearray(QUEUE_DESCRIPTOR_SIZE)
    struct.pack_into("<Q", record, QUEUE_POINTERS_ADDR, pointers_addr)
    struct.pack_into("<Q", record, QUEUE_RING_ADDR, ring_addr)
    struct.pack_into("<Q", record, QUEUE_JOB_LIST_ADDR, job_list_addr)
    # Read pointers firmware owns; a fresh queue starts at zero.
    struct.pack_into("<I", record, QUEUE_GPU_RPTR1, 0)
    struct.pack_into("<I", record, QUEUE_GPU_RPTR2, 0)
    struct.pack_into("<I", record, QUEUE_GPU_RPTR3, 0)
    # This sentinel ends immediately before +0x38. Ordinary queues carry six
    # bytes; the first native grid-6/7 queues carry only the final two.
    sentinel_size = int(sentinel_size)
    if not 0 <= sentinel_size <= QUEUE_SENTINEL_SIZE:
        raise ValueError("queue sentinel size must be between 0 and %d" %
                         QUEUE_SENTINEL_SIZE)
    if unk_30 is None:
        sentinel_start = QUEUE_UNK_38 - sentinel_size
        record[sentinel_start:QUEUE_UNK_38] = b"\xff" * sentinel_size
    else:
        struct.pack_into("<Q", record, QUEUE_UNK_30, int(unk_30))
    # Signed, and minus one in every queue observed.
    struct.pack_into("<i", record, QUEUE_EVENT_ID, -1)
    struct.pack_into("<I", record, QUEUE_PRIORITY, priority)
    struct.pack_into("<I", record, QUEUE_UNK_2C, unk_2c)
    struct.pack_into("<I", record, QUEUE_UNK_38, unk_38)
    struct.pack_into("<I", record, QUEUE_PRIO5, prio5)
    struct.pack_into("<i", record, QUEUE_UNK_44, -1)
    struct.pack_into("<I", record, QUEUE_UUID, uuid)
    struct.pack_into("<I", record, QUEUE_UNK_94, unk_94)
    struct.pack_into("<Q", record, QUEUE_CONTEXT_ADDR, context_addr)
    return bytes(record)


def build_queue_pointers(ring_size=0xffffffff):
    """Build a queue's pointer block, empty.

    Every index starts at zero, which is what an unused queue holds, and the ring-size word is all
    ones in every queue observed.
    """
    import struct

    block = bytearray(QUEUE_PTR_BLOCK_SIZE)
    struct.pack_into("<I", block, QUEUE_PTR_RING_SIZE, ring_size)
    return bytes(block)


def build_job_list(self_addr):
    """Build an empty job list.

    The list is intrusive and three 64-bit words. Empty is recognised by its second word pointing
    at the list itself, which is why this needs its own address.
    """
    import struct

    body = bytearray(0x18)
    struct.pack_into("<Q", body, 0x08, self_addr)
    return bytes(body)


def build_event_record(group_number, kind=None, queue_index=0, subtype=None):
    """Build the host-written first record of an event item.

    ``queue_index`` is the queue's index on the queue grid, which the subtype carries in its low
    half. ``kind`` selects the trailing word, which a fragment channel sets and a tiling one does
    not.

    ``subtype`` overrides the whole field for experiments. Hardware captures use the grid-derived form
    for both the initial pair and later submissions on a host-created pair.
    """
    import struct

    record = bytearray(EVENT_RECORD_SIZE)
    struct.pack_into("<I", record, EVENT_RECORD_TYPE, SELECTOR_EVENT)
    struct.pack_into("<I", record, EVENT_RECORD_SUBTYPE,
                     EVENT_SUBTYPE_BASE | (queue_index & 0xffff)
                     if subtype is None else int(subtype))
    struct.pack_into("<I", record, EVENT_RECORD_COUNTER,
                     group_number << EVENT_COUNTER_SHIFT)
    struct.pack_into("<I", record, EVENT_RECORD_UNK10,
                     EVENT_UNK10_BY_KIND.get(kind, 0))
    return bytes(record)

# Selector-0x01 records are a fixed size on a pool stride: every observed
# address difference between two of them is an exact multiple of this value.
RENDER_ITEM_SIZE = 0x2240

# Identical in all 20 selector-0x01 records of one publication. External notes
# describe this offset as a context identifier; only its constancy is confirmed.
RENDER_ITEM_CONTEXT_OFFSET = 0x0c

# Present in all 20 instances of one publication. Reads past RENDER_ITEM_SIZE
# belong to the next pooled record, not to this one.
RENDER_ITEM_POINTER_OFFSETS = (
    0x20, 0x28, 0x30, 0x38,
    0x2140, 0x2148, 0x21a0,
)

# Populated in 5 of 20 instances, and mapped whenever present, so a consumer
# must treat it as optional rather than required.
RENDER_ITEM_OPTIONAL_POINTER_OFFSETS = (0x2198,)

# The 0x28/0x30/0x38 group is progress state rather than work input. Its first
# target holds two equal 32-bit counters, then the value at
# RENDER_ITEM_CONTEXT_OFFSET, then an all-ones sentinel, with the counter
# equal to the selector-0x01 item count. Its third target is entirely zero
# before the doorbell, consistent with a firmware-written completion location.
# Individual roles within the group are unresolved.
RENDER_ITEM_PROGRESS_OFFSETS = (0x28, 0x30, 0x38)

# Selector-0x0f records are an array of equally sized subrecords, each carrying
# pointers at these relative offsets. Some instances hold extra pointer fields
# outside the repeat, so the array is not uniformly populated.
ARRAY_ITEM_SUBRECORD_SIZE = 0x180
ARRAY_ITEM_SUBRECORD_POINTER_OFFSETS = (0x10, 0x78, 0xd0)

# Firmware addresses are encoded in a 44-bit field and must be sign-extended
# using the active virtual-address width before a table walk.
DVA_VA_BITS = 43
DVA_SIGN_BIT = 42

# Sentinel seen in progress state and in unused pointer slots. It is not an
# address and must not be walked.
SENTINEL_ALL_ONES = (1 << 64) - 1


# --- Initdata root -----------------------------------------------------------
# Derived from the captured root object, not from an older generation's schema.
# Two independent sources of evidence are used: the hardware pointer graph,
# which says which offsets hold resolvable addresses, and the UAT geometry
# established by walking live tables, which the root happens to describe.

# Offsets holding addresses, per the captured pointer graph.
INITDATA_ROOT_POINTER_OFFSETS = (0x08, 0x18, 0x20, 0xa8, 0xb0)

# Confirmed: these read 16384, 14 and 3 in the capture, matching the page size
# and page-bit count of the walker and the three table levels below the root.
INITDATA_UAT_PAGE_SIZE = 0x30    # u16
INITDATA_UAT_PAGE_BITS = 0x32    # u8
INITDATA_UAT_NUM_LEVELS = 0x33   # u8

# Three level descriptors follow, one per table level below the root.
INITDATA_UAT_LEVEL_OFFSETS = (0x34, 0x54, 0x74)
UAT_LEVEL_DESC_SIZE = 0x20
# Field offsets within one descriptor. index_shift and num_entries reproduce the
# walker's geometry exactly, which is what confirms this decoding.
UAT_LEVEL_INDEX_SHIFT = 0x03     # u8:  36, 25, 14
UAT_LEVEL_NUM_ENTRIES = 0x04     # u16: 64, 2048, 2048
UAT_LEVEL_TABLE_SIZE = 0x06      # u16: 0x4000 in every descriptor

# Observed but unresolved: 0x00 holds four 16-bit values, and 0x28 holds a zero
# u32 followed by a u32 of 1. Older generations place an address at 0x28; this
# capture does not, and instead carries addresses at 0xa8 and 0xb0 where those
# generations have scalars. Do not assume the older meaning for those three.
INITDATA_ROOT_VER_INFO = 0x00    # 4 x u16, role unresolved
INITDATA_ROOT_UNK_28 = 0x28      # (0, 1), role unresolved


# --- Channel table -----------------------------------------------------------
# The main configuration object at root +0x18 carries the channel table. Its
# first twelve entries were confirmed by comparing every address against the
# channel ring and state addresses recovered independently by tracing live work
# submission, and all twelve matched including their order.
#
# An entry is four addresses, so 0x20 bytes, against two addresses on earlier
# generations: this generation has three state addresses per channel rather than
# one. The table holds 17 entries and ends exactly where the object's populated
# data ends.
# Offsets here are relative to the main configuration object, which begins part
# way into its page: in the observed capture the root's address for it had page
# offset 0x25c0. Offsets taken from a page dump must have that subtracted.
CHANNEL_TABLE_OFFSET = 0x20
CHANNEL_ENTRY_SIZE = 0x20
CHANNEL_ENTRY_STATE_COUNT = 3
CHANNEL_ENTRY_RING_OFFSET = 0x18
CHANNEL_TABLE_ENTRIES = 17

# Work-channel order in the table, confirmed entry by entry. Note the state
# blocks of the work channels lie on a 0x40 grid ordered 3, 2, 1, 0 within each
# workload group, which is not the table order.
CHANNEL_TABLE_WORK_ORDER = (
    "TA_0", "3D_0", "CL_0",
    "TA_1", "3D_1", "CL_1",
    "TA_2", "3D_2", "CL_2",
    "TA_3", "3D_3", "CL_3",
)
CHANNEL_STATE_STRIDE = 0x40

# Work-channel state addresses sit on this spacing inside the compact block.
# Firmware-produced channels 13 and 14 instead name independent split counter
# objects: the state address is host-owned and its firmware peer is at +0x20.
CHANNEL_ENTRY_STATE_SPACING = 0x10
CHANNEL_STATE_CONSUMER = 0
CHANNEL_STATE_PRODUCER = 2
REPORT_CHANNEL_INDICES = (13, 14)
REPORT_STATE_INDICES = (0, 2)
REPORT_PEER_OFFSET = 0x20

# Native channel state is not laid out in channel-table order. Channels 0-12
# occupy one compact block with the work queues permuted by workload/grid. The
# primary root's second status address is the word immediately after that
# block. Channels 13-15 are sparse aliases relative to the first root status
# address; preserving these address identities is part of the descriptor ABI.
NATIVE_WORK_STATE_OFFSETS = (
    0x0c0, 0x1c0, 0x2c0,
    0x080, 0x180, 0x280,
    0x040, 0x140, 0x240,
    0x000, 0x100, 0x200,
    0x300,
)
NATIVE_STATUS_B_OFFSET = 0x340
NATIVE_TRAILING_STATE_OFFSETS = {
    13: (0x00040, 0x002c0, 0x00080),
    14: (0x00240, 0xa6ac0, 0x00280),
    15: (0x2d2c0, None, None),
}
NATIVE_TRAILING_RING_OFFSETS = {
    13: 0x04ac0,
    14: 0xafac0,
}
NATIVE_TRAILING_STATE_SIZE = 0xb4000

# The descriptor graph occupies two address clusters. These are offsets from
# the firmware-context base, confirmed across native captures. The high cluster
# begins at the hardware-data bundle and also contains the work rings and both
# main objects. The low cluster contains both instances' state/status objects,
# their service rings, and the zero state target named by bundle +0x8ed8.
NATIVE_PRIVATE_CLUSTER_OFFSET = 0x00020000
NATIVE_PRIVATE_CLUSTER_SIZE = 0x00178000
NATIVE_PRIMARY_WORK_STATE_OFFSET = 0x00020000
NATIVE_PRIMARY_STATUS_A_OFFSET = 0x0002ee40
NATIVE_SECONDARY_STATUS_A_OFFSET = 0x000e3100
NATIVE_SECONDARY_WORK_STATE_OFFSET = 0x001970c0
NATIVE_HWDATA_STATE_OFFSET = 0x00197480
# The primary root's status-B pointer names a large status/configuration object,
# not merely its 0x80-byte leading block. It ends exactly where status A begins.
NATIVE_PRIMARY_STATUS_B_SIZE = (
    NATIVE_PRIMARY_STATUS_A_OFFSET
    - (NATIVE_PRIMARY_WORK_STATE_OFFSET + NATIVE_STATUS_B_OFFSET))
NATIVE_PRIMARY_STATUS_B_FWCTL_STATE = 0x48e0
NATIVE_PRIMARY_STATUS_B_FWCTL_RING = 0x48e8
NATIVE_FWCTL_OFFSET = 0x001c0000
# The large status object's final 0x6cc bytes contain a 12-byte lifecycle
# header followed by configuration. These are every nonzero byte in the exact
# pre-init capture, before either firmware descriptor is published. Their field
# meanings are unresolved, so preserve them as measured sparse runs instead of
# inventing a structure. Values that change after work begins are represented by
# their pre-init state here.
NATIVE_PRIMARY_STATUS_B_CONFIG_HEADER = 0xe434
NATIVE_PRIMARY_STATUS_B_CONFIG_OFFSET = 0xe440
NATIVE_PRIMARY_STATUS_B_CONFIG_RUNS = (
    (0x010, bytes.fromhex("0f")),
    (0x017, bytes.fromhex("3f")),
    (0x01a, bytes.fromhex("884028")),
    (0x020, bytes.fromhex("01")),
    (0x0c8, bytes.fromhex("f82a")),
    (0x0cc, bytes.fromhex("401f")),
    (0x0d8, bytes.fromhex("52b8a24119041641")),
    (0x0f0, bytes.fromhex("ac26")),
    (0x0f4, bytes.fromhex("c8")),
    (0x10a, bytes.fromhex("c842")),
    (0x10e, bytes.fromhex("c843c8")),
    (0x128, bytes.fromhex("01")),
    (0x12c, bytes.fromhex("4e25")),
    (0x133, bytes.fromhex("3fcdcccc40")),
    (0x14c, bytes.fromhex("01")),
    (0x1c0, bytes.fromhex("01")),
    (0x1c4, bytes.fromhex("01")),
    (0x1c8, bytes.fromhex("04")),
    (0x1cc, bytes.fromhex("01")),
    (0x1d0, bytes.fromhex("01")),
    (0x1d4, bytes.fromhex("01")),
    (0x1d8, bytes.fromhex("01")),
    (0x4e4, bytes.fromhex("01")),
    (0x4e8, bytes.fromhex("f401")),
    (0x4ec, bytes.fromhex("06")),
    (0x4f0, bytes.fromhex("d430")),
    (0x4f4, bytes.fromhex("d430")),
    (0x4f8, bytes.fromhex("d430")),
    (0x4fc, bytes.fromhex("d430")),
    (0x500, bytes.fromhex("d430")),
    (0x504, bytes.fromhex("d430")),
    (0x508, bytes.fromhex("a00f")),
    (0x51c, bytes.fromhex("d430")),
    (0x520, bytes.fromhex("d430")),
    (0x524, bytes.fromhex("d430")),
    (0x528, bytes.fromhex("d430")),
    (0x52c, bytes.fromhex("d430")),
    (0x530, bytes.fromhex("01")),
    (0x58c, bytes.fromhex("06")),
    (0x590, bytes.fromhex("ac0d")),
    (0x594, bytes.fromhex("e803")),
    (0x598, bytes.fromhex("b80b")),
    (0x59c, bytes.fromhex("64")),
    (0x5cc, bytes.fromhex("01")),
    (0x5d0, bytes.fromhex("04")),
    (0x5dc, bytes.fromhex("401f")),
    (0x5e0, bytes.fromhex("c8")),
    (0x5e4, bytes.fromhex("a00f")),
    (0x5e8, bytes.fromhex("c8")),
    (0x5ec, bytes.fromhex("d007")),
    (0x5f0, bytes.fromhex("c8")),
    (0x5f4, bytes.fromhex("e803")),
    (0x5f8, bytes.fromhex("c8")),
    (0x606, bytes.fromhex("7041")),
    (0x60a, bytes.fromhex("a04020")),
    (0x610, bytes.fromhex("e803")),
    (0x620, bytes.fromhex("8403")),
)

# The secondary root's +0xc0 target is an independent 0x80-byte status/config
# object. Its complete pre-init nonzero content is stable across every full
# native capture currently in the corpus.
NATIVE_SECONDARY_ROOT_EXTRA_1_RUNS = (
    (0x014, bytes.fromhex("01")),
    (0x02c, bytes.fromhex("01")),
    (0x030, bytes.fromhex("01")),
    (0x040, bytes.fromhex("01")),
    (0x04c, bytes.fromhex("01")),
    (0x050, bytes.fromhex("6a18")),
)
# The secondary root extends the primary root format by two pointers. Their
# targets are stable offsets in the native low private cluster. Their semantic
# roles are not yet established; the second is the secondary work-state base
# plus NATIVE_STATUS_B_OFFSET.
NATIVE_SECONDARY_ROOT_EXTRA_OFFSETS = (0x0002e780, 0x00197400)
# The first target runs exactly to the primary status-A object. Native
# configuration remains populated well past the first 0x80 bytes, so a closure
# audit must not truncate this unresolved object to a status-block-sized prefix.
NATIVE_SECONDARY_ROOT_EXTRA_0_SIZE = (
    NATIVE_PRIMARY_STATUS_A_OFFSET - NATIVE_SECONDARY_ROOT_EXTRA_OFFSETS[0])

NATIVE_HWDATA_OFFSET = 0xc0788000
NATIVE_WORK_RING_OFFSETS = (
    0x10dc0, 0x16dc0, 0x1cdc0,
    0x0f5c0, 0x155c0, 0x1b5c0,
    0x0ddc0, 0x13dc0, 0x19dc0,
    0x0c5c0, 0x125c0, 0x185c0,
)
NATIVE_PRIMARY_MAIN_OFFSET = 0x1e5c0
NATIVE_SECONDARY_MAIN_OFFSET = 0x22a80
NATIVE_SHARED_CLUSTER_SIZE = 0x28000
NATIVE_HWDATA_REGION_OFFSETS = (0x48000, 0x70000)
NATIVE_PRIMARY_REGION_TRIPLES = (
    (0xc07c8000, 0x01838000),
    (0x015e0000, 0x01840000),
    (0x015e8000, None),
)
# The legacy tuple representation packs the six qwords at main +0x2d0. The
# apparent ``value`` and ``0x70`` words are the low and high halves of full
# context-0 addresses. Native mappings make those two low/high pairs physical
# aliases; the first address is a high-only blank sentinel and the last qword
# is null.
NATIVE_PRIMARY_REGION_ALIASES = (
    (0x015e0000, 0x7001838000),
    (0x015e8000, 0x7001840000),
)
# This page is not named by a raw descriptor pointer. After the two firmware
# instances exchange their first endpoint-0x23 peer messages, the primary
# scheduler accesses +0xe00 within it. The native pre-init image maps the page
# and leaves all 16 KiB zero.
NATIVE_PRIMARY_COMPUTED_PAGE_OFFSET = 0x015d8000
NATIVE_ROOT_OFFSET = 0x1a8000

# --- Device control ----------------------------------------------------------
# The channel that continues the work-channel state grid carries device control.
# Read out of a live ring: messages are 0x40 bytes on a 0x40 grid, twice the
# width of a work ring slot, and the leading u32 is the message type. The first
# three messages a live host sends are all the type below, and the fourth is a
# different type carrying an address, so the type below is what brings the device
# up rather than something periodic that happens to come first.
CONTROL_MESSAGE_SIZE = 0x40

# Ring indices are validated below 0x100, so a service ring holding 0x40-byte
# entries needs 256 of them. The work rings are a different shape entirely and keep
# their own stride.
SERVICE_RING_SIZE = 0x40 * 0x100
CONTROL_MESSAGE_TYPE = 0x00      # u32
CONTROL_MESSAGE_INIT = 0x16

# The opening sequence is three entries of that opcode with no payload, staged
# together, with the producer set to cover all three before firmware is notified
# once. Firmware then advances both completion counters through all three.
# One message is staged, not three. The three seen in a running system's ring had
# accumulated by then; at handoff there is exactly one, with the producer at one.
CONTROL_INIT_ENTRIES = 1

# The control-only instance opens with a different opcode, the same value its main
# configuration object carries as its interval.
CONTROL_MESSAGE_INIT_SECONDARY = 0x2a

# Hardware data and the five bare addresses in the primary main object are views
# into one contiguous allocation. The last two views overlap by all but 0x80.
# Keeping these relationships matters: firmware uses offsets within the shared
# allocation rather than treating the pointers as five independent objects.
HWDATA_BUNDLE_SIZE = 0xc000

# The main object repeats an address at +0x08 and +0x10, and it is not the bundle
# base: both instances name the bundle plus this offset, which is past the bundle's
# own 0xc000. It reads zero at handoff, so it is a region firmware writes into and a
# host only has to provide it mapped. Measured on both instances of a live capture.
MAIN_REPEATED_ADDR_OFFSET = 0xc500

# So the allocation has to reach past the repeated address, not just the bundle.
HWDATA_BUNDLE_ALLOC_SIZE = 0x10000

# The accelerator's device-tree carveouts. Firmware maps the shared one itself: its
# own fault report lists that region's physical address among its code and data
# mappings. A capture of a running machine has thousands of non-zero bytes in it.
FIXED_REGION_SNAPSHOT = ("/Users/user/asahi_re/artifacts/agx_g17p/"
                         "initdata_pre_submit_all_uat_roots_v2_20260724_150935")
MAIN_ADDR_OBJECT_OFFSETS = (0x2740, 0x3380, 0x4400, 0xbc80, 0xbd00)
# The last two views extend past the bundle's own 0xc000. Their sizes were once cut
# off exactly at 0xc000, on the reading that a capture had run past the end of the
# view into unrelated memory, which discarded 23 runs from each. That reading was
# wrong on both counts: the repeated address proves the allocation continues past
# 0xc000, and every one of those runs matches an independent later capture byte for
# byte. The sizes now reflect where the content actually ends.
MAIN_ADDR_OBJECT_VALID_SIZES = (0x18c0, 0x0c80, 0x3c00, 0x3380, 0x3300)
# This field in the third bundle page points at a separate, initially zero state
# object. Firmware reads at least through +0x680 after acknowledging initdata.
HWDATA_BUNDLE_STATE_PTR = 0x8ed8
# The state object is not placed freely. In a native capture it sits exactly 0xc0
# above the second instance's device-control state block, while the first
# instance's control state is in an unrelated region, so the relation is to the
# second instance. Its captured extent is 0xb80. The same kind of fixed relation
# is what the secondary's own main-object pointer turned out to be.
HWDATA_STATE_AFTER_CONTROL_STATE = 0xc0
HWDATA_STATE_SIZE = 0xb80
# The secondary's post-init task holds a pointer to this pair when selecting its
# next state object. The values are stable across four independent captures.
HWDATA_BUNDLE_SELECT_VALUES = (0xaeec, bytes.fromhex("cdccc841cdccc841"))
# Other nonzero bytes in the bundle's third page that are identical across four
# independent captures. The only DVA in this page is modeled separately above.
HWDATA_BUNDLE_STATIC_RUNS = (
    (0x080ac, bytes.fromhex("06")),
    (0x080b8, bytes.fromhex("01")),
    (0x08177, bytes.fromhex("ac0d")),
    (0x0817b, bytes.fromhex("e803")),
    (0x0817f, bytes.fromhex("b80b")),
    (0x08183, bytes.fromhex("e803")),
    (0x08187, bytes.fromhex("e803")),
    (0x0818b, bytes.fromhex("64")),
    (0x0818f, bytes.fromhex("20")),
    (0x081b4, bytes.fromhex("04")),
    (0x081c2, bytes.fromhex("783f")),
    (0x081cb, bytes.fromhex("3d")),
    (0x081d2, bytes.fromhex("a040")),
    (0x081de, bytes.fromhex("8047")),
    (0x081e2, bytes.fromhex("7041")),
    (0x081ec, bytes.fromhex("8403")),
    (0x081f0, bytes.fromhex("e803")),
    (0x081f4, bytes.fromhex("e803")),
    (0x08200, bytes.fromhex("e803")),
    (0x08234, bytes.fromhex("e803")),
    (0x08274, bytes.fromhex("64")),
    (0x08290, bytes.fromhex("2a08")),
    (0x08298, bytes.fromhex("7d")),
    (0x0829c, bytes.fromhex("01")),
    (0x08ee0, bytes.fromhex("ae18")),
    (0x08ee8, bytes.fromhex("01")),
    HWDATA_BUNDLE_SELECT_VALUES,
    (0x0b5e4, bytes.fromhex("01")),
    (0x0b5e8, bytes.fromhex("f401")),
    (0x0b5ec, bytes.fromhex("06")),
    (0x0b5f0, bytes.fromhex("d430")),
    (0x0b5f4, bytes.fromhex("d430")),
    (0x0b5f8, bytes.fromhex("d430")),
    (0x0b5fc, bytes.fromhex("d430")),
    (0x0b600, bytes.fromhex("d430")),
    (0x0b604, bytes.fromhex("d430")),
    (0x0b608, bytes.fromhex("a00f")),
    (0x0b61c, bytes.fromhex("d430")),
    (0x0b620, bytes.fromhex("d430")),
    (0x0b624, bytes.fromhex("d430")),
    (0x0b628, bytes.fromhex("d430")),
    (0x0b62c, bytes.fromhex("d430")),
    (0x0b630, bytes.fromhex("01")),
    (0x0b7a8, bytes.fromhex("01")),
    (0x0b7b4, bytes.fromhex("cdcc4c42")),
    (0x0b7f5, bytes.fromhex("800644")),
    (0x0b834, bytes.fromhex("9a99c941")),
    (0x0b8e0, bytes.fromhex("6a18")),
)

# The secondary main object carries one additional unaligned pointer into the
# third primary view. The pointer lands five bytes before that view's first
# populated run.
SECONDARY_EXTRA_ADDR_OBJECT = 2
SECONDARY_EXTRA_ADDR_OFFSET = 0xe40

# The control-start notification carries a zero channel field rather than the
# device-control channel number: the whole message is the type in the top bits and
# nothing else. It is what makes firmware service the device-control ring for the
# first time, so a host that sends it with a channel number gets no response.
CONTROL_START_CHANNEL = 0

# Written zero before the initialisation message, as part of the observed start
# sequence, at this offset from the accelerator's register base.
SGX_PRE_INIT_REGISTER = 0xd06030

# Doorbell channel number for device control. The work channels use
# (queue << 2) | kind, which leaves this value free, and it is the number earlier
# parts use for the same channel.
CONTROL_DOORBELL_CHANNEL = 0x11

# The endpoint the first instance messages when its scheduler wakes, on a mailbox
# separate from the one the host talks on. Firmware never advertises it in its
# endpoint map, so a host is not expected to serve it.
PEER_ENDPOINT = 0x23

# Entries past the twelve work channels are additional channels whose roles are
# not yet established. Entry 12 continues the work-channel state grid; entries 13
# and 14 take their state addresses from a different region; entry 15 carries only
# a first address and entry 16 is empty.
CHANNEL_TABLE_WORK_COUNT = 12

# The trailing entries are not fully populated. This one carries a first state
# address and no ring, and everything past it is entirely zero. Filling them like
# the rest declares channels that do not exist.
CHANNEL_PARTIAL_ENTRY = 15


def parse_channel_table(page, offset=CHANNEL_TABLE_OFFSET):
    """Decode the channel table out of the main configuration object."""
    import struct

    entries = []
    for index in range(CHANNEL_TABLE_ENTRIES):
        base = offset + index * CHANNEL_ENTRY_SIZE
        words = struct.unpack_from("<4Q", page, base)
        entries.append({
            "index": index,
            "offset": base,
            "name": CHANNEL_TABLE_WORK_ORDER[index]
                    if index < CHANNEL_TABLE_WORK_COUNT else None,
            "state_addrs": list(words[:CHANNEL_ENTRY_STATE_COUNT]),
            "ring_addr": words[3],
        })
    return entries


# --- Mapped register regions -------------------------------------------------
# One object reached from the main configuration object holds addresses in this
# range. The pages do not exist in captured memory and each resolves to a device
# register address, so the range maps hardware registers rather than memory.
# Confirmed windows cover the graphics accelerator, the memory controller, the
# interrupt controller, the power manager, and a neural accelerator range.
REGISTER_VA_BASE = 0xfffffc2180000000
REGISTER_VA_END = 0xfffffc2190000000

# Mappings are a sparse array of 0x28-byte entries inside the hardware-data
# object, which is the object the main configuration object references at
# +0x25c0. Every populated entry offset is an exact multiple of the stride from
# the base, and unused slots are zero.
#
# The decoding is self-verifying: for all 18 populated entries, translating the
# entry's device address through the live tables yields exactly the physical
# address the same entry records.
REGISTER_MAP_ARRAY_OFFSET = 0x640
REGISTER_MAP_ENTRY_SIZE = 0x28
# The array runs to at least slot 52. Scanning past it picks up the
# performance-state tables as false entries, so a scan must be bounded. Slots may
# also carry only the flag at 0x20, declared but not mapped.
REGISTER_MAP_SLOT_COUNT = 53
REGISTER_MAP_PHYS = 0x00        # u64
REGISTER_MAP_DEVICE_VA = 0x08   # u64
REGISTER_MAP_SIZE = 0x10        # u32, a byte count and not always a granule multiple
REGISTER_MAP_SIZE2 = 0x14       # u32, identical to the first size in every entry
REGISTER_MAP_UNK_18 = 0x18      # u64, low 24 bits of the physical address for
                                # accelerator-internal windows, else zero
REGISTER_MAP_FLAG = 0x20        # u32, 2 in sixteen entries and 0 in two

# The performance-state tables live in this same object. Two ladders of 11 states
# share their low six entries and then alternate through the device tree's single
# 16-entry table. The index maps below are what prove that: they are the ladders'
# own index lists into the device tree table, held by firmware.
FREQ_LADDER_ENTRIES = 11
HWDATA_FREQ_LADDER_A_OFFSET = 0xfc8          # MHz per state
HWDATA_FREQ_LADDER_B_OFFSETS = (0x1808, 0x1cdc)
HWDATA_RELATIVE_LADDER_A_OFFSET = 0x18c8     # rises to 100, units unresolved
HWDATA_RELATIVE_LADDER_B_OFFSET = 0x1908
HWDATA_INDEX_MAP_A_OFFSET = 0x19c8           # (0,1,2,3,4,5,7,9,11,13,15)
HWDATA_INDEX_MAP_B_OFFSET = 0x1a08           # (0,1,2,3,4,5,6,8,10,12,14)

# Per-state voltage blocks. Each state owns a 0x40 block holding the same value
# repeated, so the value is per-state and the repeat is per some unit within the
# device. Both tables match the device tree voltage columns selected by index
# map A exactly.
HWDATA_STATE_BLOCK_STRIDE = 0x40
HWDATA_CORE_VOLTAGE_OFFSET = 0x1008
HWDATA_MEMORY_VOLTAGE_OFFSET = 0x1408


# The performance-state ladders, read out of a live hardware-data object. Eleven
# states. The two index maps are each ladder's own list of positions into the
# device tree's sixteen-entry table, which is what proves the pairing; the two
# ladders share their low six entries and then alternate.
#
# A descriptor is accepted with these zeroed, so they are not needed to reach an
# acknowledgement. Whether firmware needs real values before it will schedule is
# a separate question, and this table is what lets it be asked.
PERF_TABLES = {
    "freq_a":          [0, 338, 492, 618, 796, 928, 1056, 1170, 1278, 1338, 1470],
    "freq_b":          [0, 338, 492, 618, 796, 928, 952, 1053, 1152, 1204, 1326],
    "scale_b":         [1065520988, 1065520988, 1065520988, 1065520988, 1065520988, 1065520988, 1065520988, 1065520988, 1065520988, 1065520988, 1065520988],
    "relative_a":      [0, 16, 23, 30, 43, 57, 74, 85, 90, 92, 100],
    "relative_b":      [0, 0, 13, 24, 40, 52, 63, 73, 83, 88, 100],
    "index_a":         [0, 1, 2, 3, 4, 5, 7, 9, 11, 13, 15],
    "index_b":         [0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14],
    "core_voltage":    [125, 595, 615, 635, 685, 730, 780, 815, 865, 885, 955],
    "memory_voltage":  [765, 765, 765, 765, 765, 765, 780, 815, 865, 885, 955],
    "voltage_repeat":  16,
}

def parse_perf_tables(page):
    """Decode the performance-state tables from the hardware-data object."""
    import struct

    def ladder(offset):
        return list(struct.unpack_from("<%dI" % FREQ_LADDER_ENTRIES, page, offset))

    def per_state(offset):
        return [struct.unpack_from("<I", page, offset + i * HWDATA_STATE_BLOCK_STRIDE)[0]
                for i in range(FREQ_LADDER_ENTRIES)]

    return {
        "freq_mhz_a": ladder(HWDATA_FREQ_LADDER_A_OFFSET),
        "freq_mhz_b": [ladder(o) for o in HWDATA_FREQ_LADDER_B_OFFSETS],
        "relative_a": ladder(HWDATA_RELATIVE_LADDER_A_OFFSET),
        "relative_b": ladder(HWDATA_RELATIVE_LADDER_B_OFFSET),
        "index_map_a": ladder(HWDATA_INDEX_MAP_A_OFFSET),
        "index_map_b": ladder(HWDATA_INDEX_MAP_B_OFFSET),
        "core_voltage": per_state(HWDATA_CORE_VOLTAGE_OFFSET),
        "memory_voltage": per_state(HWDATA_MEMORY_VOLTAGE_OFFSET),
    }


# The populated register-mapping entries, as read out of a live hardware-data
# object. Each entry names a physical register window and the address the
# firmware reaches it at, and the decoding is self-verifying: translating the
# recorded device address through the live tables yields the recorded physical
# address for every one of them. A host that starts firmware itself has to
# both map these windows and declare them here, since firmware reaches its own
# registers through this table and not through any fixed address.
#
# Two entries are not granule aligned and share the same offset within their
# page, so mapping the containing page places them correctly.
REGISTER_WINDOWS = (
    # slot, physical, device address, size, low-address echo, flag
    ( 0, 0x00301014000, 0xfffffc2180000000, 0x004000, 0x000000, 2),
    ( 3, 0x00220104000, 0xfffffc2180008000, 0x018000, 0x000000, 2),
    ( 9, 0x003003d0000, 0xfffffc2180028000, 0x001000, 0x000000, 2),
    (10, 0x003003c0000, 0xfffffc2180030000, 0x002000, 0x000000, 0),
    (12, 0x0040165c000, 0xfffffc2180038000, 0x004000, 0x000000, 2),
    (14, 0x00300280000, 0xfffffc2180040000, 0x008000, 0x000000, 0),
    (17, 0x00480000000, 0xfffffc2180050000, 0x021400, 0x000000, 2),
    (22, 0x00481000000, 0xfffffc2180078000, 0x008000, 0x000000, 2),
    (26, 0x00480d04000, 0xfffffc2180088000, 0x008000, 0xd04000, 2),
    (27, 0x00480d0d000, 0xfffffc2180099000, 0x001000, 0xd0d000, 2),
    (28, 0x00480d58000, 0xfffffc21800a0000, 0x008000, 0xd58000, 2),
    (29, 0x00480d10000, 0xfffffc21800b0000, 0x004000, 0xd10000, 2),
    (31, 0x00480d40000, 0xfffffc21800b8000, 0x004000, 0xd40000, 2),
    (32, 0x00480d60000, 0xfffffc21800c0000, 0x004000, 0xd60000, 2),
    (35, 0x00480e00000, 0xfffffc21800c8000, 0x004000, 0xe00000, 2),
    (39, 0x00480e08000, 0xfffffc21800d0000, 0x008000, 0x000000, 2),
    (40, 0x00480e1c000, 0xfffffc21800e0000, 0x004000, 0xe1c000, 2),
    (41, 0x00480e1f800, 0xfffffc21800eb800, 0x004000, 0x000000, 2),
)

# Slots that carry a flag but map nothing. They are declared the same way in
# every capture, so firmware is told the slot exists and is empty rather than
# the slot simply being absent.
REGISTER_FLAG_ONLY_SLOTS = {
     2: 2,
     5: 2,
     6: 2,
     7: 2,
     8: 2,
    30: 2,
    33: 2,
    34: 2,
    37: 2,
    38: 2,
    42: 2,
    43: 2,
    46: 2,
    47: 2,
    48: 2,
    49: 2,
    52: 2,
}

# The physical bases of the mapped register windows, for comparing the state of a
# machine this host brought up against one brought up normally.
# Only the accelerator window is safe for the host processor to read. The other
# entries in the table are addresses the accelerator reaches, and several of them
# fault the host when read directly: an attempt to read four words from each of the
# eighteen took the machine down. A host driver should treat this table as
# describing what to map for the accelerator, not as a list of readable registers.
REGISTER_WINDOW_BASES = (0x480000000,)
REGISTER_WINDOW_BASES_ALL = tuple(w[1] for w in REGISTER_WINDOWS)


# The five bare addresses in the main configuration object point at views with
# real content inside the contiguous hardware-data bundle. A host that supplies
# blank pages there is not giving firmware what it needs. The views captured at
# handoff hold no addresses at all, only data, so their populated runs can be
# reproduced verbatim. Offsets are relative to each view, not to the bundle.
#
# Their meaning is not established. They are recorded as bytes because that is
# what is known: the alternative is inventing a field model for them.
MAIN_ADDR_OBJECTS = (
    {  # addr0
        "size": 0x38c0,
        "runs": (
            (0x01658, bytes.fromhex("ffffffff")),
            (0x01670, bytes.fromhex("ffffffff")),
        ),
    },
    {  # addr1
        "size": 0x3c80,
        "runs": (
            (0x00a18, bytes.fromhex("ffffffff")),
            (0x00a30, bytes.fromhex("ffffffff")),
        ),
    },
    {  # addr2
        "size": 0x3c00,
        "runs": (
            (0x00e45, bytes.fromhex("dc050000dc050000000000040000000000803f")),
            (0x00e6c, bytes.fromhex("0100000001")),
            (0x00e80, bytes.fromhex("6400000001000000e80300000000000064")),
            (0x00ea0, bytes.fromhex("040000000000803f000000000100000001")),
            (0x00ec0, bytes.fromhex("6400000001000000e80300000000000064")),
            (0x00f00, bytes.fromhex("5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f")),
            (0x017f8, bytes.fromhex("7102")),
            (0x01804, bytes.fromhex("9f2e7f3f000000005461513b000000008695a53c")),
            (0x01821, bytes.fromhex("381546db0fa940000000004473d6bd28000000e8030000e803")),
            (0x01844, bytes.fromhex("4e25")),
            (0x01878, bytes.fromhex("e803")),
            (0x018b0, bytes.fromhex("04")),
            (0x018c6, bytes.fromhex("803f00000000cdcccc40")),
            (0x018da, bytes.fromhex("80470000003f000000000000000028000000e803")),
            (0x018fc, bytes.fromhex("4e25")),
            (0x01908, bytes.fromhex("100000000000000000dc05")),
            (0x01968, bytes.fromhex("5c0000000000000064000000220000000600000000000000060000000100000000000000cdcc4c3fb6f37d3fcdcc4c3e6f12033cd8d4693fd8d4693f000000000000be42c3f56440c3f564403694174164000000e803000064")),
            (0x019cc, bytes.fromhex("5c")),
            (0x01a00, bytes.fromhex("64")),
            (0x01a20, bytes.fromhex("01040000006400000000000000401f0000c8000000a00f0000c8000000d0070000c8000000e8030000c800000001")),
            (0x01aa4, bytes.fromhex("01")),
            (0x01ad0, bytes.fromhex("01")),
            (0x02ad7, bytes.fromhex("ff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7f")),
            (0x030da, bytes.fromhex("80470000204200007a44be05")),
            (0x030f8, bytes.fromhex("28")),
            (0x03102, bytes.fromhex("c842e803000000000000cdcc4c3fcdcc4c3e")),
            (0x03150, bytes.fromhex("2a08000000000000401f00000000000004")),
            (0x03176, bytes.fromhex("803f0000000019041641")),
            (0x0318a, bytes.fromhex("804752b8a241000000000000000028000000e8030000e803")),
            (0x031ac, bytes.fromhex("f82a")),
            (0x031e0, bytes.fromhex("e803")),
            (0x033fc, bytes.fromhex("06000042")),
            (0x03612, bytes.fromhex("52b87e3f000000000ad7a33b000000000000c843")),
            (0x03630, bytes.fromhex("80470000c842000000000000c8ba84030000e8030000e80300000000000000803b45ac26")),
            (0x03686, bytes.fromhex("e803")),
            (0x036a2, bytes.fromhex("c8")),
            (0x03758, bytes.fromhex("e803")),
            (0x0376c, bytes.fromhex("01")),
            (0x037a0, bytes.fromhex("010100000004")),
            (0x037bd, bytes.fromhex("3f0200000100000001")),
            (0x037dd, bytes.fromhex("400200000100000001")),
            (0x037fd, bytes.fromhex("4102")),
            (0x03848, bytes.fromhex("01000000000000004e2500004e2500004e25")),
            (0x0386a, bytes.fromhex("803f040000001000000000dc05")),
            (0x03944, bytes.fromhex("3c")),
            (0x03950, bytes.fromhex("efee6e3f000000008988883d000000000000003f")),
            (0x0396e, bytes.fromhex("804700008840000000000000000028000000e8030000e803000000000000003815464e25")),
            (0x0399c, bytes.fromhex("f00000000000000000e457")),
            (0x039c4, bytes.fromhex("e803")),
            (0x03a04, bytes.fromhex("01")),
            (0x03ad4, bytes.fromhex("320000000100000000000000398e633fabaa2a3f398ee33dabaaaa3ecdcc4cbfcdcc4cbf00000000000080470000a0c00000a0c00000000064000000e803000064")),
            (0x03b1e, bytes.fromhex("7a467805")),
            (0x03b2c, bytes.fromhex("900000003000000000bc340000000000009411")),
            (0x03b4a, bytes.fromhex("8047")),
            (0x03b70, bytes.fromhex("803e000002000000c40900000d020000020000000400000032")),
            (0x03bba, bytes.fromhex("8047")),
            (0x03bc8, bytes.fromhex("28000000e803")),
        ),
    },
    {  # addr3
        "size": 0x3380,
        "runs": (
            (0x015c5, bytes.fromhex("dc050000dc050000000000040000000000803f")),
            (0x015ec, bytes.fromhex("0100000001")),
            (0x01600, bytes.fromhex("6400000001000000e80300000000000064")),
            (0x01620, bytes.fromhex("040000000000803f000000000100000001")),
            (0x01640, bytes.fromhex("6400000001000000e80300000000000064")),
            (0x01680, bytes.fromhex("5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f")),
            (0x01f78, bytes.fromhex("7102")),
            (0x01f84, bytes.fromhex("9f2e7f3f000000005461513b000000008695a53c")),
            (0x01fa1, bytes.fromhex("381546db0fa940000000004473d6bd28000000e8030000e803")),
            (0x01fc4, bytes.fromhex("4e25")),
            (0x01ff8, bytes.fromhex("e803")),
            (0x02030, bytes.fromhex("04")),
            (0x02046, bytes.fromhex("803f00000000cdcccc40")),
            (0x0205a, bytes.fromhex("80470000003f000000000000000028000000e803")),
            (0x0207c, bytes.fromhex("4e25")),
            (0x02088, bytes.fromhex("100000000000000000dc05")),
            (0x020e8, bytes.fromhex("5c0000000000000064000000220000000600000000000000060000000100000000000000cdcc4c3fb6f37d3fcdcc4c3e6f12033cd8d4693fd8d4693f000000000000be42c3f56440c3f564403694174164000000e803000064")),
            (0x0214c, bytes.fromhex("5c")),
            (0x02180, bytes.fromhex("64")),
            (0x021a0, bytes.fromhex("01040000006400000000000000401f0000c8000000a00f0000c8000000d0070000c8000000e8030000c800000001")),
            (0x02224, bytes.fromhex("01")),
            (0x02250, bytes.fromhex("01")),
            (0x03257, bytes.fromhex("ff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff")),
        ),
    },
    {  # addr4
        "size": 0x3300,
        "runs": (
            (0x01545, bytes.fromhex("dc050000dc050000000000040000000000803f")),
            (0x0156c, bytes.fromhex("0100000001")),
            (0x01580, bytes.fromhex("6400000001000000e80300000000000064")),
            (0x015a0, bytes.fromhex("040000000000803f000000000100000001")),
            (0x015c0, bytes.fromhex("6400000001000000e80300000000000064")),
            (0x01600, bytes.fromhex("5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f")),
            (0x01ef8, bytes.fromhex("7102")),
            (0x01f04, bytes.fromhex("9f2e7f3f000000005461513b000000008695a53c")),
            (0x01f21, bytes.fromhex("381546db0fa940000000004473d6bd28000000e8030000e803")),
            (0x01f44, bytes.fromhex("4e25")),
            (0x01f78, bytes.fromhex("e803")),
            (0x01fb0, bytes.fromhex("04")),
            (0x01fc6, bytes.fromhex("803f00000000cdcccc40")),
            (0x01fda, bytes.fromhex("80470000003f000000000000000028000000e803")),
            (0x01ffc, bytes.fromhex("4e25")),
            (0x02008, bytes.fromhex("100000000000000000dc05")),
            (0x02068, bytes.fromhex("5c0000000000000064000000220000000600000000000000060000000100000000000000cdcc4c3fb6f37d3fcdcc4c3e6f12033cd8d4693fd8d4693f000000000000be42c3f56440c3f564403694174164000000e803000064")),
            (0x020cc, bytes.fromhex("5c")),
            (0x02100, bytes.fromhex("64")),
            (0x02120, bytes.fromhex("01040000006400000000000000401f0000c8000000a00f0000c8000000d0070000c8000000e8030000c800000001")),
            (0x021a4, bytes.fromhex("01")),
            (0x021d0, bytes.fromhex("01")),
            (0x031d7, bytes.fromhex("ff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff")),
        ),
    },
)

def parse_register_mappings(page, count=REGISTER_MAP_SLOT_COUNT):
    """Decode the register-mapping array from the hardware-data object.

    Only slots carrying a device address in the register range are returned, so
    declared-but-unmapped slots and anything past the array are excluded.
    """
    import struct

    entries = []
    for index in range(count):
        base = REGISTER_MAP_ARRAY_OFFSET + index * REGISTER_MAP_ENTRY_SIZE
        if base + REGISTER_MAP_ENTRY_SIZE > len(page):
            break
        phys, device_va = struct.unpack_from("<QQ", page, base)
        if not is_register_va(device_va):
            continue
        size, size2 = struct.unpack_from("<II", page, base + REGISTER_MAP_SIZE)
        entries.append({
            "index": index,
            "offset": base,
            "phys": phys,
            "device_va": device_va,
            "size": size,
            "size2": size2,
            "unk_18": struct.unpack_from("<Q", page, base + REGISTER_MAP_UNK_18)[0],
            "flag": struct.unpack_from("<I", page, base + REGISTER_MAP_FLAG)[0],
        })
    return entries


def is_register_va(value):
    """True if ``value`` falls in the mapped register-region address range."""
    return REGISTER_VA_BASE <= value < REGISTER_VA_END


def parse_initdata_root(page):
    """Decode the confirmed parts of a captured initdata root object.

    ``page`` is the raw bytes of the root object. Returns the UAT geometry it
    describes plus the raw values of the offsets whose role is unresolved, so a
    caller can compare a fresh capture against the recorded observations.
    """
    import struct

    levels = []
    for offset in INITDATA_UAT_LEVEL_OFFSETS:
        descriptor = page[offset:offset + UAT_LEVEL_DESC_SIZE]
        levels.append({
            "index_shift": descriptor[UAT_LEVEL_INDEX_SHIFT],
            "num_entries": struct.unpack_from(
                "<H", descriptor, UAT_LEVEL_NUM_ENTRIES)[0],
            "table_size": struct.unpack_from(
                "<H", descriptor, UAT_LEVEL_TABLE_SIZE)[0],
        })

    return {
        "page_size": struct.unpack_from("<H", page, INITDATA_UAT_PAGE_SIZE)[0],
        "page_bits": page[INITDATA_UAT_PAGE_BITS],
        "num_levels": page[INITDATA_UAT_NUM_LEVELS],
        "levels": levels,
        "pointers": {
            offset: struct.unpack_from("<Q", page, offset)[0]
            for offset in INITDATA_ROOT_POINTER_OFFSETS
        },
        "ver_info": list(struct.unpack_from("<4H", page, INITDATA_ROOT_VER_INFO)),
        "unk_28": list(struct.unpack_from("<2I", page, INITDATA_ROOT_UNK_28)),
    }


def mbox_selector(message):
    """Return the message selector from a 64-bit mailbox word."""
    return (message >> MBOX_TYPE_SHIFT) & MBOX_TYPE_MASK


def mbox_address(message):
    """Return the address payload from a 64-bit mailbox word."""
    return message & MBOX_ADDR_MASK


def work_doorbell(message=0):
    """Build the work-ring doorbell word.

    Only the selector field is established. The low bits observed on hardware
    are reproduced verbatim by the caller rather than composed here, because
    their encoding is unresolved.
    """
    return (MSG_WORK_DOORBELL << MBOX_TYPE_SHIFT) | mbox_address(message)


def next_producer(producer):
    """Advance an 8-bit wrapping producer counter."""
    return (producer + 1) & PRODUCER_MASK


def ring_slot_address(ring_base, index):
    """Address of one ring slot, wrapping at the ring's slot count."""
    return ring_base + (index % RING_SLOT_COUNT) * RING_SLOT_SIZE


def ring_slots(data):
    """Yield (offset, queue_pointer, flags_head) for populated ring slots.

    ``data`` is one or more consecutive 0x18-byte slots read from a ring.
    """
    import struct

    for offset in range(0, len(data) - RING_SLOT_SIZE + 1, RING_SLOT_SIZE):
        slot = data[offset:offset + RING_SLOT_SIZE]
        if not any(slot):
            continue
        pointer = struct.unpack_from("<Q", slot, RING_SLOT_QUEUE_PTR)[0]
        flags_head = struct.unpack_from("<I", slot, RING_SLOT_FLAGS_HEAD)[0]
        if pointer:
            yield offset, pointer, flags_head


def outer_queue_pointers(record):
    """Deprecated name for :func:`ring_slots`, yielding (offset, pointer)."""
    for offset, pointer, _ in ring_slots(record):
        yield offset, pointer


def is_dva(value):
    """True if ``value`` looks like a canonical sign-extended firmware address."""
    if value == SENTINEL_ALL_ONES:
        return False
    low = value & ((1 << DVA_VA_BITS) - 1)
    high = ((1 << 64) - 1) ^ ((1 << DVA_VA_BITS) - 1)
    return value == (low | high) and bool(low & (1 << DVA_SIGN_BIT))
