# SPDX-License-Identifier: MIT
"""T8140/G17P compute work-item and direct-CDM builders.

The layouts in this module are constructed field by field from hardware-tested
G17P submissions.  They contain no captured page contents.  Unknown constants
remain named constants so that experiments can vary them without treating an
opaque byte image as an ABI.
"""

import struct


PAGE_SIZE = 0x4000

COMPUTE_SELECTOR = 3
COMPUTE_DESCRIPTOR_SIZE = PAGE_SIZE
COMPUTE_REGISTER_START = 0x40
COMPUTE_REGISTER_CAPACITY = 128
COMPUTE_REGISTER_SIZE = 0x0c
COMPUTE_SECONDARY_REGISTER_START = 0x760

COMPUTE_HEADER_U16 = (0x22, 0x23, 0x23, 0x24)

# The second register program mirrors four scratch addresses from the main
# program.  The permutation is stable across four independent native boots.
COMPUTE_SECONDARY_REGISTERS = (
    (0x10099, 0x0A5C1),
    (0x10091, 0x0A5C9),
    (0x0A5C1, 0x10099),
    (0x0A5C9, 0x10091),
)

# Scalar fields outside the two register arrays.  Their functional names are
# intentionally conservative where hardware testing has established only the
# value and location.
COMPUTE_FIXED_U32 = {
    0xE68: 0x00300004,  # secondary count=4, byte length=4*12
    0xF28: 0xFFFFFFFF,
    0xF50: 0x00000100,
}

COMPUTE_PRIMARY_COUNT = 0x748

# Encoder parameters embedded near the tail of the compute descriptor.  The
# sampler array is deliberately unaligned; do not round this block to qwords.
COMPUTE_ENCODER_PARAMS = 0xF14
COMPUTE_SAMPLER_ARRAY = COMPUTE_ENCODER_PARAMS + 0x18
COMPUTE_SAMPLER_COUNT = COMPUTE_ENCODER_PARAMS + 0x20
COMPUTE_SAMPLER_MAX = COMPUTE_ENCODER_PARAMS + 0x24

# Queue/client state supplied by ``drm_asahi_cmd_compute`` on register-array
# firmware generations. Keep this order: it is the order used by the upstream
# command builder and places queue-specific state immediately after the six
# preemption/control-stream registers.
COMPUTE_UAPI_REGISTERS = (
    0x10071,  # USC_EXEC_BASE_CP
    0x11841,  # helper binary offset and enable tags
    0x11849,  # helper data DVA
    0x11F81,  # helper configuration
)

COMPUTE_DISPATCH_A = 0xFFFFFC20001C8028
COMPUTE_DISPATCH_B = 0xFFFFFC20C07C0028
COMPUTE_STATUS_A = 0xFFFFFC2000024C68
COMPUTE_STATUS_B = 0xFFFFFC2000024C70
COMPUTE_SHARED_CONTROL = 0xFFFFFC20C0998000
COMPUTE_ZERO_PAGE = 0xFFFFFC2001710000

COMPUTE_OPTIONAL_SIZE = 0xC0
COMPUTE_OPTIONAL_SELECTOR = 0x0F
COMPUTE_EVENT_SIZE = 0x400

COMPUTE_QUEUE_CONTEXT_SIZE = PAGE_SIZE
COMPUTE_QUEUE_CONTEXT_EXTENT = 8 * PAGE_SIZE
COMPUTE_QUEUE_CONTEXT_RECORD_SIZE = 0x200
COMPUTE_QUEUE_CONTEXT_RECORDS = (
    COMPUTE_QUEUE_CONTEXT_EXTENT // COMPUTE_QUEUE_CONTEXT_RECORD_SIZE)

COMPUTE_SHARED_SUPPORT_SIZE = PAGE_SIZE
COMPUTE_SHARED_STATE_SIZE = PAGE_SIZE
COMPUTE_SCHEDULER_SLOT_SIZE = 0x40

# The final native pre-CL2 context-3 table has entries 0..20 populated and is
# zero from +0x540 onward.
COMPUTE_OPERAND_TABLE_ENTRIES = 21
COMPUTE_OPERAND_TABLE_STRIDE = 0x40
COMPUTE_OPERAND_BUFFER_STRIDE = 0x108000
COMPUTE_OPERAND_BUFFER_SIZE = 0x100000
COMPUTE_OPERAND_BUFFER_FLAG = 0x1000000000000000

COMPUTE_CLASS2_POOL_RECORDS = 80
COMPUTE_CLASS2_POOL_RECORD_STRIDE = 0x80
COMPUTE_CLASS2_POOL_SLOT_OFFSET = 0x280
COMPUTE_CLASS2_POOL_INDEX_BASE = 0x808000
COMPUTE_CLASS2_POOL_INDEX_PERIOD = 36
COMPUTE_CLASS2_PREDECESSOR_RECORDS = 36
COMPUTE_CLASS2_PREDECESSOR_RECORD_STRIDE = 0x100

# Active state measured at the first native CL_0 publication.  Record zero is
# the reserved/inactive entry; records 1..9 belong to the already-open channel
# set.  The one value of 3 corresponds to record 5, all other active records
# carry 5 in both state fields.
COMPUTE_CLASS2_POOL_ACTIVE = (5, 5, 5, 5, 3, 5, 5, 5, 5)
COMPUTE_CLASS2_PREDECESSOR_ACTIVE = (
    (3, 0x02000279, 0x02000278),
    (5, 0x02000304, 0x02000303),
    (7, 0x0200030F, 0x0200030E),
)

CDM_RECORD_SIZE = 0x2C
CDM_TERMINATOR = 0x40000000
CDM_INDIRECT_HELPER_RECORD_SIZE = 0x1C

INDIRECT_HELPER_TABLE_OFFSET = 0x14A0
INDIRECT_GEOMETRY_OFFSET = 0x14C0
INDIRECT_MAIN_TABLE_OFFSET = 0x14E0
INDIRECT_GEOMETRY_WORDS = 6


def _register_pairs(registers):
    pairs = list(registers.items()) if hasattr(registers, "items") else list(registers)
    if len(pairs) > COMPUTE_REGISTER_CAPACITY:
        raise ValueError(
            "compute register array holds at most %d entries"
            % COMPUTE_REGISTER_CAPACITY
        )
    return [(int(number), int(value)) for number, value in pairs]


def build_register_array(registers, capacity=COMPUTE_REGISTER_CAPACITY):
    """Build a padded G17P register array without losing duplicate entries."""
    pairs = _register_pairs(registers)
    if len(pairs) > capacity:
        raise ValueError("register array has %d entries, capacity is %d" %
                         (len(pairs), capacity))
    out = bytearray(capacity * COMPUTE_REGISTER_SIZE)
    for index, (number, value) in enumerate(pairs):
        struct.pack_into(
            "<IQ", out, index * COMPUTE_REGISTER_SIZE,
            number & 0xFFFFFFFF, value & 0xFFFFFFFFFFFFFFFF,
        )
    return bytes(out)


def register_value(registers, number, occurrence=0):
    """Return one value while preserving duplicate-register ordering."""
    found = [value for register, value in _register_pairs(registers)
             if register == number]
    if occurrence >= len(found):
        raise ValueError("compute register %#x occurrence %d is absent" %
                         (number, occurrence))
    return found[occurrence]


def apply_compute_uapi_registers(
        registers, preempt_base, cdm_base, usc_exec_base,
        helper_binary=0, helper_data=0, helper_cfg=0):
    """Overlay caller/queue compute state onto a proven G17P register program.

    The six leading registers point at driver-owned preemption storage and the
    caller's CDM stream. The four queue/UAPI registers are inserted after those
    fields, replacing prior occurrences while preserving unrelated registers
    and intentional duplicate writes.
    """
    preempt_base = int(preempt_base)
    replacements = {
        0x1A510: preempt_base,
        0x1A420: int(cdm_base),
        0x1A4D0: preempt_base + 0x1480,
        0x1A4D8: preempt_base + 0x1488,
        0x1A4E0: preempt_base + 0x1490,
        0x1A4E8: preempt_base + 0x1498,
    }
    supplied = {
        0x10071: int(usc_exec_base),
        0x11841: int(helper_binary),
        0x11849: int(helper_data),
        0x11F81: int(helper_cfg),
    }
    filtered = []
    inserted = False
    for number, value in _register_pairs(registers):
        if number in supplied:
            continue
        filtered.append((number, replacements.get(number, value)))
        if number == 0x1A4E8:
            filtered.extend((register, supplied[register])
                            for register in COMPUTE_UAPI_REGISTERS)
            inserted = True
    if not inserted:
        raise ValueError(
            "compute register program has no final preemption register 0x1a4e8")
    return tuple(filtered)


def build_compute_register_program(
        preempt_base, cdm_base, dispatch_identity, context_id,
        work_ordinal, robustness, operand_state_base,
        usc_exec_base=0, helper_binary=0, helper_data=0, helper_cfg=0,
        execution_gate=1):
    """Build the complete hardware-tested G17P compute register program."""
    preempt_base = int(preempt_base)
    dispatch_identity = int(dispatch_identity)
    context_word = (int(context_id) << 8) | int(work_ordinal)
    operand_state_base = int(operand_state_base)
    registers = (
        (0x1A510, preempt_base),
        (0x1A420, int(cdm_base)),
        (0x1A4D0, preempt_base + 0x1480),
        (0x1A4D8, preempt_base + 0x1488),
        (0x1A4E0, preempt_base + 0x1490),
        (0x1A4E8, preempt_base + 0x1498),
        (0x10071, int(usc_exec_base)),
        (0x11841, int(helper_binary)),
        (0x11849, int(helper_data)),
        (0x11F81, int(helper_cfg)),
        (0x1A440, 0x154024201),
        (0x1A458, 0x10C08860),
        (0x101D9, 0x1C),
        (0x1A089, 0), (0x1A091, 0),
        (0x1A059, 0), (0x1A061, 0),
        (0x1A0B9, 0), (0x1A0C1, 0),
        (0x101D1, 0), (0x0D479, 0),
        (0x1A0E9, 8),
        (0x107A1, 0xFF0000),
        (0x0A599, 0x13200400020),
        (0x0D411, 0x200000001),
        (0x1A540, dispatch_identity),
        (0x014A9, dispatch_identity),
        (0x0A351, dispatch_identity),
        (0x10201, context_word),
        (0x10428, context_word),
        (0x14028, int(execution_gate)),
        (0x14070, int(robustness) | 1),
        (0x10229, operand_state_base + 0x12800),
        (0x140A8, operand_state_base + 0x13000),
        (0x10099, operand_state_base + 0x9405),
        (0x10091, operand_state_base + 0x12400),
        (0x0A5C1, operand_state_base + 0x0005),
        (0x0A5C9, operand_state_base + 0x9000),
        (0x1A440, 0x154024209),
        (0x0A599, 0x6000400020),
    )
    if len(registers) != 40:
        raise AssertionError("G17P compute register program changed size")
    return registers


def build_compute_descriptor(
    registers,
    scheduler_record,
    low_alias,
    cdm_terminator,
    submit_sequence=0,
    context_id=1,
    grid_index=2,
    dispatch_a=COMPUTE_DISPATCH_A,
    dispatch_b=COMPUTE_DISPATCH_B,
    status_a=COMPUTE_STATUS_A,
    status_b=COMPUTE_STATUS_B,
    user_timestamp_start=0,
    user_timestamp_end=0,
    shared_control=COMPUTE_SHARED_CONTROL,
    zero_page=COMPUTE_ZERO_PAGE,
    protection_index=1,
    support_control=0x21000001,
    support_flags=1,
    work_ordinal=0,
    queue_submission=1,
    queue_ordinal=None,
    submission_index=None,
    sampler_array=0,
    sampler_count=0,
):
    """Build one complete one-page opcode-3 work item.

    ``cdm_terminator`` points at the terminating ``0x40000000`` word, not one
    byte past the stream.  ``low_alias`` is the executable/low-context alias of
    this descriptor's page and is used by both register-array locators.
    """
    pairs = _register_pairs(registers)
    values = {}
    for number, value in pairs:
        values.setdefault(number, []).append(value)

    def one(number, occurrence=0):
        try:
            return values[number][occurrence]
        except (KeyError, IndexError) as error:
            raise ValueError(
                "compute descriptor needs register %#x occurrence %d"
                % (number, occurrence)
            ) from error

    out = bytearray(COMPUTE_DESCRIPTOR_SIZE)
    struct.pack_into(
        "<IQI", out, 0, COMPUTE_SELECTOR,
        int(submit_sequence) & 0xFFFFFFFFFFFFFFFF,
        int(context_id) & 0xFFFFFFFF,
    )
    struct.pack_into("<Q", out, 0x10, int(scheduler_record))
    struct.pack_into("<4H", out, 0x18, *COMPUTE_HEADER_U16)

    primary = build_register_array(pairs)
    out[COMPUTE_REGISTER_START:
        COMPUTE_REGISTER_START + len(primary)] = primary

    struct.pack_into("<Q", out, 0x740, int(low_alias) + COMPUTE_REGISTER_START)
    struct.pack_into(
        "<I", out, COMPUTE_PRIMARY_COUNT,
        (len(pairs) * COMPUTE_REGISTER_SIZE << 16) | len(pairs),
    )
    for offset, value in COMPUTE_FIXED_U32.items():
        struct.pack_into("<I", out, offset, value)
    # Older callers named +0xf60 ``protection_index`` based on its first few
    # observed values.  Native rollover captures show that it is the global
    # submission index instead.  Retain the old argument as a compatibility
    # default while new callers use the decoded name.
    if submission_index is None:
        submission_index = protection_index
    submission_index = int(submission_index)
    if submission_index < 1:
        raise ValueError("compute submission index must be positive")
    ordinal = int(work_ordinal)
    if ordinal < 0:
        raise ValueError("compute work ordinal must be non-negative")
    queue_submission = int(queue_submission)
    if queue_submission < 1:
        raise ValueError("compute queue submission number must be positive")
    if queue_ordinal is None:
        queue_ordinal = ordinal
    queue_ordinal = int(queue_ordinal)
    if queue_ordinal < 0:
        raise ValueError("compute queue ordinal must be non-negative")
    sampler_array = int(sampler_array)
    sampler_count = int(sampler_count)
    if sampler_count < 0 or sampler_count > 0xFFFFFFFE:
        raise ValueError("compute sampler count is outside the descriptor range")
    if bool(sampler_array) != bool(sampler_count):
        raise ValueError(
            "compute sampler array and count must both be zero or nonzero")
    if sampler_array & 7:
        raise ValueError("compute sampler array must be 8-byte aligned")
    struct.pack_into("<I", out, 0xF50, queue_submission << 8)
    struct.pack_into("<I", out, 0xF58, queue_ordinal)
    struct.pack_into("<I", out, 0xF60, submission_index)
    struct.pack_into("<I", out, 0xF70, ordinal)

    secondary = [
        (destination, one(source))
        for destination, source in COMPUTE_SECONDARY_REGISTERS
    ]
    secondary_body = build_register_array(secondary)
    out[COMPUTE_SECONDARY_REGISTER_START:
        COMPUTE_SECONDARY_REGISTER_START + len(secondary_body)] = secondary_body
    struct.pack_into(
        "<Q", out, 0xE60,
        int(low_alias) + COMPUTE_SECONDARY_REGISTER_START,
    )

    resource = one(0x1A510)
    cdm_base = one(0x1A420)
    dispatch_identity = one(0x1A540)
    struct.pack_into("<Q", out, 0xED8, resource)
    struct.pack_into("<Q", out, 0xEE0, int(cdm_terminator))
    struct.pack_into("<Q", out, 0xF08, one(0x1A440, 0))
    struct.pack_into("<I", out, 0xF20, dispatch_identity >> 32)
    struct.pack_into("<Q", out, COMPUTE_SAMPLER_ARRAY, sampler_array)
    struct.pack_into("<I", out, COMPUTE_SAMPLER_COUNT, sampler_count)
    struct.pack_into(
        "<I", out, COMPUTE_SAMPLER_MAX,
        sampler_count + 1 if sampler_count else 0,
    )
    struct.pack_into("<Q", out, 0xF40, int(dispatch_a))
    struct.pack_into("<Q", out, 0xF48, int(dispatch_b))
    struct.pack_into("<I", out, 0xF54, int(grid_index))
    struct.pack_into("<Q", out, 0xF68, dispatch_identity & 0xFFFFFFFF)
    struct.pack_into("<Q", out, 0xF7C, int(status_a))
    struct.pack_into("<Q", out, 0xF84, int(status_b))
    struct.pack_into("<Q", out, 0xF8C, int(user_timestamp_start))
    struct.pack_into("<Q", out, 0xF94, int(user_timestamp_end))

    # The packed final support block is not naturally qword aligned.  Its
    # scalars are stable across four native boots; addresses remain arguments.
    struct.pack_into("<H", out, 0xFB0, 0x001A)
    struct.pack_into("<Q", out, 0xFB2, int(shared_control))
    struct.pack_into("<I", out, 0xFBA, int(support_control))
    struct.pack_into("<I", out, 0xFBE, int(support_flags))
    struct.pack_into("<B", out, 0xFC5, 0x9F)
    struct.pack_into("<I", out, 0xFC8, (ordinal & 3) << 30)
    struct.pack_into("<Q", out, 0xFCB, int(zero_page))
    struct.pack_into("<B", out, 0xFD3, 1)

    # Keep this relation explicit: a malformed end pointer can otherwise look
    # like a valid register program and retire without executing client work.
    if int(cdm_terminator) < cdm_base:
        raise ValueError("CDM terminator precedes its stream base")
    return bytes(out)


def build_compute_optional(
    context_low,
    context_high,
    grid_index=2,
    submission_ordinal=0,
    shared_control=COMPUTE_SHARED_CONTROL,
    channel_control=0xFFFFFC20C07B8000,
    uuid=0xA6,
    field_46=2,
    field_1e=0,
    field_32=1,
    field_56=1,
    field_5e=1,
    first_submit=True,
    item_index=0,
):
    """Build the selector-0x0f record paired with a compute descriptor."""
    out = bytearray(COMPUTE_OPTIONAL_SIZE)
    struct.pack_into("<I", out, 0, COMPUTE_OPTIONAL_SELECTOR)
    struct.pack_into("<Q", out, 0x08, int(context_low))
    struct.pack_into("<Q", out, 0x10, int(context_high))
    for offset, value in (
        (0x18, grid_index),
        (0x1A, 1 if first_submit else 0),
        (0x1E, field_1e),
        (0x22, 2),
        (0x32, field_32),
        (0x3E, submission_ordinal),
        (0x46, field_46),
        (0x52, 1 if first_submit else 0),
        (0x56, field_56),
        (0x5A, uuid),
        (0x5E, field_5e),
        (0x62, 1 if first_submit else 0),
        (0x66, 1),
    ):
        struct.pack_into("<H", out, offset, int(value) & 0xFFFF)
    struct.pack_into("<Q", out, 0x36, int(shared_control))
    struct.pack_into("<Q", out, 0x4A, int(channel_control))
    out[0x76:0x86] = b"\xff" * 0x10
    item_index = int(item_index)
    if item_index < 0:
        raise ValueError("compute optional item index must be non-negative")
    if item_index:
        struct.pack_into("<H", out, 0x2A, item_index & 0xFFFF)
        struct.pack_into("<H", out, 0x2E, (item_index << 8) & 0xFFFF)
    return bytes(out)


def build_compute_event(group_number, grid_index=2, counter_low=0):
    """Build compute's host-owned event record and reserve firmware output."""
    out = bytearray(COMPUTE_EVENT_SIZE)
    struct.pack_into("<I", out, 0x00, 0x0E)
    struct.pack_into("<I", out, 0x04, 0x00010000 | (int(grid_index) & 0xFFFF))
    struct.pack_into(
        "<I", out, 0x08,
        (int(group_number) << 8) | (int(counter_low) & 0xFF),
    )
    struct.pack_into("<I", out, 0x10, 0x200)
    return bytes(out)


def build_compute_queue_context_item(
        descriptor, queue, grid_index=2, flags_200=0,
        word_220=0xFFFF080100000001, word_330=2, word_338=0,
        word_350=0x000110038001A002,
        word_358=0x000020038001A03B,
        word_378=0x003FFFFFFFFFFFFF, item_index=0):
    """Build one 0x200-byte record in compute's per-queue context object."""
    item_index = int(item_index)
    if item_index < 0:
        raise ValueError("compute queue-context item index must be non-negative")
    out = bytearray(0x200)
    struct.pack_into("<Q", out, 0x00,
                     int(flags_200) | ((int(grid_index) * 4) << 40)
                     | ((item_index + 1) * 4))
    struct.pack_into("<Q", out, 0x10, int(descriptor))
    struct.pack_into("<Q", out, 0x18, int(queue))
    struct.pack_into("<Q", out, 0x20, int(word_220))
    struct.pack_into("<Q", out, 0x28,
                     (int(grid_index) << 40) | item_index)
    struct.pack_into("<Q", out, 0x130, int(word_330))
    struct.pack_into("<Q", out, 0x138, int(word_338))
    struct.pack_into("<Q", out, 0x150, int(word_350))
    struct.pack_into("<Q", out, 0x158, int(word_358))
    struct.pack_into("<Q", out, 0x178, int(word_378))
    return bytes(out)


COMPUTE_QUEUE_CONTEXT_HOST_QWORDS = (
    0x00, 0x10, 0x18, 0x20, 0x28,
    0x130, 0x138, 0x150, 0x158, 0x178,
)


def update_compute_queue_context_item(previous, current):
    """Patch host-owned fields while retaining firmware state on slot reuse."""
    if len(previous) != COMPUTE_QUEUE_CONTEXT_RECORD_SIZE:
        raise ValueError("previous compute queue-context item has wrong size")
    if len(current) != COMPUTE_QUEUE_CONTEXT_RECORD_SIZE:
        raise ValueError("current compute queue-context item has wrong size")
    out = bytearray(previous)
    for offset in COMPUTE_QUEUE_CONTEXT_HOST_QWORDS:
        out[offset:offset + 8] = current[offset:offset + 8]
    return bytes(out)


def compute_queue_context_record_offset(item_index, record_count=None):
    """Return the physical ring offset for a monotonic context-item index."""
    item_index = int(item_index)
    if item_index < 0:
        raise ValueError("compute queue-context item index must be non-negative")
    if record_count is None:
        record_count = COMPUTE_QUEUE_CONTEXT_RECORDS
    record_count = int(record_count)
    if record_count < 2 or record_count > COMPUTE_QUEUE_CONTEXT_RECORDS:
        raise ValueError("compute queue-context record count is out of range")
    return ((item_index + 1) % record_count
            * COMPUTE_QUEUE_CONTEXT_RECORD_SIZE)


def build_compute_queue_context(
        descriptor, queue, grid_index=2, flags_200=0,
        word_220=0xFFFF080100000001, word_330=2, word_338=0,
        word_350=0x000110038001A002,
        word_358=0x000020038001A03B,
        word_378=0x003FFFFFFFFFFFFF, item_index=0):
    """Build the page named through compute's low and high context aliases."""
    out = bytearray(COMPUTE_QUEUE_CONTEXT_SIZE)
    item_index = int(item_index)
    start = (item_index + 1) * 0x200
    if start + 0x200 > len(out):
        raise ValueError("compute queue-context item exceeds its page")
    out[start:start + 0x200] = build_compute_queue_context_item(
        descriptor, queue, grid_index,
        flags_200=flags_200, word_220=word_220,
        word_330=word_330, word_338=word_338,
        word_350=word_350, word_358=word_358,
        word_378=word_378, item_index=item_index,
    )
    return bytes(out)


def build_compute_scheduler_record(slot_addr, work_id=0, phase=0,
                                   job_list=0, node_id=0):
    """Build the directly referenced 0x100-byte compute scheduler record.

    The minimal host-owned state is the slot and marker.  Optional lifecycle
    values permit exact native-layout validation and controlled live probes;
    callers should normally leave them zero for firmware to own.
    """
    out = bytearray(0x100)
    struct.pack_into("<Q", out, 0x00, int(slot_addr))
    struct.pack_into("<I", out, 0x08, int(work_id))
    struct.pack_into("<I", out, 0x0C, int(phase))
    struct.pack_into("<I", out, 0x10, 0x50)
    if phase:
        struct.pack_into("<I", out, 0x24, 1)
    if job_list:
        struct.pack_into("<Q", out, 0xA0, int(job_list))
    if node_id:
        struct.pack_into("<Q", out, 0xA8, 0x02000000 | int(node_id))
        struct.pack_into("<Q", out, 0xB0, 0x02000000 | (int(node_id) - 1))
        struct.pack_into("<Q", out, 0xC0, 1)
    return bytes(out)


def build_compute_scheduler_slot(first_value=0x35, occupied=1):
    """Build the host-owned slot named by a compute scheduler record.

    Native pre-doorbell captures consistently encode live entries as
    ``(2 << 32) | value``.  The first entry is the one selected by the
    scheduler record; later entries vary with unrelated concurrent work and
    are deliberately left empty by a single-dispatch caller.
    """
    if not 0 <= int(occupied) <= COMPUTE_SCHEDULER_SLOT_SIZE // 8:
        raise ValueError("compute scheduler slot occupancy is out of range")
    out = bytearray(COMPUTE_SCHEDULER_SLOT_SIZE)
    for index in range(int(occupied)):
        value = int(first_value) if index == 0 else 0
        struct.pack_into("<Q", out, index * 8, (2 << 32) | value)
    return bytes(out)


def build_compute_shared_state(active=1):
    """Build the one-word firmware state page named by shared support."""
    out = bytearray(COMPUTE_SHARED_STATE_SIZE)
    struct.pack_into("<I", out, 0, int(active))
    return bytes(out)


def build_compute_operand_table(
        buffer_base, entries=COMPUTE_OPERAND_TABLE_ENTRIES):
    """Build the buffer-registration table named by shared support +0x30."""
    entries = int(entries)
    if not 0 <= entries <= PAGE_SIZE // COMPUTE_OPERAND_TABLE_STRIDE:
        raise ValueError("compute operand-table entry count is out of range")
    out = bytearray(PAGE_SIZE)
    for index in range(entries):
        value = (
            int(buffer_base) + index * COMPUTE_OPERAND_BUFFER_STRIDE
        ) | COMPUTE_OPERAND_BUFFER_FLAG
        struct.pack_into(
            "<Q", out, index * COMPUTE_OPERAND_TABLE_STRIDE, value)
    return bytes(out)


def build_compute_operand_table_bases(buffer_bases):
    """Build an operand table from allocator-selected buffer DVAs."""
    buffer_bases = tuple(int(base) for base in buffer_bases)
    if len(buffer_bases) > PAGE_SIZE // COMPUTE_OPERAND_TABLE_STRIDE:
        raise ValueError("compute operand-table entry count is out of range")
    out = bytearray(PAGE_SIZE)
    for index, base in enumerate(buffer_bases):
        struct.pack_into(
            "<Q", out, index * COMPUTE_OPERAND_TABLE_STRIDE,
            base | COMPUTE_OPERAND_BUFFER_FLAG)
    return bytes(out)


def build_compute_operand_page_list(
        buffer_base, buffers=8,
        buffer_size=COMPUTE_OPERAND_BUFFER_SIZE,
        buffer_stride=COMPUTE_OPERAND_BUFFER_STRIDE,
        page_size=0x1000):
    """Build the page-DVA list used to register operand-memory tranches.

    Native compact controls list every 4 KiB page in eight 1 MiB buffers. The
    buffers are separated by the same 0x8000 gap encoded in the operand-table
    stride, so the complete eight-buffer list occupies one 16 KiB page.
    """
    buffers = int(buffers)
    buffer_size = int(buffer_size)
    buffer_stride = int(buffer_stride)
    page_size = int(page_size)
    if buffers <= 0 or buffer_size <= 0 or page_size <= 0:
        raise ValueError("compute operand page-list dimensions must be positive")
    if buffer_size % page_size:
        raise ValueError("compute operand buffer size must be page-aligned")
    pages_per_buffer = buffer_size // page_size
    if buffers * pages_per_buffer != PAGE_SIZE // 8:
        raise ValueError(
            "compute operand page list must contain exactly %d entries" %
            (PAGE_SIZE // 8))
    out = bytearray(PAGE_SIZE)
    index = 0
    for buffer_index in range(buffers):
        base = int(buffer_base) + buffer_index * buffer_stride
        for page_index in range(pages_per_buffer):
            struct.pack_into(
                "<Q", out, index * 8, base + page_index * page_size)
            index += 1
    return bytes(out)


def build_compute_operand_page_lists(
        buffer_base, entries=COMPUTE_OPERAND_TABLE_ENTRIES,
        buffer_size=COMPUTE_OPERAND_BUFFER_SIZE,
        buffer_stride=COMPUTE_OPERAND_BUFFER_STRIDE,
        page_size=0x1000):
    """Build the complete padded page-list array for an operand table.

    Each 16 KiB list page holds eight one-megabyte tranches at 4 KiB
    granularity.  The native 21-entry context therefore uses three list pages:
    two full eight-tranche pages and five tranches in the final page.
    """
    entries = int(entries)
    buffer_size = int(buffer_size)
    buffer_stride = int(buffer_stride)
    page_size = int(page_size)
    if entries <= 0 or buffer_size <= 0 or page_size <= 0:
        raise ValueError("compute operand page-list dimensions must be positive")
    if buffer_size % page_size:
        raise ValueError("compute operand buffer size must be page-aligned")
    pages_per_buffer = buffer_size // page_size
    buffers_per_list = PAGE_SIZE // 8 // pages_per_buffer
    if not buffers_per_list:
        raise ValueError("one operand buffer does not fit in a page list")
    list_pages = (entries + buffers_per_list - 1) // buffers_per_list
    out = bytearray(list_pages * PAGE_SIZE)
    for buffer_index in range(entries):
        list_index = buffer_index // buffers_per_list
        list_slot = buffer_index % buffers_per_list
        base = int(buffer_base) + buffer_index * buffer_stride
        first = (list_index * PAGE_SIZE
                 + list_slot * pages_per_buffer * 8)
        for page_index in range(pages_per_buffer):
            struct.pack_into(
                "<Q", out, first + page_index * 8,
                base + page_index * page_size)
    return bytes(out)


def build_compute_shared_support(
    client_state,
    firmware_state,
    word_08=2,
    word_10=0x0200800000000001,
    header=3,
    resource_class=0x13,
    cursor=0x98,
    field_54=0,
    field_5c=1,
    final_kind=1,
    word_20=None,
    word_28=None,
):
    """Build compute's packed shared-support page from explicit pointers.

    ``firmware_state`` is intentionally unaligned at +0x4c in this layout.
    Treating the surrounding qwords as opaque constants hides that pointer and
    produces a graph whose apparent closure is incomplete.
    """
    out = bytearray(COMPUTE_SHARED_SUPPORT_SIZE)
    struct.pack_into("<Q", out, 0x00, int(header))
    struct.pack_into("<Q", out, 0x08, int(word_08))
    struct.pack_into("<Q", out, 0x10, int(word_10))
    struct.pack_into("<Q", out, 0x18, 0x0004000000000070)
    resource = int(resource_class) << 40
    struct.pack_into(
        "<Q", out, 0x20,
        resource if word_20 is None else int(word_20))
    struct.pack_into(
        "<Q", out, 0x28,
        resource if word_28 is None else int(word_28))
    struct.pack_into("<Q", out, 0x30, int(client_state))
    struct.pack_into("<Q", out, 0x40, 4)
    struct.pack_into("<I", out, 0x48, int(cursor))
    struct.pack_into("<Q", out, 0x4C, int(firmware_state))
    struct.pack_into("<I", out, 0x54, int(field_54))
    struct.pack_into("<I", out, 0x5C, int(field_5c))
    struct.pack_into("<I", out, 0x60, int(final_kind))
    return bytes(out)


def build_compute_compact_control_support(
        control_class, operand_table, low_buffer, firmware_state,
        active, resource_class, cursor, final_kind,
        word_20=None, word_28=None, field_54=0, field_5c=0,
        header_value=None):
    """Build a compact object consumed by class-1/2 control ``0x20``.

    ``+0x14`` stores the low 32 bits of a buffer in the operand table's low-DVA
    namespace. The state pointer at ``+0x4c`` is a full, unaligned firmware-DVA
    pointer. Keeping the two forms distinct is required: combining ``+0x14``
    with the firmware object's upper bits names an unmapped address.
    """
    out = bytearray(COMPUTE_SHARED_SUPPORT_SIZE)
    # The first-partial object proves these are independent: its leading
    # lifecycle value is 1 while its class selector at +0x10 is 2.
    struct.pack_into(
        "<I", out, 0x00,
        int(control_class if header_value is None else header_value))
    struct.pack_into("<I", out, 0x08, int(active))
    struct.pack_into("<I", out, 0x10, int(control_class))
    struct.pack_into("<I", out, 0x14, int(low_buffer) & 0xFFFFFFFF)
    struct.pack_into("<Q", out, 0x18, 0x0004000000000070)
    resource = int(resource_class) << 40
    struct.pack_into(
        "<Q", out, 0x20,
        resource if word_20 is None else int(word_20))
    struct.pack_into(
        "<Q", out, 0x28,
        resource if word_28 is None else int(word_28))
    struct.pack_into("<Q", out, 0x30, int(operand_table))
    struct.pack_into("<I", out, 0x40, 4)
    struct.pack_into("<I", out, 0x48, int(cursor))
    struct.pack_into("<Q", out, 0x4C, int(firmware_state))
    struct.pack_into("<I", out, 0x54, int(field_54))
    struct.pack_into("<I", out, 0x5C, int(field_5c))
    struct.pack_into("<I", out, 0x60, int(final_kind))
    return bytes(out)


def build_compute_class1_support(operand_table, low_buffer, firmware_state,
                                 active=0, resource_class=0x13,
                                 cursor=0x98, final_kind=2,
                                 word_20=None, word_28=None,
                                 field_54=0, field_5c=0):
    """Build the compact first object consumed by class-1 control ``0x20``."""
    return build_compute_compact_control_support(
        1, operand_table, low_buffer, firmware_state,
        active, resource_class, cursor, final_kind,
        word_20=word_20, word_28=word_28,
        field_54=field_54, field_5c=field_5c)


def build_compute_class2_support(operand_table, low_buffer, firmware_state,
                                 active=1, resource_class=0x17,
                                 cursor=0xB8, final_kind=3,
                                 word_20=None, word_28=None,
                                 field_54=0, field_5c=0):
    """Build the compact first object consumed by class-2 control ``0x20``."""
    return build_compute_compact_control_support(
        2, operand_table, low_buffer, firmware_state,
        active, resource_class, cursor, final_kind,
        word_20=word_20, word_28=word_28,
        field_54=field_54, field_5c=field_5c)


def build_compute_class2_pool(
        low_slots, high_slots, shared_state,
        record_count=COMPUTE_CLASS2_POOL_RECORDS,
        index_base=COMPUTE_CLASS2_POOL_INDEX_BASE,
        active=COMPUTE_CLASS2_POOL_ACTIVE):
    """Build the array-form first object accepted by class-2 control.

    Each 0x80-byte record pairs low/high aliases of one u32 slot.  The fields
    at +0x10 and +0x48 are left zero because native snapshots show them as
    per-record runtime state rather than pointer/namespace inputs.
    """
    record_count = int(record_count)
    if not 0 < record_count <= PAGE_SIZE // COMPUTE_CLASS2_POOL_RECORD_STRIDE:
        raise ValueError("class-2 pool record count does not fit in one page")
    out = bytearray(PAGE_SIZE)
    for index in range(record_count):
        offset = index * COMPUTE_CLASS2_POOL_RECORD_STRIDE
        slot_offset = COMPUTE_CLASS2_POOL_SLOT_OFFSET + index * 4
        struct.pack_into("<Q", out, offset + 0x00,
                         int(low_slots) + slot_offset)
        struct.pack_into("<Q", out, offset + 0x08,
                         int(high_slots) + slot_offset)
        struct.pack_into("<Q", out, offset + 0x28,
                         int(index_base)
                         + (index % COMPUTE_CLASS2_POOL_INDEX_PERIOD) * 0x20)
        struct.pack_into("<Q", out, offset + 0x40,
                         int(shared_state) + 0x40)
        if 0 < index <= len(active):
            state = int(active[index - 1])
            struct.pack_into("<Q", out, offset + 0x10, state)
            struct.pack_into("<II", out, offset + 0x48, state, 1)
    return bytes(out)


def build_compute_class2_pool_state(limit=8, active=5):
    """Build the small shared state page referenced by every pool record."""
    out = bytearray(PAGE_SIZE)
    struct.pack_into("<II", out, 0x00, int(limit), int(limit))
    struct.pack_into("<I", out, 0x40, int(active))
    return bytes(out)


def build_compute_class2_predecessor(slots, job_list):
    """Build the zero-state 36-record object registered before the pool.

    Three active records name the resource job-list head and carry stable
    identity scalars.  Remaining records contain only their u32 slot pointer.
    """
    out = bytearray(PAGE_SIZE)
    for index in range(COMPUTE_CLASS2_PREDECESSOR_RECORDS):
        struct.pack_into(
            "<Q", out, index * COMPUTE_CLASS2_PREDECESSOR_RECORD_STRIDE,
            int(slots) + index * 4,
        )
    for index, (state, high_id, low_id) in enumerate(
            COMPUTE_CLASS2_PREDECESSOR_ACTIVE, 1):
        offset = index * COMPUTE_CLASS2_PREDECESSOR_RECORD_STRIDE
        struct.pack_into("<II", out, offset + 0x08, state, 2)
        struct.pack_into("<Q", out, offset + 0x10, 0x50)
        struct.pack_into("<II", out, offset + 0x20, 0, 2)
        struct.pack_into("<Q", out, offset + 0xA0, int(job_list))
        struct.pack_into("<Q", out, offset + 0xA8, high_id)
        struct.pack_into("<Q", out, offset + 0xB0, low_id)
        struct.pack_into("<Q", out, offset + 0xC0, 1)
    return bytes(out)


def build_compute_class2_predecessor_seed(slots):
    """Build the host-owned input image accepted by class-2 registration.

    Before the handler runs, each 0x100-byte record contains only its stable
    u32 slot pointer.  Firmware populates the scheduler state in place.
    """
    out = bytearray(PAGE_SIZE)
    for index in range(COMPUTE_CLASS2_PREDECESSOR_RECORDS):
        struct.pack_into(
            "<Q", out, index * COMPUTE_CLASS2_PREDECESSOR_RECORD_STRIDE,
            int(slots) + index * 4,
        )
    return bytes(out)


def build_compute_minimal_class2_predecessor(slots, job_list):
    """Build the post-registration predecessor image seen before native work.

    The table has 36 address-bearing records on a 0x100-byte stride.  Records
    one and two carry firmware-populated scheduler state at the first compute
    publication; this is not the host seed consumed by the class-2 handler.
    """
    out = bytearray(PAGE_SIZE)
    for index in range(COMPUTE_CLASS2_PREDECESSOR_RECORDS):
        struct.pack_into(
            "<Q", out, index * COMPUTE_CLASS2_PREDECESSOR_RECORD_STRIDE,
            int(slots) + index * 4,
        )

    first = COMPUTE_CLASS2_PREDECESSOR_RECORD_STRIDE
    struct.pack_into("<II", out, first + 0x08, 0, 1)
    struct.pack_into("<Q", out, first + 0x10, 0x50)
    struct.pack_into("<II", out, first + 0x20, 0, 3)
    struct.pack_into("<Q", out, first + 0xA0, int(job_list))
    struct.pack_into("<Q", out, first + 0xB8, 0x03000220)
    struct.pack_into("<Q", out, first + 0xC0, 2)

    second = 2 * COMPUTE_CLASS2_PREDECESSOR_RECORD_STRIDE
    struct.pack_into("<Q", out, second + 0x08, 1)
    struct.pack_into("<Q", out, second + 0x10, 0x50)
    return bytes(out)


def build_compute_minimal_class2_predecessor_slots():
    """Build the two live u32 slots paired with the minimal predecessor."""
    out = bytearray(PAGE_SIZE)
    struct.pack_into("<3I", out, 0, 0, 1, 1)
    return bytes(out)


def build_compute_class2_predecessor_slots():
    """Build c08b's u32 slot state: reserved zero, then three active twos."""
    out = bytearray(PAGE_SIZE)
    struct.pack_into("<4I", out, 0, 0, 2, 2, 2)
    return bytes(out)


def encode_shader_pointer(executable_va):
    """Encode a 64-byte-aligned executable shader address for direct CDM.

    The low word carries bits 6..37 of the VA.  The following control word has
    bit 30 set and carries the VA's 1 TiB region in its low bits; it is not the
    high word of a conventional 64-bit ``VA >> 6`` value.
    """
    executable_va = int(executable_va)
    if executable_va & 0x3F:
        raise ValueError("compute shader address must be 64-byte aligned")
    if executable_va < 0 or executable_va >= (1 << 62):
        raise ValueError("compute shader address is outside the CDM VA encoding")
    low = (executable_va >> 6) & 0xFFFFFFFF
    control = 0x40000000 | (executable_va >> 40)
    return low | (control << 32)


def build_direct_dispatch(shader_va, grid, threadgroup,
                          config=0x00080000,
                          constant=0x01000000,
                          tail=0x60000160):
    """Build one hardware-confirmed 0x2c direct-dispatch CDM record."""
    grid = tuple(int(value) for value in grid)
    threadgroup = tuple(int(value) for value in threadgroup)
    if len(grid) != 3 or len(threadgroup) != 3:
        raise ValueError("grid and threadgroup must each have three dimensions")
    if any(value <= 0 or value > 0xFFFFFFFF for value in grid + threadgroup):
        raise ValueError("dispatch dimensions must be nonzero u32 values")
    return struct.pack(
        "<IIQ3I3II", int(config), int(constant),
        encode_shader_pointer(shader_va),
        *grid, *threadgroup, int(tail),
    )


def build_cdm_stream(dispatches):
    """Append compute dispatch records and the required stream terminator."""
    records = list(dispatches)
    if not records:
        raise ValueError("a CDM stream needs at least one dispatch")
    if any(len(record) != CDM_RECORD_SIZE for record in records):
        raise ValueError("every direct CDM record must be %#x bytes" % CDM_RECORD_SIZE)
    return b"".join(records) + struct.pack("<I", CDM_TERMINATOR)


def build_indirect_grid_setup(shader_va, geometry_va,
                              config=0x10080000,
                              constant=0x01000000,
                              tail=0x60000160):
    """Build the compact helper record used by indirect compute dispatch.

    The geometry pointer is stored high-word first.  The helper writes six
    u32 values there: global thread dimensions followed by local dimensions.
    """
    geometry_va = int(geometry_va)
    if geometry_va < 0 or geometry_va >= (1 << 64):
        raise ValueError("indirect geometry address is outside u64 range")
    return struct.pack(
        "<IIQIII",
        int(config), int(constant), encode_shader_pointer(shader_va),
        geometry_va >> 32, geometry_va & 0xFFFFFFFF, int(tail),
    )


def build_indirect_cdm_stream(main_dispatch, grid_setup):
    """Build one main dispatch followed by its indirect grid helper."""
    if len(main_dispatch) != CDM_RECORD_SIZE:
        raise ValueError(
            "indirect main CDM record must be %#x bytes" % CDM_RECORD_SIZE)
    if len(grid_setup) != CDM_INDIRECT_HELPER_RECORD_SIZE:
        raise ValueError(
            "indirect helper CDM record must be %#x bytes" %
            CDM_INDIRECT_HELPER_RECORD_SIZE)
    return main_dispatch + grid_setup + struct.pack("<I", CDM_TERMINATOR)


def build_buffer_resource_table(buffer_addresses, size=PAGE_SIZE,
                                table_offset=0x14A0):
    """Build the inline Tier-2 argument table for buffer-only compute."""
    addresses = [int(address) for address in buffer_addresses]
    if table_offset + len(addresses) * 8 > size:
        raise ValueError("resource table does not fit in its object")
    out = bytearray(size)
    for index, address in enumerate(addresses):
        struct.pack_into("<Q", out, table_offset + index * 8, address)
    return bytes(out)


def build_indirect_resource_table(
        helper_buffers, main_buffers, size=PAGE_SIZE,
        helper_offset=INDIRECT_HELPER_TABLE_OFFSET,
        geometry_offset=INDIRECT_GEOMETRY_OFFSET,
        main_offset=INDIRECT_MAIN_TABLE_OFFSET):
    """Build the two argument tables and zero geometry for indirect compute.

    ``helper_buffers`` name the helper's constant and binding objects.  The
    binding object in turn names the indirect argument block and the geometry
    output at ``resource + geometry_offset``.  ``main_buffers`` are consumed
    by the caller shader after the helper publishes geometry.
    """
    helper_buffers = tuple(int(address) for address in helper_buffers)
    main_buffers = tuple(int(address) for address in main_buffers)
    size = int(size)
    helper_end = int(helper_offset) + len(helper_buffers) * 8
    geometry_end = int(geometry_offset) + INDIRECT_GEOMETRY_WORDS * 4
    main_end = int(main_offset) + len(main_buffers) * 8
    if helper_end > int(geometry_offset):
        raise ValueError("indirect helper table overlaps generated geometry")
    if geometry_end > int(main_offset):
        raise ValueError("indirect geometry overlaps main argument table")
    if max(helper_end, geometry_end, main_end) > size:
        raise ValueError("indirect resource tables do not fit in their object")
    out = bytearray(size)
    for index, address in enumerate(helper_buffers):
        struct.pack_into("<Q", out, int(helper_offset) + index * 8, address)
    for index, address in enumerate(main_buffers):
        struct.pack_into("<Q", out, int(main_offset) + index * 8, address)
    return bytes(out)


def build_indirect_helper_constant(size=PAGE_SIZE):
    """Build the unsigned-division lookup table bound to helper slot 0.

    Entry ``d - 1`` holds the reciprocal multiplier and shift used to divide
    by ``d``.  The native table may start at an offset within a larger
    allocation; callers can point at this standalone table's first entry.
    """
    size = int(size)
    if size < 8:
        raise ValueError("indirect helper constant object is smaller than one qword")
    if size % 8:
        raise ValueError("indirect helper constant object must hold whole entries")
    out = bytearray(size)
    for divisor in range(1, size // 8 + 1):
        shift = (divisor - 1).bit_length() - 1 if divisor > 1 else 0
        multiplier = ((1 << (32 + shift)) - 1) // divisor
        struct.pack_into(
            "<II", out, (divisor - 1) * 8, multiplier, shift)
    return bytes(out)


def build_indirect_helper_binding(indirect_arguments_va, geometry_va,
                                  size=PAGE_SIZE):
    """Build the compact-helper input, output, and dispatch-state object.

    Two output-positive native submissions expose the same 0x68-byte body.
    The leading pointers name the public indirect counts and the six-word
    generated geometry.  The remaining packed state is stable for the
    verified ``{2, 1, 1} * {32, 1, 1}`` launch; its individual scalar meanings
    are not yet separated.
    """
    size = int(size)
    if size < 0x68:
        raise ValueError("indirect helper binding object is smaller than its body")
    out = bytearray(size)
    struct.pack_into(
        "<QQ", out, 0, int(indirect_arguments_va), int(geometry_va))
    for offset, value in (
        (0x18, 0x0001002000000000),
        (0x20, 0x00600C0004000001),
        (0x28, 0x0000000000000240),
        (0x30, 0x0000000000000001),
        (0x40, 0x0000000100000060),
        (0x48, 0x0000000100000001),
        (0x50, 0x0000000100000001),
        (0x58, 0x0000000100000001),
        (0x60, 0x0000000000000001),
    ):
        struct.pack_into("<Q", out, offset, value)
    return bytes(out)
