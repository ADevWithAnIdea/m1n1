# SPDX-License-Identifier: GPL-2.0-only
"""Source builders for the observed T8142/G17G compute submission.

The outer channel and queue layouts live in :mod:`m1n1.drm_shim.g17g`.  This
module covers the selector-15/3/14 group and the caller-owned CDM resources
from the accepted one-dispatch, first-work capture.  It does not import a
snapshot or contain an opaque captured page: every firmware-visible field is
written explicitly and every address remains a caller input.

The shader bytes are the compiler output for the repository's own
``g17g_native_compute.metal`` kernel.  They are caller-owned program contents,
not Apple firmware or driver code, and are kept separately from the ABI
objects so another compiler path can replace them later.
"""

import hashlib
import struct

from . import g17g


PAGE_SIZE = 0x4000

COMPUTE_SELECTOR = 3
COMPUTE_DESCRIPTOR_SIZE = PAGE_SIZE
COMPUTE_DESCRIPTOR_OBJECT_SIZE = 0x1000
COMPUTE_DESCRIPTOR_STRIDE = 0x1040
COMPUTE_REGISTER_START = 0x40
COMPUTE_REGISTER_SIZE = 0x0C
COMPUTE_REGISTER_COUNT = 40
COMPUTE_SECONDARY_REGISTER_START = 0x760
COMPUTE_SECONDARY_REGISTER_COUNT = 4
COMPUTE_HEADER_U16 = (0x25, 0x27, 0x27, 0x28)

COMPUTE_OPTIONAL_SELECTOR = 15
COMPUTE_OPTIONAL_SIZE = 0xC0
COMPUTE_EVENT_SELECTOR = 14
COMPUTE_EVENT_SIZE = 0x40
COMPUTE_QUEUE_CONTEXT_ITEM_SIZE = 0x200
COMPUTE_QUEUE_CONTEXT_ITEM_COUNT = 256

CDM_RECORD_SIZE = 0x2C
CDM_TERMINATOR = 0x40000000

RESOURCE_TABLE_OFFSET = 0x14A0

COMPUTE_OPERAND_TABLE_ENTRIES = 11
COMPUTE_OPERAND_TABLE_STRIDE = 0x40
COMPUTE_OPERAND_BUFFER_STRIDE = 0x208000
COMPUTE_OPERAND_BUFFER_SIZE = 0x200000
COMPUTE_OPERAND_BUFFER_FLAG = 0x2000000000000000
COMPUTE_OPERAND_PAGE_LIST_SIZE = 3 * PAGE_SIZE

COMPUTE_QUEUE_GENERATION = 0x119
COMPUTE_CHANNEL_STATE_OFFSET = 0x240
COMPUTE_CHANNEL_RING_SLOT_OFFSET = 0x2640
# The pointer block's native +0x60 capacity is 0x500 entries.  Compute uses
# one selector-15 registration item followed by two items per command.  The
# independent 127-record scheduler arena is exhausted before this ring.
COMPUTE_ITEM_RING_ENTRY_COUNT = 0x500
COMPUTE_DESCRIPTOR_BASE = 0xFFFFFC20C0358000

COMPUTE_CONTEXT1_PAGE_COUNT = 1739
COMPUTE_CONTEXT1_DVA_SHA256 = (
    "f9d6f692c2f1a55be1f22be7972a36a"
    "ea25a4a429834590a926ead7e9e50216b"
)
COMPUTE_CONTEXT1_RUNS = (
    (0x1000000000, 4),
    (0x1000018000, 1),
    (0x7200000000, 256),
    (0x7200408000, 4),
    (0x7200420000, 8),
    (0x7200448000, 128),
    (0x7200650000, 128),
    (0x7200858000, 128),
    (0x7200A60000, 128),
    (0x7200C68000, 128),
    (0x7200E70000, 128),
    (0x7201078000, 128),
    (0x7201280000, 128),
    (0x7201488000, 128),
    (0x7201690000, 128),
    (0x7201898000, 128),
    (0x10000000000, 4),
    (0x10000018000, 4),
    (0x10000030000, 1),
    (0x10000038000, 1),
    (0x10000040000, 1),
    (0x10000048000, 8),
    (0x10000070000, 8),
    (0x10000098000, 2),
    (0x100000A8000, 2),
    (0x100000B8000, 2),
    (0x100000C8000, 2),
    (0x100000D8000, 2),
    (0x100000E8000, 2),
    (0x100000F8000, 3),
    (0x10000108000, 2),
    (0x10000118000, 2),
    (0x10000128000, 2),
    (0x10000138000, 2),
    (0x10000148000, 2),
    (0x10000158000, 2),
    (0x10000168000, 3),
    (0x2FFFFFF8000, 1),
)

COMPUTE_CONTEXT1_ZERO_RUNS = (
    (0x1000000000, 4),
    (0x10000000000, 4),
    (0x10000018000, 4),
    (0x10000048000, 8),
    (0x10000070000, 8),
    (0x10000098000, 2),
    (0x100000B8000, 2),
    (0x100000D8000, 2),
    (0x100000E8000, 2),
    (0x2FFFFFF8000, 1),
)

# Native first-compute has one PTE attribute distinction across this topology.
# These 22 pages use the GPU read-only class (OS=1, AP=2, UXN=0); every other
# context-1 leaf uses the GPU read/write class (OS=1, AP=2, UXN=1).  The names
# reflect GPU access as decoded by UAT rather than the misleading ARM UXN bit.
COMPUTE_CONTEXT1_READ_ONLY_RUNS = (
    (0x1000000000, 4),
    (0x10000000000, 4),
    (0x10000018000, 4),
    (0x10000098000, 2),
    (0x100000B8000, 2),
    (0x100000C8000, 2),
    (0x100000D8000, 2),
    (0x100000E8000, 2),
    (0x10000108000, 2),
    (0x10000128000, 2),
    (0x10000138000, 2),
    (0x10000148000, 2),
    (0x10000158000, 2),
)
COMPUTE_CONTEXT1_READ_ONLY_PAGE_COUNT = 32
COMPUTE_CONTEXT1_READ_ONLY_DVA_SHA256 = (
    "505d9754f0b120f572f075a71eed2422"
    "876c70372cfef0d8d07d4fd77127384c"
)

# The native compiler emits two short caller-owned support records in the
# first read-only context-1 page.  Range minimization proved these 64 bytes are
# sufficient for the repository's one-dispatch g17g_add workload; the rest of
# the 16-KiB page is zero.  Keeping each record and its offset explicit avoids
# treating a captured page as an ABI object.
COMPUTE_PIPELINE_SUPPORT_DVA = 0x10000000000
COMPUTE_PIPELINE_RECORD_OFFSET = 0x2A0
COMPUTE_PIPELINE_RECORD = bytes.fromhex(
    "0700100f0000270004002000a50a0600"
)
COMPUTE_PIPELINE_AUX_RECORD_OFFSET = 0x3C0
COMPUTE_PIPELINE_AUX_RECORD = bytes.fromhex(
    "1ca010060f000302182210402f040302"
    "180210c04100800000002900041a2220"
    "a002040812000f080302010610400e00"
)

COMPUTE_ADDRESS_LIST_PAGE_DVAS = tuple(
    0x7200000000 + index * PAGE_SIZE for index in range(4)
)
COMPUTE_REFERENCE_OPERAND_BUFFER_BASE = 0x7200448000
COMPUTE_ADDRESS_LIST_ENTRIES_PER_BUFFER = (
    COMPUTE_OPERAND_BUFFER_SIZE // 0x1000
)
COMPUTE_ADDRESS_LIST_ENTRY_STRIDE = 8
COMPUTE_ADDRESS_LIST_ADDRESS_STRIDE = 0x1000
COMPUTE_ADDRESS_LIST_PAGE_SHA256 = (
    "c66c6f50e171f76f70e5834d0d72aa80726f83f7f43ddb505759d0ce9f7f5efb",
    "f238c49e987f0c8bf7aeec058f27abc2098e3252f4982bb53a67c364185ad8d6",
    "f29a9af92019904a17ca12eca1b22fb925d7be3829573464a88f59c2ee6fee9c",
    "4fe7b59af6de3b665b67788cc2f99892ab827efae3a467342b3bb4e3bc8e5bfe",
)


# Own-source ``g17g_add`` compiled for the accepted beta-5 native workload.
# The native caller-owned executable page is zero after this exact prefix.
G17G_ADD_SHADER = bytes.fromhex(
    "2ca0020012087c003c800200040000000ca0420000000c001c80420004000000"
    "ef040300a80c0042af040300e80c00400f204300a80c00400700000c00000000"
    "c703400e0000000000010700000d0000000000001c8002000000000034810100"
    "2000a0020c800200040000002704041a2100a302888000001c80020004000000"
    "270404003000a4124b1c09445b1e09040b1409041b1609042b1809043b1a0904"
    "6b2009047b220904230007024220a0020e"
)

G17G_ADD_SHADER_RELOCATION_OFFSET = 0x06
G17G_ADD_SHADER_RELOCATION_UNIT = 0x2000
G17G_ADD_SHADER_RECORD_STRIDE = 0xC0
G17G_ADD_RESOURCE_RECORD_STRIDE = 0x20
# The native four-encoder first-work command keeps one selector-3 descriptor
# and one resource object.  Its launch copies advance the table selector in a
# split form: byte +1 supplies the low seven bits (with bit 7 set), while the
# selector at byte +4 advances by two whenever that low field wraps.  Thus the
# first four copies begin a0/12, c0/12, e0/12, 80/14.  Sixty-four records fit
# in the observed one-page shader, CDM, and resource arenas.
G17G_ADD_MAX_DIRECT_DISPATCHES = 64


def relocate_add_shader(reference_va, target_va):
    """Relocate the one address-bearing immediate in ``g17g_add``.

    Same-boot native submission two duplicates its compiler arena at
    ``+0x70000``.  Its otherwise byte-identical program advances the u16 at
    offset six by ``0x38``, establishing an address unit of 0x2000 bytes.
    """
    reference_va = _u64(reference_va, "reference shader address")
    target_va = _u64(target_va, "target shader address")
    delta = target_va - reference_va
    if delta < 0 or delta % G17G_ADD_SHADER_RELOCATION_UNIT:
        raise ValueError(
            "compute shader relocation is not a positive 0x2000 multiple"
        )
    data = bytearray(G17G_ADD_SHADER)
    value = struct.unpack_from(
        "<H", data, G17G_ADD_SHADER_RELOCATION_OFFSET
    )[0]
    value += delta // G17G_ADD_SHADER_RELOCATION_UNIT
    if value >= (1 << 16):
        raise ValueError("compute shader relocation immediate overflow")
    struct.pack_into(
        "<H", data, G17G_ADD_SHADER_RELOCATION_OFFSET, value
    )
    return bytes(data)


def build_add_shader_program(
        reference_va, target_va, dispatch_count=1, dispatch_index_base=0):
    """Build the caller-owned program array for one CDM descriptor.

    Native encodes multiple compute encoders in one selector-3 item as a
    sequence of 0xc0-stride copies of the same compiled kernel.  The first
    two instructions jointly select the matching 0x20-stride resource record.
    Native's first four encodings are ``a0/12``, ``c0/12``, ``e0/12``, and
    ``80/14`` at bytes ``+1/+4``.  The ordinary page-placement relocation
    remains common to every copy.
    """
    dispatch_count = int(dispatch_count)
    if not 1 <= dispatch_count <= G17G_ADD_MAX_DIRECT_DISPATCHES:
        raise ValueError(
            "add shader dispatch count must be 1 through %d"
            % G17G_ADD_MAX_DIRECT_DISPATCHES
        )
    dispatch_index_base = int(dispatch_index_base)
    if (
        dispatch_index_base < 0
        or dispatch_index_base + dispatch_count
        > G17G_ADD_MAX_DIRECT_DISPATCHES
    ):
        raise ValueError("add shader resource-selector range is out of bounds")
    if dispatch_count * G17G_ADD_SHADER_RECORD_STRIDE > PAGE_SIZE:
        raise ValueError("add shader program array exceeds one page")
    base = relocate_add_shader(reference_va, target_va)
    result = bytearray(PAGE_SIZE)
    for index in range(dispatch_count):
        variant = bytearray(base)
        resource_index = dispatch_index_base + index
        low = (
            (base[1] & 0x7F)
            + resource_index * G17G_ADD_RESOURCE_RECORD_STRIDE
        )
        carry, low = divmod(low, 0x80)
        variant[1] = 0x80 | low
        variant[4] = base[4] + 2 * carry
        if variant[4] >= 0x100:
            raise ValueError("add shader resource selector overflow")
        start = index * G17G_ADD_SHADER_RECORD_STRIDE
        result[start:start + len(variant)] = variant
    return bytes(result)


def add_resource_record_offset(index):
    """Return the resource-object offset selected by one shader copy."""
    index = int(index)
    if not 0 <= index < G17G_ADD_MAX_DIRECT_DISPATCHES:
        raise ValueError("add resource-table slot is out of range")
    return (
        RESOURCE_TABLE_OFFSET
        + index * G17G_ADD_RESOURCE_RECORD_STRIDE
    )


def build_compute_pipeline_support():
    """Build the sparse caller-owned compiler support page for g17g_add."""
    data = bytearray(PAGE_SIZE)
    data[
        COMPUTE_PIPELINE_RECORD_OFFSET:
        COMPUTE_PIPELINE_RECORD_OFFSET + len(COMPUTE_PIPELINE_RECORD)
    ] = COMPUTE_PIPELINE_RECORD
    data[
        COMPUTE_PIPELINE_AUX_RECORD_OFFSET:
        COMPUTE_PIPELINE_AUX_RECORD_OFFSET + len(COMPUTE_PIPELINE_AUX_RECORD)
    ] = COMPUTE_PIPELINE_AUX_RECORD
    return bytes(data)


def expand_compute_context1_dvas():
    """Expand the complete native first-compute selector-zero leaf set."""
    pages = []
    for base, page_count in COMPUTE_CONTEXT1_RUNS:
        if base & (PAGE_SIZE - 1) or int(page_count) <= 0:
            raise ValueError("invalid compute context-1 run")
        pages.extend(
            int(base) + index * PAGE_SIZE
            for index in range(int(page_count))
        )
    if len(pages) != COMPUTE_CONTEXT1_PAGE_COUNT:
        raise ValueError("compute context-1 page count changed")
    if pages != sorted(set(pages)):
        raise ValueError("compute context-1 runs overlap or are unordered")
    encoded = b"".join(struct.pack("<Q", dva) for dva in pages)
    if hashlib.sha256(encoded).hexdigest() != COMPUTE_CONTEXT1_DVA_SHA256:
        raise ValueError("compute context-1 DVA hash changed")
    return tuple(pages)


def expand_compute_context1_read_only_dvas():
    """Expand and validate the exact native GPU-read-only leaf subset."""
    pages = tuple(
        int(base) + index * PAGE_SIZE
        for base, page_count in COMPUTE_CONTEXT1_READ_ONLY_RUNS
        for index in range(int(page_count))
    )
    if len(pages) != COMPUTE_CONTEXT1_READ_ONLY_PAGE_COUNT:
        raise ValueError("compute read-only page count changed")
    if pages != tuple(sorted(set(pages))):
        raise ValueError("compute read-only runs overlap or are unordered")
    if not set(pages) <= set(expand_compute_context1_dvas()):
        raise ValueError("compute read-only leaf is absent from topology")
    encoded = b"".join(struct.pack("<Q", dva) for dva in pages)
    if hashlib.sha256(encoded).hexdigest() != (
        COMPUTE_CONTEXT1_READ_ONLY_DVA_SHA256
    ):
        raise ValueError("compute read-only DVA hash changed")
    return pages


def build_compute_address_list_pages(
        buffer_base, address_list_base=COMPUTE_ADDRESS_LIST_PAGE_DVAS[0]):
    """Build a relocatable 4-KiB address enumeration for 11 buffers."""
    buffer_base = _u64(buffer_base, "operand buffer base")
    address_list_base = _u64(address_list_base, "address-list base")
    if buffer_base & (PAGE_SIZE - 1):
        raise ValueError("operand buffer base must be page aligned")
    if address_list_base & (PAGE_SIZE - 1):
        raise ValueError("address-list base must be page aligned")
    page_dvas = tuple(
        address_list_base + index * PAGE_SIZE for index in range(4)
    )
    pages = [bytearray(PAGE_SIZE) for _dva in COMPUTE_ADDRESS_LIST_PAGE_DVAS]
    entries_per_page = PAGE_SIZE // COMPUTE_ADDRESS_LIST_ENTRY_STRIDE
    for buffer_index in range(COMPUTE_OPERAND_TABLE_ENTRIES):
        run_base = (
            buffer_base + buffer_index * COMPUTE_OPERAND_BUFFER_STRIDE
        )
        for entry_index in range(COMPUTE_ADDRESS_LIST_ENTRIES_PER_BUFFER):
            flat_index = (
                buffer_index * COMPUTE_ADDRESS_LIST_ENTRIES_PER_BUFFER
                + entry_index
            )
            page_index, local_index = divmod(flat_index, entries_per_page)
            struct.pack_into(
                "<Q", pages[page_index],
                local_index * COMPUTE_ADDRESS_LIST_ENTRY_STRIDE,
                run_base + entry_index * COMPUTE_ADDRESS_LIST_ADDRESS_STRIDE,
            )
    result = {
        dva: bytes(page)
        for dva, page in zip(page_dvas, pages)
    }
    if (
        buffer_base == COMPUTE_REFERENCE_OPERAND_BUFFER_BASE
        and page_dvas == COMPUTE_ADDRESS_LIST_PAGE_DVAS
    ):
        hashes = tuple(
            hashlib.sha256(result[dva]).hexdigest()
            for dva in COMPUTE_ADDRESS_LIST_PAGE_DVAS
        )
        if hashes != COMPUTE_ADDRESS_LIST_PAGE_SHA256:
            raise ValueError("compute address-list numeric page hashes changed")
    return result


def _u64(value, name):
    value = int(value)
    if not 0 <= value < (1 << 64):
        raise ValueError("%s does not fit in u64" % name)
    return value


def build_register_array(registers, count):
    """Encode an exact ordered sequence of ``(register, value)`` pairs."""
    pairs = tuple((int(register), _u64(value, "register value"))
                  for register, value in registers)
    if len(pairs) != int(count):
        raise ValueError(
            "G17G register program has %d entries, expected %d"
            % (len(pairs), int(count))
        )
    data = bytearray(len(pairs) * COMPUTE_REGISTER_SIZE)
    for index, (register, value) in enumerate(pairs):
        if not 0 <= register < (1 << 32):
            raise ValueError("register number does not fit in u32")
        struct.pack_into(
            "<IQ", data, index * COMPUTE_REGISTER_SIZE, register, value
        )
    return bytes(data)


def build_compute_registers(
    resource,
    cdm,
    robustness,
    scratch,
    dispatch_identity,
    pipeline_word=0x0000000010C08860,
    context_id=1,
    work_ordinal=0,
    register_14028=0,
):
    """Build the 40-write register program from the native G17G dispatch.

    ``scratch`` is the base of the caller-owned low-address scratch layout.
    The offsets below are the relations observed in the accepted first-work
    command, while allocation addresses themselves remain caller choices.
    """
    resource = _u64(resource, "resource address")
    cdm = _u64(cdm, "CDM address")
    robustness = _u64(robustness, "robustness address")
    scratch = _u64(scratch, "scratch address")
    dispatch_identity = _u64(dispatch_identity, "dispatch identity")
    context_id = int(context_id)
    work_ordinal = int(work_ordinal)
    register_14028 = _u64(register_14028, "register 0x14028")
    if not 0 <= context_id < (1 << 8):
        raise ValueError("compute register context ID does not fit in u8")
    if not 0 <= work_ordinal < (1 << 8):
        raise ValueError("compute register work ordinal does not fit in u8")
    context_work = (context_id << 8) | work_ordinal
    return (
        (0x1A510, resource),
        (0x1A420, cdm),
        (0x1A4D0, resource + 0x1480),
        (0x1A4D8, resource + 0x1488),
        (0x1A4E0, resource + 0x1490),
        (0x1A4E8, resource + 0x1498),
        (0x1A440, 0x0000000154024201),
        (0x0D4A1, 0x54B),
        (0x0D411, 0x0000000200000001),
        (0x0A599, 0x000000F500400020),
        (0x1A458, pipeline_word),
        (0x101D9, 0x1C),
        (0x1A089, 0),
        (0x1A091, 0),
        (0x1A059, 0),
        (0x1A061, 0),
        (0x1A0B9, 0),
        (0x1A0C1, 0),
        (0x101D1, 0),
        (0x0D479, 0),
        (0x1A0E9, 8),
        (0x1A141, 0),
        (0x107A1, 0xFF0000),
        (0x1A540, dispatch_identity),
        (0x014A9, dispatch_identity),
        (0x0A351, dispatch_identity),
        (0x0A731, 0),
        (0x10201, context_work),
        (0x10428, context_work),
        (0x14028, register_14028),
        (0x14070, robustness | 1),
        (0x10229, scratch + 0x1E800),
        (0x140A8, scratch + 0x1F000),
        (0x10099, scratch + 0x0F405),
        (0x10091, scratch + 0x1E400),
        (0x0A5C1, scratch + 0x00005),
        (0x0A5C9, scratch + 0x0F000),
        (0x0A731, 0),
        (0x1A440, 0x0000000154024209),
        (0x0A599, 0x0000006000400020),
    )


def build_compute_descriptor(
    registers,
    scheduler_record,
    low_alias,
    cdm_terminator,
    dispatch_identity,
    dispatch_a,
    dispatch_b,
    status_a,
    status_b,
    shared_control,
    zero_page,
    submit_sequence=0,
    context_id=1,
    descriptor_index=0,
    lifecycle_ordinal=1,
    queue_submission=None,
    queue_ordinal=None,
    tail_submit_sequence=None,
    user_timestamp_start=0,
    user_timestamp_end=0,
    sampler_heap=0,
    sampler_count=0,
):
    """Build the complete one-page selector-3 G17G work item."""
    registers = tuple(registers)
    if len(registers) != COMPUTE_REGISTER_COUNT:
        raise ValueError("G17G compute requires exactly 40 register writes")
    values = {}
    for register, value in registers:
        values.setdefault(int(register), []).append(int(value))

    def register_value(register, occurrence=0):
        try:
            return values[int(register)][int(occurrence)]
        except (KeyError, IndexError) as error:
            raise ValueError(
                "G17G descriptor lacks register %#x occurrence %d"
                % (int(register), int(occurrence))
            ) from error

    dispatch_identity = _u64(dispatch_identity, "dispatch identity")
    if register_value(0x1A540) != dispatch_identity:
        raise ValueError("descriptor and register dispatch identities differ")
    cdm = register_value(0x1A420)
    cdm_terminator = _u64(cdm_terminator, "CDM terminator")
    if cdm_terminator < cdm:
        raise ValueError("CDM terminator precedes its stream base")

    data = bytearray(COMPUTE_DESCRIPTOR_SIZE)
    struct.pack_into(
        "<IQI", data, 0,
        COMPUTE_SELECTOR,
        _u64(submit_sequence, "submit sequence"),
        int(context_id),
    )
    struct.pack_into("<Q", data, 0x10, _u64(scheduler_record, "scheduler"))
    struct.pack_into("<4H", data, 0x18, *COMPUTE_HEADER_U16)
    primary = build_register_array(registers, COMPUTE_REGISTER_COUNT)
    data[COMPUTE_REGISTER_START:
         COMPUTE_REGISTER_START + len(primary)] = primary

    low_alias = _u64(low_alias, "descriptor low alias")
    struct.pack_into("<Q", data, 0x740, low_alias + COMPUTE_REGISTER_START)
    struct.pack_into("<I", data, 0x748, COMPUTE_REGISTER_COUNT)

    secondary = (
        (0x10099, register_value(0x0A5C1)),
        (0x10091, register_value(0x0A5C9)),
        (0x0A5C1, register_value(0x10099)),
        (0x0A5C9, register_value(0x10091)),
    )
    secondary_body = build_register_array(
        secondary, COMPUTE_SECONDARY_REGISTER_COUNT
    )
    data[COMPUTE_SECONDARY_REGISTER_START:
         COMPUTE_SECONDARY_REGISTER_START + len(secondary_body)] = (
             secondary_body
         )
    struct.pack_into(
        "<Q", data, 0xE60, low_alias + COMPUTE_SECONDARY_REGISTER_START
    )
    struct.pack_into("<I", data, 0xE68, COMPUTE_SECONDARY_REGISTER_COUNT)

    struct.pack_into("<Q", data, 0xED8, register_value(0x1A510))
    struct.pack_into("<Q", data, 0xEE0, cdm_terminator)
    struct.pack_into("<Q", data, 0xF08, register_value(0x1A440, 0))
    struct.pack_into("<I", data, 0xF20, dispatch_identity >> 32)
    struct.pack_into("<I", data, 0xF28, 0xFFFFFFFF)
    data[0xF2C:0xF3C] = build_compute_sampler_input(sampler_heap, sampler_count)
    struct.pack_into("<Q", data, 0xF40, _u64(dispatch_a, "dispatch A"))
    struct.pack_into("<Q", data, 0xF48, _u64(dispatch_b, "dispatch B"))
    lifecycle_ordinal = int(lifecycle_ordinal)
    if not 1 <= lifecycle_ordinal < (1 << 24):
        raise ValueError("descriptor lifecycle ordinal is out of range")
    if queue_submission is None:
        queue_submission = lifecycle_ordinal
    queue_submission = int(queue_submission)
    if not 1 <= queue_submission < (1 << 24):
        raise ValueError("descriptor queue submission is out of range")
    struct.pack_into("<I", data, 0xF50, queue_submission << 8)
    struct.pack_into("<I", data, 0xF54, int(descriptor_index))
    if queue_ordinal is None:
        queue_ordinal = submit_sequence
    queue_ordinal = int(queue_ordinal)
    if not 0 <= queue_ordinal < (1 << 32):
        raise ValueError("descriptor queue ordinal is out of range")
    struct.pack_into("<I", data, 0xF58, queue_ordinal)
    struct.pack_into("<I", data, 0xF60, lifecycle_ordinal)
    struct.pack_into("<Q", data, 0xF68, dispatch_identity & 0xFFFFFFFF)
    if tail_submit_sequence is None:
        tail_submit_sequence = submit_sequence
    struct.pack_into("<Q", data, 0xF70, _u64(
        tail_submit_sequence, "tail submit sequence"
    ))
    struct.pack_into("<Q", data, 0xF7C, _u64(status_a, "status A"))
    struct.pack_into("<Q", data, 0xF84, _u64(status_b, "status B"))
    # Source-only T8142 probes qualified these optional pointers, including
    # distinct pages spanning the selected 64 MiB timestamp allocation window.
    # Firmware writes nanoseconds here; internal status uses 24 MHz ticks.
    struct.pack_into("<Q", data, 0xF8C, _u64(user_timestamp_start, "user timestamp start"))
    struct.pack_into("<Q", data, 0xF94, _u64(user_timestamp_end, "user timestamp end"))

    # Unaligned final support structure, reproduced from the native G17G item.
    struct.pack_into(
        "<Q", data, 0xFB2, _u64(shared_control, "shared control")
    )
    struct.pack_into("<I", data, 0xFBA, 0xB1000001)
    data[0xFC4] = 0x80
    data[0xFC5] = 0x66
    struct.pack_into("<Q", data, 0xFCB, _u64(zero_page, "zero page"))
    data[0xFD3] = 2
    struct.pack_into("<H", data, 0xFDA, 4)
    return bytes(data)


def build_compute_sampler_input(heap=0, count=0):
    """EncoderParams sampler input, reused for completion timestamps by FW."""
    heap = _u64(heap, 'compute sampler heap')
    if heap & 7 or not 0 <= count <= 1024 or bool(heap) != bool(count):
        raise ValueError('invalid compute sampler heap/count')
    return struct.pack('<QII', heap, count, count + 1 if count else 0)


def build_compute_optional(
    context_low,
    context_high,
    shared_control,
    channel_control,
    submission_ordinal=1,
    token=0x119,
    first_queue=True,
    queue_index=0,
    byte_46=0,
):
    """Build the selector-15 record paired with the G17G compute item."""
    data = bytearray(COMPUTE_OPTIONAL_SIZE)
    struct.pack_into("<I", data, 0, COMPUTE_OPTIONAL_SELECTOR)
    struct.pack_into("<Q", data, 0x08, _u64(context_low, "low context"))
    struct.pack_into("<Q", data, 0x10, _u64(context_high, "high context"))
    first_queue = bool(first_queue)
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 16):
        raise ValueError("compute queue index does not fit in u16")
    byte_46 = int(byte_46)
    if not 0 <= byte_46 < (1 << 8):
        raise ValueError("selector-15 byte +0x46 does not fit in u8")
    struct.pack_into("<H", data, 0x18, queue_index)
    for offset, value in (
        (0x1A, 1 if first_queue else 0),
        (0x1E, 2),
        (0x22, 2),
        (0x32, 1),
        (0x3E, submission_ordinal),
        (0x52, 1 if first_queue else 0),
        (0x5A, token),
        (0x5E, 2),
        (0x62, 1 if first_queue else 0),
        (0x66, 1),
    ):
        if not 0 <= int(value) < (1 << 16):
            raise ValueError("selector-15 scalar does not fit in u16")
        struct.pack_into("<H", data, offset, int(value))
    struct.pack_into(
        "<Q", data, 0x36, _u64(shared_control, "shared control")
    )
    struct.pack_into(
        "<Q", data, 0x4A, _u64(channel_control, "channel control")
    )
    data[0x46] = byte_46
    data[0x76:0x86] = b"\xFF" * 0x10
    return bytes(data)


def build_compute_event(group_number=1, generation=2, queue_index=0):
    """Build the complete selector-14 record from the native compute group."""
    if not 0 <= int(group_number) < (1 << 24):
        raise ValueError("compute group number is out of range")
    if not 0 <= int(generation) < (1 << 8):
        raise ValueError("compute event generation is out of range")
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 16):
        raise ValueError("compute event queue index does not fit in u16")
    data = bytearray(COMPUTE_EVENT_SIZE)
    struct.pack_into("<I", data, 0x00, COMPUTE_EVENT_SELECTOR)
    struct.pack_into("<I", data, 0x04, 0x00010000 | queue_index)
    struct.pack_into(
        "<I", data, 0x08,
        (int(group_number) << 8) | int(generation),
    )
    struct.pack_into("<I", data, 0x10, 0x200)
    return bytes(data)


def build_compute_channel_slot(queue, queue_index=0, item_limit=3):
    """Build an initial channel-8 slot, including queue registration.

    The native one-command form publishes ``[15, 3, 14]`` with limit three.
    More selector-3/event pairs may be present at the same first-work boundary;
    bit 24 remains the one-time registration tag while the low 24 bits carry
    their cumulative odd item limit.
    """
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("compute channel queue index does not fit in u8")
    item_limit = int(item_limit)
    if not 3 <= item_limit < (1 << 24) or item_limit & 1 == 0:
        raise ValueError("initial compute item limit must be an odd u24")
    return g17g.build_ring_slot(
        _u64(queue, "queue address"),
        2,
        0x01000000 | item_limit
        | (queue_index << g17g.RING_SLOT_QUEUE_INDEX_SHIFT),
    )


def build_compute_repeat_channel_slot(queue, item_limit=5, queue_index=0):
    """Build an ordinary compute publication after queue registration.

    The first channel slot carries bit 24 while publishing the three-item
    ``[15, 3, 14]`` registration group.  Same-queue submissions reuse the
    selector-15 object, append only ``[3, 14]``, and therefore publish the
    untagged cumulative item limit (five for submission two).
    """
    item_limit = int(item_limit)
    if not 3 < item_limit < (1 << 24) or item_limit & 1 == 0:
        raise ValueError("compute repeat item limit must be an odd u24")
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("compute channel queue index does not fit in u8")
    return g17g.build_ring_slot(
        _u64(queue, "queue address"),
        2,
        item_limit | (queue_index << g17g.RING_SLOT_QUEUE_INDEX_SHIFT),
    )


def build_compute_full_group_channel_slot(
        queue, item_limit=6, queue_index=0):
    """Build a later same-queue slot carrying a complete item group.

    The earliest mixed render/compute repeat appends a second complete
    ``[15, 3, 14]`` group.  Unlike the initial registration slot, its
    cumulative item limit has no bit-24 registration tag; unlike the ordinary
    two-item repeat, that limit may be even (six for command two).
    """
    item_limit = int(item_limit)
    if not 3 < item_limit < (1 << 24) or item_limit % 3:
        raise ValueError(
            "compute full-group item limit must be a positive multiple of 3"
        )
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("compute channel queue index does not fit in u8")
    return g17g.build_ring_slot(
        _u64(queue, "queue address"),
        2,
        item_limit | (queue_index << g17g.RING_SLOT_QUEUE_INDEX_SHIFT),
    )


def build_compute_queue_record(
    pointer_block,
    item_ring,
    job_list,
    channel_control,
    queue_generation=COMPUTE_QUEUE_GENERATION,
):
    """Build the exact pre-kick queue record used by native G17G compute."""
    queue_generation = int(queue_generation)
    if not 0 <= queue_generation < (1 << 32):
        raise ValueError("queue generation does not fit in u32")
    return g17g.build_queue_record(
        _u64(pointer_block, "pointer block"),
        _u64(item_ring, "item ring"),
        _u64(job_list, "job list"),
        _u64(channel_control, "channel control"),
        word_20=0xFFFFFFFF00000000,
        word_28=0x0000000200000002,
        word_30=0xFFFF000000000000,
        word_38=0x0000000200000000,
        word_40=(queue_generation << 32) | 0xFFFFFFFF,
    )


def build_compute_queue_context_item(
        descriptor, queue, item_index=0, queue_index=0):
    """Build one 0x200-stride per-command queue-context record."""
    item_index = int(item_index)
    if not 0 <= item_index < (1 << 16):
        raise ValueError("compute queue-context item index is out of range")
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("compute queue-context queue index is out of range")
    data = bytearray(0x200)
    struct.pack_into(
        "<Q", data, 0x00,
        0x1000000000000004
        + (queue_index << 42)
        + item_index * 4,
    )
    struct.pack_into("<Q", data, 0x10, _u64(descriptor, "descriptor"))
    struct.pack_into("<Q", data, 0x18, _u64(queue, "queue"))
    struct.pack_into("<Q", data, 0x20, 0xFFFF080000000001)
    struct.pack_into("<Q", data, 0x28, (queue_index << 40) | item_index)
    struct.pack_into("<Q", data, 0x138, 2)
    descriptor = _u64(descriptor, "descriptor")
    descriptor_delta = descriptor - COMPUTE_DESCRIPTOR_BASE
    if descriptor_delta < 0 or descriptor_delta % 0x20:
        raise ValueError("compute descriptor has no aligned context locator")
    descriptor_locator_delta = descriptor_delta // 0x20
    struct.pack_into(
        "<Q", data, 0x150,
        0x000128039001A002 + descriptor_locator_delta,
    )
    struct.pack_into(
        "<Q", data, 0x158,
        0x000020039001A03B + descriptor_locator_delta,
    )
    struct.pack_into("<Q", data, 0x178, 0x003FFFFFFFFFFFFF)
    struct.pack_into("<Q", data, 0x180, 1)
    return bytes(data)


def compute_queue_context_item_offset(item_index):
    """Return the cyclic offset for a monotonic compute context-item index."""
    item_index = int(item_index)
    if item_index < 0:
        raise ValueError("compute queue-context item index is negative")
    return (
        (item_index + 1) % COMPUTE_QUEUE_CONTEXT_ITEM_COUNT
    ) * COMPUTE_QUEUE_CONTEXT_ITEM_SIZE


def build_compute_queue_context(
        descriptor, queue, item_index=0, queue_index=0):
    """Build the page reached through selector-15's paired aliases."""
    item_index = int(item_index)
    if not 0 <= item_index < 31:
        raise ValueError("compute queue-context page item is out of range")
    data = bytearray(PAGE_SIZE)
    start = compute_queue_context_item_offset(item_index)
    item = build_compute_queue_context_item(
        descriptor, queue, item_index=item_index, queue_index=queue_index
    )
    data[start:start + len(item)] = item
    return bytes(data)


def build_compute_scheduler_record(slot_page, slot_index=1, work_id=0):
    """Build one native sparse scheduler record selected by selector 3.

    The 36-record pool shares one page of four-byte ready words.  Native
    record zero points at the page base, while work records one through 35
    point at ``slot_page + 4 * record_index``.  The first accepted compute
    graph uses record/slot one and work ID zero.
    """
    slot_page = _u64(slot_page, "scheduler slot page")
    if slot_page & (PAGE_SIZE - 1):
        raise ValueError("scheduler slot page must be page aligned")
    slot_index = int(slot_index)
    work_id = int(work_id)
    if not 0 <= slot_index < 256:
        raise ValueError("scheduler slot index is out of range")
    if not 0 <= work_id < (1 << 32):
        raise ValueError("scheduler work ID does not fit in u32")
    data = bytearray(0x100)
    struct.pack_into("<Q", data, 0x00, slot_page + 4 * slot_index)
    struct.pack_into("<I", data, 0x08, work_id)
    struct.pack_into("<I", data, 0x10, 0x50)
    return bytes(data)


def build_compute_scheduler_slot():
    """Build the one-word initial scheduler-slot page."""
    data = bytearray(PAGE_SIZE)
    struct.pack_into("<I", data, 0x04, 1)
    return bytes(data)


def build_compute_shared_state(active=1):
    data = bytearray(PAGE_SIZE)
    struct.pack_into("<I", data, 0, int(active))
    return bytes(data)


def build_compute_shared_support(client_state, firmware_state, active=1):
    """Build the G17G shared-support object referenced by selector 3."""
    data = bytearray(PAGE_SIZE)
    struct.pack_into("<Q", data, 0x00, _u64(active, "active ordinal"))
    struct.pack_into("<Q", data, 0x10, 2)
    struct.pack_into("<Q", data, 0x18, 0x0008000000000072)
    struct.pack_into("<Q", data, 0x20, 0x0000160000000000)
    struct.pack_into("<Q", data, 0x28, 0x0000160000000000)
    struct.pack_into("<Q", data, 0x30, _u64(client_state, "client state"))
    struct.pack_into("<I", data, 0x48, 0x58)
    struct.pack_into("<Q", data, 0x4C, _u64(firmware_state, "firmware state"))
    struct.pack_into("<I", data, 0x5C, 1)
    struct.pack_into("<I", data, 0x60, 2)
    return bytes(data)


def build_compute_operand_table(buffer_base):
    """Build the 11-entry G17G client-state operand table."""
    buffer_base = _u64(buffer_base, "operand buffer base")
    data = bytearray(PAGE_SIZE)
    for index in range(COMPUTE_OPERAND_TABLE_ENTRIES):
        value = (
            buffer_base + index * COMPUTE_OPERAND_BUFFER_STRIDE
        ) | COMPUTE_OPERAND_BUFFER_FLAG
        struct.pack_into(
            "<Q", data, index * COMPUTE_OPERAND_TABLE_STRIDE, value
        )
    return bytes(data)


def build_compute_operand_page_lists():
    """Build the three zero pages observed beside the G17G operand table."""
    return bytes(COMPUTE_OPERAND_PAGE_LIST_SIZE)


def encode_shader_pointer(executable_va):
    """Encode the G17G direct-CDM shader pointer."""
    executable_va = _u64(executable_va, "shader address")
    if executable_va & 0x3F:
        raise ValueError("compute shader address must be 64-byte aligned")
    low = (executable_va >> 6) & 0xFFFFFFFF
    control = 0x40000000 | (executable_va >> 40)
    return low | (control << 32)


def build_direct_dispatch(
    shader_va,
    grid,
    threadgroup,
    config=0,
    constant=0x01000000,
    tail=0x60000160,
):
    """Build the accepted 0x2c direct-dispatch CDM record."""
    grid = tuple(int(value) for value in grid)
    threadgroup = tuple(int(value) for value in threadgroup)
    if len(grid) != 3 or len(threadgroup) != 3:
        raise ValueError("grid and threadgroup require three dimensions")
    if any(value <= 0 or value >= (1 << 32)
           for value in grid + threadgroup):
        raise ValueError("dispatch dimensions must be nonzero u32 values")
    return struct.pack(
        "<IIQ3I3II",
        int(config),
        int(constant),
        encode_shader_pointer(shader_va),
        *grid,
        *threadgroup,
        int(tail),
    )


def build_cdm_stream(dispatches):
    records = tuple(dispatches)
    if not records or any(len(record) != CDM_RECORD_SIZE for record in records):
        raise ValueError("CDM stream requires 0x2c-byte dispatch records")
    return b"".join(records) + struct.pack("<I", CDM_TERMINATOR)


def build_buffer_resource_table(buffer_addresses, size=PAGE_SIZE):
    """Build the caller buffer table in kernel argument order."""
    return build_buffer_resource_tables((tuple(buffer_addresses),), size=size)


def build_buffer_resource_tables(dispatch_buffers, size=PAGE_SIZE):
    """Build the 0x20-stride argument records for direct CDM dispatches."""
    records = tuple(tuple(
        _u64(value, "buffer address") for value in addresses
    ) for addresses in dispatch_buffers)
    if not records:
        raise ValueError("resource table requires at least one dispatch")
    if len(records) > G17G_ADD_MAX_DIRECT_DISPATCHES:
        raise ValueError(
            "resource table supports at most %d dispatches"
            % G17G_ADD_MAX_DIRECT_DISPATCHES
        )
    if any(len(record) != 3 for record in records):
        raise ValueError("g17g_add resource record requires three buffers")
    data = bytearray(int(size))
    for record_index, record in enumerate(records):
        start = add_resource_record_offset(record_index)
        if start + 3 * 8 > len(data):
            raise ValueError("resource tables do not fit in their object")
        struct.pack_into("<3Q", data, start, *record)
    return bytes(data)
