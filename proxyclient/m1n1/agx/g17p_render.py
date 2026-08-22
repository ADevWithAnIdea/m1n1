# SPDX-License-Identifier: MIT
"""Ordered T8140/G17P TA and fragment register recipes.

The firmware consumes these arrays as programs. Register numbers can occur more
than once, and the later write can deliberately replace an earlier value, so the
builders return ordered ``(number, value)`` pairs rather than dictionaries.

The address split is visible in working hardware submissions. TA object addresses
are offsets from the render context base, while fragment object addresses and
completion records are full device addresses. Callers always provide full
addresses; this module performs the TA conversion and rejects addresses outside
the context.
"""

import struct
from dataclasses import dataclass


TILE_WIDTH = 32
TILE_HEIGHT = 32
MACRO_TILES_X = 4
MACRO_TILES_Y = 4
REGION_ENTRY_SIZE = 5
MERGE_SCALE = 1.732051
RENDER_TIMESTAMP_A = 0xFFFFFC2000024C68
RENDER_TIMESTAMP_B = 0xFFFFFC2000024C70
RENDER_CLASS4_SUPPORT_SIZE = 0x70
RENDER_CLASS2_COMMAND_COUNT = 0x28
RENDER_CLASS2_OPERAND_OFFSET = 0x5C0
RENDER_CLASS4_COMMAND_COUNT = 0x20
RENDER_CLASS4_OPERAND_OFFSET = 0x580
RENDER_CLASS4_REGISTER_NUMBERS = (
    0x15401, 0x15421, 0x15409, 0x15429,
    0x153C1, 0x15411, 0x153C9, 0x15431,
    0x153D1, 0x15419, 0x153D9, 0x15439,
    0x16429, 0x16060, 0x16431, 0x10039,
    0x16020, 0x16451, 0x15359, 0x100B8,
    0x16461, 0x16090, 0x101E9, 0x160A8,
    0x16068, 0x1A0A9, 0x1A0B1, 0x1A079,
    0x1A081, 0x1A0D9, 0x1A0E1, 0x101C1,
)


def _align(value, alignment):
    return (value + alignment - 1) & -alignment


def _float_bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def _work_stamp(submission_ordinal):
    # Native reserves one ordinal outside the descriptor stream after every
    # two submissions: 0, 1, 3, 4, 6, 7, ... . These command registers carry
    # that same ordinal in the low byte with a fixed 0x100 marker.
    work_ordinal = submission_ordinal + submission_ordinal // 2
    return 0x100 | work_ordinal


@dataclass(frozen=True)
class G17PRenderParameters:
    """Inputs needed by the verified first-render register recipe."""

    width: int
    height: int
    context_base: int

    tilemap: int
    heapmeta: int
    tpc: int
    deflake_1: int
    deflake_2: int
    deflake_3: int
    encoder: int
    ta_status: int

    store_pipeline_bind: int
    store_pipeline: int
    load_pipeline_bind: int
    load_pipeline: int
    scissor_array: int
    depth_bias_array: int
    aux_fb: int
    fragment_status: int

    layers: int = 1
    utile_width: int = 32
    utile_height: int = 32
    samples: int = 1
    sample_size: int = 0
    occlusion_query_base: int = 0
    depth_stride: int = 0
    stencil_stride: int = 0
    depth_aux_stride: int = 0
    stencil_aux_stride: int = 0
    merge_upper_x_bits: int = 0
    merge_upper_y_bits: int = 0
    partial_load_pipeline_bind: int = 0
    partial_load_pipeline: int = 0
    partial_store_pipeline_bind: int = 0
    partial_store_pipeline: int = 0
    sampler_array: int = 0
    sampler_count: int = 0
    process_empty_tiles: bool = True
    emit_uapi_fields: bool = False

    # Queue creation supplies one 4 GiB USC window base. Native G17P work
    # descriptors do not repeat it as the older-generation 0x10061/0x10069
    # register writes; retaining the value here keeps it available to callers
    # without changing the measured 73/89-write programs.
    usc_exec_base: int = 0x100_0000_0000

    # Firmware-owned render timestamp destinations.  The descriptor carries a
    # second start/end pair for optional caller timestamps for each stage.
    timestamp_a: int = RENDER_TIMESTAMP_A
    timestamp_b: int = RENDER_TIMESTAMP_B
    ta_timestamp_end: int = 0
    fragment_timestamp_start: int = RENDER_TIMESTAMP_A
    fragment_timestamp_end: int = RENDER_TIMESTAMP_B
    ta_user_timestamp_start: int = 0
    ta_user_timestamp_end: int = 0
    fragment_user_timestamp_start: int = 0
    fragment_user_timestamp_end: int = 0

    depth_buffer: int = 0
    stencil_buffer: int = 0
    depth_aux_buffer: int = 0
    stencil_aux_buffer: int = 0
    depth_clear_value_bits: int = 0x3f800000
    stencil_clear_value: int = 0
    depth_flags: int = 0
    depth_dimensions: int = 0

    utile_config: int = 0xa000
    multisample_control: int = 0x88
    ppp_control: int = 0x202
    tib_blocks: int = 8
    tile_config: int = 0x10280
    aux_fb_flags: int = 0xc001
    aux_fb_page_count: int = 0x100000
    lifecycle_ordinal: int = 0
    queue_pair: int = 0
    queue_item_index: int = 0
    # The queue, cycle, record-index, and render-status arrays are distinct
    # namespaces.  They usually advance together, but native forced-partial
    # work restarts the low status destinations while retaining a later queue
    # identity.  None preserves the historical coupled behavior.
    status_queue_pair: int | None = None
    status_item_index: int | None = None
    native_cycle_registers: bool = False
    native_record_index_register: bool = False
    native_pair_registers: bool = False
    native_status_registers: bool = False
    # Advance only state consumed by successive items on the same queue pair.
    # Unlike the native_* switches above, this does not infer a pair namespace.
    local_item_registers: bool = False
    # Compatibility umbrella for the original combined hardware experiment.
    native_item_fields: bool = False

    def ta_offset(self, address):
        offset = address - self.context_base
        if offset < 0:
            raise ValueError(
                "TA address %#x precedes context base %#x"
                % (address, self.context_base)
            )
        return offset


def _geometry(params):
    if params.width <= 0 or params.height <= 0:
        raise ValueError("render dimensions must be positive")

    if not 1 <= params.layers <= 2048:
        raise ValueError("render layer count must be within 1..2048")
    if (params.utile_width, params.utile_height) not in (
            (32, 32), (32, 16), (16, 16)):
        raise ValueError("render utile dimensions are invalid")

    tiles_x = (params.width + TILE_WIDTH - 1) // TILE_WIDTH
    tiles_y = (params.height + TILE_HEIGHT - 1) // TILE_HEIGHT
    utiles_per_tile_x = TILE_WIDTH // params.utile_width
    utiles_per_tile_y = TILE_HEIGHT // params.utile_height
    utiles_per_tile = utiles_per_tile_x * utiles_per_tile_y
    mtile_x1 = _align(
        (tiles_x + MACRO_TILES_X - 1) // MACRO_TILES_X, 4)
    mtile_y1 = _align(
        (tiles_y + MACRO_TILES_Y - 1) // MACRO_TILES_Y, 4)
    mtile_x2, mtile_x3 = 2 * mtile_x1, 3 * mtile_x1
    mtile_y2, mtile_y3 = 2 * mtile_y1, 3 * mtile_y1
    mtile_stride = mtile_x1 * mtile_y1
    size1 = (
        REGION_ENTRY_SIZE * mtile_x1 * mtile_y1 * utiles_per_tile + 3
    ) // 4

    return {
        "tiles_x": tiles_x,
        "tiles_y": tiles_y,
        "mtile_x1": mtile_x1,
        "mtile_y1": mtile_y1,
        "size1": size1,
        "size2": mtile_stride,
        "size3": 2 * mtile_stride * utiles_per_tile,
        "x_blocks": mtile_x3 | (mtile_x2 << 9) | (mtile_x1 << 18),
        "y_blocks": mtile_y3 | (mtile_y2 << 9) | (mtile_y1 << 18),
        "screen": ((tiles_y - 1) << 12) | (tiles_x - 1),
        "pixels": (params.width - 1) | ((params.height - 1) << 16),
        "macro_size": (
            mtile_y1 * utiles_per_tile_y
            | (mtile_x1 * utiles_per_tile_x << 16)
        ),
    }


def descriptor_lifecycle_value(kind, ordinal):
    """Return the hardware-tested inert value for this register family."""
    if kind not in ("tiling", "fragment"):
        raise ValueError("kind must be tiling or fragment")
    if ordinal < 0:
        raise ValueError("descriptor lifecycle ordinal must be non-negative")
    return 0


def build_render_class2_prestate(operand_table, firmware_state,
                                 low_object, context_word=3):
    """Build the blank class-2 predecessor of a graphics class-4 object.

    Native graphics reuses one firmware-high support object.  Its first
    publication is class 2 with forty zero operand records and a low-object
    offset; a later publication rewrites the same object into class 4.
    """
    operand_table = int(operand_table)
    low_object = int(low_object)
    if (operand_table >> 32) != (low_object >> 32):
        raise ValueError(
            "class-2 operand table and low object must share a 32-bit DVA prefix")
    out = bytearray(RENDER_CLASS4_SUPPORT_SIZE)
    struct.pack_into("<I", out, 0x00, 2)
    struct.pack_into("<I", out, 0x08, int(context_word))
    struct.pack_into("<I", out, 0x10, 2)
    struct.pack_into("<I", out, 0x14, low_object & 0xffffffff)
    struct.pack_into("<Q", out, 0x18, 0x0004000000000070)
    struct.pack_into("<Q", out, 0x20, 0x0000170000000000)
    struct.pack_into("<Q", out, 0x28, 0x0000170000000000)
    struct.pack_into("<Q", out, 0x30, operand_table)
    struct.pack_into("<I", out, 0x40, 4)
    struct.pack_into("<I", out, 0x48, 0xB8)
    struct.pack_into("<Q", out, 0x4C, int(firmware_state))
    struct.pack_into("<I", out, 0x60, 3)
    return bytes(out)


def _build_render_class4_state(operand_table, firmware_state,
                               context_word, active):
    out = bytearray(RENDER_CLASS4_SUPPORT_SIZE)
    struct.pack_into("<I", out, 0x00, 6)
    struct.pack_into("<I", out, 0x08, int(context_word))
    struct.pack_into("<I", out, 0x10, 2)
    struct.pack_into("<Q", out, 0x18, 0x0004000000000070)
    struct.pack_into("<Q", out, 0x20, 0x0000160000000000)
    struct.pack_into("<Q", out, 0x28, 0x0000160000000000)
    struct.pack_into("<Q", out, 0x30, int(operand_table))
    struct.pack_into("<II", out, 0x40, 4, int(active))
    struct.pack_into("<I", out, 0x48, 0xB0)
    struct.pack_into("<Q", out, 0x4C, int(firmware_state))
    struct.pack_into("<I", out, 0x60, 3)
    return bytes(out)


def build_render_class4_prestate(operand_table, firmware_state,
                                 context_word=2):
    """Build the complete state observed immediately before class-4 publish."""
    return _build_render_class4_state(
        operand_table, firmware_state, context_word, active=0)


def build_render_class4_observed_state(operand_table, firmware_state,
                                       context_word=0):
    """Build the observed post-lifecycle state of render class 4 ``0x20``.

    Independent native direct-render captures agree on this complete 0x70-byte
    layout after class 4 has consumed. The same object was previously used by
    class 2 and therefore cannot be synthesized in this state and registered as
    a fresh class-4 object. The control entry independently names
    ``operand_table + 0x580``; this state names the table base and an unaligned
    firmware-high child pointer at ``+0x4c``.
    """
    return _build_render_class4_state(
        operand_table, firmware_state, context_word, active=1)


def select_render_class4_registers(fragment_registers):
    """Select the exact 32-write class-4 program from a fragment recipe."""
    registers = tuple((int(number), int(value))
                      for number, value in fragment_registers)
    count = len(RENDER_CLASS4_REGISTER_NUMBERS)
    for start in range(len(registers) - count + 1):
        candidate = registers[start:start + count]
        if tuple(number for number, _value in candidate) == \
                RENDER_CLASS4_REGISTER_NUMBERS:
            return candidate
    raise ValueError("fragment recipe has no complete class-4 register program")


def build_render_class4_register_program(fragment_registers):
    """Encode class 4's selected operand-table range as packed register writes."""
    return b"".join(
        struct.pack("<IQ", number, value)
        for number, value in select_render_class4_registers(fragment_registers)
    )


def build_tiling_registers(params):
    """Build the 73-entry ordered TA register program."""
    geometry = _geometry(params)
    offset = params.ta_offset
    tilemap = offset(params.tilemap)
    heapmeta = offset(params.heapmeta)
    deflake_1 = offset(params.deflake_1)
    lifecycle = descriptor_lifecycle_value(
        "tiling", params.lifecycle_ordinal)
    cycle = 0x178020
    status = params.ta_status
    record_index = 0x80005
    status_pair = (params.queue_pair if params.status_queue_pair is None
                   else params.status_queue_pair)
    status_item = (params.queue_item_index if params.status_item_index is None
                   else params.status_item_index)
    if (params.native_item_fields or params.native_pair_registers
            or params.native_cycle_registers):
        cycle += params.queue_pair * 0x5e0000 + params.queue_item_index * 0x20
    elif params.local_item_registers:
        cycle += params.queue_item_index * 0x20
    if (params.native_item_fields or params.native_pair_registers
            or params.native_record_index_register):
        record_index += params.queue_pair * 0x140 + params.queue_item_index * 4
    elif params.local_item_registers:
        record_index += params.queue_item_index * 4
    if params.native_item_fields or params.native_status_registers:
        status = (
            0x1000078000,
            0x1000660000,
            0x1000c40000,
            0x1000078000,
        )[status_pair]
        status += status_item * 0x40
    else:
        status += status_item * 0x40

    work_stamp = _work_stamp(params.lifecycle_ordinal)

    return [
        (0x01748, 0x0000000000000001),
        (0x10141, 0x0000000000000200),
        (0x1c039, tilemap),
        (0x1c9c8, tilemap),
        (0x1c0a1, offset(params.tpc)),
        (0x1c031, heapmeta | 0x8000000000000000),
        (0x1c9c0, heapmeta | 0x8000000000000000),
        (0x1c051, 0x003a0012006b0003),
        (0x1c061, 0x0000000000000001),
        (0x10149, params.utile_config),
        (0x10139, params.multisample_control),
        (0x10111, deflake_1),
        (0x1c9b0, deflake_1),
        (0x10119, offset(params.deflake_2)),
        (0x1c9b8, offset(params.deflake_2)),
        (0x1c958, 0x0000000000000001),
        (0x1c950, offset(params.deflake_3) | 0x0004000000000000),
        (0x1c930, 0x0000000000000000),
        (0x1c880, offset(params.encoder)),
        (0x1c079, heapmeta),
        (0x1c9d8, heapmeta),
        (0x10151, 0x0000000000000000),
        (0x1c199, 0x0000000000000000),
        (0x1c1a1, 0x0000000000000000),
        (0x1c1a9, 0x0000000000000000),
        (0x1c1b1, 0x0000000000000000),
        (0x1c1b9, 0x0000000000000000),
        (0x1c8f8, 0x0000000000008860),
        (0x1c0b1, geometry["size1"]),
        (0x1c850, geometry["size1"]),
        (0x10131, params.multisample_control),
        (0x10121, params.ppp_control),
        (0x10129, geometry["pixels"]),
        (0x101b9, geometry["screen"]),
        (0x1c069, geometry["x_blocks"]),
        (0x1c071, geometry["y_blocks"]),
        (0x1c081, geometry["size2"]),
        (0x1c0a9, geometry["size3"]),
        (0x10171, 0x0000000000000100),
        (0x10169, (0xe000 | (params.layers - 1))
         if params.layers > 1 else 0x8000),
        (0x0a309, 0x0000000000000000),
        (0x1c8e0, 0xffffffffffffffff),
        (0x1c8e8, 0xffffffffffffffff),
        (0x1c898, 0x0000000000000000),
        (0x101e1, 0x000000000000001c),
        (0x1c9e8, 0x0000000000000000),
        (0x1a099, 0x0000000000000000),
        (0x1a0a1, 0x0000000000000000),
        (0x1a069, 0x0000000000000000),
        (0x1a071, 0x0000000000000000),
        (0x1a0c9, 0x0000000000000000),
        (0x1a0d1, 0x0000000000000000),
        (0x101c9, 0x0000000000000000),
        (0x0d471, 0x0000000000000000),
        (0x1a0f1, 0x0000000000000008),
        (0x10799, 0x0000000000ff0000),
        (0x1c830, 0x0000000000000000),
        (0x1ca30, cycle),
        (0x16c39, cycle),
        (0x1c910, record_index),
        (0x0a5a1, 0x000000fe00400020),
        (0x0d419, 0x0000000200000001),
        (0x1ca10, lifecycle),
        (0x014a1, lifecycle),
        (0x0a349, lifecycle),
        (0x10209, work_stamp),
        (0x1c9f0, work_stamp),
        (0x14320, work_stamp),
        (0x14308, 0x0000000000000000),
        (0x14318, status | 1),
        (0x01740, 0x0000000000000001),
        (0x1c880, deflake_1),
        (0x1c898, 0x0000000000000001),
    ]


def build_fragment_registers(params):
    """Build the 89-entry ordered fragment register program."""
    geometry = _geometry(params)
    lifecycle = descriptor_lifecycle_value(
        "fragment", params.lifecycle_ordinal)
    cycle = 0x178020
    status = params.fragment_status
    status_pair = (params.queue_pair if params.status_queue_pair is None
                   else params.status_queue_pair)
    status_item = (params.queue_item_index if params.status_item_index is None
                   else params.status_item_index)
    if (params.native_item_fields or params.native_pair_registers
            or params.native_cycle_registers):
        cycle += params.queue_pair * 0x5e0000 + params.queue_item_index * 0x20
    elif params.local_item_registers:
        cycle += params.queue_item_index * 0x20
    if params.native_item_fields or params.native_status_registers:
        status = (
            0x10001a8000,
            0x1000788000,
            0x1000d68000,
            0x10001a8000,
        )[status_pair]
        status += status_item * 0x40
    else:
        status += status_item * 0x40
    tile_state = (
        0x3717f
        | ((geometry["tiles_x"] - 1) << 44)
        | ((geometry["tiles_y"] - 1) << 53)
        | 0x2000000000
        | (0x100000000 if params.layers > 1 else 0)
        | ((params.utile_config & 0xf000) << 28)
    )

    merge_upper_x = (
        params.merge_upper_x_bits if params.emit_uapi_fields
        else _float_bits(MERGE_SCALE / params.width)
    )
    merge_upper_y = (
        params.merge_upper_y_bits if params.emit_uapi_fields
        else _float_bits(MERGE_SCALE / params.height)
    )

    work_stamp = _work_stamp(params.lifecycle_ordinal)

    return [
        (0x01739, 0x0000000000000001),
        (0x10009, params.utile_config),
        (0x15379, params.store_pipeline_bind),
        (0x15381, params.store_pipeline),
        (0x15369, params.load_pipeline_bind),
        (0x15371, params.load_pipeline),
        (0x15131, merge_upper_x),
        (0x15139, merge_upper_y),
        (0x100a1, 0x0000000000000000),
        (0x15069, 0x0000000000000000),
        (0x15071, 0x0000000000000000),
        (0x16058, 0x0000000000000000),
        (0x10019, params.multisample_control),
        (0x100b1, geometry["macro_size"]),
        (0x16030, geometry["macro_size"]),
        (0x100d9, geometry["screen"]),
        (0x0a301, 0x0000000000000000),
        (0x10791, 0x0000000000ff0200),
        (0x16098, params.heapmeta),
        (0x15109, params.scissor_array),
        (0x15101, params.depth_bias_array),
        (0x15021, params.aux_fb_flags),
        (0x15211, (params.height << 32) | params.width),
        (0x15049, params.aux_fb_page_count),
        (0x10051, params.tib_blocks),
        (0x15321, params.depth_dimensions),
        (0x15301, params.depth_clear_value_bits),
        (0x15309, params.stencil_clear_value | 0x300),
        (0x15311, params.occlusion_query_base),
        (0x15319, params.depth_flags),
        (0x15349, 0x0000000004040404),
        (0x15351, 0x0000000000000000),
        (0x15329, params.depth_buffer),
        (0x15331, params.depth_buffer),
        (0x15339, params.stencil_buffer),
        (0x15341, params.stencil_buffer),
        (0x15231, 0x0000000000000000),
        (0x15221, 0x0000000000000000),
        (0x15239, 0x0000000000000000),
        (0x15229, 0x0000000000000000),
        (0x15401, params.depth_stride),
        (0x15421, params.depth_stride),
        (0x15409, params.stencil_stride),
        (0x15429, params.stencil_stride),
        (0x153c1, params.depth_aux_buffer),
        (0x15411, params.depth_aux_stride),
        (0x153c9, params.depth_aux_buffer),
        (0x15431, params.depth_aux_stride),
        (0x153d1, params.stencil_aux_buffer),
        (0x15419, params.stencil_aux_stride),
        (0x153d9, params.stencil_aux_buffer),
        (0x15439, params.stencil_aux_stride),
        (0x16429, params.tilemap),
        (0x16060, params.heapmeta),
        (0x16431, (4 * geometry["size1"]) << 24),
        (0x10039, params.tile_config),
        (0x16020, 0x0000000000000000),
        (0x16451, 0x0000000000000000),
        (0x15359, 0x0000000000000000),
        (0x100b8, 0x0000000000008860),
        (0x16461, params.aux_fb),
        (0x16090, params.aux_fb),
        (0x101e9, 0x000000000000001c),
        (0x160a8, 0x0000000000000000),
        (0x16068, tile_state),
        (0x1a0a9, 0x0000000000000000),
        (0x1a0b1, 0x0000000000000000),
        (0x1a079, 0x0000000000000000),
        (0x1a081, 0x0000000000000000),
        (0x1a0d9, 0x0000000000000000),
        (0x1a0e1, 0x0000000000000000),
        (0x101c1, 0x0000000000000000),
        (0x0d469, 0x0000000000000000),
        (0x1a0f9, 0x0000000000000008),
        (0x0a5a9, 0x0000014600400020),
        (0x0d429, 0x0000000200000001),
        (0x160e0, lifecycle),
        (0x01499, lifecycle),
        (0x0a341, lifecycle),
        (0x1c838, 0x0000000000000000),
        (0x1ca28, cycle),
        (0x10211, work_stamp),
        (0x10420, work_stamp),
        (0x14048, 0x0000000000000000),
        (0x14080, status | 1),
        (0x01731, 0x0000000000000001),
        (0x16020, 0x0000000000000001),
        (0x16020, 0x0000000000000000),
        (0x16068, 0x0000000000040000),
    ]


def build_fragment_partial_store_registers(params):
    """Build the 16-write register program used when pausing a partial render."""
    return [
        (0x15379, params.partial_store_pipeline_bind),
        (0x15381, params.partial_store_pipeline),
        (0x10039, params.tile_config),
        (0x15359, 0x20),
        (0x15331, params.depth_buffer),
        (0x153c9, params.depth_aux_buffer),
        (0x15341, params.stencil_buffer),
        (0x153d9, params.stencil_aux_buffer),
        (0x15421, params.depth_stride),
        (0x15431, params.depth_aux_stride),
        (0x15429, params.stencil_stride),
        (0x15439, params.stencil_aux_stride),
        (0x15221, 0),
        (0x15229, 0),
        (0x15319, params.depth_flags),
        (0x15349, 0x04040404),
    ]


def build_fragment_partial_resume_registers(params):
    """Build the 23-write partial pause/resume register program."""
    return [
        (0x15379, params.partial_store_pipeline_bind),
        (0x15381, params.partial_store_pipeline),
        (0x15369, params.partial_load_pipeline_bind),
        (0x15371, params.partial_load_pipeline),
        (0x10039, params.tile_config & 0xffff),
        (0x15359, 0x20),
        (0x15331, params.depth_buffer),
        (0x153c9, params.depth_aux_buffer),
        (0x15341, params.stencil_buffer),
        (0x153d9, params.stencil_aux_buffer),
        (0x15421, params.depth_stride),
        (0x15431, params.depth_aux_stride),
        (0x15429, params.stencil_stride),
        (0x15439, params.stencil_aux_stride),
        (0x15221, 0),
        (0x15229, 0),
        (0x15309, params.stencil_clear_value | 0x300),
        (0x15329, params.depth_buffer),
        (0x153c1, params.depth_aux_buffer),
        (0x15339, params.stencil_buffer),
        (0x153d1, params.stencil_aux_buffer),
        (0x15319, params.depth_flags),
        (0x15349, 0x04040404),
    ]


def build_fragment_partial_load_registers(params):
    """Build the 10-write register program used when resuming a partial render."""
    return [
        (0x15369, params.partial_load_pipeline_bind),
        (0x15371, params.partial_load_pipeline),
        (0x10039, params.tile_config & 0xffff),
        (0x15309, params.stencil_clear_value | 0x300),
        (0x15329, params.depth_buffer),
        (0x153c1, params.depth_aux_buffer),
        (0x15339, params.stencil_buffer),
        (0x153d1, params.stencil_aux_buffer),
        (0x15319, params.depth_flags),
        (0x15349, 0x04040404),
    ]

# The render objects a submission binds that this project used to copy out of a capture. They are
# small, and most of what is in them is either derivable from the render's own dimensions or a
# constant that does not move between submissions. Building them makes the dependency explicit: a
# value below is either computed or measured and named, and nothing is lifted from a capture at run
# time. Each builder returns a whole page, and the caller checks it against the capture before use.

RENDER_OBJECT_PAGE = 0x4000

# Seven records on a 0x80 stride, each carrying the same pair of words, then a trailing word. The
# two exceptions are in the sixth and seventh records; their roles are not separated.
BIND0_RECORDS = 7
BIND0_RECORD_STRIDE = 0x80
BIND0_RECORD_HEAD = 0x00000080
BIND0_RECORD_BODY_AT = 0x40
BIND0_RECORD_BODY = 0x10040000
BIND0_EXTRA = ((0x2c8, 0x00040000), (0x344, 0x00000008), (0x348, 0x00000004),
               (0x380, 0x0000fc40))

# Twenty-three words of packed binding state, none of them separated on hardware.
BIND_GROUP_WORDS = (
    (0x00, 0x00800000), (0x04, 0x00010100), (0x08, 0x0000c9c0), (0x10, 0x01000000),
    (0x14, 0x00066420), (0x1c, 0x0c0a0000), (0x20, 0x00010000), (0x2c, 0x00000006),
    (0x30, 0x010000b4), (0x34, 0x00040200), (0x38, 0x07200f00), (0x3c, 0x0e000000),
    (0x40, 0x07200f00), (0x44, 0x0e000000), (0x4c, 0x02000048), (0x50, 0x00000200),
    (0x54, 0x07e00000), (0x58, 0x07e00000), (0x5c, 0x0000000f), (0x60, 0x00410000),
    (0x68, 0x00000080), (0x6c, 0x00200000), (0x70, 0x00000480),
)

# Exact direct-draw deltas from the coherent source-controlled 128x37 pass.
# The remaining words are common with the retained indexed profile above.
DIRECT_BIND0_WORDS = (
    (0x2c8, 0x00000000),
    (0x300, 0x0000fcc0),
    (0x340, 0x00000000),
    (0x344, 0x00000000),
    (0x348, 0x00000000),
    (0x380, 0x00000000),
)
DIRECT_BIND_GROUP_WORDS = (
    (0x04, 0x00000000),
    (0x08, 0x00000000),
    (0x14, 0x00004e19),
    (0x20, 0x00000000),
    (0x2c, 0x00000004),
    (0x5c, 0x0001ffff),
)

# The viewport transform, at a fixed offset into the page the deflake addresses also live in.
VIEWPORT_AT = 0x900
VIEWPORT_SCALE_AT = 0x910
VIEWPORT_DEPTH_AT = 0x924
VIEWPORT_DEPTH = 1.0

AUX_FB_AT = 0x480
AUX_FB_WORDS = (0x60000000, 0x0000035b)

INDEX_BUFFER_AT = 0x00
INDEX_BUFFER_WORD = 0x00000100


def build_bind0():
    """The first bind table: a run of identical records and four measured exceptions."""
    page = bytearray(RENDER_OBJECT_PAGE)
    for index in range(BIND0_RECORDS):
        base = index * BIND0_RECORD_STRIDE
        struct.pack_into("<I", page, base, BIND0_RECORD_HEAD)
        struct.pack_into("<I", page, base + BIND0_RECORD_BODY_AT, BIND0_RECORD_BODY)
    for offset, value in BIND0_EXTRA:
        struct.pack_into("<I", page, offset, value)
    return bytes(page)


def build_bind_group():
    """The bind table the tiler stream names for groups one through seven."""
    page = bytearray(RENDER_OBJECT_PAGE)
    for offset, value in BIND_GROUP_WORDS:
        struct.pack_into("<I", page, offset, value)
    return bytes(page)


def build_direct_bind0():
    """Bind page 0 for the established compact direct triangle."""
    page = bytearray(build_bind0())
    for offset, value in DIRECT_BIND0_WORDS:
        struct.pack_into("<I", page, offset, value)
    return bytes(page)


def build_direct_bind_group():
    """Shared fixed-function bind page for the compact direct triangle."""
    page = bytearray(build_bind_group())
    for offset, value in DIRECT_BIND_GROUP_WORDS:
        struct.pack_into("<I", page, offset, value)
    return bytes(page)


def build_viewport(width, height):
    """The viewport transform, which is the render's own dimensions in floating point.

    The four words are the half-width twice and the half-height positive then negative, which is a
    scale and translate pair for each axis with the vertical one inverted.
    """
    if width <= 0 or height <= 0:
        raise ValueError("viewport dimensions must be positive")
    tiles_x = (width + TILE_WIDTH - 1) // TILE_WIDTH
    tiles_y = (height + TILE_HEIGHT - 1) // TILE_HEIGHT
    page = bytearray(RENDER_OBJECT_PAGE)
    struct.pack_into(
        "<III", page, VIEWPORT_AT,
        0x00000c00, 0x80000000 | (tiles_x - 1), tiles_y - 1)
    struct.pack_into("<ffff", page, VIEWPORT_SCALE_AT,
                     width / 2.0, width / 2.0, height / 2.0, -(height / 2.0))
    struct.pack_into("<f", page, VIEWPORT_DEPTH_AT, VIEWPORT_DEPTH)
    return bytes(page)


def build_index_buffer():
    """The index buffer's one non-zero word.

    Not the index count: the tiler stream's draw record says six, and this word is `0x100`. What it
    is has not been separated, so it is carried as a measured constant.
    """
    page = bytearray(RENDER_OBJECT_PAGE)
    struct.pack_into("<I", page, INDEX_BUFFER_AT, INDEX_BUFFER_WORD)
    return bytes(page)


def build_aux_fb():
    """The auxiliary framebuffer's header pair. Neither word is separated on hardware."""
    page = bytearray(RENDER_OBJECT_PAGE)
    struct.pack_into("<II", page, AUX_FB_AT, *AUX_FB_WORDS)
    return bytes(page)
