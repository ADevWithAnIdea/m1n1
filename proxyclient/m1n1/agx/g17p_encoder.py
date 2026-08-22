# SPDX-License-Identifier: MIT
"""The T8140/G17P tiler encoder: the command stream the accelerator executes.

Hardware established that this object's contents decide whether anything is drawn. Filling it with a
constant byte retires the submission and renders nothing, while the same page relocated with its
contents intact renders; and within it, the half-word at ``+0x6e`` of the draw record gates the draw
while the byte beside it does not.

The stream is a header, eight ``(address, control)`` bind pairs naming render-context objects, and
one draw record. Bound addresses are render-context offsets, not full device addresses, so callers
pass full addresses and this module subtracts the context base, refusing anything outside it.
"""

import struct
from dataclasses import dataclass, field


HEADER_SIZE = 0x20
BIND_PAIR_COUNT = 8
BIND_PAIRS_AT = 0x20
DRAW_RECORD_AT = 0x60
ENCODER_SIZE = 0x8c

# Established on hardware: zeroing this half-word suppresses every render write, with the
# submission still retiring. A 16-bit indexed triangle list uses this value.
DRAW_OPCODE_DIRECT = 0x61c4
DRAW_OPCODE_INDEXED_16 = 0x61f2
DRAW_OPCODE_INDEXED_16_INDIRECT = 0x6432

# The public MTLDrawIndexedPrimitivesIndirectArguments layout.  The VDM record
# points at this complete device address with high32 followed by low32.
INDEXED_INDIRECT_ARGUMENTS_SIZE = 0x14

# Not a gate; zeroing it still renders. A first submission selects this value.
PRIMITIVE_TRIANGLE = 0x06


@dataclass
class G17PBindPair:
    """One bound object: a render-context address and its control word."""

    address: int
    control: int


@dataclass
class G17PEncoderParameters:
    """Everything a first-submission tiler stream needs.

    Addresses are full device addresses in the render context. Values whose meaning hardware has not
    separated are carried as named constants rather than described, so that a later run can change
    one without the name implying more than was measured.
    """

    context_base: int

    # Objects the stream binds, in the order the captured stream binds them.
    binds: list

    # The draw record. Direct and indexed commands have different layouts.
    # ``draw_state`` is the always-present low-region graphics object at the
    # first word of a direct command. The legacy indexed fields retain their
    # names because existing experiments consume that independently measured
    # packet shape.
    index_buffer: int = 0
    index_count: int = 0
    draw_state: int = 0
    vertex_count: int = 0
    vertex_start: int = 0
    instance_count: int = 1
    base_vertex: int = 0
    primitive: int = PRIMITIVE_TRIANGLE
    opcode: int = DRAW_OPCODE_INDEXED_16
    restart_comparand: int = 0xffff
    draw_config: int = 0x40000001
    index_config: int = 0x01bc0200
    index_extent: int = 0x0000ff7f

    # Header words whose roles are not yet separated on hardware.
    header_flags: int = 0x4000002e
    header_mode: int = 0x01000000
    header_state: int = 0x00066000
    header_class: int = 0x00000606
    header_control: int = 0x00000500

    # Trailing words, likewise unseparated.
    tail_count: int = 0x00000001
    tail_flags: int = 0xc0000000

    # A nonzero address replaces the inline index/instance counts.  The
    # remaining indexed-draw words retain their direct values.
    indirect_args: int = 0

    def offset(self, address):
        """A render-context offset, which is what the stream stores."""
        if address == 0:
            return 0
        relative = address - self.context_base
        if relative < 0:
            raise ValueError("address %#x precedes render context base %#x"
                             % (address, self.context_base))
        return relative


def build_encoder(params):
    """Serialize the tiler command stream."""
    if len(params.binds) != BIND_PAIR_COUNT:
        raise ValueError("the stream holds %d bind pairs, not %d"
                         % (BIND_PAIR_COUNT, len(params.binds)))

    stream = bytearray(ENCODER_SIZE)
    struct.pack_into("<I", stream, 0x00, params.header_flags)
    struct.pack_into("<I", stream, 0x04, 0)
    struct.pack_into("<I", stream, 0x08, params.header_mode)
    struct.pack_into("<I", stream, 0x0c, params.header_state)
    struct.pack_into("<I", stream, 0x10, params.header_class)
    struct.pack_into("<I", stream, 0x14, 0)
    struct.pack_into("<I", stream, 0x18, 0)
    struct.pack_into("<I", stream, 0x1c, params.header_control)

    for index, bind in enumerate(params.binds):
        at = BIND_PAIRS_AT + index * 8
        struct.pack_into("<II", stream, at, params.offset(bind.address), bind.control)

    at = DRAW_RECORD_AT
    if params.opcode == DRAW_OPCODE_DIRECT:
        if params.indirect_args:
            raise ValueError("direct-indirect draw layout has not been established")
        if not params.draw_state:
            raise ValueError("a direct draw needs its graphics-state object")
        if params.vertex_count <= 0:
            raise ValueError("a direct draw needs a positive vertex count")
        struct.pack_into("<I", stream, at + 0x00,
                         params.offset(params.draw_state))
        struct.pack_into("<I", stream, at + 0x04,
                         ((params.opcode & 0xffff) << 16)
                         | ((params.primitive & 0xff) << 8))
        struct.pack_into("<I", stream, at + 0x08, params.vertex_count)
        struct.pack_into("<I", stream, at + 0x0c, params.instance_count)
        struct.pack_into("<I", stream, at + 0x10, params.vertex_start)
        struct.pack_into("<I", stream, at + 0x14, params.tail_flags)
        return bytes(stream)

    struct.pack_into("<I", stream, at + 0x00, params.offset(params.index_buffer))
    struct.pack_into("<I", stream, at + 0x04, params.draw_config)
    struct.pack_into("<I", stream, at + 0x08, params.restart_comparand)
    # The gating half-word and the primitive byte share this word; hardware separated them.
    struct.pack_into("<B", stream, at + 0x0d, params.primitive & 0xff)
    opcode = params.opcode
    if params.indirect_args:
        if opcode == DRAW_OPCODE_INDEXED_16:
            opcode = DRAW_OPCODE_INDEXED_16_INDIRECT
        elif opcode != DRAW_OPCODE_INDEXED_16_INDIRECT:
            raise ValueError("indexed indirect draw needs opcode %#x, got %#x"
                             % (DRAW_OPCODE_INDEXED_16_INDIRECT, opcode))
    struct.pack_into("<H", stream, at + 0x0e, opcode & 0xffff)
    struct.pack_into("<I", stream, at + 0x10, params.index_config)
    if params.indirect_args:
        struct.pack_into("<II", stream, at + 0x14,
                         (params.indirect_args >> 32) & 0xffffffff,
                         params.indirect_args & 0xffffffff)
    else:
        struct.pack_into("<I", stream, at + 0x14, params.index_count)
        struct.pack_into("<I", stream, at + 0x18, params.instance_count)
    if params.indirect_args:
        # baseVertex moves into the public argument structure, shortening the
        # indexed record by one word. The fixed indexed tail shifts left.
        struct.pack_into("<I", stream, at + 0x1c, params.index_extent)
        struct.pack_into("<I", stream, at + 0x20, params.tail_count)
        struct.pack_into("<I", stream, at + 0x24, params.tail_flags)
    else:
        struct.pack_into("<I", stream, at + 0x1c, params.base_vertex)
        struct.pack_into("<I", stream, at + 0x20, params.index_extent)
        struct.pack_into("<I", stream, at + 0x24, params.tail_count)
        struct.pack_into("<I", stream, at + 0x28, params.tail_flags)
    return bytes(stream)


def build_indexed_indirect_arguments(index_count, instance_count=1,
                                     index_start=0, base_vertex=0,
                                     base_instance=0):
    """Serialize the public indexed-indirect argument structure."""
    unsigned = (index_count, instance_count, index_start, base_instance)
    if any(value < 0 or value > 0xffffffff for value in unsigned):
        raise ValueError("indexed indirect unsigned arguments must fit in u32")
    if base_vertex < -0x80000000 or base_vertex > 0x7fffffff:
        raise ValueError("indexed indirect base vertex must fit in i32")
    return struct.pack("<IIIiI", index_count, instance_count, index_start,
                       base_vertex, base_instance)


def parse_encoder(stream, context_base):
    """Recover the parameters of a captured stream, so a build can be checked against it."""
    if len(stream) < ENCODER_SIZE:
        raise ValueError("stream is %d bytes, shorter than %d" % (len(stream), ENCODER_SIZE))

    binds = []
    for index in range(BIND_PAIR_COUNT):
        address, control = struct.unpack_from("<II", stream, BIND_PAIRS_AT + index * 8)
        binds.append(G17PBindPair(
            address=context_base + address if address else 0, control=control))

    at = DRAW_RECORD_AT
    direct_word = struct.unpack_from("<I", stream, at + 0x04)[0]
    direct_opcode = direct_word >> 16
    if direct_opcode == DRAW_OPCODE_DIRECT:
        draw_state = struct.unpack_from("<I", stream, at + 0x00)[0]
        return G17PEncoderParameters(
            context_base=context_base,
            binds=binds,
            draw_state=context_base + draw_state if draw_state else 0,
            vertex_count=struct.unpack_from("<I", stream, at + 0x08)[0],
            instance_count=struct.unpack_from("<I", stream, at + 0x0c)[0],
            vertex_start=struct.unpack_from("<I", stream, at + 0x10)[0],
            primitive=(direct_word >> 8) & 0xff,
            opcode=direct_opcode,
            header_flags=struct.unpack_from("<I", stream, 0x00)[0],
            header_mode=struct.unpack_from("<I", stream, 0x08)[0],
            header_state=struct.unpack_from("<I", stream, 0x0c)[0],
            header_class=struct.unpack_from("<I", stream, 0x10)[0],
            header_control=struct.unpack_from("<I", stream, 0x1c)[0],
            tail_flags=struct.unpack_from("<I", stream, at + 0x14)[0],
        )

    index_buffer = struct.unpack_from("<I", stream, at + 0x00)[0]
    opcode = struct.unpack_from("<H", stream, at + 0x0e)[0]
    indirect_args = 0
    if opcode == DRAW_OPCODE_INDEXED_16_INDIRECT:
        high, low = struct.unpack_from("<II", stream, at + 0x14)
        indirect_args = (high << 32) | low
        base_vertex = 0
        index_extent = struct.unpack_from("<I", stream, at + 0x1c)[0]
        tail_count = struct.unpack_from("<I", stream, at + 0x20)[0]
        tail_flags = struct.unpack_from("<I", stream, at + 0x24)[0]
    else:
        base_vertex = struct.unpack_from("<I", stream, at + 0x1c)[0]
        index_extent = struct.unpack_from("<I", stream, at + 0x20)[0]
        tail_count = struct.unpack_from("<I", stream, at + 0x24)[0]
        tail_flags = struct.unpack_from("<I", stream, at + 0x28)[0]
    return G17PEncoderParameters(
        context_base=context_base,
        binds=binds,
        index_buffer=context_base + index_buffer if index_buffer else 0,
        draw_config=struct.unpack_from("<I", stream, at + 0x04)[0],
        restart_comparand=struct.unpack_from("<I", stream, at + 0x08)[0],
        primitive=stream[at + 0x0d],
        opcode=opcode,
        index_config=struct.unpack_from("<I", stream, at + 0x10)[0],
        index_count=struct.unpack_from("<I", stream, at + 0x14)[0],
        instance_count=struct.unpack_from("<I", stream, at + 0x18)[0],
        base_vertex=base_vertex,
        index_extent=index_extent,
        header_flags=struct.unpack_from("<I", stream, 0x00)[0],
        header_mode=struct.unpack_from("<I", stream, 0x08)[0],
        header_state=struct.unpack_from("<I", stream, 0x0c)[0],
        header_class=struct.unpack_from("<I", stream, 0x10)[0],
        header_control=struct.unpack_from("<I", stream, 0x1c)[0],
        tail_count=tail_count,
        tail_flags=tail_flags,
        indirect_args=indirect_args,
    )
