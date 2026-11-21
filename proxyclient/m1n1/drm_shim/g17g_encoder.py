# SPDX-License-Identifier: GPL-2.0-only
"""Source encoder for the first observed T8142/G17G VDM direct draw.

The packet shape and constants come from the clean earliest native partial
render.  Keep the encoder deliberately narrow until hardware experiments
establish additional command variants.
"""

import dataclasses
import hashlib
import struct


PAGE_SIZE = 0x4000
VDM_STREAM_DVA = 0x1000018000
VDM_STREAM_SIZE = 0xA4
DIRECT_DRAW_STATE_OFFSET = 0x88
DIRECT_DRAW_RECORD_OFFSET = 0x8C
DIRECT_DRAW_RECORD_SIZE = 0x14
USC_EXEC_BASE = 0x10000000000
NATIVE_PARTIAL_VERTEX_PIPELINE = 0x100001E8700
NATIVE_PARTIAL_VERTEX_COUNT = 0x008D42C0
NATIVE_PARTIAL_PAGE_SHA256 = (
    "f672ee00d706ae307fc1b517fd91f4371a24a5a8edcc87a3960dbcfd809d564c"
)
PARTIAL_STATE_PAGE_SHA256 = {
    0x1000000000: (
        "292f782ed0e17db2bc37170184b836d724f60b32c34b603c83fbacf919c8c683"
    ),
    0x1000048000: (
        "b29991fd82acb21627638fd253bf69c28fb2bafb4510c3f7c54b239186914604"
    ),
    0x1000058000: (
        "fccdba8c4a6c29e877a3d80a9aa5def00ec6894b5b37db74f0b53d87bb4430b8"
    ),
    0x1000068000: (
        "2df0ba8069d6b95d70e539ef253877d00067da0b09ad7789ddbeac451deddf9c"
    ),
}


@dataclasses.dataclass(frozen=True)
class G17GDirectDraw:
    """Caller-selected fields in the observed G17G direct-draw command."""

    vertex_count: int = NATIVE_PARTIAL_VERTEX_COUNT
    instance_count: int = 1
    vertex_start: int = 0
    vertex_pipeline: int = NATIVE_PARTIAL_VERTEX_PIPELINE
    viewport_width: int = 128
    viewport_height: int = 128

    def validate(self):
        for name in ("vertex_count", "instance_count", "vertex_start"):
            value = int(getattr(self, name))
            if not 0 <= value < (1 << 32):
                raise ValueError("G17G direct %s must fit in u32" % name)
        if not self.vertex_count:
            raise ValueError("G17G direct vertex count must be nonzero")
        if not self.instance_count:
            raise ValueError("G17G direct instance count must be nonzero")
        pipeline = int(self.vertex_pipeline)
        if pipeline < USC_EXEC_BASE or pipeline - USC_EXEC_BASE >= (1 << 32):
            raise ValueError("G17G vertex pipeline is outside the USC window")
        if pipeline & 0x3F:
            raise ValueError("G17G vertex pipeline must be 64-byte aligned")
        for name in ("viewport_width", "viewport_height"):
            value = int(getattr(self, name))
            if not 1 <= value <= 0x10000:
                raise ValueError(
                    "G17G direct %s must be within 1..65536" % name
                )


# Three short records precede the VDM state packet in the M5 first-partial
# stream.  They are part of the command stream, not stale page contents.
_PREFIX_WORDS = (
    0x00000600, 0x00058000,
    0x00002100, 0x00058018,
    0x00002100, 0x0005809C,
)

# The observed packet binds ten state records by address offset and control.
# The offsets are relative to the caller's 0x1000000000 resource base.
_STATE_BINDINGS = (
    (0x00000040, 0x00000700),
    (0x00058120, 0x00000600),
    (0x0005813C, 0x00000500),
    (0x00058154, 0x00000700),
    (0x00058168, 0x00000500),
    (0x00058184, 0x00000A00),
    (0x000689C0, 0x00000300),
    (0x00058198, 0x00000200),
    (0x000581A4, 0x00000500),
    (0x00048000, 0x00000300),
)


def direct_vdm_stream_size(draw_count=1):
    """Return the meaningful byte count for a direct-record sequence."""
    draw_count = int(draw_count)
    if not 1 <= draw_count <= (
        (PAGE_SIZE - DIRECT_DRAW_RECORD_OFFSET - 4)
        // DIRECT_DRAW_RECORD_SIZE
    ):
        raise ValueError("G17G direct draw count does not fit in one page")
    return DIRECT_DRAW_RECORD_OFFSET + draw_count * DIRECT_DRAW_RECORD_SIZE + 4


def build_direct_vdm_page(draw=None, draws=None):
    """Build one page containing one or more observed direct-draw records."""
    if draws is None:
        draws = (G17GDirectDraw() if draw is None else draw,)
    else:
        if draw is not None:
            raise ValueError("G17G direct draw and draw sequence conflict")
        draws = tuple(draws)
    direct_vdm_stream_size(len(draws))
    for item in draws:
        if not isinstance(item, G17GDirectDraw):
            raise TypeError("G17G direct draw parameters have the wrong type")
        item.validate()
    state = (
        draws[0].vertex_pipeline,
        draws[0].viewport_width,
        draws[0].viewport_height,
    )
    if any(
        (item.vertex_pipeline, item.viewport_width, item.viewport_height)
        != state for item in draws[1:]
    ):
        raise ValueError(
            "G17G direct records in one state packet must share bound state"
        )

    page = bytearray(PAGE_SIZE)
    struct.pack_into("<6I", page, 0, *_PREFIX_WORDS)
    # G17G packet header.  The two explicit zero words are reserved fields in
    # the native packet and remain visible here to keep the layout auditable.
    struct.pack_into(
        "<8I", page, 0x18,
        0x4000002E, 0,
        0x01000040, 0x00007600, 0x00002424, 0, 0, 0x00000500,
    )
    offset = 0x38
    for address, control in _STATE_BINDINGS:
        struct.pack_into("<II", page, offset, address, control)
        offset += 8
    if offset != 0x88:
        raise AssertionError("G17G direct binding layout changed")
    # The final state address belongs to the opening state packet.  The word
    # after it is the actual block-type-3 Index List header.  Additional draws
    # therefore repeat only the five-word Index List record, not this state
    # address.
    struct.pack_into("<I", page, offset, 0x000581AC)
    offset += 4
    for item in draws:
        struct.pack_into(
            "<5I", page, offset,
            0x69C40600,  # direct draw, triangle primitive (6)
            int(item.vertex_count),
            int(item.instance_count),
            int(item.vertex_start),
            0,
        )
        offset += DIRECT_DRAW_RECORD_SIZE
    struct.pack_into("<I", page, offset, 0xC0000000)
    return bytes(page)


def validate_native_direct_vdm_page():
    """Assert that the source encoder still matches the earliest witness."""
    body = build_direct_vdm_page()
    if hashlib.sha256(body).hexdigest() != NATIVE_PARTIAL_PAGE_SHA256:
        raise ValueError("source-built G17G native direct VDM page changed")
    return body


def _build_sparse_u32_page(fields):
    page = bytearray(PAGE_SIZE)
    for offset, value in fields:
        if offset & 3 or not 0 <= offset <= PAGE_SIZE - 4:
            raise ValueError("G17G sparse state offset is invalid")
        if struct.unpack_from("<I", page, offset)[0]:
            raise ValueError("G17G sparse state offset is duplicated")
        struct.pack_into("<I", page, offset, int(value))
    return bytes(page)


def build_partial_bound_state_pages(
        vertex_pipeline=NATIVE_PARTIAL_VERTEX_PIPELINE,
        render_x=0, render_y=0, render_width=128, render_height=128,
        viewport_width=128, viewport_height=128):
    """Build the four sparse pages named by the observed VDM bind table.

    ``render_x``, ``render_y``, ``render_width``, and ``render_height`` are the
    active render area, not the attachment dimensions.  The bound words carry
    inclusive minimum and maximum 32x32 tile indices.
    """
    vertex_pipeline = int(vertex_pipeline)
    if (
        vertex_pipeline < USC_EXEC_BASE
        or vertex_pipeline - USC_EXEC_BASE >= (1 << 32)
        or vertex_pipeline & 0x3F
    ):
        raise ValueError("G17G vertex pipeline has an invalid USC address")
    vertex_pipeline_word = (vertex_pipeline - USC_EXEC_BASE) >> 6
    render_x = int(render_x)
    render_y = int(render_y)
    render_width = int(render_width)
    render_height = int(render_height)
    viewport_width = int(viewport_width)
    viewport_height = int(viewport_height)
    if not 0 <= render_x < 0x10000:
        raise ValueError("G17G render X origin must be within 0..65535")
    if not 0 <= render_y < 0x10000:
        raise ValueError("G17G render Y origin must be within 0..65535")
    if not 1 <= render_width <= 0x10000 - render_x:
        raise ValueError("G17G render width must be within 1..65536")
    if not 1 <= render_height <= 0x10000 - render_y:
        raise ValueError("G17G render height must be within 1..65536")
    if not 1 <= viewport_width <= 0x10000:
        raise ValueError("G17G viewport width must be within 1..65536")
    if not 1 <= viewport_height <= 0x10000:
        raise ValueError("G17G viewport height must be within 1..65536")
    min_tile_x = render_x // 32
    min_tile_y = render_y // 32
    max_tile_x = (render_x + render_width - 1) // 32
    max_tile_y = (render_y + render_height - 1) // 32

    def float_bits(value):
        return struct.unpack("<I", struct.pack("<f", value))[0]

    root_fields = []
    for record in range(6):
        offset = record * 0x80
        root_fields.append((offset, 0x80))
        root_fields.append((offset + 0x40, 0x10100000))
    root_fields.extend(((0x44, 0x20), (0x300, 0xFCC0)))

    fields_58000 = (
        (0x000, 0x00000001), (0x004, 0x000007AA),
        (0x008, 0xE2E00000), (0x00C, 0xF0C00000),
        (0x010, 0x00023020), (0x014, 0x0001FFFF),
        (0x018, 0x13D03762), (0x09C, 0x13D03760),
        (0x120, 0x01000000), (0x124, 0x00090100),
        (0x128, 0x00000600), (0x130, 0x01000000),
        (0x134, vertex_pipeline_word), (0x138, 0x00000001),
        (0x13C, 0x00000001), (0x140, 0x000007AA),
        (0x144, 0xE2E00000), (0x148, 0xF0C00000),
        (0x14C, 0x00023020), (0x150, 0x0001FFFF),
        (0x154, 0x0C280000), (0x158, 0x00010000),
        (0x164, 0x00000024), (0x168, 0x020000E0),
        (0x16C, 0x00040200), (0x170, 0x07200F00),
        (0x174, 0x07200F00), (0x178, 0x0E000000),
        (0x17C, 0x0E000000), (0x184, 0x02000062),
        (0x188, 0x20000200), (0x18C, 0x07E00000),
        (0x190, 0x07E00000), (0x194, 0x0001FFFF),
        (0x198, 0x00840002), (0x1A0, 0x00000080),
        (0x1A4, 0x00800000), (0x1A8, 0x00000480),
        (0x1AC, 0x00000400),
    )
    pages = {
        0x1000000000: _build_sparse_u32_page(root_fields),
        0x1000048000: _build_sparse_u32_page((
            (0x0, 0x00000300),
            (0x4, 0x01000000),
            (0x8, 0x00350000),
        )),
        0x1000058000: _build_sparse_u32_page(fields_58000),
        0x1000068000: _build_sparse_u32_page((
            (0x9C0, 0x00003000),
            (0x9C4, 0x80000000 | (min_tile_x << 16) | max_tile_x),
            (0x9C8, (min_tile_y << 16) | max_tile_y),
            (0x9D0, float_bits(viewport_width / 2.0)),
            (0x9D4, float_bits(viewport_width / 2.0)),
            (0x9D8, float_bits(viewport_height / 2.0)),
            (0x9DC, float_bits(-(viewport_height / 2.0))),
            (0x9E4, float_bits(1.0)),
        )),
    }
    for address, page in pages.items():
        if (
            vertex_pipeline == NATIVE_PARTIAL_VERTEX_PIPELINE
            and render_x == 0
            and render_y == 0
            and render_width == 128
            and render_height == 128
            and viewport_width == 128
            and viewport_height == 128
            and hashlib.sha256(page).hexdigest()
            != PARTIAL_STATE_PAGE_SHA256[address]
        ):
            raise ValueError(
                "source-built G17G partial state page changed at %#x" % address
            )
    return pages
