# SPDX-License-Identifier: GPL-2.0-only
"""Source-built T8142/G17G render descriptors and caller clear fixtures.

Two controlled first-kick captures establish the products in this module.  A
16 KiB retained allocation moved the caller target and every following Metal
allocation by 0x8000, while the clear color also changed.  The register number
sequences remained identical.  One context-1 page moved by the same 0x8000 and
is completely described here from its own address, the target DVA, the clear
RGBA bytes and measured constants.

Numeric register IDs remain numeric clean-room ABI facts.  The limited names
on caller inputs describe only the controlled relationship proven by the two
captures; they do not import semantics from another GPU generation.
"""

import hashlib
import struct
from dataclasses import dataclass, replace
from .g17g_render_buffers import RenderBuffers


PAGE_SIZE = 0x4000
CLEAR_WIDTH = 64
CLEAR_HEIGHT = 64
TILE_WIDTH = 32
TILE_HEIGHT = 32
MACRO_TILES_X = 4
MACRO_TILES_Y = 4
REGION_ENTRY_SIZE = 5
MERGE_SCALE = 1.732051
REGISTER_ENTRY_SIZE = 0xC
TILING_REGISTER_COUNT = 73
FRAGMENT_REGISTER_COUNT = 89
OPTIONAL_ITEM_SIZE = 0xC0
EVENT_ITEM_SIZE = 0x40
TILING_DESCRIPTOR_SIZE = 0x9C0
FRAGMENT_DESCRIPTOR_SIZE = 0x2240

DESCRIPTOR_OBJECTS = (
    0xFFFFFC20C08A8100,
    0xFFFFFC20C08E8000,
    0xFFFFFC20C08B8080,
    0xFFFFFC20C08BA800,
)
TILING_LOW_ALIAS = 0x7200000000
FRAGMENT_LOW_ALIAS = 0x7200098000
DISPATCH_A = 0xFFFFFC20001C8000
DISPATCH_B = 0xFFFFFC20C07D8000
STATUS_A = 0xFFFFFC2000024E48
STATUS_B = 0xFFFFFC2000024E50
TIMESTAMP_APERTURE_BASE = 0xFFFFFC2181400000
SHARED_CONTROL = 0xFFFFFC20C08B0000
TILING_STATUS = 0xFFFFFC2001610000
FRAGMENT_STATUS = 0xFFFFFC2001630000
TILING_REGISTER_STATUS = 0x1000078000
FRAGMENT_REGISTER_STATUS = 0x1000258000

# Firmware consumes this word in register 0x15021 and in the fragment
# descriptor tail at +0x1f40.  Bit zero is present in both members of the
# matched explicit-scissor/no-scissor native A/B, so it is deliberately not
# assigned scissor semantics.  The source partial baseline also executes with
# it clear.
FRAGMENT_AUX_FLAGS_BASE = 0x10C000
FRAGMENT_AUX_FLAG_BIT0 = 1 << 0
FRAGMENT_AUX_FLAG_DBIAS_IS_INT = 1 << 18

# Stable numeric addresses carried by both first-clear selector-15 records.
# They are firmware/context objects outside the six-item group; the graph
# builder must provide their backing before publication.
TILING_CONTEXT_SCRATCH = 0x7200438000
FRAGMENT_CONTEXT_SCRATCH = 0x7200460000
TILING_FIRMWARE_SCRATCH = 0xFFFFFC20001D8000
FRAGMENT_FIRMWARE_SCRATCH = 0xFFFFFC2000200000
CHANNEL_CONTROL = 0xFFFFFC20C07C0000
TILING_SHARED_OBJECT = 0xFFFFFC20C08E8000

CLEAR_RENDER_ITEM_ORDER = (
    "tiling_optional", "tiling_descriptor", "tiling_event",
    "fragment_optional", "fragment_descriptor", "fragment_event",
)

RENDER_OPERAND_TABLE_DVA = 0x7200408000
RENDER_ADDRESS_LIST_PAGE_DVAS = tuple(
    0x7200000000 + index * PAGE_SIZE for index in range(4)
)
# The source topology reserves 256 pages; only the first four have startup
# images. Firmware appends recycled addresses throughout the larger storage.
RENDER_ADDRESS_LIST_STORAGE_SIZE = 0x400000
RENDER_ADDRESS_LIST_STORAGE_DVAS = tuple(range(
    RENDER_ADDRESS_LIST_PAGE_DVAS[0],
    RENDER_ADDRESS_LIST_PAGE_DVAS[0] + RENDER_ADDRESS_LIST_STORAGE_SIZE, PAGE_SIZE))
RENDER_OPERAND_BASE = 0x7200420000
RENDER_OPERAND_COUNT = 15
PARTIAL_RENDER_OPERAND_COUNT = 18
RENDER_OPERAND_STRIDE = 0x208000
RENDER_OPERAND_SIZE = 0x200000
RENDER_OPERAND_FLAG = 0x2000000000000000
RENDER_ADDRESS_ENTRY_STRIDE = 8
RENDER_ADDRESS_GRANULE = 0x1000
RENDER_ADDRESS_ENTRIES_PER_OPERAND = (
    RENDER_OPERAND_SIZE // RENDER_ADDRESS_GRANULE
)
RENDER_ADDRESS_LIST_PAGE_SHA256 = (
    "2b5ffe0b0907c4c3bea3a5dc89c3863f2cee52fd55f849bd0ef0e643c9bb46df",
    "51b019ce6025aba5bae4a29c31f722a570f2c7ef1284d420c7118ea56d006778",
    "ce22cf7bfe61f5ffb24066323cfcdfa12c812c1a124249db19ef5725bba3be43",
    "2f3d5ec9cf0c0e531d3c6067f122925482984a87cbb887614d97daf9a3645fc8",
)
RENDER_SERVICE_INPUT_OPERAND_COUNT = 13
RENDER_SERVICE_INPUT_ADDRESS_LIST_PAGE_SHA256 = (
    *RENDER_ADDRESS_LIST_PAGE_SHA256[:3],
    "17d4fd0ccc02e9a79c92988186926f9d937784fa15afeb10747a56ea7866581f",
)
PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT = 18
PARTIAL_RENDER_ADDRESS_LIST_PAGE_SHA256 = (
    "2b5ffe0b0907c4c3bea3a5dc89c3863f2cee52fd55f849bd0ef0e643c9bb46df",
    "51b019ce6025aba5bae4a29c31f722a570f2c7ef1284d420c7118ea56d006778",
    "ce22cf7bfe61f5ffb24066323cfcdfa12c812c1a124249db19ef5725bba3be43",
    "b0bc074ecf08389779384a21f3b47d8cfbfb19f90e16f5d81f92990be48685cf",
    "cc3355a776570919d36c395831e791345a34394663e90abbc7a656688e1a314f",
)
PARTIAL_RENDER_OPERAND_TABLE_SHA256 = (
    "c68eee49ceeeb88b19f45cc509323ecd5b13bbb5f63b43e0bd92eb4ea23cbe25"
)
RENDER_BASE10_SUPPORT_DVA = 0x1000000000
RENDER_SCISSOR_DVA = 0x10000140000
VDM_RESOURCE_BASE = 0x1000000000
VDM_CTRL_STREAM_BASE = 0x1000018000

# Exact selector-zero leaf topology from the canonical first-clear boundary.
# The boolean is the native GPU read-only/executable permission class; false
# is the native read/write/UXN class.  Page contents are independently built
# or freshly zeroed and are never sourced from this topology table.
RENDER_CONTEXT1_RUNS = (
    (0x1000000000, 4, True),
    (0x1000018000, 2, True),
    (0x1000028000, 2, True),
    (0x1000038000, 2, True),
    (0x1000048000, 2, True),
    (0x1000058000, 2, False),
    (0x1000068000, 3, False),
    (0x1000078000, 1, False),
    (0x1000080000, 1, False),
    (0x1000088000, 32, False),
    (0x1000110000, 32, False),
    (0x1000198000, 32, False),
    (0x1000220000, 1, False),
    (0x1000228000, 2, False),
    (0x1000238000, 6, False),
    (0x1000258000, 1, False),
    (0x1000260000, 9, False),
    (0x1000288000, 1, False),
    (0x7200000000, 256, False),
    (0x7200408000, 4, False),
    (0x7200420000, 128, False),
    (0x7200628000, 128, False),
    (0x7200830000, 128, False),
    (0x7200A38000, 128, False),
    (0x7200C40000, 128, False),
    (0x7200E48000, 128, False),
    (0x7201050000, 128, False),
    (0x7201258000, 128, False),
    (0x7201460000, 128, False),
    (0x7201668000, 128, False),
    (0x7201870000, 128, False),
    (0x7201A78000, 128, False),
    (0x7201C80000, 128, False),
    (0x7201E88000, 128, False),
    (0x7202090000, 128, False),
    (0x10000000000, 4, True),
    (0x10000018000, 1, False),
    (0x10000048000, 4, True),
    (0x10000060000, 8, False),
    (0x10000088000, 28, True),
    (0x10000100000, 2, True),
    (0x10000110000, 2, True),
    (0x10000120000, 2, False),
    (0x10000130000, 2, False),
    (0x10000140000, 64, False),
    (0x10000248000, 2, False),
    (0x10000258000, 2, True),
    (0x10000268000, 2, True),
    (0x10000278000, 2, True),
    (0x10000288000, 2, True),
    (0x10000298000, 48, True),
    (0x2FFFFFF8000, 1, False),
)
RENDER_CONTEXT1_PAGE_COUNT = 2491
RENDER_CONTEXT1_DVA_SHA256 = (
    "3f737ac5684eee478410873351664d8d870ba0abc9d96bdc7a8ec006e7c390ae"
)
RENDER_CONTEXT1_READ_ONLY_PAGE_COUNT = 108
RENDER_CONTEXT1_READ_ONLY_DVA_SHA256 = (
    "e49ad57e004e5f1984706d0bc650684c04f185f62a9dd5a69b7200729fcfb412"
)

# Exact selector-zero leaf topology of the earliest native partial render.
# The lower compiler/operand region shares the first-clear layout through
# 0x7202090000, then adds three operand runs.  Its high caller allocations are
# a distinct layout, not a superset of the clear topology.  Contents are built
# or freshly zeroed independently; this table preserves only numeric DVAs and
# the two observed PTE permission classes.
PARTIAL_RENDER_CONTEXT1_RUNS = (
    (0x1000000000, 4, True),
    (0x1000018000, 2, True),
    (0x1000028000, 2, True),
    (0x1000038000, 2, True),
    (0x1000048000, 2, True),
    (0x1000058000, 2, False),
    (0x1000068000, 3, False),
    (0x1000078000, 1, False),
    (0x1000080000, 1, False),
    (0x1000088000, 32, False),
    (0x1000110000, 32, False),
    (0x1000198000, 32, False),
    (0x1000220000, 1, False),
    (0x1000228000, 2, False),
    (0x1000238000, 6, False),
    (0x1000258000, 1, False),
    (0x1000260000, 9, False),
    (0x1000288000, 1, False),
    (0x7200000000, 256, False),
    (0x7200408000, 4, False),
    (0x7200420000, 128, False),
    (0x7200628000, 128, False),
    (0x7200830000, 128, False),
    (0x7200A38000, 128, False),
    (0x7200C40000, 128, False),
    (0x7200E48000, 128, False),
    (0x7201050000, 128, False),
    (0x7201258000, 128, False),
    (0x7201460000, 128, False),
    (0x7201668000, 128, False),
    (0x7201870000, 128, False),
    (0x7201A78000, 128, False),
    (0x7201C80000, 128, False),
    (0x7201E88000, 128, False),
    (0x7202090000, 128, False),
    (0x7202298000, 128, False),
    (0x72024A0000, 128, False),
    (0x72026A8000, 128, False),
    (0x10000000000, 4, True),
    (0x10000018000, 8, False),
    (0x10000040000, 4, True),
    (0x10000058000, 4, False),
    (0x10000070000, 4, False),
    (0x10000088000, 4, False),
    (0x100000A0000, 4, False),
    (0x100000B8000, 4, False),
    (0x100000D0000, 4, False),
    (0x100000E8000, 4, False),
    (0x10000100000, 4, False),
    (0x10000118000, 8, False),
    (0x10000140000, 28, True),
    (0x100001B8000, 2, True),
    (0x100001C8000, 2, True),
    (0x100001D8000, 2, False),
    (0x100001E8000, 2, False),
    (0x100001F8000, 64, False),
    (0x10000300000, 2, False),
    (0x10000310000, 2, True),
    (0x10000320000, 2, True),
    (0x10000330000, 2, True),
    (0x10000340000, 2, True),
    (0x10000350000, 48, True),
    (0x2FFFFFF8000, 1, False),
)
PARTIAL_RENDER_CONTEXT1_PAGE_COUNT = 2914
PARTIAL_RENDER_CONTEXT1_DVA_SHA256 = (
    "40c5e326df4f8338787a0d5cba0eda2862213cd5080da4abe27c026b672f080f"
)
PARTIAL_RENDER_CONTEXT1_READ_ONLY_PAGE_COUNT = 108
PARTIAL_RENDER_CONTEXT1_READ_ONLY_DVA_SHA256 = (
    "bb214dd0212d86d89b41103a91d1ccfaeaa3822fb1519865af335116630df056"
)

# Caller-owned compiler output for the repository's clear-only native
# harness.  Four bounded program records occupy the prefix and the rest of
# the 16-KiB allocation is zero.  These bytes are program contents, not an
# Apple firmware, kernel, kext, or opaque runtime-state page.
CLEAR_PIPELINE_CANONICAL_BASE = 0x10000130000
CLEAR_PIPELINE_DIFFERENTIAL_BASE = 0x10000138000
CLEAR_PIPELINE_MIXED_BASE = 0x10000148000
CLEAR_PIPELINE_PROGRAM_PREFIX = bytes.fromhex(
    "2c800200000088003c800200040000002ce04200080024003c80420004000000"
    "ef040300e80c00cc010000000001af040300e80c00402f24c300c80c0050ef24"
    "8300e80c004eaf248300e80c004c6f248300e80c004a2f248300e80c0048ef24"
    "4300e80c0046af244300e80c00446f244300e80c00422f244300e80c00401700"
    "002c000018084781580e000008000001e701000d0000000000001c8002000000"
    "0000348101002000a0020c800200040000002704041a2100a302888000001c80"
    "020004000000270404003000a412cb0001044b1c01442300073826d0a4125b1e"
    "01043302073826d0a4126b2001042300074026d0a41a7b220104330207402650"
    "a01a0b1409041b1609042b1809043b1a0904db648904eb668904fb6889049b5c"
    "8904ab5e8904bb608904cb6289045b5489046b5689047b5889048b5a89041b4c"
    "89042b4e89043b5089044b528904db444904eb464904fb4849040b4a89049b3c"
    "4904ab3e4904bb404904cb4249045b3449046b3649047b3849048b3a49041b2c"
    "49042b2e49043b3049044b324904db240904eb260904fb2809040b2a49040710"
    "00040000248021104701a08a3c8a08270c8c08431c8e08073f040300884400b1"
    "4100800000012300216023002001ab84010423010100a30a07803070a342c4bf"
    "b700001a3600a102388600340000bb040904a30607803030a352c4bf0e000000"
    "2c8002000c0088003c800200040000002ce04200080024003c80420004000000"
    "ef040300e80c00cc010000000001af040300e80c00402f24c300c80c0050ef24"
    "8300e80c004eaf248300e80c004c6f248300e80c004a2f248300e80c0048ef24"
    "4300e80c0046af244300e80c00446f244300e80c00422f244300e80c00401700"
    "002c000018084781580e000008000001e701000d0000000000001c8002000000"
    "0000348101002000a0020c800200040000002704041a2100a302888000001c80"
    "020004000000270404003000a412cb0001044b1c01442300073826d0a4125b1e"
    "01043302073826d0a4126b2001042300074026d0a41a7b220104330207402650"
    "a01a0b1409041b1609042b1809043b1a0904db648904eb668904fb6889049b5c"
    "8904ab5e8904bb608904cb6289045b5489046b5689047b5889048b5a89041b4c"
    "89042b4e89043b5089044b528904db444904eb464904fb4849040b4a89049b3c"
    "4904ab3e4904bb404904cb4249045b3449046b3649047b3849048b3a49041b2c"
    "49042b2e49043b3049044b324904db240904eb260904fb2809040b2a49040710"
    "00040000248021104701a08a3c8a08270c8c08431c8e08073f040300884400b1"
    "4100800000012300216023002001ab84010423010100a30a07803070a342c4bf"
    "b700001a3600a102388600340000bb040904a30607803030a352c4bf0e000000"
    "2c800200180088003c80020004000000fce002000c0024000c80420004000000"
    "cf040300c80c00c4010000000002af040300a80c0040bf1e8300e80c004e7f1e"
    "8300e80c004c3f1e8300e80c004aff1e4300e80c0048bf1e4300e80c00467f1e"
    "4300e80c00443f1e4300e80c0042ff1e0300e80c00401700002c000018088726"
    "580e0000000000014701000d0000000000001c80020000000000348101002000"
    "a0020c800200040000002704041a2100a302888000001c800200040000002704"
    "04003000a4125b0081046b0081047b0081042b1809443b1a09044b1c09040b14"
    "09041b1609041b5689042b5889043b5a89044b5c8904db4e4904eb504904fb52"
    "49040b5489049b464904ab484904bb4a4904cb4c49045b3e49046b4049047b42"
    "49048b4449041b3649042b3849043b3a49044b3c4904db2e0904eb300904fb32"
    "09040b3449049b260904ab280904bb2a0904cb2c09045b1e09046b2009047b22"
    "09048b2409040e00000000000000000000000000000000000000000000000000"
    "2cc00200020488003c80020004000000fce002000c0024000c80420004000000"
    "cf040300c80c00c4010000000002af040300a80c0040bf1e8300e80c004e7f1e"
    "8300e80c004c3f1e8300e80c004aff1e4300e80c0048bf1e4300e80c00467f1e"
    "4300e80c00443f1e4300e80c0042ff1e0300e80c00401700002c000018088726"
    "580e0000000000014701000d0000000000001c80020000000000348101002000"
    "a0020c800200040000002704041a2100a302888000001c800200040000002704"
    "04003000a4125b0081046b0081047b0081042b1809443b1a09044b1c09040b14"
    "09041b1609041b5689042b5889043b5a89044b5c8904db4e4904eb504904fb52"
    "49040b5489049b464904ab484904bb4a4904cb4c49045b3e49046b4049047b42"
    "49048b4449041b3649042b3849043b3a49044b3c4904db2e0904eb300904fb32"
    "09040b3449049b260904ab280904bb2a0904cb2c09045b1e09046b2009047b22"
    "09048b2409040e"
)
CLEAR_COMPILER_SUPPORT_DVA = 0x10000000000
CLEAR_COMPILER_SUPPORT_PAGE_COUNT = 4
CLEAR_COMPILER_PIPELINE_RECORD_OFFSET = 0x2A0
CLEAR_COMPILER_PIPELINE_RECORD = bytes.fromhex(
    "0700100f0000270004002000a50a0600"
)
CLEAR_COMPILER_AUX_RECORD_OFFSET = 0x3C0
CLEAR_COMPILER_AUX_RECORD = bytes.fromhex(
    "0cdd10062704041a2900a30a288024003701041a2500a302208111002702041a"
    "2500a302208101002f000304180210c000081f000302000200c000080f000300"
    "080200c04108800000002b00070a2682a4021b022924230807022681a40a3480"
    "030a270bae0a0000351033002480a002350533002400a00a350a33002440a012"
    "3523330024c0a01a0e00000000000000"
)

ZLS_LOAD_STENCIL = 1 << 14
ZLS_LOAD_DEPTH = 1 << 15
ZLS_STORE_STENCIL = 1 << 18
ZLS_STORE_DEPTH = 1 << 19
ZLS_LOAD_DEPTH_COMPRESSED = 1 << 2
ZLS_LOAD_STENCIL_COMPRESSED = 1 << 4
ZLS_STORE_DEPTH_COMPRESSED = 1 << 6
ZLS_STORE_STENCIL_COMPRESSED = 1 << 8


def _float_bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def _align(value, alignment):
    return (value + alignment - 1) & -alignment


def encode_bgra8_unorm_pixel(clear_rgba):
    """Encode semantic RGBA bytes in the clear target's physical byte order."""
    if len(clear_rgba) != 4 or any(
        not isinstance(value, int) or not 0 <= value <= 0xFF
        for value in clear_rgba
    ):
        raise ValueError("G17G clear RGBA must contain four uint8 values")
    red, green, blue, alpha = clear_rgba
    return bytes((blue, green, red, alpha))


def encode_zls_dimensions(width, height):
    """Pack G17G's two 16-bit minus-one ZLS dimensions."""
    width = int(width)
    height = int(height)
    if not 1 <= width <= 0x10000 or not 1 <= height <= 0x10000:
        raise ValueError("G17G ZLS dimensions must fit in positive u16")
    return (width - 1) | ((height - 1) << 16)


def _validate_u64(value, name):
    if not 0 <= value < (1 << 64):
        raise ValueError("%s does not fit in u64" % name)


@dataclass(frozen=True)
class G17GClearRenderParameters:
    """Caller-controlled values separated by the two native clear captures."""

    target_dva: int
    clear_state_page: int
    clear_rgba: tuple
    store_pipeline: int
    load_pipeline: int
    auxiliary_object: int
    tiling_lifecycle: int
    width: int = CLEAR_WIDTH
    height: int = CLEAR_HEIGHT
    target_stride_pixels: int = CLEAR_WIDTH
    layers: int = 1
    utile_width: int = 32
    utile_height: int = 32
    samples: int = 1
    sample_size: int = 0
    utile_config: int | None = None
    multisample_control: int = 0x88
    ppp_control: int = 0x202
    tib_blocks: int | None = None
    merge_upper_x_bits: int | None = None
    merge_upper_y_bits: int | None = None
    store_pipeline_bind: int = 0
    load_pipeline_bind: int = 0xFFFF800000000040
    partial_load_pipeline_bind: int = 0xFFFF800000000040
    partial_load_pipeline: int | None = None
    partial_store_pipeline_bind: int = 0
    partial_store_pipeline: int | None = None
    tib_bytes: int = 8
    aux_fb_flags: int = 0x10C001
    depth_bias_is_integer: bool = False
    partial_mode: bool = False
    request_tvb_growth: bool = False
    partial_render_fallback: bool = True
    fragment_sync_grow: bool | None = None
    depth_buffer: int = 0
    stencil_buffer: int = 0
    depth_aux_buffer: int = 0
    stencil_aux_buffer: int = 0
    depth_stride: int = 0
    stencil_stride: int = 0
    depth_aux_stride: int = 0
    stencil_aux_stride: int = 0
    depth_clear_value_bits: int = 0x3F800000
    stencil_clear_value: int = 0
    depth_flags: int = 0
    depth_dimensions: int = 0
    occlusion_query_base: int = 0
    tile_config: int = 0x10280
    process_empty_tiles: bool = True
    sampler_array: int = 0
    sampler_count: int = 0
    scissor_array: int | None = None
    scissor_x: int = 0
    scissor_y: int = 0
    scissor_width: int | None = None
    scissor_height: int | None = None
    depth_bias_array: int | None = None
    tiling_timestamp_start: int = STATUS_A
    tiling_timestamp_end: int = 0
    tiling_user_timestamp_start: int = 0
    tiling_user_timestamp_end: int = 0
    fragment_timestamp_start: int = STATUS_A
    fragment_timestamp_end: int = STATUS_B
    fragment_user_timestamp_start: int = 0
    fragment_user_timestamp_end: int = 0
    vdm_ctrl_stream_base: int = VDM_CTRL_STREAM_BASE
    # Explicit driver-owned per-command storage; None preserves reference
    # experiments that model the original native allocation family.
    buffers: RenderBuffers | None = None

    def validate(self):
        if not isinstance(self.request_tvb_growth, bool):
            raise ValueError("G17G TVB growth selection must be boolean")
        if not isinstance(self.partial_render_fallback, bool):
            raise ValueError("G17G partial-render fallback selection must be boolean")
        if not self.partial_render_fallback and not self.request_tvb_growth:
            raise ValueError("G17G no-fallback recipe requires TVB growth selection")
        if self.fragment_sync_grow is not None and not isinstance(self.fragment_sync_grow, bool):
            raise ValueError("G17G fragment growth selection must be boolean or unspecified")
        if not isinstance(self.process_empty_tiles, bool):
            raise ValueError("G17G process-empty-tiles must be boolean")
        if not isinstance(self.depth_bias_is_integer, bool):
            raise ValueError("G17G integer-depth-bias selection must be boolean")
        if not 1 <= self.layers <= 2048:
            raise ValueError("G17G render layers must be within 1..2048")
        if (self.utile_width, self.utile_height) not in (
            (32, 32), (32, 16), (16, 16),
        ):
            raise ValueError("G17G render utile dimensions are invalid")
        if self.samples not in (1, 2, 4):
            raise ValueError("G17G render samples must be 1, 2, or 4")
        if not 0 <= self.sample_size < (1 << 32):
            raise ValueError("G17G render sample size must fit in u32")
        utile_bytes = (
            self.sample_size * self.utile_width * self.utile_height
            * self.samples
        )
        if utile_bytes > 32768:
            raise ValueError("G17G render utile exceeds the 32-KiB TIB limit")
        if self.buffers is not None:
            from .g17g_render_buffers import render_buffers
            if self.buffers != render_buffers(self, self.buffers.tilemap):
                raise ValueError("render buffers do not match this command's geometry")
        elif self.partial_mode and (self.width, self.height) != (128, 128):
            raise ValueError(
                "current G17G partial-render recipe is established only "
                "for 128x128"
            )
        if self.buffers is None and not self.partial_mode and (
            self.width <= 0
            or self.height <= 0
            or self.target_stride_pixels < self.width
            or self.target_stride_pixels * self.height * 4 > PAGE_SIZE
        ):
            raise ValueError(
                "current G17G ordinary-clear proof requires positive "
                "dimensions within a positive one-page BGRA row stride"
            )
        if self.target_dva & 0xF:
            raise ValueError("G17G clear target must be 16-byte aligned")
        if self.clear_state_page & (PAGE_SIZE - 1):
            raise ValueError("G17G clear-state page must be 16 KiB aligned")
        encode_bgra8_unorm_pixel(self.clear_rgba)
        for name in (
            "target_dva", "clear_state_page", "store_pipeline",
            "load_pipeline", "auxiliary_object", "tiling_lifecycle",
            "store_pipeline_bind", "load_pipeline_bind",
            "partial_load_pipeline_bind", "partial_store_pipeline_bind",
            "depth_buffer", "stencil_buffer", "depth_aux_buffer",
            "stencil_aux_buffer", "depth_stride", "stencil_stride",
            "depth_aux_stride", "stencil_aux_stride", "depth_flags",
            "depth_dimensions", "occlusion_query_base", "tile_config",
            "target_stride_pixels", "sampler_array", "sampler_count",
            "layers", "utile_width", "utile_height", "samples",
            "sample_size", "multisample_control", "ppp_control",
            "scissor_x", "scissor_y",
            "tiling_timestamp_start", "tiling_timestamp_end",
            "tiling_user_timestamp_start", "tiling_user_timestamp_end",
            "fragment_timestamp_start", "fragment_timestamp_end",
            "fragment_user_timestamp_start", "fragment_user_timestamp_end",
            "vdm_ctrl_stream_base",
        ):
            _validate_u64(getattr(self, name), name)
        _validate_u64(self.resolved_utile_config(), "utile_config")
        _validate_u64(self.resolved_tib_blocks(), "tib_blocks")
        for name, value in (
            ("merge_upper_x_bits", self.resolved_merge_upper_x_bits()),
            ("merge_upper_y_bits", self.resolved_merge_upper_y_bits()),
        ):
            if not 0 <= value < (1 << 32):
                raise ValueError("G17G %s must fit in u32" % name)
        self.resolved_vdm_ctrl_stream_offset()
        for name in (
            "tiling_user_timestamp_start", "tiling_user_timestamp_end",
            "fragment_user_timestamp_start", "fragment_user_timestamp_end",
        ):
            value = getattr(self, name)
            if value and value & 7:
                raise ValueError("G17G %s must be 8-byte aligned" % name)
        if bool(self.sampler_array) != bool(self.sampler_count):
            raise ValueError(
                "G17G sampler array and count must both be zero or nonzero"
            )
        if self.sampler_array & 7:
            raise ValueError("G17G sampler array must be 8-byte aligned")
        if self.sampler_count > 1024:
            raise ValueError("G17G sampler count exceeds the UAPI heap limit")
        if (self.scissor_width is None) != (self.scissor_height is None):
            raise ValueError(
                "G17G scissor width and height must be supplied together"
            )
        if self.scissor_width is not None:
            if not 1 <= self.scissor_width <= self.width - self.scissor_x:
                raise ValueError("G17G scissor X range exceeds the render width")
            if not 1 <= self.scissor_height <= self.height - self.scissor_y:
                raise ValueError("G17G scissor Y range exceeds the render height")
        elif self.scissor_x or self.scissor_y:
            raise ValueError("G17G scissor origins require explicit dimensions")
        if self.occlusion_query_base & 7:
            raise ValueError("G17G occlusion-query base must be 8-byte aligned")
        for name, value in (
            ("partial_load_pipeline", self.resolved_partial_load_pipeline()),
            ("partial_store_pipeline", self.resolved_partial_store_pipeline()),
            ("scissor_array", self.resolved_scissor_array()),
            ("depth_bias_array", self.resolved_depth_bias_array()),
            ("aux_fb_flags", self.aux_fb_flags),
        ):
            _validate_u64(value, name)
        for name, value in (
            ("scissor array", self.resolved_scissor_array()),
            ("depth-bias array", self.resolved_depth_bias_array()),
        ):
            if value & 7 or (name == "scissor array" and not value):
                raise ValueError(
                    "G17G %s must be 8-byte aligned (scissor is required)" % name
                )
        expected_tib = 32 if self.partial_mode else 8
        if self.tib_bytes != expected_tib:
            raise ValueError(
                "current G17G render recipe requires %d TIB bytes"
                % expected_tib
            )
        allowed_aux = (
            {
                FRAGMENT_AUX_FLAGS_BASE,
                FRAGMENT_AUX_FLAGS_BASE | FRAGMENT_AUX_FLAG_BIT0,
            }
            if self.partial_mode else
            {FRAGMENT_AUX_FLAGS_BASE | FRAGMENT_AUX_FLAG_BIT0}
        )
        if self.aux_fb_flags not in allowed_aux:
            raise ValueError(
                "current G17G render recipe requires aux flags in %s"
                % ", ".join("%#x" % value for value in sorted(allowed_aux))
            )
        if self.tiling_lifecycle == 0:
            raise ValueError("G17G tiling lifecycle must admit fragment value - 1")
        if not 0 <= self.depth_clear_value_bits < (1 << 32):
            raise ValueError("G17G depth clear value must fit in u32")
        if not 0 <= self.stencil_clear_value < (1 << 8):
            raise ValueError("G17G stencil clear value must fit in u8")
        if self.depth_flags & (ZLS_LOAD_DEPTH | ZLS_STORE_DEPTH):
            if not self.depth_buffer or not self.depth_dimensions:
                raise ValueError(
                    "G17G depth load/store requires a buffer and dimensions"
                )
        if self.depth_flags & (ZLS_LOAD_STENCIL | ZLS_STORE_STENCIL):
            if not self.stencil_buffer or not self.depth_dimensions:
                raise ValueError(
                    "G17G stencil load/store requires a buffer and dimensions"
                )

    def resolved_partial_load_pipeline(self):
        if self.partial_load_pipeline is not None:
            return self.partial_load_pipeline
        return self.load_pipeline & ~(PAGE_SIZE - 1)

    def resolved_partial_store_pipeline(self):
        if self.partial_store_pipeline is not None:
            return self.partial_store_pipeline
        return self.store_pipeline

    def resolved_scissor_array(self):
        if self.scissor_array is not None:
            return self.scissor_array
        return (self.store_pipeline & ~(PAGE_SIZE - 1)) + 0x10000

    def resolved_scissor_width(self):
        if self.scissor_width is not None:
            return self.scissor_width
        return self.width

    def resolved_scissor_height(self):
        if self.scissor_height is not None:
            return self.scissor_height
        return self.height

    def resolved_depth_bias_array(self):
        if self.depth_bias_array is not None:
            return self.depth_bias_array
        return self.auxiliary_object + 0x50000

    def resolved_tile_config(self):
        return (
            (self.tile_config & ~0x10001)
            | (0x10000 if self.process_empty_tiles else 0)
            | (1 if self.layers > 1 else 0)
        )

    def resolved_aux_fb_flags(self):
        return (
            self.aux_fb_flags
            | (
                FRAGMENT_AUX_FLAG_DBIAS_IS_INT
                if self.depth_bias_is_integer else 0
            )
        )

    def resolved_utile_config(self):
        if self.utile_config is not None:
            return int(self.utile_config)
        return (
            ((self.utile_width // 16) << 12)
            | ((self.utile_height // 16) << 14)
            | {1: 0, 2: 1, 4: 2}[self.samples]
        )

    def resolved_tib_blocks(self):
        if self.tib_blocks is not None:
            return int(self.tib_blocks)
        utile_bytes = (
            self.sample_size * self.utile_width * self.utile_height
            * self.samples
        )
        return (utile_bytes + 2047) // 2048

    def resolved_merge_upper_x_bits(self):
        if self.merge_upper_x_bits is not None:
            return int(self.merge_upper_x_bits)
        return _float_bits(MERGE_SCALE / self.width)

    def resolved_merge_upper_y_bits(self):
        if self.merge_upper_y_bits is not None:
            return int(self.merge_upper_y_bits)
        return _float_bits(MERGE_SCALE / self.height)

    def resolved_vdm_ctrl_stream_offset(self):
        """Encode the caller VDM DVA in G17G's resource-base-relative form."""
        offset = int(self.vdm_ctrl_stream_base) - VDM_RESOURCE_BASE
        # Hardware accepts all 39 offset bits; bit39 instead selects TTBR1
        # without the resource-base bias. Other caller placements require a
        # private alias, not truncation of their primary address.
        if not 0 <= offset < (1 << 39) or offset & 3:
            raise ValueError(
                "G17G VDM control stream must be a 4-byte-aligned DVA "
                "within the 39-bit render-resource window or use a private alias"
            )
        return offset


def _render_geometry(params):
    """Derive G17G's packed 32x32-tile geometry register values."""
    tiles_x = (params.width + TILE_WIDTH - 1) // TILE_WIDTH
    tiles_y = (params.height + TILE_HEIGHT - 1) // TILE_HEIGHT
    utiles_per_tile_x = TILE_WIDTH // params.utile_width
    utiles_per_tile_y = TILE_HEIGHT // params.utile_height
    utiles_per_tile = utiles_per_tile_x * utiles_per_tile_y
    mtile_x1 = _align(
        (tiles_x + MACRO_TILES_X - 1) // MACRO_TILES_X, 4
    )
    mtile_y1 = _align(
        (tiles_y + MACRO_TILES_Y - 1) // MACRO_TILES_Y, 4
    )
    mtile_x2, mtile_x3 = 2 * mtile_x1, 3 * mtile_x1
    mtile_y2, mtile_y3 = 2 * mtile_y1, 3 * mtile_y1
    mtile_stride = mtile_x1 * mtile_y1
    size1 = (
        REGION_ENTRY_SIZE * mtile_stride * utiles_per_tile + 3
    ) // 4
    utile_config = params.resolved_utile_config()
    return {
        "size1": size1,
        "size2": mtile_stride,
        "size3": 2 * mtile_stride * utiles_per_tile,
        # G17G widens both packed block fields relative to G17P.
        "x_blocks": mtile_x3 | (mtile_x2 << 10) | (mtile_x1 << 20),
        "y_blocks": mtile_y3 | (mtile_y2 << 10) | (mtile_y1 << 20),
        "screen": ((tiles_y - 1) << 12) | (tiles_x - 1),
        "pixels": (params.width - 1) | ((params.height - 1) << 16),
        "macro_size": (
            mtile_y1 * utiles_per_tile_y
            | (mtile_x1 * utiles_per_tile_x << 16)
        ),
        # G17G places tile X/Y counts at bits 42/52. G17P uses 44/53.
        "tile_state": (
            0x000002000003717F
            | ((utile_config & 0xF000) << 24)
            | (0x100000000 if params.layers > 1 else 0)
            | ((tiles_x - 1) << 42)
            | ((tiles_y - 1) << 52)
        ),
    }


def build_partial_generation_parameters(params, submission_ordinal):
    """Derive one native persistent-queue partial-render generation.

    The earliest three native submissions establish two distinct transitions:
    generation two advances the lifecycle by ``(2 << 32) + 0x17`` and moves
    four pipeline/bind operands to their recurrent values; later generations
    advance only by ``(2 << 32) + 3`` while retaining those operands.  Keeping
    this derivation next to descriptor serialization prevents callers from
    accidentally treating the first transition as a fixed stride.
    """
    params.validate()
    submission_ordinal = int(submission_ordinal)
    if not params.partial_mode:
        raise ValueError("G17G partial generation requires partial mode")
    if not 1 <= submission_ordinal < (1 << 16):
        raise ValueError(
            "G17G partial generation ordinal must fit in positive u16"
        )
    if submission_ordinal == 1:
        return params

    lifecycle = (
        params.tiling_lifecycle
        + (2 << 32) + 0x17
        + (submission_ordinal - 2) * ((2 << 32) + 3)
    )
    generated = replace(
        params,
        tiling_lifecycle=lifecycle,
        store_pipeline=params.store_pipeline + 0x140,
        partial_store_pipeline=params.resolved_partial_store_pipeline() + 0x140,
        load_pipeline_bind=params.load_pipeline_bind + 0xE0,
        partial_load_pipeline_bind=params.partial_load_pipeline_bind - 0x40,
    )
    generated.validate()
    return generated


def build_clear_state_page(params):
    """Build the exact source-described context-1 clear-state page.

    The page has three records beginning at 0x00, 0x300 and 0x600.  The first
    two carry identical RGBA float blocks.  Their packed target fields share a
    0x3c prefix, while the third uses 0x0f.  Self-pointers move with the page.
    """
    params.validate()
    # The old partial reference graph carries an unused 64x64 clear record
    # alongside its separate draw programs. Preserve that reference image.
    width, height = ((64, 64) if params.partial_mode and params.buffers is None
                     else (params.width, params.height))
    if params.target_stride_pixels < width or params.target_stride_pixels % 16:
        raise ValueError("linear BGRA caller stride must cover the width and align to 64 bytes")
    page = bytearray(PAGE_SIZE)
    base = params.clear_state_page
    target_units = params.target_dva >> 4
    texture = 0x60A0A02 | ((width - 1) << 28) | ((height - 1) << 43)
    stride = params.target_stride_pixels // 4 - 1

    qwords = (
        (0x000, base + 0x020),
        (0x008, base + 0x120),
        (0x020, texture),
        (0x028, (stride << 46) | target_units),
        (0x120, 0x00000740000F0000),
        (0x140, 0x0000075B60000000),
        (0x160, base + 0x168),
        (0x168, 0x0000000100000002),
        (0x1F0, 0x000000003F800000),
        (0x1F8, 0x3F80000000000000),
        (0x2D0, 0x0000000000100083),
        (0x2F0, 0x0000000000408001),
        (0x300, base + 0x320),
        (0x308, base + 0x420),
        (0x320, texture),
        (0x328, (stride << 46) | target_units),
        (0x420, 0x00000740000F0000),
        (0x440, 0x0000075B60000000),
        (0x460, base + 0x468),
        (0x468, 0x0000000001000002),
        (0x4F0, 0x000000003F800000),
        (0x4F8, 0x3F80000000000000),
        (0x5D0, 0x0000000000100083),
        (0x5F0, 0x0000000000408001),
        (0x600, base + 0x620),
        (0x608, 0xFFFFFFFFFFFFFFFF),
        (0x610, 0xFFFFFFFFFFFFFFFF),
        (0x618, 0xFFFFFFFFFFFFFFFF),
        (0x620, 0xC60A02 | ((width - 1) << 24) | ((height - 1) << 39)),
        (0x628, (stride << 44) | target_units),
        (0x820, base + 0x828),
        (0x828, 0x1002030000000000),
        (0x870, 0x0000000100000000),
        (0x878, 0x0000000000400081),
        (0x8B8, 0xFFFFFFFF00000000),
        (0xB88, 0x0006800000068000),
        (0xB90, 0x0000000060000000),
        (0xB98, 0x0000000000068000),
    )
    for offset, value in qwords:
        _validate_u64(value, "clear-state qword at %#x" % offset)
        struct.pack_into("<Q", page, offset, value)

    rgba_bits = tuple(_float_bits(value / 255.0) for value in params.clear_rgba)
    for offset in (0x170, 0x470):
        struct.pack_into("<4I", page, offset, *rgba_bits)
    return bytes(page)


def build_render_operand_table(
        buffer_base=RENDER_OPERAND_BASE, operand_count=RENDER_OPERAND_COUNT):
    """Build the sparse table naming caller-visible render operand runs."""
    _validate_u64(buffer_base, "render operand base")
    operand_count = int(operand_count)
    if not 0 <= operand_count <= PARTIAL_RENDER_OPERAND_COUNT:
        raise ValueError("G17G render operand count is out of range")
    if buffer_base & (PAGE_SIZE - 1):
        raise ValueError("G17G render operand base must be 16 KiB aligned")
    page = bytearray(PAGE_SIZE)
    for index in range(operand_count):
        struct.pack_into(
            "<Q", page, index * 0x40,
            RENDER_OPERAND_FLAG + buffer_base + index * RENDER_OPERAND_STRIDE,
        )
    page = bytes(page)
    if (
        buffer_base == RENDER_OPERAND_BASE
        and operand_count == PARTIAL_RENDER_OPERAND_COUNT
        and hashlib.sha256(page).hexdigest()
        != PARTIAL_RENDER_OPERAND_TABLE_SHA256
    ):
        raise ValueError("G17G partial-render operand table changed")
    return page


def merge_render_operand_growth_page(live_page, old_page, grown_page):
    """Apply only a caller's operand-growth delta to firmware-live state.

    The address-list and operand-table pages are live before an exhausted
    render report is returned.  Replacing a whole page with its initial
    full-pool image can therefore erase firmware-owned state which is
    invisible in the caller's pre-service image.  Treat ``old_page`` to
    ``grown_page`` as the caller-owned transaction and preserve every live
    byte outside that delta.
    """
    live_page = bytes(live_page)
    old_page = bytes(old_page)
    grown_page = bytes(grown_page)
    if not all(
        len(page) == PAGE_SIZE
        for page in (live_page, old_page, grown_page)
    ):
        raise ValueError("G17G operand growth requires complete pages")
    merged = bytearray(live_page)
    for offset, (old, grown) in enumerate(zip(old_page, grown_page)):
        if old != grown:
            merged[offset] = grown
    return bytes(merged)


def expand_render_context1_dvas():
    """Expand and hash-gate the canonical first-clear DVA topology."""
    pages = tuple(
        base + index * PAGE_SIZE
        for base, page_count, _read_only in RENDER_CONTEXT1_RUNS
        for index in range(page_count)
    )
    if len(pages) != RENDER_CONTEXT1_PAGE_COUNT:
        raise ValueError("G17G render context-1 page count changed")
    if pages != tuple(sorted(set(pages))):
        raise ValueError("G17G render context-1 runs overlap or are unordered")
    encoded = b"".join(struct.pack("<Q", page) for page in pages)
    if hashlib.sha256(encoded).hexdigest() != RENDER_CONTEXT1_DVA_SHA256:
        raise ValueError("G17G render context-1 DVA hash changed")
    return pages


def expand_render_context1_read_only_dvas():
    """Expand and hash-gate the native read-only subset."""
    pages = tuple(
        base + index * PAGE_SIZE
        for base, page_count, read_only in RENDER_CONTEXT1_RUNS
        if read_only
        for index in range(page_count)
    )
    if len(pages) != RENDER_CONTEXT1_READ_ONLY_PAGE_COUNT:
        raise ValueError("G17G render read-only page count changed")
    if not set(pages) <= set(expand_render_context1_dvas()):
        raise ValueError("G17G render read-only page is absent from topology")
    encoded = b"".join(struct.pack("<Q", page) for page in pages)
    if hashlib.sha256(encoded).hexdigest() != (
        RENDER_CONTEXT1_READ_ONLY_DVA_SHA256
    ):
        raise ValueError("G17G render read-only DVA hash changed")
    return pages


def expand_partial_render_context1_dvas():
    """Expand and hash-gate the exact first-partial selector-zero root."""
    pages = tuple(
        base + index * PAGE_SIZE
        for base, page_count, _read_only in PARTIAL_RENDER_CONTEXT1_RUNS
        for index in range(page_count)
    )
    if len(pages) != PARTIAL_RENDER_CONTEXT1_PAGE_COUNT:
        raise ValueError("G17G partial-render context topology changed")
    if pages != tuple(sorted(set(pages))):
        raise ValueError("G17G partial-render runs overlap or are unordered")
    encoded = b"".join(struct.pack("<Q", page) for page in pages)
    if hashlib.sha256(encoded).hexdigest() != (
        PARTIAL_RENDER_CONTEXT1_DVA_SHA256
    ):
        raise ValueError("G17G partial-render DVA hash changed")
    return pages


def expand_partial_render_context1_read_only_dvas():
    """Return the measured read-only subset of the first-partial root."""
    pages = tuple(
        base + index * PAGE_SIZE
        for base, page_count, read_only in PARTIAL_RENDER_CONTEXT1_RUNS
        if read_only
        for index in range(page_count)
    )
    if len(pages) != PARTIAL_RENDER_CONTEXT1_READ_ONLY_PAGE_COUNT:
        raise ValueError("G17G partial-render read-only page count changed")
    if not set(pages) <= set(expand_partial_render_context1_dvas()):
        raise ValueError("G17G partial-render read-only page is absent")
    encoded = b"".join(struct.pack("<Q", page) for page in pages)
    if hashlib.sha256(encoded).hexdigest() != (
        PARTIAL_RENDER_CONTEXT1_READ_ONLY_DVA_SHA256
    ):
        raise ValueError("G17G partial-render read-only DVA hash changed")
    return pages


def build_render_address_list_pages(
    buffer_base=RENDER_OPERAND_BASE,
    address_list_base=RENDER_ADDRESS_LIST_PAGE_DVAS[0],
    operand_count=RENDER_OPERAND_COUNT,
):
    """Enumerate every 4 KiB address in a bounded operand-run prefix."""
    _validate_u64(buffer_base, "render operand base")
    _validate_u64(address_list_base, "render address-list base")
    operand_count = int(operand_count)
    if not 0 <= operand_count <= PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT:
        raise ValueError("G17G render operand count is out of range")
    if buffer_base & (PAGE_SIZE - 1):
        raise ValueError("G17G render operand base must be 16 KiB aligned")
    if address_list_base & (PAGE_SIZE - 1):
        raise ValueError("G17G render address-list base must be 16 KiB aligned")
    entries_per_page = PAGE_SIZE // RENDER_ADDRESS_ENTRY_STRIDE
    populated_page_count = (
        operand_count * RENDER_ADDRESS_ENTRIES_PER_OPERAND
        + entries_per_page - 1
    ) // entries_per_page
    page_count = max(len(RENDER_ADDRESS_LIST_PAGE_DVAS), populated_page_count)
    address_list_dvas = tuple(
        address_list_base + index * PAGE_SIZE
        for index in range(page_count)
    )
    pages = [bytearray(PAGE_SIZE) for _dva in address_list_dvas]
    for operand_index in range(operand_count):
        run_base = buffer_base + operand_index * RENDER_OPERAND_STRIDE
        for entry_index in range(RENDER_ADDRESS_ENTRIES_PER_OPERAND):
            flat_index = (
                operand_index * RENDER_ADDRESS_ENTRIES_PER_OPERAND
                + entry_index
            )
            page_index, local_index = divmod(flat_index, entries_per_page)
            struct.pack_into(
                "<Q", pages[page_index],
                local_index * RENDER_ADDRESS_ENTRY_STRIDE,
                run_base + entry_index * RENDER_ADDRESS_GRANULE,
            )
    result = {
        dva: bytes(page)
        for dva, page in zip(address_list_dvas, pages)
    }
    if (
        buffer_base == RENDER_OPERAND_BASE
        and address_list_base == RENDER_ADDRESS_LIST_PAGE_DVAS[0]
    ):
        hashes = tuple(
            hashlib.sha256(result[dva]).hexdigest()
            for dva in address_list_dvas
        )
        expected_hashes = (
            PARTIAL_RENDER_ADDRESS_LIST_PAGE_SHA256
            if operand_count == PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT
            else
            RENDER_SERVICE_INPUT_ADDRESS_LIST_PAGE_SHA256
            if operand_count == RENDER_SERVICE_INPUT_OPERAND_COUNT
            else RENDER_ADDRESS_LIST_PAGE_SHA256
            if operand_count == RENDER_OPERAND_COUNT
            else None
        )
        if expected_hashes is not None and hashes != expected_hashes:
            raise ValueError("G17G render address-list recipe changed")
    return result


def build_render_base10_support_page():
    """Build the sparse fixed page referenced by the fragment descriptor."""
    page = bytearray(PAGE_SIZE)
    for offset in range(0, 0x280, 0x80):
        struct.pack_into("<Q", page, offset, 0x80)
        struct.pack_into("<Q", page, offset + 0x40, 0x10100000)
    struct.pack_into("<Q", page, 0x280, 0xFD40)
    return bytes(page)


def build_render_scissor_page(width=CLEAR_WIDTH, height=CLEAR_HEIGHT):
    """Build one caller-owned G17G scissor-array page."""
    width = int(width)
    height = int(height)
    if not 1 <= width < (1 << 32) or not 1 <= height < (1 << 32):
        raise ValueError("G17G scissor dimensions must fit in positive u32")
    page = bytearray(PAGE_SIZE)
    struct.pack_into("<II", page, 0, width, height)
    struct.pack_into("<I", page, 0x0C, 0x3F800000)
    return bytes(page)


RENDER_QUEUE_CONTEXT_ITEM_SIZE = 0x200
RENDER_QUEUE_CONTEXT_ITEM_BASE = 0x200
RENDER_QUEUE_CONTEXT_ITEMS_PER_PAGE = (
    PAGE_SIZE - RENDER_QUEUE_CONTEXT_ITEM_BASE
) // RENDER_QUEUE_CONTEXT_ITEM_SIZE
# The caller parameter-buffer allocation is exactly nine pages: 32 records at
# a 0x1200 stride. Descriptor storage, scheduler records, logical ordinals, and
# queue-context storage are independent namespaces and continue beyond that
# first parameter-pool wrap.  Queue-context *payload* ordinals continue, while
# their finite physical record array wraps independently.  The native
# context-zero aliases bound the two
# descriptor arenas independently: 37 pages hold 242 complete 0x9c0 tiling
# records plus the first 0x880 bytes of descriptor 242; one host-provided 16K
# page completes descriptors 242..248. Descriptors 249..255 occupy the next
# 16K canonical page, which initially belongs to retired fragment descriptors
# 0 and 1 and must be rebound only after those users quiesce.
# The fragment view has 241 complete 0x2240 records followed by one missing
# alias page; supplying that page extends the arena through descriptor 241,
# and native mappings then carry all remaining descriptors used here.
RENDER_PARAMETER_SLOT_COUNT = 32
RENDER_QUEUE_CONTEXT_ITEM_COUNT = 256
RENDER_SUBMISSION_COUNTER_COUNT = 256
RENDER_TILING_DESCRIPTOR_COUNT = 256
RENDER_FRAGMENT_DESCRIPTOR_COUNT = 256
RENDER_OPTIONAL_ITEM_PAIR_COUNT = 256
RENDER_EVENT_ITEM_PAIR_COUNT = 512


def render_queue_context_item_offset(item_index):
    """Return one physical record offset in the native 256-item ring.

    The firmware-scratch allocation is exactly eight 16-KiB pages.  Record
    zero starts at +0x200, leaving the allocation's first 0x200 bytes unused
    until the final physical identity: record 255 occupies +0x000.  Native
    work 257 then wraps to +0x200 and replaces record zero.  Treating the
    records as a linear ``+0x200`` array incorrectly places work 256 on an
    invented ninth page, where firmware never reads it.
    """
    item_index = int(item_index)
    if not 0 <= item_index < RENDER_QUEUE_CONTEXT_ITEM_COUNT:
        raise ValueError("G17G queue-context storage index is out of range")
    return (
        (item_index + 1) % RENDER_QUEUE_CONTEXT_ITEM_COUNT
    ) * RENDER_QUEUE_CONTEXT_ITEM_SIZE

# These two scheduler-record pools share neither their stride nor their
# capacity.  The source-built pages contain 35 initialized 0x100-byte pool-A
# records and 79 initialized 0x80-byte pool-B records; the remainder of each
# 16K page is zero, not additional usable records.  Their physical indices
# therefore wrap independently of descriptor storage, parameter-buffer slots,
# and the logical submission ordinal.
RENDER_POOL_A_SLOT_COUNT = 35
RENDER_POOL_B_SLOT_COUNT = 79

# The native allocator has one additional cyclic record immediately before
# each initially populated array.  The 257-work earliest-state capture exposes
# the complete cycles: pool A walks 36 records rooted at ...c08a8000 and pool B
# walks 80 rooted at ...c08b8000.  Work one therefore selects slot 1 in each
# ring, while work 257 selects slots 5 and 17 respectively.
RENDER_POOL_A_RING_BASE = DESCRIPTOR_OBJECTS[0] - 0x100
RENDER_POOL_B_RING_BASE = DESCRIPTOR_OBJECTS[2] - 0x80
RENDER_POOL_A_RING_SLOT_COUNT = 36
RENDER_POOL_B_RING_SLOT_COUNT = 80

# Native descriptor storage wraps independently for the two engines.  The
# hash-pinned 257-work corpus contains TA ordinals 16..257 in slots 15..14 and
# fragment ordinals 17..257 in slots 16..15, proving these exact capacities.
RENDER_TILING_ALLOCATION_SLOT_COUNT = 242
RENDER_FRAGMENT_ALLOCATION_SLOT_COUNT = 241


def render_descriptor_work_index(submission_ordinal):
    """Return the retained scheduler ordinal carried by a TA descriptor.

    The native 257-work corpus proves one reserved value after every 63
    ordinary logical indices: 62 -> 64, 126 -> 128, 189 -> 192, and
    252 -> 256.  This timeline is independent of descriptor, status, and
    queue-transport storage.
    """
    submission_ordinal = int(submission_ordinal)
    if not 1 <= submission_ordinal < (1 << 16):
        raise ValueError("G17G render submission ordinal is out of range")
    logical_index = submission_ordinal - 1
    return logical_index + logical_index // 63


def render_descriptor_work_stamp(submission_ordinal):
    """Return the six-bit work stamp in render-context namespace one."""
    return render_descriptor_work_index(submission_ordinal) & 0x3F


def render_tiling_allocation_index(submission_ordinal):
    submission_ordinal = int(submission_ordinal)
    render_descriptor_work_index(submission_ordinal)
    return (submission_ordinal - 1) % RENDER_TILING_ALLOCATION_SLOT_COUNT


def render_fragment_allocation_index(submission_ordinal):
    submission_ordinal = int(submission_ordinal)
    render_descriptor_work_index(submission_ordinal)
    return (
        (submission_ordinal - 1)
        % RENDER_FRAGMENT_ALLOCATION_SLOT_COUNT
    )


def render_pool_a_allocation(submission_ordinal):
    submission_ordinal = int(submission_ordinal)
    render_descriptor_work_index(submission_ordinal)
    slot = submission_ordinal % RENDER_POOL_A_RING_SLOT_COUNT
    return slot, RENDER_POOL_A_RING_BASE + slot * 0x100


def render_pool_b_allocation(submission_ordinal):
    submission_ordinal = int(submission_ordinal)
    render_descriptor_work_index(submission_ordinal)
    slot = submission_ordinal % RENDER_POOL_B_RING_SLOT_COUNT
    return slot, RENDER_POOL_B_RING_BASE + slot * 0x80


def render_pool_a_retired_qwords(completed_ordinal):
    """Return firmware-retired pool-A state for one completed render.

    Native works one and two establish the first transition, the exact
    80-work source stream establishes the recurrent three-count step, and the
    earliest-state work-257 corpus pins the extra 0x20 at the 256 boundary.
    The record pointer at +0x00 is allocation-specific and remains untouched.
    """
    completed_ordinal = int(completed_ordinal)
    if not 1 <= completed_ordinal <= 257:
        raise ValueError(
            "G17G retired pool-A model is established only through work 257"
        )
    if completed_ordinal == 1:
        completion_end = 0xF3
    else:
        completion_end = (
            0x10B
            + 3 * (completed_ordinal - 2)
            + 0x20 * ((completed_ordinal - 1) // 256)
        )
    return (
        (0x08, 0x0000000200000000
         | render_descriptor_work_index(completed_ordinal)),
        (0x10, 0x50),
        (0x20, 0x0000000100000000),
        (0xA0, 0xFFFFFC2000000000),
        (0xA8, 0x0000000100000000 | completion_end),
        (0xB0, 0x0000000100000000 | (completion_end - 1)),
        (0xC0, 1),
    )


def render_pool_b_retired_qwords(completed_ordinal):
    """Return the one firmware-retired pool-B readiness qword."""
    completed_ordinal = int(completed_ordinal)
    if not 1 <= completed_ordinal < (1 << 16):
        raise ValueError("G17G retired pool-B ordinal is out of range")
    return ((0x48, 0x0000000100000000),)

# Parameter identity selects finite accelerator-owned context-1 state.  A
# retired slot must be cleared before reuse; rewriting only the firmware work
# descriptor leaves the old parameter block live and firmware retires the
# replacement without executing it.
RENDER_RECYCLED_CONTEXT1_ZERO_RANGES = (
    (0x1000080000, 0x40, 0x40),
    (0x1000220040, 0x40, 0x40),
    (0x1000260000, 0x1200, 0x1200),
)

def build_render_recycled_parameter_ranges(parameter_index):
    """Return zero-state context-1 ranges for one retired parameter slot."""
    parameter_index = int(parameter_index)
    if not 0 <= parameter_index < RENDER_PARAMETER_SLOT_COUNT:
        raise ValueError("G17G render parameter index is out of range")
    return tuple(
        (base + parameter_index * stride, size)
        for base, stride, size in RENDER_RECYCLED_CONTEXT1_ZERO_RANGES
    )


def render_transport_descriptor_index(
        logical_group_index, transport_group_index, transport_generation):
    """Select descriptor storage without restarting the work timeline.

    A fresh transport generation owns fresh descriptor backing and restarts
    its allocation cursor at zero.  Submission/status and queue-context
    identities remain on the logical render timeline; callers pass those
    independently to the descriptor and queue-context builders.
    """
    logical_group_index = int(logical_group_index)
    transport_group_index = int(transport_group_index)
    transport_generation = int(transport_generation)
    if logical_group_index < 0 or transport_group_index < 0:
        raise ValueError("G17G render group index must be non-negative")
    if transport_generation < 0:
        raise ValueError("G17G render transport generation is negative")
    index = (
        transport_group_index
        if transport_generation else logical_group_index
    )
    if not 0 <= index < RENDER_TILING_DESCRIPTOR_COUNT:
        raise ValueError("G17G render transport descriptor index is exhausted")
    return index


def _validate_render_pool_index(name, index, count):
    index = int(index)
    if not 0 <= index < count:
        raise ValueError("G17G render %s index is out of range" % name)
    return index


def build_render_queue_context_item(
        kind, descriptor_address, item_index=0, queue_index=None,
        queue_address=None, descriptor_index=None, context_id=None):
    """Build one per-group record in a render queue-context page.

    Three native consecutive groups establish the 0x200 stride.  The first two
    publication snapshots establish the item-0/item-1 arithmetic below; the
    descriptor address remains a caller-owned pool choice.
    """
    if kind not in ("tiling", "fragment"):
        raise ValueError("G17G render queue-context kind is invalid")
    descriptor_address = int(descriptor_address)
    item_index = int(item_index)
    stage = 0 if kind == "tiling" else 1
    if queue_index is None:
        queue_index = stage
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("G17G queue-context queue index must fit in uint8")
    if kind == "fragment" and queue_index == 0:
        raise ValueError("G17G fragment queue index must be positive")
    if queue_address is None:
        queue_address = 0xFFFFFC20C0000000 + queue_index * 0x80
    queue_address = int(queue_address)
    _validate_u64(descriptor_address, "G17G queue-context descriptor")
    _validate_u64(queue_address, "G17G queue-context queue")
    if not 0 <= item_index < (1 << 16):
        raise ValueError("G17G render queue-context item index is out of range")
    if descriptor_index is None:
        descriptor_index = item_index
    descriptor_index = int(descriptor_index)
    if descriptor_index < 0:
        raise ValueError("G17G queue-context descriptor index is negative")
    if context_id is None:
        context_id = queue_index // 2
    context_id = int(context_id)
    if not 0 <= context_id < (1 << 32):
        raise ValueError("G17G queue-context id must fit in uint32")
    item = bytearray(RENDER_QUEUE_CONTEXT_ITEM_SIZE)
    if kind == "tiling":
        values = (
            (0x00, 0x1000000000000000
             | (queue_index << 42) | (4 * (item_index + 1))),
            (0x10, descriptor_address),
            (0x18, queue_address),
            (0x20, 0xFFFF0C0000000001 | (context_id << 32)),
            (0x28, (queue_index << 40) | item_index),
            (0x150, 0x0002780390000003 + descriptor_index * 0x4E),
            (0x178, 0x003FFFFFFFFFFFFF),
            (0x180, 0x0000000000000001),
        )
    else:
        values = (
            (0x00, 0x1000000000000000
             | (queue_index << 42) | (4 * (item_index + 1))),
            (0x10, descriptor_address),
            (0x18, queue_address),
            (0x20, 0xFFFF180000000003 | (context_id << 32)),
            (0x28, ((queue_index - 1) << 40) | (item_index + 1)),
            (0x30, (queue_index << 40) | item_index),
            (0x150, 0x0002B80390004C05 + descriptor_index * 0x112),
            (0x158, 0x0000880390004C3E + descriptor_index * 0x112),
            (0x160, 0x0000C00390004C77 + descriptor_index * 0x112),
            (0x168, 0x0000600390004CB0 + descriptor_index * 0x112),
            (0x178, 0x003FFFFFFFFFFFFF),
            (0x180, 0x0000000000000005),
        )
    for offset, value in values:
        struct.pack_into("<Q", item, offset, value)
    return bytes(item)


def build_tiling_firmware_scratch_page(
        descriptor_address=0xFFFFFC20C0018000, queue_index=0,
        queue_address=None, context_id=None):
    """Build the sparse first-clear tiling scratch/control page."""
    page = bytearray(PAGE_SIZE)
    item = build_render_queue_context_item(
        "tiling", descriptor_address, queue_index=queue_index,
        queue_address=queue_address, context_id=context_id,
    )
    page[RENDER_QUEUE_CONTEXT_ITEM_BASE:
         RENDER_QUEUE_CONTEXT_ITEM_BASE + len(item)] = item
    return bytes(page)


def build_fragment_firmware_scratch_page(
        descriptor_address=0xFFFFFC20C00B0000, queue_index=1,
        queue_address=None, context_id=None):
    """Build the sparse first-clear fragment scratch/control page."""
    page = bytearray(PAGE_SIZE)
    item = build_render_queue_context_item(
        "fragment", descriptor_address, queue_index=queue_index,
        queue_address=queue_address, context_id=context_id,
    )
    page[RENDER_QUEUE_CONTEXT_ITEM_BASE:
         RENDER_QUEUE_CONTEXT_ITEM_BASE + len(item)] = item
    return bytes(page)


def build_clear_pipeline_page(
        pipeline_base=CLEAR_PIPELINE_CANONICAL_BASE,
        mixed_compute_publication_count=2):
    """Build the position-independent caller-owned clear program page."""
    pipeline_base = int(pipeline_base)
    _validate_u64(pipeline_base, "clear pipeline base")
    if pipeline_base & (PAGE_SIZE - 1):
        raise ValueError("G17G clear pipeline base must be page aligned")
    page = bytearray(PAGE_SIZE)
    page[:len(CLEAR_PIPELINE_PROGRAM_PREFIX)] = CLEAR_PIPELINE_PROGRAM_PREFIX
    # Four independent earliest-work captures agree on these eight bytes.
    # Leaving the older values in place retires the TA/3D queues but suppresses
    # the target store.  They are part of the compiled clear pipeline, not
    # placement or per-submit state.
    for offset, value in {
        0x014: 0x04,
        0x214: 0x04,
        0x414: 0x08,
        0x47E: 0x07,
        0x47F: 0x24,
        0x594: 0x08,
        0x5FE: 0x07,
        0x5FF: 0x24,
    }.items():
        page[offset] = value
    if pipeline_base == CLEAR_PIPELINE_DIFFERENTIAL_BASE:
        for offset, value in {
            0x006: 0x8C, 0x016: 0x28, 0x087: 0x01, 0x08C: 0x09,
            0x206: 0x8C, 0x216: 0x28, 0x287: 0x01, 0x28C: 0x09,
            0x406: 0x8C, 0x416: 0x28,
            0x586: 0x8C, 0x596: 0x28,
        }.items():
            page[offset] = value
    elif pipeline_base == CLEAR_PIPELINE_MIXED_BASE:
        # The coherent render allocation selects a distinct compiler variant.
        # Page minimization left only these 22 bytes different from the
        # position-independent clear image; spell them out as compiler fields
        # instead of retaining a second whole-page product.  The final eight
        # values were measured at the earliest coherent render+compute
        # boundary; the older clear-only values retire the queues but suppress
        # the mixed target store.
        values = {
            0x006: 0x94, 0x011: 0xA0, 0x014: 0x0A, 0x016: 0x0C,
            0x087: 0x01, 0x08C: 0x0A,
            0x206: 0x94, 0x211: 0xA0, 0x214: 0x0A, 0x216: 0x0C,
            0x287: 0x01, 0x28C: 0x0A,
            0x406: 0x94, 0x411: 0xA0, 0x414: 0x0E, 0x416: 0x0C,
            0x47E: 0x47, 0x47F: 0x27,
            0x586: 0x94, 0x591: 0xA0, 0x594: 0x0E, 0x596: 0x0C,
            0x5FE: 0x47, 0x5FF: 0x27,
        }
        mixed_compute_publication_count = int(
            mixed_compute_publication_count
        )
        if mixed_compute_publication_count == 1:
            values.update({
                0x014: 0x06, 0x214: 0x06,
                0x414: 0x0A, 0x47E: 0xC7, 0x47F: 0x24,
                0x594: 0x0A, 0x5FE: 0xC7, 0x5FF: 0x24,
            })
        elif mixed_compute_publication_count != 2:
            raise ValueError(
                "G17G mixed pipeline variant requires one or two publications"
            )
        for offset, value in values.items():
            page[offset] = value
    return bytes(page)


def build_clear_compiler_support_pages():
    """Build the sparse caller compiler-support candidate for a clear.

    Compute range minimization established this two-record shape at the same
    DVA.  The first record is byte-identical in the native clear capture; the
    second is the clear capture's bounded caller-owned program record.  Render
    execution, rather than page equality, must establish whether the omitted
    compiler-cache contents are unnecessary.
    """
    first = bytearray(PAGE_SIZE)
    first[
        CLEAR_COMPILER_PIPELINE_RECORD_OFFSET:
        CLEAR_COMPILER_PIPELINE_RECORD_OFFSET
        + len(CLEAR_COMPILER_PIPELINE_RECORD)
    ] = CLEAR_COMPILER_PIPELINE_RECORD
    first[
        CLEAR_COMPILER_AUX_RECORD_OFFSET:
        CLEAR_COMPILER_AUX_RECORD_OFFSET + len(CLEAR_COMPILER_AUX_RECORD)
    ] = CLEAR_COMPILER_AUX_RECORD
    return {
        CLEAR_COMPILER_SUPPORT_DVA + index * PAGE_SIZE:
            bytes(first) if index == 0 else bytes(PAGE_SIZE)
        for index in range(CLEAR_COMPILER_SUPPORT_PAGE_COUNT)
    }


_TILING_REGISTERS = (
    (0x01748, 0x0000000000000001),
    (0x10141, 0x0000000000000200),
    (0x1C039, 0x0000000000260000),
    (0x1C9C8, 0x0000000000260000),
    (0x1C0A1, 0x0000000000288000),
    (0x1C031, 0x8000000000261000),
    (0x1C9C0, 0x8000000000261000),
    (0x1C051, 0x003A0012006B0003),
    (0x1C061, 0x0000000000000001),
    (0x10149, 0x000000000000A000),
    (0x10139, 0x0000000000000088),
    (0x10111, 0x0000000000068340),
    (0x1C9B0, 0x0000000000068340),
    (0x10119, 0x0000000000068040),
    (0x1C9B8, 0x0000000000068040),
    (0x1C958, 0x0000000000000001),
    (0x1C950, 0x0004000000068000),
    (0x1C930, 0x0000000000000000),
    (0x1C880, 0x0000000000018000),
    (0x1C079, 0x0000000000261000),
    (0x1C9D8, 0x0000000000261000),
    (0x10151, 0x0000000000000000),
    (0x1C199, 0x0000000000000000),
    (0x1C1A1, 0x0000000000000000),
    (0x1C1A9, 0x0000000000000000),
    (0x1C1B1, 0x0000000000000000),
    (0x1C1B9, 0x0000000000000000),
    (0x0D499, 0x000000000000054B),
    (0x0D419, 0x0000000200000001),
    (0x0A5A1, 0x000000A300400020),
    (0x1C8F8, 0x0000000010C08860),
    (0x1C0B1, 0x0000000000000014),
    (0x1C850, 0x0000000000000014),
    (0x10131, 0x0000000000000088),
    (0x10121, 0x0000000000000202),
    (0x10129, 0x00000000003F003F),
    (0x101B9, 0x0000000000001001),
    (0x1C069, 0x000000000040200C),
    (0x1C071, 0x000000000040200C),
    (0x1C081, 0x0000000000000010),
    (0x1C0A9, 0x0000000000000020),
    (0x1CA50, 0x0000000000001001),
    (0x1CA58, 0x000000000000A000),
    (0x1CA60, 0x0000000000000200),
    (0x1CA70, 0x000000000040200C),
    (0x1CA78, 0x000000000040200C),
    (0x1CA68, 0x0000000000000010),
    (0x10171, 0x0000000000000100),
    (0x10169, 0x0000000000008000),
    (0x1C8E0, 0xFFFFFFFFFFFFFFFF),
    (0x1C8E8, 0xFFFFFFFFFFFFFFFF),
    (0x1C898, 0x0000000000000700),
    (0x101E1, 0x000000000000001C),
    (0x1C9E8, 0x0000000000000000),
    (0x1A099, 0x0000000000000000),
    (0x1A0A1, 0x0000000000000000),
    (0x1A069, 0x0000000000000000),
    (0x1A071, 0x0000000000000000),
    (0x1A0C9, 0x0000000000000000),
    (0x1A0D1, 0x0000000000000000),
    (0x101C9, 0x0000000000000000),
    (0x0D471, 0x0000000000000000),
    (0x1A0F1, 0x0000000000000008),
    (0x1A149, 0x0000000000000000),
    (0x10799, 0x0000000000FF0000),
    (0x1C830, 0x0000000000000000),
    (0x1CA30, 0x0000000000220040),
    (0x16C39, 0x0000000000220040),
    (0x1C910, 0x0000000000080041),
    (0x1CA10, None),
    (0x014A1, None),
    (0x0A349, None),
    (0x0A739, 0x0000000000000000),
)

_TILING_SECOND_DESCRIPTOR_OVERRIDES = {
    0x1C039: 0x0000000000261200,
    0x1C9C8: 0x0000000000261200,
    0x1C031: 0x8000000000262200,
    0x1C9C0: 0x8000000000262200,
    0x1C079: 0x0000000000262200,
    0x1C9D8: 0x0000000000262200,
    0x1CA30: 0x0000000000220080,
    0x16C39: 0x0000000000220080,
    0x1C910: 0x0000000000080081,
}

# The earliest native 128x128 overflow workload changes only these numeric
# members of the otherwise identical 73-write TA program.  Keep the partial
# mode separate from descriptor-generation overrides: it is a render-shape
# choice, not a queue ordinal.
_TILING_PARTIAL_OVERRIDES = {
    0x0D499: 0x000000000004054B,
    0x0A5A1: 0x0000010600400020,
}

_FRAGMENT_PARTIAL_OVERRIDES = {
    0x0A5A9: 0x000000E300400020,
}


_FRAGMENT_REGISTERS = (
    (0x01739, 0x0000000000000001),
    (0x10009, 0x000000000000A000),
    (0x15379, "store_pipeline_bind"),
    (0x15381, "store_pipeline"),
    (0x153B1, "store_pipeline_bind"),
    (0x153B9, "store_pipeline"),
    (0x15369, "load_pipeline_bind"),
    (0x15371, "load_pipeline"),
    (0x15131, 0x000000003CDDB3D9),
    (0x15139, 0x000000003CDDB3D9),
    (0x100A1, 0x0000000000000000),
    (0x15069, 0x0000000000000000),
    (0x15071, 0x0000000000000000),
    (0x16058, 0x0000000000000000),
    (0x10019, 0x0000000000000088),
    (0x16469, 0x0000000000040004),
    (0x16030, 0x0000000000040004),
    (0x16471, 0x0000000000001001),
    (0x10791, 0x0000200000FF0200),
    (0x16098, 0x0000001000261000),
    (0x15021, "aux_fb_flags"),
    (0x15211, 0x0000004000000040),
    (0x15049, 0x0000000000100000),
    (0x10051, 0x0000000000000000),
    (0x0D491, 0x000000000104054B),
    (0x0D429, 0x0000000200000001),
    (0x0A5A9, 0x000000CE00400020),
    (0x15321, "depth_dimensions"),
    (0x15301, "depth_clear_value_bits"),
    (0x15309, "stencil_clear_value"),
    (0x15311, "occlusion_query_base"),
    (0x15319, "depth_flags"),
    (0x15349, 0x0000000004040404),
    (0x15351, 0x0000000000000000),
    (0x15329, "depth_buffer"),
    (0x15331, "depth_buffer"),
    (0x15339, "stencil_buffer"),
    (0x15341, "stencil_buffer"),
    (0x15231, 0x0000000000000000),
    (0x15221, 0x0000000000000000),
    (0x15239, 0x0000000000000000),
    (0x15229, 0x0000000000000000),
    (0x15401, "depth_stride"),
    (0x15421, "depth_stride"),
    (0x15409, "stencil_stride"),
    (0x15429, "stencil_stride"),
    (0x153C1, "depth_aux_buffer"),
    (0x15411, "depth_aux_stride"),
    (0x153C9, "depth_aux_buffer"),
    (0x15431, "depth_aux_stride"),
    (0x153D1, "stencil_aux_buffer"),
    (0x15419, "stencil_aux_stride"),
    (0x153D9, "stencil_aux_buffer"),
    (0x15439, "stencil_aux_stride"),
    (0x16429, 0x0000001000260000),
    (0x16060, 0x0000001000261000),
    (0x16431, 0x0000000050000000),
    (0x10039, "tile_config"),
    (0x16020, 0x0000000000000000),
    (0x16451, 0x0000000000000000),
    (0x15359, 0x0000000000000000),
    (0x16138, 0x0000000000008860),
    (0x16461, "auxiliary_object"),
    (0x16090, "auxiliary_object"),
    (0x101E9, 0x000000000000001C),
    (0x16068, 0x001006A00003717F),
    (0x1A0A9, 0x0000000000000000),
    (0x1A0B1, 0x0000000000000000),
    (0x1A079, 0x0000000000000000),
    (0x1A081, 0x0000000000000000),
    (0x1A0D9, 0x0000000000000000),
    (0x1A0E1, 0x0000000000000000),
    (0x101C1, 0x0000000000000000),
    (0x0D469, 0x0000000000000000),
    (0x1A0F9, 0x0000000000000008),
    (0x1A151, 0x0000000000000000),
    (0x160E0, "fragment_lifecycle"),
    (0x01499, "fragment_lifecycle"),
    (0x0A341, "fragment_lifecycle"),
    (0x1C838, 0x0000000000000000),
    (0x1CA28, 0x0000000000220040),
    (0x0A741, 0x0000000000000000),
    (0x10211, 0x0000000000000100),
    (0x10420, 0x0000000000000100),
    (0x14048, 0x0000000000000000),
    (0x14080, 0x0000001000258001),
    (0x01731, 0x0000000000000001),
    (0x0A741, 0x0000000000000000),
    (0x16020, 0x0000000000000001),
)

_FRAGMENT_SECOND_DESCRIPTOR_OVERRIDES = {
    0x16098: 0x0000001000262200,
    0x16429: 0x0000001000261200,
    0x16060: 0x0000001000262200,
    0x1CA28: 0x0000000000220080,
    0x10211: 0x0000000000000101,
    0x10420: 0x0000000000000101,
    0x14080: 0x0000001000258041,
}


def _validate_descriptor_index(descriptor_index):
    descriptor_index = int(descriptor_index)
    if not 0 <= descriptor_index < RENDER_SUBMISSION_COUNTER_COUNT:
        raise ValueError(
            "G17G render descriptor index is outside the source-built arena"
        )
    return descriptor_index


def _validate_tiling_descriptor_index(descriptor_index):
    descriptor_index = int(descriptor_index)
    if not 0 <= descriptor_index < RENDER_TILING_DESCRIPTOR_COUNT:
        raise ValueError("G17G tiling descriptor index is outside its arena")
    return descriptor_index


def _validate_fragment_descriptor_index(descriptor_index):
    descriptor_index = int(descriptor_index)
    if not 0 <= descriptor_index < RENDER_FRAGMENT_DESCRIPTOR_COUNT:
        raise ValueError("G17G fragment descriptor index is outside its arena")
    return descriptor_index


def _tiling_descriptor_overrides(descriptor_index):
    """Derive the fixed-stride per-descriptor TA register fields."""
    descriptor_index = _validate_descriptor_index(descriptor_index)
    return {
        0x1C039: 0x0000000000260000 + descriptor_index * 0x1200,
        0x1C9C8: 0x0000000000260000 + descriptor_index * 0x1200,
        0x1C031: 0x8000000000261000 + descriptor_index * 0x1200,
        0x1C9C0: 0x8000000000261000 + descriptor_index * 0x1200,
        0x1C079: 0x0000000000261000 + descriptor_index * 0x1200,
        0x1C9D8: 0x0000000000261000 + descriptor_index * 0x1200,
        0x1CA30: 0x0000000000220040 + descriptor_index * 0x40,
        0x16C39: 0x0000000000220040 + descriptor_index * 0x40,
        0x1C910: 0x0000000000080041 + descriptor_index * 0x40,
    }


def _fragment_descriptor_overrides(
        descriptor_index, work_index=None, status_index=None):
    """Derive physical-pool and logical-item fragment register fields."""
    descriptor_index = _validate_descriptor_index(descriptor_index)
    if work_index is None:
        work_index = descriptor_index
    if status_index is None:
        status_index = work_index
    work_index = int(work_index)
    status_index = int(status_index)
    if not 0 <= work_index < (1 << 32) - 0x100:
        raise ValueError("G17G fragment work index is out of range")
    if not 0 <= status_index < (1 << 16):
        raise ValueError("G17G fragment status index is out of range")
    return {
        0x16098: 0x0000001000261000 + descriptor_index * 0x1200,
        0x16429: 0x0000001000260000 + descriptor_index * 0x1200,
        0x16060: 0x0000001000261000 + descriptor_index * 0x1200,
        0x1CA28: 0x0000000000220040 + descriptor_index * 0x40,
        0x10211: 0x0000000000000100 + work_index,
        0x10420: 0x0000000000000100 + work_index,
        0x14080: 0x0000001000258001 + status_index * 0x40,
    }


def _apply_register_overrides(registers, overrides):
    return tuple(
        (number, overrides.get(number, value)) for number, value in registers
    )


def build_tiling_registers(params, descriptor_index=0):
    """Return the exact ordered 73-write numeric tiling program."""
    params.validate()
    descriptor_index = _validate_descriptor_index(descriptor_index)
    result = tuple(
        (number, params.tiling_lifecycle if value is None else value)
        for number, value in _TILING_REGISTERS
    )
    geometry = _render_geometry(params)
    result = _apply_register_overrides(result, {
        0x10149: params.resolved_utile_config(),
        0x10139: params.multisample_control,
        0x10131: params.multisample_control,
        0x10121: params.ppp_control,
        0x10169: (
            0xE000 | (params.layers - 1)
            if params.layers > 1 else 0x8000
        ),
        0x1C0B1: geometry["size1"],
        0x1C850: geometry["size1"],
        0x10129: geometry["pixels"],
        0x101B9: geometry["screen"],
        0x1C069: geometry["x_blocks"],
        0x1C071: geometry["y_blocks"],
        0x1C081: geometry["size2"],
        0x1C0A9: geometry["size3"],
        0x1CA50: geometry["screen"],
        0x1CA58: params.resolved_utile_config(),
        0x1CA70: geometry["x_blocks"],
        0x1CA78: geometry["y_blocks"],
        0x1CA68: geometry["size2"],
        0x1C880: params.resolved_vdm_ctrl_stream_offset(),
    })
    if params.partial_mode:
        result = _apply_register_overrides(result, _TILING_PARTIAL_OVERRIDES)
    if descriptor_index:
        result = _apply_register_overrides(
            result, _tiling_descriptor_overrides(descriptor_index)
        )
    if len(result) != TILING_REGISTER_COUNT:
        raise AssertionError("G17G tiling register recipe length changed")
    return result


def build_fragment_registers(
        params, descriptor_index=0, submission_index=None,
        work_index=None, status_index=None):
    """Return the exact ordered 89-write numeric fragment program."""
    params.validate()
    descriptor_index = _validate_descriptor_index(descriptor_index)
    if submission_index is None:
        submission_index = descriptor_index
    if work_index is None:
        work_index = submission_index
    if status_index is None:
        status_index = submission_index
    values = {
        "store_pipeline": params.store_pipeline,
        "store_pipeline_bind": params.store_pipeline_bind,
        "load_pipeline": params.load_pipeline,
        "load_pipeline_bind": params.load_pipeline_bind,
        "aux_fb_flags": params.resolved_aux_fb_flags(),
        "auxiliary_object": params.auxiliary_object,
        "fragment_lifecycle": params.tiling_lifecycle - 1,
        "depth_buffer": params.depth_buffer,
        "stencil_buffer": params.stencil_buffer,
        "depth_aux_buffer": params.depth_aux_buffer,
        "stencil_aux_buffer": params.stencil_aux_buffer,
        "depth_stride": params.depth_stride,
        "stencil_stride": params.stencil_stride,
        "depth_aux_stride": params.depth_aux_stride,
        "stencil_aux_stride": params.stencil_aux_stride,
        "depth_clear_value_bits": params.depth_clear_value_bits,
        "stencil_clear_value": params.stencil_clear_value | 0x300,
        "depth_flags": params.depth_flags,
        "depth_dimensions": params.depth_dimensions,
        "occlusion_query_base": params.occlusion_query_base,
        "tile_config": params.resolved_tile_config(),
    }
    result = tuple(
        (number, values[value] if isinstance(value, str) else value)
        for number, value in _FRAGMENT_REGISTERS
    )
    geometry = _render_geometry(params)
    result = _apply_register_overrides(result, {
        0x10009: params.resolved_utile_config(),
        0x10019: params.multisample_control,
        0x10051: params.resolved_tib_blocks(),
        0x15131: params.resolved_merge_upper_x_bits(),
        0x15139: params.resolved_merge_upper_y_bits(),
        0x16469: geometry["macro_size"],
        0x16030: geometry["macro_size"],
        0x16471: geometry["screen"],
        0x15211: (params.height << 32) | params.width,
        0x16431: (4 * geometry["size1"]) << 24,
        0x16068: geometry["tile_state"],
    })
    if params.partial_mode:
        result = _apply_register_overrides(
            result, _FRAGMENT_PARTIAL_OVERRIDES
        )
    result = _apply_register_overrides(
        result,
        _fragment_descriptor_overrides(
            descriptor_index, work_index, status_index
        ),
    )
    if len(result) != FRAGMENT_REGISTER_COUNT:
        raise AssertionError("G17G fragment register recipe length changed")
    return result


def build_register_array(registers):
    """Serialize ordered G17G register writes as one 12-byte-entry array."""
    output = bytearray()
    for number, value in registers:
        if not 0 <= number < (1 << 32):
            raise ValueError("G17G register number does not fit in u32")
        _validate_u64(value, "G17G register value")
        output += struct.pack("<IQ", number, value)
    return bytes(output)


def build_optional_item(
    kind,
    context_scratch,
    firmware_scratch,
    shared_control,
    channel_control,
    token,
    tiling_shared_object=None,
    submission_ordinal=1,
    queue_index=None,
    queue_context_index=None,
    first_record=None,
    context_id=0,
    secondary_context_id=None,
    lifecycle_ordinal=None,
    tiling_pair_index=None,
):
    """Build the complete selector-15 record paired with one render stage."""
    if kind not in ("tiling", "fragment"):
        raise ValueError("G17G render optional kind must be tiling or fragment")
    if kind == "tiling" and tiling_shared_object is None:
        raise ValueError("G17G tiling optional item needs its shared object")
    if kind == "fragment" and tiling_shared_object is not None:
        raise ValueError("G17G fragment optional item has no tiling shared object")
    for name, value in (
        ("context_scratch", context_scratch),
        ("firmware_scratch", firmware_scratch),
        ("shared_control", shared_control),
        ("channel_control", channel_control),
        ("tiling_shared_object", tiling_shared_object or 0),
    ):
        _validate_u64(value, name)
    if not 0 <= token < (1 << 16):
        raise ValueError("G17G render optional token does not fit in u16")
    if not 1 <= submission_ordinal < (1 << 16):
        raise ValueError(
            "G17G render optional ordinal must fit in positive u16"
        )
    context_id = int(context_id)
    if not 0 <= context_id < (1 << 16):
        raise ValueError("G17G render optional context id must fit in uint16")
    if secondary_context_id is None:
        secondary_context_id = context_id
    secondary_context_id = int(secondary_context_id)
    if not 0 <= secondary_context_id < (1 << 16):
        raise ValueError(
            "G17G render optional secondary context id must fit in uint16"
        )
    if first_record is None:
        first_record = submission_ordinal == 1
    first_record = bool(first_record)
    if lifecycle_ordinal is None:
        lifecycle_ordinal = submission_ordinal - 1
    lifecycle_ordinal = int(lifecycle_ordinal)
    if not 0 <= lifecycle_ordinal < (1 << 16):
        raise ValueError(
            "G17G render optional lifecycle ordinal must fit in uint16"
        )
    if queue_index is None:
        queue_index = 0 if kind == "tiling" else 1
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("G17G render optional queue index must fit in uint8")
    if kind == "fragment" and queue_index == 0:
        raise ValueError("G17G fragment optional queue index must be positive")
    if kind == "tiling":
        if tiling_pair_index is None:
            tiling_pair_index = queue_index // 2
        tiling_pair_index = int(tiling_pair_index)
        if not 0 <= tiling_pair_index < (1 << 16):
            raise ValueError("G17G tiling pair index must fit in uint16")
    else:
        if tiling_pair_index not in (None, 0):
            raise ValueError(
                "G17G fragment optional item has no tiling pair index"
            )
        tiling_pair_index = 0
    if queue_context_index is None:
        queue_context_index = (submission_ordinal - 1) & 0xFF
    queue_context_index = int(queue_context_index)
    if not 0 <= queue_context_index < (1 << 16):
        raise ValueError(
            "G17G render optional queue-context index must fit in uint16"
        )
    output = bytearray(OPTIONAL_ITEM_SIZE)
    struct.pack_into("<I", output, 0, 15)
    struct.pack_into("<Q", output, 0x08, context_scratch)
    struct.pack_into("<Q", output, 0x10, firmware_scratch)
    struct.pack_into("<Q", output, 0x36, shared_control)
    struct.pack_into("<Q", output, 0x4A, channel_control)
    if kind == "tiling":
        struct.pack_into("<Q", output, 0x6E, tiling_shared_object)
    else:
        output[0x76:0x86] = b"\xFF" * 0x10

    common_u16 = {
        0x1A: 1,
        0x1E: 2,
        0x26: 1,
        0x32: 1,
        0x3E: submission_ordinal,
        0x52: 1,
        0x5A: token,
        0x5E: 2,
        0x62: 1,
        0x66: 1,
    }
    stage_u16 = {
        "tiling": {
            0x18: queue_index,
            0x7E: tiling_pair_index,
            0x82: queue_index + 1,
        },
        "fragment": {0x18: queue_index, 0x22: 1},
    }
    for offset, value in {**common_u16, **stage_u16[kind]}.items():
        struct.pack_into("<H", output, offset, value)
    struct.pack_into("<H", output, 0x46, context_id)
    struct.pack_into("<H", output, 0x56, secondary_context_id)
    if not first_record:
        # The earliest native groups retain the shared-control pointer and
        # carry affine generation indices at +0x2a/+0x2e (and, for tiling,
        # +0x76). Four first-work flags change state, but there is no
        # beta-4-style all-ones sentinel.
        struct.pack_into("<H", output, 0x1A, 0)
        struct.pack_into("<H", output, 0x2A, queue_context_index)
        struct.pack_into(
            "<H", output, 0x2E, (queue_context_index & 0xFF) << 8
        )
        struct.pack_into("<H", output, 0x52, 0)
        struct.pack_into("<H", output, 0x62, 0)
    if kind == "tiling":
        struct.pack_into("<H", output, 0x76, lifecycle_ordinal)
    return bytes(output)


def build_event_item(kind, group_number=1, generation=2, queue_index=None):
    """Build the complete selector-14 record paired with one render stage."""
    if kind not in ("tiling", "fragment"):
        raise ValueError("G17G render event kind must be tiling or fragment")
    if not 0 <= group_number < (1 << 24):
        raise ValueError("G17G render event group does not fit in 24 bits")
    if not 0 <= generation < (1 << 8):
        raise ValueError("G17G render event generation does not fit in uint8")
    stage = 0 if kind == "tiling" else 1
    if queue_index is None:
        queue_index = stage
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("G17G render event queue index must fit in uint8")
    if kind == "fragment" and queue_index == 0:
        raise ValueError("G17G fragment event queue index must be positive")
    output = bytearray(EVENT_ITEM_SIZE)
    struct.pack_into("<I", output, 0x00, 14)
    struct.pack_into("<I", output, 0x04, 0x10000 | queue_index)
    struct.pack_into("<I", output, 0x08, (group_number << 8) | generation)
    struct.pack_into("<I", output, 0x10, stage << 8)
    return bytes(output)


def _write_registers(output, offset, registers):
    body = build_register_array(registers)
    output[offset:offset + len(body)] = body


def _resolve_registers(
        template, params, descriptor_index=0, submission_index=None):
    values = {
        "store_pipeline": params.store_pipeline,
        "load_pipeline_base": params.load_pipeline & ~(PAGE_SIZE - 1),
        "partial_store_pipeline_bind": params.partial_store_pipeline_bind,
        "partial_store_pipeline": params.resolved_partial_store_pipeline(),
        "partial_load_pipeline_bind": params.partial_load_pipeline_bind,
        "partial_load_pipeline": params.resolved_partial_load_pipeline(),
        "partial_store_tile_config": (
            params.resolved_tile_config() | 0x200000
        ),
        "partial_resume_tile_config": (
            params.resolved_tile_config() & 0xFFFF
        ) | 0x200000,
        "depth_buffer": params.depth_buffer,
        "stencil_buffer": params.stencil_buffer,
        "depth_aux_buffer": params.depth_aux_buffer,
        "stencil_aux_buffer": params.stencil_aux_buffer,
        "depth_stride": params.depth_stride,
        "stencil_stride": params.stencil_stride,
        "depth_aux_stride": params.depth_aux_stride,
        "stencil_aux_stride": params.stencil_aux_stride,
        "depth_flags": params.depth_flags,
        "stencil_clear_value": params.stencil_clear_value | 0x300,
    }
    result = tuple(
        (number, values[value] if isinstance(value, str) else value)
        for number, value in template
    )
    if submission_index is None:
        submission_index = descriptor_index
    if descriptor_index or submission_index:
        result = _apply_register_overrides(
            result,
            _fragment_descriptor_overrides(
                descriptor_index, submission_index
            ),
        )
    return result


_TILING_SECONDARY_REGISTERS = (
    (0x10209, 0x0000000000000100),
    (0x1C9F0, 0x0000000000000100),
    (0x14320, 0x0000000000000100),
    (0x14308, 0x0000000000000000),
    (0x14318, 0x0000001000078001),
    (0x01740, 0x0000000000000001),
    (0x0A739, 0x0000000000000000),
    (0x1C880, 0x0000000000068340),
    (0x1C898, 0x0000000000000701),
)

_TILING_SECONDARY_SECOND_DESCRIPTOR_OVERRIDES = {
    0x10209: 0x0000000000000101,
    0x1C9F0: 0x0000000000000101,
    0x14320: 0x0000000000000101,
    0x14318: 0x0000001000078041,
}

_FRAGMENT_BLOCK_0_REGISTERS = (
    (0x15379, "partial_store_pipeline_bind"),
    (0x15381, "partial_store_pipeline"),
    (0x153B1, "partial_store_pipeline_bind"),
    (0x153B9, "partial_store_pipeline"),
    (0x10039, "partial_store_tile_config"),
    (0x15331, "depth_buffer"),
    (0x153C9, "depth_aux_buffer"),
    (0x15341, "stencil_buffer"),
    (0x153D9, "stencil_aux_buffer"),
    (0x15421, "depth_stride"),
    (0x15431, "depth_aux_stride"),
    (0x15429, "stencil_stride"),
    (0x15439, "stencil_aux_stride"),
    (0x15221, 0),
    (0x15229, 0),
    (0x15319, "depth_flags"),
    (0x15349, 0x04040404),
)

_FRAGMENT_BLOCK_1_REGISTERS = (
    (0x15379, "partial_store_pipeline_bind"),
    (0x15381, "partial_store_pipeline"),
    (0x153B1, "partial_store_pipeline_bind"),
    (0x153B9, "partial_store_pipeline"),
    (0x15369, "partial_load_pipeline_bind"),
    (0x15371, "partial_load_pipeline"),
    (0x10039, "partial_resume_tile_config"),
    (0x15331, "depth_buffer"),
    (0x153C9, "depth_aux_buffer"),
    (0x15341, "stencil_buffer"),
    (0x153D9, "stencil_aux_buffer"),
    (0x15421, "depth_stride"),
    (0x15431, "depth_aux_stride"),
    (0x15429, "stencil_stride"),
    (0x15439, "stencil_aux_stride"),
    (0x15221, 0),
    (0x15229, 0),
    (0x15309, "stencil_clear_value"),
    (0x15329, "depth_buffer"),
    (0x153C1, "depth_aux_buffer"),
    (0x15339, "stencil_buffer"),
    (0x153D1, "stencil_aux_buffer"),
    (0x15319, "depth_flags"),
    (0x15349, 0x04040404),
)

_FRAGMENT_BLOCK_2_REGISTERS = (
    (0x15369, "partial_load_pipeline_bind"),
    (0x15371, "partial_load_pipeline"),
    (0x10039, "partial_resume_tile_config"),
    (0x15309, "stencil_clear_value"),
    (0x153B1, "partial_store_pipeline_bind"),
    (0x153B9, "partial_store_pipeline"),
    (0x15329, "depth_buffer"),
    (0x153C1, "depth_aux_buffer"),
    (0x15339, "stencil_buffer"),
    (0x153D1, "stencil_aux_buffer"),
    (0x15319, "depth_flags"),
    (0x15349, 0x04040404),
)


def build_tiling_descriptor(
        params, sequence=1, descriptor_index=0, submission_index=None,
        submission_ordinal=None,
        parameter_index=None, pool_a_index=None, pool_b_index=None,
        pool_a_address=None, pool_b_address=None,
        queue_index=0, status_base=TILING_STATUS, status_index=None,
        register_status_base=None, register_status_index=None,
        work_stamp_index=None,
        descriptor_objects=DESCRIPTOR_OBJECTS, register_pair_index=0,
        register_resource_index=None, shared_control=SHARED_CONTROL,
        work_index=None,
        resource_address_offset=0, context_id=0):
    """Build the complete source-described selector-0 clear descriptor."""
    params.validate()
    _validate_u64(sequence, "G17G tiling descriptor sequence")
    _validate_u64(shared_control, "G17G tiling shared control")
    resource_address_offset = int(resource_address_offset)
    context_id = int(context_id)
    if resource_address_offset < 0:
        raise ValueError("G17G tiling resource offset is negative")
    if not 0 <= context_id < (1 << 32):
        raise ValueError("G17G tiling context id must fit in uint32")
    descriptor_index = _validate_tiling_descriptor_index(descriptor_index)
    if submission_index is None:
        submission_index = descriptor_index
    submission_index = int(submission_index)
    if not 0 <= submission_index < 0x100:
        raise ValueError("G17G tiling submission index is out of range")
    if submission_ordinal is None:
        submission_ordinal = submission_index + 1
    submission_ordinal = int(submission_ordinal)
    if not 1 <= submission_ordinal < (1 << 16):
        raise ValueError("G17G tiling submission ordinal is out of range")
    if work_index is None:
        work_index = render_descriptor_work_index(submission_ordinal)
    work_index = int(work_index)
    if not 0 <= work_index < (1 << 64):
        raise ValueError("G17G tiling work index does not fit in u64")
    if work_stamp_index is None:
        work_stamp_index = work_index & 0x3F
    work_stamp_index = int(work_stamp_index)
    if not 0 <= work_stamp_index < (1 << 32) - 0x100:
        raise ValueError("G17G tiling work-stamp index is out of range")
    if parameter_index is None:
        parameter_index = descriptor_index
    parameter_index = int(parameter_index)
    if not 0 <= parameter_index < RENDER_PARAMETER_SLOT_COUNT:
        raise ValueError("G17G tiling parameter index is out of range")
    if pool_a_index is None:
        pool_a_index = descriptor_index
    if pool_b_index is None:
        pool_b_index = descriptor_index
    pool_a_index = _validate_render_pool_index(
        "pool_a", pool_a_index, RENDER_POOL_A_RING_SLOT_COUNT
    )
    pool_b_index = _validate_render_pool_index(
        "pool_b", pool_b_index, RENDER_POOL_B_RING_SLOT_COUNT
    )
    if pool_a_address is None:
        pool_a_address = descriptor_objects[0] + pool_a_index * 0x100
    if pool_b_address is None:
        pool_b_address = descriptor_objects[2] + pool_b_index * 0x80
    pool_a_address = int(pool_a_address)
    pool_b_address = int(pool_b_address)
    _validate_u64(pool_a_address, "G17G tiling pool-A record")
    _validate_u64(pool_b_address, "G17G tiling pool-B record")
    queue_index = int(queue_index)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("G17G tiling queue index is invalid")
    register_pair_index = int(register_pair_index)
    if not 0 <= register_pair_index < (1 << 8):
        raise ValueError("G17G tiling register pair index is out of range")
    if register_resource_index is None:
        register_resource_index = parameter_index
    register_resource_index = int(register_resource_index)
    if not 0 <= register_resource_index < RENDER_SUBMISSION_COUNTER_COUNT:
        raise ValueError("G17G tiling register resource index is out of range")
    descriptor_objects = tuple(int(address) for address in descriptor_objects)
    if len(descriptor_objects) != 4:
        raise ValueError("G17G descriptor object family must have four members")
    for address in descriptor_objects:
        _validate_u64(address, "G17G tiling descriptor object")
    status_base = int(status_base)
    _validate_u64(status_base, "G17G tiling status base")
    if status_index is None:
        status_index = submission_index
    status_index = int(status_index)
    if not 0 <= status_index < (1 << 16):
        raise ValueError("G17G tiling status index is out of range")
    status_address = status_base + status_index * 0x40
    register_status_override = (
        register_status_base is not None or register_status_index is not None
    )
    if register_status_base is None:
        register_status_base = TILING_REGISTER_STATUS
    register_status_base = int(register_status_base)
    _validate_u64(register_status_base, "G17G tiling register-status base")
    if register_status_index is None:
        register_status_index = submission_index
    register_status_index = int(register_status_index)
    if not 0 <= register_status_index < (1 << 16):
        raise ValueError("G17G tiling register-status index is out of range")
    register_status_address = (
        register_status_base + register_status_index * 0x40
    )
    descriptor_offset = descriptor_index * TILING_DESCRIPTOR_SIZE
    output = bytearray(TILING_DESCRIPTOR_SIZE)
    struct.pack_into("<IQI", output, 0, 0, sequence, 1)
    struct.pack_into(
        "<Q", output, 0x10, pool_a_address,
    )
    selected_objects = (
        descriptor_objects[1],
        pool_b_address,
        descriptor_objects[3],
    )
    struct.pack_into("<3Q", output, 0x20, *selected_objects)
    struct.pack_into("<Q", output, 0x38, 0x000000520052004F)
    # This is the retained pair/render-context work timeline.  It is distinct
    # from the finite status and queue-context index and does not restart when
    # either the queue transport or those storage indices wrap.
    struct.pack_into("<Q", output, 0x48, work_index)
    primary_registers = build_tiling_registers(params, parameter_index)
    if register_pair_index:
        cycle = (
            0x220040 + register_pair_index * 0x5E0000
            + register_resource_index * 0x40
        )
        record = (
            0x80041 + register_pair_index * 0x5E8000
            + register_resource_index * 0x40
        )
        primary_registers = _apply_register_overrides(
            primary_registers,
            {0x1CA30: cycle, 0x16C39: cycle, 0x1C910: record},
        )
    if register_status_override:
        primary_registers = _apply_register_overrides(
            primary_registers, {0x14318: register_status_address | 1}
        )
    if resource_address_offset:
        resource_registers = {
            0x1C039, 0x1C9C8, 0x1C0A1, 0x1C031, 0x1C9C0,
            0x1C079, 0x1C9D8, 0x1CA30, 0x16C39, 0x1C910,
        }
        primary_registers = tuple(
            (
                number,
                value + resource_address_offset
                if number in resource_registers else value,
            )
            for number, value in primary_registers
        )
    if params.buffers is not None:
        buffers = params.buffers
        tilemap = buffers.tilemap - VDM_RESOURCE_BASE
        metadata = buffers.metadata - VDM_RESOURCE_BASE
        primary_registers = _apply_register_overrides(primary_registers, {
            0x1C039: tilemap, 0x1C9C8: tilemap,
            0x1C031: (1 << 63) | metadata, 0x1C9C0: (1 << 63) | metadata,
            0x1C079: metadata, 0x1C9D8: metadata,
            0x1C0A1: buffers.tpc - VDM_RESOURCE_BASE,
        })
    _write_registers(output, 0x60, primary_registers)
    secondary_registers = _TILING_SECONDARY_REGISTERS
    overrides = {
        0x10209: 0x100 + work_stamp_index,
        0x1C9F0: 0x100 + work_stamp_index,
        0x14320: 0x100 + work_stamp_index,
        # This register names a context-local status array.  It is distinct
        # from the pair-local firmware status record in the descriptor tail.
        0x14318: (
            register_status_address | 1
            if register_status_override
            else TILING_REGISTER_STATUS + submission_index * 0x40 | 1
        ),
        0x14308: context_id,
    }
    secondary_registers = _apply_register_overrides(
        secondary_registers,
        overrides,
    )
    _write_registers(output, 0x3CC, secondary_registers)

    struct.pack_into(
        "<Q", output, 0x760,
        TILING_LOW_ALIAS + descriptor_offset + 0x60,
    )
    struct.pack_into("<I", output, 0x768, 0x52)
    struct.pack_into(
        "<Q", output, 0x780, 0x1000288000 + resource_address_offset
    )
    if params.buffers is not None:
        struct.pack_into("<2Q", output, 0x780,
                         params.buffers.tpc, params.buffers.tpc_size)
    else:
        output[0x789] = 8
    ordinal = submission_ordinal
    for offset, value in (
        (0x79C, queue_index + 1),
        (0x7A0, ordinal << 8),
        (0x7A8, ordinal),
        (0x7B0, (ordinal & 0xFF) * 0x101),
    ):
        struct.pack_into("<I", output, offset, value)
    struct.pack_into("<I", output, 0x7D6, 0x68340)
    output[0x85F] = 7
    struct.pack_into("<Q", output, 0x86E, params.tiling_lifecycle >> 32)
    struct.pack_into("<I", output, 0x876, 0xFFFFFFFF)
    struct.pack_into("<Q", output, 0x87A, params.sampler_array)
    struct.pack_into("<I", output, 0x882, params.sampler_count)
    struct.pack_into(
        "<I", output, 0x886,
        params.sampler_count + 1 if params.sampler_count else 0,
    )
    # A native stored/memoryless contrast isolates this byte. Changing only
    # 0 -> 1 on the working stored replay produces an in-job type-6 request;
    # fresh source-built type-8 growth then yields exact output (2026-09-09).
    output[0x892] = int(params.request_tvb_growth)
    struct.pack_into(
        "<Q", output, 0x8A6, DISPATCH_A + queue_index * 4
    )
    struct.pack_into(
        "<Q", output, 0x8AE, DISPATCH_B + queue_index * 4
    )
    struct.pack_into("<I", output, 0x8BA, queue_index)
    # These three fields are byte-sized generation counters.  Submission 256
    # carries logical index 255 and advances them through 0xff -> 0x00.
    output[0x8B7] = ordinal & 0xFF
    output[0x8C6] = ordinal & 0xFF
    output[0x8CB] = ordinal & 0xFF
    struct.pack_into(
        "<Q", output, 0x8CE, params.tiling_lifecycle & 0xFFFFFFFF
    )
    output[0x8D6] = submission_index
    struct.pack_into("<Q", output, 0x8FE, params.tiling_timestamp_start)
    struct.pack_into("<Q", output, 0x906, params.tiling_timestamp_end)
    struct.pack_into(
        "<Q", output, 0x90E, params.tiling_user_timestamp_start
    )
    struct.pack_into(
        "<Q", output, 0x916, params.tiling_user_timestamp_end
    )
    struct.pack_into("<Q", output, 0x934, shared_control)
    output[0x93C] = 1
    struct.pack_into(
        "<H", output, 0x93E,
        0x9080 if params.partial_mode else 0x5E80,
    )
    struct.pack_into(
        "<Q", output, 0x945,
        status_address,
    )
    output[0x94D] = 2
    output[0x954] = 4
    return bytes(output)


def build_fragment_descriptor(
        params, sequence=0, descriptor_index=0, submission_index=None,
        submission_ordinal=None,
        parameter_index=None, pool_a_index=None, pool_b_index=None,
        pool_a_address=None, pool_b_address=None,
        queue_index=1, status_base=FRAGMENT_STATUS, status_index=None,
        register_status_base=None, register_status_index=None,
        work_stamp_index=None,
        descriptor_objects=DESCRIPTOR_OBJECTS, register_pair_index=0,
        register_resource_index=None, shared_control=SHARED_CONTROL,
        resource_address_offset=0, context_id=0):
    """Build the complete source-described selector-1 clear descriptor."""
    params.validate()
    _validate_u64(sequence, "G17G fragment descriptor sequence")
    _validate_u64(shared_control, "G17G fragment shared control")
    resource_address_offset = int(resource_address_offset)
    context_id = int(context_id)
    if resource_address_offset < 0:
        raise ValueError("G17G fragment resource offset is negative")
    if not 0 <= context_id < (1 << 32):
        raise ValueError("G17G fragment context id must fit in uint32")
    descriptor_index = _validate_fragment_descriptor_index(descriptor_index)
    if submission_index is None:
        submission_index = descriptor_index
    submission_index = int(submission_index)
    if not 0 <= submission_index < (1 << 16):
        raise ValueError("G17G fragment submission index is out of range")
    if submission_ordinal is None:
        submission_ordinal = submission_index + 1
    submission_ordinal = int(submission_ordinal)
    if not 1 <= submission_ordinal < (1 << 16):
        raise ValueError("G17G fragment submission ordinal is out of range")
    logical_work_index = submission_ordinal - 1
    if work_stamp_index is None:
        work_stamp_index = render_descriptor_work_stamp(submission_ordinal)
    work_stamp_index = int(work_stamp_index)
    if not 0 <= work_stamp_index < (1 << 32) - 0x100:
        raise ValueError("G17G fragment work-stamp index is out of range")
    if parameter_index is None:
        parameter_index = descriptor_index
    parameter_index = int(parameter_index)
    if not 0 <= parameter_index < RENDER_PARAMETER_SLOT_COUNT:
        raise ValueError("G17G fragment parameter index is out of range")
    if pool_a_index is None:
        pool_a_index = descriptor_index
    if pool_b_index is None:
        pool_b_index = descriptor_index
    pool_a_index = _validate_render_pool_index(
        "pool_a", pool_a_index, RENDER_POOL_A_RING_SLOT_COUNT
    )
    pool_b_index = _validate_render_pool_index(
        "pool_b", pool_b_index, RENDER_POOL_B_RING_SLOT_COUNT
    )
    if pool_a_address is None:
        pool_a_address = descriptor_objects[0] + pool_a_index * 0x100
    if pool_b_address is None:
        pool_b_address = descriptor_objects[2] + pool_b_index * 0x80
    pool_a_address = int(pool_a_address)
    pool_b_address = int(pool_b_address)
    _validate_u64(pool_a_address, "G17G fragment pool-A record")
    _validate_u64(pool_b_address, "G17G fragment pool-B record")
    queue_index = int(queue_index)
    if not 1 <= queue_index < (1 << 8):
        raise ValueError("G17G fragment queue index is invalid")
    register_pair_index = int(register_pair_index)
    if not 0 <= register_pair_index < (1 << 8):
        raise ValueError("G17G fragment register pair index is out of range")
    if register_resource_index is None:
        register_resource_index = parameter_index
    register_resource_index = int(register_resource_index)
    if not 0 <= register_resource_index < RENDER_SUBMISSION_COUNTER_COUNT:
        raise ValueError("G17G fragment register resource index is out of range")
    descriptor_objects = tuple(int(address) for address in descriptor_objects)
    if len(descriptor_objects) != 4:
        raise ValueError("G17G descriptor object family must have four members")
    for address in descriptor_objects:
        _validate_u64(address, "G17G fragment descriptor object")
    status_base = int(status_base)
    _validate_u64(status_base, "G17G fragment status base")
    if status_index is None:
        status_index = submission_index
    status_index = int(status_index)
    if not 0 <= status_index < (1 << 16):
        raise ValueError("G17G fragment status index is out of range")
    status_address = status_base + status_index * 0x40
    register_status_override = (
        register_status_base is not None or register_status_index is not None
    )
    if register_status_base is None:
        register_status_base = FRAGMENT_REGISTER_STATUS
    register_status_base = int(register_status_base)
    _validate_u64(register_status_base, "G17G fragment register-status base")
    if register_status_index is None:
        register_status_index = submission_index
    register_status_index = int(register_status_index)
    if not 0 <= register_status_index < (1 << 16):
        raise ValueError("G17G fragment register-status index is out of range")
    register_status_address = (
        register_status_base + register_status_index * 0x40
    )
    descriptor_offset = descriptor_index * FRAGMENT_DESCRIPTOR_SIZE
    output = bytearray(FRAGMENT_DESCRIPTOR_SIZE)
    struct.pack_into("<IQI", output, 0, 1, sequence, 1)
    descriptor_objects = list(descriptor_objects)
    descriptor_objects[0] = pool_a_address
    descriptor_objects[2] = pool_b_address
    struct.pack_into("<4Q", output, 0x20, *descriptor_objects)
    geometry = _render_geometry(params)
    for offset, value in (
        (
            0x40,
            0x1000260000 + parameter_index * 0x1200
            + resource_address_offset,
        ),
        (0x48, 0x88),
        (0x50, (geometry["macro_size"] << 32) | 1),
        (
            0x68,
            params.resolved_merge_upper_x_bits()
            | (params.resolved_merge_upper_y_bits() << 32),
        ),
        (0x78, ((params.width + TILE_WIDTH - 1) // TILE_WIDTH)
         * ((params.height + TILE_HEIGHT - 1) // TILE_HEIGHT)),
        (0x80, 0x0000005900590057),
        (0x88, 0x5A),
        (0x90, submission_ordinal & 0xFF),
    ):
        struct.pack_into("<Q", output, offset, value)
    primary_registers = build_fragment_registers(
        params, parameter_index, submission_index,
        work_index=work_stamp_index, status_index=submission_index,
    )
    if register_pair_index:
        primary_registers = _apply_register_overrides(
            primary_registers,
            {0x1CA28: (
                0x220040 + register_pair_index * 0x5E0000
                + register_resource_index * 0x40
            )},
        )
    if register_status_override:
        primary_registers = _apply_register_overrides(
            primary_registers, {0x14080: register_status_address | 1}
        )
    if resource_address_offset or context_id:
        resource_registers = {0x16098, 0x16429, 0x16060, 0x1CA28}
        primary_registers = tuple(
            (
                number,
                context_id if number == 0x14048 else
                value + resource_address_offset
                if number in resource_registers else value,
            )
            for number, value in primary_registers
        )
    if params.buffers is not None:
        struct.pack_into("<Q", output, 0x40, params.buffers.tilemap)
        primary_registers = _apply_register_overrides(primary_registers, {
            0x16429: params.buffers.tilemap,
            0x16098: params.buffers.metadata, 0x16060: params.buffers.metadata,
        })
    _write_registers(output, 0xA0, primary_registers)
    _write_registers(output, 0x4CC, ((0x16068, 0x40000),))

    block_specs = (
        (0x7A0, 0x0A0, 0x5A, 0x7C0, _FRAGMENT_BLOCK_0_REGISTERS),
        (0xEC0, 0x7C0, 0x11, 0xEE0, _FRAGMENT_BLOCK_1_REGISTERS),
        (0x15E0, 0xEE0, 0x18, 0x1600, _FRAGMENT_BLOCK_2_REGISTERS),
    )
    for self_offset, self_target, header, register_offset, registers in block_specs:
        struct.pack_into(
            "<Q", output, self_offset,
            FRAGMENT_LOW_ALIAS + descriptor_offset + self_target,
        )
        struct.pack_into("<I", output, self_offset + 8,
                         1 if not params.partial_render_fallback and self_target != 0xA0 else header)
        if not params.partial_render_fallback:
            # Native first-work memoryless descriptors carry one 0x16068
            # entry in each of the three partial programs. Preserve their
            # link addresses and the normal initial/final render programs.
            # This source option is qualified independently on hardware;
            # it is not permission to omit backing or corrupt pool counts.
            registers = ((0x16068, 0x40000),)
        _write_registers(
            output, register_offset,
            _resolve_registers(
                registers, params, parameter_index, submission_index,
            ),
        )
    struct.pack_into(
        "<Q", output, 0x1D00,
        FRAGMENT_LOW_ALIAS + descriptor_offset + 0x1600,
    )
    struct.pack_into("<I", output, 0x1D08, 0x0C if params.partial_render_fallback else 1)

    struct.pack_into(
        "<Q", output, 0x1D20, params.resolved_depth_bias_array()
    )
    struct.pack_into(
        "<Q", output, 0x1D30, params.resolved_scissor_array()
    )
    struct.pack_into("<Q", output, 0x1D40, params.occlusion_query_base)
    struct.pack_into("<Q", output, 0x1E78, params.load_pipeline_bind)
    struct.pack_into("<Q", output, 0x1E80, params.load_pipeline)
    struct.pack_into(
        "<Q", output, 0x1EA8, params.partial_load_pipeline_bind
    )
    struct.pack_into(
        "<Q", output, 0x1EB0, params.resolved_partial_load_pipeline()
    )
    struct.pack_into("<I", output, 0x1EC0, 0x04040404)
    struct.pack_into("<Q", output, 0x1F40, params.resolved_aux_fb_flags())
    struct.pack_into("<I", output, 0x1F48, params.width)
    struct.pack_into("<I", output, 0x1F4C, params.height)
    struct.pack_into("<Q", output, 0x1F50, 0x100000)
    struct.pack_into("<Q", output, 0x1F58, params.resolved_tile_config())
    struct.pack_into("<I", output, 0x1F78, params.store_pipeline_bind)
    struct.pack_into("<Q", output, 0x1F7C, params.store_pipeline)
    struct.pack_into(
        "<I", output, 0x1F98, params.partial_store_pipeline_bind
    )
    struct.pack_into(
        "<Q", output, 0x1F9C, params.resolved_partial_store_pipeline()
    )
    struct.pack_into("<I", output, 0x1FA8, params.depth_clear_value_bits)
    struct.pack_into(
        "<Q", output, 0x1FAC,
        (params.tib_bytes << 32) | params.stencil_clear_value | 0x300,
    )
    output[0x1FB0] = params.tib_bytes

    fragment_lifecycle = params.tiling_lifecycle - 1
    # Native memoryless work sets this independently of +0x2124 and tile
    # configuration. Preserve the old coupled recipe unless explicitly
    # selected. EncoderParams::sync_grow is the independent Asahi layout
    # hypothesis; its M5 effects need their own hardware witnesses.
    output[0x2100] = int(not params.process_empty_tiles if params.fragment_sync_grow is None
                         else params.fragment_sync_grow)
    struct.pack_into("<Q", output, 0x2108, fragment_lifecycle >> 32)
    struct.pack_into("<I", output, 0x2110, 0xFFFFFFFF)
    struct.pack_into("<Q", output, 0x2114, params.sampler_array)
    struct.pack_into("<I", output, 0x211C, params.sampler_count)
    struct.pack_into(
        "<I", output, 0x2120,
        params.sampler_count + 1 if params.sampler_count else 0,
    )
    output[0x2124] = int(params.process_empty_tiles)
    output[0x2128] = 1
    struct.pack_into(
        "<Q", output, 0x2140,
        DISPATCH_A + queue_index * 4,
    )
    struct.pack_into(
        "<Q", output, 0x2148,
        DISPATCH_B + queue_index * 4,
    )
    ordinal = submission_ordinal
    struct.pack_into("<I", output, 0x2150, ordinal << 8)
    struct.pack_into("<I", output, 0x2154, queue_index)
    struct.pack_into("<I", output, 0x2160, ordinal)
    struct.pack_into("<I", output, 0x2164, (ordinal & 0xFF) << 8)
    struct.pack_into("<Q", output, 0x2168, fragment_lifecycle & 0xFFFFFFFF)
    struct.pack_into("<I", output, 0x2170, logical_work_index)
    struct.pack_into("<I", output, 0x2174, 0)
    struct.pack_into("<Q", output, 0x2198, params.fragment_timestamp_start)
    struct.pack_into("<Q", output, 0x21A0, params.fragment_timestamp_end)
    struct.pack_into(
        "<Q", output, 0x21A8, params.fragment_user_timestamp_start
    )
    struct.pack_into(
        "<Q", output, 0x21B0, params.fragment_user_timestamp_end
    )
    struct.pack_into("<Q", output, 0x21CE, shared_control)
    output[0x21D6] = 1
    output[0x21D9] = 0x87 if params.partial_mode else 0x77
    struct.pack_into(
        "<Q", output, 0x21DF,
        status_address,
    )
    output[0x21E7] = 2
    output[0x21EE] = 4
    output[0x220F] = 1
    output[0x2213] = 1
    return bytes(output)


def apply_retained_completion_endpoints(
        items, tiling_endpoints, fragment_endpoints):
    """Populate the duplicated completion endpoints in a retained group.

    The early native ordinal-2 boundary carries each engine's live start/end
    pair twice in its descriptor. Fresh descriptors leave those output-like
    fields zero, but the retained-generation path republishes the prior live
    pair as part of the next group's admission record. Keep the values live
    and caller-supplied; only their observed locations are ABI constants.
    """
    if tuple(items) != CLEAR_RENDER_ITEM_ORDER:
        raise ValueError("G17G retained completion item order changed")
    result = {name: bytes(body) for name, body in items.items()}
    specs = (
        (
            "tiling_descriptor",
            TILING_DESCRIPTOR_SIZE,
            (0x87A, 0x882, 0x95D, 0x965),
            tiling_endpoints,
        ),
        (
            "fragment_descriptor",
            FRAGMENT_DESCRIPTOR_SIZE,
            (0x2114, 0x211C, 0x21F7, 0x21FF),
            fragment_endpoints,
        ),
    )
    for name, expected_size, offsets, endpoints in specs:
        endpoints = tuple(int(value) for value in endpoints)
        if (
            len(endpoints) != 2
            or not 0 < endpoints[0] < endpoints[1] < (1 << 64)
        ):
            raise ValueError("G17G retained completion endpoints changed")
        body = bytearray(result[name])
        if len(body) != expected_size:
            raise ValueError("G17G retained completion descriptor size changed")
        for offset, value in zip(offsets, endpoints * 2):
            if struct.unpack_from("<Q", body, offset)[0] != 0:
                raise ValueError(
                    "G17G retained completion destination is not zero"
                )
            struct.pack_into("<Q", body, offset, value)
        result[name] = bytes(body)
    return result


def build_clear_work_items(
    params,
    token,
    submission_ordinal=1,
    event_group=1,
    event_generation=2,
    descriptor_index=None,
    tiling_descriptor_index=None,
    fragment_descriptor_index=None,
    submission_index=None,
    parameter_index=None,
    pool_a_index=None,
    pool_b_index=None,
    pool_a_address=None,
    pool_b_address=None,
    queue_indices=(0, 1),
    queue_context_index=None,
    channel_control=CHANNEL_CONTROL,
    tiling_context_scratch=TILING_CONTEXT_SCRATCH,
    tiling_firmware_scratch=TILING_FIRMWARE_SCRATCH,
    fragment_context_scratch=FRAGMENT_CONTEXT_SCRATCH,
    fragment_firmware_scratch=FRAGMENT_FIRMWARE_SCRATCH,
    tiling_status_base=TILING_STATUS,
    fragment_status_base=FRAGMENT_STATUS,
    status_index=None,
    tiling_register_status_base=None,
    fragment_register_status_base=None,
    register_status_index=None,
    work_stamp_index=None,
    descriptor_objects=DESCRIPTOR_OBJECTS,
    register_pair_index=0,
    register_resource_index=None,
    shared_control=SHARED_CONTROL,
    optional_submission_ordinal=None,
    optional_first_record=None,
    optional_context_id=0,
    optional_secondary_context_id=None,
    optional_lifecycle_ordinal=None,
    tiling_optional_pair_index=None,
    tiling_work_index=None,
    descriptor_resource_address_offset=0,
    descriptor_context_id=0,
    descriptor_sequence_bias=0,
):
    """Build the complete ordered six-item first-clear work group.

    This is deliberately one layer below queue publication.  The returned
    bytes contain both channels' selector sequences ``[15, 0, 14]`` and
    ``[15, 1, 14]`` but do not imply that their referenced scratch, pipeline,
    tiler, queue, or global lifecycle objects have been installed.
    """
    params.validate()
    descriptor_sequence_bias = int(descriptor_sequence_bias)
    if not 0 <= descriptor_sequence_bias < (1 << 32):
        raise ValueError("G17G descriptor sequence bias must fit in uint32")
    if optional_submission_ordinal is None:
        optional_submission_ordinal = submission_ordinal
    optional_submission_ordinal = int(optional_submission_ordinal)
    if not 1 <= event_group < (1 << 24):
        raise ValueError("G17G render work group must be positive")
    if descriptor_index is None:
        descriptor_index = event_group - 1
    if tiling_descriptor_index is None:
        tiling_descriptor_index = descriptor_index
    if fragment_descriptor_index is None:
        fragment_descriptor_index = descriptor_index
    tiling_descriptor_index = _validate_tiling_descriptor_index(
        tiling_descriptor_index
    )
    fragment_descriptor_index = _validate_fragment_descriptor_index(
        fragment_descriptor_index
    )
    if parameter_index is None:
        parameter_index = descriptor_index
    if submission_index is None:
        submission_index = int(submission_ordinal) - 1
    submission_index = int(submission_index)
    descriptor_objects = tuple(int(address) for address in descriptor_objects)
    if len(descriptor_objects) != 4:
        raise ValueError("G17G descriptor object family must have four members")
    for address in descriptor_objects:
        _validate_u64(address, "G17G descriptor object")
    _validate_u64(shared_control, "G17G shared control")
    queue_indices = tuple(int(index) for index in queue_indices)
    if len(queue_indices) != 2:
        raise ValueError("G17G render queue-index pair must have two entries")
    if queue_indices[0] == queue_indices[1]:
        raise ValueError("G17G render queue identities must be distinct")
    items = {
        "tiling_optional": build_optional_item(
            "tiling",
            tiling_context_scratch,
            tiling_firmware_scratch,
            shared_control,
            channel_control,
            token,
            descriptor_objects[1],
            optional_submission_ordinal,
            queue_indices[0],
            queue_context_index,
            optional_first_record,
            optional_context_id,
            optional_secondary_context_id,
            optional_lifecycle_ordinal,
            tiling_optional_pair_index,
        ),
        "tiling_descriptor": build_tiling_descriptor(
            params,
            sequence=2 * event_group - 1 + descriptor_sequence_bias,
            descriptor_index=tiling_descriptor_index,
            submission_index=submission_index,
            submission_ordinal=submission_ordinal,
            parameter_index=parameter_index,
            pool_a_index=pool_a_index,
            pool_b_index=pool_b_index,
            pool_a_address=pool_a_address,
            pool_b_address=pool_b_address,
            queue_index=queue_indices[0],
            status_base=tiling_status_base,
            status_index=status_index,
            register_status_base=tiling_register_status_base,
            register_status_index=register_status_index,
            work_stamp_index=work_stamp_index,
            descriptor_objects=descriptor_objects,
            register_pair_index=register_pair_index,
            register_resource_index=register_resource_index,
            shared_control=shared_control,
            work_index=tiling_work_index,
            resource_address_offset=descriptor_resource_address_offset,
            context_id=descriptor_context_id,
        ),
        "tiling_event": build_event_item(
            "tiling", event_group, event_generation, queue_indices[0]
        ),
        "fragment_optional": build_optional_item(
            "fragment",
            fragment_context_scratch,
            fragment_firmware_scratch,
            shared_control,
            channel_control,
            token,
            submission_ordinal=optional_submission_ordinal,
            queue_index=queue_indices[1],
            queue_context_index=queue_context_index,
            first_record=optional_first_record,
            context_id=optional_context_id,
            secondary_context_id=optional_secondary_context_id,
            lifecycle_ordinal=optional_lifecycle_ordinal,
        ),
        "fragment_descriptor": build_fragment_descriptor(
            params,
            sequence=2 * event_group - 2 + descriptor_sequence_bias,
            descriptor_index=fragment_descriptor_index,
            submission_index=submission_index,
            submission_ordinal=submission_ordinal,
            parameter_index=parameter_index,
            pool_a_index=pool_a_index,
            pool_b_index=pool_b_index,
            pool_a_address=pool_a_address,
            pool_b_address=pool_b_address,
            queue_index=queue_indices[1],
            status_base=fragment_status_base,
            status_index=status_index,
            register_status_base=fragment_register_status_base,
            register_status_index=register_status_index,
            work_stamp_index=work_stamp_index,
            descriptor_objects=descriptor_objects,
            register_pair_index=register_pair_index,
            register_resource_index=register_resource_index,
            shared_control=shared_control,
            resource_address_offset=descriptor_resource_address_offset,
            context_id=descriptor_context_id,
        ),
        "fragment_event": build_event_item(
            "fragment", event_group, event_generation, queue_indices[1]
        ),
    }
    if tuple(items) != CLEAR_RENDER_ITEM_ORDER:
        raise AssertionError("G17G clear work-item order changed")
    return items
