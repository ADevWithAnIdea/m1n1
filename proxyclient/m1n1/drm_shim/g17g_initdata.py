# SPDX-License-Identifier: GPL-2.0-only
"""Construct independently validated T8142/G17G pre-init data.

The imported T8140 builders suggested candidate offsets, but every constant and
layout here is reproduced byte-for-byte by two independent native T8142
pre-init captures.  Unresolved fields retain numeric names.  This module does
not copy a snapshot blob; it constructs the complete descriptor closure and
the additional nonzero pages observed in the firmware translation root.
"""

import struct

from . import g17g


# Numeric descriptor root.
ROOT_PRIMARY_SIZE = 0xB8
ROOT_SECONDARY_SIZE = 0xC8
ROOT_VERSION = 0x00
ROOT_REGION_08 = 0x08
ROOT_ZERO_10 = 0x10
ROOT_MAIN_CONFIG = 0x18
ROOT_REGION_20 = 0x20
ROOT_INSTANCE_INDEX = 0x28
ROOT_WORD_2C = 0x2C
ROOT_GRANULE = 0x30
ROOT_GRANULE_BITS = 0x32
ROOT_LEVEL_COUNT = 0x33
ROOT_LEVELS = 0x34
ROOT_ADDRESS_A8 = 0xA8
ROOT_ADDRESS_B0 = 0xB0
ROOT_SECONDARY_ADDRESS_B8 = 0xB8
ROOT_SECONDARY_ADDRESS_C0 = 0xC0

# macOS 27.0 beta 5 / mBoot-20457.1.27 publishes this interface tuple in
# both roots.  Relative to beta 4, only words one and two changed.
ROOT_VERSION_VALUES = (0x04C0, 0x83A0, 0x4339, 0x0C8B)
GRANULE = 0x4000
GRANULE_BITS = 14
LEVEL_DESCRIPTOR_SIZE = 0x20
LEVEL_PHYSICAL_MASK = 0x000003FFFFFFC000
LEVELS = ((36, 64), (25, 2048), (14, 2048))


def _u64(value, name):
    if not 0 <= value < (1 << 64):
        raise ValueError("%s does not fit in u64" % name)
    return value


def build_level_descriptor(index_shift, entry_count):
    """Build one exact 0x20-byte numeric translation-level descriptor."""
    if not 0 <= index_shift < 64:
        raise ValueError("numeric level shift is out of range")
    if entry_count not in (64, 2048):
        raise ValueError("numeric level entry count is not observed")
    data = bytearray(LEVEL_DESCRIPTOR_SIZE)
    data[0:4] = bytes((8, GRANULE_BITS, GRANULE_BITS, index_shift))
    struct.pack_into("<H", data, 0x04, entry_count)
    struct.pack_into("<H", data, 0x06, GRANULE)
    struct.pack_into("<Q", data, 0x08, 1)
    struct.pack_into("<Q", data, 0x10, LEVEL_PHYSICAL_MASK)
    struct.pack_into("<Q", data, 0x18, (entry_count - 1) << index_shift)
    return bytes(data)


def build_root(
    region_08,
    main_config,
    region_20,
    address_a8,
    address_b0,
    instance_index=0,
    secondary_address_b8=0,
    secondary_address_c0=0,
    version=ROOT_VERSION_VALUES,
):
    """Build one complete observed primary or secondary numeric root."""
    if len(version) != 4 or any(not 0 <= item < (1 << 16) for item in version):
        raise ValueError("numeric root version must contain four u16 values")
    if instance_index not in (0, 1):
        raise ValueError("numeric root instance index must be 0 or 1")
    secondary = bool(secondary_address_b8 or secondary_address_c0)
    if secondary != bool(instance_index):
        raise ValueError("numeric secondary root addresses/index disagree")
    size = ROOT_SECONDARY_SIZE if secondary else ROOT_PRIMARY_SIZE
    data = bytearray(size)
    struct.pack_into("<4H", data, ROOT_VERSION, *version)
    for offset, value in (
        (ROOT_REGION_08, region_08),
        (ROOT_MAIN_CONFIG, main_config),
        (ROOT_REGION_20, region_20),
        (ROOT_ADDRESS_A8, address_a8),
        (ROOT_ADDRESS_B0, address_b0),
    ):
        struct.pack_into("<Q", data, offset, _u64(value, "root field"))
    struct.pack_into("<I", data, ROOT_INSTANCE_INDEX, instance_index)
    struct.pack_into("<I", data, ROOT_WORD_2C, 1)
    struct.pack_into("<H", data, ROOT_GRANULE, GRANULE)
    data[ROOT_GRANULE_BITS] = GRANULE_BITS
    data[ROOT_LEVEL_COUNT] = len(LEVELS)
    for index, (shift, count) in enumerate(LEVELS):
        offset = ROOT_LEVELS + index * LEVEL_DESCRIPTOR_SIZE
        data[offset:offset + LEVEL_DESCRIPTOR_SIZE] = (
            build_level_descriptor(shift, count)
        )
    if secondary:
        struct.pack_into(
            "<Q", data, ROOT_SECONDARY_ADDRESS_B8,
            _u64(secondary_address_b8, "secondary root field"),
        )
        struct.pack_into(
            "<Q", data, ROOT_SECONDARY_ADDRESS_C0,
            _u64(secondary_address_c0, "secondary root field"),
        )
    return bytes(data)


def root_from_bytes(data):
    """Extract exactly the fields accepted by :func:`build_root`."""
    if len(data) not in (ROOT_PRIMARY_SIZE, ROOT_SECONDARY_SIZE):
        raise ValueError("numeric root has an unexpected size")
    secondary = len(data) == ROOT_SECONDARY_SIZE
    result = {
        "version": struct.unpack_from("<4H", data, ROOT_VERSION),
        "region_08": struct.unpack_from("<Q", data, ROOT_REGION_08)[0],
        "main_config": struct.unpack_from("<Q", data, ROOT_MAIN_CONFIG)[0],
        "region_20": struct.unpack_from("<Q", data, ROOT_REGION_20)[0],
        "instance_index": struct.unpack_from(
            "<I", data, ROOT_INSTANCE_INDEX
        )[0],
        "address_a8": struct.unpack_from("<Q", data, ROOT_ADDRESS_A8)[0],
        "address_b0": struct.unpack_from("<Q", data, ROOT_ADDRESS_B0)[0],
        "secondary_address_b8": 0,
        "secondary_address_c0": 0,
    }
    if secondary:
        result["secondary_address_b8"] = struct.unpack_from(
            "<Q", data, ROOT_SECONDARY_ADDRESS_B8
        )[0]
        result["secondary_address_c0"] = struct.unpack_from(
            "<Q", data, ROOT_SECONDARY_ADDRESS_C0
        )[0]
    return result


# Numeric main configuration object.
MAIN_CONFIG_SIZE = 0x600
MAIN_HWDATA_ADDRESS = 0x00
MAIN_REPEATED_ADDRESS_08 = 0x08
MAIN_REPEATED_ADDRESS_10 = 0x10
MAIN_CHANNEL_TABLE = g17g.CHANNEL_TABLE_OFFSET
MAIN_ADDRESS_ARRAY = 0x254
MAIN_ADDRESS_ARRAY_COUNT = 5
MAIN_REGION_TRIPLES = 0x2D0
MAIN_REGION_TRIPLE_STRIDE = 0x10
MAIN_REGION_TRIPLE_COUNT = 3
MAIN_REGION_TRIPLE_KIND = 0x72
MAIN_WORD_300 = 0x300
MAIN_WORD_3E0 = 0x3E0
MAIN_SECONDARY_ADDRESS_481 = 0x481
MAIN_WORD_4C0 = 0x4C0

MAIN_PRIMARY_WORD_3E0 = 0xFF
MAIN_PRIMARY_WORD_4C0 = 0x15
MAIN_SECONDARY_FIRST_CHANNEL = 12
MAIN_SECONDARY_WORD_300 = 0x0C
MAIN_SECONDARY_WORD_4C0 = 0x2A


def build_channel_entry(state_addresses, ring_address):
    """Build one exact 0x20-byte numeric channel-table entry."""
    if len(state_addresses) != g17g.CHANNEL_STATE_COUNT:
        raise ValueError("numeric channel entry requires three state addresses")
    values = tuple(state_addresses) + (ring_address,)
    return struct.pack(
        "<4Q", *(_u64(value, "channel address") for value in values)
    )


def parse_main_config(data):
    """Decode the bounded numeric fields in a complete 0x600-byte object."""
    if len(data) != MAIN_CONFIG_SIZE:
        raise ValueError("numeric main config has an unexpected size")
    channels = []
    for index in range(g17g.CHANNEL_ENTRY_COUNT):
        start = MAIN_CHANNEL_TABLE + index * g17g.CHANNEL_ENTRY_SIZE
        entry = g17g.parse_channel_entry(
            data[start:start + g17g.CHANNEL_ENTRY_SIZE]
        )
        channels.append((entry["state_addresses"], entry["ring_address"]))
    return {
        "hwdata_address": struct.unpack_from(
            "<Q", data, MAIN_HWDATA_ADDRESS
        )[0],
        "repeated_address": struct.unpack_from(
            "<Q", data, MAIN_REPEATED_ADDRESS_08
        )[0],
        "channels": channels,
        "address_array": tuple(
            struct.unpack_from("<Q", data, MAIN_ADDRESS_ARRAY + index * 8)[0]
            for index in range(MAIN_ADDRESS_ARRAY_COUNT)
        ),
        "region_triples": tuple(
            (
                struct.unpack_from(
                    "<Q", data,
                    MAIN_REGION_TRIPLES + index * MAIN_REGION_TRIPLE_STRIDE,
                )[0],
                struct.unpack_from(
                    "<I", data,
                    MAIN_REGION_TRIPLES + index * MAIN_REGION_TRIPLE_STRIDE + 8,
                )[0],
                struct.unpack_from(
                    "<I", data,
                    MAIN_REGION_TRIPLES + index * MAIN_REGION_TRIPLE_STRIDE + 0xC,
                )[0],
            )
            for index in range(MAIN_REGION_TRIPLE_COUNT)
        ),
        "word_300": struct.unpack_from("<I", data, MAIN_WORD_300)[0],
        "word_3e0": struct.unpack_from("<I", data, MAIN_WORD_3E0)[0],
        "secondary_address_481": struct.unpack_from(
            "<Q", data, MAIN_SECONDARY_ADDRESS_481
        )[0],
        "word_4c0": struct.unpack_from("<I", data, MAIN_WORD_4C0)[0],
    }


def build_main_config(
    hwdata_address,
    repeated_address,
    channels,
    address_array=(),
    region_triples=(),
    word_300=0,
    word_3e0=0,
    secondary_address_481=0,
    word_4c0=0,
):
    """Build the complete observed 0x600-byte numeric main configuration."""
    if len(channels) != g17g.CHANNEL_ENTRY_COUNT:
        raise ValueError("numeric main config requires 17 channel entries")
    if len(address_array) > MAIN_ADDRESS_ARRAY_COUNT:
        raise ValueError("numeric main address array is too long")
    if len(region_triples) > MAIN_REGION_TRIPLE_COUNT:
        raise ValueError("numeric main region-triple array is too long")
    data = bytearray(MAIN_CONFIG_SIZE)
    struct.pack_into(
        "<Q", data, MAIN_HWDATA_ADDRESS,
        _u64(hwdata_address, "hardware-data address"),
    )
    repeated_address = _u64(repeated_address, "repeated address")
    struct.pack_into("<Q", data, MAIN_REPEATED_ADDRESS_08, repeated_address)
    struct.pack_into("<Q", data, MAIN_REPEATED_ADDRESS_10, repeated_address)
    for index, (state_addresses, ring_address) in enumerate(channels):
        offset = MAIN_CHANNEL_TABLE + index * g17g.CHANNEL_ENTRY_SIZE
        data[offset:offset + g17g.CHANNEL_ENTRY_SIZE] = build_channel_entry(
            state_addresses, ring_address
        )
    for index, address in enumerate(address_array):
        struct.pack_into(
            "<Q", data, MAIN_ADDRESS_ARRAY + index * 8,
            _u64(address, "main address-array value"),
        )
    for index, (address, value, kind) in enumerate(region_triples):
        offset = MAIN_REGION_TRIPLES + index * MAIN_REGION_TRIPLE_STRIDE
        struct.pack_into(
            "<Q", data, offset, _u64(address, "main region address")
        )
        struct.pack_into("<I", data, offset + 8, value)
        struct.pack_into("<I", data, offset + 0xC, kind)
    for offset, value in (
        (MAIN_WORD_300, word_300),
        (MAIN_WORD_3E0, word_3e0),
        (MAIN_WORD_4C0, word_4c0),
    ):
        if not 0 <= value < (1 << 32):
            raise ValueError("numeric main scalar does not fit in u32")
        struct.pack_into("<I", data, offset, value)
    struct.pack_into(
        "<Q", data, MAIN_SECONDARY_ADDRESS_481,
        _u64(secondary_address_481, "secondary main address"),
    )
    return bytes(data)


def rebuild_main_config(data):
    """Rebuild a captured main config solely from its parsed numeric fields."""
    fields = parse_main_config(data)
    return build_main_config(**fields)


STATUS_RECORD_SIZE = 0x80
STATUS_RECORD_WORD_04 = 0x04


def build_status_record():
    """Build the complete observed 0x80-byte numeric status record."""
    data = bytearray(STATUS_RECORD_SIZE)
    struct.pack_into("<I", data, STATUS_RECORD_WORD_04, 1)
    return bytes(data)


# Complete sparse numeric region selected by root +0x20.  The offsets and
# values reproduce two native boots exactly; individual roles remain unknown.
REGION_20_SIZE = 0x1000
REGION_20_CONSTANTS = (
    (0x0024, bytes.fromhex("b80b")),
    (0x0030, bytes.fromhex("010000000100000001")),
    (0x0040, bytes.fromhex("78")),
    (0x0058, bytes.fromhex("ffff2800ffff")),
    (0x0062, bytes.fromhex("01000000010000000300000001")),
    (0x007C, bytes.fromhex("01")),
    (0x0080, bytes.fromhex("0100000001000000")),
    (0x0088, bytes.fromhex("b05e0000b0040000b004")),
    (0x009C, bytes.fromhex("b004")),
    (0x00A0, bytes.fromhex("0d00003202000031")),
    (0x07C8, bytes.fromhex("e204")),
    (0x07CE, bytes.fromhex(
        "803fcdcc4c3fcdcc4c3e6666663fcdcccc3d0000803e3333333f6666663f"
        "0600000001000000010000006400000064"
    )),
    (0x099C, bytes.fromhex("280000000a000000fa000000010000003303")),
    (0x09BC, bytes.fromhex("c0270900c027090005")),
    (0x09CC, bytes.fromhex("280000003200000001")),
    (0x09DC, bytes.fromhex("32")),
    (0x0E0C, bytes.fromhex("fa")),
    (0x0E21, bytes.fromhex("01")),
    (0x0E5D, bytes.fromhex("0300000001")),
    (0x0E70, bytes.fromhex("0000000000010000")),
)


def build_region_20():
    """Build the complete observed sparse 0x1000-byte numeric region."""
    data = bytearray(REGION_20_SIZE)
    for offset, value in REGION_20_CONSTANTS:
        data[offset:offset + len(value)] = value
    return bytes(data)


# Complete numeric hardware-data object selected by main config +0x00.
# macOS 27.0 beta 5 adds one zero 0x28-byte register record and a later
# zero 0x18-byte extension.  Together they grow this allocation by 0x40.
HWDATA_SIZE = 0x3EF4
HWDATA_HEADER_ADDRESS_20 = 0x20
HWDATA_HEADER_ADDRESS_28 = 0x28
HWDATA_REGISTER_ARRAY = 0x640
HWDATA_REGISTER_RECORD_SIZE = 0x28
HWDATA_REGISTER_RECORD_COUNT = 60
HWDATA_CHIP_ID = 0xFB0

HWDATA_PERF_STATE_COUNT = 13
HWDATA_FREQUENCY_TABLE = 0x10E4
HWDATA_CORE_TABLE = 0x1124
HWDATA_MEMORY_TABLE = 0x1524
HWDATA_STATE_BLOCK_STRIDE = 0x40
HWDATA_STATE_BLOCK_REPEATS = 16
HWDATA_SCALE_TABLE = 0x1964
HWDATA_RELATIVE_TABLE_A = 0x19E4
HWDATA_RELATIVE_TABLE_B = 0x1A28
HWDATA_INDEX_TABLE = 0x1AE4
HWDATA_INDEX_COUNT = 16

HWDATA_FLAG_GROUPS = 0x26B0
HWDATA_FLAG_GROUP_PATTERN = (1, 1, 1, 0)
HWDATA_FLAG_GROUP_COUNT = 2
HWDATA_UNASSIGNED_TABLE = 0x26D0
HWDATA_UNASSIGNED_COUNT = 12
HWDATA_REGION_RECORDS = 0x2730
HWDATA_REGION_RECORD_SIZE = 0x20
HWDATA_REGION_RECORD_COUNT = 4
HWDATA_ADDRESS_27A4 = 0x27CC
HWDATA_ADDRESS_27AC = 0x27D4
HWDATA_SENTINELS = (0x3ED8, 0x3EF0)

# Two-boot-stable numeric values outside the structured ranges above.  As with
# older clean-room chip tables, unresolved constants are explicit source data;
# allocation addresses and register/performance tables are never embedded here.
_HWDATA_PRE_BETA5_CONSTANTS = (
    (0x0004, bytes.fromhex("6f0000000000c0ff")),
    (0x0014, bytes.fromhex("100000000000000010")),
    (0x00E0, bytes.fromhex("0820")),
    (0x00EA, bytes.fromhex("0820")),
    (0x00F4, bytes.fromhex(
        "08200000cb240000fa2c8ac9cb24f6f417e97718cb24d9380000abbd"
    )),
    (0x02D9, bytes.fromhex(
        "20f8ffdb2c2dd3002000f526e9da210020b638080042c7"
    )),
    (0x03E0, bytes.fromhex("e07f")),
    (0x03EA, bytes.fromhex("e07f")),
    (0x03F4, bytes.fromhex("e07f00000080")),
    (0x0403, bytes.fromhex("80")),
    (0x040D, bytes.fromhex("80")),
    (0x05D8, bytes.fromhex(
        "4526234b980e00005feaa2d5ff3f004000405ecaa2f50040"
    )),
    (0x0F81, bytes.fromhex("80")),
    (0x0F8C, bytes.fromhex("02")),
    (0x0F98, bytes.fromhex("0100000001")),
    (0x0FB0, bytes.fromhex(
        "0100000001000000000000000100000000000000c05d00000100000008000000"
        "00000000010000000100000001"
    )),
    (0x0FF8, bytes.fromhex("1f")),
    (0x1018, bytes.fromhex("040080070c")),
    (0x1028, bytes.fromhex("0100000001")),
    (0x1040, bytes.fromhex("31")),
    (0x1060, bytes.fromhex("01")),
    (0x107C, bytes.fromhex("0a00000001")),
    (0x10AC, bytes.fromhex("17000000050000000a0000000c")),
    (0x2638, bytes.fromhex("0400000006000000030000000700000007")),
    (0x265C, bytes.fromhex("080000000000000001")),
    (0x2682, bytes.fromhex("18")),
    (0x26E8, bytes.fromhex("0100000096")),
    (0x26F8, bytes.fromhex("010000000000000001")),
    (0x27B4, bytes.fromhex("0100000001")),
    (0x27E0, bytes.fromhex("e80300000000000001")),
    (0x2812, bytes.fromhex("0100000001")),
)

# The first beta-5 extension is exactly one register-record wide and precedes
# every sparse constant from old offset 0xf81 onward.  The later 0x18-byte
# extension is all zero, so it affects only the final sentinels and total size.
HWDATA_CONSTANTS = tuple(
    (offset + (0x28 if offset >= 0x0F81 else 0), value)
    for offset, value in _HWDATA_PRE_BETA5_CONSTANTS
)


def parse_register_record(data):
    """Decode one complete 0x28-byte numeric register-map record."""
    if len(data) != HWDATA_REGISTER_RECORD_SIZE:
        raise ValueError("numeric register record has an unexpected size")
    values = struct.unpack("<QQIIQII", data)
    return {
        "field_00": values[0],
        "field_08": values[1],
        "word_10": values[2],
        "word_14": values[3],
        "field_18": values[4],
        "word_20": values[5],
        "word_24": values[6],
    }


def build_register_record(
    field_00=0, field_08=0, word_10=0, word_14=0,
    field_18=0, word_20=0, word_24=0,
):
    """Build one complete 0x28-byte numeric register-map record."""
    qwords = (field_00, field_08, field_18)
    words = (word_10, word_14, word_20, word_24)
    if any(not 0 <= value < (1 << 64) for value in qwords):
        raise ValueError("numeric register qword does not fit in u64")
    if any(not 0 <= value < (1 << 32) for value in words):
        raise ValueError("numeric register word does not fit in u32")
    return struct.pack(
        "<QQIIQII", field_00, field_08, word_10, word_14,
        field_18, word_20, word_24,
    )


def parse_region_record(data):
    """Decode one complete 0x20-byte numeric hardware-data region record."""
    if len(data) != HWDATA_REGION_RECORD_SIZE:
        raise ValueError("numeric region record has an unexpected size")
    values = struct.unpack("<IIIQIII", data)
    return {
        "word_00": values[0],
        "word_04": values[1],
        "word_08": values[2],
        "address_0c": values[3],
        "word_14": values[4],
        "word_18": values[5],
        "word_1c": values[6],
    }


def build_region_record(
    word_00, word_04, word_08, address_0c,
    word_14=0x800, word_18=0x40, word_1c=0,
):
    """Build one complete 0x20-byte numeric hardware-data region record."""
    words = (word_00, word_04, word_08, word_14, word_18, word_1c)
    if any(not 0 <= value < (1 << 32) for value in words):
        raise ValueError("numeric region-record word does not fit in u32")
    return struct.pack(
        "<IIIQIII", word_00, word_04, word_08,
        _u64(address_0c, "region-record address"),
        word_14, word_18, word_1c,
    )


def parse_hwdata(data):
    """Extract every parameter needed to rebuild the complete hardware data."""
    if len(data) != HWDATA_SIZE:
        raise ValueError("numeric hardware data has an unexpected size")
    register_records = []
    for index in range(HWDATA_REGISTER_RECORD_COUNT):
        offset = HWDATA_REGISTER_ARRAY + index * HWDATA_REGISTER_RECORD_SIZE
        register_records.append(parse_register_record(
            data[offset:offset + HWDATA_REGISTER_RECORD_SIZE]
        ))

    def words(offset, count):
        return struct.unpack_from("<%dI" % count, data, offset)

    core = tuple(
        words(
            HWDATA_CORE_TABLE + index * HWDATA_STATE_BLOCK_STRIDE,
            HWDATA_STATE_BLOCK_REPEATS,
        )[0]
        for index in range(HWDATA_PERF_STATE_COUNT)
    )
    memory = tuple(
        words(
            HWDATA_MEMORY_TABLE + index * HWDATA_STATE_BLOCK_STRIDE,
            HWDATA_STATE_BLOCK_REPEATS,
        )[0]
        for index in range(HWDATA_PERF_STATE_COUNT)
    )
    region_records = []
    for index in range(HWDATA_REGION_RECORD_COUNT):
        offset = HWDATA_REGION_RECORDS + index * HWDATA_REGION_RECORD_SIZE
        region_records.append(parse_region_record(
            data[offset:offset + HWDATA_REGION_RECORD_SIZE]
        ))
    return {
        "header_address_20": struct.unpack_from(
            "<Q", data, HWDATA_HEADER_ADDRESS_20
        )[0],
        "header_address_28": struct.unpack_from(
            "<Q", data, HWDATA_HEADER_ADDRESS_28
        )[0],
        "register_records": tuple(register_records),
        "chip_id": struct.unpack_from("<I", data, HWDATA_CHIP_ID)[0],
        "frequency_table": words(
            HWDATA_FREQUENCY_TABLE, HWDATA_PERF_STATE_COUNT
        ),
        "core_table": core,
        "memory_table": memory,
        "scale_table": words(HWDATA_SCALE_TABLE, HWDATA_PERF_STATE_COUNT),
        "relative_table_a": words(
            HWDATA_RELATIVE_TABLE_A, HWDATA_PERF_STATE_COUNT
        ),
        "relative_table_b": words(
            HWDATA_RELATIVE_TABLE_B, HWDATA_PERF_STATE_COUNT
        ),
        "index_table": words(HWDATA_INDEX_TABLE, HWDATA_INDEX_COUNT),
        "region_records": tuple(region_records),
        "address_27a4": struct.unpack_from(
            "<Q", data, HWDATA_ADDRESS_27A4
        )[0],
        "address_27ac": struct.unpack_from(
            "<Q", data, HWDATA_ADDRESS_27AC
        )[0],
    }


def build_hwdata(
    header_address_20,
    header_address_28,
    register_records,
    chip_id,
    frequency_table,
    core_table,
    memory_table,
    scale_table,
    relative_table_a,
    relative_table_b,
    index_table,
    region_records,
    address_27a4,
    address_27ac,
    constants=HWDATA_CONSTANTS,
):
    """Build the complete observed 0x3ef4-byte numeric hardware data."""
    sized = (
        ("register records", register_records, HWDATA_REGISTER_RECORD_COUNT),
        ("frequency table", frequency_table, HWDATA_PERF_STATE_COUNT),
        ("core table", core_table, HWDATA_PERF_STATE_COUNT),
        ("memory table", memory_table, HWDATA_PERF_STATE_COUNT),
        ("scale table", scale_table, HWDATA_PERF_STATE_COUNT),
        ("relative table A", relative_table_a, HWDATA_PERF_STATE_COUNT),
        ("relative table B", relative_table_b, HWDATA_PERF_STATE_COUNT),
        ("index table", index_table, HWDATA_INDEX_COUNT),
        ("region records", region_records, HWDATA_REGION_RECORD_COUNT),
    )
    for name, values, count in sized:
        if len(values) != count:
            raise ValueError("numeric %s requires %d entries" % (name, count))
    data = bytearray(HWDATA_SIZE)
    for offset, value in constants:
        data[offset:offset + len(value)] = value
    struct.pack_into(
        "<Q", data, HWDATA_HEADER_ADDRESS_20,
        _u64(header_address_20, "hardware-data header address"),
    )
    struct.pack_into(
        "<Q", data, HWDATA_HEADER_ADDRESS_28,
        _u64(header_address_28, "hardware-data header address"),
    )
    for index, record in enumerate(register_records):
        offset = HWDATA_REGISTER_ARRAY + index * HWDATA_REGISTER_RECORD_SIZE
        data[offset:offset + HWDATA_REGISTER_RECORD_SIZE] = (
            build_register_record(**record)
        )
    if chip_id != g17g.CHIP_ID:
        raise ValueError("numeric hardware data requires chip ID 0x8142")
    struct.pack_into("<I", data, HWDATA_CHIP_ID, chip_id)

    def write_words(offset, values):
        if any(not 0 <= value < (1 << 32) for value in values):
            raise ValueError("numeric hardware-data table value does not fit u32")
        struct.pack_into("<%dI" % len(values), data, offset, *values)

    write_words(HWDATA_FREQUENCY_TABLE, frequency_table)
    for base, values in (
        (HWDATA_CORE_TABLE, core_table),
        (HWDATA_MEMORY_TABLE, memory_table),
    ):
        for index, value in enumerate(values):
            write_words(
                base + index * HWDATA_STATE_BLOCK_STRIDE,
                [value] * HWDATA_STATE_BLOCK_REPEATS,
            )
    write_words(HWDATA_SCALE_TABLE, scale_table)
    write_words(HWDATA_RELATIVE_TABLE_A, relative_table_a)
    write_words(HWDATA_RELATIVE_TABLE_B, relative_table_b)
    write_words(HWDATA_INDEX_TABLE, index_table)
    for group in range(HWDATA_FLAG_GROUP_COUNT):
        write_words(
            HWDATA_FLAG_GROUPS
            + group * len(HWDATA_FLAG_GROUP_PATTERN) * 4,
            HWDATA_FLAG_GROUP_PATTERN,
        )
    write_words(
        HWDATA_UNASSIGNED_TABLE,
        [0xFFFFFFFF] * HWDATA_UNASSIGNED_COUNT,
    )
    for index, record in enumerate(region_records):
        offset = HWDATA_REGION_RECORDS + index * HWDATA_REGION_RECORD_SIZE
        data[offset:offset + HWDATA_REGION_RECORD_SIZE] = (
            build_region_record(**record)
        )
    struct.pack_into(
        "<Q", data, HWDATA_ADDRESS_27A4,
        _u64(address_27a4, "hardware-data address +0x27a4"),
    )
    struct.pack_into(
        "<Q", data, HWDATA_ADDRESS_27AC,
        _u64(address_27ac, "hardware-data address +0x27ac"),
    )
    for offset in HWDATA_SENTINELS:
        struct.pack_into("<I", data, offset, 0xFFFFFFFF)
    return bytes(data)


def rebuild_hwdata(data):
    """Rebuild captured hardware data solely from parsed numeric parameters."""
    return build_hwdata(**parse_hwdata(data))


# The bounded pre-init address closure contains these 25 fixed DVAs.  A host may
# back them with new physical pages; all embedded references are GPU DVAs.
PREINIT_CLOSURE_PAGE_DVAS = (
    0xFFFFFC2000020000,
    0xFFFFFC200002C000,
    0xFFFFFC2000030000,
    0xFFFFFC200005C000,
    0xFFFFFC20000D4000,
    0xFFFFFC20000DC000,
    0xFFFFFC20000E0000,
    0xFFFFFC20000E4000,
    0xFFFFFC2000110000,
    0xFFFFFC2000188000,
    0xFFFFFC2000190000,
    0xFFFFFC2000194000,
    0xFFFFFC20001A0000,
    0xFFFFFC20001A8000,
    0xFFFFFC20001B0000,
    0xFFFFFC20001B8000,
    0xFFFFFC20015E8000,
    0xFFFFFC20015F0000,
    0xFFFFFC20C0788000,
    0xFFFFFC20C0794000,
    0xFFFFFC20C0798000,
    0xFFFFFC20C079C000,
    0xFFFFFC20C07A0000,
    0xFFFFFC20C07A4000,
    0xFFFFFC20C07A8000,
)

PRIMARY_ROOT_ADDRESS = 0xFFFFFC20001A8000
SECONDARY_ROOT_ADDRESS = 0xFFFFFC20001B0000
REGION_20_ADDRESS = 0xFFFFFC20001A0000
HWDATA_ADDRESS = 0xFFFFFC20C0788000
PRIMARY_MAIN_ADDRESS = 0xFFFFFC20C07A6E40
SECONDARY_MAIN_ADDRESS = 0xFFFFFC20C07AB300

# Stable numeric bytes outside the typed objects above.  Five sparse pages are
# sufficient; the other closure pages are either generated objects or zero.
PREINIT_SPARSE_PAGE_CONSTANTS = {
    0xFFFFFC2000020000: (
        (0x0320, bytes.fromhex("01")),
    ),
    0xFFFFFC200002C000: (
        (0x2A54, bytes.fromhex("01")),
        (0x2A60, bytes.fromhex("44f1020020fcffff")),
        (0x2A90, bytes.fromhex("1f000000713d0a3e48e11a402800000001")),
        (0x2B48, bytes.fromhex("f82a0000401f")),
        (0x2B5A, bytes.fromhex("9841285c0f3d")),
        (0x2B70, bytes.fromhex("ac260000c8")),
        (0x2B8A, bytes.fromhex("c8420000c843c8")),
        (0x2BA8, bytes.fromhex("01000000b05e00000000803e9a99993f")),
        (0x2BD8, bytes.fromhex("0e")),
        (0x2C40, bytes.fromhex(
            "0100000000000000010000000200000001000000010000000100000001"
        )),
        (0x301C, bytes.fromhex(
            "01000000bc0200000a000000ac0d0000e8030000b80b"
        )),
        (0x3064, bytes.fromhex("0100000004")),
        (0x3074, bytes.fromhex(
            "401f0000c8000000a00f00002c010000d00700002c010000e80300002c010000"
            "0000000001000000000070410000a04020000000b004"
        )),
        (0x30B8, bytes.fromhex("4c04")),
        (0x3144, bytes.fromhex("010000005cea020020fcffff")),
        # Primary report channel 14 state zero is split: the AP-owned word is
        # zero at +0x00 and firmware's initial peer is eight at +0x20.  The
        # matching state-one invariant below is five.  Both values are visible
        # at the earliest native first-work boundary and match the completed
        # T8140 report-channel contract.
        (0x33E0, bytes.fromhex("08000000")),
    ),
    0xFFFFFC20000D4000: (
        (0x1C40, bytes.fromhex("05000000")),
    ),
    0xFFFFFC2000194000: (
        (0x3720, bytes.fromhex("01")),
        (0x3750, bytes.fromhex("0200000001")),
        (0x376C, bytes.fromhex("0100000001")),
        (0x3780, bytes.fromhex("01")),
        (0x378C, bytes.fromhex("010000006a18")),
    ),
    0xFFFFFC20C0794000: (
        (0x002D, bytes.fromhex("800b45")),
        (0x006E, bytes.fromhex("2a43")),
        (0x0118, bytes.fromhex("6a18")),
    ),
}


# Four nonzero pages in the complete firmware root are not reachable from the
# descriptor graph above.  They are nevertheless pre-init construction inputs.
# All bytes are stable across two native boots except the explicit u32 on the
# 0x...c0790000 page.  The long 0x7fff table is kept as a generated pattern
# rather than disguised as one captured page blob.
PREINIT_AUXILIARY_PAGE_DVAS = (
    0xFFFFFC2000024000,
    0xFFFFFC20C078C000,
    0xFFFFFC20C0790000,
    0xFFFFFC20C07B8000,
)
AUXILIARY_REPEATED_7FFF_PAGE = 0xFFFFFC20C078C000
AUXILIARY_REPEATED_7FFF_OFFSET = 0x3027
AUXILIARY_REPEATED_7FFF_COUNT = 512
AUXILIARY_DYNAMIC_U32_PAGE = 0xFFFFFC20C0790000
AUXILIARY_DYNAMIC_U32_OFFSET = 0x3F94

_PRE_BETA5_AUXILIARY_SPARSE_PAGE_CONSTANTS = {
    0xFFFFFC2000024000: (
        (0x0E02, bytes.fromhex("1c0020fcffff40001c0020fcffff")),
    ),
    0xFFFFFC20C078C000: (
        (0x1344, bytes.fromhex(
            "400d0300400d030000000000040000000000803f"
        )),
        (0x136C, bytes.fromhex("0100000001")),
        (0x1380, bytes.fromhex(
            "6400000001000000b00400000000000064"
        )),
        (0x13A0, bytes.fromhex(
            "040000000000803f000000000100000001"
        )),
        (0x13C0, bytes.fromhex(
            "6400000001000000b00400000000000064"
        )),
        (0x13DC, bytes.fromhex("01000000010000000100000001")),
        (0x1410, bytes.fromhex(
            "5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f"
            "5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f5c8f823f"
        )),
        (0x1D08, bytes.fromhex("7102")),
        (0x1D14, bytes.fromhex(
            "9f2e7f3f000000005461513b000000008695a53c"
        )),
        (0x1D31, bytes.fromhex(
            "60bd46e40fa94000000000b4c54abd28000000b0040000b004"
        )),
        (0x1D54, bytes.fromhex("b05e")),
        (0x1D88, bytes.fromhex("b004")),
        (0x1DC0, bytes.fromhex("08")),
        (0x1DCF, bytes.fromhex(
            "3f000000000000003f000000009a99993f"
        )),
        (0x1DEA, bytes.fromhex("80470000803e")),
        (0x1DF8, bytes.fromhex("28000000b004")),
        (0x1E0C, bytes.fromhex("b05e")),
        (0x1E18, bytes.fromhex("10")),
        (0x1E21, bytes.fromhex("dc05")),
        (0x1E78, bytes.fromhex(
            "4b000000000000005a0000003200000006000000010000000600000001000000"
            "00000000cdcc4c3f52b87e3fcdcc4c3e0ad7a33b3c4b143f3c4b143f00000000"
            "0000be4285eb294085eb29405e43394164000000b004000064"
        )),
        (0x1EDC, bytes.fromhex("4a0000000000000001")),
        (0x1F10, bytes.fromhex("64")),
        (0x1F30, bytes.fromhex(
            "01040000006400000000000000401f0000c8000000a00f00002c010000d0070000"
            "2c010000e80300002c01000001"
        )),
        (0x1FB4, bytes.fromhex("01")),
        (0x35EA, bytes.fromhex("80470000c842000096442a06")),
        (0x3608, bytes.fromhex("64")),
        (0x3612, bytes.fromhex("c842b004000000000000cdcc4c3fcdcc4c3e")),
        (0x3660, bytes.fromhex("fafbdcdc00000000401f00000000000004")),
        (0x3686, bytes.fromhex("803f00000000285c0f3d")),
        (0x369A, bytes.fromhex("804700009841")),
        (0x36A8, bytes.fromhex("28000000b0040000b004")),
        (0x36BC, bytes.fromhex("f82a")),
        (0x36F0, bytes.fromhex("b004")),
        (0x3908, bytes.fromhex("0200000006000042")),
        (0x3B22, bytes.fromhex(
            "52b87e3f000000000ad7a33b000000000000c843"
        )),
        (0x3B40, bytes.fromhex(
            "80470000c842000000000000c8ba84030000b0040000e80300000000000000803b"
            "45ac26"
        )),
        (0x3B96, bytes.fromhex("b004")),
        (0x3BB2, bytes.fromhex("c8")),
        (0x3C68, bytes.fromhex("b004")),
        (0x3C7C, bytes.fromhex("01")),
        (0x3CC8, bytes.fromhex("01000100000002")),
        (0x3CE6, bytes.fromhex("3f0200000100000001")),
        (0x3D06, bytes.fromhex("400200000100000001")),
        (0x3D26, bytes.fromhex("4102")),
        (0x3DD2, bytes.fromhex(
            "6400000000000100000000000000b05e0000b05e0000b05e"
        )),
        (0x3DFA, bytes.fromhex("803f040000000800000000ee02")),
        (0x3ED4, bytes.fromhex("7c")),
        (0x3EE0, bytes.fromhex(
            "efbd773f000000000821043d00000000713d0a3e"
        )),
        (0x3EFE, bytes.fromhex("804748e11a40")),
        (0x3F0C, bytes.fromhex(
            "28000000b0040000b0040000000000000060bd46b05e"
        )),
        (0x3F2C, bytes.fromhex("f8")),
        (0x3F35, bytes.fromhex("d25a")),
        (0x3F54, bytes.fromhex("b004")),
        (0x3F94, bytes.fromhex("01")),
    ),
    0xFFFFFC20C0790000: (
        (0x0064, bytes.fromhex(
            "320000000100000000000000398e633fabaa2a3f398ee33dabaaaa3ecdccccbe"
            "cdcc4cbf00000000000080470000a0c00000a0c00000000064000000b0040000"
            "64"
        )),
        (0x00AE, bytes.fromhex(
            "fa4578050000000000000e0000004800000018000000005e1a000000000000ca08"
        )),
        (0x00DA, bytes.fromhex("8047")),
        (0x0100, bytes.fromhex(
            "401f000004000000c409000058020000020000000400000032"
        )),
        (0x014A, bytes.fromhex("8047")),
        (0x0158, bytes.fromhex("28000000b004")),
        (0x0228, bytes.fromhex("0100000001")),
        (0x0248, bytes.fromhex("0a000000ac0d0000e8030000b80b")),
        (0x02F4, bytes.fromhex(
            "b0040000b0040000bc020000200000000000000001"
        )),
        (0x0324, bytes.fromhex("04")),
        (0x0332, bytes.fromhex(
            "783f000000000000003d000000000000a040"
        )),
        (0x034E, bytes.fromhex("804700007041")),
        (0x035C, bytes.fromhex("4c040000b0040000b004")),
        (0x0370, bytes.fromhex("b004")),
        (0x03A4, bytes.fromhex("b004")),
        (0x03EE, bytes.fromhex("c842")),
        (0x0400, bytes.fromhex("fafbdcdc000000007d00000001")),
        (0x1070, bytes.fromhex("c077190020fcfffffbfbdcdc0000000001")),
        (0x3086, bytes.fromhex("c8410000c841")),
        (0x3819, bytes.fromhex("807bc020fcffff52543067")),
        (0x3860, bytes.fromhex("01")),
        (0x38A0, bytes.fromhex("4c4643524c465847")),
        (0x38B0, bytes.fromhex("504c5847")),
        (0x38C0, bytes.fromhex("01")),
        (0x3FA0, bytes.fromhex("01")),
        (0x3FAE, bytes.fromhex("3443")),
    ),
    0xFFFFFC20C07B8000: (
        (0x0000, bytes.fromhex("5254306701001d000114")),
    ),
}

# Every object following hardware data in the linear gfx-data allocation moves
# by the hardware-data object's 0x40-byte growth.  The old final c0790000
# constant spills into c0794000 and is therefore represented in the closure
# table above at its new address.
PREINIT_AUXILIARY_SPARSE_PAGE_CONSTANTS = {
    page_va: tuple(
        (
            offset + (
                0x40 if page_va in (
                    0xFFFFFC20C078C000,
                    0xFFFFFC20C0790000,
                ) else 0
            ),
            value,
        )
        for offset, value in records
    )
    for page_va, records in _PRE_BETA5_AUXILIARY_SPARSE_PAGE_CONSTANTS.items()
}


def _place_page_bytes(pages, address, data, name):
    cursor = 0
    while cursor < len(data):
        page_va = address & ~(GRANULE - 1)
        page_offset = address & (GRANULE - 1)
        count = min(len(data) - cursor, GRANULE - page_offset)
        if page_va not in pages:
            raise ValueError("%s lies outside the numeric pre-init pages" % name)
        target = pages[page_va]
        value = data[cursor:cursor + count]
        old = target[page_offset:page_offset + count]
        if any(old) and old != value:
            raise ValueError("%s overlaps different constructed bytes" % name)
        target[page_offset:page_offset + count] = value
        address += count
        cursor += count


def build_preinit_closure(
    primary_root_fields,
    secondary_root_fields,
    primary_main_fields,
    secondary_main_fields,
    hwdata_fields,
):
    """Build all 25 non-code pre-init closure pages from source parameters."""
    pages = {
        address: bytearray(GRANULE) for address in PREINIT_CLOSURE_PAGE_DVAS
    }
    for page_va, records in PREINIT_SPARSE_PAGE_CONSTANTS.items():
        for offset, value in records:
            _place_page_bytes(
                pages, page_va + offset, value,
                "sparse numeric page constant",
            )
    objects = (
        (PRIMARY_ROOT_ADDRESS, build_root(**primary_root_fields), "primary root"),
        (
            SECONDARY_ROOT_ADDRESS,
            build_root(**secondary_root_fields),
            "secondary root",
        ),
        (REGION_20_ADDRESS, build_region_20(), "root +0x20 region"),
        (HWDATA_ADDRESS, build_hwdata(**hwdata_fields), "hardware data"),
        (
            PRIMARY_MAIN_ADDRESS,
            build_main_config(**primary_main_fields),
            "primary main config",
        ),
        (
            SECONDARY_MAIN_ADDRESS,
            build_main_config(**secondary_main_fields),
            "secondary main config",
        ),
    )
    for address, value, name in objects:
        _place_page_bytes(pages, address, value, name)
    status_addresses = (
        primary_root_fields["address_a8"],
        primary_root_fields["address_b0"],
        secondary_root_fields["address_a8"],
    )
    if secondary_root_fields["address_b0"]:
        raise ValueError("observed secondary root +0xb0 must remain zero")
    for address in status_addresses:
        _place_page_bytes(
            pages, address, build_status_record(), "numeric status record"
        )
    return {address: bytes(data) for address, data in pages.items()}


def build_preinit_auxiliary_pages(dynamic_u32):
    """Build the four nonzero firmware-root pages outside the closure."""
    if not 0 <= dynamic_u32 < (1 << 32):
        raise ValueError("numeric auxiliary dynamic value does not fit in u32")
    pages = {
        address: bytearray(GRANULE)
        for address in PREINIT_AUXILIARY_PAGE_DVAS
    }
    for page_va, records in PREINIT_AUXILIARY_SPARSE_PAGE_CONSTANTS.items():
        for offset, value in records:
            _place_page_bytes(
                pages, page_va + offset, value,
                "sparse numeric auxiliary-page constant",
            )
    _place_page_bytes(
        pages,
        AUXILIARY_REPEATED_7FFF_PAGE + AUXILIARY_REPEATED_7FFF_OFFSET,
        struct.pack("<H", 0x7FFF) * AUXILIARY_REPEATED_7FFF_COUNT,
        "numeric auxiliary repeated table",
    )
    _place_page_bytes(
        pages, AUXILIARY_DYNAMIC_U32_PAGE + AUXILIARY_DYNAMIC_U32_OFFSET,
        struct.pack("<I", dynamic_u32),
        "numeric auxiliary dynamic u32",
    )
    return {address: bytes(data) for address, data in pages.items()}


def build_preinit_seed_pages(
    primary_root_fields,
    secondary_root_fields,
    primary_main_fields,
    secondary_main_fields,
    hwdata_fields,
    auxiliary_dynamic_u32,
):
    """Build every nonzero page needed to seed the observed firmware root.

    The result includes the entire 25-page descriptor closure, including its
    zero pages, plus the four nonzero auxiliary pages.  All remaining captured
    RAM leaves in the root are observed zero and may be freshly zero-filled.
    """
    pages = build_preinit_closure(
        primary_root_fields=primary_root_fields,
        secondary_root_fields=secondary_root_fields,
        primary_main_fields=primary_main_fields,
        secondary_main_fields=secondary_main_fields,
        hwdata_fields=hwdata_fields,
    )
    auxiliary = build_preinit_auxiliary_pages(auxiliary_dynamic_u32)
    overlap = set(pages) & set(auxiliary)
    if overlap:
        raise ValueError("numeric closure and auxiliary pages overlap")
    pages.update(auxiliary)
    return pages
