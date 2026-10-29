# SPDX-License-Identifier: GPL-2.0-only
"""Canonical source inputs for the observed T8142/G17G pre-init package.

Every value below is source-level data for the current beta-5 pre-init ABI.
The first three region-record addresses are allocation choices and remain an
explicit parameter.  The fourth address is stable.  No captured byte page is
embedded or loaded by this module.
"""

from . import g17g
from . import g17g_initdata


CANONICAL_REGION_ADDRESSES = (
    0xFFFFFC20C07F8000,
    0xFFFFFC20C0820000,
    0xFFFFFC20C0848000,
    0xFFFFFC20C0880000,
)


PRIMARY_CHANNELS = (
    ((0xFFFFFC20000200C0, 0xFFFFFC20000200D0, 0xFFFFFC20000200E0),
     0xFFFFFC20C0799640),
    ((0xFFFFFC20000201C0, 0xFFFFFC20000201D0, 0xFFFFFC20000201E0),
     0xFFFFFC20C079F640),
    ((0xFFFFFC20000202C0, 0xFFFFFC20000202D0, 0xFFFFFC20000202E0),
     0xFFFFFC20C07A5640),
    ((0xFFFFFC2000020080, 0xFFFFFC2000020090, 0xFFFFFC20000200A0),
     0xFFFFFC20C0797E40),
    ((0xFFFFFC2000020180, 0xFFFFFC2000020190, 0xFFFFFC20000201A0),
     0xFFFFFC20C079DE40),
    ((0xFFFFFC2000020280, 0xFFFFFC2000020290, 0xFFFFFC20000202A0),
     0xFFFFFC20C07A3E40),
    ((0xFFFFFC2000020040, 0xFFFFFC2000020050, 0xFFFFFC2000020060),
     0xFFFFFC20C0796640),
    ((0xFFFFFC2000020140, 0xFFFFFC2000020150, 0xFFFFFC2000020160),
     0xFFFFFC20C079C640),
    ((0xFFFFFC2000020240, 0xFFFFFC2000020250, 0xFFFFFC2000020260),
     0xFFFFFC20C07A2640),
    ((0xFFFFFC2000020000, 0xFFFFFC2000020010, 0xFFFFFC2000020020),
     0xFFFFFC20C0794E40),
    ((0xFFFFFC2000020100, 0xFFFFFC2000020110, 0xFFFFFC2000020120),
     0xFFFFFC20C079AE40),
    ((0xFFFFFC2000020200, 0xFFFFFC2000020210, 0xFFFFFC2000020220),
     0xFFFFFC20C07A0E40),
    ((0xFFFFFC2000020300, 0xFFFFFC2000020310, 0xFFFFFC2000020320),
     0xFFFFFC20C07A7300),
    ((0xFFFFFC200002F1C0, 0xFFFFFC200002F440, 0xFFFFFC200002F200),
     0xFFFFFC2000033C40),
    ((0xFFFFFC200002F3C0, 0xFFFFFC20000D5C40, 0xFFFFFC200002F400),
     0xFFFFFC20000DEC40),
    ((0xFFFFFC200005C440, 0, 0), 0),
    ((0, 0, 0), 0),
)

SECONDARY_CHANNELS = (
    *((((0, 0, 0), 0),) * 12),
    ((0xFFFFFC2000197700, 0xFFFFFC2000197710, 0xFFFFFC2000197720),
     0xFFFFFC20C07AB7C0),
    ((0xFFFFFC20000E3480, 0xFFFFFC20000E3700, 0xFFFFFC20000E34C0),
     0xFFFFFC20000E7F00),
    ((0xFFFFFC20000E3680, 0xFFFFFC2000189F00, 0xFFFFFC20000E36C0),
     0xFFFFFC2000192F00),
    ((0xFFFFFC2000110700, 0, 0), 0),
    ((0, 0, 0), 0),
)

# Nonempty register-map records, keyed by their position in the 60-entry
# numeric table.  Rows are field_00, field_08, word_10, word_14, field_18,
# word_20, word_24.  Empty flag-only records are listed separately.
REGISTER_RECORD_ROWS = {
    0: (0x381014000, 0xFFFFFC2180000000, 0x4000, 0x4000, 0, 2, 0),
    3: (0x220104000, 0xFFFFFC2180008000, 0x18000, 0x18000, 0, 2, 0),
    8: (0x3A1350000, 0xFFFFFC2180028000, 0x4000, 0x4000, 0, 2, 0),
    9: (0x3803D0000, 0xFFFFFC2180030000, 0x4000, 0x4000, 0, 2, 0),
    10: (0x3803C0000, 0xFFFFFC2180038000, 0x4000, 0x4000, 0, 0, 0),
    12: (0x42165C000, 0xFFFFFC2180040000, 0x4000, 0x4000, 0, 2, 0),
    14: (0x380280000, 0xFFFFFC2180048000, 0x8000, 0x8000, 0, 0, 0),
    15: (0x38C840000, 0xFFFFFC2180058000, 0x24000, 0x24000, 0, 2, 0),
    17: (0x580000000, 0xFFFFFC2180080000, 0x21400, 0x21400, 0, 2, 0),
    22: (0x581000000, 0xFFFFFC21800A8000, 0x8000, 0x8000, 0, 2, 0),
    24: (0x580EC0000, 0xFFFFFC21800B8000, 0x10000, 0x10000, 0, 2, 0),
    31: (0x580D04000, 0xFFFFFC21800D0000, 0x8000, 0x8000,
         0xD04000, 2, 0),
    32: (0x580D0D000, 0xFFFFFC21800E1000, 0x1000, 0x1000,
         0xD0D000, 2, 0),
    33: (0x580D50000, 0xFFFFFC21800E8000, 0x10000, 0x10000,
         0xD50000, 2, 0),
    34: (0x580D10000, 0xFFFFFC2180100000, 0x4000, 0x4000,
         0xD10000, 2, 0),
    36: (0x580D40000, 0xFFFFFC2180108000, 0x4000, 0x4000,
         0xD40000, 2, 0),
    37: (0x580D60000, 0xFFFFFC2180110000, 0x8000, 0x8000,
         0xD60000, 2, 0),
    40: (0x580E00000, 0xFFFFFC2180120000, 0x4000, 0x4000,
         0xE00000, 2, 0),
    44: (0x580E08000, 0xFFFFFC2180128000, 0x10000, 0x8000, 0, 2, 0),
    46: (0x580E33800, 0xFFFFFC2180143800, 0x4000, 0x4000, 0, 2, 0),
    47: (0x580E35000, 0xFFFFFC2180151000, 0x4000, 0x4000, 0, 2, 0),
    56: (0x580014400, 0xFFFFFC2180160400, 0x400, 0x400,
         0x14400, 0, 0),
}

REGISTER_FLAG_ONLY_INDICES = (
    2, 5, 6, 7, 25, 26, 27, 35, 38, 39, 42, 43, 45, 48,
    52, 53, 54, 55, 58,
)

FREQUENCY_TABLE = (
    0, 338, 486, 636, 796, 888, 988, 1084, 1182, 1278, 1374, 1470, 1578,
)
CORE_TABLE = (125, 625, 650, 680, 705, 735, 755, 795, 835, 865, 890, 945, 1010)
MEMORY_TABLE = (770, 770, 770, 770, 770, 770, 770, 795, 835, 865, 890, 945, 1010)
SCALE_TABLE = (1065520988,) * 13
RELATIVE_TABLE_A = (
    0, 0x41B44397, 0x41EC9152, 0x42190D85, 0x42404B32,
    0x4262EE42, 0x4282173C, 0x429BD98F, 0x42A558B6,
    0x42AB4981, 0x42B03CD5, 0x42BB20F3, 0x42C80000,
)
RELATIVE_TABLE_B = (
    0, 0x413EF7BE, 0x41C04210, 0x4213BDF0, 0x42316B5B,
    0x4251AD6C, 0x4270A529, 0x42882108, 0x42979CE7,
    0x42A718C6, 0x42B694A5, 0x42C80000, 0,
)
INDEX_TABLE = tuple(range(16))

REGISTER_KEYS = (
    "field_00", "field_08", "word_10", "word_14",
    "field_18", "word_20", "word_24",
)


def canonical_register_records():
    records = [
        dict(zip(REGISTER_KEYS, (0,) * 7))
        for _ in range(g17g_initdata.HWDATA_REGISTER_RECORD_COUNT)
    ]
    for index, row in REGISTER_RECORD_ROWS.items():
        records[index] = dict(zip(REGISTER_KEYS, row))
    for index in REGISTER_FLAG_ONLY_INDICES:
        records[index]["word_20"] = 2
    return tuple(records)




def canonical_hwdata_fields(region_addresses=CANONICAL_REGION_ADDRESSES):
    if len(region_addresses) != 4:
        raise ValueError("canonical G17G package requires four region addresses")
    if any(address & (g17g_initdata.GRANULE - 1) for address in region_addresses):
        raise ValueError("canonical G17G region addresses must be page aligned")
    region_shapes = (
        (0x100, 0x1848000, 0x72, 0x800, 0x40, 0),
        (0, 0x1870000, 0x72, 0x800, 0x40, 1),
        (0, 0x1898000, 0x72, 0x800, 0x40, 2),
        (0, 0x18C0000, 0x72, 0x800, 0x40, 3),
    )
    region_records = tuple(
        {
            "word_00": shape[0], "word_04": shape[1],
            "word_08": shape[2], "address_0c": address,
            "word_14": shape[3], "word_18": shape[4],
            "word_1c": shape[5],
        }
        for address, shape in zip(region_addresses, region_shapes)
    )
    return {
        "header_address_20": 0x2FFFFFF8000,
        "header_address_28": 0xFFFFFC2181400000,
        "register_records": canonical_register_records(),
        "chip_id": g17g.CHIP_ID,
        "frequency_table": FREQUENCY_TABLE,
        "core_table": CORE_TABLE,
        "memory_table": MEMORY_TABLE,
        "scale_table": SCALE_TABLE,
        "relative_table_a": RELATIVE_TABLE_A,
        "relative_table_b": RELATIVE_TABLE_B,
        "index_table": INDEX_TABLE,
        "region_records": region_records,
        "address_27a4": 0xFFFFFC20015E0000,
        "address_27ac": 0xFFFFFC20015D8000,
    }


def canonical_preinit_fields(region_addresses=CANONICAL_REGION_ADDRESSES):
    """Return all source parameters accepted by ``build_preinit_closure``."""
    return {
        "primary_root_fields": {
            "version": g17g_initdata.ROOT_VERSION_VALUES,
            "region_08": 0xFFFFFC20001B8000,
            "main_config": 0xFFFFFC20C07A6E40,
            "region_20": 0xFFFFFC20001A0000,
            "instance_index": 0,
            "address_a8": 0xFFFFFC200002F180,
            "address_b0": 0xFFFFFC2000020340,
            "secondary_address_b8": 0,
            "secondary_address_c0": 0,
        },
        "secondary_root_fields": {
            "version": g17g_initdata.ROOT_VERSION_VALUES,
            "region_08": 0xFFFFFC20001B8000,
            "main_config": 0xFFFFFC20C07AB300,
            "region_20": 0xFFFFFC20001A0000,
            "instance_index": 1,
            "address_a8": 0xFFFFFC20000E3440,
            "address_b0": 0,
            "secondary_address_b8": 0xFFFFFC200002EA80,
            "secondary_address_c0": 0xFFFFFC2000197740,
        },
        "primary_main_fields": {
            "hwdata_address": 0xFFFFFC20C0788000,
            "repeated_address": 0xFFFFFC20C0794D80,
            "channels": PRIMARY_CHANNELS,
            "address_array": (
                0xFFFFFC20C078A880, 0xFFFFFC20C078B4C0,
                0xFFFFFC20C078C540, 0xFFFFFC20C0794500,
                0xFFFFFC20C0794580,
            ),
            "region_triples": (
                (0xFFFFFC20C07E0000, 0x1838000, 0x72),
                (0xFFFFFC20015E8000, 0x1840000, 0x72),
                (0xFFFFFC20015F0000, 0, 0),
            ),
            "word_300": 0,
            "word_3e0": 0xFF,
            "secondary_address_481": 0,
            "word_4c0": 0x15,
        },
        "secondary_main_fields": {
            "hwdata_address": 0xFFFFFC20C0788000,
            "repeated_address": 0xFFFFFC20C0794D80,
            "channels": SECONDARY_CHANNELS,
            "address_array": (0, 0, 0, 0, 0),
            "region_triples": (
                (0, 0x1838000, 0x72),
                (0, 0x1840000, 0x72),
                (0, 0, 0),
            ),
            "word_300": 0xC,
            "word_3e0": 0,
            "secondary_address_481": 0xFFFFFC20C078D380,
            "word_4c0": 0x2A,
        },
        "hwdata_fields": canonical_hwdata_fields(region_addresses),
    }


def build_canonical_seed_pages(
    auxiliary_dynamic_u32,
    region_addresses=CANONICAL_REGION_ADDRESSES,
):
    return g17g_initdata.build_preinit_seed_pages(
        **canonical_preinit_fields(region_addresses),
        auxiliary_dynamic_u32=auxiliary_dynamic_u32,
    )
