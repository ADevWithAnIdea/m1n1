# SPDX-License-Identifier: MIT
"""Source description of the established G17P cold-boot mapping topology.

This module contains no captured memory or firmware objects.  It records only
the page addresses, leaf attributes, context tags, and cross-context physical
alias relationships established by the cold-boot mapping experiments.  Runs
are (first_dva, page_count, pte_attribute_bits); the physical backing is
allocated fresh by the boot path.
"""

PAGE_SIZE = 0x4000

# Physical placement is part of the cold first-render ABI on T8140.  These
# are address-only measurements: no page body, table body, or firmware object
# is retained here.  Each leaf run is (first DVA, first PA, count, PA stride).
# Most firmware-private arenas are allocated from the top down, hence the
# negative stride.  The live boot path clears each destination and fills it
# exclusively from its source constructors before making it visible.
NATIVE_FIRMWARE_LEAF_RUNS = (
    (0xfffffc2000000000, 0x100594f0000, 1, 0),
    (0xfffffc2000010000, 0x10054448000, 2, -PAGE_SIZE),
    (0xfffffc2000020000, 0x10034b54000, 86, -PAGE_SIZE),
    (0xfffffc2000178000, 0x100351fc000, 8, -PAGE_SIZE),
    (0xfffffc20001a0000, 0x100351dc000, 1, 0),
    (0xfffffc20001a8000, 0x100351d8000, 1, 0),
    (0xfffffc20001b0000, 0x100351d4000, 1, 0),
    (0xfffffc20001b8000, 0x100351d0000, 1, 0),
    (0xfffffc20001c0000, 0x100351c4000, 1, 0),
    (0xfffffc20001c8000, 0x100351b0000, 1, 0),
    (0xfffffc20001d0000, 0x100351a0000, 1, 0),
    (0xfffffc20001d8000, 0x100543d8000, 8, -PAGE_SIZE),
    (0xfffffc2000200000, 0x100543b8000, 8, -PAGE_SIZE),
    (0xfffffc20015d8000, 0x10035144000, 1, 0),
    (0xfffffc20015e0000, 0x1003513c000, 1, 0),
    (0xfffffc20015e8000, 0x10035130000, 1, 0),
    (0xfffffc20015f0000, 0x1002d3d4000, 1, 0),
    (0xfffffc20015f8000, 0x10059530000, 1, 0),
    (0xfffffc2001600000, 0x1005a184000, 1, 0),
    (0xfffffc2001608000, 0x10054458000, 1, 0),
    (0xfffffc2001610000, 0x100543f0000, 1, 0),
    (0xfffffc2001618000, 0x10054438000, 1, 0),
    (0xfffffc2001620000, 0x100543e0000, 1, 0),
    (0xfffffc2001628000, 0x100543dc000, 1, 0),
    (0xfffffc20c0000000, 0x1005444c000, 1, 0),
    (0xfffffc20c0008000, 0x10054440000, 2, -PAGE_SIZE),
    (0xfffffc20c0018000, 0x100350ec000, 37, -PAGE_SIZE),
    (0xfffffc20c00b0000, 0x10035058000, 129, -PAGE_SIZE),
    (0xfffffc20c02b8000, 0x10034e54000, 22, -PAGE_SIZE),
    (0xfffffc20c0310000, 0x100355fc000, 16, -PAGE_SIZE),
    (0xfffffc20c0358000, 0x100355bc000, 61, -PAGE_SIZE),
    (0xfffffc20c0450000, 0x100354c8000, 85, -PAGE_SIZE),
    (0xfffffc20c05a8000, 0x10035374000, 1, 0),
    (0xfffffc20c05b0000, 0x10035370000, 1, 0),
    (0xfffffc20c05b8000, 0x1003536c000, 2, -PAGE_SIZE),
    (0xfffffc20c05c8000, 0x10035364000, 2, -PAGE_SIZE),
    (0xfffffc20c05d8000, 0x1003535c000, 3, -PAGE_SIZE),
    (0xfffffc20c05e8000, 0x10035350000, 4, -PAGE_SIZE),
    (0xfffffc20c0600000, 0x10035340000, 6, -PAGE_SIZE),
    (0xfffffc20c0620000, 0x10035328000, 1, 0),
    (0xfffffc20c0628000, 0x10035324000, 1, 0),
    (0xfffffc20c0630000, 0x10035320000, 13, -PAGE_SIZE),
    (0xfffffc20c0668000, 0x100352ec000, 50, -PAGE_SIZE),
    (0xfffffc20c0738000, 0x10035224000, 10, -PAGE_SIZE),
    (0xfffffc20c0760000, 0x100359fc000, 3, -PAGE_SIZE),
    (0xfffffc20c0770000, 0x100359f0000, 4, -PAGE_SIZE),
    (0xfffffc20c0788000, 0x10034c3c000, 2, -0xc0000),
    (0xfffffc20c0790000, 0x10034b78000, 8, -PAGE_SIZE),
    (0xfffffc20c07b8000, 0x100594e8000, 1, 0),
    (0xfffffc20c07c0000, 0x100351a8000, 1, 0),
    (0xfffffc20c07c8000, 0x100351c0000, 1, 0),
    (0xfffffc20c07d0000, 0x1003512c000, 8, -PAGE_SIZE),
    (0xfffffc20c07f8000, 0x1003510c000, 8, -PAGE_SIZE),
    (0xfffffc20c0820000, 0x100594f4000, 1, 0),
    (0xfffffc20c0828000, 0x1005445c000, 1, 0),
    (0xfffffc20c0830000, 0x100543f4000, 1, 0),
    (0xfffffc20c0838000, 0x1005c0bc000, 2, -PAGE_SIZE),
    (0xfffffc20c0848000, 0x1005c0cc000, 4, -PAGE_SIZE),
    (0xfffffc20c0860000, 0x100543e4000, 1, 0),
    (0xfffffc2180000000, 0x301014000, 1, 0),
    (0xfffffc2180008000, 0x220104000, 6, PAGE_SIZE),
    (0xfffffc2180028000, 0x3003d0000, 1, 0),
    (0xfffffc2180030000, 0x3003c0000, 1, 0),
    (0xfffffc2180038000, 0x40165c000, 1, 0),
    (0xfffffc2180040000, 0x300280000, 2, PAGE_SIZE),
    (0xfffffc2180050000, 0x480000000, 9, PAGE_SIZE),
    (0xfffffc2180078000, 0x481000000, 2, PAGE_SIZE),
    (0xfffffc2180088000, 0x480d04000, 2, PAGE_SIZE),
    (0xfffffc2180098000, 0x480d0c000, 1, 0),
    (0xfffffc21800a0000, 0x480d58000, 2, PAGE_SIZE),
    (0xfffffc21800b0000, 0x480d10000, 1, 0),
    (0xfffffc21800b8000, 0x480d40000, 1, 0),
    (0xfffffc21800c0000, 0x480d60000, 1, 0),
    (0xfffffc21800c8000, 0x480e00000, 1, 0),
    (0xfffffc21800d0000, 0x480e08000, 2, PAGE_SIZE),
    (0xfffffc21800e0000, 0x480e1c000, 1, 0),
    (0xfffffc21800e8000, 0x480e1c000, 2, PAGE_SIZE),
)

NATIVE_TABLE_TARGETS = {
    "context0": {
        (): 0x10034bcc000,
        (7,): 0x10035138000,
        (7, 0): 0x10035134000,
    },
    "render_low": {
        (): 0x10057ba0000,
        (1,): 0x10054454000,
        (1, 0): 0x10054450000,
        (7,): 0x1005a18c000,
        (7, 0): 0x1005a188000,
        (16,): 0x1005bb48000,
        (16, 0): 0x1005bb44000,
        (47,): 0x10057b94000,
        (47, 2047): 0x10057b90000,
    },
    "firmware_high": {
        (): 0x10021598000,
        (2,): 0x101fff34000,
        (2, 0): 0x100351ac000,
        (2, 96): 0x100351a4000,
        (2, 192): 0x100359e0000,
    },
}

ROOT_CONTEXT_IDS = {
    0: 0,
    1: 64,
    2: 65535,
    3: 65535,
    4: 65535,
    5: 65535,
    6: 65535,
    7: 1,
    8: 65535,
    9: 65535,
    10: 65535,
    11: 65535,
}

CONTEXT0_FIRMWARE_PEER_RUNS = (
    (0x7000000000, 37, 0xfffffc20c0018000),
    (0x7000098000, 129, 0xfffffc20c00b0000),
    (0x70002a0000, 38, 0xfffffc20c02b8000),
    (0x7000340000, 61, 0xfffffc20c0358000),
    (0x7000438000, 8, 0xfffffc20001d8000),
    (0x7000460000, 8, 0xfffffc2000200000),
    (0x7001838000, 1, 0xfffffc20015e0000),
    (0x7001840000, 1, 0xfffffc20015e8000),
    (0x7001848000, 8, 0xfffffc20c07d0000),
    (0x7001870000, 8, 0xfffffc20c07f8000),
)

_ROOT_0_RUNS = (
    (0x7000000000, 37, 0x0080000000000c8b),
    (0x7000098000, 129, 0x0080000000000c8b),
    (0x70002a0000, 38, 0x0080000000000c8b),
    (0x7000340000, 61, 0x0080000000000c8b),
    (0x7000438000, 8, 0x0080000000000c8b),
    (0x7000460000, 8, 0x0080000000000c8b),
    (0x7001838000, 1, 0x00c0000000000c8b),
    (0x7001840000, 1, 0x00c0000000000c8b),
    (0x7001848000, 8, 0x00c0000000000c8b),
    (0x7001870000, 8, 0x00c0000000000c8b),
)

_ROOT_1_RUNS = (
    (0xfffffc2000000000, 1, 0x00c000000000044b),
    (0xfffffc2000010000, 2, 0x00c000000000044b),
    (0xfffffc2000020000, 94, 0x00c000000000044b),
    (0xfffffc20001a0000, 1, 0x008000000000044b),
    (0xfffffc20001a8000, 1, 0x008000000000044b),
    (0xfffffc20001b0000, 1, 0x008000000000044b),
    (0xfffffc20001b8000, 1, 0x008000000000044b),
    (0xfffffc20001c0000, 1, 0x00c000000000044b),
    (0xfffffc20001c8000, 1, 0x00c000000000044b),
    (0xfffffc20001d0000, 1, 0x00c000000000044b),
    (0xfffffc20001d8000, 8, 0x00c000000000044b),
    (0xfffffc2000200000, 8, 0x00c000000000044b),
    (0xfffffc20015d8000, 1, 0x00c000000000044b),
    (0xfffffc20015e0000, 1, 0x00c000000000044b),
    (0xfffffc20015e8000, 1, 0x00c000000000044b),
    (0xfffffc20015f0000, 1, 0x00c000000000044b),
    (0xfffffc20015f8000, 1, 0x00c000000000044b),
    (0xfffffc2001600000, 1, 0x00c000000000044b),
    (0xfffffc2001608000, 1, 0x00c000000000044b),
    (0xfffffc2001610000, 1, 0x008000000000044b),
    (0xfffffc2001618000, 1, 0x00c000000000044b),
    (0xfffffc2001620000, 1, 0x00c000000000044b),
    (0xfffffc2001628000, 1, 0x00c000000000044b),
    (0xfffffc2001630000, 1, 0x008000000000044b),
    (0xfffffc20c0000000, 1, 0x00c0000000000443),
    (0xfffffc20c0008000, 2, 0x00c0000000000443),
    (0xfffffc20c0018000, 37, 0x00c0000000000443),
    (0xfffffc20c00b0000, 129, 0x00c0000000000443),
    (0xfffffc20c02b8000, 38, 0x00c0000000000443),
    (0xfffffc20c0358000, 61, 0x00c0000000000443),
    (0xfffffc20c0450000, 85, 0x00c0000000000443),
    (0xfffffc20c05a8000, 1, 0x00c0000000000443),
    (0xfffffc20c05b0000, 1, 0x00c0000000000443),
    (0xfffffc20c05b8000, 2, 0x00c0000000000443),
    (0xfffffc20c05c8000, 2, 0x00c0000000000443),
    (0xfffffc20c05d8000, 3, 0x00c0000000000443),
    (0xfffffc20c05e8000, 4, 0x00c0000000000443),
    (0xfffffc20c0600000, 6, 0x00c0000000000443),
    (0xfffffc20c0620000, 1, 0x00c0000000000443),
    (0xfffffc20c0628000, 1, 0x00c0000000000443),
    (0xfffffc20c0630000, 13, 0x00c0000000000443),
    (0xfffffc20c0668000, 50, 0x00c0000000000443),
    (0xfffffc20c0738000, 13, 0x00c0000000000443),
    (0xfffffc20c0770000, 4, 0x00c0000000000443),
    (0xfffffc20c0788000, 10, 0x00c0000000000443),
    (0xfffffc20c07b8000, 1, 0x00c0000000000443),
    (0xfffffc20c07c0000, 1, 0x00c0000000000443),
    (0xfffffc20c07c8000, 1, 0x00c0000000000443),
    (0xfffffc20c07d0000, 8, 0x00c0000000000443),
    (0xfffffc20c07f8000, 8, 0x00c0000000000443),
    (0xfffffc20c0820000, 1, 0x00c0000000000443),
    (0xfffffc20c0828000, 1, 0x00c0000000000443),
    (0xfffffc20c0830000, 1, 0x00c0000000000443),
    (0xfffffc20c0838000, 1, 0x00c0000000000443),
    (0xfffffc20c0840000, 2, 0x00c0000000000443),
    (0xfffffc20c0850000, 4, 0x00c0000000000443),
    (0xfffffc20c0868000, 1, 0x00c0000000000443),
)

_ROOT_7_RUNS = (
    (0x1000000000, 4, 0x0080000000000c8b),
    (0x1000018000, 2, 0x0080000000000c8b),
    (0x1000028000, 2, 0x0080000000000c8b),
    (0x1000038000, 2, 0x0080000000000c8b),
    (0x1000048000, 2, 0x0080000000000c8b),
    (0x1000058000, 2, 0x00c0000000000c8b),
    (0x1000068000, 3, 0x00c0000000000c8b),
    (0x1000078000, 1, 0x00c0000000000c8b),
    (0x1000080000, 1, 0x00c0000000000c8b),
    (0x1000088000, 8, 0x00c0000000000c8b),
    (0x10000b0000, 8, 0x00c0000000000c8b),
    (0x10000d8000, 8, 0x00c0000000000c8b),
    (0x1000100000, 8, 0x00c0000000000c8b),
    (0x1000128000, 8, 0x00c0000000000c8b),
    (0x1000150000, 8, 0x00c0000000000c8b),
    (0x1000178000, 1, 0x00c0000000000c8b),
    (0x1000180000, 2, 0x00c0000000000c8b),
    (0x1000190000, 4, 0x00c0000000000c8b),
    (0x10001a8000, 1, 0x00c0000000000c8b),
    (0x10001b0000, 34, 0x00c0000000000c8b),
    (0x1000240000, 2, 0x00c0000000000c8b),
    (0x1000250000, 8, 0x00c0000000000c8b),
    (0x1000278000, 8, 0x00c0000000000c8b),
    (0x10002a0000, 8, 0x00c0000000000c8b),
    (0x10002c8000, 8, 0x00c0000000000c8b),
    (0x10002f0000, 8, 0x00c0000000000c8b),
    (0x1000318000, 8, 0x00c0000000000c8b),
    (0x1000340000, 8, 0x00c0000000000c8b),
    (0x1000368000, 8, 0x00c0000000000c8b),
    (0x1000390000, 8, 0x00c0000000000c8b),
    (0x10003b8000, 8, 0x00c0000000000c8b),
    (0x10003e0000, 8, 0x00c0000000000c8b),
    (0x1000408000, 8, 0x00c0000000000c8b),
    (0x1000430000, 8, 0x00c0000000000c8b),
    (0x1000458000, 8, 0x00c0000000000c8b),
    (0x1000480000, 8, 0x00c0000000000c8b),
    (0x10004a8000, 8, 0x00c0000000000c8b),
    (0x10004d0000, 8, 0x00c0000000000c8b),
    (0x10004f8000, 8, 0x00c0000000000c8b),
    (0x1000520000, 8, 0x00c0000000000c8b),
    (0x1000548000, 8, 0x00c0000000000c8b),
    (0x1000570000, 8, 0x00c0000000000c8b),
    (0x1000598000, 8, 0x00c0000000000c8b),
    (0x10005c0000, 8, 0x00c0000000000c8b),
    (0x10005e8000, 8, 0x00c0000000000c8b),
    (0x1000610000, 8, 0x00c0000000000c8b),
    (0x1000638000, 8, 0x00c0000000000c8b),
    (0x7000000000, 128, 0x00c0000000000c8b),
    (0x7000208000, 4, 0x00c0000000000c8b),
    (0x7000220000, 64, 0x00c0000000000c8b),
    (0x7000328000, 64, 0x00c0000000000c8b),
    (0x7000430000, 64, 0x00c0000000000c8b),
    (0x7000538000, 64, 0x00c0000000000c8b),
    (0x7000640000, 64, 0x00c0000000000c8b),
    (0x7000748000, 64, 0x00c0000000000c8b),
    (0x7000850000, 64, 0x00c0000000000c8b),
    (0x7000958000, 64, 0x00c0000000000c8b),
    (0x7000a60000, 64, 0x00c0000000000c8b),
    (0x7000b68000, 64, 0x00c0000000000c8b),
    (0x7000c70000, 64, 0x00c0000000000c8b),
    (0x7000d78000, 64, 0x00c0000000000c8b),
    (0x7000e80000, 64, 0x00c0000000000c8b),
    (0x7000f88000, 64, 0x00c0000000000c8b),
    (0x7001090000, 64, 0x00c0000000000c8b),
    (0x7001198000, 64, 0x00c0000000000c8b),
    (0x70012a0000, 64, 0x00c0000000000c8b),
    (0x70013a8000, 64, 0x00c0000000000c8b),
    (0x70014b0000, 64, 0x00c0000000000c8b),
    (0x70015b8000, 64, 0x00c0000000000c8b),
    (0x70016c0000, 64, 0x00c0000000000c8b),
    (0x70017c8000, 64, 0x00c0000000000c8b),
    (0x10000000000, 4, 0x0080000000000c8b),
    (0x10000020000, 8, 0x00c0000000000c8b),
    (0x10000048000, 4, 0x0080000000000c8b),
    (0x10000060000, 8, 0x00c0000000000c8b),
    (0x10000088000, 1559, 0x00c0000000000c8b),
    (0x100018e8000, 29, 0x0080000000000c8b),
    (0x10001960000, 2, 0x0080000000000c8b),
    (0x10001970000, 2, 0x0080000000000c8b),
    (0x10001980000, 2, 0x00c0000000000c8b),
    (0x10001990000, 2, 0x00c0000000000c8b),
    (0x100019a0000, 64, 0x00c0000000000c8b),
    (0x10001aa8000, 2, 0x00c0000000000c8b),
    (0x10001ab8000, 2, 0x0080000000000c8b),
    (0x10001ac8000, 2, 0x0080000000000c8b),
    (0x10001ad8000, 2, 0x0080000000000c8b),
    (0x10001ae8000, 2, 0x0080000000000c8b),
    (0x10001af8000, 48, 0x0080000000000c8b),
    (0x10001bc0000, 16, 0x00c0000000000c8b),
    (0x2ffffff8000, 1, 0x00c0000000000c8b),
)

# Exact render-low leaf inventory of the clean first-partial topology.  This
# is smaller than the older mature render-root inventory above and occupies
# hardware slot 2 rather than slot 7.
_PARTIAL_RENDER_RUNS = (
    (0x1000000000, 4, 0x0080000000000c8b),
    (0x1000018000, 2, 0x0080000000000c8b),
    (0x1000028000, 2, 0x0080000000000c8b),
    (0x1000038000, 2, 0x0080000000000c8b),
    (0x1000048000, 2, 0x0080000000000c8b),
    (0x1000058000, 2, 0x00c0000000000c8b),
    (0x1000068000, 3, 0x00c0000000000c8b),
    (0x1000078000, 1, 0x00c0000000000c8b),
    (0x1000080000, 1, 0x00c0000000000c8b),
    (0x1000088000, 8, 0x00c0000000000c8b),
    (0x10000b0000, 8, 0x00c0000000000c8b),
    (0x10000d8000, 8, 0x00c0000000000c8b),
    (0x1000100000, 8, 0x00c0000000000c8b),
    (0x1000128000, 8, 0x00c0000000000c8b),
    (0x1000150000, 8, 0x00c0000000000c8b),
    (0x1000178000, 1, 0x00c0000000000c8b),
    (0x1000180000, 2, 0x00c0000000000c8b),
    (0x1000190000, 4, 0x00c0000000000c8b),
    (0x10001a8000, 1, 0x00c0000000000c8b),
    (0x10001b0000, 9, 0x00c0000000000c8b),
    (0x10001d8000, 1, 0x00c0000000000c8b),
    (0x10001e0000, 8, 0x00c0000000000c8b),
    (0x1000208000, 8, 0x00c0000000000c8b),
    (0x7000000000, 128, 0x00c0000000000c8b),
    (0x7000208000, 4, 0x00c0000000000c8b),
    (0x7000220000, 64, 0x00c0000000000c8b),
    (0x7000328000, 64, 0x00c0000000000c8b),
    (0x7000430000, 64, 0x00c0000000000c8b),
    (0x7000538000, 64, 0x00c0000000000c8b),
    (0x7000640000, 64, 0x00c0000000000c8b),
    (0x7000748000, 64, 0x00c0000000000c8b),
    (0x7000850000, 64, 0x00c0000000000c8b),
    (0x7000958000, 64, 0x00c0000000000c8b),
    (0x7000a60000, 64, 0x00c0000000000c8b),
    (0x7000b68000, 64, 0x00c0000000000c8b),
    (0x7000c70000, 64, 0x00c0000000000c8b),
    (0x7000d78000, 64, 0x00c0000000000c8b),
    (0x7000e80000, 64, 0x00c0000000000c8b),
    (0x7000f88000, 64, 0x00c0000000000c8b),
    (0x7001090000, 64, 0x00c0000000000c8b),
    (0x7001198000, 64, 0x00c0000000000c8b),
    (0x70012a0000, 64, 0x00c0000000000c8b),
    (0x70013a8000, 64, 0x00c0000000000c8b),
    (0x70014b0000, 64, 0x00c0000000000c8b),
    (0x70015b8000, 64, 0x00c0000000000c8b),
    (0x70016c0000, 64, 0x00c0000000000c8b),
    (0x70017c8000, 64, 0x00c0000000000c8b),
    (0x70018d0000, 64, 0x00c0000000000c8b),
    (0x70019d8000, 64, 0x00c0000000000c8b),
    (0x7001ae0000, 64, 0x00c0000000000c8b),
    (0x7001be8000, 64, 0x00c0000000000c8b),
    (0x7001cf0000, 64, 0x00c0000000000c8b),
    (0x7001df8000, 64, 0x00c0000000000c8b),
    (0x10000000000, 4, 0x0080000000000c8b),
    (0x10000018000, 8, 0x00c0000000000c8b),
    (0x10000040000, 4, 0x0080000000000c8b),
    (0x10000058000, 4, 0x00c0000000000c8b),
    (0x10000070000, 4, 0x00c0000000000c8b),
    (0x10000088000, 4, 0x00c0000000000c8b),
    (0x100000a0000, 4, 0x00c0000000000c8b),
    (0x100000b8000, 4, 0x00c0000000000c8b),
    (0x100000d0000, 4, 0x00c0000000000c8b),
    (0x100000e8000, 4, 0x00c0000000000c8b),
    (0x10000100000, 4, 0x00c0000000000c8b),
    (0x10000118000, 8, 0x00c0000000000c8b),
    (0x10000140000, 29, 0x0080000000000c8b),
    (0x100001b8000, 2, 0x0080000000000c8b),
    (0x100001c8000, 2, 0x0080000000000c8b),
    (0x100001d8000, 2, 0x00c0000000000c8b),
    (0x100001e8000, 2, 0x00c0000000000c8b),
    (0x100001f8000, 64, 0x00c0000000000c8b),
    (0x10000300000, 2, 0x00c0000000000c8b),
    (0x10000310000, 2, 0x0080000000000c8b),
    (0x10000320000, 2, 0x0080000000000c8b),
    (0x10000330000, 2, 0x0080000000000c8b),
    (0x10000340000, 2, 0x0080000000000c8b),
    (0x10000350000, 48, 0x0080000000000c8b),
    (0x2ffffff8000, 1, 0x00c0000000000c8b),
)

_AUX_RENDER_RUNS = (
    (0x1000078000, 1, 0x0080000000000c8b),
    (0x1000080000, 1, 0x0080000000000c8b),
    (0x1000088000, 8, 0x0080000000000c8b),
    (0x10000b0000, 8, 0x0080000000000c8b),
    (0x10000d8000, 8, 0x0080000000000c8b),
    (0x1000100000, 8, 0x0080000000000c8b),
    (0x1000128000, 8, 0x0080000000000c8b),
    (0x1000150000, 8, 0x0080000000000c8b),
    (0x1000178000, 1, 0x0080000000000c8b),
    (0x1000180000, 2, 0x0080000000000c8b),
    (0x1000190000, 4, 0x0080000000000c8b),
    (0x10001a8000, 1, 0x0080000000000c8b),
    (0x1000250000, 8, 0x0080000000000c8b),
    (0x1000278000, 8, 0x0080000000000c8b),
    (0x10002a0000, 8, 0x0080000000000c8b),
    (0x10002c8000, 8, 0x0080000000000c8b),
    (0x10002f0000, 8, 0x0080000000000c8b),
    (0x1000318000, 8, 0x0080000000000c8b),
    (0x1000340000, 8, 0x0080000000000c8b),
    (0x1000368000, 8, 0x0080000000000c8b),
    (0x1000390000, 8, 0x0080000000000c8b),
    (0x10003b8000, 8, 0x0080000000000c8b),
    (0x10003e0000, 8, 0x0080000000000c8b),
    (0x1000408000, 8, 0x0080000000000c8b),
    (0x1000430000, 8, 0x0080000000000c8b),
    (0x1000458000, 8, 0x0080000000000c8b),
    (0x1000480000, 8, 0x0080000000000c8b),
    (0x10004a8000, 8, 0x0080000000000c8b),
    (0x10004d0000, 8, 0x0080000000000c8b),
    (0x10004f8000, 8, 0x0080000000000c8b),
    (0x1000520000, 8, 0x0080000000000c8b),
    (0x1000548000, 8, 0x0080000000000c8b),
    (0x1000570000, 8, 0x0080000000000c8b),
    (0x1000598000, 8, 0x0080000000000c8b),
    (0x10005c0000, 8, 0x0080000000000c8b),
    (0x10005e8000, 8, 0x0080000000000c8b),
    (0x1000610000, 8, 0x0080000000000c8b),
    (0x1000638000, 8, 0x0080000000000c8b),
    (0x7000000000, 128, 0x0080000000000c8b),
    (0x7000208000, 4, 0x0080000000000c8b),
    (0x7000220000, 64, 0x0080000000000c8b),
    (0x7000328000, 64, 0x0080000000000c8b),
    (0x7000430000, 64, 0x0080000000000c8b),
    (0x7000538000, 64, 0x0080000000000c8b),
    (0x7000640000, 64, 0x0080000000000c8b),
    (0x7000748000, 64, 0x0080000000000c8b),
    (0x7000850000, 64, 0x0080000000000c8b),
    (0x7000958000, 64, 0x0080000000000c8b),
    (0x7000a60000, 64, 0x0080000000000c8b),
    (0x7000b68000, 64, 0x0080000000000c8b),
    (0x7000c70000, 64, 0x0080000000000c8b),
    (0x7000d78000, 64, 0x0080000000000c8b),
    (0x7000e80000, 64, 0x0080000000000c8b),
    (0x7000f88000, 64, 0x0080000000000c8b),
    (0x7001090000, 64, 0x0080000000000c8b),
    (0x7001198000, 64, 0x0080000000000c8b),
    (0x70012a0000, 64, 0x0080000000000c8b),
    (0x70013a8000, 64, 0x0080000000000c8b),
    (0x70014b0000, 64, 0x0080000000000c8b),
    (0x70015b8000, 64, 0x0080000000000c8b),
    (0x70016c0000, 64, 0x0080000000000c8b),
    (0x70017c8000, 64, 0x0080000000000c8b),
    (0x2ffffff8000, 1, 0x00c0000000000c8b),
)

ROOT_RUNS = {
    0: _ROOT_0_RUNS,
    1: _ROOT_1_RUNS,
    2: ((0x2ffffff8000, 1, 0x00c0000000000c8b),),
    3: ((0x2ffffff8000, 1, 0x00c0000000000c8b),),
    4: ((0x2ffffff8000, 1, 0x00c0000000000c8b),),
    5: ((0x2ffffff8000, 1, 0x00c0000000000c8b),),
    6: ((0x2ffffff8000, 1, 0x00c0000000000c8b),),
    7: _ROOT_7_RUNS,
    8: _AUX_RENDER_RUNS,
    9: _AUX_RENDER_RUNS,
    10: _AUX_RENDER_RUNS,
    11: ((0x2ffffff8000, 1, 0x00c0000000000c8b),),
}


def expand_root_runs():
    """Return fresh per-root DVA to PTE attribute-bit dictionaries."""
    return {
        root: {
            first + index * PAGE_SIZE: flags
            for first, count, flags in runs
            for index in range(count)
        }
        for root, runs in ROOT_RUNS.items()
    }


def context0_firmware_peers():
    """Return the measured context-0 low-DVA to firmware-high-DVA aliases."""
    return {
        low_first + index * PAGE_SIZE: high_first + index * PAGE_SIZE
        for low_first, count, high_first in CONTEXT0_FIRMWARE_PEER_RUNS
        for index in range(count)
    }


def native_firmware_leaf_pages():
    """Return the measured DVA-to-PA placement required before first work."""
    pages = {}
    for first_dva, first_pa, count, pa_stride in NATIVE_FIRMWARE_LEAF_RUNS:
        for index in range(count):
            dva = first_dva + index * PAGE_SIZE
            pa = first_pa + index * pa_stride
            if dva in pages:
                raise RuntimeError("overlapping native firmware leaf run")
            pages[dva] = pa
    return pages


def native_table_targets(name):
    """Return a fresh table-path-to-PA map for one established root tree."""
    try:
        return dict(NATIVE_TABLE_TARGETS[name])
    except KeyError as exc:
        raise ValueError("unknown native G17P table topology %r" % name) from exc


class G17PSourceTopology:
    """Capture-compatible view backed only by source topology constants.

    The cold-boot builder historically accepted a capture object for both
    topology and byte-content experiments.  This view supplies the structural
    half of that interface while making every content read return zero.  It is
    therefore suitable only for the strict no-capture-content path.
    """

    def __init__(self, partial_opening=False):
        roots = expand_root_runs()
        root_ctx = dict(ROOT_CONTEXT_IDS)
        if partial_opening:
            roots = {
                0: roots[0],
                1: roots[1],
                2: {
                    first + index * PAGE_SIZE: flags
                    for first, count, flags in _PARTIAL_RENDER_RUNS
                    for index in range(count)
                },
            }
            root_ctx = {0: 0, 1: 64, 2: 1}
        self.selected_root = 1
        self.root_ctx = root_ctx
        self.by_root = {
            root: {address: (0, pte) for address, pte in pages.items()}
            for root, pages in roots.items()
        }
        self.blobs = {
            address: 0 for pages in roots.values() for address in pages
        }
        self.ptes = {
            address: pte
            for pages in roots.values()
            for address, pte in pages.items()
        }

        # These values are stable alias identities, not physical addresses to
        # program.  build_captured_contexts() compares them only for equality
        # to recover the context-0 <-> firmware-high peer relationship.
        self.pa_by_root = {
            root: {address: address for address in pages}
            for root, pages in roots.items()
        }
        peers = context0_firmware_peers()
        self.pa_by_root[0] = dict(peers)
        self.pas = {
            address: identity
            for root in sorted(self.pa_by_root)
            for address, identity in self.pa_by_root[root].items()
        }
        self.ram = b""

    @staticmethod
    def flags_from_pte(pte):
        return {
            "AttrIndex": (pte >> 2) & 7,
            "AP": (pte >> 6) & 3,
            "SH": (pte >> 8) & 3,
            "AF": (pte >> 10) & 1,
            "nG": (pte >> 11) & 1,
            "PXN": (pte >> 53) & 1,
            "UXN": (pte >> 54) & 1,
            "OS": (pte >> 55) & 1,
        }

    def flags(self, dva, default=None):
        pte = self.ptes.get(dva & ~(PAGE_SIZE - 1))
        return (dict(default or {}) if pte is None
                else self.flags_from_pte(pte))

    def flags_for_root(self, root_index, dva, default=None):
        record = self.by_root.get(int(root_index), {}).get(
            dva & ~(PAGE_SIZE - 1))
        return (dict(default or {}) if record is None
                else self.flags_from_pte(record[1]))

    @staticmethod
    def blob(_index):
        return bytes(PAGE_SIZE)

    @staticmethod
    def page(_dva):
        return bytes(PAGE_SIZE)

    @staticmethod
    def bytes_or_zero(_dva, size):
        return bytes(size)

    @staticmethod
    def bytes(_dva, size):
        return bytes(size)
