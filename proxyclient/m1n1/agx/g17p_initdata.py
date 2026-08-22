# SPDX-License-Identifier: MIT
"""Construct a T8140/G17P initialization descriptor from source.

The replay path reproduces a captured descriptor byte for byte by copying it.
This module builds one instead, from the field model in ``g17p.py`` plus the
addresses of the objects it references, and it is validated by rebuilding a
captured descriptor and comparing byte for byte. Any field this module cannot
derive is a field that is not yet understood, so a byte-exact rebuild is the
coverage test: every mismatch names something still to decode.

Fields whose value is known but whose meaning is not are passed in explicitly
rather than hardcoded, so a caller cannot mistake them for understood values.
"""

import struct

# --- Descriptor root ---------------------------------------------------------
ROOT_SIZE = 0xb8
ROOT_SECONDARY_SIZE = 0xc8

ROOT_VERSION = 0x00            # 4 x u16, meaning unresolved
ROOT_REGION_A = 0x08           # address of a 16 KiB region, shared by both
                               # instances. An earlier note here called it zero in
                               # every capture; that came from a running system,
                               # and at handoff it carries a real address.
ROOT_UNK_10 = 0x10             # u64, zero at handoff on both instances
ROOT_MAIN_CONFIG = 0x18        # address of the main configuration object
ROOT_REGION_C = 0x20           # address of the data region
ROOT_KIND = 0x28               # u32, 0 on the first instance and 1 on the second
ROOT_UNK_2C = 0x2c             # u32, 1 in every capture
ROOT_GRANULE = 0x30            # u16
ROOT_GRANULE_BITS = 0x32       # u8
ROOT_LEVEL_COUNT = 0x33        # u8
ROOT_LEVELS = 0x34             # 3 level descriptors
ROOT_STATUS_A = 0xa8           # address of a channel state block
ROOT_STATUS_B = 0xb0           # address of a channel state block
ROOT_SECONDARY_EXTRA_0 = 0xb8  # secondary-only address, role unresolved
ROOT_SECONDARY_EXTRA_1 = 0xc0  # secondary-only address, role unresolved

# --- Address-translation level descriptor ------------------------------------
# Every field is derivable from the level's index shift and entry count. The
# index mask is (entries - 1) << shift, which reproduces all three captured
# masks exactly, and the remaining fields are the same constants in all three.
LEVEL_DESC_SIZE = 0x20
LEVEL_CONST_0 = 0x08           # first byte, 8 in all three descriptors
LEVEL_CONST_1 = 0x0e           # second and third bytes, both the granule bits
LEVEL_TABLE_SIZE = 0x4000      # u16 following the entry count
LEVEL_UNK_8 = 1                # u64, 1 in all three descriptors
LEVEL_PHYS_MASK = 0x000003ffffffc000

# Geometry of the three levels below the root, confirmed against a live walk.
LEVELS = ((36, 64), (25, 2048), (14, 2048))
GRANULE = 0x4000
GRANULE_BITS = 14


def build_level_descriptor(index_shift, num_entries):
    """Build one address-translation level descriptor."""
    out = bytearray(LEVEL_DESC_SIZE)
    out[0] = LEVEL_CONST_0
    out[1] = LEVEL_CONST_1
    out[2] = LEVEL_CONST_1
    out[3] = index_shift
    struct.pack_into("<H", out, 0x04, num_entries)
    struct.pack_into("<H", out, 0x06, LEVEL_TABLE_SIZE)
    struct.pack_into("<Q", out, 0x08, LEVEL_UNK_8)
    struct.pack_into("<Q", out, 0x10, LEVEL_PHYS_MASK)
    struct.pack_into("<Q", out, 0x18, (num_entries - 1) << index_shift)
    return bytes(out)


def build_root(version, region_a, main_config, region_c, status_a, status_b,
               kind=0, levels=LEVELS, granule=GRANULE, granule_bits=GRANULE_BITS,
               secondary_extra_0=0, secondary_extra_1=0):
    """Build the descriptor root.

    ``version`` is the four 16-bit values at offset 0. Their meaning is not
    established, so the caller supplies them rather than this module inventing
    them.
    """
    size = (ROOT_SECONDARY_SIZE
            if secondary_extra_0 or secondary_extra_1 else ROOT_SIZE)
    out = bytearray(size)
    struct.pack_into("<4H", out, ROOT_VERSION, *version)
    struct.pack_into("<Q", out, ROOT_REGION_A, region_a)
    struct.pack_into("<Q", out, ROOT_MAIN_CONFIG, main_config)
    struct.pack_into("<Q", out, ROOT_REGION_C, region_c)
    struct.pack_into("<I", out, ROOT_KIND, kind)
    struct.pack_into("<I", out, ROOT_UNK_2C, 1)
    struct.pack_into("<H", out, ROOT_GRANULE, granule)
    out[ROOT_GRANULE_BITS] = granule_bits
    out[ROOT_LEVEL_COUNT] = len(levels)
    for i, (shift, entries) in enumerate(levels):
        offset = ROOT_LEVELS + i * LEVEL_DESC_SIZE
        out[offset:offset + LEVEL_DESC_SIZE] = build_level_descriptor(shift, entries)
    struct.pack_into("<Q", out, ROOT_STATUS_A, status_a)
    struct.pack_into("<Q", out, ROOT_STATUS_B, status_b)
    if len(out) == ROOT_SECONDARY_SIZE:
        struct.pack_into("<Q", out, ROOT_SECONDARY_EXTRA_0, secondary_extra_0)
        struct.pack_into("<Q", out, ROOT_SECONDARY_EXTRA_1, secondary_extra_1)
    return bytes(out)


# --- Main configuration object -----------------------------------------------
# Offsets are relative to the object, which does not begin at a page boundary.
#
# The host does not write this object all at once. At the point where firmware is
# handed the descriptor, only the fields below are populated; a capture taken later
# in a running system additionally holds a marker at 0x344, further copies of the
# 0x16 value, and a tail block from 0x580, none of which are needed for the
# descriptor to be accepted. Building the earlier state is therefore what a cold
# start needs.
MAIN_SIZE = 0x600

MAIN_HWDATA_ADDR = 0x00        # address of the hardware-data object
MAIN_REPEATED_ADDR = 0x08      # the same address appears at 0x08 and 0x10
MAIN_REPEATED_ADDR_2 = 0x10
MAIN_CHANNEL_TABLE = 0x20      # 17 entries of 0x20
MAIN_ADDR_ARRAY = 0x254        # five addresses at an 8-byte stride, 4-byte aligned
MAIN_ADDR_ARRAY_COUNT = 5
# Historical API name retained for callers. This is six consecutive qwords:
# one high-only sentinel, two low/high alias pairs, then a null terminator.
# The apparent value/0x70 halves are the two context-0 virtual addresses.
MAIN_REGION_TRIPLES = 0x2d0
MAIN_REGION_TRIPLE_STRIDE = 0x10
MAIN_REGION_TRIPLE_COUNT = 3
MAIN_REGION_TRIPLE_KIND = 0x70
MAIN_BYTE_MASK = 0x3e0         # u32 reading 0xff
MAIN_BYTE_MASK_VALUE = 0xff
MAIN_INTERVAL = 0x4c0          # u32 reading 0x16
MAIN_INTERVAL_VALUE = 0x16

# The second record in primary record page B is sufficient to distinguish
# queue retirement from actual compute execution. It is invariant across the
# minimal add3 and larger native compute captures. The five scalar semantics
# remain unknown; none is an address.
COMPUTE_DISPATCH_RECORD_STRIDE = 0x20
COMPUTE_DISPATCH_RECORD_FIELDS = (
    0xe0000000,
    0x08000000,
    0x00000000,
    0x00002a00,
    0x00001500,
)


def build_compute_dispatch_record():
    """Build the hardware-required primary compute dispatch record."""
    out = bytearray(COMPUTE_DISPATCH_RECORD_STRIDE)
    struct.pack_into("<5I", out, 0, *COMPUTE_DISPATCH_RECORD_FIELDS)
    return bytes(out)

CHANNEL_TABLE_ENTRIES = 17
CHANNEL_ENTRY_SIZE = 0x20
CHANNEL_ENTRY_STATE_COUNT = 3


def build_channel_entry(state_addrs, ring_addr):
    """Build one channel table entry: three state addresses then the ring base."""
    out = bytearray(CHANNEL_ENTRY_SIZE)
    for index, addr in enumerate(state_addrs[:CHANNEL_ENTRY_STATE_COUNT]):
        struct.pack_into("<Q", out, index * 8, addr)
    struct.pack_into("<Q", out, CHANNEL_ENTRY_STATE_COUNT * 8, ring_addr)
    return bytes(out)


# The second instance is handed a control-only object. Captured at the moment each
# instance is given its descriptor, it has no work channels at all, no address
# array and no region triples, and three scalars differ from the first instance's.
# It shares the first instance's hardware-data object, so the register windows are
# not per instance.
MAIN_SECONDARY_KIND = 0x300            # u32, 4 here against 0 for the first
MAIN_SECONDARY_KIND_VALUE = 4
MAIN_SECONDARY_INTERVAL_VALUE = 0x2a   # at MAIN_INTERVAL, against 0x16
MAIN_SECONDARY_ADDR = 0x471            # u64 address, absent on the first instance
SECONDARY_FIRST_CHANNEL = 12           # entries below this are left empty


def build_secondary_main_config(hwdata_addr, repeated_addr, channels,
                                region_triples=(), extra_addr=0):
    """Build the main configuration object for the control-only instance.

    ``channels`` is indexed the same way as for the first instance so a caller can
    pass the same list; entries below the first control channel are ignored, since
    the second instance is given none.
    """
    out = bytearray(MAIN_SIZE)
    struct.pack_into("<Q", out, MAIN_HWDATA_ADDR, hwdata_addr)
    struct.pack_into("<Q", out, MAIN_REPEATED_ADDR, repeated_addr)
    struct.pack_into("<Q", out, MAIN_REPEATED_ADDR_2, repeated_addr)

    for index in range(SECONDARY_FIRST_CHANNEL, len(channels)):
        state_addrs, ring_addr = channels[index]
        base = MAIN_CHANNEL_TABLE + index * CHANNEL_ENTRY_SIZE
        out[base:base + CHANNEL_ENTRY_SIZE] = build_channel_entry(state_addrs,
                                                                  ring_addr)

    # The region triples keep their values and kinds but carry no addresses here,
    # so the values are not properties of the regions they sit beside.
    for index, (addr, value) in enumerate(region_triples[:MAIN_REGION_TRIPLE_COUNT]):
        base = MAIN_REGION_TRIPLES + index * MAIN_REGION_TRIPLE_STRIDE
        struct.pack_into("<Q", out, base, addr)
        if value is None:
            continue
        struct.pack_into("<I", out, base + 8, value)
        struct.pack_into("<I", out, base + 0xc, MAIN_REGION_TRIPLE_KIND)

    struct.pack_into("<I", out, MAIN_SECONDARY_KIND, MAIN_SECONDARY_KIND_VALUE)
    struct.pack_into("<I", out, MAIN_INTERVAL, MAIN_SECONDARY_INTERVAL_VALUE)
    if extra_addr:
        struct.pack_into("<Q", out, MAIN_SECONDARY_ADDR, extra_addr)
    return bytes(out)


def build_main_config(hwdata_addr, repeated_addr, channels, addr_array,
                      region_triples):
    """Build the main configuration object as the host has it at handoff.

    ``channels`` is a sequence of (state_addrs, ring_addr), ``addr_array`` five
    addresses, and ``region_triples`` three pairs used to encode the six region
    view qwords. For the first two pairs, ``value`` is the low 32 bits of the
    following context-0 address and the historical kind constant is its high
    32 bits (`0x70`). A final ``None`` emits the null terminator.
    """
    out = bytearray(MAIN_SIZE)
    struct.pack_into("<Q", out, MAIN_HWDATA_ADDR, hwdata_addr)
    struct.pack_into("<Q", out, MAIN_REPEATED_ADDR, repeated_addr)
    struct.pack_into("<Q", out, MAIN_REPEATED_ADDR_2, repeated_addr)

    for index, (state_addrs, ring_addr) in enumerate(channels):
        base = MAIN_CHANNEL_TABLE + index * CHANNEL_ENTRY_SIZE
        out[base:base + CHANNEL_ENTRY_SIZE] = build_channel_entry(state_addrs,
                                                                 ring_addr)

    for index, addr in enumerate(addr_array[:MAIN_ADDR_ARRAY_COUNT]):
        struct.pack_into("<Q", out, MAIN_ADDR_ARRAY + index * 8, addr)

    # A value of None leaves the following qword zero, terminating the view
    # chain after the final firmware-high address.
    for index, (addr, value) in enumerate(region_triples[:MAIN_REGION_TRIPLE_COUNT]):
        base = MAIN_REGION_TRIPLES + index * MAIN_REGION_TRIPLE_STRIDE
        struct.pack_into("<Q", out, base, addr)
        if value is None:
            continue
        struct.pack_into("<I", out, base + 8, value)
        struct.pack_into("<I", out, base + 0xc, MAIN_REGION_TRIPLE_KIND)

    struct.pack_into("<I", out, MAIN_BYTE_MASK, MAIN_BYTE_MASK_VALUE)
    struct.pack_into("<I", out, MAIN_INTERVAL, MAIN_INTERVAL_VALUE)
    return bytes(out)


# --- Hardware-data object ----------------------------------------------------
# Host configuration: a live copy differed from a pre-start one in a single byte.
HWDATA_SIZE = 0x3db4

REGISTER_ARRAY_OFFSET = 0x640
REGISTER_ENTRY_SIZE = 0x28
REGISTER_SLOT_COUNT = 53

# The performance-state tables come in two groups with an identical internal
# layout, one per ladder: a frequency ladder, then a voltage column 0x40 further
# on, then a memory-rail voltage column 0x400 beyond that, both columns stored as
# per-state blocks that repeat the value. Group 2's base was found by rebuilding
# the object and noticing the leftover per-state tables held the same voltage
# columns as group 1.
# The groups differ in how a per-state value is stored: the first replicates it
# across sixteen words of the block, the second stores it once and leaves the rest
# of the block zero.
TABLE_GROUP_BASES = (0xfc8, 0x1cdc)
TABLE_GROUP_REPEATS = (16, 1)
GROUP_VOLTAGE_DELTA = 0x40
GROUP_MEMORY_VOLTAGE_DELTA = 0x440
STATE_BLOCK_STRIDE = 0x40
LADDER_ENTRIES = 11

FREQ_LADDER_A = TABLE_GROUP_BASES[0]
CORE_VOLTAGE = FREQ_LADDER_A + GROUP_VOLTAGE_DELTA
MEMORY_VOLTAGE = FREQ_LADDER_A + GROUP_MEMORY_VOLTAGE_DELTA
FREQ_LADDER_B_COPY = TABLE_GROUP_BASES[1]

# Ladder B also appears on its own, ahead of the second group, followed by an
# 11-entry table of 32-bit floats whose value was the same in every state.
FREQ_LADDER_B = 0x1808
SCALE_LADDER_B = 0x1848
RELATIVE_LADDER_A = 0x18c8
RELATIVE_LADDER_B = 0x1908
INDEX_MAP_A = 0x19c8
INDEX_MAP_B = 0x1a08


HWDATA_CHIP_ID = 0xe90         # u32, reads the chip identifier

# The one block of otherwise unexplained bytes that firmware requires in order to
# accept the descriptor. Bisecting by zeroing showed every other unexplained byte
# can be zero, so this is the part that has to be right.
#
# It decodes as a work-channel count, two groups of flags, and a table with one
# all-ones entry per work channel, which is the same unassigned pattern the
# per-queue context objects carry before work is submitted.
HWDATA_CHANNEL_COUNT = 0x258e          # u16, equals the number of work channels
HWDATA_FLAG_GROUPS = 0x2590            # two groups of four u32
HWDATA_FLAG_GROUP_PATTERN = (0, 1, 1, 1)
HWDATA_FLAG_GROUP_COUNT = 2
HWDATA_UNASSIGNED_TABLE = 0x25b4       # one u32 per work channel
HWDATA_UNASSIGNED_VALUE = 0xffffffff
HWDATA_TRAILING_ONES = (0x25f4, 0x2600, 0x2608)
WORK_CHANNEL_COUNT = 12

# An array of 0x40-byte records each carrying an address, a value paired with the
# recurring constant 0x70, and three trailing constants. The same value-plus-0x70
# pairing appears in the main configuration object.
REGION_RECORD_OFFSET = 0x2610
REGION_RECORD_STRIDE = 0x40
REGION_RECORD_LEAD = 0x00      # u32
REGION_RECORD_VALUE = 0x04     # u32, paired with the constant below
REGION_RECORD_KIND = 0x08      # u32, 0x70 in every observed record
REGION_RECORD_ADDR = 0x0c      # u64, on a 4-byte boundary
REGION_RECORD_SIZE_A = 0x14    # u32, 0x800 in every observed record
REGION_RECORD_SIZE_B = 0x18    # u32, 0x40 in every observed record
REGION_RECORD_TRAIL = 0x1c     # u32, 2 in every observed record
REGION_RECORD_KIND_VALUE = 0x70


def build_region_record(lead, value, addr, size_a=0x800, size_b=0x40, trail=2):
    """Build one 0x40-byte region record."""
    out = bytearray(REGION_RECORD_STRIDE)
    struct.pack_into("<I", out, REGION_RECORD_LEAD, lead)
    struct.pack_into("<I", out, REGION_RECORD_VALUE, value)
    struct.pack_into("<I", out, REGION_RECORD_KIND, REGION_RECORD_KIND_VALUE)
    struct.pack_into("<Q", out, REGION_RECORD_ADDR, addr)
    struct.pack_into("<I", out, REGION_RECORD_SIZE_A, size_a)
    struct.pack_into("<I", out, REGION_RECORD_SIZE_B, size_b)
    struct.pack_into("<I", out, REGION_RECORD_TRAIL, trail)
    return bytes(out)


def build_register_entry(phys, device_va, size, flag, unk_18=0):
    """Build one register-mapping entry."""
    out = bytearray(REGISTER_ENTRY_SIZE)
    struct.pack_into("<QQ", out, 0x00, phys, device_va)
    struct.pack_into("<II", out, 0x10, size, size)
    struct.pack_into("<Q", out, 0x18, unk_18)
    struct.pack_into("<I", out, 0x20, flag)
    return bytes(out)


def build_hwdata(register_entries, flag_only_slots, perf, opaque_fields=None,
                 chip_id=None, region_records=()):
    """Build the hardware-data object.

    ``register_entries`` maps a slot index to a dict of entry fields.
    ``flag_only_slots`` maps a slot index to the flag value for slots that carry
    a flag but no address. ``perf`` supplies the performance-state tables.
    ``extra_fields`` is a list of (offset, bytes) for regions not yet decoded, so
    a rebuild can be byte-exact while making the undecoded remainder explicit.
    """
    out = bytearray(HWDATA_SIZE)

    for slot, entry in register_entries.items():
        base = REGISTER_ARRAY_OFFSET + slot * REGISTER_ENTRY_SIZE
        out[base:base + REGISTER_ENTRY_SIZE] = build_register_entry(**entry)
    for slot, flag in flag_only_slots.items():
        base = REGISTER_ARRAY_OFFSET + slot * REGISTER_ENTRY_SIZE
        struct.pack_into("<I", out, base + 0x20, flag)

    def ladder(offset, values):
        struct.pack_into("<%dI" % len(values), out, offset, *values)

    def per_state(base, column, repeat):
        for state, value in enumerate(column):
            block = base + state * STATE_BLOCK_STRIDE
            for word in range(repeat):
                struct.pack_into("<I", out, block + word * 4, value)

    # Two table groups with the same internal layout, one per ladder, differing
    # only in how many words of each per-state block hold the value.
    for group, repeat, freq in zip(TABLE_GROUP_BASES, TABLE_GROUP_REPEATS,
                                   (perf["freq_a"], perf["freq_b"])):
        ladder(group, freq)
        per_state(group + GROUP_VOLTAGE_DELTA, perf["core_voltage"], repeat)
        per_state(group + GROUP_MEMORY_VOLTAGE_DELTA, perf["memory_voltage"],
                  repeat)

    ladder(FREQ_LADDER_B, perf["freq_b"])
    ladder(SCALE_LADDER_B, perf["scale_b"])
    ladder(RELATIVE_LADDER_A, perf["relative_a"])
    ladder(RELATIVE_LADDER_B, perf["relative_b"])
    ladder(INDEX_MAP_A, perf["index_a"])
    ladder(INDEX_MAP_B, perf["index_b"])

    if chip_id is not None:
        struct.pack_into("<I", out, HWDATA_CHIP_ID, chip_id)

    # The block firmware requires. Derived from the work-channel count rather than
    # copied, so a constructed descriptor needs nothing from a capture here.
    struct.pack_into("<H", out, HWDATA_CHANNEL_COUNT, WORK_CHANNEL_COUNT)
    for group in range(HWDATA_FLAG_GROUP_COUNT):
        base = HWDATA_FLAG_GROUPS + group * 4 * len(HWDATA_FLAG_GROUP_PATTERN)
        struct.pack_into("<%dI" % len(HWDATA_FLAG_GROUP_PATTERN), out, base,
                         *HWDATA_FLAG_GROUP_PATTERN)
    for channel in range(WORK_CHANNEL_COUNT):
        struct.pack_into("<I", out, HWDATA_UNASSIGNED_TABLE + channel * 4,
                         HWDATA_UNASSIGNED_VALUE)
    for offset in HWDATA_TRAILING_ONES:
        struct.pack_into("<I", out, offset, 1)

    for index, record in enumerate(region_records):
        base = REGION_RECORD_OFFSET + index * REGION_RECORD_STRIDE
        out[base:base + REGION_RECORD_STRIDE] = build_region_record(**record)

    # Bytes whose value is known but whose meaning is not. Default to the recorded
    # device constants so a descriptor can be built without a capture; pass an
    # explicit list to override, or an empty list to leave them zero and test
    # whether firmware needs them.
    if opaque_fields is None:
        opaque_fields = HWDATA_CONSTANTS
    for offset, data in opaque_fields:
        out[offset:offset + len(data)] = data

    return bytes(out)


def root_from_capture(data):
    """Extract the inputs build_root needs from a captured root object."""
    return {
        "version": list(struct.unpack_from("<4H", data, ROOT_VERSION)),
        "region_a": struct.unpack_from("<Q", data, ROOT_REGION_A)[0],
        "main_config": struct.unpack_from("<Q", data, ROOT_MAIN_CONFIG)[0],
        "region_c": struct.unpack_from("<Q", data, ROOT_REGION_C)[0],
        "status_a": struct.unpack_from("<Q", data, ROOT_STATUS_A)[0],
        "status_b": struct.unpack_from("<Q", data, ROOT_STATUS_B)[0],
    }


def rebuild_root(data):
    """Rebuild a captured root from its own inputs, for the coverage test."""
    return build_root(**root_from_capture(data))
# Device-specific constants whose meaning is not established. They are
# recorded here so a descriptor can be constructed without a capture, the
# same way earlier generations carry named unknown fields in their chip
# tables. Hardware testing showed the descriptor is accepted without them
# but that the device-control phase that follows is not, so they are
# required for operation rather than for acceptance.
HWDATA_CONSTANTS = (
    (0x000004, bytes.fromhex(  # 8 bytes
        "6f0000000000c0ff"
    )),
    (0x000014, bytes.fromhex(  # 28 bytes
        "1000000000000000100000000080ffffff0200000000408121fcffff"
    )),
    (0x0000e0, bytes.fromhex(  # 2 bytes
        "0820"
    )),
    (0x0000ea, bytes.fromhex(  # 2 bytes
        "0820"
    )),
    (0x0000f4, bytes.fromhex(  # 28 bytes
        "08200000cb240000fa2c8ac9cb24f6f417e97718cb24d9380000abbd"
    )),
    (0x0002d9, bytes.fromhex(  # 23 bytes
        "20f8ffdb2c2dd3002000f526e9da210020b638080042c7"
    )),
    (0x0003e0, bytes.fromhex(  # 2 bytes
        "e07f"
    )),
    (0x0003ea, bytes.fromhex(  # 2 bytes
        "e07f"
    )),
    (0x0003f4, bytes.fromhex(  # 6 bytes
        "e07f00000080"
    )),
    (0x000403, bytes.fromhex(  # 1 bytes
        "80"
    )),
    (0x00040d, bytes.fromhex(  # 1 bytes
        "80"
    )),
    (0x0005d8, bytes.fromhex(  # 24 bytes
        "4526234b980e00005feaa2d5ff3f004000405ecaa2f50040"
    )),
    (0x000e94, bytes.fromhex(  # 17 bytes
        "0100000001000000000000000100000001"
    )),
    (0x000eb8, bytes.fromhex(  # 49 bytes
        "010000000000000001000000000000000100000000000000c05d000001000000"
        "1000000000000000010000000100000001"
    )),
    (0x000f04, bytes.fromhex(  # 1 bytes
        "1f"
    )),
    (0x000f24, bytes.fromhex(  # 1 bytes
        "04"
    )),
    (0x000f34, bytes.fromhex(  # 5 bytes
        "0100000001"
    )),
    (0x000f4c, bytes.fromhex(  # 1 bytes
        "31"
    )),
    (0x000f6c, bytes.fromhex(  # 1 bytes
        "01"
    )),
    (0x000f88, bytes.fromhex(  # 5 bytes
        "0600000001"
    )),
    (0x000fac, bytes.fromhex(  # 1 bytes
        "01"
    )),
    (0x000fb8, bytes.fromhex(  # 13 bytes
        "1e00000004000000060000000a"
    )),
    (0x001cd8, bytes.fromhex(  # 1 bytes
        "0a"
    )),
    (0x002544, bytes.fromhex(  # 17 bytes
        "0400000006000000030000000700000007"
    )),
    (0x002568, bytes.fromhex(  # 9 bytes
        "050000000000000001"
    )),
    # 0x2630 is deliberately absent. It is the one byte that differed between a
    # pre-start and a running capture, so it is firmware state rather than host
    # configuration, and the host leaves it zero. Recording it here would have
    # baked a captured firmware value into the builder.
    (0x0026ad, bytes.fromhex(  # 12 bytes
        "805d0120fcffff0100000001"
    )),
    (0x0026e8, bytes.fromhex(  # 1 bytes
        "01"
    )),
    (0x003d98, bytes.fromhex(  # 4 bytes
        "ffffffff"
    )),
    (0x003db0, bytes.fromhex(  # 4 bytes
        "ffffffff"
    )),
)
HWDATA_CONSTANT_BYTES = 269
# --- Data region at root +0x20 ------------------------------------------------
# Tunables: timeouts, intervals, percentages and a block of 32-bit floats that
# read as ratios between 0.1 and 1.0. Their individual meanings are not
# established, so they are recorded as named constants the same way the
# hardware-data constants are. Everything else in the region is zero.
REGION_C_SIZE = 0x1000
REGION_C_CONSTANTS = (
    (0x000024, bytes.fromhex(  # 4 bytes
        "b80b0000"
    )),
    (0x000030, bytes.fromhex(  # 16 bytes
        "01000000010000000000000078000000"
    )),
    (0x000054, bytes.fromhex(  # 24 bytes
        "ffff2800ffff000000000100000001000000030000000100"
    )),
    (0x000078, bytes.fromhex(  # 4 bytes
        "01000000"
    )),
    (0x000084, bytes.fromhex(  # 12 bytes
        "4e250000e8030000e8030000"
    )),
    (0x000098, bytes.fromhex(  # 4 bytes
        "e8030000"
    )),
    (0x0007c4, bytes.fromhex(  # 56 bytes
        "d00700000000803fcdcc4c3fcdcc4c3e6666663fcdcccc3d0000803e9a99193f"
        "6666663f0600000001000000010000006400000064000000"
    )),
    (0x000998, bytes.fromhex(  # 16 bytes
        "280000000a000000fa00000001000000"
    )),
    (0x0009b8, bytes.fromhex(  # 28 bytes
        "c0270900c02709000500000000000000280000003200000001000000"
    )),
    (0x000e1c, bytes.fromhex(  # 4 bytes
        "00010000"
    )),
    (0x000e38, bytes.fromhex(  # 8 bytes
        "0003000000010000"
    )),
    # Required before the first compact class-1 registration. Leaving this
    # clear makes primary firmware take an asynchronous SError while consuming
    # opcode 0x20; the exact function of the field is not established yet.
    (0x000e50, bytes.fromhex(  # 4 bytes
        "00010000"
    )),
)
REGION_C_CONSTANT_BYTES = 180

# The two blocks the root reaches at +0xa8 and +0xb0 each hold a single 32-bit
# 1 at offset 4 before firmware starts; the rest is zero.
STATUS_BLOCK_SIZE = 0x80
STATUS_BLOCK_ONE_OFFSET = 0x04


def build_region_c():
    """Build the data region at root +0x20."""
    out = bytearray(REGION_C_SIZE)
    for offset, data in REGION_C_CONSTANTS:
        out[offset:offset + len(data)] = data
    return bytes(out)


# Two further fields appear after an instance acknowledges its descriptor. The
# exact pre-init snapshot leaves them clear; build_status_block exposes them for
# reconstructing the later state, while an initial handoff uses extra=False.
STATUS_BLOCK_EXTRA_OFFSETS = (0x10, 0x14)


def build_status_block(extra=False):
    """Build one of the blocks the root reaches at +0xa8 and +0xb0.

    extra adds the two post-acknowledgement fields seen in a running status block.
    """
    out = bytearray(STATUS_BLOCK_SIZE)
    struct.pack_into("<I", out, STATUS_BLOCK_ONE_OFFSET, 1)
    if extra:
        for offset in STATUS_BLOCK_EXTRA_OFFSETS:
            struct.pack_into("<I", out, offset, 1)
    return bytes(out)


def build_sparse_object(size, runs):
    """Build an unresolved object from hardware-verified populated byte runs."""
    out = bytearray(size)
    for offset, data in runs:
        data = bytes(data)
        if offset < 0 or offset + len(data) > size:
            raise ValueError("sparse run at %#x exceeds %#x-byte object" %
                             (offset, size))
        out[offset:offset + len(data)] = data
    return bytes(out)


def build_primary_status_b(size, fwctl_state, fwctl_ring,
                           config_header_offset, config_offset, config_runs):
    """Build the complete primary status/config object seen at pre-init."""
    out = bytearray(size)
    out[:STATUS_BLOCK_SIZE] = build_status_block()
    struct.pack_into("<QQ", out, 0x48e0, fwctl_state, fwctl_ring)
    # The three-word header is [enabled, lifecycle sequence, reserved] at
    # pre-init. Only the enabled word is nonzero before work starts.
    struct.pack_into("<III", out, config_header_offset, 1, 0, 0)
    config = build_sparse_object(size - config_offset, config_runs)
    out[config_offset:config_offset + len(config)] = config
    return bytes(out)
