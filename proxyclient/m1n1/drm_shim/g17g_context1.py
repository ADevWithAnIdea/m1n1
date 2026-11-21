# SPDX-License-Identifier: GPL-2.0-only
"""Numeric T8142/G17G context-1 mapping topology before type 0x84.

Two independent native snapshots have the exact same 2,431-DVA selector-zero
set for the sole active nonzero hardware context.  Every observed leaf uses
the context UXN class (low PTE bits 0xc8b).  Physical placement and page
contents are deliberately absent: callers allocate fresh backing and decide
which source-built contents, if any, to publish.
"""

import hashlib
import struct


PAGE_SIZE = 0x4000
EXPECTED_PAGE_COUNT = 2431
EXPECTED_DVA_SHA256 = (
    "aab9914401e948d5925a040b627b7c32"
    "b7c62dbea48c33a997fae1fb1a6414fe"
)

# (DVA base, 16-KiB page count).  This is the complete stable set, compressed
# into maximal contiguous DVA runs.  It includes no captured physical address
# and no captured page bytes.
CONTEXT1_RUNS = (
    (0x1000000000, 4),
    (0x1000018000, 2),
    (0x1000028000, 2),
    (0x1000038000, 2),
    (0x1000048000, 2),
    (0x1000058000, 2),
    (0x1000068000, 3),
    (0x1000078000, 1),
    (0x1000080000, 1),
    (0x1000088000, 32),
    (0x1000110000, 32),
    (0x1000198000, 32),
    (0x1000220000, 1),
    (0x1000228000, 2),
    (0x1000238000, 6),
    (0x1000258000, 1),
    (0x1000260000, 17),
    (0x10002A8000, 1),
    (0x7200000000, 256),
    (0x7200408000, 4),
    (0x7200420000, 128),
    (0x7200628000, 128),
    (0x7200830000, 128),
    (0x7200A38000, 128),
    (0x7200C40000, 128),
    (0x7200E48000, 128),
    (0x7201050000, 128),
    (0x7201258000, 128),
    (0x7201460000, 128),
    (0x7201668000, 128),
    (0x7201870000, 128),
    (0x7201A78000, 128),
    (0x7201C80000, 128),
    (0x7201E88000, 128),
    (0x10000000000, 4),
    (0x10000020000, 8),
    (0x10000048000, 4),
    (0x10000060000, 8),
    (0x10000088000, 37),
    (0x10000120000, 28),
    (0x10000198000, 2),
    (0x100001A8000, 2),
    (0x100001B8000, 2),
    (0x100001C8000, 2),
    (0x100001D8000, 64),
    (0x100002E0000, 2),
    (0x100002F0000, 2),
    (0x10000300000, 2),
    (0x10000310000, 2),
    (0x10000320000, 2),
    (0x10000330000, 48),
    (0x100003F8000, 16),
    (0x2FFFFFF8000, 1),
)

# Stable cross-context physical aliases in both native pre-type-0x84 captures.
# Values name the source-built context-64 post-control DVA whose physical page
# must also back the context-1 key.  This records topology, not captured PAs.
POSTCONTROL_ALIASES = {
    0x1000078000: 0xFFFFFC2001610000,
    0x1000080000: 0xFFFFFC2001620000,
    0x1000238000: 0xFFFFFC20C08C8000,
    0x100023C000: 0xFFFFFC20C08CC000,
    0x1000240000: 0xFFFFFC20C08D0000,
    0x1000244000: 0xFFFFFC20C08D4000,
    0x1000248000: 0xFFFFFC20C08D8000,
    0x100024C000: 0xFFFFFC20C08DC000,
    0x1000258000: 0xFFFFFC2001630000,
}

# The post-control numeric descriptor at 0xfffffc20c08b0000 names this
# context-1 page directly.  Both independent native pre-type-0x84 captures
# contain the same 14 tagged qwords at a 0x40-byte stride.  The low address
# portion of each qword names the first page of one of the 14 stable 128-page
# runs already represented in CONTEXT1_RUNS.  These names describe only the
# observed numeric shape; they do not assign an object or execution role.
TAGGED_ADDRESS_PAGE_DVA = 0x7200408000
TAGGED_ADDRESS_COUNT = 14
TAGGED_ADDRESS_STRIDE = 0x40
TAGGED_ADDRESS_VALUE_MASK = 0x2000000000000000
TAGGED_ADDRESS_TARGET_BASE = 0x7200420000
TAGGED_ADDRESS_TARGET_STRIDE = 0x208000
TAGGED_ADDRESS_PAGE_SHA256 = (
    "66b86dadc6db7b900a3abdd43b9115bd"
    "12a583f61ef3b23cf1bb55d57639adaa"
)

# Immediately before native type 0x84, these four pages contain the 4-KiB
# address enumeration for tagged target runs 0 through 12.  A same-boot
# snapshot pair shows firmware filling run 13 into page 3 at +0x1000 before
# returning type 0x42.  The pre-image therefore deliberately leaves entries
# 6656 through 7167 zero.
ADDRESS_LIST_PAGE_DVAS = tuple(
    0x7200000000 + index * PAGE_SIZE for index in range(4)
)
ADDRESS_LIST_PREPOPULATED_RUN_COUNT = 13
ADDRESS_LIST_ENTRIES_PER_RUN = 512
ADDRESS_LIST_ENTRY_STRIDE = 8
ADDRESS_LIST_ADDRESS_STRIDE = 0x1000
ADDRESS_LIST_PAGE_SHA256 = (
    "2b5ffe0b0907c4c3bea3a5dc89c3863f2cee52fd55f849bd0ef0e643c9bb46df",
    "51b019ce6025aba5bae4a29c31f722a570f2c7ef1284d420c7118ea56d006778",
    "ce22cf7bfe61f5ffb24066323cfcdfa12c812c1a124249db19ef5725bba3be43",
    "17d4fd0ccc02e9a79c92988186926f9d937784fa15afeb10747a56ea7866581f",
)
ADDRESS_LIST_COMPLETED_PAGE_SHA256 = (
    *ADDRESS_LIST_PAGE_SHA256[:3],
    "7585d0815da70f827f61586e1936309744c8b764cddb41b4f6fc8da7fb47d184",
)


def expand_context1_dvas():
    """Expand and validate the complete numeric selector-zero DVA set."""
    pages = []
    for base, page_count in CONTEXT1_RUNS:
        if base & (PAGE_SIZE - 1) or page_count <= 0:
            raise ValueError("invalid numeric context-1 run")
        pages.extend(base + index * PAGE_SIZE for index in range(page_count))
    if len(pages) != EXPECTED_PAGE_COUNT:
        raise ValueError("numeric context-1 page count changed")
    if pages != sorted(set(pages)):
        raise ValueError("numeric context-1 runs overlap or are unordered")
    return tuple(pages)


def validate_postcontrol_aliases(postcontrol_dvas):
    """Validate and return the numeric cross-context alias map."""
    context1 = set(expand_context1_dvas())
    postcontrol = set(postcontrol_dvas)
    if not set(POSTCONTROL_ALIASES) <= context1:
        raise ValueError("context-1 alias key is absent from topology")
    if not set(POSTCONTROL_ALIASES.values()) <= postcontrol:
        raise ValueError("context-1 alias target is absent from post-control")
    return dict(POSTCONTROL_ALIASES)


def build_tagged_address_page():
    """Build the stable directly referenced context-1 numeric page."""
    context1 = set(expand_context1_dvas())
    if TAGGED_ADDRESS_PAGE_DVA not in context1:
        raise ValueError("tagged-address page is absent from topology")
    page = bytearray(PAGE_SIZE)
    for index in range(TAGGED_ADDRESS_COUNT):
        target = (
            TAGGED_ADDRESS_TARGET_BASE
            + index * TAGGED_ADDRESS_TARGET_STRIDE
        )
        if target not in context1:
            raise ValueError("tagged-address target is absent from topology")
        struct.pack_into(
            "<Q", page, index * TAGGED_ADDRESS_STRIDE,
            TAGGED_ADDRESS_VALUE_MASK | target,
        )
    body = bytes(page)
    if hashlib.sha256(body).hexdigest() != TAGGED_ADDRESS_PAGE_SHA256:
        raise ValueError("tagged-address numeric page hash changed")
    return body


def build_address_list_pages(completed=False):
    """Build the exact pre-image or observed completed numeric address list."""
    context1 = set(expand_context1_dvas())
    if not set(ADDRESS_LIST_PAGE_DVAS) <= context1:
        raise ValueError("address-list page is absent from topology")
    pages = [bytearray(PAGE_SIZE) for _va in ADDRESS_LIST_PAGE_DVAS]
    entries_per_page = PAGE_SIZE // ADDRESS_LIST_ENTRY_STRIDE
    run_count = (
        TAGGED_ADDRESS_COUNT
        if completed else ADDRESS_LIST_PREPOPULATED_RUN_COUNT
    )
    for run_index in range(run_count):
        run_base = (
            TAGGED_ADDRESS_TARGET_BASE
            + run_index * TAGGED_ADDRESS_TARGET_STRIDE
        )
        for entry_index in range(ADDRESS_LIST_ENTRIES_PER_RUN):
            address = run_base + entry_index * ADDRESS_LIST_ADDRESS_STRIDE
            if (address & ~(PAGE_SIZE - 1)) not in context1:
                raise ValueError("address-list target is absent from topology")
            flat_index = (
                run_index * ADDRESS_LIST_ENTRIES_PER_RUN + entry_index
            )
            page_index, local_index = divmod(flat_index, entries_per_page)
            struct.pack_into(
                "<Q", pages[page_index],
                local_index * ADDRESS_LIST_ENTRY_STRIDE,
                address,
            )
    result = {
        va: bytes(page)
        for va, page in zip(ADDRESS_LIST_PAGE_DVAS, pages)
    }
    hashes = tuple(hashlib.sha256(result[va]).hexdigest()
                   for va in ADDRESS_LIST_PAGE_DVAS)
    expected_hashes = (
        ADDRESS_LIST_COMPLETED_PAGE_SHA256
        if completed else ADDRESS_LIST_PAGE_SHA256
    )
    if hashes != expected_hashes:
        raise ValueError("address-list numeric page hashes changed")
    return result
