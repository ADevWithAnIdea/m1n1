# SPDX-License-Identifier: MIT
"""Small G17P resource-record encodings, independent of capture readers.

The primary index allocation has a firmware-high view and a context-1 low
view. Record page A stores the low address relative to the 64-GiB base in
16-byte units. This helper does not allocate backing or choose a record slot.
"""
import struct


def build_primary_index_address(index_dva):
    index_dva = int(index_dva)
    base = 0x1000000000
    if index_dva < base or index_dva >= base * 2 or index_dva & 0xf:
        raise ValueError("primary index address must be in its aligned low-view window")
    return struct.pack("<I", (index_dva - base) >> 4)


def build_shared_slot_head(index_head):
    """Serialize the shared index head without copying a leaf-page image."""
    index_head = int(index_head)
    if not 0 <= index_head <= 0xffffffff:
        raise ValueError("shared index head must fit u32")
    return struct.pack("<I", index_head)


def build_primary_index_registration(index_dva, index_count):
    """Host-owned address/count pair; leave the adjacent firmware words live."""
    index_count = int(index_count)
    if not 0 < index_count <= 0xffffffff:
        raise ValueError("primary index count must be a positive u32")
    return build_primary_index_address(index_dva) + struct.pack("<I", index_count)


def build_primary_index_page(group_bases):
    """Serialize four consecutive indices per explicit live block group."""
    groups = tuple(map(int, group_bases))
    if not groups or len(groups) > 0x400:
        raise ValueError("index groups must fit one page")
    members = [base + member for base in groups for member in range(4)]
    if any(value < 0 or value > 0xffffffff for value in members):
        raise ValueError("index group is outside u32")
    if len(set(members)) != len(members):
        raise ValueError("index groups overlap")
    body = bytearray(0x4000)
    struct.pack_into("<%dI" % len(members), body, 0, *members)
    return bytes(body)


def build_partial_index_shared_object(*, index_high, index_low, pool_b_slots,
                                      shared_slots, flag, owner, head, tail,
                                      group_count, opaque_84=0x180000):
    """Build the qualified eight-group partial index object from scalars.

    Head/tail and group order are allocator state supplied by the caller. This
    encoder deliberately does not infer a general recycling rule from A2.
    """
    if group_count != 8 or not 0 <= owner < 64:
        raise ValueError("unqualified partial index group count/owner")
    if not 0 <= tail <= head <= 0xffffffff or head - tail != group_count:
        raise ValueError("partial index head/tail do not describe the group inventory")
    pointers = (index_high, index_low, pool_b_slots, shared_slots, flag)
    if any(value <= 0 or value > 0xffffffffffffffff or value & 0x3fff
           for value in pointers):
        raise ValueError("partial index pointers must name aligned pages")
    build_primary_index_address(index_low)
    if not 0 <= opaque_84 <= 0xffffffff:
        raise ValueError("shared-object scalar +0x84 must fit u32")
    body = bytearray(0x4000)
    for offset, value in zip((0x20, 0x28, 0x44, 0x4c, 0x64), pointers):
        struct.pack_into("<Q", body, offset, value)
    for offset, value in ((0x0c, owner), (0x30, 0x10000),
                          (0x34, group_count * 4), (0x38, 0xc18),
                          (0x3c, head), (0x40, tail), (0x54, group_count * 4 - 1),
                          (0x58, 0x20000), (0x7c, 0x3060),
                          (0x80, 0x1020), (0x84, opaque_84)):
        struct.pack_into("<I", body, offset, value)
    return bytes(body)


def build_partial_pool_b(slot_base, shared_slot, index_base, cycle_base, ready_record):
    """80 records including reserved slot zero; numeric namespaces are independent."""
    if (slot_base <= 0 or shared_slot <= 0 or (slot_base | shared_slot) & 3 or
            not 0 <= index_base <= 0xffffffff - 79 * 4 or
            not 0 <= cycle_base <= 0xffffffff - 35 * 0x20 or
            not 0 <= ready_record < 80):
        raise ValueError("invalid partial Pool-B namespace/slot")
    body = bytearray(0x4000)
    for index in range(80):
        offset = index * 0x80
        struct.pack_into("<IIQ", body, offset, index_base + index * 4, 0x10, slot_base + index * 4)
        struct.pack_into("<I", body, offset + 0x28, cycle_base + (index % 36) * 0x20)
        struct.pack_into("<Q", body, offset + 0x40, shared_slot)
    struct.pack_into("<I", body, ready_record * 0x80 + 0x4c, 1)
    return bytes(body)


def build_partial_pool_a(slot_base, ready_record, node_id):
    """36 physical records, including reserved zero, in the partial opening."""
    if (slot_base <= 0 or slot_base & 3 or slot_base + 35 * 4 > 0xffffffffffffffff or
            not 0 <= ready_record < 36 or not 0 <= node_id <= 0xffffffff):
        raise ValueError("invalid partial Pool-A slot/record/node")
    body = bytearray(0x4000)
    for index in range(36):
        struct.pack_into("<Q", body, index * 0x100, slot_base + index * 4)
    struct.pack_into("<I", body, ready_record * 0x100 + 8, node_id)
    struct.pack_into("<I", body, ready_record * 0x100 + 0x10, 0x50)
    return bytes(body)


def build_pool_a_ready_fields(record, slot, node_id):
    """Paired work's host fields; adjacent firmware state is not overwritten."""
    record, slot, node_id = int(record), int(slot), int(node_id)
    if record <= 0 or record & 3 or slot <= 0 or slot & 3:
        raise ValueError("pool record and slot must be nonzero word-aligned addresses")
    if not 0 <= node_id <= 0xffffffff:
        raise ValueError("pool node ID must fit u32")
    return ((record + 8, struct.pack("<I", node_id)),
            (record + 0x10, struct.pack("<I", 0x50)),
            (slot, struct.pack("<I", 2)))


def build_event_notification(counter, grid, *, fragment):
    """Build a complete event record from its owned counter and queue grid."""
    counter, grid = int(counter), int(grid)
    if not 0 <= counter <= 0xffffffff or not 0 <= grid <= 0xffff:
        raise ValueError("event counter/grid is out of range")
    body = bytearray(0x40)
    struct.pack_into("<III", body, 0, 0xe, 0x10000 | grid, counter)
    struct.pack_into("<I", body, 0x10, 0x100 if fragment else 0)
    return bytes(body)


def build_partial_queue_context_item(kind, descriptor, queue, grid, item_index):
    """Partial-layout host record; owner, item index and locator are separate."""
    if kind not in ("tiling", "fragment"):
        raise ValueError("unknown queue-context kind")
    descriptor, queue, grid, item_index = map(int, (descriptor, queue, grid, item_index))
    fragment = kind == "fragment"
    if not 0 <= grid < 128 or grid % 2 != int(fragment):
        raise ValueError("queue grid disagrees with descriptor kind")
    if not 0 <= item_index < 0x3fffffff or queue <= 0:
        raise ValueError("invalid queue context item/queue")
    base = 0xfffffc20c00b0000 if fragment else 0xfffffc20c0018000
    delta = descriptor - base
    if delta < 0 or delta % 0x20:
        raise ValueError("descriptor has no aligned queue-context locator")
    values = {
        0x00: 0x1000000000000000 | (grid << 42) | (4 * (item_index + 1)),
        0x10: descriptor,
        0x18: queue,
        0x20: (0xffff180000000003 if fragment else 0xffff0c0000000001) | ((grid // 2) << 32),
        0x28: ((grid - int(fragment)) << 40) | (item_index + int(fragment)),
        0x178: 0x003fffffffffffff,
    }
    if fragment:
        values[0x30] = (grid << 40) | item_index
        locators = ((0x150, 0x0002b00380004c05), (0x158, 0x0000800380004c3e),
                    (0x160, 0x0000b80380004c77), (0x168, 0x0000500380004cb0))
    else:
        locators = ((0x150, 0x0002380380000003),)
    values.update((offset, locator + delta // 0x20) for offset, locator in locators)
    body = bytearray(0x180)
    for offset, value in values.items():
        struct.pack_into("<Q", body, offset, value)
    return bytes(body)
