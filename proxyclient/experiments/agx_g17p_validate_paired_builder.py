#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate paired G17P construction and publication without hardware."""

import pathlib
import os
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.agx import g17p                         # noqa: E402
from m1n1.agx import g17p_submission as submission  # noqa: E402
from m1n1.agx.g17p_backend import (               # noqa: E402
    G17PChannels,
    G17PPairedWorkBuilder,
    G17PSubmitter,
)
from m1n1.agx.g17p_shim import (                  # noqa: E402
    grid_index_for,
    work_doorbell_channel,
)


class Memory:
    def __init__(self):
        self.next = 0x100000000
        self.allocations = {}
        self.writes = []

    def alloc(self, size, name):
        address = self.next
        self.next += (size + 0xfff) & ~0xfff
        self.allocations[address] = (size, name)
        return address

    def write(self, address, data):
        self.writes.append((address, bytes(data)))

    def last_write(self, address):
        for target, data in reversed(self.writes):
            if target <= address < target + len(data):
                return data[address - target:]
        raise KeyError(address)


class Channels:
    def next_free_slot(self, entry):
        return entry["slot"]


class Queue:
    def __init__(self, address, grid_index=0, write=0):
        self.address = address
        self.pointers_addr = address + 0x1000
        self.item_ring = address + 0x2000
        self.grid_index = grid_index
        self.write = write

    def indices(self):
        return {"read": self.write, "write": self.write, "done": self.write}


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("  ok  %s" % message)


def descriptor_pointers(body, kind):
    layout = submission.DESCRIPTOR_LAYOUT[kind]
    cursor = layout["pointers"]
    result = [struct.unpack_from("<Q", body, cursor)[0]]
    cursor += 8 + layout["pointer_gap"]
    for _ in range(3):
        result.append(struct.unpack_from("<Q", body, cursor)[0])
        cursor += 8
    return result


def main():
    check(g17p.producer_for_slot(0xff) == 0,
          "channel producer wraps from slot 255 to zero")
    check(g17p.producer_reached(0xff, 0, 0),
          "channel completion comparison spans producer wrap")

    channel_words = {0x10: 0xff, 0x20: 0xff, 0x30: 0xff}

    def read_channel_word(address, size):
        assert size == 4
        return struct.pack("<I", channel_words[address])

    channels = G17PChannels.__new__(G17PChannels)
    channels.read = read_channel_word
    channel = {"state_addrs": [0x10, 0x20, 0x30], "ring_addr": 0x1000}
    check(channels.next_free_slot(channel) == 0xff,
          "idle channel publishes slot 255 before wrapping")
    channel_words.update({0x10: 0, 0x20: 1, 0x30: 0xff})
    try:
        channels.next_free_slot(channel)
    except RuntimeError as exc:
        check("full" in str(exc),
              "either lagging consumer applies channel backpressure")
    else:
        raise AssertionError("full channel was accepted")

    check(
        submission.wrap_pool_record_indices(
            submission.ARRAY_A_RECORDS, submission.ARRAY_B_RECORDS) == (0, 0),
        "record pools wrap independently at their finite capacities",
    )
    memory = Memory()
    builder = G17PPairedWorkBuilder(memory.alloc, memory.write)
    graph = builder.build_submission_graph()
    pools = graph["pools"]
    shared = graph["shared"]
    nested = (
        graph["pages"]["primary_index"],
        graph["pages"]["secondary_index"],
        graph["pages"]["shared_slots"],
        graph["pages"]["flag"],
    )
    for name, body in submission.build_submission_leaf_pages().items():
        check(
            memory.last_write(graph["pages"][name]) == body,
            "%s leaf page is generated" % name,
        )
    check(
        memory.last_write(shared[0]) == submission.build_shared_object(nested),
        "packed shared object is generated",
    )
    check(
        memory.last_write(shared[1]) == submission.build_zero_shared_object(),
        "zero shared object is generated",
    )

    pair1_memory = Memory()
    pair1_builder = G17PPairedWorkBuilder(
        pair1_memory.alloc, pair1_memory.write, queue_pair=1)
    pair1_graph = pair1_builder.build_submission_graph()
    pair1_primary = pair1_memory.last_write(
        pair1_graph["pages"]["primary_index"])
    pair1_secondary = pair1_memory.last_write(
        pair1_graph["pages"]["secondary_index"])
    pair1_shared = pair1_memory.last_write(pair1_graph["shared"][0])
    pair1_pool_b = pair1_memory.last_write(pair1_graph["pools"]["pool_b"])
    check(
        struct.unpack_from("<4I", pair1_primary, 0) ==
        (0xcd, 0xce, 0xcf, 0xd0)
        and struct.unpack_from("<Q", pair1_secondary, 0)[0] == 0xcd,
        "pair-one leaf index tables continue at the measured global base",
    )
    check(
        struct.unpack_from("<I", pair1_shared, 0x0c)[0] == 1
        and struct.unpack_from("<I", pair1_shared, 0x28)[0] == 0x00770000
        and struct.unpack_from("<I", pair1_shared, 0x84)[0] == 0x00760000,
        "pair-one packed object carries its measured index state",
    )
    check(
        struct.unpack_from("<Q", pair1_pool_b, 0)[0]
        == 0x0000001000080144
        and struct.unpack_from("<Q", pair1_pool_b, 0x08)[0]
        == pair1_graph["pages"]["pool_b_slots"] + 0x144
        and struct.unpack_from("<I", pair1_pool_b, 0x28)[0] == 0x00758020
        and struct.unpack_from("<Q", pair1_pool_b, 0x40)[0]
        == pair1_graph["pages"]["shared_slots"] + 0x40,
        "pair-one pool-B first record carries its measured index and cycle bases",
    )
    common_optional = {
        "context_scratch": 0x400000000,
        "firmware_scratch": 0x400010000,
        "shared_control": 0x400020000,
        "channel_control": 0x400030000,
    }
    pair = builder.item(
        0,
        None,
        [(0x1748, 1)],
        [(0x1739, 1)],
        common_optional,
        common_optional,
        context_id=1,
    )

    ta_descriptor = memory.last_write(pair["tiling"][0])
    fragment_descriptor = memory.last_write(pair["fragment"][0])
    check(
        sum(target == pair["tiling"][0] for target, _data in memory.writes) == 1
        and sum(target == pair["fragment"][0]
                for target, _data in memory.writes) == 1,
        "each complete work descriptor is published with one host write",
    )
    check(
        descriptor_pointers(ta_descriptor, "tiling")
        == [pools["pool_a"], shared[0], pools["pool_b"], shared[1]],
        "tiling descriptor uses shared pools and objects",
    )
    check(
        descriptor_pointers(fragment_descriptor, "fragment")
        == [pools["pool_a"], shared[0], pools["pool_b"], shared[1]],
        "fragment descriptor uses the same pools and objects",
    )
    check(
        struct.unpack_from("<IQI", ta_descriptor, 0)
        == (0, submission.item_submit_sequence("tiling", 0), 1),
        "tiling common header",
    )
    check(
        struct.unpack_from("<IQI", fragment_descriptor, 0)
        == (1, submission.item_submit_sequence("fragment", 0), 1),
        "fragment common header",
    )

    ordinal_ta = submission.build_descriptor(
        "tiling", (1, 2, 3, 4), (), size=0x400,
        submission_ordinal=2, queue_pair=0)
    ordinal_fragment = submission.build_descriptor(
        "fragment", (1, 2, 3, 4), (), size=0x500,
        submission_ordinal=2, queue_pair=0)
    check(
        all(struct.unpack_from("<I", ordinal_ta, offset)[0] == 0
            for offset in submission.DESCRIPTOR_ORDINAL_FIELDS["tiling"]["pair"])
        and all(struct.unpack_from("<I", ordinal_fragment, offset)[0] == 0
                for offset in submission.DESCRIPTOR_ORDINAL_FIELDS["fragment"]["pair"])
        and all(struct.unpack_from("<I", ordinal_ta, offset)[0] == 3
                for offset in submission.DESCRIPTOR_ORDINAL_FIELDS["tiling"]["work"]),
        "descriptor separates queue-pair and global work ordinals",
    )
    check(
        all(struct.unpack_from("<I", ordinal_ta, offset)[0] == 0x103
            for offset in submission.DESCRIPTOR_ORDINAL_FIELDS["tiling"]["stamps"])
        and all(struct.unpack_from("<I", ordinal_fragment, offset)[0] == 0x103
                for offset in submission.DESCRIPTOR_ORDINAL_FIELDS["fragment"]["stamps"]),
        "global work ordinal advances descriptor stamps",
    )

    os.environ["G17P_NATIVE_TAIL_ITEM_FIELDS"] = "1"
    ordinal_builder = G17PPairedWorkBuilder(memory.alloc, memory.write)
    os.environ.pop("G17P_NATIVE_TAIL_ITEM_FIELDS")
    ordinal_builder.build_submission_graph()
    ordinal_pair = ordinal_builder.item(
        0, None, (), (), common_optional, common_optional,
        context_id=1, submission_ordinal=1, queue_pair=1)
    check(
        struct.unpack_from("<Q", memory.last_write(
            ordinal_pair["fragment"][0] + 0x7a0))[0]
        == 0x70000980a0 + 0x2240,
        "global submission ordinal advances fragment self-relative pointers",
    )
    ordinal_ta = ordinal_pair["tiling"][0]
    ordinal_fragment = ordinal_pair["fragment"][0]
    check(
        struct.unpack_from("<Q", memory.last_write(ordinal_ta + 0x8a6))[0]
        == 0xfffffc20001c8008
        and struct.unpack_from("<Q", memory.last_write(ordinal_ta + 0x8ae))[0]
        == 0xfffffc20c07c0008
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x8ba))[0] == 2
        and struct.unpack_from("<Q", memory.last_write(ordinal_ta + 0x945))[0]
        == 0xfffffc2001638000,
        "pair-one tiling tail selects queue slots, grid, and local status record",
    )
    check(
        struct.unpack_from("<Q", memory.last_write(ordinal_fragment + 0x2140))[0]
        == 0xfffffc20001c800c
        and struct.unpack_from("<Q", memory.last_write(ordinal_fragment + 0x2148))[0]
        == 0xfffffc20c07c000c
        and struct.unpack_from("<I", memory.last_write(ordinal_fragment + 0x2154))[0] == 3
        and struct.unpack_from("<Q", memory.last_write(ordinal_fragment + 0x21df))[0]
        == 0xfffffc2001650000,
        "pair-one fragment tail selects queue slots, grid, and local status record",
    )
    check(
        struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x79c))[0] == 3
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x7a0))[0]
        == 0x100
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x7a8))[0] == 1
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x7b0))[0]
        == 0x101
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x8b4))[0]
        == 0x0100ffff
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x8c0))[0]
        == 0x10000
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x8c4))[0]
        == 0x10000
        and struct.unpack_from("<I", memory.last_write(ordinal_ta + 0x8c8))[0]
        == 0x01000000,
        "pair-one tiling tail carries the first local item index family",
    )
    check(
        struct.unpack_from("<I", memory.last_write(ordinal_fragment + 0x2150))[0]
        == 0x100
        and struct.unpack_from("<I", memory.last_write(
            ordinal_fragment + 0x215c))[0] == 1
        and struct.unpack_from("<I", memory.last_write(
            ordinal_fragment + 0x2160))[0] == 1
        and struct.unpack_from("<I", memory.last_write(
            ordinal_fragment + 0x2164))[0] == 0x100,
        "pair-one fragment tail carries the first local item index family",
    )
    ordinal_record = (ordinal_builder.tiling.array_a
                      + 0 * submission.ARRAY_A_STRIDE)
    check(
        struct.unpack_from("<I", memory.last_write(ordinal_record + 0x08))[0] == 1
        and struct.unpack_from(
            "<I", memory.last_write(
                ordinal_record + submission.ARRAY_A_FIRST_MARKER_OFFSET))[0]
        == submission.ARRAY_A_FIRST_MARKER,
        "selected pool-A record carries host work ordinal and marker",
    )

    repeated_pair1 = ordinal_builder.item(
        1, None, (), (), common_optional, common_optional,
        context_id=1, submission_ordinal=4, queue_pair=1)
    repeated_ta_body = memory.last_write(repeated_pair1["tiling"][0])
    repeated_fragment_body = memory.last_write(repeated_pair1["fragment"][0])
    check(
        struct.unpack_from("<Q", repeated_ta_body, 0x10)[0]
        == ordinal_builder.tiling.array_a + 2 * submission.ARRAY_A_STRIDE
        and struct.unpack_from("<Q", repeated_fragment_body, 0x30)[0]
        == ordinal_builder.fragment.array_b + submission.ARRAY_B_STRIDE
        and struct.unpack_from(
            "<I", memory.last_write(repeated_pair1["fragment"][0] + 0x90))[0]
        == 2,
        "later created-pair work advances pool A twice and pool B once",
    )
    check(
        struct.unpack_from(
            "<Q", memory.last_write(repeated_pair1["tiling"][0] + 0x945))[0]
        == 0xfffffc2001638040
        and struct.unpack_from(
            "<Q", memory.last_write(repeated_pair1["fragment"][0] + 0x21df))[0]
        == 0xfffffc2001650040,
        "later pair-one work advances its pair-local status records",
    )

    pair1_ta_context = submission.build_queue_context("tiling", pair=1)
    pair1_fragment_context = submission.build_queue_context("fragment", pair=1)
    check(
        struct.unpack_from("<Q", pair1_ta_context, 0x200)[0]
        == 0x0000080000000004
        and struct.unpack_from("<Q", pair1_ta_context, 0x228)[0]
        == 0x0000020000000000,
        "created tiling queue context carries pair-one state",
    )
    check(
        struct.unpack_from("<Q", pair1_fragment_context, 0x200)[0]
        == 0x04000c0000000004
        and struct.unpack_from("<Q", pair1_fragment_context, 0x368)[0]
        == 0x0000100380004dc2,
        "created fragment queue context carries pair-one state",
    )

    second_ta_context = submission.build_queue_context_item(
        "tiling", 0xfffffc20c0019380, 0xfffffc20c0000000,
        pair=0, item_index=1)
    second_fragment_context = submission.build_queue_context_item(
        "fragment", 0xfffffc20c00b4480, 0xfffffc20c00000c0,
        pair=0, item_index=1)
    check(
        struct.unpack_from("<Q", second_ta_context, 0x00)[0] == 8
        and struct.unpack_from("<Q", second_ta_context, 0x10)[0]
        == 0xfffffc20c0019380
        and struct.unpack_from("<Q", second_ta_context, 0x28)[0] == 1
        and struct.unpack_from("<Q", second_ta_context, 0x150)[0]
        == 0x000238038000009f,
        "second pair-zero tiling context item matches the native third publication",
    )
    check(
        struct.unpack_from("<Q", second_fragment_context, 0x00)[0]
        == 0x0400040000000008
        and struct.unpack_from("<Q", second_fragment_context, 0x08)[0]
        == 0x000000e000139640
        and struct.unpack_from("<Q", second_fragment_context, 0x10)[0]
        == 0xfffffc20c00b4480
        and struct.unpack_from("<Q", second_fragment_context, 0x28)[0] == 2
        and struct.unpack_from("<Q", second_fragment_context, 0x30)[0]
        == 0x0000010000000001
        and struct.unpack_from("<Q", second_fragment_context, 0x150)[0]
        == 0x0002b00380004e29
        and struct.unpack_from("<Q", second_fragment_context, 0x168)[0]
        == 0x0000100380004ed4,
        "second pair-zero fragment context item matches the native third publication",
    )

    ta_optional = memory.last_write(pair["tiling"][1])
    fragment_optional = memory.last_write(pair["fragment"][1])
    check(
        ta_optional == submission.build_optional_item(
            "tiling", **common_optional, tiling_shared_object=shared[0]),
        "tiling optional item is generated",
    )
    check(
        fragment_optional
        == submission.build_optional_item(
            "fragment", **common_optional, grid_index=1),
        "fragment optional item is generated",
    )
    ordinal_ta_optional = memory.last_write(ordinal_pair["tiling"][1])
    ordinal_fragment_optional = memory.last_write(
        ordinal_pair["fragment"][1])
    check(
        ordinal_ta_optional == submission.build_optional_item(
            "tiling", **common_optional,
            tiling_shared_object=ordinal_builder.shared[0], grid_index=2,
            submission_ordinal=1),
        "pair-one tiling optional item carries grid and pair state",
    )
    check(
        ordinal_fragment_optional == submission.build_optional_item(
            "fragment", **common_optional, grid_index=3,
            submission_ordinal=1),
        "pair-one fragment optional item carries grid and pair state",
    )
    repeated_optional = submission.build_optional_item(
        "tiling", **common_optional, tiling_shared_object=shared[0],
        grid_index=0, item_index=1, submission_ordinal=2)
    check(
        all(struct.unpack_from("<H", repeated_optional, offset)[0] == 0
            for offset in (0x1a, 0x52, 0x62))
        and struct.unpack_from("<H", repeated_optional, 0x2a)[0] == 1
        and struct.unpack_from("<H", repeated_optional, 0x2e)[0] == 0x100
        and struct.unpack_from("<H", repeated_optional, 0x3e)[0] == 2
        and struct.unpack_from("<H", repeated_optional, 0x76)[0] == 2,
        "later optional item carries queue-local and global lifecycle state",
    )
    for kind in ("tiling", "fragment"):
        event = pair[kind][2]
        size, name = memory.allocations[event]
        check(size == submission.EVENT_ITEM_SIZE,
              "%s event allocation reserves firmware output" % kind)
        check(memory.last_write(event) == bytes(submission.EVENT_RECORD_SIZE),
              "%s host event record starts clear without erasing later records" % kind)

    publication_writes = []
    doorbells = []
    doorbell_channels = []

    def publish_write(address, data):
        publication_writes.append((address, bytes(data)))

    def ring(channel=0):
        doorbells.append(len(publication_writes))
        doorbell_channels.append(channel)

    submitter = G17PSubmitter(
        lambda _address, size: bytes(size),
        publish_write,
        ring,
        Channels(),
    )
    ta_entry = {
        "slot": 2,
        "ring_addr": 0x500000000,
        "state_addrs": (0, 0, 0x500010000),
    }
    fragment_entry = {
        "slot": 3,
        "ring_addr": 0x600000000,
        "state_addrs": (0, 0, 0x600010000),
    }
    ta_queue = Queue(0x700000000)
    fragment_queue = Queue(0x800000000, grid_index=1)
    submitter.stage(ta_entry, ta_queue, pair["tiling"], 1,
                    first_submit=True, kind="tiling")
    submitter.stage(fragment_entry, fragment_queue, pair["fragment"], 1,
                    first_submit=True, kind="fragment")
    check(not doorbells, "both channel publications are staged before wakeup")
    writes_before_notify = len(publication_writes)
    submitter.notify()
    check(
        doorbells
        == [writes_before_notify] * g17p.PUBLISH_DOORBELL_RINGS,
        "shared doorbell uses the configured count after both publications",
    )
    submitter.notify(0x8)
    check(
        doorbell_channels[-g17p.PUBLISH_DOORBELL_RINGS:]
        == [0x8] * g17p.PUBLISH_DOORBELL_RINGS,
        "submitter forwards an explicitly selected doorbell channel",
    )
    check(
        grid_index_for("TA_1") == 4
        and work_doorbell_channel(0) == 0,
        "queue grid and multiplexed transport doorbell are independent",
    )
    check(
        (pair["tiling"][2], g17p.build_event_record(1, "tiling", 0))
        in publication_writes,
        "tiling event record carries its grid index",
    )
    check(
        (pair["fragment"][2], g17p.build_event_record(1, "fragment", 1))
        in publication_writes,
        "fragment event record carries its grid index and kind word",
    )

    # Queues append independently even though their shared channel slots interleave. A shallow
    # four-slot trace looked like heads 3,3,6,6 on one queue; the queue pointers show that this is
    # pair 0 at 3, pair 1 at 3, pair 0 at 6, pair 1 at 6.
    publication_writes.clear()
    appended = Queue(0x900000000, write=6)
    next_group = (0xa00000000, 0xa00001000, 0xa00002000)
    published = submitter.stage(
        ta_entry, appended, next_group, 3, kind="tiling")
    check(published["write_before"] == 6 and published["write_after"] == 9,
          "a later group advances its own queue from six to nine")
    for index, address in enumerate(next_group, 6):
        check((appended.item_ring + index * 8, struct.pack("<Q", address))
              in publication_writes,
              "appended item %d is written into the third group" % index)
    check((appended.pointers_addr + g17p.QUEUE_PTR_WRITE, struct.pack("<I", 9))
          in publication_writes,
          "the appended publication advances write index to nine")

    publication_writes.clear()
    reusable = Queue(0x910000000, write=3)
    refreshed = (0xb00000000, 0xb00001000, 0xb00002000)
    published = submitter.stage(
        ta_entry, reusable, refreshed, 2, kind="tiling", in_place=True)
    check(published["write_before"] == 3 and published["write_after"] == 3,
          "an in-place publication keeps the queue head at three")
    for index, address in enumerate(refreshed):
        check((reusable.item_ring + index * 8, struct.pack("<Q", address))
              in publication_writes,
              "in-place publication refreshes item %d" % index)

    print("Paired builder and publication gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
