# SPDX-License-Identifier: MIT
"""Minimal T8140/G17P accelerator backend.

This is the part a DRM shim calls: find the channels, find a command queue, and
publish work so firmware consumes it. Every step here was established on hardware
and is recorded in ``docs/t8140-g17p-firmware-abi-spec.md``; the publication sequence in
particular was arrived at by a series of failed attempts, so the ordering and the
announce-then-ring discipline are load-bearing rather than incidental.

The paired builder constructs the firmware-side item graph. Callers still supply
register values and the render-context objects those values name, which is the
remaining translation from a userspace command buffer to new rendering.

The accessors take a read and write callback so the same code can run against a
frozen guest through the hypervisor, or against firmware the host started itself.
"""

import os
import struct

from . import g17p
from . import g17p_render
from . import g17p_submission as submission


class G17PChannels:
    """The channel table, read out of a live initialization descriptor."""

    CHANNEL_TABLE_OFFSET = g17p.CHANNEL_TABLE_OFFSET
    ENTRY_SIZE = g17p.CHANNEL_ENTRY_SIZE

    def __init__(self, read, initdata_addr):
        self.read = read
        self.initdata_addr = initdata_addr
        root = read(initdata_addr, 0x20)
        self.main_config = struct.unpack_from("<Q", root, 0x18)[0]
        self.entries = []
        for index in range(g17p.CHANNEL_TABLE_ENTRIES):
            base = self.main_config + self.CHANNEL_TABLE_OFFSET + index * self.ENTRY_SIZE
            words = struct.unpack_from("<4Q", read(base, self.ENTRY_SIZE), 0)
            name = (g17p.CHANNEL_TABLE_WORK_ORDER[index]
                    if index < g17p.CHANNEL_TABLE_WORK_COUNT else None)
            self.entries.append({
                "index": index,
                "name": name,
                "state_addrs": list(words[:3]),
                "ring_addr": words[3],
            })

    def by_name(self, name):
        for entry in self.entries:
            if entry["name"] == name:
                return entry
        raise KeyError(name)

    def counters(self, entry):
        """The channel's three state counters.

        The third is the producer the host advances; the other two are firmware's.

        Each counter is read at its own address. An earlier version read them as offsets 0, 0x10 and
        0x20 of one 0x40-aligned block, which is right only because a work or control channel's three
        addresses happen to lie 0x10 apart. The firmware-produced channels' do not: channel 14 keeps
        its second counter in an entirely different page, so the block read returned memory that was
        not a counter at all and moved for unrelated reasons.
        """
        return [struct.unpack("<I", self.read(addr, 4))[0] if addr else 0
                for addr in entry["state_addrs"]]

    def next_free_slot(self, entry):
        """Return the producer slot, refusing to overtake either consumer."""
        consumers = self.counters(entry)
        if any(value & ~g17p.PRODUCER_MASK for value in consumers):
            raise RuntimeError("channel counters outside 8-bit range: %r" % consumers)
        producer = consumers[2]
        next_producer = g17p.next_producer(producer)
        if next_producer in consumers[:2]:
            raise RuntimeError(
                "channel ring is full: consumers %r, producer %#x" %
                (consumers[:2], producer))
        return producer

    def slot(self, entry, index):
        data = self.read(entry["ring_addr"] + index * g17p.RING_SLOT_SIZE,
                         g17p.RING_SLOT_SIZE)
        queue = struct.unpack_from("<Q", data, g17p.RING_SLOT_QUEUE_PTR)[0]
        packed = struct.unpack_from("<I", data, g17p.RING_SLOT_FLAGS_HEAD)[0]
        result = g17p.decode_slot_flags(packed)
        result["queue"] = queue
        return result


class G17PQueue:
    """One command queue: its record, pointer block, item ring and job list."""

    def __init__(self, read, address, grid_index):
        self.read = read
        self.address = address
        self.grid_index = grid_index
        record = read(address, g17p.QUEUE_DESCRIPTOR_SIZE)
        self.record = g17p.parse_queue_record(record)
        self.pointers_addr = self.record["pointers_addr"]
        self.item_ring = self.record["ring_addr"]
        self.job_list_addr = self.record["job_list_addr"]

    def indices(self):
        block = self.read(self.pointers_addr, g17p.QUEUE_PTR_BLOCK_SIZE)
        return g17p.parse_queue_pointers(block)

    def items(self, count=None):
        write = self.indices()["write"] if count is None else count
        if not write:
            return []
        data = self.read(self.item_ring, write * g17p.ITEM_RING_ENTRY_SIZE)
        return list(struct.unpack_from("<%dQ" % write, data, 0))

    def groups(self):
        """Split the populated item ring into submission groups."""
        result, current = [], []
        for index, address in enumerate(self.items()):
            if not address:
                continue
            current.append(index)
            selector = struct.unpack_from("<I", self.read(address, 4), 0)[0]
            if selector == g17p.SELECTOR_EVENT:
                result.append(current)
                current = []
        return result


class G17PSubmitter:
    """Publishes submission groups onto a channel.

    The sequence and its ordering come from hardware: the payload and every index first, then
    the doorbell.

    Two claims that stood here are withdrawn. The queue's work announcement is not part of what
    a host does: publishing without writing that field at all, firmware still takes the entries
    off the ring and retires the group, and a working host leaves it zero on every queue.
    ``announce`` therefore defaults to reproducing the transition only because callers relied on
    it, not because firmware needs it. And an idle firmware does not require a second doorbell to
    act: a world that renders sends exactly one, on the first instance, with a zero channel field.

    A third claim is withdrawn. That a first group is taken during the control-start notification
    rather than at a doorbell was read as a property of the part; it is a property of publishing
    before the control start. A working host's capture, trapped at its own first work doorbell, has
    the opening performed and the group published and untouched: write pointer 3, done index 0.
    Holding the producer back until after the control start puts this path in that same position.
    """

    def __init__(self, read, write, doorbell, channels):
        self.read = read
        self.write = write
        self.doorbell = doorbell
        self.channels = channels
        # When this is a list rather than None, the channel producer advance is collected here
        # instead of being written. Firmware scans a channel by its producer index, so holding it
        # back is what keeps a staged group invisible until a caller chooses to reveal it.
        self.deferred_producers = None

    def stage(self, entry, queue, item_addresses, group_number, slot=None,
              first_submit=False, kind=None, in_place=False, announce=True,
              event_subtype=None, event_counter=None, event_counter_low=0,
              queue_indices=None,
              consumers_before=None):
        """Make one group visible without ringing the shared work doorbell.

        ``slot`` overrides which ring slot announces the group. Firmware takes its startup work
        from slot zero, and whether the slot a publication uses matters is not established, so a
        caller is allowed to choose rather than always taking the next free one.
        """
        indices = queue.indices() if queue_indices is None else queue_indices
        write_index = indices["write"]
        slot_index = (self.channels.next_free_slot(entry)
                      if slot is None else int(slot))

        # A host's first publication appends one group. Its second replaces that first group, its
        # third appends the second group, and later submissions replace the second group. The
        # channel producer and its next ring slot publish each replacement.
        first_entry = (write_index - len(item_addresses)) if in_place else write_index
        if first_entry < 0:
            raise ValueError("no group to write over: write index is %d" % write_index)
        for offset, address in enumerate(item_addresses):
            self.write((queue.item_ring
                        + (first_entry + offset) * g17p.ITEM_RING_ENTRY_SIZE),
                       struct.pack("<Q", address))

        # The event item's first record is the only part of it the host writes. Live captures use
        # 0x10000 | queue.grid_index on every observed work submission. ``event_subtype`` remains an
        # explicit experiment override; None selects the captured grid-derived form.
        event = bytearray(g17p.build_event_record(
            group_number, kind, queue.grid_index, subtype=event_subtype))
        if event_counter is not None:
            struct.pack_into(
                "<I", event, g17p.EVENT_RECORD_COUNTER,
                int(event_counter))
        elif event_counter_low:
            counter = struct.unpack_from("<I", event, g17p.EVENT_RECORD_COUNTER)[0]
            struct.pack_into(
                "<I", event, g17p.EVENT_RECORD_COUNTER,
                counter | int(event_counter_low))
        self.write(item_addresses[-1], event)

        new_write = write_index if in_place else write_index + len(item_addresses)
        self.write(queue.pointers_addr + g17p.QUEUE_PTR_WRITE,
                   struct.pack("<I", new_write))

        self.write(entry["ring_addr"] + slot_index * g17p.RING_SLOT_SIZE,
                   g17p.build_ring_slot(queue.address, new_write,
                                        queue.grid_index, first_submit, kind))
        producer_write = (entry["state_addrs"][2],
                          struct.pack("<I", g17p.producer_for_slot(slot_index)))
        # A caller may defer only some channels, so that one stage is visible when firmware
        # performs the opening and the other is not. That is how to tell which stage faults.
        defer_names = getattr(self, "defer_only", None)
        if self.deferred_producers is None or (
                defer_names is not None and entry.get("name") not in defer_names):
            self.write(*producer_write)
        else:
            self.deferred_producers.append(producer_write)

        # Announce last, by writing the queue record's has-commands field. Whether a host writes it
        # at all is open: it reads zero on every queue in a world six submissions in, including the
        # pair still in use, so a host does not leave it set. ``announce`` exists to publish without
        # it, since setting a field a host never sets is a way to wedge firmware rather than to
        # signal it.
        if announce:
            for value in g17p.PUBLISH_ANNOUNCE_SEQUENCE:
                self.write(queue.address + g17p.PUBLISH_ANNOUNCE_OFFSET,
                           struct.pack("<I", value))

        return {
            "slot": slot_index,
            "producer": g17p.producer_for_slot(slot_index),
            "consumers_before": (
                consumers_before if consumers_before is not None else
                (self.channels.counters(entry)[:2]
                 if hasattr(self.channels, "counters") else None)),
            "write_before": write_index,
            "write_after": new_write,
            "group_number": group_number,
            "items": list(item_addresses),
        }

    def notify(self, channel=0):
        """Wake firmware after every channel in a paired submission is staged."""
        for _ in range(g17p.PUBLISH_DOORBELL_RINGS):
            if channel:
                self.doorbell(channel)
            else:
                self.doorbell()

    def publish(self, entry, queue, item_addresses, group_number):
        """Stage one group and immediately notify firmware."""
        published = self.stage(entry, queue, item_addresses, group_number)
        self.notify(queue.grid_index << 2)
        return published

    def accepted(self, entry, queue, published):
        """True once firmware has taken the publication off the ring.

        This is the weaker of the two signals: the queue's read index has reached
        the new write index, so firmware has consumed the entries.
        """
        return queue.indices()["read"] >= published["write_after"]

    def completed(self, entry, queue, published):
        """True once firmware reports the work as finished.

        Distinct from acceptance. Republishing item buffers from a drained group is
        accepted and the read index advances, but the done index does not, because
        the items' progress state was already consumed. Real completion needs the
        item body's progress fields refreshed, which this module does not do.
        """
        counters = self.channels.counters(entry)
        before = published.get("consumers_before")
        if before is None:
            channel_done = counters[0] == published["producer"]
        else:
            channel_done = all(
                g17p.producer_reached(start, current, published["producer"])
                for start, current in zip(before, counters[:2]))
        return (queue.indices()["done"] >= published["write_after"]
                and channel_done)

    def consumed(self, entry, queue, published):
        """Deprecated name for :meth:`completed`."""
        return self.completed(entry, queue, published)


class G17PQueueFence:
    """One firmware queue-prefix completion point.

    The queue's done cursor controls ownership: once it covers ``write_after``
    firmware has finished every earlier item on that queue.  A command-local
    status destination may be attached for attribution and timestamps, but it
    is diagnostic rather than the ownership predicate.
    """

    def __init__(self, submitter, entry, queue, published,
                 status_read=None, status_initial=None, name=None):
        self.submitter = submitter
        self.entry = entry
        self.queue = queue
        self.published = dict(published)
        self.status_read = status_read
        self.status_initial = (bytes(status_initial)
                               if status_initial is not None else None)
        self.name = name or "queue %#x at %d" % (
            queue.address, self.published["write_after"])

    @property
    def sequence(self):
        return self.published["write_after"]

    def accepted(self):
        return self.submitter.accepted(
            self.entry, self.queue, self.published)

    def signaled(self):
        return self.submitter.completed(
            self.entry, self.queue, self.published)

    def status(self):
        return bytes(self.status_read()) if self.status_read is not None else None

    def status_changed(self):
        current = self.status()
        return (current is not None and self.status_initial is not None
                and current != self.status_initial)

    def snapshot(self):
        return {
            "name": self.name,
            "sequence": self.sequence,
            "queue": self.queue.indices(),
            "channel": self.submitter.channels.counters(self.entry),
            "accepted": self.accepted(),
            "signaled": self.signaled(),
            "status": self.status(),
            "status_changed": self.status_changed(),
        }

    def wait(self, timeout=2.0, event_pump=None, poll_interval=0.0001):
        import time

        deadline = time.monotonic() + timeout
        while True:
            if self.signaled():
                return self.snapshot()
            if time.monotonic() >= deadline:
                break
            if event_pump is not None:
                event_pump()
            time.sleep(poll_interval)
        raise TimeoutError(
            "G17P fence did not signal: %r" % self.snapshot())

class G17PWorkBuilder:
    """Builds the bodies a submission needs, so a caller need not find them.

    ``G17PSubmitter`` publishes item addresses and says so: it does not build what
    those addresses point at. This does, from the model in ``g17p_submission``, which
    is checked against captured submissions by three gates.

    A queue's two record pools are built once, by ``build_pools``. Each work item then
    takes the next record of each, which is the whole of the per-item allocation on
    this part; nothing is allocated per submission. ``item`` returns the address triple
    ``G17PSubmitter.publish`` expects.

    What a caller supplies: an allocator returning device addresses in the firmware's
    context, the two shared pointers every item's descriptor carries, and the register
    list for each item. The register values contain addresses in the *render* context,
    which is a separate address space and the caller's to allocate in.

    What this does not build: the remaining kind-specific descriptor fields outside
    the common header, pointer block, and register array. The first hardware replay
    executes with those fields zero, but their roles in later work are not established.
    """

    def __init__(self, alloc, write, kind="tiling", queue_pair=0):
        # A tail of zeros reserves the space firmware reads but names nothing; the addresses in
        # TAIL_POINTERS are what make the item describe real work.
        self.write_tail = True
        self.low_alias = None
        self.alloc = alloc
        self.write = write
        self.kind = kind
        self.queue_pair = queue_pair
        self.write_lifecycle_fields = (
            os.getenv("G17P_NATIVE_LIFECYCLE_FIELDS") == "1")
        self.write_item_fields = (
            os.getenv("G17P_NATIVE_ITEM_FIELDS") == "1"
            or os.getenv("G17P_NATIVE_TAIL_ITEM_FIELDS") == "1")
        self.write_structural_tail = (
            os.getenv("G17P_STRUCTURAL_TAIL_FIELDS") == "1")
        # Runtime graph allocations replace the historical bootstrap addresses
        # in TAIL_POINTERS. Keys are descriptor byte offsets; status_base is the
        # first 0x40-byte pair-local status record for this descriptor kind.
        self.tail_pointer_overrides = {}
        self.status_base = None
        self.array_a = None
        self.array_b = None
        self.descriptors = []

    def build_pools(self, slot_base_a, slot_base_b, shared_slot):
        """Allocate and fill both record pools.

        The slot bases are addresses of the four-byte locations the records name, one a
        record; ``shared_slot`` is the address every record of the second pool carries
        unchanged. The pools are generated rather than copied, which the submission gate
        checks byte for byte against a capture.
        """
        body_a = submission.build_record_array_a(slot_base_a)
        body_b = submission.build_record_array_b(
            slot_base_b, shared_slot, pair_index=self.queue_pair)
        self.array_a = self.alloc(len(body_a), "record_pool_a")
        self.array_b = self.alloc(len(body_b), "record_pool_b")
        self.write(self.array_a, body_a)
        self.write(self.array_b, body_b)
        return {"pool_a": self.array_a, "pool_b": self.array_b,
                "capacity": (submission.ARRAY_A_RECORDS,
                             submission.ARRAY_B_RECORDS)}

    def use_pools(self, array_a, array_b):
        """Use record pools owned by the paired descriptor half."""
        self.array_a = array_a
        self.array_b = array_b

    # Body bytes the descriptor builder does not produce and a group will not draw without.
    # Measured: with these absent and everything else correct, both queues retire the group and
    # it writes nothing at all; with them present it draws. Their meaning is not established,
    # only that they are required and constant across the submissions seen so far.
    # What firmware reads for a work item, which is more than the descriptor builder returns.
    # The compact body is what the queue parser needs; the rest is read through the other view
    # and has to be reserved, or the next allocation lands inside the previous item. Measured:
    # without this the fragment descriptor was placed at the tiling body's +0x3d0 and the group
    # retired having drawn nothing.
    BODY_STRIDE = {"tiling": 0x9c0, "fragment": 0x2240}

    # Every address a work item's tail holds, at the offset it is held at. Several are unaligned,
    # which is why they are listed rather than found. Two of each kind's entries are the item's
    # own address seen through a low alias in context 0. Queue-pair slots advance by eight bytes;
    # status records are pair-local arrays whose records advance by 0x40 bytes.
    TAIL_POINTERS = {
        "tiling": (
            (0x0760, 0x7000000060, "self"),
            (0x0780, 0x1000240000, None),
            (0x08a6, 0xfffffc20001c8000, "pair_slot"),
            (0x08ae, 0xfffffc20c07c0000, "pair_slot"),
            (0x08fe, 0xfffffc2000024c68, None),
            (0x0934, 0xfffffc20c0830000, None),
            (0x0945, 0, "status"),
        ),
        "fragment": (
            (0x07a0, 0x70000980a0, "self"),
            (0x0ec0, 0x70000987c0, "self"),
            (0x15e0, 0x7000098ee0, "self"),
            (0x1d00, 0x7000099600, "self"),
            (0x1f4e, 0x1000000000, None),
            (0x2140, 0xfffffc20001c8004, "pair_slot"),
            (0x2148, 0xfffffc20c07c0004, "pair_slot"),
            (0x2198, 0xfffffc2000024c68, None),
            (0x21a0, 0xfffffc2000024c70, None),
            (0x21ce, 0xfffffc20c0830000, None),
            (0x21df, 0, "status"),
        ),
    }

    PAIR_STATUS_BASES = {
        "tiling": (0xfffffc2001610000, 0xfffffc2001638000,
                   0xfffffc2001690000, 0xfffffc20c1698000),
        "fragment": (0xfffffc2001630000, 0xfffffc2001650000,
                     0xfffffc20016b0000, 0xfffffc20c16c8000),
    }

    PAIR_GRID_FIELDS = {
        "tiling": (0x08ba, 0),
        "fragment": (0x2154, 1),
    }

    LIFECYCLE_FIELDS = {
        "tiling": (0x1ca10, 0x086e, 0x08ce),
        "fragment": (0x160e0, 0x2108, 0x2168),
    }

    BODY_FIELDS = {
        "tiling": ((0x38, 0x47), (0x3a, 0x49), (0x3c, 0x49)),
        # The fragment register array starts at +0xa0.  In particular, +0xc8
        # and +0xe0 are the low bytes of the caller-selected store and load
        # pipeline values (registers 0x15381 and 0x15371), not body constants.
        # Older captures happened to contain 0x40 in both locations; writing
        # those bytes after encoding the register array silently redirected
        # any pipeline whose low byte was different.
        "fragment": ((0x50, 0x01), (0x80, 0x56), (0x82, 0x57), (0x84, 0x57),
                     (0x88, 0x59)),
    }

    def _write_item_tail_fields(self, body, index, queue_pair,
                                queue_grid_index=None):
        """Write descriptor-tail values derived only from item and pair indices."""
        item_number = int(index) + 1
        queue_pair = int(queue_pair)
        if queue_grid_index is None:
            queue_grid_index = queue_pair * 2 + (
                0 if self.kind == "tiling" else 1)
        queue_grid_index = int(queue_grid_index)
        if self.kind == "tiling":
            fields = (
                (0x079c, queue_grid_index + 1),
                (0x07a0, item_number * 0x100),
                (0x07a8, item_number),
                (0x07b0, item_number * 0x101),
                (0x08b4, (item_number << 24) | 0xffff),
                (0x08c4, item_number << 16),
                (0x08c8, item_number << 24),
                (0x08d4, int(index) << 16),
            )
        else:
            fields = (
                (0x2150, item_number << 8),
                (0x215c, 1),
                (0x2160, item_number),
                (0x2164, item_number << 8),
                (0x2170, int(index)),
            )
        for offset, value in fields:
            struct.pack_into("<I", body, offset, value)

    def _write_structural_tail(self, body, parameters, registers):
        """Patch host-owned state beyond the G17P register array."""
        values = dict(registers.items() if hasattr(registers, "items")
                      else registers)

        sampler_array = int(getattr(parameters, "sampler_array", 0))
        sampler_count = int(getattr(parameters, "sampler_count", 0))
        if bool(sampler_array) != bool(sampler_count):
            raise ValueError(
                "render sampler array and count must both be zero or nonzero")
        if sampler_array & 7:
            raise ValueError("render sampler array must be 8-byte aligned")
        sampler_max = sampler_count + 1 if sampler_count else 0

        def put(offset, fmt, value):
            struct.pack_into("<" + fmt, body, offset, value)

        if self.kind == "tiling":
            deflake = values.get(0x10111)
            if deflake is None:
                raise ValueError("tiling structural tail requires register 0x10111")
            put(0x0768, "I", 0x036c0049)
            # This tail pointer names the same caller-selected TPC allocation
            # as the TA register program. Keeping the original bring-up DVA
            # here made otherwise relocated/partial submissions internally
            # inconsistent even though their register arrays were correct.
            put(0x0780, "Q", parameters.tpc)
            put(0x0789, "B", 0x78)
            put(0x07d6, "I", deflake & 0xffffffff)
            put(0x0876, "I", 0xffffffff)
            put(0x087a, "Q", sampler_array)
            put(0x0882, "I", sampler_count)
            put(0x0886, "I", sampler_max)
            put(0x0932, "B", 0x44)
            put(0x093c, "B", 1)
            put(0x094d, "B", 1)
            put(0x08fe, "Q", parameters.timestamp_a)
            put(0x0906, "Q", parameters.ta_timestamp_end)
            put(0x090e, "Q", parameters.ta_user_timestamp_start)
            put(0x0916, "Q", parameters.ta_user_timestamp_end)
            return

        if parameters is None:
            raise ValueError("fragment structural tail requires render parameters")

        def put_register_program(header_offset, program_offset, entries):
            encoded = submission.build_register_array(entries)
            if len(entries) > 0xffff or len(encoded) > 0xffff:
                raise ValueError("embedded fragment register program is too large")
            put(header_offset, "I", (len(encoded) << 16) | len(entries))
            body[program_offset:program_offset + len(encoded)] = encoded

        partial_store_registers = (
            g17p_render.build_fragment_partial_store_registers(parameters))
        partial_resume_registers = (
            g17p_render.build_fragment_partial_resume_registers(parameters))
        partial_load_registers = (
            g17p_render.build_fragment_partial_load_registers(parameters))

        # Each 0x720-byte structural block describes the register program in
        # the preceding block. The first header therefore describes the main
        # 89-write array at +0xa0; the remaining three name explicit partial
        # store, combined pause/resume, and partial-load programs.
        main_encoded = submission.build_register_array(registers)
        put(0x07a8, "I", (len(main_encoded) << 16) | len(registers))
        put_register_program(0x0ec8, 0x07c0, partial_store_registers)
        put_register_program(0x15e8, 0x0ee0, partial_resume_registers)
        put_register_program(0x1d08, 0x1600, partial_load_registers)

        put(0x1d20, "Q", parameters.depth_bias_array)
        put(0x1d30, "Q", parameters.scissor_array)
        put(0x1d40, "Q", parameters.occlusion_query_base)
        put(0x1e78, "Q", parameters.load_pipeline_bind)
        put(0x1e80, "Q", parameters.load_pipeline)
        put(0x1ea8, "Q", parameters.partial_load_pipeline_bind)
        put(0x1eb0, "Q", parameters.partial_load_pipeline)
        put(0x1ec0, "I", 0x04040404)
        put(0x1f38, "Q", parameters.tib_blocks)
        put(0x1f40, "Q", parameters.aux_fb_flags)
        put(0x1f48, "I", parameters.width)
        put(0x1f4c, "I", parameters.height)
        put(0x1f50, "Q", parameters.aux_fb_page_count)
        put(0x1f58, "Q", parameters.tile_config)
        put(0x1f78, "I", parameters.store_pipeline_bind)
        put(0x1f7c, "Q", parameters.store_pipeline)
        put(0x1f98, "I", parameters.partial_store_pipeline_bind)
        put(0x1f9c, "Q", parameters.partial_store_pipeline)
        put(0x1fa8, "I", parameters.depth_clear_value_bits)
        # This is a packed TIB-capacity scalar, not a pointer.  The native
        # corpus gives 0x8_00000300, 0x10_00000300, and 0x20_00000300 for 4,
        # 8, and 16 blocks respectively.
        put(0x1fac, "Q", (int(parameters.tib_blocks) << 33) | 0x300)
        # Native ordinary work carries (0x2100, 0x2124) = (1, 0), while the
        # executing overflow/partial workload carries (0, 1).  These are one
        # process-empty-tiles choice represented in two complementary fields,
        # not two independent fixed flags.
        put(0x2100, "B", int(not parameters.process_empty_tiles))
        put(0x2110, "I", 0xffffffff)
        put(0x2114, "Q", sampler_array)
        put(0x211c, "I", sampler_count)
        put(0x2120, "I", sampler_max)
        put(0x2124, "B", int(parameters.process_empty_tiles))
        put(0x2128, "B", 1)
        put(0x2198, "Q", parameters.fragment_timestamp_start)
        put(0x21a0, "Q", parameters.fragment_timestamp_end)
        put(0x21a8, "Q", parameters.fragment_user_timestamp_start)
        put(0x21b0, "Q", parameters.fragment_user_timestamp_end)
        put(0x21cc, "B", 0x53)
        put(0x21d6, "B", 1)
        put(0x21e7, "B", 1)
        put(0x2208, "B", 1)
        put(0x220c, "B", 1)
        put(0x222d, "B", 1)

    def item(self, index, shared, registers, support_a, support_b, context_id=0,
             record_indices=None, tail=b"", submission_ordinal=None,
             queue_pair=0, parameters=None, submit_sequence=None,
             queue_grid_index=None, allocation_index=None):
        """Build work item ``index`` and return its address triple.

        ``support_a`` and ``support_b`` are the item's two further inner entries, which
        this does not build: the second is where the submitter writes an event record,
        and neither has an established layout.

        ``tail`` extends the record past the register array. The compact body is what the
        queue parser reads, and it is enough for the queue; the context-global locator reads
        further, and a record with nothing there faulted on hardware. So a caller that
        publishes both views supplies the tail.
        """
        if self.array_a is None:
            raise RuntimeError("build_pools first")
        capacity = min(submission.ARRAY_A_RECORDS, submission.ARRAY_B_RECORDS)
        if index >= capacity and record_indices is None:
            raise ValueError("pool capacity is %d items" % capacity)
        # ``index`` is a logical queue ordinal, not necessarily an allocation
        # in these finite record pools.  A paired builder passes the physical
        # records explicitly after proving/recycling their completed slots;
        # native's 36-render opening therefore legitimately builds item 35
        # against wrapped Pool-A record zero.
        body = bytearray(submission.build_item_descriptor(
            self.kind, index, self.array_a, self.array_b, shared, registers,
            context_id=context_id, record_indices=record_indices,
            submission_ordinal=submission_ordinal, queue_pair=queue_pair,
            submit_sequence=submit_sequence))
        if tail:
            body.extend(tail)
        stride = self.BODY_STRIDE.get(self.kind)
        if stride and len(body) < stride:
            body.extend(bytes(stride - len(body)))
        if allocation_index is None:
            allocation_index = index
        address = self.alloc(
            len(body), "work_descriptor_%d" % int(allocation_index))
        for offset, value in self.BODY_FIELDS.get(self.kind, ()):
            body[offset] = value
        if self.kind == "fragment":
            # This counter is local to the queue pair. Native A/B/A work carries
            # 1, 1, 2 here as pair zero, pair one, then pair zero are selected.
            struct.pack_into("<I", body, 0x90, index + 1)
        if self.write_tail:
            if (self.status_base is None
                    and queue_pair >= len(self.PAIR_STATUS_BASES[self.kind])):
                raise ValueError(
                    "descriptor tail is unknown for queue pair %d" % queue_pair)
            alias = self.low_alias.get(self.kind) if self.low_alias else None
            ordinal = index if submission_ordinal is None else submission_ordinal
            for offset, value, role in self.TAIL_POINTERS.get(self.kind, ()):
                if offset in self.tail_pointer_overrides:
                    value = int(self.tail_pointer_overrides[offset])
                elif role == "self" and alias is not None:
                    value = alias + (value & (0x4000 - 1))
                elif role == "self":
                    value += ordinal * self.BODY_STRIDE[self.kind]
                elif role == "pair_slot":
                    value += queue_pair * 8
                elif role == "status":
                    status_base = (
                        self.PAIR_STATUS_BASES[self.kind][queue_pair]
                        if self.status_base is None else int(self.status_base)
                    )
                    value = status_base + index * 0x40
                struct.pack_into("<Q", body, offset, value)
            offset, kind_index = self.PAIR_GRID_FIELDS[self.kind]
            if queue_grid_index is None:
                queue_grid_index = queue_pair * 2 + kind_index
            struct.pack_into(
                "<I", body, offset, int(queue_grid_index))
            if self.write_lifecycle_fields:
                register, high_offset, low_offset = self.LIFECYCLE_FIELDS[self.kind]
                values = dict(registers.items() if hasattr(registers, "items")
                              else registers)
                if register not in values:
                    raise ValueError(
                        "%s descriptor has no lifecycle register %#x" %
                        (self.kind, register))
                lifecycle = values[register]
                struct.pack_into("<Q", body, high_offset, lifecycle >> 32)
                struct.pack_into(
                    "<Q", body, low_offset, lifecycle & 0xffffffff)
            if self.write_item_fields:
                self._write_item_tail_fields(
                    body, index, queue_pair, queue_grid_index)
            # Cold boot also builds a seed group which has no render parameters.
            # Preserve that established descriptor; structural fields belong to
            # concrete submissions whose pointers and dimensions are known.
            if self.write_structural_tail and parameters is not None:
                self._write_structural_tail(body, parameters, registers)
        # Work is not published until this method returns. Send the complete descriptor in one
        # proxy transaction instead of issuing a debug-USB round trip for every patched field.
        self.write(address, body)
        self.descriptors.append(address)
        return (address, support_a, support_b)


class G17PPairedWorkBuilder:
    """Build one TA/fragment pair with shared pools and generated support items."""

    def __init__(self, alloc, write, queue_pair=0):
        self.alloc = alloc
        self.write = write
        self.queue_pair = queue_pair
        self.tiling = G17PWorkBuilder(
            alloc, write, kind="tiling", queue_pair=queue_pair)
        self.fragment = G17PWorkBuilder(
            alloc, write, kind="fragment", queue_pair=queue_pair)
        self.shared = None
        self.leaf_pages = None
        self.index_group_ranges = None
        self.shared_count = 0x20

    def build_pools(self, slot_base_a, slot_base_b, shared_slot):
        result = self.tiling.build_pools(
            slot_base_a, slot_base_b, shared_slot)
        self.fragment.use_pools(result["pool_a"], result["pool_b"])
        return result

    def bind_runtime_control_page(self, address):
        """Bind both descriptor halves to a runtime pair's control page."""
        address = int(address)
        if not address:
            raise ValueError("runtime descriptor control page must be nonzero")
        self.tiling.tail_pointer_overrides[0x0934] = address
        self.fragment.tail_pointer_overrides[0x21ce] = address
        return address

    def build_shared_objects(self, nested_addresses, group_count=0x20):
        """Allocate the packed second object and the zero fourth object."""
        packed = submission.build_shared_object(
            nested_addresses, pair_index=self.queue_pair,
            group_count=group_count)
        zero = submission.build_zero_shared_object()
        packed_address = self.alloc(len(packed), "descriptor_shared_object")
        zero_address = self.alloc(len(zero), "descriptor_zero_object")
        self.write(packed_address, packed)
        self.write(zero_address, zero)
        self.shared = (packed_address, zero_address)
        return self.shared

    def build_submission_graph(self, index_group_ranges=None,
                               shared_count=0x20):
        """Build pools, shared objects, and every leaf page below them."""
        self.index_group_ranges = index_group_ranges
        self.shared_count = int(shared_count)
        bodies = submission.build_submission_leaf_pages(
            self.queue_pair, index_group_ranges=index_group_ranges,
            shared_count=shared_count)
        pages = {}
        for name, body in bodies.items():
            address = self.alloc(len(body), "submission_%s" % name)
            self.write(address, body)
            pages[name] = address
        self.leaf_pages = pages
        pools = self.build_pools(
            pages["pool_a_slots"] + submission.POOL_A_SLOT_OFFSET,
            pages["pool_b_slots"] + submission.POOL_B_SLOT_OFFSET,
            pages["shared_slots"] + submission.SHARED_SLOT_OFFSET,
        )
        shared = self.build_shared_objects((
            pages["primary_index"],
            pages["secondary_index"],
            pages["shared_slots"],
            pages["flag"],
        ), group_count=shared_count)
        return {"pages": dict(pages), "pools": pools, "shared": shared}

    def rebuild_submission_graph(self):
        """Regenerate this graph in place after a quiesced address-space reuse."""
        if self.leaf_pages is None:
            raise RuntimeError("submission graph has no leaf pages")
        if self.tiling.array_a is None or self.tiling.array_b is None:
            raise RuntimeError("submission graph has no record pools")
        if self.shared is None:
            raise RuntimeError("submission graph has no shared objects")

        bodies = submission.build_submission_leaf_pages(
            self.queue_pair,
            index_group_ranges=self.index_group_ranges,
            shared_count=self.shared_count,
        )
        for name, body in bodies.items():
            self.write(self.leaf_pages[name], body)

        pool_a_slots = (
            self.leaf_pages["pool_a_slots"] + submission.POOL_A_SLOT_OFFSET)
        pool_b_slots = (
            self.leaf_pages["pool_b_slots"] + submission.POOL_B_SLOT_OFFSET)
        shared_slot = (
            self.leaf_pages["shared_slots"] + submission.SHARED_SLOT_OFFSET)
        self.write(
            self.tiling.array_a,
            submission.build_record_array_a(pool_a_slots),
        )
        self.write(
            self.tiling.array_b,
            submission.build_record_array_b(
                pool_b_slots, shared_slot, pair_index=self.queue_pair),
        )
        pointers = tuple(
            self.leaf_pages[name]
            for name in (
                "primary_index", "secondary_index", "shared_slots", "flag"))
        self.write(
            self.shared[0],
            submission.build_shared_object(
                pointers,
                pair_index=self.queue_pair,
                group_count=self.shared_count,
            ),
        )
        self.write(self.shared[1], submission.build_zero_shared_object())
        return {
            "pages": dict(self.leaf_pages),
            "pools": (self.tiling.array_a, self.tiling.array_b),
            "shared": tuple(self.shared),
        }

    def _optional(self, kind, pointers, tiling_shared_object=None,
                  grid_index=None, item_index=0, submission_ordinal=0):
        if pointers.get("submission_ordinal_base") is not None:
            submission_ordinal = (
                int(pointers["submission_ordinal_base"]) + item_index)
        queue_context_index = pointers.get("queue_context_index")
        if pointers.get("queue_context_index_base") is not None:
            queue_context_index = (
                int(pointers["queue_context_index_base"]) + item_index)
        queue_context_phase = pointers.get("queue_context_phase")
        if pointers.get("queue_context_phase_base") is not None:
            queue_context_phase = (
                int(pointers["queue_context_phase_base"])
                + (item_index << 8)
            )
        lifecycle_ordinal = pointers.get("lifecycle_ordinal")
        if pointers.get("lifecycle_ordinal_base") is not None:
            lifecycle_ordinal = (
                int(pointers["lifecycle_ordinal_base"]) + item_index
            )
        body = submission.build_optional_item(
            kind,
            pointers["context_scratch"],
            pointers["firmware_scratch"],
            pointers["shared_control"],
            pointers["channel_control"],
            tiling_shared_object=tiling_shared_object,
            grid_index=grid_index,
            item_index=item_index,
            submission_ordinal=submission_ordinal,
            context_id=pointers.get("context_id"),
            uuid=pointers.get("uuid"),
            scheduler_class=pointers.get("scheduler_class"),
            queue_context_index=queue_context_index,
            queue_context_phase=queue_context_phase,
            first_record=pointers.get("first_record"),
            lifecycle_ordinal=lifecycle_ordinal,
            queue_namespace=pointers.get("queue_namespace"),
            u16_overrides=pointers.get("u16_overrides"),
        )
        address = self.alloc(len(body), "%s_optional_item" % kind)
        self.write(address, body)
        return address

    def _event(self, kind):
        address = self.alloc(
            submission.EVENT_ITEM_SIZE, "%s_event_item" % kind)
        # Event pointers are records in one shared array, not independent 0x400-byte
        # allocations. Firmware may append beyond the first record, but clearing that
        # whole observed output extent here destroys later host records at the native
        # 0x80 stride. The host owns and initializes only the first 0x40 bytes.
        self.write(address, bytes(submission.EVENT_RECORD_SIZE))
        return address

    def item(self, index, shared, tiling_registers, fragment_registers,
             tiling_optional, fragment_optional, context_id, tails=None,
             submission_ordinal=None, queue_pair=0, record_indices=None,
             parameters=None, lifecycle_phase=None,
             optional_submission_ordinal=None, queue_grid_pair=None,
             submit_sequences=None, allocation_index=None,
             optional_item_index=None):
        """Build both three-entry groups for paired work item ``index``.

        ``tails`` is an optional ``{kind: bytes}`` extending each record past its register
        array, for a caller that also publishes the context-global descriptor view.
        """
        tails = tails or {}
        submit_sequences = submit_sequences or {}
        if self.tiling.array_a is None:
            raise RuntimeError("build_pools first")
        if shared is None:
            if self.shared is None:
                raise RuntimeError("build_shared_objects first")
            shared = self.shared

        # The fragment half's records come first. A captured pair holds its two optional items in
        # one page with the fragment one at `+0x00` and the tiling one at `+0xc0`, and its two event
        # items likewise with the fragment one first, `0x40` apart. Allocating the tiling half first
        # reverses both, and enough adjacency relationships on this part have turned out to matter,
        # the queue records at a `0xc0` stride and the item rings `0x2870` apart, that the order is
        # not free to choose.
        ordinal = index if submission_ordinal is None else submission_ordinal
        optional_ordinal = (ordinal if optional_submission_ordinal is None else
                            int(optional_submission_ordinal))
        optional_index = (index if optional_item_index is None else
                          int(optional_item_index))
        if queue_grid_pair is None:
            queue_grid_pair = queue_pair
        if isinstance(queue_grid_pair, (tuple, list)):
            if len(queue_grid_pair) != 2:
                raise ValueError("queue grids must name tiling and fragment")
            tiling_grid, fragment_grid = map(int, queue_grid_pair)
        else:
            tiling_grid = int(queue_grid_pair) * 2
            fragment_grid = tiling_grid + 1
        fragment_optional = self._optional(
            "fragment", fragment_optional,
            grid_index=fragment_grid,
            item_index=optional_index, submission_ordinal=optional_ordinal)
        ta_optional = self._optional(
            "tiling", tiling_optional, tiling_shared_object=shared[0],
            grid_index=tiling_grid, item_index=optional_index,
            submission_ordinal=optional_ordinal)
        fragment_event = self._event("fragment")
        ta_event = self._event("tiling")

        # Both halves name the same pair-local record in each pool. The initial
        # pair advances A and B together. In the captured created-pair series,
        # the first three groups select A0/B0, A2/B1, and A4/B2: Pool A advances
        # twice as fast while these three-entry groups carry their optional item.
        records = submission.paired_item_pool_record_indices(
            index, record_indices=record_indices)
        # The host prepares the pool-A job record when it takes it. Native records
        # carry the global work ordinal at +0x08 and the 0x50 marker at +0x10 before
        # their doorbell; the scheduler writes the remaining lifecycle fields.
        record_a = self.tiling.array_a + records[0] * submission.ARRAY_A_STRIDE
        work_ordinal = submission.descriptor_work_ordinal(ordinal)
        self.write(record_a + 0x08, struct.pack("<I", work_ordinal))
        self.write(record_a + submission.ARRAY_A_FIRST_MARKER_OFFSET,
                   struct.pack("<I", submission.ARRAY_A_FIRST_MARKER))
        if lifecycle_phase is not None:
            lifecycle_phase("before")
            # Native constructs fragment first, publishes phase one, then
            # constructs tiling and publishes phase two.
            fragment = self.fragment.item(
                index, shared, fragment_registers, fragment_optional,
                fragment_event, context_id=context_id,
                record_indices=records, tail=tails.get("fragment", b""),
                submission_ordinal=submission_ordinal,
                queue_pair=queue_pair, parameters=parameters,
                submit_sequence=submit_sequences.get("fragment"),
                queue_grid_index=fragment_grid,
                allocation_index=allocation_index)
            lifecycle_phase("fragment")
            ta = self.tiling.item(
                index, shared, tiling_registers, ta_optional, ta_event,
                context_id=context_id, record_indices=records,
                tail=tails.get("tiling", b""),
                submission_ordinal=submission_ordinal,
                queue_pair=queue_pair, parameters=parameters,
                submit_sequence=submit_sequences.get("tiling"),
                queue_grid_index=tiling_grid,
                allocation_index=allocation_index)
            lifecycle_phase("tiling")
        else:
            ta = self.tiling.item(
                index, shared, tiling_registers, ta_optional, ta_event,
                context_id=context_id, record_indices=records,
                tail=tails.get("tiling", b""),
                submission_ordinal=submission_ordinal, queue_pair=queue_pair,
                parameters=parameters,
                submit_sequence=submit_sequences.get("tiling"),
                queue_grid_index=tiling_grid,
                allocation_index=allocation_index)
            fragment = self.fragment.item(
                index, shared, fragment_registers, fragment_optional,
                fragment_event, context_id=context_id,
                record_indices=records, tail=tails.get("fragment", b""),
                submission_ordinal=submission_ordinal,
                queue_pair=queue_pair, parameters=parameters,
                submit_sequence=submit_sequences.get("fragment"),
                queue_grid_index=fragment_grid,
                allocation_index=allocation_index)
        return {"tiling": ta, "fragment": fragment}
