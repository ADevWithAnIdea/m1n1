# SPDX-License-Identifier: MIT
"""Publish a host-constructed submission group into a live T8140/G17P queue.

    import builtins
    builtins.exec(open("proxyclient/hv/probe_agx_g17p_submit.py").read(), globals())

Run from the stop-at-capture HV shell, where the guest is halted at a work-channel
producer write. The guest CPU cannot interfere while halted, so the GPU processes
whatever the host publishes and the result is attributable.

The group is built from a drained group's item buffers, so no item body is
constructed here: this tests the publication path only, which is the pivotal
capability. Set ``SUBMIT_ARM = True`` in the shell to actually publish; the default
is a dry run that prints every write it would make.

Publication order, from the structures already decoded:
  1. write the item pointers into consecutive item-ring entries
  2. write the event item's first record with the next group counter
  3. advance the queue write index
  4. write the channel ring slot with the new head and the queue's grid index
  5. advance the channel producer counter, the third state counter
  6. ring the work doorbell
"""

import datetime
import json
import pathlib
import struct
import time

_ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
_SLOT_SIZE = 0x18
_CHANNEL_TABLE_OFFSET = 0x20
_CHANNEL_ENTRY_SIZE = 0x20
_WORK_NAMES = ("TA_0", "3D_0", "CL_0", "TA_1", "3D_1", "CL_1",
               "TA_2", "3D_2", "CL_2", "TA_3", "3D_3", "CL_3")
_EVENT_RECORD_SIZE = 0x40
_EVENT_SUBTYPE_HOST = 0x00010008


def _submit():
    recorder = g17p
    uat, root, hv = recorder.uat, recorder.root, recorder.hv
    arm = bool(globals().get("SUBMIT_ARM", False))
    want = globals().get("PROBE_CHANNEL", "TA_0")

    def read(dva, size):
        out = bytearray()
        while len(out) < size:
            chunk = min(size - len(out), 0x4000 - ((dva + len(out)) & 0x3fff))
            out.extend(uat.ioread_root(root, dva + len(out), chunk))
        return bytes(out)

    writes = []

    def write(dva, data, label):
        """Record, and when armed perform, one host write to firmware memory."""
        writes.append({"dva": dva, "bytes": data.hex(), "label": label})
        print("   %-28s %#018x  %s" % (label, dva, data.hex()))
        if not arm:
            return
        offset = 0
        while offset < len(data):
            page = (dva + offset) & ~0x3fff
            span = min(len(data) - offset, 0x4000 - ((dva + offset) & 0x3fff))
            pa = uat.translate_root_page(root, dva + offset)
            if pa is None:
                raise RuntimeError("unmapped write target %#x" % (dva + offset))
            hv.iface.writemem(pa, data[offset:offset + span])
            hv.p.dc_civac(pa & ~0x3fff, 0x4000)
            offset += span

    index = _WORK_NAMES.index(want)
    main_addr = struct.unpack_from("<Q", read(recorder.initdata_addr, 0x20), 0x18)[0]
    entry = read(main_addr + _CHANNEL_TABLE_OFFSET + index * _CHANNEL_ENTRY_SIZE, 0x20)
    state_addrs = list(struct.unpack_from("<3Q", entry, 0))
    ring_addr = struct.unpack_from("<Q", entry, 0x18)[0]

    def counters():
        # Valid because this probe only reads a work channel, whose three state addresses lie
        # 0x10 apart. The firmware-produced channels scatter theirs, so pointing this at channel
        # 13 or 14 would read words that are not counters; read each address on its own there.
        block = read(state_addrs[0], 0x40)
        return [struct.unpack_from("<I", block, o)[0] for o in (0x00, 0x10, 0x20)]

    before = counters()

    # The producer counter is a count of published slots, not the index of the
    # last one: an idle channel read 1 with exactly one populated slot, at index
    # 0. So publishing slot N requires setting it to N+1. It can also lag by one
    # while a guest write is trapped, so the next free slot is found by scanning
    # the ring rather than trusting the counter.
    next_slot = before[2]
    while next_slot < 0x100 and any(read(ring_addr + next_slot * _SLOT_SIZE,
                                        _SLOT_SIZE)):
        next_slot += 1
    producer = next_slot - 1
    slot = read(ring_addr + producer * _SLOT_SIZE, _SLOT_SIZE)
    queue_addr = struct.unpack_from("<Q", slot, 0x08)[0]
    queue_index = (struct.unpack_from("<I", slot, 0x14)[0] >> 16) & 0xff

    qrec = read(queue_addr, 0xc0)
    ptr_addr, item_ring = struct.unpack_from("<QQ", qrec, 0)
    ptrs = read(ptr_addr, 0x60)
    done, rd_i, wr_i = (struct.unpack_from("<I", ptrs, o)[0] for o in (0, 0x30, 0x40))

    entries = struct.unpack_from("<%dQ" % wr_i, read(item_ring, wr_i * 8), 0) if wr_i else ()
    selectors = {}
    for i, addr in enumerate(entries):
        if addr:
            selectors[i] = struct.unpack_from("<I", read(addr, 4), 0)[0]

    # Source group: the newest fully drained group, so its buffers are idle.
    groups, current = [], []
    for i in sorted(selectors):
        current.append(i)
        if selectors[i] == 0x0e:
            groups.append(current)
            current = []
    drained = [g for g in groups if g[-1] < done]
    if not drained:
        raise RuntimeError("no drained group to copy item buffers from")
    source = drained[-1]
    work_item = entries[source[0]]
    event_item = entries[source[-1]]

    print("channel %s: state counters %s, producer %d" % (want, before, producer))
    print("queue %#x grid %d: done %d read %d write %d, %d groups"
          % (queue_addr, queue_index, done, rd_i, wr_i, len(groups)))
    print("source group %s -> work item %#x, event item %#x"
          % (source, work_item, event_item))
    print("%s:" % ("ARMED, performing writes" if arm else "DRY RUN, writes not performed"))

    new_write = wr_i + 2
    group_number = len(groups) + 1

    write(item_ring + wr_i * 8, struct.pack("<Q", work_item), "item ring entry")
    write(item_ring + (wr_i + 1) * 8, struct.pack("<Q", event_item), "item ring entry")

    record = bytearray(_EVENT_RECORD_SIZE)
    struct.pack_into("<I", record, 0x00, 0x0e)
    struct.pack_into("<I", record, 0x04, _EVENT_SUBTYPE_HOST)
    struct.pack_into("<I", record, 0x08, group_number << 8)
    write(event_item, bytes(record), "event item record")

    write(ptr_addr + 0x40, struct.pack("<I", new_write), "queue write index")


    new_slot = bytearray(_SLOT_SIZE)
    struct.pack_into("<Q", new_slot, 0x08, queue_addr)
    struct.pack_into("<I", new_slot, 0x14, new_write | (queue_index << 16))
    write(ring_addr + next_slot * _SLOT_SIZE, bytes(new_slot), "channel ring slot")

    # Count of published slots, so one past the slot just written.
    write(state_addrs[2], struct.pack("<I", next_slot + 1), "channel producer")

    # Announce last, once the payload and every index are already in place.
    # Without this the firmware consumes the doorbell and emits an event but never
    # scans the channel slot. It is the transition that signals: firmware does not
    # clear the field after draining, so re-writing 1 over an existing 1 does
    # nothing, and announcing before the slot exists wastes the signal because
    # firmware may scan in between and find no new work.
    write(queue_addr + 0x7c, struct.pack("<I", 0), "queue has_commands clear")
    write(queue_addr + 0x7c, struct.pack("<I", 1), "queue has_commands set")

    doorbell = None
    if arm:
        asc = int(hv.adt["/arm-io/gfx-asc"].get_reg(0)[0])
        doorbell = 0x0083000000000000
        # Ring twice with an interval. When firmware has gone idle the first
        # doorbell wakes it, and it emits an event and returns to idle without
        # scanning the channel; the second is the one it acts on. A single
        # doorbell was repeatedly ignored while a second always drained the
        # publication.
        for attempt in range(2):
            hv.p.write64(asc + 0x8800, doorbell)
            hv.p.write64(asc + 0x8808, 0x21)
            print("   doorbell %#x to endpoint 0x21 at %#x (ring %d)"
                  % (doorbell, asc + 0x8800, attempt + 1))
            time.sleep(0.5)

    after, observed = before, []
    if arm:
        for _ in range(20):
            time.sleep(0.25)
            after = counters()
            new_ptrs = read(ptr_addr, 0x60)
            new_done = struct.unpack_from("<I", new_ptrs, 0)[0]
            observed.append({"counters": after, "queue_done": new_done})
            if after[0] > before[0] or new_done > done:
                break
        print("counters after: %s (were %s)" % (after, before))
        print("queue done after: %d (was %d)" % (observed[-1]["queue_done"], done))
        advanced = after[0] > before[0] or observed[-1]["queue_done"] > done
        print("RESULT: %s" % ("firmware consumed the constructed group"
                              if advanced else "no advance observed"))

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = _ARTIFACTS / ("constructed_submit_%s" % stamp)
    out.mkdir(parents=True, exist_ok=False)
    (out / "submit.json").write_text(json.dumps({
        "format": "m1n1-t8140-g17p-constructed-submit-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "armed": arm,
        "channel": want,
        "ring_addr": ring_addr,
        "state_addrs": state_addrs,
        "counters_before": before,
        "counters_after": after,
        "producer": producer,
        "queue_addr": queue_addr,
        "queue_index": queue_index,
        "queue_done_before": done,
        "queue_read_before": rd_i,
        "queue_write_before": wr_i,
        "queue_write_after": new_write,
        "group_number": group_number,
        "source_group": source,
        "work_item": work_item,
        "event_item": event_item,
        "writes": writes,
        "doorbell": doorbell,
        "polls": observed,
    }, indent=2, sort_keys=True) + "\n")
    print("artifact %s" % out)
    return out


submit_artifact = _submit()
