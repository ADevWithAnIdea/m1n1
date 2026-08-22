# SPDX-License-Identifier: MIT
"""Republish a group with its per-submission fields advanced.

    import builtins
    builtins.exec(open("proxyclient/hv/probe_agx_g17p_advance.py").read(), globals())

Differencing 32 consecutive geometry items of one queue showed that only 64 of the
record's 624 words change between submissions, and that a submission index appears
at several offsets in fixed encodings. This republishes a drained group with that
index family and the per-submission progress pointer advanced, which is the minimum
a fresh submission would have to do, and reports whether firmware completes it.

Set ``ADVANCE_ARM = True`` to write and publish.
"""

import datetime
import json
import pathlib
import struct
import time

_ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")

# Offsets in a geometry item that carry the submission index, with the multiplier
# each one applies. Established by differencing consecutive items.
INDEX_FIELDS = (
    (0x7a8, 1),
    (0x7a0, 0x100),
    (0x7b0, 0x101),
    (0x8c4, 0x10000),
    (0x8c8, 0x1000000),
)

# Every field that advances by one uniform stride across all 32 captured
# submissions. These are the mechanical per-submission state; the roughly fifty
# other varying fields move by workload-dependent amounts and describe the work
# itself, so resubmitting the same work should only need these.
UNIFORM_FIELDS = (
    (0x028, 0x000080),
    (0x310, 0x000020),
    (0x31c, 0x000020),
    (0x328, 0x000004),
    (0x3a0, 0x000040),
    (0x7a0, 0x000100),
    (0x7a8, 0x000001),
    (0x7b0, 0x000101),
    (0x8b4, 0x1000000),
    (0x8c4, 0x010000),
    (0x8c8, 0x1000000),
    (0x944, 0x004000),
)
SEQUENCE_OFFSET = 0x004
PROGRESS_PTR_OFFSET = 0x028
PROGRESS_PTR_STRIDE = 0x80
PROGRESS_TARGET_OFFSET = 0x04


def _run():
    recorder = g17p
    uat, root, hv = recorder.uat, recorder.root, recorder.hv
    arm = bool(globals().get("ADVANCE_ARM", False))
    want = globals().get("PROBE_CHANNEL", "TA_0")

    from m1n1.agx import g17p as layout
    from m1n1.agx import g17p_backend as backend

    def read(dva, size):
        out = bytearray()
        while len(out) < size:
            chunk = min(size - len(out), 0x4000 - ((dva + len(out)) & 0x3fff))
            out.extend(uat.ioread_root(root, dva + len(out), chunk))
        return bytes(out)

    def write(dva, data):
        if not arm:
            return
        offset = 0
        while offset < len(data):
            span = min(len(data) - offset, 0x4000 - ((dva + offset) & 0x3fff))
            pa = uat.translate_root_page(root, dva + offset)
            if pa is None:
                raise RuntimeError("unmapped write target %#x" % (dva + offset))
            hv.iface.writemem(pa, data[offset:offset + span])
            hv.p.dc_civac(pa & ~0x3fff, 0x4000)
            offset += span

    asc = int(hv.adt["/arm-io/gfx-asc"].get_reg(0)[0])

    def doorbell():
        if not arm:
            return
        hv.p.write64(asc + 0x8800, layout.PUBLISH_DOORBELL)
        hv.p.write64(asc + 0x8808, layout.ENDPOINT_WORK)
        time.sleep(0.5)

    channels = backend.G17PChannels(read, recorder.initdata_addr)
    entry = channels.by_name(want)
    slot_index = channels.next_free_slot(entry)
    previous = channels.slot(entry, max(0, slot_index - 1))
    queue = backend.G17PQueue(read, previous["queue"], previous["queue_index"])
    indices = queue.indices()
    groups = queue.groups()
    drained = [group for group in groups if group[-1] < indices["done"]]
    if not drained:
        raise RuntimeError("no drained group to reuse")
    source = drained[-1]
    all_items = queue.items()
    item_addresses = [all_items[index] for index in source]

    work_item = item_addresses[0]
    body = read(work_item, 0x9c0)

    # A geometry item has around sixty per-submission fields, most of them
    # addresses of working buffers, and macOS allocates a fresh item for every
    # submission. Only a handful are advanced below, so anything firmware mutated
    # in the rest stays stale on a resubmission. Restoring the body to the state it
    # had when the queue first went idle tests whether that mutation is what stops
    # a second resubmission completing.
    if globals().get("ADVANCE_RESTORE_TEMPLATE", False):
        template = globals().get("ADVANCE_TEMPLATE")
        if template is None:
            globals()["ADVANCE_TEMPLATE"] = body
            print("saved item template (%d bytes)" % len(body))
        else:
            write(work_item, template)
            body = template
            print("restored item template before republishing")
    old_index = struct.unpack_from("<I", body, INDEX_FIELDS[0][0])[0]
    old_seq = struct.unpack_from("<I", body, SEQUENCE_OFFSET)[0]
    old_progress = struct.unpack_from("<Q", body, PROGRESS_PTR_OFFSET - 8 + 8)[0] \
        if False else struct.unpack_from("<Q", body, 0x28)[0]
    new_index = old_index + 1
    new_progress = old_progress + PROGRESS_PTR_STRIDE

    print("channel %s queue %#x: %s, %d groups" % (want, queue.address, indices,
                                                   len(groups)))
    print("work item %#x: index %d -> %d, sequence %d -> %d"
          % (work_item, old_index, new_index, old_seq, old_seq + 1))
    print("progress pointer %#x -> %#x" % (old_progress, new_progress))

    # Advance the per-submission fields in place. Advancing only the index family
    # and the progress pointer lets exactly one resubmission complete, so try every
    # field that moves by a uniform stride.
    if globals().get("ADVANCE_ALL_UNIFORM", True):
        for offset, stride in UNIFORM_FIELDS:
            current = struct.unpack_from("<I", body, offset)[0]
            write(work_item + offset, struct.pack("<I", current + stride))
        print("advanced %d uniform-stride fields" % len(UNIFORM_FIELDS))
    else:
        for offset, multiplier in INDEX_FIELDS:
            write(work_item + offset, struct.pack("<I", new_index * multiplier))
        write(work_item + 0x28, struct.pack("<Q", new_progress))
    write(work_item + SEQUENCE_OFFSET, struct.pack("<I", old_seq + 1))

    # Advance the shared pair's second word from its own previous value. Advancing
    # it from the first word instead is wrong: that word never moves, so the target
    # would stop advancing after the first resubmission.
    shared = struct.unpack_from("<Q", body, 0x20)[0]
    pair = read(shared, 0x10)
    first, target = struct.unpack_from("<II", pair, 0)
    write(shared + PROGRESS_TARGET_OFFSET, struct.pack("<I", target + 1))
    print("shared pair at %#x: first %d target %d -> %d"
          % (shared, first, target, target + 1))

    # Clear the third progress target, which is the location firmware writes on
    # completion. Left holding a previous result it may read as already finished.
    output = struct.unpack_from("<Q", body, 0x30)[0]
    if globals().get("ADVANCE_CLEAR_OUTPUT", True):
        write(output, bytes(0x40))
        print("cleared completion output at %#x" % output)

    # Every submission macOS makes gets its own item buffers: 32 consecutive
    # submissions used 32 distinct event buffers and 9 distinct optional buffers.
    # The event item is a ring firmware appends into, so reusing one leaves a stale
    # append position. Step the event buffer along its pool instead.
    EVENT_POOL_STRIDE = 0x80
    if globals().get("ADVANCE_FRESH_EVENT", True):
        base_event = globals().setdefault("ADVANCE_EVENT_BASE", item_addresses[-1])
        fresh_event = base_event + (new_index - 1) * EVENT_POOL_STRIDE
        write(fresh_event, bytes(0x400))
        item_addresses = list(item_addresses[:-1]) + [fresh_event]
        print("event buffer %#x -> %#x (fresh slot %d)"
              % (base_event, fresh_event, new_index - 1))

    submitter = backend.G17PSubmitter(read, write, doorbell, channels)
    published = submitter.publish(entry, queue, item_addresses, len(groups) + 1)
    print("%s: %s" % ("published" if arm else "would publish", published))

    accepted = completed_flag = None
    if arm:
        for _ in range(24):
            time.sleep(0.25)
            accepted = submitter.accepted(entry, queue, published)
            completed_flag = submitter.completed(entry, queue, published)
            if completed_flag:
                break
        print("counters after: %s" % channels.counters(entry))
        print("queue after: %s" % queue.indices())
        print("shared pair after: %s" % read(shared, 0x10).hex())
        print("RESULT: accepted=%s completed=%s" % (accepted, completed_flag))

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = _ARTIFACTS / ("advance_submit_%s" % stamp)
    out.mkdir(parents=True, exist_ok=False)
    (out / "advance.json").write_text(json.dumps({
        "format": "m1n1-t8140-g17p-advance-submit-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "armed": arm,
        "channel": want,
        "queue": queue.address,
        "indices_before": indices,
        "indices_after": queue.indices() if arm else None,
        "work_item": work_item,
        "index_before": old_index,
        "index_after": new_index,
        "sequence_before": old_seq,
        "progress_before": old_progress,
        "progress_after": new_progress,
        "shared_pair": shared,
        "published": published,
        "accepted": accepted,
        "completed": completed_flag,
    }, indent=2, sort_keys=True) + "\n")
    print("artifact %s" % out)
    return out


advance_artifact = _run()
