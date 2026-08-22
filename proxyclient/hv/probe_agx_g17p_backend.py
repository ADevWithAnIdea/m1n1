# SPDX-License-Identifier: MIT
"""Drive the T8140/G17P backend against a frozen guest.

    import builtins
    builtins.exec(open("proxyclient/hv/probe_agx_g17p_backend.py").read(), globals())

Runs from the stop-at-capture HV shell. This exercises the backend module rather
than open-coding the publication, so the code a DRM shim would call is the code
under test. Set ``BACKEND_ARM = True`` to publish; the default reports what it
would do.

Item buffers are reused from a drained group, so this drives the GPU without
constructing a work item body.
"""

import datetime
import json
import pathlib
import struct
import time

_ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")


def _run():
    recorder = g17p_recorder = g17p
    uat, root, hv = recorder.uat, recorder.root, recorder.hv
    arm = bool(globals().get("BACKEND_ARM", False))
    want = globals().get("PROBE_CHANNEL", "TA_0")

    # The backend imports as a normal package module, so a shim would reach it the
    # same way.
    from m1n1.agx import g17p as layout
    from m1n1.agx import g17p_backend as backend

    def read(dva, size):
        out = bytearray()
        while len(out) < size:
            chunk = min(size - len(out), 0x4000 - ((dva + len(out)) & 0x3fff))
            out.extend(uat.ioread_root(root, dva + len(out), chunk))
        return bytes(out)

    writes = []

    def write(dva, data):
        writes.append({"dva": dva, "bytes": data.hex()})
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
    counters = channels.counters(entry)
    slot_index = channels.next_free_slot(entry)
    print("channel %s: counters %s, next free slot %d"
          % (want, counters, slot_index))

    # The queue the most recent slot referenced.
    previous = channels.slot(entry, max(0, slot_index - 1))
    queue = backend.G17PQueue(read, previous["queue"], previous["queue_index"])
    indices = queue.indices()
    groups = queue.groups()
    print("queue %#x grid %d: %s, %d groups"
          % (queue.address, queue.grid_index, indices, len(groups)))

    drained = [group for group in groups if group[-1] < indices["done"]]
    if not drained:
        raise RuntimeError("no drained group to reuse item buffers from")
    source = drained[-1]
    all_items = queue.items()
    item_addresses = [all_items[index] for index in source]
    print("reusing item buffers from group %s: %s"
          % (source, [hex(a) for a in item_addresses]))

    submitter = backend.G17PSubmitter(read, write, doorbell, channels)
    published = submitter.publish(entry, queue, item_addresses, len(groups) + 1)
    print("%s: %s" % ("published" if arm else "would publish", published))
    for record in writes:
        print("   write %#018x  %s" % (record["dva"], record["bytes"][:48]))

    accepted = completed = None
    if arm:
        for _ in range(20):
            time.sleep(0.25)
            accepted = submitter.accepted(entry, queue, published)
            completed = submitter.completed(entry, queue, published)
            if completed:
                break
        print("counters after: %s" % channels.counters(entry))
        print("queue after: %s" % queue.indices())
        print("RESULT: accepted=%s completed=%s" % (accepted, completed))

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = _ARTIFACTS / ("backend_submit_%s" % stamp)
    out.mkdir(parents=True, exist_ok=False)
    (out / "backend.json").write_text(json.dumps({
        "format": "m1n1-t8140-g17p-backend-submit-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "armed": arm,
        "channel": want,
        "counters_before": counters,
        "counters_after": channels.counters(entry) if arm else None,
        "queue": queue.address,
        "queue_grid_index": queue.grid_index,
        "indices_before": indices,
        "indices_after": queue.indices() if arm else None,
        "groups_before": len(groups),
        "source_group": source,
        "published": published,
        "accepted": accepted,
        "completed": completed,
        "writes": writes,
    }, indent=2, sort_keys=True) + "\n")
    print("artifact %s" % out)
    return out


backend_artifact = _run()
