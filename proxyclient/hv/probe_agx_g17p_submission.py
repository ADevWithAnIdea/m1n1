# SPDX-License-Identifier: MIT
"""Dump one live T8140/G17P submission group in full, from the frozen HV shell.

    import builtins; builtins.exec(open("proxyclient/hv/probe_agx_g17p_submission.py").read(), globals())

Requires the stop-at-capture shell, where the guest is halted at a work-channel
producer write. Set ``PROBE_CHANNEL`` to a channel name to override the default.

Walks the halted channel's ring slot to its queue, reads the queue record,
pointer block, job list and context object, then dumps every item of the
outstanding submission groups at that item type's own record size, following one
hop from each pointer field. Saves everything as an artifact.
"""

import collections
import datetime
import json
import pathlib
import struct

_ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
_SLOT_SIZE = 0x18
_QUEUE_RECORD = 0xc0
_PTR_BLOCK = 0x60
_JOB_LIST = 0x18
# Record size per item selector, from the pool strides measured on live items.
_ITEM_SIZE = {0x00: 0x9c0, 0x01: 0x2240}
_ITEM_SIZE_DEFAULT = 0x400
_CHANNEL_TABLE_OFFSET = 0x20
_CHANNEL_ENTRY_SIZE = 0x20
_WORK_NAMES = ("TA_0", "3D_0", "CL_0", "TA_1", "3D_1", "CL_1",
               "TA_2", "3D_2", "CL_2", "TA_3", "3D_3", "CL_3")


def _probe():
    recorder = g17p
    uat, root = recorder.uat, recorder.root
    want = globals().get("PROBE_CHANNEL", "TA_0")

    def read(dva, size):
        data = bytearray()
        while len(data) < size:
            chunk = min(size - len(data), 0x4000 - ((dva + len(data)) & 0x3fff))
            try:
                data.extend(uat.ioread_root(root, dva + len(data), chunk))
            except Exception:
                break
        return bytes(data) if data else None

    def is_dva(v):
        return (v >> 40) == 0xfffffc and v != (1 << 64) - 1

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = _ARTIFACTS / ("live_submission_%s" % stamp)
    out.mkdir(parents=True, exist_ok=False)

    main_addr = struct.unpack_from("<Q", read(recorder.initdata_addr, 0x20), 0x18)[0]
    index = _WORK_NAMES.index(want)
    entry = read(main_addr + _CHANNEL_TABLE_OFFSET + index * _CHANNEL_ENTRY_SIZE, 0x20)
    state_addrs = list(struct.unpack_from("<3Q", entry, 0))
    ring_addr = struct.unpack_from("<Q", entry, 0x18)[0]

    state_block = read(state_addrs[0] & ~0x3f, 0x40)
    counters = [struct.unpack_from("<I", state_block, o)[0] for o in (0, 0x10, 0x20)]

    # The halted publication is the slot the counters point at.
    slot_index = counters[0]
    slot = read(ring_addr + slot_index * _SLOT_SIZE, _SLOT_SIZE)
    queue_addr = struct.unpack_from("<Q", slot, 0x08)[0]
    packed = struct.unpack_from("<I", slot, 0x14)[0]

    qrec = read(queue_addr, _QUEUE_RECORD)
    ptr_addr, item_ring, job_addr = struct.unpack_from("<3Q", qrec, 0)
    ctx_addr = struct.unpack_from("<Q", qrec, 0x9c)[0]
    ptr_block = read(ptr_addr, _PTR_BLOCK)
    pointers = {n: struct.unpack_from("<I", ptr_block, o)[0]
                for n, o in (("done", 0), ("read", 0x30), ("write", 0x40),
                             ("ring_size", 0x50))}

    # Every populated item-ring entry, then the outstanding window.
    entries = []
    raw = read(item_ring, (pointers["write"] + 8) * 8)
    for i in range((pointers["write"] + 8)):
        value = struct.unpack_from("<Q", raw, i * 8)[0] if raw else 0
        entries.append(value)

    items = {}
    raw_items = bytearray()
    for i, addr in enumerate(entries):
        if not addr:
            continue
        head = read(addr, 4)
        if head is None:
            continue
        selector = struct.unpack_from("<I", head, 0)[0]
        size = _ITEM_SIZE.get(selector, _ITEM_SIZE_DEFAULT)
        data = read(addr, size)
        if data is None:
            continue
        fields = []
        for off in range(0, len(data) - 7, 4):
            v = struct.unpack_from("<Q", data, off)[0]
            if is_dva(v):
                fields.append({"offset": off, "value": v})
        extent = len(data)
        while extent and data[extent - 1] == 0:
            extent -= 1
        items[i] = {
            "ring_index": i,
            "addr": addr,
            "selector": selector,
            "size_read": len(data),
            "nonzero_extent": extent,
            "capture_offset": len(raw_items),
            "pointer_fields": fields,
            "outstanding": pointers["read"] <= i < pointers["write"],
        }
        raw_items.extend(data)

    # One hop out of every pointer field of the outstanding items.
    targets = {}
    raw_targets = bytearray()
    for item in items.values():
        if not item["outstanding"]:
            continue
        for f in item["pointer_fields"]:
            v = f["value"]
            if v in targets:
                continue
            data = read(v, 0x80)
            if data is None:
                continue
            targets[v] = {"dva": v, "capture_offset": len(raw_targets)}
            raw_targets.extend(data)

    report = {
        "format": "m1n1-t8140-g17p-live-submission-v2",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "channel": want,
        "ring_addr": ring_addr,
        "state_addrs": state_addrs,
        "state_counters": counters,
        "halted_slot": slot_index,
        "slot_hex": slot.hex(),
        "slot_queue": queue_addr,
        "slot_head": packed & 0xffff,
        "slot_queue_index": (packed >> 16) & 0xff,
        "queue_addr": queue_addr,
        "queue_hex": qrec.hex(),
        "queue_pointers": pointers,
        "item_ring_addr": item_ring,
        "job_list_addr": job_addr,
        "job_list_hex": (read(job_addr, _JOB_LIST) or b"").hex(),
        "context_addr": ctx_addr,
        "context_hex": (read(ctx_addr, 0x40) or b"").hex(),
        "item_ring_entries": entries,
        "items": list(items.values()),
        "item_sizes": {str(k): v for k, v in _ITEM_SIZE.items()},
        "pointer_targets": sorted(targets.values(), key=lambda t: t["capture_offset"]),
        "uat_root": root,
    }
    (out / "submission.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / "items.bin").write_bytes(bytes(raw_items))
    (out / "pointer_targets.bin").write_bytes(bytes(raw_targets))

    by_sel = collections.Counter(i["selector"] for i in items.values())
    print("G17P submission: %s slot %d -> queue %#x (grid %d), head %d"
          % (want, slot_index, queue_addr, (packed >> 16) & 0xff, packed & 0xffff))
    print("G17P submission: pointers %s" % pointers)
    print("G17P submission: %d items read, selectors %s"
          % (len(items), dict(sorted(by_sel.items()))))
    print("G17P submission: %d pointer targets from the outstanding group"
          % len(targets))
    print("G17P submission: artifact %s" % out)
    return report


submission_report = _probe()
