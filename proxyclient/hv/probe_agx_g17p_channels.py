# SPDX-License-Identifier: MIT
"""Probe the live T8140/G17P channel table and channel state blocks.

Run from a compatible frozen HV shell at a work-channel producer boundary:

    import builtins; builtins.exec(open("proxyclient/hv/probe_agx_g17p_channels.py").read(), globals())

The guest is halted at a work-channel producer write, so channel state blocks,
queue records and ring slots all hold live values. This walks the channel table
out of the initialization descriptor, reads each channel's state block and ring
slots, follows the queue records those slots reference, and saves an artifact.

Uses the corrected ring model: a slot is 0x18 bytes with the queue pointer at
+0x08 and a packed head, queue index and first-slot flag at +0x14.
"""

import datetime
import json
import pathlib
import struct

_ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
_SLOT_SIZE = 0x18
_SLOT_COUNT = 0x100
_STATE_BLOCK = 0x40
_QUEUE_RECORD = 0xc0
# Relative to the main configuration object, which does not begin at a page
# boundary. Offsets read out of a page dump are 0x25c0 higher.
_CHANNEL_TABLE_OFFSET = 0x20
_CHANNEL_ENTRY_SIZE = 0x20
_CHANNEL_ENTRIES = 17
_WORK_NAMES = (
    "TA_0", "3D_0", "CL_0", "TA_1", "3D_1", "CL_1",
    "TA_2", "3D_2", "CL_2", "TA_3", "3D_3", "CL_3",
)


def _probe():
    recorder = g17p
    uat, root = recorder.uat, recorder.root

    def read(dva, size):
        try:
            return uat.ioread_root(root, dva, size)
        except Exception:
            return None

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = _ARTIFACTS / ("live_channels_%s" % stamp)
    out.mkdir(parents=True, exist_ok=False)

    initdata = recorder.initdata_addr
    root_obj = read(initdata, 0xc0)
    main_addr = struct.unpack_from("<Q", root_obj, 0x18)[0]

    table = []
    for index in range(_CHANNEL_ENTRIES):
        entry = read(main_addr + _CHANNEL_TABLE_OFFSET + index * _CHANNEL_ENTRY_SIZE, 0x20)
        if entry is None:
            continue
        words = struct.unpack_from("<4Q", entry, 0)
        record = {
            "index": index,
            "name": _WORK_NAMES[index] if index < len(_WORK_NAMES) else None,
            "state_addrs": list(words[:3]),
            "ring_addr": words[3],
            "state_blocks": [],
            "slots": [],
            "queues": {},
        }
        # Each state address sits inside a 0x40 block; capture the whole block
        # once, from the first address, so the layout is visible.
        block = read(words[0] & ~(_STATE_BLOCK - 1), _STATE_BLOCK) if words[0] else None
        if block is not None:
            record["state_block_base"] = words[0] & ~(_STATE_BLOCK - 1)
            record["state_block_hex"] = block.hex()
            record["state_words"] = list(struct.unpack_from("<16I", block, 0))
        # Ring slots: read what fits inside the ring's first page.
        if words[3]:
            span = min(_SLOT_COUNT * _SLOT_SIZE,
                       0x4000 - (words[3] & 0x3fff))
            data = read(words[3], span)
            if data is not None:
                for off in range(0, len(data) - _SLOT_SIZE + 1, _SLOT_SIZE):
                    slot = data[off:off + _SLOT_SIZE]
                    if not any(slot):
                        continue
                    queue = struct.unpack_from("<Q", slot, 0x08)[0]
                    packed = struct.unpack_from("<I", slot, 0x14)[0]
                    record["slots"].append({
                        "slot": off // _SLOT_SIZE,
                        "queue": queue,
                        "head": packed & 0xffff,
                        "queue_index": (packed >> 16) & 0xff,
                        "first_submit": bool(packed & (1 << 24)),
                    })
                    if queue and queue not in record["queues"]:
                        qrec = read(queue, _QUEUE_RECORD)
                        if qrec is not None:
                            record["queues"][queue] = qrec.hex()
        record["queues"] = {hex(k): v for k, v in record["queues"].items()}
        table.append(record)

    report = {
        "format": "m1n1-t8140-g17p-live-channels-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "initdata_addr": initdata,
        "main_config_addr": main_addr,
        "channel_table_offset": _CHANNEL_TABLE_OFFSET,
        "slot_size": _SLOT_SIZE,
        "channels": table,
        "uat_root": root,
    }
    (out / "channels.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    populated = sum(1 for c in table if c["slots"])
    print("G17P channels: %d entries, %d with populated ring slots" % (len(table), populated))
    for c in table:
        if c["slots"]:
            print("   %-5s ring %#x: %d slots, queues %s"
                  % (c["name"] or ("ch%d" % c["index"]), c["ring_addr"],
                     len(c["slots"]), sorted(c["queues"])))
    print("G17P channels: artifact %s" % out)
    return report


channel_report = _probe()
