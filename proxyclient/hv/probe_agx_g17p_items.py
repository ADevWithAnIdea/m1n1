# SPDX-License-Identifier: MIT
"""Probe a frozen T8140/G17P submission from the HV shell.

Run this from a compatible frozen HV shell at the producer-before-doorbell
boundary:

    exec(open("proxyclient/hv/probe_agx_g17p_items.py").read())

The guest is halted at the work-channel producer write, before the firmware
doorbell, so every object the submission references is still resident. This
walks the publication's own structures, records each queue item verbatim,
follows one hop from every pointer field, and saves the result as an artifact.
It records bytes and observed relationships, never inferred field names.
"""

import collections
import datetime
import json
import pathlib
import struct

_PAGE = 0x4000
_TARGET_BYTES = 0x40
_ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")

# Override from the shell to widen the per-item window:
#   PROBE_ITEM_BYTES = 0x2400
_ITEM_BYTES = int(globals().get("PROBE_ITEM_BYTES", 0x200))


def _probe():
    recorder = g17p
    uat, root = recorder.uat, recorder.root
    target = json.loads((recorder.output / "target.json").read_text())

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = _ARTIFACTS / ("live_probe_%s" % stamp)
    out.mkdir(parents=True, exist_ok=False)

    def read(dva, size):
        try:
            return uat.ioread_root(root, dva, size)
        except Exception:
            return None

    def read_max(dva, size):
        """Read up to ``size`` bytes, stopping at the first unmapped page.

        Item records can be larger than one 16 KiB page and the tail is not
        always resident, so a single read of the full window would discard an
        otherwise usable record.
        """
        data = bytearray()
        while len(data) < size:
            chunk = min(size - len(data), _PAGE - ((dva + len(data)) & (_PAGE - 1)))
            piece = read(dva + len(data), chunk)
            if piece is None:
                break
            data.extend(piece)
        return bytes(data) if data else None

    def mapped(dva):
        try:
            return uat.translate_root_page(root, dva) is not None
        except Exception:
            return False

    def is_dva(value):
        return recorder.canonical_high_dva(value) is not None

    queue = target["queues"][0]
    entries = queue["inner_entries"]

    # Re-read the publication's own structures from live memory rather than
    # trusting the capture, so the probe is self-consistent.
    live = {
        "outer": read(target["outer_dva"], 0x60),
        "queue_descriptor": read(queue["descriptor_dva"], 0xc0)
        if "descriptor_dva" in queue else None,
        "inner_ring": read(queue["inner_dva"], len(entries) * 0x18),
    }

    items = []
    raw_items = bytearray()
    slot_total = 0
    for index, entry in enumerate(entries):
        for field, pointer in enumerate(entry):
            slot_total += 1
            if not pointer or not mapped(pointer):
                continue
            data = read_max(pointer, _ITEM_BYTES)
            if data is None:
                continue
            extent = len(data)
            while extent > 0 and data[extent - 1] == 0:
                extent -= 1
            fields = []
            for offset in range(0, len(data) - 7, 8):
                value = struct.unpack_from("<Q", data, offset)[0]
                if is_dva(value):
                    fields.append({
                        "offset": offset,
                        "value": value,
                        "mapped": mapped(value),
                    })
            items.append({
                "entry_index": index,
                "entry_field": field,
                "dva": pointer,
                "type": struct.unpack_from("<I", data, 0)[0],
                "bytes_read": len(data),
                "nonzero_extent": extent,
                "capture_offset": len(raw_items),
                "pointer_fields": fields,
            })
            raw_items.extend(data)

    # One hop out of every pointer field found above.
    seen = {}
    raw_targets = bytearray()
    for item in items:
        for field in item["pointer_fields"]:
            value = field["value"]
            if value in seen or not field["mapped"]:
                continue
            data = read(value, _TARGET_BYTES)
            if data is None:
                continue
            seen[value] = {
                "dva": value,
                "capture_offset": len(raw_targets),
                "referenced_by": [],
            }
            raw_targets.extend(data)
    for item in items:
        for field in item["pointer_fields"]:
            record = seen.get(field["value"])
            if record is not None:
                record["referenced_by"].append(
                    {"item_dva": item["dva"], "offset": field["offset"]}
                )

    by_type = collections.Counter(item["type"] for item in items)
    unmapped_refs = sorted({
        field["value"]
        for item in items
        for field in item["pointer_fields"]
        if not field["mapped"]
    })

    report = {
        "format": "m1n1-t8140-g17p-live-item-probe-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_capture": str(recorder.output),
        "channel": target["channel"],
        "producer_before": target["producer_before"],
        "producer_after": target["producer_after"],
        "entry_index": target["entry_index"],
        "inner_entry_count": len(entries),
        "inner_slot_total": slot_total,
        "live_item_count": len(items),
        "items_by_type": {str(k): v for k, v in sorted(by_type.items())},
        "item_stride_captured": _ITEM_BYTES,
        "items": items,
        "pointer_targets": sorted(seen.values(), key=lambda r: r["capture_offset"]),
        "target_stride_captured": _TARGET_BYTES,
        "unmapped_pointer_targets": unmapped_refs,
        "live_structures": {
            name: (value.hex() if value is not None else None)
            for name, value in live.items()
        },
        "uat_root": root,
    }
    (out / "probe.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (out / "items.bin").write_bytes(bytes(raw_items))
    (out / "pointer_targets.bin").write_bytes(bytes(raw_targets))

    print("G17P probe: %d live items of %d slots, types %s"
          % (len(items), slot_total, dict(sorted(by_type.items()))))
    print("G17P probe: %d pointer targets followed, %d unmapped references"
          % (len(seen), len(unmapped_refs)))
    print("G17P probe: artifact %s" % out)
    return report


probe_report = _probe()
