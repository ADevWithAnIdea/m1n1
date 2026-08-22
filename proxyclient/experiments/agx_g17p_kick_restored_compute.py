#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse
import datetime
import hashlib
import json
import pathlib
import struct
import time

from m1n1.fw.asc.base import ASCMessage1
from m1n1.hw.asc import ASC
from m1n1.setup import *


PAGE_SIZE = 0x4000
DEFAULT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "pre_compute_full_20260806_004547"
)
DEFAULT_TARGET = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260806_004435"
)
DEFAULT_OUTPUT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/restored_compute_kick"
)
WATCH_DVAS = (
    0x0000007000208000,
    0x0000010001D7C000,
    0x0000001000000000,
    0x0000010000000000,
)
WORK_CHANNEL_NAMES = (
    "TA_0", "3D_0", "CL_0",
    "TA_1", "3D_1", "CL_1",
    "TA_2", "3D_2", "CL_2",
    "TA_3", "3D_3", "CL_3",
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Kick the live post-control full-UAT compute replay"
    )
    parser.add_argument("--snapshot", type=pathlib.Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--target", type=pathlib.Path, default=DEFAULT_TARGET)
    parser.add_argument("--output-root", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--channel", choices=WORK_CHANNEL_NAMES, default="CL_0")
    parser.add_argument(
        "--watch-dva",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
        help="context-1 DVA to compare across the kick; may be repeated",
    )
    parser.add_argument(
        "--resume-control-producer",
        type=int,
        help="before restoring the pre-kick image, send the opening 0x89 to "
        "both firmware instances and wait for this device-control producer",
    )
    parser.add_argument(
        "--restore-state-before-kick",
        action="store_true",
        help="rewind every captured UAT data/table page before publishing",
    )
    parser.add_argument(
        "--restore-coprocessor-data-regions",
        action="store_true",
        help="with --restore-state-before-kick, restore gfx-data and gfx1-data last",
    )
    return parser.parse_args()


def mapping_pa(manifest, context, dva):
    page = int(dva) & ~(PAGE_SIZE - 1)
    matches = []
    for group in manifest["root_mappings"]:
        if int(group["root_ctx_id"]) != int(context):
            continue
        for mapping in group["mappings"]:
            if int(mapping["va"]) == page:
                matches.append(mapping)
    if len(matches) != 1:
        raise RuntimeError(
            "DVA %#x in context %d has %d mappings" % (dva, context, len(matches))
        )
    return int(matches[0]["pa"]) + (int(dva) & (PAGE_SIZE - 1))


def read_page(pa):
    page = int(pa) & ~(PAGE_SIZE - 1)
    p.dc_civac(page, PAGE_SIZE)
    return bytes(iface.readmem(page, PAGE_SIZE))


def merge_ranges(ranges):
    merged = []
    for start, size in sorted(ranges):
        end = start + size
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [(start, end - start) for start, end in merged]


def restore_live_state(args, manifest, state_pas):
    ram_path = args.snapshot / manifest["ram_file"]
    ram = ram_path.read_bytes()
    if hashlib.sha256(ram).hexdigest() != manifest["ram_sha256"]:
        raise RuntimeError("RAM blob checksum mismatch")

    producer_pa = int(state_pas[2])
    producer_page = producer_pa & ~(PAGE_SIZE - 1)
    producer_override = None
    pages = sorted(
        (int(page["original_pa"]), page) for page in manifest["blob_pages"]
    )
    cursor = 0
    completed = 0
    while cursor < len(pages):
        start = pages[cursor][0]
        end = start + PAGE_SIZE
        next_cursor = cursor + 1
        while (
            next_cursor < len(pages)
            and pages[next_cursor][0] == end
            and end - start < 0x400000
        ):
            end += PAGE_SIZE
            next_cursor += 1
        body = bytearray()
        for pa, page in pages[cursor:next_cursor]:
            index = int(page["index"])
            data = ram[index * PAGE_SIZE:(index + 1) * PAGE_SIZE]
            if pa == producer_page:
                data = bytearray(data)
                struct.pack_into("<I", data, producer_pa - producer_page, 0)
                producer_override = bytes(data)
                data = producer_override
            body.extend(data)
        iface.writemem(start, body)
        completed += next_cursor - cursor
        if completed % 256 == 0 or completed == len(pages):
            print("  rewound UAT RAM pages %d/%d" % (completed, len(pages)))
        cursor = next_cursor
    if producer_override is None:
        raise RuntimeError("producer page is absent from the captured RAM image")

    table_path = args.snapshot / manifest["tables_file"]
    tables = table_path.read_bytes()
    if hashlib.sha256(tables).hexdigest() != manifest["tables_sha256"]:
        raise RuntimeError("UAT table blob checksum mismatch")
    table_ranges = []
    for record in manifest["table_page_records"]:
        index = int(record["index"])
        pa = int(record["original_pa"])
        data = tables[index * PAGE_SIZE:(index + 1) * PAGE_SIZE]
        iface.writemem(pa, data)
        table_ranges.append((pa, PAGE_SIZE))

    shared_names = {
        "gpu-region",
        "gfx-shared-region",
        "gfx-shared-l2-region",
        "gfx-handoff",
    }
    private_names = {"gfx-data", "gfx1-data"}
    fixed_ranges = []
    private = []
    for region in manifest["fixed_regions"]:
        name = region["name"]
        if name not in shared_names and not (
            args.restore_coprocessor_data_regions and name in private_names
        ):
            continue
        data = (args.snapshot / region["file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != region["sha256"]:
            raise RuntimeError("fixed-region checksum mismatch for %s" % name)
        record = (int(region["pa"]), data, name)
        if name in private_names:
            private.append(record)
        else:
            iface.writemem(record[0], record[1])
            fixed_ranges.append((record[0], len(record[1])))

    cache_ranges = [(pa, PAGE_SIZE) for pa, _page in pages]
    cache_ranges.extend(table_ranges)
    cache_ranges.extend(fixed_ranges)
    for pa, size in merge_ranges(cache_ranges):
        p.dc_civac(pa, size)
    u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")

    # Private runtime data is deliberately last: management boot and initdata
    # have completed, and the captured work is still hidden in its page image.
    for pa, data, name in sorted(private, key=lambda item: item[2], reverse=True):
        print("  restoring late private region %s at %#x+%#x" % (name, pa, len(data)))
        iface.writemem(pa, data)
        p.dc_civac(pa, len(data))
    if private:
        u.inst("dsb sy; isb")


def main():
    args = parse_args()
    manifest = json.loads((args.snapshot / "manifest.json").read_text())
    metadata = json.loads((args.target / "metadata.json").read_text())
    channel = next(
        item for item in metadata["channels"] if item["name"] == args.channel
    )
    state_pas = [
        mapping_pa(manifest, 64, dva) for dva in channel["state_addrs"]
    ]
    control_report = None
    if args.resume_control_producer is not None:
        target_path = args.target / args.channel / "target.json"
        target = json.loads(target_path.read_text())
        control = target["device_control"]
        control_pas = [
            mapping_pa(manifest, 64, dva) for dva in control["state_addrs"]
        ]
        before = [int(p.read32(pa)) for pa in control_pas]
        expected = int(args.resume_control_producer)
        if before != [0, 0, expected]:
            raise RuntimeError(
                "device-control state is not the resumable 0/0/%d boundary: %r"
                % (expected, before)
            )
        for path in ("/arm-io/gfx-asc", "/arm-io/gfx1-asc"):
            asc_base = int(u.adt[path].get_reg(0)[0])
            ASC(u, asc_base).send(0x0089000000000000, ASCMessage1(EP=0x21))
        deadline = time.monotonic() + args.timeout
        after = before
        while time.monotonic() < deadline:
            p.dc_civac(control_pas[0] & ~(PAGE_SIZE - 1), PAGE_SIZE)
            after = [int(p.read32(pa)) for pa in control_pas]
            if after[:2] == [expected, expected]:
                break
            time.sleep(0.001)
        if after[:2] != [expected, expected]:
            raise TimeoutError(
                "device-control resume timed out: expected %d/%d/%d, got %r"
                % (expected, expected, expected, after)
            )
        control_report = {
            "message": 0x0089000000000000,
            "state_dvas": control["state_addrs"],
            "state_pas": control_pas,
            "before": before,
            "after": after,
        }
        print("Device-control counters: %s -> %s" % (before, after))
    if args.restore_coprocessor_data_regions and not args.restore_state_before_kick:
        raise RuntimeError(
            "--restore-coprocessor-data-regions requires --restore-state-before-kick"
        )
    if args.restore_state_before_kick:
        restore_live_state(args, manifest, state_pas)
    counters_before = [int(p.read32(pa)) for pa in state_pas]
    hidden = int(channel["initial_counters"][0])
    producer = int(
        json.loads((args.target / args.channel / "target.json").read_text())[
            "producer_after"
        ]
    )
    if counters_before != [hidden, hidden, hidden]:
        raise RuntimeError(
            "post-reapply %s is not hidden at %d/%d/%d: %r"
            % (args.channel, hidden, hidden, hidden, counters_before)
        )

    watches = []
    for dva in args.watch_dva or WATCH_DVAS:
        pa = mapping_pa(manifest, 1, dva)
        watches.append({"dva": dva, "pa": pa, "before": read_page(pa)})

    producer_pa = state_pas[2]
    p.write32(producer_pa, producer)
    p.dc_civac(producer_pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
    u.inst("dsb sy")

    message = int(manifest["trigger_message"])
    if ((message >> 48) & 0xFF) != 0x83:
        raise RuntimeError("snapshot trigger is not a work message: %#x" % message)
    asc_base = int(u.adt["/arm-io/gfx-asc"].get_reg(0)[0])
    ASC(u, asc_base).send(message, ASCMessage1(EP=0x21))

    deadline = time.monotonic() + args.timeout
    counters_after = counters_before
    while time.monotonic() < deadline:
        p.dc_civac(state_pas[0] & ~(PAGE_SIZE - 1), PAGE_SIZE)
        counters_after = [int(p.read32(pa)) for pa in state_pas]
        if counters_after[:2] == [producer, producer]:
            break
        time.sleep(0.001)

    time.sleep(0.005)
    changed_pages = 0
    report_watches = []
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output = args.output_root / stamp
    output.mkdir(parents=True, exist_ok=False)
    for watch in watches:
        after = read_page(watch["pa"])
        changed = [
            index
            for index, (before, current) in enumerate(zip(watch["before"], after))
            if before != current
        ]
        if changed:
            changed_pages += 1
        stem = "%x" % watch["dva"]
        (output / (stem + "_before.bin")).write_bytes(watch["before"])
        (output / (stem + "_after.bin")).write_bytes(after)
        report_watches.append(
            {
                "dva": watch["dva"],
                "pa": watch["pa"],
                "changed_bytes": len(changed),
                "first_changed_offsets": changed[:128],
            }
        )
        print(
            "DVA %#x PA %#x: %d physical bytes changed"
            % (watch["dva"], watch["pa"], len(changed))
        )

    report = {
        "format": "m1n1-agx-g17p-restored-compute-kick-v1",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snapshot": str(args.snapshot.resolve()),
        "target": str(args.target.resolve()),
        "channel": args.channel,
        "message": message,
        "endpoint": 0x21,
        "state_dvas": channel["state_addrs"],
        "state_pas": state_pas,
        "counters_before": counters_before,
        "counters_after": counters_after,
        "control_resume": control_report,
        "restored_state_before_kick": bool(args.restore_state_before_kick),
        "restored_coprocessor_data_regions": bool(
            args.restore_coprocessor_data_regions
        ),
        "changed_pages": changed_pages,
        "watches": report_watches,
    }
    (output / "result.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print("Counters: %s -> %s" % (counters_before, counters_after))
    print("Captured work message: %#018x" % message)
    print("Artifacts: %s" % output)
    return 0 if changed_pages else 1


if __name__ == "__main__":
    raise SystemExit(main())
