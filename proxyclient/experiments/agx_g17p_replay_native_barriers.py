#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Full captured C/R/C replay; require all three exact dependent outputs.

This is a replay-only diagnostic, not the source-built shim. The default
addresses and kick train belong to the self-authored g17p_native_barriers
witness. Nothing re-arms retired queues or supplies intermediate GPU output.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT.parent / "artifacts/agx_g17p"
PAGE = 0x4000
OUTPUT_PAGE = 0x10000030000
EXPECTED = {
    "positions": (0x200, struct.pack("<12f", -1, -1, 0, 1, 3, -1, 0, 1,
                                     -1, 3, 0, 1)),
    "texture": (0x300, struct.pack("<4f", .25, .5, .75, 1) * 16),
    "result": (0x400, struct.pack("<4f", .25, .5, .75, 1) * 16),
}
HELD_KICKS = (0x8300000000000a, 0x83000000000008, 0x8300000000000a)


def capture_queue_state(manifest, ram):
    """Read host queue data only, keeping captured retirement visible."""
    selected = int(manifest["selected_root"]["index"])
    mask = (1 << 44) - 1
    pages = {int(row["va"]) & mask: row
             for root in manifest["root_mappings"] if root["root_index"] == selected
             for row in root["mappings"]}

    def read(address, size):
        output = bytearray()
        while size:
            offset = address & (PAGE - 1)
            count = min(size, PAGE - offset)
            row = pages[(address & mask) & ~(PAGE - 1)]
            if row.get("blob_index") is None:
                raise ValueError("queue data is not in captured host RAM")
            start = row["blob_index"] * PAGE + offset
            body = ram[start:start + count]
            if len(body) != count:
                raise ValueError("short captured queue data")
            output.extend(body)
            address += count
            size -= count
        return bytes(output)

    def qword(address):
        return struct.unpack("<Q", read(address, 8))[0]

    def word(address):
        return struct.unpack("<I", read(address, 4))[0]

    region_b = qword(int(manifest["init_addr"]) + 0x18)
    channels = []
    for index, name in ((6, "TA_2"), (7, "3D_2"), (8, "CL_2")):
        base = region_b + 0x20 + index * 0x20
        counters = [word(qword(base + offset)) for offset in (0, 8, 16)]
        if counters[2] not in (1, 2):
            raise ValueError("unexpected native barrier publication count")
        ring = qword(base + 24)
        queues = []
        for slot in range(counters[2]):
            queue = qword(ring + 24 * slot + 8)
            pointers = qword(queue)
            queues.append(dict(slot=slot, queue=queue, pointers=pointers,
                done=word(pointers), read=word(pointers + 0x30),
                write=word(pointers + 0x40)))
        channels.append(dict(name=name, counters=counters, queues=queues))
    return channels


def validate_outputs(before, after):
    if len(before) != PAGE or len(after) != PAGE:
        raise ValueError("the complete witness page is required")
    outputs = {}
    for name, (offset, expected) in EXPECTED.items():
        pre = before[offset:offset + len(expected)]
        post = after[offset:offset + len(expected)]
        outputs[name] = dict(
            dva=OUTPUT_PAGE + offset, size=len(expected),
            initially_zero=pre == bytes(len(expected)),
            exact=post == expected,
            changed_bytes=sum(a != b for a, b in zip(pre, post)),
            mismatched_bytes=sum(a != b for a, b in zip(expected, post)),
            expected_hex=expected.hex(), actual_hex=post.hex())
    return dict(outputs=outputs, passed=all(
        value["initially_zero"] and value["exact"] and value["changed_bytes"]
        for value in outputs.values()), execution_path="full-capture replay only")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--no-bootstrap", action="store_true")
    parser.add_argument("--reduction", type=Path)
    parser.add_argument("--output-root", type=Path, default=ARTIFACTS)
    firmware_data = parser.add_mutually_exclusive_group()
    firmware_data.add_argument("--fresh-coprocessor-data", action="store_true",
                              default=True,
                              help="use normal cold ASC private data (default)")
    firmware_data.add_argument("--restore-coprocessor-data-regions",
                              dest="fresh_coprocessor_data", action="store_false",
                              help="diagnostic: restore late ASC private data; known not to cold-boot")
    args = parser.parse_args()
    snapshot = args.snapshot.resolve(strict=True)
    device = os.environ.get("M1N1DEVICE", "")
    if (not device.startswith("/dev/ttys") or
            not stat.S_ISCHR(os.stat(device, follow_symlinks=False).st_mode)):
        raise RuntimeError("use the exact raw PTY returned by the owned RID 1 relay")
    manifest = json.loads((snapshot / "manifest.json").read_text())
    if manifest["chip_id"] != 0x8140 or manifest["unsupported_entries"]:
        raise RuntimeError("complete T8140 all-root capture required")
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    if hashlib.sha256(ram).hexdigest() != manifest["ram_sha256"]:
        raise RuntimeError("capture RAM checksum mismatch")
    queue_state = capture_queue_state(manifest, ram)
    if args.reduction is not None:
        from g17p_barrier_bisect import zero_page_overrides
        zero_page_overrides(manifest, ram, json.loads(args.reduction.read_text()))
    maps = [mapping for root in manifest["root_mappings"]
            if root["root_ctx_id"] == 1 and root["selector"] == 0
            for mapping in root["mappings"] if mapping["va"] == OUTPUT_PAGE]
    if len(maps) != 1 or "blob_index" not in maps[0]:
        raise RuntimeError("unique captured client output mapping required")
    start = maps[0]["blob_index"] * PAGE
    captured_page = ram[start:start + PAGE]
    for name, (offset, expected) in EXPECTED.items():
        if captured_page[offset:offset + len(expected)] != bytes(len(expected)):
            raise RuntimeError("captured %s does not start at zero" % name)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    directory = args.output_root / ("native_barrier_replay_" + stamp)
    directory.mkdir()
    environment = dict(os.environ, PYTHONPATH=str(ROOT / "proxyclient"),
                       PYTHONUNBUFFERED="1")
    if not args.no_bootstrap:
        subprocess.run([sys.executable, "proxyclient/tools/rid1_bootstrap.py", device],
                       cwd=ROOT, env=environment, check=True)
    command = [sys.executable, "proxyclient/experiments/agx_g17p_replay_initdata.py",
               "--snapshot", str(snapshot), "--output-root", str(directory),
               "--replay-first-work", "--resume-post-control",
               "--watch-context", "1", "--watch-render-from-start",
               "--watch-before-work-publication",
               "--watch-render-dva", hex(OUTPUT_PAGE), "--require-render-change",
               "--wait-for-work-events", "3", "--timeout", "2"]
    for channel in ("TA_2", "3D_2", "CL_2"):
        command.extend(("--defer-work-channel", channel))
    if not args.fresh_coprocessor_data:
        command.append("--restore-coprocessor-data-regions")
    if args.reduction is not None:
        command.extend(("--barrier-reduction", str(args.reduction.resolve())))
    for message in HELD_KICKS:
        command.extend(("--held-work-message", hex(message)))
    print("Full native barrier replay artifacts:", directory, flush=True)
    print("Captured queue state:", json.dumps(queue_state), flush=True)
    print("Cold replay; original queue state; three recorded kicks without "
          "intermediate waits or copyback", flush=True)
    (directory / "invocation.json").write_text(json.dumps(dict(
        command=command, snapshot=str(snapshot), captured_outputs_zero=True,
        captured_queue_state=queue_state,
        fresh_coprocessor_data=args.fresh_coprocessor_data,
        manifest_sha256=hashlib.sha256((snapshot / "manifest.json").read_bytes()).hexdigest()
    ), indent=2) + "\n")
    try:
        result = subprocess.run(command, cwd=ROOT, env=environment, timeout=150)
    except subprocess.TimeoutExpired:
        (directory / "dependent_outputs.json").write_text(json.dumps(dict(
            passed=False, error="replay process timeout", snapshot=str(snapshot)), indent=2) + "\n")
        return 1
    attempts = list(directory.glob("replay_first_work_*"))
    if len(attempts) != 1:
        raise RuntimeError("expected exactly one replay attempt")
    attempt = attempts[0]
    watch_path = attempt / "render_watch.json"
    if not watch_path.exists():
        report = dict(passed=False, error="replay did not reach complete output readback")
    else:
        watch = json.loads(watch_path.read_text())
        if len(watch) != 1 or watch[0]["dva"] != OUTPUT_PAGE:
            raise RuntimeError("unexpected replay witness mapping")
        record = watch[0]
        report = validate_outputs((attempt / record["before_file"]).read_bytes(),
                                  (attempt / record["after_file"]).read_bytes())
        pre_path = attempt / "render_watch_pre_work_publication.json"
        pre_watch = json.loads(pre_path.read_text()) if pre_path.exists() else []
        if len(pre_watch) != 1 or pre_watch[0]["dva"] != OUTPUT_PAGE:
            pre_page = b""
        else:
            pre_page = (attempt / pre_watch[0]["after_file"]).read_bytes()
        report["zero_after_firmware_init_before_publication"] = len(pre_page) == PAGE and all(
            pre_page[offset:offset + len(expected)] == bytes(len(expected))
            for offset, expected in EXPECTED.values())
        report["passed"] &= report["zero_after_firmware_init_before_publication"]
    report.update(replay_exit_code=result.returncode, attempt=str(attempt),
                  snapshot=str(snapshot), fresh_coprocessor_data=args.fresh_coprocessor_data)
    report["passed"] &= result.returncode == 0
    if args.reduction is not None:
        report["reduction"] = json.loads(args.reduction.read_text())
        if report["reduction"].get("release_probe"):
            report["execution_path"] = "capture replay with diagnostic synthetic dependency release"
            release_path = attempt / "barrier_release.json"
            report["release_probe"] = (json.loads(release_path.read_text())
                                       if release_path.exists() else None)
        if report["reduction"].get("delay_producer"):
            report["execution_path"] = "capture replay with consumer-first real producer publication"
            delay_path = attempt / "barrier_delayed_producer.json"
            delay = json.loads(delay_path.read_text()) if delay_path.exists() else {}
            report["delayed_producer"] = delay
            report["passed"] &= bool(delay.get("passed_before_release") and delay.get("released"))
    (directory / "dependent_outputs.json").write_text(json.dumps(report, indent=2) + "\n")
    print("DEPENDENT OUTPUT REPLAY", "PASS" if report["passed"] else "FAIL",
          {name: {key: value[key] for key in ("initially_zero", "exact", "changed_bytes")}
           for name, value in report.get("outputs", {}).items()}, flush=True)
    return 0 if report["passed"] and result.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
