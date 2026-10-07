#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cold-replay the latest clean first-application partial checkpoint."""

import datetime
import json
import math
import os
from pathlib import Path
import subprocess
import struct
import stat
import sys


ROOT = Path(__file__).resolve().parents[2]
DEVICE = os.environ.get("G17P_M1N1DEVICE") or os.environ.get("M1N1DEVICE")
LATEST = Path("/Users/user/asahi_re/artifacts/agx_g17p/latest")
OUTPUT_BASES = (0x10000058000, 0x10000118000)
OUTPUT_DVAS = tuple(
    base + attachment * 0x18000 + 0x4000
    for base in OUTPUT_BASES
    for attachment in range(8)
)
ATTEMPT_GLOB = "replay_first_work_original_pa_attempt_*"
DIAGNOSTIC_FLOAT_OFFSETS = (16124, 16128)


def run(command, *, environment=None):
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def validate_independent_outputs(attempt):
    report_path = attempt / "render_watch.json"
    report = json.loads(report_path.read_text())
    by_dva = {int(record["dva"]): record for record in report}
    if set(by_dva) != set(OUTPUT_DVAS):
        raise RuntimeError(
            "render watch set mismatch: expected %s, got %s"
            % ([hex(dva) for dva in OUTPUT_DVAS],
               [hex(dva) for dva in sorted(by_dva)])
        )

    decoded = []
    for queue_index, base in enumerate(OUTPUT_BASES):
        values = []
        for attachment in range(8):
            dva = base + attachment * 0x18000 + 0x4000
            record = by_dva[dva]
            if int(record["changed_bytes"]) == 0:
                raise RuntimeError(
                    "queue %d attachment %d did not change"
                    % (queue_index + 1, attachment)
                )
            body = (attempt / record["after_file"]).read_bytes()
            samples = [
                struct.unpack_from("<f", body, offset)[0]
                for offset in DIAGNOSTIC_FLOAT_OFFSETS
            ]
            expected = float(attachment + 1)
            if not all(
                math.isfinite(value) and abs(value - expected) < 0.02
                for value in samples
            ):
                raise RuntimeError(
                    "queue %d attachment %d expected %.1f, got %r"
                    % (queue_index + 1, attachment, expected, samples)
                )
            values.append(samples[0])
        decoded.append(values)
    print("INDEPENDENT TWO-QUEUE OUTPUT PASS: %s" % decoded)


def execute_replay(
    *,
    label="direct",
    extra_args=(),
    output_dvas=OUTPUT_DVAS,
    validate=validate_independent_outputs,
    snapshot=None,
    bootstrap=True,
    wait_for_work_events=2,
    resume_post_control=True,
):
    if not DEVICE or not DEVICE.startswith("/dev/ttys"):
        raise RuntimeError(
            "set G17P_M1N1DEVICE to the exact raw PTY printed by the live "
            "/usr/local/bin/kisd --rid 1 instance"
        )
    # Reject a disappeared relay PTY before even resetting RID 1. A matching
    # name alone is not evidence that the owning relay is still alive.
    try:
        device_stat = os.stat(DEVICE, follow_symlinks=False)
    except FileNotFoundError:
        raise RuntimeError("the recorded raw PTY no longer exists; start a new RID 1 relay") from None
    if not stat.S_ISCHR(device_stat.st_mode):
        raise RuntimeError("the raw RID 1 PTY must be a character device, not a symlink")
    snapshot = (
        LATEST.resolve(strict=True)
        if snapshot is None else Path(snapshot).resolve(strict=True)
    )
    required = (
        ROOT / "build/m1n1.bin",
        ROOT / "proxyclient/experiments/agx_g17p_replay_initdata.py",
        snapshot / "manifest.json",
        snapshot / "ram.bin",
        snapshot / "tables.bin",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError("missing partial replay assets: %s" % missing)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    console = ROOT / "logs" / (
        "g17p_latest_partial_%s_replay_%s.console.txt" % (label, stamp)
    )
    environment = os.environ.copy()
    environment.update({
        "M1N1DEVICE": DEVICE,
        "PYTHONPATH": str(ROOT / "proxyclient"),
        "PYTHONUNBUFFERED": "1",
    })
    attempts_before = set(LATEST.parent.glob(ATTEMPT_GLOB))

    if bootstrap:
        run([
            sys.executable,
            "proxyclient/tools/rid1_bootstrap.py", DEVICE,
        ], environment=environment)

    command = [
        "/usr/bin/perl", "-e", "alarm 180; exec @ARGV",
        "/usr/bin/script", "-q", str(console),
        sys.executable,
        "proxyclient/experiments/agx_g17p_replay_initdata.py",
        "--snapshot", str(snapshot),
        "--replay-first-work",
        "--watch-context", "1",
        "--watch-render-from-start", "--require-render-change",
        # A two-pending capture presents producer 2 before ASC startup.  Hide
        # both halves of the pair until the explicit replay doorbell so the
        # restored firmware cannot ingest them during its init handshake.
        "--defer-work-channel", "TA_2",
        "--defer-work-channel", "3D_2",
        "--wait-for-work-events", str(wait_for_work_events),
        "--use-captured-work-message", "--timeout", "15",
    ]
    if resume_post_control:
        command.append("--resume-post-control")
    command.extend(extra_args)
    for dva in output_dvas:
        command.extend(("--watch-render-dva", hex(dva)))
    run(command, environment=environment)
    attempts_after = set(LATEST.parent.glob(ATTEMPT_GLOB))
    created = attempts_after - attempts_before
    if len(created) != 1:
        raise RuntimeError(
            "expected one new replay attempt, found %d" % len(created)
        )
    attempt = created.pop()
    validate(attempt)
    print("latest partial snapshot: %s" % snapshot)
    print("latest partial replay artifacts: %s" % attempt)
    print("latest partial replay console: %s" % console)


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_replay_latest_partial.py accepts no arguments"
        )
    execute_replay()


if __name__ == "__main__":
    main()
