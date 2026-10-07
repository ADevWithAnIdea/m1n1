#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Negative-control the clean replay with the current source render-root state.

This is deliberately a no-argument experiment.  It restores the known-good
first-partial checkpoint and generated descriptors, then replaces a selected
cohort of comparable render-root pages at the exact post-control/pre-work boundary
with the latest source-built world's bytes.  A valid result is normal work
retirement with no render output; later bisection narrows this set.
"""

import datetime
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
DEVICE = "/dev/ttys004"
SNAPSHOT = Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_partial_first_app_pre_kick_20260821_020229"
)
SOURCE = Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "source_partial_opening_pre_publish_20260821_050250"
)
OUTPUT_DVAS = tuple(
    0x10000058000 + attachment * 0x18000 + page * 0x4000
    for attachment in range(8)
    for page in range(4)
)
EXPECTED_NEGATIVE = "work retired without changing any watched output-page byte"
# Edit only these two defaults for each recorded bisection cohort.  Every
# required replay argument remains fixed in this no-argument launcher.
GRAFT_PAGE_SLICE = "0:15"
# Use None while discovering a bisection branch.  Pin to True or False for a
# confirmatory run once that cohort's classification is known.
EXPECT_RENDER = None


def run(command, *, environment=None, check=True):
    print("RUN: %s" % " ".join(str(part) for part in command), flush=True)
    return subprocess.run(
        command, cwd=ROOT, env=environment, check=check,
    )


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_replay_first_partial_graft.py accepts no arguments"
        )
    required = (
        ROOT / "build/m1n1.bin",
        ROOT / "proxyclient/experiments/agx_g17p_replay_initdata.py",
        SNAPSHOT / "manifest.json",
        SNAPSHOT / "ram.bin",
        SNAPSHOT / "tables.bin",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if not SOURCE.is_dir():
        missing.append(str(SOURCE))
    if missing:
        raise RuntimeError("missing first-partial graft assets: %s" % missing)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    console = ROOT / "logs" / (
        "g17p_first_partial_all_source_graft_%s.console.txt" % stamp
    )
    environment = os.environ.copy()
    environment.update({
        "M1N1DEVICE": DEVICE,
        "PYTHONPATH": str(ROOT / "proxyclient"),
        "PYTHONUNBUFFERED": "1",
        "G17P_NATIVE_LIFECYCLE_FIELDS": "1",
        "G17P_NATIVE_TAIL_ITEM_FIELDS": "1",
        "G17P_STRUCTURAL_TAIL_FIELDS": "1",
    })

    run(["/usr/local/bin/macvdmtool", "--neo", "reboot", "debugusb"])
    run([
        str(ROOT / ".venv/bin/python3"),
        "proxyclient/tools/chainload.py", "-r", "build/m1n1.bin",
    ], environment=environment)

    command = [
        "/usr/bin/perl", "-e", "alarm 240; exec @ARGV",
        "/usr/bin/script", "-q", str(console),
        str(ROOT / ".venv/bin/python3"),
        "proxyclient/experiments/agx_g17p_replay_initdata.py",
        "--snapshot", str(SNAPSHOT),
        "--replay-first-work", "--resume-post-control",
        "--defer-work-channel", "TA_2",
        "--defer-work-channel", "3D_2",
        "--first-work-channel-pair", "2",
        "--first-work-descriptor-pair", "0",
        "--backend-queue-slot", "0",
        "--build-ta-descriptor", "--build-ta-captured-tail",
        "--build-3d-descriptor", "--build-3d-captured-tail",
        "--build-render-register-recipe",
        "--allow-register-recipe-differences",
        "--build-structural-tails",
        "--redirect-descriptor-backreferences",
        "--graft-firmware-pages", str(SOURCE),
        "--graft-root-index", "1",
        "--graft-different-only",
        "--graft-page-slice", GRAFT_PAGE_SLICE,
        "--graft-before-first-work",
        "--watch-context", "1",
        "--watch-render-from-start", "--require-render-change",
        "--use-captured-work-message", "--timeout", "15",
    ]
    for dva in OUTPUT_DVAS:
        command.extend(("--watch-render-dva", hex(dva)))
    completed = run(command, environment=environment, check=False)
    transcript = console.read_text(errors="replace")
    rendered = completed.returncode == 0
    expected_negative = EXPECTED_NEGATIVE in transcript
    if not rendered and not expected_negative:
        raise RuntimeError(
            "source graft failed for an unexpected reason; see %s" % console
        )
    if EXPECT_RENDER is not None and rendered != EXPECT_RENDER:
        raise RuntimeError(
            "graft slice %s classification was %s, expected %s; see %s" % (
                GRAFT_PAGE_SLICE,
                "render" if rendered else "no-output retirement",
                "render" if EXPECT_RENDER else "no-output retirement",
                console,
            )
        )
    print(
        "SOURCE GRAFT SLICE %s %s PASS: %s" % (
            GRAFT_PAGE_SLICE,
            "RENDER" if rendered else "NO-OUTPUT",
            console,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
