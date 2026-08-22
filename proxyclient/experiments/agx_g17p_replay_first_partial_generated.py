#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cold-replay the clean first partial render with generated descriptors.

This is intentionally a no-argument experiment.  It resets Neo, chainloads the
current m1n1 build, restores the clean first-application checkpoint, replaces
both pending work descriptors through the production builder, and requires the
eight physical accumulation outputs.  The current discriminator retains the
captured post-register tails as the positive boundary; tail ranges are added
only after this boundary passes.
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
OUTPUT_DVAS = tuple(
    0x10000058000 + attachment * 0x18000 + page * 0x4000
    for attachment in range(8)
    for page in range(4)
)


def run(command, *, environment=None):
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_replay_first_partial_generated.py accepts no arguments"
        )
    required = (
        ROOT / "build/m1n1.bin",
        ROOT / "proxyclient/experiments/agx_g17p_replay_initdata.py",
        SNAPSHOT / "manifest.json",
        SNAPSHOT / "ram.bin",
        SNAPSHOT / "tables.bin",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError("missing first-partial replay assets: %s" % missing)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    console = ROOT / "logs" / (
        "g17p_first_partial_generated_%s.console.txt" % stamp
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
        "--first-work-channel-pair", "2",
        "--first-work-descriptor-pair", "0",
        "--backend-queue-slot", "0",
        "--build-ta-descriptor", "--build-ta-captured-tail",
        "--build-3d-descriptor", "--build-3d-captured-tail",
        "--build-render-register-recipe",
        "--allow-register-recipe-differences",
        "--build-structural-tails",
        "--redirect-descriptor-backreferences",
        "--watch-context", "1",
        "--watch-render-from-start", "--require-render-change",
        "--use-captured-work-message", "--timeout", "15",
    ]
    for dva in OUTPUT_DVAS:
        command.extend(("--watch-render-dva", hex(dva)))
    run(command, environment=environment)
    print("generated first-partial replay console: %s" % console)


if __name__ == "__main__":
    main()
