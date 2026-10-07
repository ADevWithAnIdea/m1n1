#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the fixed native-to-m1n1 compute takeover Step 1 experiment."""

import datetime
import os
import pathlib
import subprocess
import sys
import threading


ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON = ROOT / ".venv/bin/python3"
RUN_GUEST = ROOT / "proxyclient/tools/run_guest.py"
HV_SCRIPT = ROOT / "proxyclient/hv/agx_g17p_compute_takeover_step1.py"
KERNELCACHE = ROOT / "build/kernelcache.release.Mac17,5"
# The HV script enforces the required 180-second trace ceiling after AGX
# discovery. This outer guard also allows time to stream the kernel before the
# guest and trace begin.
PROCESS_TIMEOUT = 300


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute_takeover_step1.py accepts no arguments")
    for path in (PYTHON, RUN_GUEST, HV_SCRIPT, KERNELCACHE):
        if not path.exists():
            raise SystemExit("required path does not exist: %s" % path)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    hv_log = logs / ("g17p_compute_takeover_step1_%s.hv.log" % stamp)
    console_log = logs / ("g17p_compute_takeover_step1_%s.console.log" % stamp)
    command = [
        str(PYTHON),
        str(RUN_GUEST),
        "-l", str(hv_log),
        "-m", str(HV_SCRIPT),
        str(KERNELCACHE),
    ]
    env = os.environ.copy()
    env["M1N1DEVICE"] = "/dev/m1n1-neo"
    env["PYTHONUNBUFFERED"] = "1"

    print("COMPUTE TAKEOVER STEP1 command: %s" % " ".join(command), flush=True)
    print("COMPUTE TAKEOVER STEP1 console: %s" % console_log, flush=True)
    with console_log.open("wb") as output:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        def pump():
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    return
                output.write(chunk)
                output.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()

        thread = threading.Thread(target=pump, name="step1-console", daemon=True)
        thread.start()
        try:
            result = process.wait(timeout=PROCESS_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            result = 124
            print(
                "COMPUTE TAKEOVER STEP1: 300-second setup/process guard",
                flush=True,
            )
        thread.join(timeout=2)

    print("COMPUTE TAKEOVER STEP1 exit=%d" % result, flush=True)
    print("COMPUTE TAKEOVER STEP1 hv log: %s" % hv_log, flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
