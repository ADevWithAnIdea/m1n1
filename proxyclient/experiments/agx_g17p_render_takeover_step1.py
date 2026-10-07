#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the fixed native-to-m1n1 render takeover experiment."""

import datetime
import os
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON = ROOT / ".venv/bin/python3"
RUN_GUEST = ROOT / "proxyclient/tools/run_guest.py"
HV_SCRIPT = ROOT / "proxyclient/hv/agx_g17p_render_takeover_step1.py"
KERNELCACHE = ROOT / "build/kernelcache.release.Mac17,5"
PROCESS_TIMEOUT = 300


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_render_takeover_step1.py accepts no arguments")
    for path in (PYTHON, RUN_GUEST, HV_SCRIPT, KERNELCACHE):
        if not path.exists():
            raise SystemExit("required path does not exist: %s" % path)

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    hv_log = logs / ("g17p_render_takeover_step1_%s.hv.log" % stamp)
    console_log = logs / ("g17p_render_takeover_step1_%s.console.log" % stamp)
    command = [
        str(PYTHON), str(RUN_GUEST), "--headless-guest",
        "-l", str(hv_log), "-m", str(HV_SCRIPT),
        str(KERNELCACHE), "--",
        "serial=3", "-nobsdmgroot", "wdt=-1", "sprr_tpro=0",
        "sprr_tpro_pagers=0", "-v", "msgbuf=1048576",
    ]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    print("RENDER TAKEOVER STEP1 command: %s" % " ".join(command), flush=True)
    print("RENDER TAKEOVER STEP1 console: %s" % console_log, flush=True)
    with console_log.open("wb") as output:
        process = subprocess.Popen(
            command, cwd=ROOT, env=env,
            stdout=output, stderr=subprocess.STDOUT,
        )
        try:
            result = process.wait(timeout=PROCESS_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            result = 124
            print("RENDER TAKEOVER STEP1: setup/process guard expired", flush=True)

    print("RENDER TAKEOVER STEP1 exit=%d" % result, flush=True)
    print("RENDER TAKEOVER STEP1 hv log: %s" % hv_log, flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
