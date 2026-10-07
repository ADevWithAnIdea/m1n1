#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded RID-1-only page reduction with the complete dependent-output oracle."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from g17p_barrier_bisect import FORMAT, ownership_candidates

ROOT = Path(__file__).resolve().parents[2]


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def attempt(snapshot, directory, plan):
    """Own exactly one new RID-1 relay and all of this attempt's processes."""
    with (directory / "relay.log").open("w") as relay_log:
        relay = subprocess.Popen(["/usr/local/bin/kisd", "--rid", "1"],
                                 stdout=relay_log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                body = (directory / "relay.log").read_text()
                match = re.search(r"pty (/dev/ttys\d+)", body)
                if match and "Device opened on RID 1" in body:
                    device = match[1]
                    break
                if relay.poll() is not None:
                    raise RuntimeError("owned RID 1 relay exited")
                time.sleep(0.05)
            else:
                raise TimeoutError("owned relay did not identify RID 1 and its raw PTY")
            subprocess.run(["stty", "-f", device, "raw", "-echo"], check=True)
            environment = dict(os.environ, M1N1DEVICE=device, PYTHONUNBUFFERED="1",
                               PATH="/opt/homebrew/bin:" + os.environ["PATH"])
            command = [sys.executable, str(ROOT / "proxyclient/experiments/agx_g17p_replay_native_barriers.py"),
                       str(snapshot), "--reduction", str(plan), "--output-root", str(directory)]
            with (directory / "console.txt").open("w") as console:
                child = subprocess.Popen(command, cwd=ROOT, env=environment,
                                         stdout=console, stderr=subprocess.STDOUT,
                                         start_new_session=True)
                try:
                    child.wait(timeout=180)
                except BaseException:
                    os.killpg(child.pid, signal.SIGTERM)
                    child.wait(timeout=5)
                    raise
            reports = list(directory.glob("native_barrier_replay_*/dependent_outputs.json"))
            if len(reports) != 1:
                raise RuntimeError("no unique GPU result; inspect bootstrap/transport, do not classify a cut")
            report = json.loads(reports[0].read_text())
            report["report_file"] = str(reports[0])
            return report
        finally:
            relay.terminate()
            relay.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--plans", type=Path, nargs="+",
                        help="run explicit field-reduction plans instead of page bisection")
    args = parser.parse_args()
    snapshot = args.snapshot.resolve()
    manifest = json.loads((snapshot / "manifest.json").read_text())
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    if hashlib.sha256(ram).hexdigest() != manifest["ram_sha256"]:
        raise ValueError("capture checksum mismatch")
    candidates = ownership_candidates(manifest, ram)
    directory = args.directory.resolve()
    if args.plans:
        if args.resume:
            parser.error("explicit-plan batches cannot use --resume")
        directory.mkdir(exist_ok=False)
        results = []
        for index, plan in enumerate(args.plans):
            trial = directory / ("trial_%03d_%s" % (index, plan.stem))
            trial.mkdir()
            print("START", str(plan), flush=True)
            report = attempt(snapshot, trial, plan.resolve())
            results.append(report)
            save(directory / "results.json", results)
            print("RESULT", json.dumps(dict(
                plan=str(plan), passed=report["passed"], report=report["report_file"],
                outputs={name: dict(exact=row["exact"], changed_bytes=row["changed_bytes"])
                         for name, row in report.get("outputs", {}).items()})), flush=True)
        return
    state_path = directory / "bisection.json"
    if args.resume:
        state = json.loads(state_path.read_text())
        if state["ram_sha256"] != manifest["ram_sha256"]:
            raise ValueError("resume identifies another capture")
    else:
        directory.mkdir(exist_ok=False)
        # The all-page upper bound and left-half rejection are already measured.
        # Re-test both halves here so this run is independently reproducible.
        middle = len(candidates) // 2
        state = dict(snapshot=str(snapshot), ram_sha256=manifest["ram_sha256"],
                     candidates=candidates, removed=[], necessary=[], results=[],
                     pending=[list(range(middle, len(candidates))), list(range(middle))])
        save(state_path, state)
    while state["pending"]:
        chunk = state["pending"][0]
        selected = sorted(set(state["removed"] + chunk))
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        trial = directory / ("trial_%03d_%s" % (len(state["results"]), stamp))
        trial.mkdir()
        plan = dict(format=FORMAT, ram_sha256=manifest["ram_sha256"],
                    snapshot=str(snapshot), candidates=candidates,
                    zero_blob_indices=[candidates[index]["blob_index"] for index in selected])
        plan_path = trial / "reduction.json"
        save(plan_path, plan)
        print("START", trial.name, "zero candidate indices", selected, flush=True)
        report = attempt(snapshot, trial, plan_path)
        result = dict(trial=str(trial), selected=selected, chunk=chunk,
                      passed=bool(report["passed"]), report=report["report_file"],
                      outputs={name: dict(exact=row["exact"], changed_bytes=row["changed_bytes"])
                               for name, row in report.get("outputs", {}).items()})
        state["results"].append(result)
        state["pending"].pop(0)
        if result["passed"]:
            state["removed"] = selected
        elif len(chunk) > 1:
            middle = len(chunk) // 2
            state["pending"][:0] = [chunk[:middle], chunk[middle:]]
        else:
            state["necessary"].extend(chunk)
        save(state_path, state)
        print("RESULT", json.dumps(result), flush=True)
    print("COMPLETE", json.dumps(dict(removed=state["removed"],
                                      necessary=state["necessary"])), flush=True)


if __name__ == "__main__":
    main()
