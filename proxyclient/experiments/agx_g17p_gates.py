#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run every G17P gate that needs no hardware, and say which need a target or a capture.

The gates accumulated one at a time, each written for the question in front of it, and there has
been no way to run them as a set. That matters more here than usual: this project's recurring
failure is a check whose scope is narrower than the claim drawn from it, and the gates are what
catch that. A net nobody runs is not a net.

Offline gates run here. Gates that need a live target are listed and skipped rather than silently
omitted, because a runner that quietly covers less than it appears to would be the same failure
again.
"""
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CAPTURES = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")

# Gates that run with no hardware and no arguments.
STANDALONE = [
    ("shim backend", "agx_g17p_validate_shim.py", []),
    ("tiler encoder", "agx_g17p_validate_encoder.py", []),
    ("queue builder", "agx_g17p_validate_queue.py", []),
    ("paired builder", "agx_g17p_validate_paired_builder.py", []),
    ("render recipe", "agx_g17p_validate_render_recipe.py", []),
    ("per-context aliases", "agx_g17p_validate_contexts.py", []),
]

# The third element is the glob, and the fourth says the gate needs both channel halves.
NEEDS_CAPTURE = [
    ("index family", "agx_g17p_validate_strides.py", "live_submission_targeted_*", False),
    ("capture halves", "agx_g17p_check_capture_halves.py", "live_submission_targeted_*", True),
    ("pending items", "agx_g17p_check_pending_items.py", "live_submission_targeted_*", True),
    ("dangling references", "agx_g17p_check_dangling.py", None, True),
]

# Gates that talk to a live target, listed so their absence from a green run is visible.
NEEDS_TARGET = [
    ("handoff", "agx_g17p_validate_handoff.py"),
    ("submission model", "agx_g17p_validate_submission.py"),
    ("multi-item model", "agx_g17p_validate_multi_item.py"),
    ("layout", "agx_g17p_validate_layout.py"),
]


def newest(pattern, both_halves=False):
    """The newest capture matching the pattern, optionally one holding both channel halves.

    Single-channel captures are common, and two of the gates need a tiling half and a fragment
    half. Handing them the newest capture regardless made the suite fail on a capture that was
    never meant for them, which is worse than not running: a runner that cries wolf gets ignored,
    and this suite exists to be trusted.
    """
    matches = sorted(CAPTURES.glob(pattern), key=lambda p: p.name)
    if both_halves:
        matches = [m for m in matches
                   if (m / "TA_0" / "target.json").exists()
                   and (m / "3D_0" / "target.json").exists()]
    return matches[-1] if matches else None


def run(label, script, args):
    path = HERE / script
    if not path.exists():
        print("  %-22s MISSING %s" % (label, script))
        return False
    result = subprocess.run(
        [sys.executable, str(path)] + [str(a) for a in args],
        cwd=ROOT, capture_output=True, text=True)
    ok = result.returncode == 0
    print("  %-22s %s" % (label, "pass" if ok else "FAIL (exit %d)" % result.returncode))
    if not ok:
        tail = (result.stdout + result.stderr).strip().splitlines()[-6:]
        for line in tail:
            print("      %s" % line[:110])
    return ok


def main():
    failures = 0
    ran = 0

    print("offline gates")
    for label, script, args in STANDALONE:
        ran += 1
        if not run(label, script, args):
            failures += 1

    any_capture = newest("live_submission_targeted_*")
    paired = newest("live_submission_targeted_*", both_halves=True)
    snapshot = newest("pre_work_*")
    for label, script, pattern, needs_pair in NEEDS_CAPTURE:
        chosen = paired if needs_pair else any_capture
        if chosen is None:
            print("  %-22s skipped, no %s capture on disk"
                  % (label, "two-channel" if needs_pair else "targeted"))
            continue
        if pattern is None:
            if snapshot is None:
                print("  %-22s skipped, needs a snapshot" % label)
                continue
            args = [snapshot, chosen]
        else:
            args = [chosen]
        ran += 1
        if not run(label, script, args):
            failures += 1

    print("\ngates that need a live target, not run here:")
    for label, script in NEEDS_TARGET:
        exists = "" if (HERE / script).exists() else "  (missing)"
        print("  %-22s %s%s" % (label, script, exists))

    print("\n%d offline gates ran, %d failed" % (ran, failures))
    if any_capture:
        print("capture used:  %s" % any_capture.name)
    if paired and paired is not any_capture:
        print("two-channel:   %s" % paired.name)
    if snapshot:
        print("snapshot used: %s" % snapshot.name)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
