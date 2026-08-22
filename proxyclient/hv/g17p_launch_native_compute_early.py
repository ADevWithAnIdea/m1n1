# SPDX-License-Identifier: MIT
"""Launch the staged native compute client early enough for a bounded trace."""

import os
import threading

from m1n1.proxy import EXC_RET


DELAY = float(os.environ.get("G17P_NATIVE_EARLY_DELAY", "45"))
COUNT = int(os.environ.get("G17P_NATIVE_EARLY_COUNT", "300"), 0)
PAUSE_BEFORE = os.environ.get("G17P_NATIVE_EARLY_PAUSE_BEFORE")
GUEST_DATA = "/System/Volumes/Data"
GUEST_EXECUTABLE = GUEST_DATA + "/Users/Shared/g17pcmp"
GUEST_LOG = GUEST_DATA + "/Users/Shared/g17pcmp.log"

_original_run_shell = hv.run_shell  # noqa: F821
_launch_due = False
_launched = False


def request_launch():
    global _launch_due
    _launch_due = True
    hv.interrupt()  # noqa: F821


def launch_run_shell(entry_msg="Entering shell", exit_msg="Continuing"):
    global _launched
    if _launch_due and not _launched and entry_msg == "Entering hypervisor shell":
        arguments = str(COUNT)
        if PAUSE_BEFORE is not None:
            arguments += " " + str(int(PAUSE_BEFORE, 0))
        if PAUSE_BEFORE is None:
            body = (
                f"{GUEST_EXECUTABLE} {arguments} >{GUEST_LOG} 2>&1"
            )
        else:
            body = (
                f"{GUEST_EXECUTABLE} {arguments} >{GUEST_LOG} 2>&1 & "
                "pid=$!; while ! /usr/bin/grep -q "
                f"G17P_COMPUTE_PAUSED_BEFORE {GUEST_LOG}; do sleep 1; done; "
                "echo G17P_NATIVE_EARLY_PAUSED pid=$pid"
            )
        command = (
            f"(while [ ! -x {GUEST_EXECUTABLE} ]; do sleep 1; done; "
            f"/bin/rm -f {GUEST_LOG}; {body}) & "
            "echo G17P_NATIVE_EARLY_LAUNCHED\r"
        ).encode("ascii")
        written = int(p.hv_vuart_inject(command))  # noqa: F821
        if written != len(command):
            raise RuntimeError(
                "short native-compute launch injection: %d/%d"
                % (written, len(command)))
        _launched = True
        print(
            "G17P native compute early launch queued after %.1fs: "
            "count=%d pause_before=%s"
            % (DELAY, COUNT, PAUSE_BEFORE),
            flush=True,
        )
        return EXC_RET.HANDLED
    return _original_run_shell(entry_msg, exit_msg)


hv.run_shell = launch_run_shell  # noqa: F821
threading.Timer(DELAY, request_launch).start()
print(
    "G17P native compute early launch armed: delay=%.1fs count=%d"
    % (DELAY, COUNT),
    flush=True,
)
