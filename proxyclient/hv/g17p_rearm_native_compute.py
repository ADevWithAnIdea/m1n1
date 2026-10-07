# SPDX-License-Identifier: MIT
"""Reinstall only the staged G17P compute LaunchDaemon plist."""

import base64
from pathlib import Path
import threading

from m1n1.proxy import EXC_RET


GUEST_DATA = "/System/Volumes/Data"
GUEST_TEMP = GUEST_DATA + "/Users/Shared/.g17pcmp.plist.b64"
GUEST_PLIST = GUEST_DATA + "/Library/LaunchDaemons/io.asahi.g17pcompute.plist"
encoded = base64.b64encode(
    Path("proxyclient/experiments/io.asahi.g17pcompute.plist").read_bytes()
).decode("ascii")
chunks = [encoded[offset:offset + 320] for offset in range(0, len(encoded), 320)]

_original_run_shell = hv.run_shell  # noqa: F821
_state = "waiting"
_chunk_index = 0
_scheduled_interrupt = False
_cancel = threading.Event()


def _inject(command):
    written = int(p.hv_vuart_inject(command))  # noqa: F821
    if written != len(command):
        raise RuntimeError(f"short VUART injection: {written}/{len(command)}")


def _schedule_interrupt(delay):
    def worker():
        global _scheduled_interrupt
        if _cancel.wait(delay):
            return
        _scheduled_interrupt = True
        hv.interrupt()  # noqa: F821

    threading.Thread(target=worker, daemon=True).start()


def _rearm_run_shell(entry_msg="Entering shell", exit_msg="Continuing"):
    global _chunk_index, _scheduled_interrupt, _state

    if (
        _state == "waiting"
        and getattr(hv, "_timeout_shell_fired", False)  # noqa: F821
        and entry_msg == "Entering hypervisor shell"
    ):
        _inject((
            "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
            "/sbin/mount -P 2 >/dev/null 2>&1; "
            f"/bin/mkdir -p {GUEST_DATA}/Library/LaunchDaemons; "
            f"rm -f {GUEST_TEMP}; echo G17P_REARM_READY\r"
        ).encode("ascii"))
        _state = "chunks"
        _schedule_interrupt(65)
        return EXC_RET.HANDLED

    if (
        _state in ("chunks", "final", "verify")
        and entry_msg == "Entering hypervisor shell"
    ):
        if not _scheduled_interrupt:
            _cancel.set()
            return EXC_RET.EXIT_GUEST
        _scheduled_interrupt = False

        if _state == "chunks":
            _inject((
                f"printf '%s' '{chunks[_chunk_index]}' >> {GUEST_TEMP}; "
                f"echo G17P_REARM_CHUNK={_chunk_index + 1}/{len(chunks)}\r"
            ).encode("ascii"))
            _chunk_index += 1
            if _chunk_index == len(chunks):
                _state = "final"
            _schedule_interrupt(1)
            return EXC_RET.HANDLED

        if _state == "final":
            _inject((
                f"/usr/bin/base64 -D < {GUEST_TEMP} > {GUEST_PLIST}; "
                f"/bin/chmod 644 {GUEST_PLIST}; rm -f {GUEST_TEMP}; "
                f"/bin/ls -l {GUEST_PLIST}; /bin/sync; "
                "echo G17P_REARM_COMPLETE\r"
            ).encode("ascii"))
            _state = "verify"
            _schedule_interrupt(8)
            return EXC_RET.HANDLED

        _cancel.set()
        print("G17P compute LaunchDaemon rearmed")
        return EXC_RET.EXIT_GUEST

    return _original_run_shell(entry_msg, exit_msg)


hv.run_shell = _rearm_run_shell  # noqa: F821
print(f"G17P compute LaunchDaemon rearm armed ({len(chunks)} chunks)")
