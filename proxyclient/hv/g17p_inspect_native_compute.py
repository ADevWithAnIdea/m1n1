# SPDX-License-Identifier: MIT
"""Read back the staged G17P one-shot workload state from single-user macOS."""

import os
import threading

from m1n1.proxy import EXC_RET


_original_run_shell = hv.run_shell  # noqa: F821
_state = "waiting"
_scheduled_interrupt = False
_inspect_due = False
_inspect_delay = float(os.environ.get("G17P_INSPECT_DELAY", "100"))
_truncate_log = os.environ.get("G17P_INSPECT_TRUNCATE_LOG", "0") == "1"


def _schedule_interrupt(delay):
    def worker():
        global _scheduled_interrupt
        _scheduled_interrupt = True
        device = os.environ["M1N1DEVICE"].split(":", 1)[0]
        fd = os.open(device, os.O_WRONLY | os.O_NOCTTY)
        try:
            os.write(fd, b"!")
        finally:
            os.close(fd)

    threading.Timer(delay, worker).start()


def _request_inspect():
    global _inspect_due
    _inspect_due = True
    hv.interrupt()  # noqa: F821


def _inspect_run_shell(entry_msg="Entering shell", exit_msg="Continuing"):
    global _scheduled_interrupt, _state

    if (
        _state == "waiting"
        and getattr(hv, "_timeout_shell_fired", False)  # noqa: F821
        and entry_msg == "Entering hypervisor shell"
    ):
        if not _inspect_due:
            print("G17P ignoring generic timeout before inspection delay")
            return EXC_RET.HANDLED
        truncate = (
            ": > Users/Shared/g17pcmp.log; "
            "echo G17P_INSPECT_LOG_TRUNCATED; "
            if _truncate_log else ""
        )
        command = (
            "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
            "/sbin/mount -P 2 >/dev/null 2>&1; "
            "cd /System/Volumes/Data; "
            f"{truncate}"
            "echo G17P_INSPECT_BEGIN; "
            "/bin/ls -l Library/LaunchDaemons/io.asahi.g17pcompute.plist "
            "Users/Shared/g17pcmp* 2>&1; "
            "echo G17P_INSPECT_PLIST; "
            "/bin/cat Library/LaunchDaemons/io.asahi.g17pcompute.plist 2>&1; "
            "echo G17P_INSPECT_LOG; "
            "/bin/cat Users/Shared/g17pcmp.log 2>&1; "
            "echo G17P_INSPECT_END\r"
        ).encode("ascii")
        written = int(p.hv_vuart_inject(command))  # noqa: F821
        if written != len(command):
            raise RuntimeError(f"short VUART injection: {written}/{len(command)}")
        _state = "inspect"
        _schedule_interrupt(20)
        return EXC_RET.HANDLED

    if (
        _state == "inspect"
        and _scheduled_interrupt
        and entry_msg == "Entering hypervisor shell"
    ):
        print("G17P staged workload inspection complete")
        return EXC_RET.EXIT_GUEST

    return _original_run_shell(entry_msg, exit_msg)


hv.run_shell = _inspect_run_shell  # noqa: F821
threading.Timer(_inspect_delay, _request_inspect).start()
print("G17P staged workload inspection armed after %.1fs" % _inspect_delay)
