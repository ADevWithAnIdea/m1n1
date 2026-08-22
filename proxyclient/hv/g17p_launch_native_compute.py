# SPDX-License-Identifier: MIT
"""Launch the staged own-source compute client before normal macOS boot."""

import os

from m1n1.proxy import EXC_RET


GUEST_DIR = "/System/Volumes/Data/Users/Shared"
MODE = os.environ.get("G17P_NATIVE_COMPUTE_MODE", "samplerheap")
COUNT = int(os.environ.get("G17P_NATIVE_COMPUTE_COUNT", "1"), 0)

_original_run_shell = hv.run_shell  # noqa: F821
_launched = False


def _launch_run_shell(entry_msg="Entering shell", exit_msg="Continuing"):
    global _launched

    if (
        not _launched
        and getattr(hv, "_timeout_shell_fired", False)  # noqa: F821
        and entry_msg == "Entering hypervisor shell"
    ):
        command = (
            "/sbin/mount -P 1; "
            "/usr/libexec/init_data_protection; "
            "/sbin/mount -P 2 >/dev/null 2>&1 & "
            "n=0; while [ $n -lt 90 ] && "
            f"[ ! -x {GUEST_DIR}/g17pcmp ]; do sleep 2; n=$((n+1)); done; "
            f"cd {GUEST_DIR}; : > g17pcmp.log; "
            "(while :; do "
            "rm -f g17pcmp.status; "
            f"(./g17pcmp {COUNT} sequential hold {MODE}; "
            "echo $? >g17pcmp.status) 2>&1 | "
            "/usr/bin/tee -a g17pcmp.log; "
            "[ -f g17pcmp.status ] && "
            "[ \"$(cat g17pcmp.status)\" -eq 0 ] && break; "
            "sleep 1; done) & "
            "echo G17P_NATIVE_COMPUTE_DIRECT_LAUNCHED; exit\r"
        ).encode("ascii")
        written = int(p.hv_vuart_inject(command))  # noqa: F821
        if written != len(command):
            raise RuntimeError(
                "short native-compute launch injection: %d/%d" %
                (written, len(command))
            )
        _launched = True
        hv._timeout_shell_fired = False  # noqa: F821
        print(
            "G17P direct native compute launcher queued: "
            f"count={COUNT} mode={MODE}",
            flush=True,
        )
        return EXC_RET.HANDLED

    return _original_run_shell(entry_msg, exit_msg)


hv.run_shell = _launch_run_shell  # noqa: F821
print("G17P direct native compute launcher armed", flush=True)
