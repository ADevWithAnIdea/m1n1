# SPDX-License-Identifier: MIT
"""Launch the staged render witness directly from a single-user guest shell."""

from m1n1.proxy import EXC_RET


GUEST_DIR = "/System/Volumes/Data/Users/Shared"

original_run_shell = hv.run_shell  # noqa: F821
launched = False


def direct_render_run_shell(entry_msg="Entering shell", exit_msg="Continuing"):
    global launched

    timed_stop = (
        not launched
        and getattr(hv, "_timeout_shell_fired", False)  # noqa: F821
        and entry_msg in ("Entering shell", "Entering hypervisor shell")
    )
    if not timed_stop:
        return original_run_shell(entry_msg, exit_msg)

    command = (
        "D=/System/Volumes/Data/Users/Shared; "
        "L=/System/Volumes/Data/Library/LaunchDaemons; "
        "launchctl bootout system/io.asahi.g17prender >/dev/null 2>&1; "
        "launchctl bootstrap system $L/io.asahi.g17prender.plist; "
        "echo G17P_BOOTSTRAP=$?; "
        "launchctl kickstart -k system/io.asahi.g17prender; "
        "echo G17P_KICK=$?; sleep 3; "
        "tail -80 $D/g17prender.log; echo G17P_RENDER_LAUNCH_DONE\r"
    ).encode("ascii")
    written = int(p.hv_vuart_inject(command))  # noqa: F821
    if written != len(command):
        raise RuntimeError(
            "short native-render launch injection: %d/%d" %
            (written, len(command))
        )
    launched = True
    print("G17P direct native render launch queued", flush=True)
    return EXC_RET.HANDLED


hv.run_shell = direct_render_run_shell  # noqa: F821
print("G17P direct native render launcher armed", flush=True)
