# SPDX-License-Identifier: MIT
"""Replace the boot-time partial job with the staged native render job."""

from m1n1.proxy import EXC_RET

original_run_shell = hv.run_shell  # noqa: F821
done = False


def run_shell(entry_msg="Entering shell", exit_msg="Continuing"):
    global done
    if not done and entry_msg == "Entering hypervisor shell":
        command = ("cp /System/Volumes/Data/Users/Shared/io.asahi.g17prender.plist "
                   "/System/Volumes/Data/Library/LaunchDaemons/io.asahi.g17ppartial.plist; "
                   "echo G17P_DIRECT_PLIST_COPY=$?\r").encode("ascii")
        written = int(p.hv_vuart_inject(command))  # noqa: F821
        if written != len(command):
            raise RuntimeError("short direct plist copy")
        done = True
        return EXC_RET.HANDLED
    return original_run_shell(entry_msg, exit_msg)


hv.run_shell = run_shell  # noqa: F821
print("G17P direct plist copy armed", flush=True)
