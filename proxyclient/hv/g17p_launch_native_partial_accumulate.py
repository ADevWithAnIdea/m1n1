# SPDX-License-Identifier: MIT
"""Prequeue the single-user launch without stopping the running guest."""


command = (
    "D=/System/Volumes/Data/Users/Shared; "
    "C=/System/Library/Frameworks/Metal.framework/Versions/A/"
    "XPCServices/MTLCompilerService.xpc; "
    "R=/System/Library/LaunchDaemons/com.apple.runningboardd.plist; "
    "P=/System/Volumes/Data/Library/LaunchDaemons/"
    "io.asahi.g17ppartial.plist; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -x $D/g17ppartial ]; do sleep 1; done; "
    "launchctl bootout system/io.asahi.g17ppartial 2>/dev/null; "
    "killall -9 g17ppartial 2>/dev/null; "
    # The prior clean single-user run eliminated the compiler's notification,
    # preferences, and directory lookups.  runningboardd's one remaining
    # functional lookup was coreservicesd; add precisely that daemon without
    # starting loginwindow, WindowServer, or a GUI launchd domain.
    "for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon "
    "com.apple.opendirectoryd com.apple.coreservicesd; do "
    "launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist; "
    "echo G17P_BOOTSTRAP_$x=$?; done; "
    "launchctl bootstrap system $C; c=$?; "
    "launchctl bootstrap system $R; r=$?; "
    "launchctl kickstart -k system/com.apple.runningboardd; k=$?; "
    "launchctl bootstrap system $P; q=$?; "
    "echo G17P_MINIMAL_SERVICES compiler=$c runningboard=$r "
    "kickstart=$k partial=$q\r"
).encode("ascii")

written = int(p.hv_vuart_inject_at_prompt(command))  # noqa: F821
if written != len(command):
    raise RuntimeError(
        f"short partial-accumulate prompt queue: {written}/{len(command)}"
    )

print(
    "G17P native partial accumulation launch queued for prompt (%d bytes)"
    % written,
    flush=True,
)
