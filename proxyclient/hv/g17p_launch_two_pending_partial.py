# SPDX-License-Identifier: MIT
"""Launch the installed workload as two pending partial-render owners."""


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
    "/usr/bin/plutil -replace ProgramArguments.5 -string 2 $P; "
    "/usr/bin/plutil -remove "
    "EnvironmentVariables.G17P_WARMUP_FIRST_QUEUE $P 2>/dev/null; "
    "/usr/bin/plutil -remove EnvironmentVariables.G17P_ENQUEUE_ALL $P "
    "2>/dev/null; /usr/bin/plutil -insert "
    "EnvironmentVariables.G17P_ENQUEUE_ALL -string 1 $P; "
    "/usr/bin/plutil -remove EnvironmentVariables.G17P_LOAD_EXISTING $P "
    "2>/dev/null; /usr/bin/plutil -insert "
    "EnvironmentVariables.G17P_LOAD_EXISTING -string 1 $P; "
    "/usr/bin/plutil -replace "
    "EnvironmentVariables.G17P_COMMAND_QUEUE_COUNT -string 2 $P; "
    "/usr/bin/plutil -replace "
    "EnvironmentVariables.G17P_ARM_CAPTURE_BEFORE_FIRST_COMMIT -string 1 $P; "
    "for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon "
    "com.apple.opendirectoryd com.apple.coreservicesd; do "
    "launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist; "
    "echo G17P_BOOTSTRAP_$x=$?; done; "
    "launchctl bootstrap system $C; c=$?; "
    "launchctl bootstrap system $R; r=$?; "
    "launchctl kickstart -k system/com.apple.runningboardd; k=$?; "
    "launchctl bootstrap system $P; q=$?; "
    "echo G17P_TWO_PENDING_SERVICES compiler=$c runningboard=$r "
    "kickstart=$k partial=$q\r"
).encode("ascii")

written = int(p.hv_vuart_inject_at_prompt(command))  # noqa: F821
if written != len(command):
    raise RuntimeError(
        "short two-pending partial prompt queue: %d/%d" %
        (written, len(command))
    )

print(
    "G17P two-pending native partial launch queued for prompt (%d bytes)"
    % written,
    flush=True,
)
