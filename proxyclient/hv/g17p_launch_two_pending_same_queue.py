# SPDX-License-Identifier: MIT
"""Compact single-user launch of two pending partials on one Metal queue."""


command = (
    "D=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -x $D/g17ppartial ]; do sleep 1; done; "
    "for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon "
    "com.apple.opendirectoryd com.apple.coreservicesd "
    "com.apple.runningboardd; do launchctl bootstrap system "
    "/System/Library/LaunchDaemons/$x.plist; done; "
    "launchctl bootstrap system /System/Library/Frameworks/Metal.framework/Versions/A/"
    "XPCServices/MTLCompilerService.xpc; "
    "launchctl submit -l io.asahi.g17p.two-pending -o /dev/console "
    "-e /dev/console -- /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "
    "G17P_ENQUEUE_ALL=1 G17P_COMMAND_QUEUE_COUNT=1 G17P_LOAD_EXISTING=1 "
    "/bin/sh -c '/System/Volumes/Data/Users/Shared/g17ppartial "
    "128 128 accumulate 48217 2; "
    "launchctl remove io.asahi.g17p.two-pending'; "
    "echo G17P_TWO_PENDING_LAUNCH=$?\r"
).encode("ascii")

written = int(p.hv_vuart_inject_at_prompt(command))  # noqa: F821
if written != len(command):
    raise RuntimeError(
        "short same-queue partial prompt queue: %d/%d" %
        (written, len(command))
    )

print(
    "G17P compact same-queue two-pending launch queued for prompt (%d bytes)"
    % written,
    flush=True,
)
