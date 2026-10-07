# SPDX-License-Identifier: MIT
"""Launch one minimal partial-render witness in a clean single-user guest."""

if int(hv.adt["/chosen"].chip_id) != 0x8140:  # noqa: F821
    raise RuntimeError("the single-partial witness requires T8140")
if "-s" not in hv.tba.cmdline.split():  # noqa: F821
    raise RuntimeError("the single-partial witness requires single-user -s")

# Use the already-staged own-source workload. A transient launchctl job avoids
# the persistent plist's multi-queue parameters and DYLD interposer settings.
# 48,217 triangles is the established smallest partial-triggering workload.
command = (
    "(D=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -x $D/g17ppartial ]; do sleep 1; done; "
    "if /bin/ps -axo comm | /usr/bin/grep -Eq "
    "'(^|/)(WindowServer|g17ppartial|g17prender|g17pcompute)$'; then "
    "echo G17P_SINGLE_PARTIAL_REJECT_UNRELATED_GPU_CLIENT; exit 1; fi; "
    "for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon "
    "com.apple.opendirectoryd com.apple.coreservicesd "
    "com.apple.runningboardd; do "
    "launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist; "
    "echo G17P_BOOTSTRAP_$x=$?; done; "
    "launchctl bootstrap system /System/Library/Frameworks/Metal.framework/"
    "Versions/A/XPCServices/MTLCompilerService.xpc; "
    "echo G17P_BOOTSTRAP_COMPILER=$?; "
    "launchctl submit -l io.asahi.g17p.capture-smoke "
    "-o /dev/console -e /dev/console -- "
    "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "
    "$D/g17ppartial 128 128 accumulate 48217 1; "
    "echo G17P_SINGLE_PARTIAL_LAUNCH=$?)\r"
).encode("ascii")

written = int(p.hv_vuart_inject_at_prompt(command))  # noqa: F821
if written != len(command):
    raise RuntimeError(
        "short single-partial prompt injection: %d/%d" % (written, len(command))
    )
print("G17P single-user one-command partial witness queued", flush=True)
