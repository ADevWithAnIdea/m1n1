# SPDX-License-Identifier: MIT
"""Run two native partials to completion, then capture queue A's next one."""


command = (
    "D=/System/Volumes/Data; U=$D/Users/Shared; "
    "P=$D/Library/LaunchDaemons/io.asahi.g17ppartial.plist; "
    "S=/System/Library; L=launchctl; B=/usr/bin/plutil; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -x $U/g17ppartial ]; do sleep 1; done; "
    "rm -f $U/g17ppartial.log; "
    "$B -replace ProgramArguments -json '["
    "\"/System/Volumes/Data/Users/Shared/g17ppartial\","
    "\"128\",\"128\",\"accumulate\","
    "\"48217\",\"3\"]' $P; "
    "$B -replace EnvironmentVariables -json '{"
    "\"G17P_CAPTURE_AFTER\":\"2\","
    "\"G17P_COMMAND_QUEUE_COUNT\":\"2\","
    "\"G17P_ENQUEUE_ALL\":\"1\","
    "\"G17P_ENQUEUE_BATCH_SIZE\":\"2\","
    "\"G17P_SEPARATE_QUEUE_TARGETS\":\"1\","
    "\"G17P_LOAD_EXISTING\":\"1\"}' $P; "
    "for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon "
    "com.apple.opendirectoryd com.apple.coreservicesd; do "
    "$L bootstrap system $S/LaunchDaemons/$x.plist; done; "
    "$L bootstrap system $S/Frameworks/Metal.framework/Versions/A/"
    "XPCServices/MTLCompilerService.xpc; "
    "$L bootstrap system $S/LaunchDaemons/com.apple.runningboardd.plist; "
    "$L kickstart -k system/com.apple.runningboardd; "
    "$L bootstrap system $P\r"
).encode("ascii")

written = int(p.hv_vuart_inject_at_prompt(command))  # noqa: F821
if written != len(command):
    raise RuntimeError(
        "short completed-prefix third-partial prompt queue: %d/%d" %
        (written, len(command))
    )

print(
    "G17P two completed queues then queue-A third launch queued for prompt "
    "(%d bytes)" % written,
    flush=True,
)
