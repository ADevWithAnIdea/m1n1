# SPDX-License-Identifier: MIT
"""Stage and launch the smallest native compute/render fence witness."""

import base64
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile


if int(hv.adt["/chosen"].chip_id) != 0x8140 or "-s" not in hv.tba.cmdline.split():  # noqa: F821
    raise RuntimeError("native barrier witness requires T8140 single-user -s")

assets = {
    "g17pbarrier": Path("build/g17p_native_barriers").read_bytes(),
    "g17pbarrier.metal": Path(
        "proxyclient/experiments/g17p_native_barriers.metal").read_bytes(),
}
digests = {name: hashlib.sha256(body).hexdigest()
           for name, body in assets.items()}
name = "g17pbarrier"
mode = os.environ.get("G17P_NATIVE_BARRIER_MODE", "shared-event")
if mode not in ("shared-event", "fences", "gpu-event", "gpu-event-reverse"):
    raise ValueError("unknown native barrier mode: " + mode)
workload_args = "" if mode == "shared-event" else " --" + mode
guest_dir = "/System/Volumes/Data/Users/Shared/" + name

archive_buffer = io.BytesIO()
with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
    for filename, body in assets.items():
        entry = tarfile.TarInfo(name + "/" + filename)
        entry.size = len(body)
        entry.mode = 0o755 if filename == "g17pbarrier" else 0o644
        entry.mtime = 0
        archive.addfile(entry, io.BytesIO(body))
encoded = base64.b64encode(
    gzip.compress(archive_buffer.getvalue(), mtime=0)).decode("ascii")

commands = [
    "set -e; U=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -d $U ]; do sleep 1; done; "
    "S=$(/usr/bin/mktemp -d /tmp/g17p-barrier.XXXXXX); B=$S/payload.b64",
]
if os.environ.get("G17P_NATIVE_BARRIER_REUSE") != "1":
    commands.extend(
        "printf %s '" + encoded[offset:offset + 384] + "' >> $B"
        for offset in range(0, len(encoded), 384))
    commands.append(
        "set -o pipefail; /usr/bin/base64 -D < $B | /usr/bin/gzip -dc | "
        "/usr/bin/tar -xf - -C $U")
for filename, digest in digests.items():
    commands.append(
        f"printf '%s  %s\\n' {digest} $U/{name}/{filename} | "
        "/usr/bin/shasum -a 256 -c")
for service in (
        "com.apple.notifyd", "com.apple.cfprefsd.xpc.daemon",
        "com.apple.opendirectoryd", "com.apple.coreservicesd",
        "com.apple.runningboardd"):
    commands.append(
        "launchctl bootstrap system /System/Library/LaunchDaemons/"
        f"{service}.plist || true")
commands.append(
    "launchctl bootstrap system /System/Library/Frameworks/Metal.framework/"
    "Versions/A/XPCServices/MTLCompilerService.xpc || true")
# Keep the marker split in the shell source.  The hypervisor VUART scanner sees
# echoed input as well as command output; spelling the marker literally here
# advances the injector before the command has completed and corrupts the next
# line.  Adjacent shell quotes concatenate to the intended output marker only.
commands = [(command + "; echo G17P_PARTIAL_ARM'_'CAPTURE\r").encode("ascii")
            for command in commands]
if any(len(command) >= 448 for command in commands):
    raise RuntimeError("native barrier staging line exceeds VUART bound")

previous_marker_handler = hv._vuart_marker_handler  # noqa: F821
cursor = 1


def advance_barrier_stage():
    global cursor
    if cursor == len(commands):
        hv._vuart_marker_handler = previous_marker_handler  # noqa: F821
        if callable(previous_marker_handler):
            previous_marker_handler()
        launch = (
            "launchctl submit -l io.asahi.g17p.barrier -o /dev/console "
            "-e /dev/console -- /usr/bin/env -i "
            f"PATH=/usr/bin:/bin:/usr/sbin:/sbin {guest_dir}/g17pbarrier{workload_args}\r"
        ).encode("ascii")
        if len(launch) >= 448:
            raise RuntimeError("native barrier launch line exceeds VUART bound")
        command = launch
        hv._g17p_barrier_staged = dict(  # noqa: F821
            directory=guest_dir, sha256=digests)
        print("G17P native barrier witness staged:",
              hv._g17p_barrier_staged, flush=True)  # noqa: F821
    else:
        command = commands[cursor]
        cursor += 1
        if cursor % 25 == 0:
            print("G17P native barrier staging %d/%d" %
                  (cursor, len(commands)), flush=True)
    if int(p.hv_vuart_inject(command)) != len(command):  # noqa: F821
        raise RuntimeError("short native barrier staging injection")


hv._vuart_marker_handler = advance_barrier_stage  # noqa: F821
if int(p.hv_vuart_inject_at_prompt(commands[0])) != len(commands[0]):  # noqa: F821
    raise RuntimeError("short native barrier prompt injection")
print("G17P native barrier staging queued:", len(commands), flush=True)
