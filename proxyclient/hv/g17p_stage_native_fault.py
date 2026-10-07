# SPDX-License-Identifier: MIT
"""Stage the own-source compute client and observe native fault/close handling."""
import base64
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile

if int(hv.adt["/chosen"].chip_id) != 0x8140 or "-s" not in hv.tba.cmdline.split():  # noqa: F821
    raise RuntimeError("native fault witness requires T8140 single-user -s")
dispatches = int(os.environ.get("G17P_NATIVE_COMPUTE_COUNT", "2"))
if dispatches not in (1, 2, 3):
    raise ValueError("native lifecycle witness accepts one to three commands")
assets = {"g17pcmp": Path("build/g17p_native_compute").read_bytes(),
          "g17pcmp.metallib": Path("build/g17p_native_compute.metallib").read_bytes()}
digests = {name: hashlib.sha256(body).hexdigest() for name, body in assets.items()}
archive_buffer = io.BytesIO()
with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
    for name, body in assets.items():
        entry = tarfile.TarInfo(name)
        entry.size = len(body)
        entry.mode = 0o755 if name == "g17pcmp" else 0o644
        entry.mtime = 0
        archive.addfile(entry, io.BytesIO(body))
encoded = base64.b64encode(gzip.compress(archive_buffer.getvalue(), mtime=0)).decode("ascii")
commands = [
    "set -e; U=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -d $U ]; do sleep 1; done; "
    "S=$(/usr/bin/mktemp -d /tmp/g17p-fault.XXXXXX); B=$S/payload.b64"]
if os.environ.get("G17P_NATIVE_FAULT_REUSE") != "1":
    commands.extend("printf %s '" + encoded[offset:offset + 384] + "' >> $B"
                    for offset in range(0, len(encoded), 384))
    commands.append("set -o pipefail; /usr/bin/base64 -D < $B | /usr/bin/gzip -dc | "
                    "/usr/bin/tar -xf - -C $U")
for name, digest in digests.items():
    # A native checksum tool avoids starting Perl and loading its dependency
    # tree during single-user boot. SHA256 remains in the host manifest.
    md5 = hashlib.md5(assets[name]).hexdigest()
    commands.append(f"test \"$(/sbin/md5 -q $U/{name})\" = {md5}")
commands.append("/bin/sync")
for service in ("com.apple.notifyd", "com.apple.cfprefsd.xpc.daemon",
                "com.apple.opendirectoryd", "com.apple.coreservicesd", "com.apple.runningboardd"):
    commands.append("launchctl bootstrap system /System/Library/LaunchDaemons/"
                    f"{service}.plist || true")
commands.append("launchctl bootstrap system /System/Library/Frameworks/Metal.framework/"
                "Versions/A/XPCServices/MTLCompilerService.xpc || true")
commands = [(line + "; echo G17P_PARTIAL_ARM'_'CAPTURE\r").encode("ascii") for line in commands]
if any(len(line) >= 448 for line in commands):
    raise RuntimeError("native fault staging line exceeds VUART limit")
previous_marker = getattr(hv, "_vuart_marker_handler", None)  # noqa: F821
cursor = 1


def advance_fault_stage():
    global cursor
    if cursor == len(commands):
        hv._vuart_marker_handler = previous_marker  # noqa: F821
        if callable(previous_marker):
            previous_marker()
        line = ("launchctl submit -l io.asahi.g17p.fault -o /dev/console -e /dev/console "
                "-- /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "
                f"/bin/sh -c '/System/Volumes/Data/Users/Shared/g17pcmp {dispatches} sequential; "
                "rc=$?; echo G17P_NATIVE_CLIENT_EXIT_$rc; "
                "echo G17P_PARTIAL_ARM\"_\"CAPTURE; "
                "launchctl remove io.asahi.g17p.fault; exit $rc'\r").encode("ascii")
        if len(line) >= 448:
            raise RuntimeError("native one-shot launch line exceeds VUART bound")
        print("Native fault witness staged:", digests, flush=True)
    else:
        line = commands[cursor]
        cursor += 1
        if cursor % 25 == 0:
            print("Native fault staging %d/%d" % (cursor, len(commands)), flush=True)
    if int(p.hv_vuart_inject(line)) != len(line):  # noqa: F821
        raise RuntimeError("short native fault staging injection")


hv._vuart_marker_handler = advance_fault_stage  # noqa: F821
if int(p.hv_vuart_inject_at_prompt(commands[0])) != len(commands[0]):  # noqa: F821
    raise RuntimeError("short native fault prompt injection")
print("Native fault staging queued:", len(commands), flush=True)
