# SPDX-License-Identifier: MIT
"""Hash-stage only our memoryless witness, then launch it in single-user XNU."""
import base64
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile

if int(hv.adt["/chosen"].chip_id) != 0x8140 or "-s" not in hv.tba.cmdline.split():
    raise RuntimeError("memoryless witness requires T8140 single-user -s")
count = int(os.environ.get("G17P_GROWTH_TRIANGLES", "500000"))
mode = os.environ.get("G17P_GROWTH_MODE", "memoryless")
allow_limit = os.environ.get("G17P_GROWTH_ALLOW_LIMIT", "0") == "1"
owners = os.environ.get("G17P_GROWTH_OWNERS", "0") == "1"
both = os.environ.get("G17P_GROWTH_BOTH", "0") == "1"
if both and not owners:
    raise ValueError("two pressure pools require the two-owner witness")
if not 1 <= count <= 75000000 or mode not in ("memoryless", "stored"):
    raise ValueError("invalid bounded native growth workload")
if owners and (count > 1000000 or mode != "memoryless" or allow_limit):
    raise ValueError("two-owner witness requires bounded memoryless draws")
assets = {
    "workload": Path("build/g17p-native-growth-owners" if owners else
                     "build/g17p-native-memoryless").read_bytes(),
    "shader.metal": Path("proxyclient/experiments/g17p_native_memoryless.metal").read_bytes(),
    "run.sh": b'''#!/bin/sh
set -e
D=$1
if /bin/ps -axo comm | /usr/bin/grep -Eq '(^|/)(WindowServer|g17ppartial.*|g17prender|g17pcompute|workload)$'; then
    echo NEO_GROWTH_ERROR_UNRELATED_CLIENT
    exit 1
fi
for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon com.apple.opendirectoryd com.apple.coreservicesd com.apple.runningboardd; do
    launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist || true
done
launchctl bootstrap system /System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc || true
launchctl submit -l io.asahi.g17p.memoryless -o /dev/console -e /dev/console -- /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh -c '"$1/workload" "$1/shader.metal" "$2" "$3" ${4:+"$4"}; rc=$?; echo NEO_GROWTH_CLIENT_EXIT_$rc; launchctl remove io.asahi.g17p.memoryless; exit $rc' growth "$D" "$2" "$3" ${4:+"$4"}
''',
}
digests = {name: hashlib.sha256(body).hexdigest() for name, body in assets.items()}
name = "g17p-memoryless-" + hashlib.sha256("".join(digests.values()).encode()).hexdigest()[:16]
guest_dir = "/System/Volumes/Data/Users/Shared/" + name
archive_buffer = io.BytesIO()
with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
    for filename, body in assets.items():
        entry = tarfile.TarInfo(name + "/" + filename)
        entry.size, entry.mode, entry.mtime = len(body), 0o755 if filename == "workload" else 0o644, 0
        archive.addfile(entry, io.BytesIO(body))
encoded = base64.b64encode(gzip.compress(archive_buffer.getvalue(), mtime=0)).decode("ascii")
commands = [
    "set -e; U=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -d $U ]; do sleep 1; done; "
    "S=$(/usr/bin/mktemp -d /tmp/g17p-memoryless.XXXXXX); B=$S/payload.b64",
]
commands.extend("printf %s '" + encoded[offset:offset + 384] + "' >> $B"
                for offset in range(0, len(encoded), 384))
commands.append(f"set -o pipefail; if [ ! -e $U/{name} ]; then "
    "/usr/bin/base64 -D < $B | /usr/bin/gzip -dc | /usr/bin/tar -xf - -C $U; fi")
for filename, body in assets.items():
    digest = hashlib.md5(body).hexdigest()
    commands.append(f'test "$(/sbin/md5 -q $U/{name}/{filename})" = {digest}')
commands.append("/bin/sync")
commands = [(command + "; echo G17P_PARTIAL_ARM'_'CAPTURE\r").encode("ascii") for command in commands]
if any(len(command) >= 448 for command in commands):
    raise RuntimeError("staging line exceeds VUART bound")
previous_marker_handler = hv._vuart_marker_handler
cursor = 1

def advance_memoryless_stage():
    global cursor
    if cursor == len(commands):
        hv._vuart_marker_handler = previous_marker_handler
        suffix = " allow-limit" if allow_limit else ""
        workload_mode = "memoryless-both" if both else mode
        command = f"/bin/sh {guest_dir}/run.sh {guest_dir} {count} {workload_mode}{suffix}\r".encode("ascii")
        hv._g17p_memoryless_staged = dict(directory=guest_dir, sha256=digests,
                                           allow_limit=allow_limit, owners=owners, both=both)
        print("NEO memoryless staged:", hv._g17p_memoryless_staged, flush=True)
    else:
        command = commands[cursor]
        cursor += 1
        if cursor % 25 == 0:
            print("NEO memoryless staging %d/%d" % (cursor, len(commands)), flush=True)
    if int(p.hv_vuart_inject(command)) != len(command):
        raise RuntimeError("short memoryless staging injection")

hv._vuart_marker_handler = advance_memoryless_stage
if int(p.hv_vuart_inject_at_prompt(commands[0])) != len(commands[0]):
    raise RuntimeError("short memoryless prompt injection")
print("NEO memoryless staging queued:", count, mode, len(commands), flush=True)
