# SPDX-License-Identifier: MIT
"""Stage or launch our one-varying/eight-attachment diagnostic in single-user XNU.

Set G17P_ONE_VARYING_STAGE=1 in a separate, untraced guest to stage the assets.
The default launches one eight-triangle draw from those exact hashed assets.
G17P_NATIVE_FRAGMENT=partial_fragment_constant selects the no-varying witness.
partial_fragment_biased adds a constant half to all eight varying inputs.
No existing guest asset is replaced and no persistent launchd job is installed.
G17P_ONE_VARYING_STAGE_AND_LAUNCH=1 stages and captures in one guest: staging
temporarily owns the marker callback, restoring the capture callback before
launch. This does not rely on staged files surviving a target reset.
"""
import base64
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile


if int(hv.adt["/chosen"].chip_id) != 0x8140 or "-s" not in hv.tba.cmdline.split():
    raise RuntimeError("one-varying witness requires a T8140 single-user guest")

fragment = os.environ.get("G17P_NATIVE_FRAGMENT", "partial_fragment_one_varying")
if fragment not in ("partial_fragment_one_varying", "partial_fragment_constant",
                    "partial_fragment_biased", "partial_fragment_observed"):
    raise ValueError("unsupported own fragment entry point")
observe_vertices = os.environ.get("G17P_NATIVE_OBSERVE_VERTEX", "0")
observe_fragments = os.environ.get("G17P_NATIVE_OBSERVE_FRAGMENT", "0")
if (observe_fragments not in ("0", "1") or
        (observe_fragments == "1" and (observe_vertices != "1" or fragment != "partial_fragment_observed")) or
        (fragment == "partial_fragment_observed" and observe_fragments != "1")):
    raise ValueError("fragment observation requires the observed fragment and vertex observation")
if observe_vertices not in ("0", "1") or (observe_vertices == "1" and
        fragment != ("partial_fragment_observed" if observe_fragments == "1" else "partial_fragment_biased")):
    raise ValueError("vertex observation requires the biased fragment and a boolean selector")

pressure = os.environ.get("G17P_NATIVE_CONSTANT_PRESSURE", "0")
if pressure not in ("0", "1") or (pressure == "1" and
        (fragment != "partial_fragment_constant" or observe_vertices != "0")):
    raise ValueError("constant pressure requires the unobserved constant fragment")
submissions = int(os.environ.get("G17P_NATIVE_CONSTANT_SUBMISSIONS", "1"))
if submissions not in (1, 2, 3) or (submissions != 1 and pressure != "1"):
    raise ValueError("repeated native constant pressure supports one to three draws")
capture_after = int(os.environ.get("G17P_NATIVE_CONSTANT_CAPTURE_AFTER", "0"))
if capture_after not in (0, 1) or (capture_after and
        (pressure != "1" or submissions != 2)):
    raise ValueError("second-only capture requires two constant pressure draws")

assets = {
    "g17ppartial": Path("build/g17ppartial-constant-pressure" if pressure == "1"
                        else "build/g17ppartial-one-varying").read_bytes(),
    "shader.metal": Path("proxyclient/experiments/g17p_native_partial.metal").read_bytes(),
    # Keep the console packet bounded; the old 1171-byte line lost echo bytes.
    "run.sh": b'''#!/bin/sh
D=$1
fragment=$2
observe_vertices=$3
observe_fragments=$4
/bin/ls -ld "$D" "$D/g17ppartial"
if [ ! -x "$D/g17ppartial" ]; then
    echo G17P_ONE_VARYING_REJECT_MISSING_EXECUTABLE
    exit 1
fi
if /bin/ps -axo comm | /usr/bin/grep -Eq '(^|/)(WindowServer|g17ppartial|g17prender|g17pcompute)$'; then
    echo G17P_ONE_VARYING_REJECT_UNRELATED_GPU_CLIENT
    exit 1
fi
for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon com.apple.opendirectoryd com.apple.coreservicesd com.apple.runningboardd; do
    launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist
done
launchctl bootstrap system /System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc
launchctl submit -l io.asahi.g17p.one-varying -o /dev/console -e /dev/console -- /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin G17P_PARTIAL_METAL_SOURCE=$D/shader.metal G17P_PARTIAL_FRAGMENT=$fragment G17P_OBSERVE_VERTEX_OUTPUTS=$observe_vertices G17P_OBSERVE_FRAGMENT_INPUTS=$observe_fragments G17P_ARM_CAPTURE_BEFORE_FIRST_COMMIT=1 G17P_SEPARATE_SUBMISSION_TARGETS=1 /bin/sh -c '\"$1\" 128 128 accumulate 8 1; result=$?; launchctl remove io.asahi.g17p.one-varying; exit $result' g17p-one-varying $D/g17ppartial
echo G17P_ONE_VARYING_LAUNCH=$?
''',
}
if pressure == "1":
    assets["run.sh"] = assets["run.sh"].replace(
        b"G17P_PARTIAL_METAL_SOURCE=", b"G17P_CONSTANT_PRESSURE=1 G17P_COMMAND_QUEUE_COUNT=2 G17P_PARTIAL_METAL_SOURCE="
        if submissions > 1 else b"G17P_CONSTANT_PRESSURE=1 G17P_PARTIAL_METAL_SOURCE=").replace(
        b"128 128 accumulate 8 1", ("128 128 accumulate 131072 %d" % submissions).encode("ascii"))
    if capture_after:
        assets["run.sh"] = assets["run.sh"].replace(
            b"G17P_ARM_CAPTURE_BEFORE_FIRST_COMMIT=1", b"G17P_CAPTURE_AFTER=1")
digests = {name: hashlib.sha256(body).hexdigest() for name, body in assets.items()}
bundle_hash = hashlib.sha256("".join(digests.values()).encode("ascii")).hexdigest()
name = "g17p-one-varying-" + bundle_hash[:16]
guest_dir = "/System/Volumes/Data/Users/Shared/" + name

launch_command = (
    f"(D={guest_dir}; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "for attempt in 1 2 3 4 5; do "
    "[ -r $D/run.sh ] && break; sleep 1; done; "
    f"/bin/ls -ld $D; /bin/sh $D/run.sh $D {fragment} {observe_vertices} {observe_fragments})\r"
).encode("ascii")
if len(launch_command) >= 448:
    raise RuntimeError("shader launch command exceeds VUART bound")
staged_launch_command = (
    f"/bin/sh {guest_dir}/run.sh {guest_dir} {fragment} {observe_vertices} {observe_fragments}\r"
).encode("ascii")

stage_and_launch = os.environ.get("G17P_ONE_VARYING_STAGE_AND_LAUNCH") == "1"
previous_marker_handler = getattr(hv, "_vuart_marker_handler", None)
if stage_and_launch and not callable(previous_marker_handler):
    raise RuntimeError("combined staging requires an installed capture marker handler")

if os.environ.get("G17P_ONE_VARYING_STAGE") == "1" or stage_and_launch:
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        for filename, body in assets.items():
            entry = tarfile.TarInfo(name + "/" + filename)
            entry.size = len(body)
            entry.mode = 0o755 if filename == "g17ppartial" else 0o644
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(body))
    encoded = base64.b64encode(
        gzip.compress(archive_buffer.getvalue(), mtime=0)).decode("ascii")
    commands = [
        "set -e; U=/System/Volumes/Data/Users/Shared; "
        "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
        "/sbin/mount -P 2 >/dev/null 2>&1 & "
        "while [ ! -f $U/g17ppartial.metallib ]; do sleep 1; done; "
        "S=$(/usr/bin/mktemp -d /tmp/g17p-one-varying.XXXXXX); B=$S/payload.b64",
    ]
    commands.extend("printf %s '" + encoded[offset:offset + 192] + "' >> $B"
                    for offset in range(0, len(encoded), 192))
    # Refuse to merge into a pre-existing directory. A repeated stage only
    # verifies the previous contents and fails closed on a hash mismatch.
    commands.append(
        f"set -o pipefail; if [ ! -e $U/{name} ]; then "
        "/usr/bin/base64 -D < $B | /usr/bin/gzip -dc | "
        "/usr/bin/tar -xf - -C $U; fi")
    for filename, digest in digests.items():
        commands.append(f"printf '%s  %s\\n' {digest} $U/{name}/{filename} | "
                        "/usr/bin/shasum -a 256 -c")
    commands.append(f"/bin/ls -ld $U/{name} $U/{name}/g17ppartial; "
                    f"test -x $U/{name}/g17ppartial")
    commands.append(f"/bin/sync; echo G17P_ONE_VARYING_STAGE_COMPLETE dir=$U/{name}")
    # Split the marker token in echoed input so only completed shell commands
    # acknowledge a chunk. Stage without capture hooks: they use this marker.
    commands = [(command + "; echo G17P_PARTIAL_ARM'_'CAPTURE\r").encode("ascii")
                for command in commands]
    if any(len(command) >= 448 for command in commands):
        raise RuntimeError("one-varying staging command exceeds VUART bound")
    cursor = 1

    def advance_stage():
        global cursor
        if cursor == len(commands):
            hv._vuart_marker_handler = previous_marker_handler
            hv._g17p_one_varying_staged = dict(directory=guest_dir, sha256=digests)
            print("G17P one-varying staging acknowledged: %s %s" %
                  (guest_dir, digests), flush=True)
            if stage_and_launch:
                # The current guest just verified these mounted assets. Do
                # not repeat mount phases between verification and execution.
                if int(p.hv_vuart_inject(staged_launch_command)) != len(staged_launch_command):
                    raise RuntimeError("short staged shader launch injection")
            return
        command = commands[cursor]
        if int(p.hv_vuart_inject(command)) != len(command):
            raise RuntimeError("short one-varying staging injection")
        cursor += 1
        if cursor % 25 == 0:
            print("G17P one-varying stage %d/%d" % (cursor, len(commands)), flush=True)

    hv._vuart_marker_handler = advance_stage
    command = commands[0]
else:
    command = launch_command

if int(p.hv_vuart_inject_at_prompt(command)) != len(command):
    raise RuntimeError("short one-varying prompt injection")
print("G17P shader variant queued fragment=%s observe_vertices=%s directory=%s sha256=%s" %
      (fragment, observe_vertices, guest_dir, digests), flush=True)
