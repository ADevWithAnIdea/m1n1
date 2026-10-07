# SPDX-License-Identifier: MIT
"""Add an own-source parity witness without replacing existing guest assets.

One short command is sent per acknowledged VUART marker. No pacing sleeps,
persistent launchd jobs, global process kills, or guest cleanup are used.
"""
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile


if int(hv.adt["/chosen"].chip_id) != 0x8140 or "-s" not in hv.tba.cmdline.split():
    raise RuntimeError("parity staging requires a T8140 single-user guest")

payload = Path("build/g17ppartial-parity").read_bytes()
digest = hashlib.sha256(payload).hexdigest()
name = "g17ppartial-parity-" + digest[:12]
archive_buffer = io.BytesIO()
with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
    entry = tarfile.TarInfo(name)
    entry.size = len(payload)
    entry.mode = 0o755
    entry.mtime = 0
    archive.addfile(entry, io.BytesIO(payload))
encoded = base64.b64encode(gzip.compress(archive_buffer.getvalue(), mtime=0)).decode("ascii")
# Quote-split the marker in commands so shell input echo cannot acknowledge
# them before execution. Only echo's completed output contains the full token.
ack = "; echo G17P_PARTIAL_ARM'_'CAPTURE\r"
commands = [
    "set -e; U=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -f $U/g17ppartial.metallib ]; do sleep 1; done; "
    "S=$(/usr/bin/mktemp -d /tmp/g17p-parity.XXXXXX); B=$S/payload.b64",
]
commands.extend("printf %s '" + encoded[offset:offset + 192] + "' >> $B"
                for offset in range(0, len(encoded), 192))
commands.extend((
    f"set -o pipefail; if [ ! -e $U/{name} ]; then "
    "/usr/bin/base64 -D < $B | /usr/bin/gzip -dc | "
    "/usr/bin/tar -xf - -C $U; fi",
    f"printf '%s  %s\\n' {digest} $U/{name} | /usr/bin/shasum -a 256 -c; "
    f"/bin/sync; echo G17P_PARITY_STAGE_COMPLETE file=$U/{name} sha256={digest}",
))
commands = [(command + ack).encode("ascii") for command in commands]
if any(len(command) >= 448 for command in commands):
    raise RuntimeError("parity staging command exceeds conservative VUART bound")
cursor = 1


def advance_stage():
    global cursor
    if cursor == len(commands):
        hv._vuart_marker_handler = None
        hv._g17p_parity_staged = dict(name=name, sha256=digest)
        print("G17P parity staging acknowledged all commands: %s sha256=%s" %
              (name, digest), flush=True)
        return
    command = commands[cursor]
    count = int(p.hv_vuart_inject(command))
    if count != len(command):
        raise RuntimeError("short parity stage injection")
    cursor += 1
    if cursor % 25 == 0:
        print("G17P parity stage %d/%d commands" % (cursor, len(commands)), flush=True)


hv._vuart_marker_handler = advance_stage
count = int(p.hv_vuart_inject_at_prompt(commands[0]))
if count != len(commands[0]):
    raise RuntimeError("short parity mount injection")
print("G17P additive parity stage queued: %s bytes=%d commands=%d" %
      (name, len(payload), len(commands)), flush=True)
