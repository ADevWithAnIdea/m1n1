# SPDX-License-Identifier: MIT
"""Stage our Metal reproducer on tmpfs; leave persistent debug files untouched."""
import base64
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile

assets = {
    'g17pcombined': Path('build/g17pcombined').read_bytes(),
    'shader.metal': (Path('proxyclient/experiments/g17p_native_partial.metal').read_bytes() +
                     b'\n' + Path('proxyclient/experiments/g17p_native_compute.metal').read_bytes()),
    'run.sh': b'''#!/bin/sh
D=/tmp/g17p
for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon com.apple.opendirectoryd com.apple.coreservicesd com.apple.runningboardd; do
    launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist
done
launchctl bootstrap system /System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc
launchctl submit -l io.asahi.g17p.combined -o /dev/console -e /dev/console -- /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp/g17p/tmp /bin/sh -c '/tmp/g17p/g17pcombined /tmp/g17p/shader.metal; rc=$?; echo G17P_COMBINED_EXIT=$rc; launchctl remove io.asahi.g17p.combined; exit $rc'
''',
}
if os.environ.get('G17P_COMBINED_SEPARATE_COMPUTE') == '1':
    assets['run.sh'] = assets['run.sh'].replace(
        b'g17pcombined /tmp/g17p/shader.metal;',
        b'g17pcombined /tmp/g17p/shader.metal --separate-compute;')
    print('G17P combined native compute runs in a retained second process', flush=True)
archive = io.BytesIO()
with tarfile.open(fileobj=archive, mode='w') as output:
    for name, body in assets.items():
        entry = tarfile.TarInfo(name)
        entry.size = len(body)
        entry.mode = 0o755 if name == 'g17pcombined' else 0o644
        output.addfile(entry, io.BytesIO(body))
encoded = base64.b64encode(gzip.compress(archive.getvalue(), mtime=0)).decode('ascii')
commands = ["/sbin/mount -P 1; /usr/libexec/init_data_protection; /sbin/mount -P 2; /sbin/mount_tmpfs -s 67108864 /private/tmp && /bin/mkdir -p /tmp/g17p/tmp && D=/tmp/g17p && B=$D/payload.b64"]
commands += ["printf %s '" + encoded[at:at+192] + "' >> $B" for at in range(0, len(encoded), 192)]
commands += ["set -o pipefail; /usr/bin/base64 -D < $B | /usr/bin/gzip -dc | /usr/bin/tar -xf - -C $D"]
for name, body in assets.items():
    commands += ["printf '%s  %s\\n' " + hashlib.sha256(body).hexdigest() + ' $D/' + name + ' | /usr/bin/shasum -a 256 -c']
commands += ["/sbin/mount; echo G17P_COMBINED_RAM_STAGE_COMPLETE"]
commands = [(line + "; if [ $? -eq 0 ]; then echo G17P_PARTIAL_ARM'_'CAPTURE; else echo G17P_COMBINED_STAGE_FAILED; fi\r").encode('ascii') for line in commands]
assert all(len(line) < 448 for line in commands)
previous = hv._vuart_marker_handler
cursor = 1


def stage_next():
    global cursor
    if cursor == len(commands):
        hv._vuart_marker_handler = previous
        print('G17P combined RAM staging verified', {name: hashlib.sha256(body).hexdigest() for name, body in assets.items()}, flush=True)
        command = b'/bin/sh /tmp/g17p/run.sh\r'
    else:
        command = commands[cursor]
        cursor += 1
        if cursor % 25 == 0:
            print('G17P combined RAM staging', cursor, '/', len(commands), flush=True)
    if int(p.hv_vuart_inject(command)) != len(command):
        raise RuntimeError('short combined staging injection')

hv._vuart_marker_handler = stage_next
if int(p.hv_vuart_inject_at_prompt(commands[0])) != len(commands[0]):
    raise RuntimeError('short combined prompt injection')
print('G17P combined RAM stage queued', len(commands), 'acknowledged chunks', flush=True)
