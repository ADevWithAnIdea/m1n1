# SPDX-License-Identifier: MIT
"""Launch two independent own-source Metal clients in a single-user guest."""
if int(hv.adt['/chosen'].chip_id) != 0x8140 or '-s' not in hv.tba.cmdline.split():  # noqa: F821
    raise RuntimeError('native render VM capture requires T8140 single-user mode')

command = (
    '(D=/System/Volumes/Data/Users/Shared; '
    '/sbin/mount -P 1; /usr/libexec/init_data_protection; '
    '/sbin/mount -P 2 >/dev/null 2>&1 & '
    'while [ ! -x $D/g17ppartial ]; do sleep 1; done; '
    "if /bin/ps -axo comm | /usr/bin/grep -Eq '(^|/)(WindowServer|g17ppartial|g17prender|g17pcompute)$'; "
    'then echo G17P_TWO_CLIENTS_REJECT_EXISTING_GPU_CLIENT; exit 1; fi; '
    'for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon '
    'com.apple.opendirectoryd com.apple.coreservicesd com.apple.runningboardd; do '
    'launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist; done; '
    'launchctl bootstrap system /System/Library/Frameworks/Metal.framework/'
    'Versions/A/XPCServices/MTLCompilerService.xpc; '
    'for owner in 0 1; do '
    'launchctl submit -l io.asahi.g17p.native-vm-$owner -o /dev/console -e /dev/console -- '
    '/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin '
    'G17P_PARTIAL_FRAGMENT=partial_fragment_constant '
    '$D/g17ppartial 128 128 accumulate 8 1; '
    'echo G17P_NATIVE_RENDER_CLIENT_$owner=$?; done)\r'
).encode('ascii')
written = int(p.hv_vuart_inject_at_prompt(command))  # noqa: F821
if written != len(command):
    raise RuntimeError('short two-client render prompt injection')
print('NATIVE RENDER VMS: two independent eight-triangle Metal clients queued', flush=True)
