# SPDX-License-Identifier: MIT
"""Arm an A2 capture only after the native A1/B1 prefix completes."""

import os
from m1n1.hv import TraceMode
from m1n1.utils import irange


if int(hv.adt["/chosen"].chip_id) != 0x8140:  # noqa: F821
    raise RuntimeError("the partial A/B/A witness requires T8140")
if "-s" not in hv.tba.cmdline.split():  # noqa: F821
    raise RuntimeError("the partial A/B/A witness requires single-user -s")
if os.environ.get("G17P_PRODUCER_ARM_ON_VUART_MARKER") != "1":
    raise RuntimeError("A2 capture requires workload-marker producer arming")
triangles = int(os.environ.get("G17P_ABA_TRIANGLES", "48217"))
if triangles not in (1, 48217):
    raise ValueError("A/B/A capture supports the tiny control or minimal partial witness")

if os.environ.get("G17P_ABA_DIRECT_MARKER_CAPTURE") == "1":
    held = {}
    producer_hooks = []

    def release_producers():
        for zone, name in producer_hooks:
            hv.del_tracer(zone, name)
        hv.pt_update()
        for row in held.values():
            p.write32(row["pa"], row["value"])
            p.dc_cvac(row["pa"], 4)
        u.inst("dsb sy")
        print("G17P released %d captured native producer stores" % len(held), flush=True)

    def hold_producer(address, value, width):
        if width != 32 or not isinstance(value, int):
            raise RuntimeError("unexpected native producer store width")
        channel = next(c for c in outer_submission_recorder.channels
                       if int(c["producer_pa"]) == address)
        if address in held:
            raise RuntimeError("multiple producer stores before selected A2 kick")
        p.dc_ivac(address, 4)
        before = int(p.read32(address))
        if before != 2 or value != 3 or channel["name"] not in ("TA_2", "3D_2"):
            raise RuntimeError("unexpected A2 native producer transition")
        held[address] = dict(pa=address, before=before, value=value,
                             channel=channel["name"], width=width)
        print("G17P held native %s producer %d -> %d" %
              (channel["name"], before, value), flush=True)

    def read_producer(address, width):
        if width != 32:
            raise RuntimeError("unexpected producer read width")
        return held[address]["value"] if address in held else p.read32(address)

    # The self-authored workload supplies the precise completed-prefix boundary.
    # Avoid an additional targeted closure dump before the full snapshot.
    def arm_full_snapshot_at_marker():
        if not getattr(hv, "_agx_g17p_init_message", 0):
            raise RuntimeError("A2 marker arrived without captured init message")
        if os.environ.get("G17P_ABA_HOLD_PRODUCERS") == "1" and not producer_hooks:
            for channel in outer_submission_recorder.channels:
                zone = irange(int(channel["producer_pa"]), 4)
                name = "G17PABAHeldProducer/" + channel["name"]
                hv.add_tracer(zone, name, TraceMode.HOOK,
                              read=read_producer, write=hold_producer)
                producer_hooks.append((zone, name))
            hv._agx_g17p_held_producer_stores = held
            hv._agx_g17p_release_capture_producers = release_producers
        hv._agx_g17p_full_capture_requested = True
        hv._agx_g17p_arm_full_capture()
        print("G17P A2 marker: full capture armed for next work kick", flush=True)

    hv._vuart_marker_handler = arm_full_snapshot_at_marker

# Keep the existing guest workload and persistent plist untouched. The native
# program emits ARM_CAPTURE after waiting for the first two command buffers;
# there are no producer traps on A1/B1 and no forced firmware kick forwarding.
command = (
    "(D=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    "while [ ! -x $D/g17ppartial ]; do sleep 1; done; "
    "if /bin/ps -axo comm | /usr/bin/grep -Eq "
    "'(^|/)(WindowServer|g17ppartial|g17prender|g17pcompute)$'; then "
    "echo G17P_PARTIAL_ABA_REJECT_UNRELATED_GPU_CLIENT; exit 1; fi; "
    "for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon "
    "com.apple.opendirectoryd com.apple.coreservicesd "
    "com.apple.runningboardd; do "
    "launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist; done; "
    "launchctl bootstrap system /System/Library/Frameworks/Metal.framework/"
    "Versions/A/XPCServices/MTLCompilerService.xpc; "
    "launchctl submit -l io.asahi.g17p.partial-aba "
    "-o /dev/console -e /dev/console -- "
    "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "
    "G17P_COMMAND_QUEUE_COUNT=2 G17P_ENQUEUE_ALL=1 "
    "G17P_ENQUEUE_BATCH_SIZE=2 G17P_SEPARATE_QUEUE_TARGETS=1 "
    "G17P_LOAD_EXISTING=1 G17P_CAPTURE_AFTER=2 "
    f"$D/g17ppartial 128 128 accumulate {triangles} 3; "
    "echo G17P_PARTIAL_ABA_LAUNCH=$?)\r"
).encode("ascii")

written = int(p.hv_vuart_inject_at_prompt(command))  # noqa: F821
if written != len(command):
    raise RuntimeError("short partial A/B/A prompt injection: %d/%d" %
                       (written, len(command)))
print("G17P single-user A/B/A partial witness queued; capture after A1/B1",
      flush=True)
