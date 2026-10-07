# SPDX-License-Identifier: MIT
"""Capture all three native A/B/A publications from the same single-user boot."""
import hashlib
import os
from pathlib import Path

from m1n1.hv import TraceMode
from m1n1.utils import irange


if int(hv.adt["/chosen"].chip_id) != 0x8140 or "-s" not in hv.tba.cmdline.split():
    raise RuntimeError("partial sequence requires T8140 single-user mode")
if os.environ.get("G17P_PRODUCER_ARM_ON_VUART_MARKER") != "1":
    raise RuntimeError("sequence requires deferred producer arming")
if os.environ.get("AGX_G17P_CAPTURE_SPARSE_RAM") != "1":
    raise RuntimeError("three full snapshots require the qualified sparse transport")
triangles = int(os.environ.get("G17P_SEQUENCE_TRIANGLES", "1"))
if triangles not in (1, 48217):
    raise ValueError("sequence supports tiny control or minimal pressure draw")
hooks_only = os.environ.get("G17P_SEQUENCE_HOOK_ONLY") == "1"
capture_count = int(os.environ.get("G17P_SEQUENCE_CAPTURE_COUNT", "3"))
first_capture = int(os.environ.get("G17P_SEQUENCE_FIRST_CAPTURE", "1"))
if capture_count not in (1, 2, 3) or (capture_count != 3 and not hooks_only):
    raise ValueError("custom sequence count requires the separate bounded launcher")
if first_capture not in (1, 2) or (first_capture != 1 and
        (not hooks_only or capture_count != 1)):
    raise ValueError("second-only capture requires a separate single-boundary launcher")
digest = ("separate-launcher" if hooks_only else
          hashlib.sha256(Path("build/g17ppartial-parity").read_bytes()).hexdigest())
name = "g17ppartial-parity-" + digest[:12]
held = {}
hooks = []
captures = []
hv._agx_g17p_native_sequence_ordinal = first_capture
hv._agx_g17p_native_sequence_previous = None


def release_publication():
    path = getattr(hv, "_agx_g17p_initdata_capture", None)
    if path is None:
        raise RuntimeError("sequence capture failed; publication remains held")
    captures.append(path)
    for row in held.values():
        p.write32(row["pa"], row["value"])
        p.dc_cvac(row["pa"], 4)
    u.inst("dsb sy")
    held.clear()
    hv._agx_g17p_full_capture_requested = False
    hv._agx_g17p_native_sequence_previous = path
    hv._agx_g17p_native_sequence_ordinal = first_capture + len(captures)
    if len(captures) < capture_count:
        hv._agx_g17p_initdata_capture = None
    else:
        for zone, ident in hooks:
            hv.del_tracer(zone, ident)
        hv.pt_update()
    print("G17P full native sequence checkpoint %d: %s" % (len(captures), path), flush=True)


def producer_write(address, value, width):
    if width != 32 or not isinstance(value, int) or address in held:
        raise RuntimeError("unexpected native sequence producer store")
    channel = next(c for c in outer_submission_recorder.channels
                   if int(c["producer_pa"]) == address)
    p.dc_ivac(address, 4)
    before = int(p.read32(address))
    if (channel["name"] not in ("TA_2", "3D_2") or
            before != first_capture - 1 + len(captures) or value != before + 1):
        raise RuntimeError("sequence publication does not follow completed native prefix")
    held[address] = dict(pa=address, before=before, value=value,
                         channel=channel["name"], width=width)
    if len(held) == 2:
        hv._agx_g17p_full_capture_requested = True
        hv._agx_g17p_release_capture_producers = release_publication
        hv._agx_g17p_arm_full_capture()


def producer_read(address, width):
    if width != 32:
        raise RuntimeError("unexpected sequence producer read width")
    return held[address]["value"] if address in held else p.read32(address)


def arm_sequence():
    if hooks:
        return
    if not getattr(hv, "_agx_g17p_init_message", 0):
        raise RuntimeError("sequence marker arrived without init message")
    for channel in outer_submission_recorder.channels:
        zone = irange(int(channel["producer_pa"]), 4)
        ident = "G17PSequenceProducer/" + channel["name"]
        hv.add_tracer(zone, ident, TraceMode.HOOK,
                      read=producer_read, write=producer_write)
        hooks.append((zone, ident))
    hv._agx_g17p_held_producer_stores = held
    hv.pt_update()
    print("G17P same-boot full sequence capture armed: %d boundaries" % capture_count, flush=True)


hv._vuart_marker_handler = arm_sequence
pressure = "G17P_TINY_PREFIX_COUNT=2 " if triangles == 48217 else ""
command = (
    "(D=/System/Volumes/Data/Users/Shared; "
    "/sbin/mount -P 1; /usr/libexec/init_data_protection; "
    "/sbin/mount -P 2 >/dev/null 2>&1 & "
    f"while [ ! -x $D/{name} ]; do sleep 1; done; "
    "if /bin/ps -axo comm | /usr/bin/grep -Eq "
    "'(^|/)(WindowServer|g17ppartial.*|g17prender|g17pcompute)$'; then "
    "echo G17P_SEQUENCE_REJECT_UNRELATED_GPU_CLIENT; exit 1; fi; "
    "for x in com.apple.notifyd com.apple.cfprefsd.xpc.daemon "
    "com.apple.opendirectoryd com.apple.coreservicesd com.apple.runningboardd; do "
    "launchctl bootstrap system /System/Library/LaunchDaemons/$x.plist; done; "
    "launchctl bootstrap system /System/Library/Frameworks/Metal.framework/"
    "Versions/A/XPCServices/MTLCompilerService.xpc; "
    "launchctl submit -l io.asahi.g17p.partial-sequence -o /dev/console -e /dev/console -- "
    "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "
    "G17P_COMMAND_QUEUE_COUNT=2 G17P_SEPARATE_SUBMISSION_TARGETS=1 "
    "G17P_ARM_CAPTURE_BEFORE_FIRST_COMMIT=1 " + pressure +
    f"/bin/sh -c '/System/Volumes/Data/Users/Shared/{name} "
    f"128 128 accumulate {triangles} 3; "
    "/bin/launchctl remove io.asahi.g17p.partial-sequence'; "
    "echo G17P_SEQUENCE_LAUNCH=$?)\r"
).encode("ascii")
if not hooks_only:
    count = int(p.hv_vuart_inject_at_prompt(command))
    if count != len(command):
        raise RuntimeError("short native sequence launch injection")
    print("G17P native sequence queued: %s sha256=%s triangles=%d" %
          (name, digest, triangles), flush=True)
