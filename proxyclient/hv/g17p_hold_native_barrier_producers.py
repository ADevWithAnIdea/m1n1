# SPDX-License-Identifier: MIT
"""Hold native C/R/C outer publications as well as their work kicks.

Load after the outer recorder and before the kick interposer. Fresh queues
remain invisible to firmware while macOS sees its own shadow producer stores.
The full capture materializes only these exact intercepted host stores, keeps
the raw pre-publication image too, and releases them before the recorded kicks.
"""
import struct

from m1n1.hv import TraceMode
from m1n1.utils import irange


recorder = outer_submission_recorder  # noqa: F821
held_producers = {}
producer_hooks = []
released_producers = False


def arm_held_producer(channel_name):
    if channel_name in recorder.producer_traced_channels:
        return
    channel = next(row for row in recorder.channels if row["name"] == channel_name)
    pa = int(channel["producer_pa"])
    channel["last_producer"] = int(p.read32(pa))  # noqa: F821
    if channel["last_producer"]:
        raise RuntimeError("native barrier hold requires fresh work channels")
    zone = irange(pa, 4)
    name = "G17PBarrierHeldProducer/" + channel_name

    def read_held(address, width):
        if width != 32:
            raise RuntimeError("unexpected held producer load width")
        return held_producers[address]["value"] if address in held_producers else p.read32(address)  # noqa: F821

    def write_held(address, value, width):
        if width != 32 or not isinstance(value, int):
            raise RuntimeError("unexpected held producer store width")
        if released_producers:
            p.write32(address, value)  # noqa: F821
            return
        previous = channel["last_producer"]
        if value != previous + 1 or value > 2:
            raise RuntimeError("unexpected native barrier producer transition")
        if address not in held_producers:
            before = int(p.read32(address))  # noqa: F821
            held_producers[address] = dict(pa=address, before=before, value=value,
                channel=channel_name, width=width, stores=[])
        row = held_producers[address]
        row["value"] = value
        row["stores"].append(dict(before=previous, value=value))
        channel["last_producer"] = value
        recorder.save_record(channel, previous, value, previous)
        print("G17P held outer producer %s: %d -> %d; firmware sees %d" % (
            channel_name, previous, value, row["before"]), flush=True)

    hv.add_tracer(zone, name, TraceMode.HOOK, read=read_held, write=write_held)  # noqa: F821
    producer_hooks.append((zone, name))
    recorder.producer_traced_channels.add(channel_name)
    recorder.producer_pages.add((zone.start, zone.stop))


def release_native_producers():
    global released_producers
    for row in held_producers.values():
        if int(p.read32(row["pa"])) != row["before"]:  # noqa: F821
            raise RuntimeError("held producer backing changed before release")
    for row in held_producers.values():
        p.write32(row["pa"], row["value"])  # noqa: F821
        p.dc_cvac(row["pa"], 4)  # noqa: F821
    u.inst("dsb sy")  # noqa: F821
    released_producers = True
    for zone, name in producer_hooks:
        hv.del_tracer(zone, name)  # noqa: F821
    hv.pt_update()  # noqa: F821
    print("G17P released native barrier producers:",
          [(row["channel"], row["value"]) for row in held_producers.values()],
          flush=True)


recorder.arm_producer_channel = arm_held_producer
hv._agx_g17p_held_producer_stores = held_producers  # noqa: F821
hv._agx_g17p_capture_publication_kind = "native-barrier-pending"  # noqa: F821
hv._agx_g17p_release_capture_producers = release_native_producers  # noqa: F821
print("G17P native barrier publication hold installed", flush=True)
