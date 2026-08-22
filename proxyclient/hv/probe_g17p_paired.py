# SPDX-License-Identifier: MIT
"""RETIRED. Do not run this against a guest.

This drives firmware from under a running guest, which violates the workflow's
safety rule: the guest driver owns these rings and indices, and firmware makes no
progress while the guest is held anyway, so the probe cannot produce a trustworthy
result either way.

It is kept because its publication sequence is the part worth porting to a
bare-metal test, where writing to RAM to drive the hardware belongs.

Original description follows.

Publish both halves of a submission and see whether the stream advances.

Run inside a compatible frozen hypervisor shell with the expected submission
globals installed:

    builtins.exec(open("proxyclient/hv/probe_g17p_paired.py").read(), globals())

Background. Republishing only the geometry half is accepted and then stalls: the
geometry channel of a unit reached 2, 3, 4 while its paired render channel stayed
at 1, 1, 1. Geometry produces tiles the render stage consumes and the paired
queues share a job list, so the pipeline allows one geometry submission ahead of
its render half and no more. This publishes both halves together.

It also separates two outcomes that have been conflated. Acceptance means firmware
took the entries off the ring. Completion means it reported the work finished.
Republishing drained item buffers has been accepted before without completing,
because the items' progress fields were already consumed, so the interesting
result is whether pairing alone changes that or whether the item bodies also have
to be refreshed.
"""

import json
import pathlib
import struct
import time

# The shell binds `g17p` to the recorder object, and importing the module under
# that name shadows it. Rather than depend on which one is bound, take the one
# thing needed from the shell explicitly: set INITDATA to the descriptor address
# the tracer printed before running this.
_shell_g17p = globals().get("g17p")
_initdata = globals().get("INITDATA")
if _initdata is None and hasattr(_shell_g17p, "initdata_addr"):
    _initdata = _shell_g17p.initdata_addr
if _initdata is None:
    raise RuntimeError("set INITDATA to the descriptor address first")

from m1n1.agx import g17p as agx                                   # noqa: E402
from m1n1.agx.g17p_backend import (                                # noqa: E402
    G17PChannels, G17PQueue, G17PSubmitter)

PAIRS = [("TA_0", "3D_0")]
POLL_SECONDS = 3.0
ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")


def _write(dva, data):
    """Write through the active root, one page at a time."""
    remaining = len(data)
    offset = 0
    while remaining:
        page = tr(dva + offset)                      # noqa: F821 - shell global
        if page is None:
            raise RuntimeError("unmapped write at %#x" % (dva + offset))
        span = min(remaining, 0x4000 - ((dva + offset) & 0x3fff))
        hv.iface.writemem(page, data[offset:offset + span])   # noqa: F821
        offset += span
        remaining -= span


def _doorbell_for(channel_name):
    """Ring the doorbell for one work channel.

    The doorbell word carries the channel in its low bits, as (queue << 2) | kind
    with kind 0 for geometry, 1 for render and 2 for compute. An earlier version
    rang with a zero channel field for both halves, which is the right number for
    the first geometry channel and the wrong one for everything else, so the render
    half was never actually kicked.
    """
    kind = {"TA": 0, "3D": 1, "CL": 2}[channel_name.split("_")[0]]
    queue = int(channel_name.split("_")[1])
    number = (queue << 2) | kind

    def ring():
        base = int(hv.adt["/arm-io/gfx-asc"].get_reg(0)[0])   # noqa: F821
        hv.p.write64(base + 0x8800,                           # noqa: F821
                     agx.PUBLISH_DOORBELL | number)
        hv.p.write32(base + 0x8808, agx.ENDPOINT_WORK)        # noqa: F821

    return ring


def _describe(queue):
    idx = queue.indices()
    return "read=%d done=%d write=%d" % (idx["read"], idx["done"], idx["write"])


def run():
    channels = G17PChannels(rd, _initdata)           # noqa: F821

    report = {"pairs": []}
    for geometry_name, render_name in PAIRS:
        geometry = channels.by_name(geometry_name)
        render = channels.by_name(render_name)
        if geometry is None or render is None:
            print("missing channel %s or %s" % (geometry_name, render_name))
            continue

        halves = []
        for name, entry in ((geometry_name, geometry), (render_name, render)):
            last = channels.next_free_slot(entry) - 1
            if last < 0:
                print("%s: channel has published nothing to copy" % name)
                halves = []
                break
            slot = channels.slot(entry, last)
            queue = G17PQueue(rd, slot["queue"], slot["queue_index"])  # noqa: F821
            groups = queue.groups()
            if not groups:
                print("%s: no groups to republish" % name)
                halves = []
                break
            # groups() yields item-ring indices; turn the last group into the
            # addresses it holds, which is what publish takes.
            addresses = queue.items()
            items = [addresses[i] for i in groups[-1]]
            halves.append((name, entry, queue, {"items": items,
                                                "group_number": len(groups)}))

        if not halves:
            continue

        print("before:")
        for name, entry, queue, _group in halves:
            print("  %-5s %s counters=%s"
                  % (name, _describe(queue), channels.counters(entry)))

        published = []
        for name, entry, queue, group in halves:
            submitter = G17PSubmitter(rd, _write,          # noqa: F821
                                      _doorbell_for(name), channels)
            result = submitter.publish(entry, queue, group["items"],
                                       group["group_number"] + 1)
            published.append((name, entry, queue, result))
            print("  published %s: slot %d producer %d write %d -> %d"
                  % (name, result["slot"], result["producer"],
                     result["write_before"], result["write_after"]))

        checker = G17PSubmitter(rd, _write, lambda: None, channels)  # noqa: F821
        deadline = time.time() + POLL_SECONDS
        state = {}
        while time.time() < deadline:
            state = {
                name: {"accepted": checker.accepted(entry, queue, result),
                       "completed": checker.completed(entry, queue, result)}
                for name, entry, queue, result in published
            }
            if all(v["completed"] for v in state.values()):
                break
            time.sleep(0.05)

        print("after:")
        for name, entry, queue, _result in published:
            print("  %-5s %s counters=%s accepted=%s completed=%s"
                  % (name, _describe(queue), channels.counters(entry),
                     state.get(name, {}).get("accepted"),
                     state.get(name, {}).get("completed")))

        report["pairs"].append({
            "geometry": geometry_name,
            "render": render_name,
            "result": {name: state.get(name, {}) for name, _e, _q, _r in published},
            "published": {name: result for name, _e, _q, result in published},
        })

    out = ARTIFACTS / ("paired_submit_%s" % time.strftime("%Y%m%d_%H%M%S"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "paired.json").write_text(json.dumps(report, indent=2,
                                                sort_keys=True) + "\n")
    print("wrote %s" % (out / "paired.json"))
    return report


paired_report = run()
