# SPDX-License-Identifier: MIT
"""Does firmware advance anything while the guest is held in the shell?

Run inside the frozen hypervisor shell:

    INITDATA = g17p.initdata_addr
    builtins.exec(open("proxyclient/hv/probe_g17p_frozen_progress.py").read(),
                  globals())

This publishes nothing. It samples every work channel's queue indices and counters
over several seconds and reports whether any of them move.

Why it has to come first. A paired publication made during a freeze was not
accepted, but neither was work the guest had queued before the freeze and firmware
had not yet taken. If firmware makes no progress while the guest is stopped, then
no publication made during a freeze can be observed to complete, and a negative
result from that probe says nothing about the submission itself. This separates
the two.
"""

import time

from m1n1.agx import g17p as agx
from m1n1.agx.g17p_backend import G17PChannels, G17PQueue

WATCH_SECONDS = 6.0
WORK_CHANNELS = agx.CHANNEL_TABLE_WORK_ORDER


def snapshot(channels):
    state = {}
    for name in WORK_CHANNELS:
        entry = channels.by_name(name)
        if entry is None:
            continue
        counters = tuple(channels.counters(entry))
        last = channels.next_free_slot(entry) - 1
        indices = None
        if last >= 0:
            slot = channels.slot(entry, last)
            if slot["queue"]:
                try:
                    queue = G17PQueue(rd, slot["queue"], slot["queue_index"])  # noqa: F821
                    idx = queue.indices()
                    indices = (idx["read"], idx["done"], idx["write"])
                except Exception:
                    indices = None
        state[name] = {"counters": counters, "indices": indices}
    return state


def run():
    initdata = globals().get("INITDATA")
    if initdata is None:
        raise RuntimeError("set INITDATA to the descriptor address first")
    channels = G17PChannels(rd, initdata)                     # noqa: F821

    first = snapshot(channels)
    outstanding = [n for n, v in first.items()
                   if v["indices"] and v["indices"][0] != v["indices"][2]]
    print("channels with work outstanding at the freeze: %s"
          % (", ".join(outstanding) if outstanding else "none"))
    for name in outstanding:
        v = first[name]
        print("  %-5s read=%d done=%d write=%d counters=%s"
              % (name, v["indices"][0], v["indices"][1], v["indices"][2],
                 list(v["counters"])))

    if not outstanding:
        print("nothing outstanding, so this cannot tell whether firmware runs;"
              " freeze at a moment with work in flight")

    deadline = time.time() + WATCH_SECONDS
    moved = {}
    while time.time() < deadline:
        current = snapshot(channels)
        for name, value in current.items():
            if value != first[name]:
                moved.setdefault(name, (first[name], value))
        time.sleep(0.1)

    if moved:
        print("firmware IS progressing while the guest is frozen:")
        for name, (before, after) in moved.items():
            print("  %-5s %s -> %s" % (name, before, after))
    else:
        print("no channel moved in %.0fs: firmware makes no progress while the"
              " guest is held, so a publication cannot be observed to complete"
              " during a freeze" % WATCH_SECONDS)
    return moved


frozen_progress = run()
