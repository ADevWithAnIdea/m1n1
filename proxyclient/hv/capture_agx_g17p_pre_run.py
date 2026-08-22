# SPDX-License-Identifier: MIT
"""Capture native G17P data/shared state immediately before the first ASC RUN."""

import datetime
import pathlib
import threading

from m1n1.agx.g17p_phase_state import ASC_NODES, save_phase_state
from m1n1.hv import TraceMode
from m1n1.utils import irange


ARTIFACT_ROOT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
WATCHDOG_SECONDS = 150
stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output = ARTIFACT_ROOT / ("native_pre_first_run_%s" % stamp)
captured = False


def capture(name, event):
    global captured
    value = int(event.data)
    if captured or not value & 0x10:
        return
    captured = True
    trigger = {
        "instance": name,
        "address": int(event.addr),
        "value": value,
        "width": int(event.flags.WIDTH),
    }
    manifest = save_phase_state(
        hv.iface, hv.p, hv.adt, output, "native-pre-first-asc-run", trigger
    )
    print("G17P native pre-RUN state wrote %s" % manifest)


for instance_name, node in ASC_NODES:
    base = int(hv.adt[node].get_reg(0)[0])
    hv.add_tracer(
        irange(base + 0x0044, 4),
        "G17PPreRun-%s" % instance_name,
        mode=TraceMode.SYNC,
        write=lambda event, name=instance_name: capture(name, event),
    )


def timeout():
    if not captured:
        output.mkdir(parents=True, exist_ok=True)
        (output / "TIMEOUT").write_text(
            "No ASC RUN observed within %d seconds\n" % WATCHDOG_SECONDS
        )
        print("G17P native pre-RUN capture timed out: %s" % output)


guard = threading.Timer(WATCHDOG_SECONDS, timeout)
guard.daemon = True
guard.start()
print("G17P waiting at most %d seconds for the first ASC RUN -> %s"
      % (WATCHDOG_SECONDS, output))
