# SPDX-License-Identifier: MIT
"""Capture native G17P state immediately before secondary initdata."""

import datetime
import pathlib
import threading

from m1n1.agx.g17p_phase_state import ASC_NODES, save_phase_state
from m1n1.hv import TraceMode
from m1n1.utils import irange


ARTIFACT_ROOT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
WATCHDOG_SECONDS = 150
INITDATA_TYPE = 0x81
INITDATA_ENDPOINT = 0x20
stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output = ARTIFACT_ROOT / ("native_pre_secondary_initdata_%s" % stamp)
payloads = {}
seen_initdata = []
captured = False


def mailbox(name, base, event):
    global captured
    if captured:
        return
    offset = int(event.addr) - base
    if offset == 0x8800:
        payloads[name] = int(event.data)
        return
    if offset != 0x8808 or (int(event.data) & 0xff) != INITDATA_ENDPOINT:
        return
    payload = payloads.get(name, 0)
    if (payload >> 48) & 0xff != INITDATA_TYPE:
        return
    seen_initdata.append({"instance": name, "payload": payload})
    if name != "secondary":
        return
    captured = True
    trigger = {
        "instance": name,
        "payload": payload,
        "endpoint_word": int(event.data),
        "address": int(event.addr),
        "width": int(event.flags.WIDTH),
        "initdata_seen": list(seen_initdata),
    }
    manifest = save_phase_state(
        hv.iface, hv.p, hv.adt, output, "native-pre-secondary-initdata", trigger
    )
    print("G17P native pre-secondary-initdata state wrote %s" % manifest)


for instance_name, node in ASC_NODES:
    asc_base = int(hv.adt[node].get_reg(0)[0])
    hv.add_tracer(
        irange(asc_base + 0x8800, 0x10),
        "G17PPreSecondaryInitdata-%s" % instance_name,
        mode=TraceMode.SYNC,
        write=lambda event, name=instance_name, base=asc_base:
            mailbox(name, base, event),
    )


def timeout():
    if not captured:
        output.mkdir(parents=True, exist_ok=True)
        (output / "TIMEOUT").write_text(
            "No secondary initdata observed within %d seconds\n"
            % WATCHDOG_SECONDS
        )
        print("G17P native pre-secondary-initdata capture timed out: %s"
              % output)


guard = threading.Timer(WATCHDOG_SECONDS, timeout)
guard.daemon = True
guard.start()
print("G17P waiting at most %d seconds for secondary initdata -> %s"
      % (WATCHDOG_SECONDS, output))
