# SPDX-License-Identifier: MIT
"""Log every message a guest sends the graphics coprocessor across several submissions.

This exists because of one question that no artifact on disk answers. A submission this host
publishes is accepted by firmware, linked into the scheduler's own job list, and never executed,
while the identical bytes execute when firmware finds them at startup. Every property of the work
has been eliminated, so what is left is what a working host does between one submission and the
next that this host does not do at all.

Every capture held here is of a single moment, taken by freezing the guest at one doorbell. This
logs the interval instead: every mailbox message, in order, with its endpoint, for a bounded window
covering several submissions. What matters is not any one message but whether anything besides the
work doorbell appears between two of them.

Launch from a TTY with the ordinary guest runner:

    G17P_MAILBOX_MESSAGES=400 G17P_MAILBOX_TIMEOUT=150 \\
    M1N1DEVICE=/dev/m1n1-neo PYTHONUNBUFFERED=1 \\
      .venv/bin/python3 proxyclient/tools/run_guest.py -S -m proxyclient/hv/trace_agx_g17p_mailbox_window.py build/kernelcache.release.Mac17,5

Alternatively, source it from the hypervisor shell.
"""

import os
import threading

# The hypervisor shell's own locals carry ``hv`` but not these, so import them rather than relying
# on whatever the shell happens to have bound.
from m1n1.utils import irange
from m1n1.hv.types import TraceMode

# How many messages to record before reporting. A submission is a small number of messages, so a
# few hundred covers many of them, and the cap keeps the log bounded on a busy guest.
MAX_MESSAGES = int(os.environ.get("G17P_MAILBOX_MESSAGES", "400"))
TIMEOUT = int(os.environ.get("G17P_MAILBOX_TIMEOUT", "150"))
OUTPUT = os.environ.get(
    "G17P_MAILBOX_OUTPUT",
    "/Users/user/asahi_re/artifacts/agx_g17p/mailbox_window.txt")

# Message types this record already names, so the log reads as a sequence of roles rather than of
# numbers. Anything else is printed as unknown, which is the interesting case.
KNOWN = {
    0x81: "initdata",
    0x83: "work doorbell",
    0x84: "device control",
    0x89: "control start",
}

messages = []
payload = {"value": 0}
done = threading.Event()


def _describe(endpoint, message):
    kind = (message >> 48) & 0xff
    return "ep %#04x  type %#04x %-14s  payload %#018x" % (
        endpoint, kind, KNOWN.get(kind, "unknown"), message)


def _report():
    lines = ["%4d  %s" % (index, text) for index, text in enumerate(messages)]
    body = "\n".join(lines)
    print("G17P mailbox window: %d messages" % len(messages))
    print(body)
    try:
        with open(OUTPUT, "w") as out:
            out.write(body + "\n")
        print("G17P mailbox window written to %s" % OUTPUT)
    except Exception as error:  # noqa: BLE001
        print("G17P mailbox window not written: %s" % error)


def mailbox_write(evt):
    address = int(evt.addr)
    if address == payload_addr:
        payload["value"] = int(evt.data)
        return
    if address != endpoint_addr:
        return
    if done.is_set():
        return
    endpoint = int(evt.data) & 0xff
    messages.append(_describe(endpoint, payload["value"]))
    if len(messages) >= MAX_MESSAGES:
        done.set()
        _report()


def _on_timeout():
    if not done.is_set():
        done.set()
        _report()
    os.write(2, b"[host] G17P mailbox window complete\n")
    os._exit(0)


asc_base = int(hv.adt["/arm-io/gfx-asc"].get_reg(0)[0])   # noqa: F821
payload_addr = asc_base + 0x8800
endpoint_addr = asc_base + 0x8808

hv.add_tracer(                                            # noqa: F821
    irange(payload_addr, 0x10),
    "G17PMailboxWindow",
    mode=TraceMode.SYNC,
    write=mailbox_write,
)

guard = threading.Timer(TIMEOUT, _on_timeout)
guard.name = "g17p-mailbox-window"
guard.daemon = True
guard.start()

print("G17P mailbox window: logging up to %d messages for %ds, output %s"
      % (MAX_MESSAGES, TIMEOUT, OUTPUT))
