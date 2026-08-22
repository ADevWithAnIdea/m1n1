#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Is the system management coprocessor reachable from a bare-metal host?

    M1N1DEVICE=/dev/m1n1-neo PYTHONPATH="$PWD/proxyclient" \
        .venv/bin/python3 proxyclient/experiments/agx_g17p_smc_present.py

Why this matters to the graphics work. Every interval of host register activity during
graphics bring-up has now been traced and is empty, every object handed to firmware is
byte-exact, and the doorbell and staged entry are confirmed correct, yet the graphics
firmware acknowledges its descriptor and then declines to service its control ring. That
points away from what the host does and towards something the firmware expects to be
present.

The graphics firmware runs tasks named for power management, and the second instance is
a power-management instance whose faulting task is the power one. Power management on
this platform is the management coprocessor's business, and a bare-metal path never
starts it while a full operating system always has it running. So whether it is even
reachable here is worth establishing before building anything on the idea.

This only starts the coprocessor and reads its key count. It does not touch the
graphics hardware.
"""

import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.setup import *                       # noqa: E402,F401,F403
from m1n1.fw.smc import SMCClient              # noqa: E402


def main():
    node = u.adt["arm-io/smc"]
    base = int(node.get_reg(0)[0])
    print("management coprocessor at %#x" % base)

    smc = SMCClient(u, base)
    smc.verbose = 0
    try:
        smc.start()
    except Exception as error:
        print("FAILED to start: %s" % error)
        return 1
    print("started")

    try:
        smc.start_ep(0x20)
    except Exception as error:
        print("FAILED to start its endpoint: %s" % error)
        return 1
    print("endpoint up")

    endpoint = smc.epmap[0x20]
    try:
        count = endpoint.read32b("#KEY")
    except Exception as error:
        print("FAILED to read a key: %s" % error)
        return 1
    print("RESULT: reachable, %d keys" % count)

    # A couple of keys a graphics power path would plausibly care about, read only to
    # show the endpoint answers real queries rather than just a count.
    for key in ("NESN", "gPMU"):
        try:
            length, type_, flags = endpoint.get_key_info(key)
            print("  %s: length %d type %s flags %#x" % (key, length, type_, flags))
        except Exception as error:
            print("  %s: not present (%s)" % (key, error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
