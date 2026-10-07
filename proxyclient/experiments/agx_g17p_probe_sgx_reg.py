#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Probe the accelerator register whose access aborts during device-control setup.

Firmware takes an external abort at an L2 address whose low half is sgx_base + 0x14020 whenever the
device-control setup message is sent, and the only configuration that gets work accepted is the one
that skips that message. If skipping it is also why nothing executes, this register is the thread to
pull.

Asks the cheapest question first: can the host read it at all, with the same power domains up that
the replay brings up? A host read that succeeds says the region is reachable and the abort is about
the state firmware is in, not about the register being absent.
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.setup import *  # noqa: F401,F403
from m1n1.proxy import GUARD

SGX_PATHS = ("/arm-io/gfx-asc", "/arm-io/gfx1-asc", "/arm-io/sgx")
# The offset the abort names, plus the two the bring-up path already writes, as controls.
# Controls first, suspect last: a read of the aborting offset may raise an SError, which is
# asynchronous and so not caught by the guard, and that would cost every reading after it.
OFFSETS = (0xD06030, 0x1000104, 0x1000108, 0x14000, 0x14040, 0x14020)

for path in SGX_PATHS:
    p.pmgr_adt_power_enable(path)
print("powered: %s" % ", ".join(SGX_PATHS))

sgx_base = int(u.adt["/arm-io/sgx"].get_reg(0)[0])
print("sgx base %#x" % sgx_base)

p.set_exc_guard(GUARD.SKIP | GUARD.SILENT)
for offset in OFFSETS:
    addr = sgx_base + offset
    before = p.get_exc_count()
    value = p.read32(addr)
    aborted = p.get_exc_count() != before
    print("  %#011x (+%#09x): %s"
          % (addr, offset, "ABORT" if aborted else "%#010x" % value))
p.set_exc_guard(GUARD.OFF)
