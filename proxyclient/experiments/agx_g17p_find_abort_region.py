#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Name the region the device-control abort falls in, if the device tree names one.

Firmware performing device control reads physical address 0x100009746f8 every time, deterministically
and independently of any queued work, and this host backs no page there. If a reserved region covers
it, that region is what a working host provides and this one does not.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from m1n1.setup import u     # noqa: E402

FAR = 0x100009746f8


def main():
    print("looking for %#x" % FAR)
    lookup = u.adt.build_addr_lookup()

    name, span = lookup.lookup(FAR)
    print("  device tree calls it %r, span %#x .. %#x"
          % (name, span.start, span.stop))

    # Where the neighbouring named regions sit, to see what it is between.
    for probe in (FAR - (1 << 24), FAR - (1 << 20), FAR + (1 << 20), FAR + (1 << 24)):
        if probe < 0:
            continue
        other, other_span = lookup.lookup(probe)
        print("    %+5d MiB: %-40r %#x .. %#x"
              % ((probe - FAR) // (1 << 20), other, other_span.start, other_span.stop))

    for name in ("/arm-io/sgx", "/chosen"):
        try:
            node = u.adt[name]
        except Exception:
            continue
        print("  %s:" % name)
        for field in ("gfx-handoff-base", "gfx-shared-region-base",
                      "gpu-region-base", "sgx-shared-region-base"):
            try:
                value = int(getattr(node, field.replace("-", "_")))
            except Exception:
                continue
            print("    %-26s %#x  (%+d MiB from the abort)"
                  % (field, value, (value - FAR) // (1 << 20)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
