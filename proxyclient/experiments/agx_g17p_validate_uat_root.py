#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline regression check for G15+ shared-root preservation."""

import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from m1n1.constructutils import Ver  # noqa: E402
from m1n1.hw.uat import UAT  # noqa: E402


class FakeProxy:
    def __init__(self):
        self.calls = []

    def memset64(self, address, value, size):
        self.calls.append((address, value, size))


def validate(generation, preserved):
    previous = Ver._version.get("G")
    try:
        Ver.set_version_key("G", generation)
        uat = object.__new__(UAT)
        uat.p = FakeProxy()
        uat.ttbr1_base = 0x100000
        uat.pt_cache = {0x100000: [1, 2, 3, 4]}
        uat._root_walk_cache = {0x100000: {0: 0x200000}}
        uat.clear_stale_kernel_roots()
        offset = preserved * 8
        expected = [(uat.ttbr1_base + offset, 0, uat.PAGE_SIZE - offset)]
        if uat.p.calls != expected:
            raise AssertionError(
                "%s cleared the wrong shared-root range: %r" %
                (generation, uat.p.calls))
        if uat.pt_cache or uat._root_walk_cache:
            raise AssertionError(
                "%s retained stale software translations" % generation)
    finally:
        Ver.set_version_key("G", previous)


def main():
    validate("G13", 2)
    validate("G17", 3)
    print("PASS: G15+ retains all three firmware-owned shared-root entries")


if __name__ == "__main__":
    main()
