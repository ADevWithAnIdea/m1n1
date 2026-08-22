# SPDX-License-Identifier: MIT
"""Trace the Neo's MediaTek WLAN PCIe function without decoding its ABI."""

from m1n1.hv import TraceMode
from m1n1.utils import irange


apcie = hv.adt["/arm-io/apcie"]
ecam_base, _ = apcie.get_reg(0)

# XNU enumerates the built-in MT7932 as 01:00.0. Its stable BAR assignments
# are translated by the ADT's non-prefetchable PCIe memory range.
wlan_ranges = (
    (ecam_base + (1 << 20), 0x1000, "wlan-ecam-01:00.0"),
    (apcie.translate(0x80100000 | (0x02 << 88)), 0x100000, "wlan-bar0"),
    (apcie.translate(0x80208000 | (0x02 << 88)), 0x40000, "wlan-bar2"),
)

for start, size, name in wlan_ranges:
    print(f"[host] WLAN trace {name}: {start:#x}..{start + size - 1:#x}")
    hv.trace_range(irange(start, size), mode=TraceMode.ASYNC, name=name)
