# SPDX-License-Identifier: MIT
"""Capture the native descriptor pair for the one-tile accumulation workload."""

import os
from pathlib import Path


os.environ.setdefault("G17P_OUTER_CAPTURE_MODE", "targeted")
# The native queue-pair allocator is boot-history dependent.  Arm every
# fragment producer, then let the exact 128x128 descriptor-register filter
# select our workload and lazily arm only its adjacent TA producer.
os.environ.setdefault(
    "G17P_CLOSURE_CHANNEL",
    "3D_0,TA_0,3D_1,TA_1,3D_2,TA_2,3D_3,TA_3",
)
os.environ.setdefault("G17P_VERIFIED_PAIR_CAPTURE", "1")
os.environ.setdefault("G17P_TARGET_RENDER_WIDTH", "128")
os.environ.setdefault("G17P_TARGET_RENDER_HEIGHT", "128")
os.environ.setdefault("G17P_TARGET_RENDER_DIMENSIONS_OFFSET", "0x1a8")
os.environ.setdefault("G17P_TARGETED_MAX_PAGES", "256")
os.environ.setdefault("G17P_TARGETED_CLIENT_PAGE_RESERVE", "96")
os.environ.setdefault("G17P_TARGETED_OUTPUT_PAGE_RESERVE", "16")
os.environ.setdefault("G17P_CONTROL_TIMELINE", "0")
os.environ.setdefault("G17P_MAILBOX_TIMELINE", "0")
os.environ.setdefault("G17P_PRODUCER_ARM_DELAY", "0")
os.environ.setdefault("G17P_PRODUCER_ARM_ON_VUART_MARKER", "0")
os.environ.setdefault("G17P_VERIFIED_PAIR_LAZY_TA", "1")
os.environ.setdefault("G17P_OUTER_TIMEOUT", "420")
os.environ.setdefault("G17P_BOOT_STOP_TIMEOUT", "410")

source = Path(__file__).with_name("trace_agx_g17p_outer.py")
exec(compile(source.read_bytes(), str(source), "exec"), globals())

print("G17P native partial accumulation pair capture armed", flush=True)
