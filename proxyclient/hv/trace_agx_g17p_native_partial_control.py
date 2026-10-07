# SPDX-License-Identifier: MIT
"""Capture only native G17P device-control traffic during TVB pressure."""

import os
from pathlib import Path


os.environ.setdefault("G17P_CONTROL_TIMELINE", "1")
os.environ.setdefault("G17P_CONTROL_TIMELINE_ONLY", "1")
os.environ.setdefault("G17P_MAILBOX_TIMELINE", "1")
os.environ.setdefault("G17P_MAILBOX_TIMELINE_OUTBOX", "0")
os.environ.setdefault("G17P_OUTER_TIMEOUT", "180")
os.environ.setdefault("G17P_BOOT_STOP_TIMEOUT", "180")

source = Path(__file__).with_name("trace_agx_g17p_outer.py")
exec(compile(source.read_bytes(), str(source), "exec"), globals())

print("G17P native partial-render control-only trace armed", flush=True)
