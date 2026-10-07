# SPDX-License-Identifier: MIT
"""Capture one complete native add3 graph and its firmware-visible timeline."""

import os
from pathlib import Path


os.environ.setdefault("G17P_OUTER_CAPTURE_MODE", "targeted")
os.environ.setdefault("G17P_NATIVE_ADD3_CONTROL", "1")
os.environ.setdefault("G17P_CLOSURE_CHANNEL", "CL_0,CL_1,CL_2,CL_3")
os.environ.setdefault("G17P_TARGETED_MAX_PAGES", "1024")
os.environ.setdefault("G17P_TARGETED_CLIENT_CLOSURE_DEPTH", "4")
os.environ.setdefault("G17P_CAPTURE_MAILBOX_PAGES", "1")
os.environ.setdefault("G17P_CONTROL_TIMELINE", "1")
os.environ.setdefault("G17P_MAILBOX_TIMELINE", "1")
os.environ.setdefault("G17P_MAILBOX_TIMELINE_OUTBOX", "1")
os.environ.setdefault("G17P_OUTER_TIMEOUT", "180")

source = Path(__file__).with_name("trace_agx_g17p_outer.py")
exec(compile(source.read_bytes(), str(source), "exec"), globals())
