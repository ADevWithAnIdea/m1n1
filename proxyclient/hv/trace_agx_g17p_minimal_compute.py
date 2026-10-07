# SPDX-License-Identifier: MIT
"""Capture only the first own-source 64-thread add workload on G17P."""

import os
from pathlib import Path


os.environ.setdefault("G17P_OUTER_CAPTURE_MODE", "targeted")
os.environ.setdefault("G17P_NATIVE_ADD3_CONTROL", "1")
os.environ.setdefault("G17P_CLOSURE_CHANNEL", "CL_0,CL_1,CL_2,CL_3")
os.environ.setdefault("G17P_TARGETED_MAX_PAGES", "64")
os.environ.setdefault("G17P_TARGETED_CLIENT_CLOSURE_DEPTH", "3")
os.environ.setdefault("G17P_CAPTURE_MAILBOX_PAGES", "1")
os.environ.setdefault("G17P_OUTER_TIMEOUT", "180")

source = Path(__file__).with_name("trace_agx_g17p_outer.py")
exec(compile(source.read_bytes(), str(source), "exec"), globals())
