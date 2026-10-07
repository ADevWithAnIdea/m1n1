# SPDX-License-Identifier: MIT
"""Capture one own-source render submission after an explicit arm boundary."""

import os
from pathlib import Path


os.environ.setdefault("G17P_OUTER_CAPTURE_MODE", "targeted")
os.environ.setdefault("G17P_CLOSURE_CHANNEL", "TA_2,3D_2")
os.environ.setdefault("G17P_TARGETED_MAX_PAGES", "48")
os.environ.setdefault("G17P_TARGETED_CLIENT_PAGE_RESERVE", "16")
os.environ.setdefault("G17P_TARGETED_MAX_INNER_ITEMS", "3")
os.environ.setdefault("G17P_TARGETED_CLIENT_CLOSURE_DEPTH", "4")
os.environ.setdefault("G17P_CAPTURE_MAILBOX_PAGES", "0")
os.environ.setdefault("G17P_TARGET_RENDER_WIDTH", "64")
os.environ.setdefault("G17P_TARGET_RENDER_HEIGHT", "64")
os.environ.setdefault("G17P_TARGET_RENDER_DVA", "0x10000058000")
# The own-source Metal allocation graph has no client pointers to compact
# texture/PBE records. Search its small resource window for the exact output
# address encoding and retain only matching descriptor pages.
os.environ.setdefault(
    "G17P_TARGET_RENDER_DESCRIPTOR_SCAN_START", "0x10000000000")
os.environ.setdefault(
    "G17P_TARGET_RENDER_DESCRIPTOR_SCAN_END", "0x10000400000")
os.environ.setdefault("G17P_MAILBOX_TIMELINE", "1")
os.environ.setdefault("G17P_MAILBOX_TIMELINE_OUTBOX", "0")
os.environ.setdefault("G17P_OUTER_TIMEOUT", "180")
# Keep the generic control-timeline armer inert. The native launcher owns the
# exact pre-commit capture boundary for this focused experiment.
os.environ.setdefault("G17P_CLOSURE_AFTER_CONTROL_TARGET", "0xffffffffffffffff")

source = Path(__file__).with_name("trace_agx_g17p_outer.py")
exec(compile(source.read_bytes(), str(source), "exec"), globals())

# Boot traffic is irrelevant. The native-render launcher flips this immediately
# before it resumes the process stopped at its pre-commit boundary.
outer_submission_recorder.closure_armed = False
print("G17P own-render capture deferred until pre-commit resume", flush=True)
