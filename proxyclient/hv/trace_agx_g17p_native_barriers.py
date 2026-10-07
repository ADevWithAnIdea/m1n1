# SPDX-License-Identifier: MIT
"""Record every queue publication made by the minimal native barrier witness."""

import os
from pathlib import Path


os.environ.setdefault("G17P_OUTER_CAPTURE_MODE", "records")
os.environ.setdefault(
    "G17P_RECORD_CHANNELS",
    "TA_0,3D_0,CL_0,TA_1,3D_1,CL_1,TA_2,3D_2,CL_2,TA_3,3D_3,CL_3",
)
os.environ.setdefault("G17P_RECORD_DESCRIPTOR_PREFIX", "1")
os.environ.setdefault("G17P_RECORD_ITEM_BODIES", "1")
os.environ.setdefault("G17P_RECORD_SCHEDULER", "0")
os.environ.setdefault("G17P_CONTROL_TIMELINE", "0")
os.environ.setdefault("G17P_MAILBOX_TIMELINE", "1")
os.environ.setdefault("G17P_MAILBOX_TIMELINE_OUTBOX", "0")
os.environ.setdefault("G17P_PRODUCER_ARM_DELAY", "0")
os.environ.setdefault("G17P_PRODUCER_ARM_ON_VUART_MARKER", "1")
os.environ.setdefault("G17P_OUTER_TIMEOUT", "175")
os.environ.setdefault("G17P_BOOT_STOP_TIMEOUT", "170")

source = Path(__file__).with_name("trace_agx_g17p_outer.py")
exec(compile(source.read_bytes(), str(source), "exec"), globals())

print("G17P native barrier all-channel record trace armed", flush=True)
