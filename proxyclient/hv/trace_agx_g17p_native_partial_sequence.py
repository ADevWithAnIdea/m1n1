# SPDX-License-Identifier: MIT
"""Record a bounded native render sequence without freezing its first job.

The normal-boot launch daemon runs twenty independently fenced instances of
the exact 48,217-triangle partial-render workload.  Records mode snapshots the
outer record, current queue item triple, and descriptor prefix for every work
producer while allowing the complete stream to run.  Offline filtering by the
128x128 fragment dimensions then exposes Metal's actual queue/descriptor reuse
rule across consecutive partial commands.
"""

import os
from pathlib import Path


os.environ.setdefault("G17P_OUTER_CAPTURE_MODE", "records")
os.environ.setdefault("G17P_CONTROL_TIMELINE", "0")
os.environ.setdefault("G17P_MAILBOX_TIMELINE", "0")
os.environ.setdefault("G17P_PRODUCER_ARM_DELAY", "0")
os.environ.setdefault("G17P_PRODUCER_TRACE_ASYNC", "1")
os.environ.setdefault("G17P_PRODUCER_ARM_ON_VUART_MARKER", "0")
os.environ.setdefault("G17P_RECORD_CHANNELS", "TA_2,3D_2")
os.environ.setdefault("G17P_OUTER_TIMEOUT", "420")
os.environ.setdefault("G17P_BOOT_STOP_TIMEOUT", "410")

source = Path(__file__).with_name("trace_agx_g17p_outer.py")
exec(compile(source.read_bytes(), str(source), "exec"), globals())

print("G17P native partial sequence recorder armed", flush=True)
