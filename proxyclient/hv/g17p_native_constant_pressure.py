# SPDX-License-Identifier: MIT
"""Stage our constant pressure shader and capture both native owners in -s."""
import os
from pathlib import Path

os.environ.update(G17P_SEQUENCE_HOOK_ONLY="1", G17P_SEQUENCE_CAPTURE_COUNT="2",
                  G17P_NATIVE_CONSTANT_PRESSURE="1", G17P_NATIVE_CONSTANT_SUBMISSIONS="2",
                  G17P_NATIVE_FRAGMENT="partial_fragment_constant",
                  G17P_ONE_VARYING_STAGE_AND_LAUNCH="1")
second_only = os.environ.get("G17P_CONSTANT_PRESSURE_SECOND_ONLY", "0")
if second_only not in ("0", "1"):
    raise ValueError("second-only selector must be 0 or 1")
os.environ.update(G17P_SEQUENCE_FIRST_CAPTURE="2" if second_only == "1" else "1",
                  G17P_SEQUENCE_CAPTURE_COUNT="1" if second_only == "1" else "2",
                  G17P_NATIVE_CONSTANT_CAPTURE_AFTER=second_only)
for filename in ("g17p_launch_partial_sequence.py", "g17p_native_one_varying.py"):
    source = Path("proxyclient/hv") / filename
    exec(compile(source.read_bytes(), str(source), "exec"), globals())
