#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run generated lifecycle and publish CL2 at the current class-2 boundary."""

import os


os.environ["M1N1DEVICE"] = "/dev/m1n1-neo"
os.environ["G17P_COMPUTE_PAIR1_PRELUDE"] = "1"
os.environ["G17P_COMPUTE_NATIVE_LIFECYCLE"] = "1"
os.environ["G17P_NATIVE_CONTROL_PREFIX"] = "1"
os.environ["G17P_FINAL_26_6_SECONDARY_LIFECYCLE"] = "1"
os.environ["G17P_FINAL_26_6_SECONDARY_TARGET"] = "36"
os.environ["G17P_COMPUTE_NATIVE_SCHEDULER_WIDTH"] = "1"
os.environ["G17P_COMPUTE_RUNTIME_GRAPH_PHASE"] = "post_class1"
os.environ["G17P_COMPUTE_RUNTIME_GRAPH_LOCAL_INDEX"] = "1"
os.environ["G17P_COMPUTE_POST_CLASS1_RENDERS"] = "1"
os.environ["G17P_COMPUTE_EXACT_NATIVE_CL2"] = "1"
os.environ["G17P_COMPUTE_EXACT_NATIVE_CHANNEL"] = "1"
os.environ["G17P_COMPUTE_CURRENT_CLASS2_TAIL"] = "1"

from agx_g17p_compute_lifecycle_archive import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
