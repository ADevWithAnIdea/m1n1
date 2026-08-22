#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run exact generated firmware lifecycle with captured clean-room client state."""

import os


os.environ["M1N1DEVICE"] = "/dev/m1n1-neo"
os.environ["G17P_COMPUTE_PAIR1_PRELUDE"] = "1"
os.environ["G17P_COMPUTE_NATIVE_LIFECYCLE"] = "1"
os.environ["G17P_SECONDARY_RUNTIME_22"] = "publish"
os.environ["G17P_COMPUTE_NATIVE_SCHEDULER_WIDTH"] = "1"
os.environ["G17P_COMPUTE_RUNTIME_GRAPH_PHASE"] = "post_class1"
os.environ["G17P_COMPUTE_RUNTIME_GRAPH_LOCAL_INDEX"] = "1"
os.environ["G17P_COMPUTE_POST_CLASS1_RENDERS"] = "1"
os.environ["G17P_COMPUTE_EXACT_NATIVE_CL2"] = "1"
os.environ["G17P_COMPUTE_NATIVE_CLIENT_REPLAY"] = "1"
os.environ["G17P_COMPUTE_NATIVE_FINAL_SEQUENCE"] = "0x144"
os.environ["G17P_CONTROL_RING_RECYCLE"] = "1"
os.environ["G17P_CONTROL_RING_RESTART_SEQUENCE"] = "0xec"

from agx_g17p_compute_lifecycle_archive import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
