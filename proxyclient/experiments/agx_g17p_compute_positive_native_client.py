#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the final-26.6 lifecycle with the output-positive native CL2 payload."""

import os


# Keep the final-26.6 firmware/control lifecycle from the direct positive
# experiment, but substitute the captured clean-room client contract as one
# D03+D04 isolation: resource bindings, CDM record, shader, and output oracle.
os.environ["G17P_COMPUTE_NATIVE_CLIENT_REPLAY"] = "1"
os.environ["G17P_COMPUTE_NATIVE_FINAL_DESCRIPTOR"] = "1"

from agx_g17p_compute_positive_class2 import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
