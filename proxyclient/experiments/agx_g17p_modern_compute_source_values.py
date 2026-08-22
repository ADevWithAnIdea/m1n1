#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run modern command 2 with the exact source command-2 caller values."""

import os

os.environ["G17P_MODERN_INPUT_ORDINAL"] = "1"
os.environ["G17P_MODERN_NATIVE_COMPUTE_REGISTERS"] = "1"
os.environ["G17P_MODERN_NATIVE_COMPUTE_PREPARE"] = "1"
os.environ["G17P_STAGE_FINGERPRINT"] = "1"

from agx_g17p_modern_compute import main


if __name__ == "__main__":
    raise SystemExit(main(use_timestamps=False))
