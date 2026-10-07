#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run modern compute with the proven native register tuple and no timestamps."""

import os

os.environ["G17P_MODERN_NATIVE_COMPUTE_REGISTERS"] = "1"
os.environ["G17P_MODERN_NATIVE_COMPUTE_PREPARE"] = "1"

from agx_g17p_modern_compute import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(use_timestamps=False))
