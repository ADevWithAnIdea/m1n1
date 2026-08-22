#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the modern direct-compute path without timestamp destinations."""

from agx_g17p_modern_compute import main


if __name__ == "__main__":
    raise SystemExit(main(use_timestamps=False))
