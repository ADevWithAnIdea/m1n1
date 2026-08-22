#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run repeated indexed-indirect draws through the clean G17P DRM shim."""

import os
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


if __name__ == "__main__":
    os.environ.setdefault("M1N1HEAP_RESERVE", "1")
    from agx_g17p_shim_submit import main

    sys.argv[1:] = [
        "--width", "64", "--height", "64",
        "--drain-staged", "--repeat-fresh", "8",
        "--fresh-target-stride", "0x100000000",
        "--drm-color-attachment", "--witness-pages", "1",
        "--indirect-indexed",
    ]
    raise SystemExit(main())
