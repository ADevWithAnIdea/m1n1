#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test the complete native scheduler pointer page at the positive CL2 tail."""

import os


os.environ["G17P_COMPUTE_FULL_SCHEDULER_PAGE"] = "1"

from agx_g17p_compute_positive_class2 import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
