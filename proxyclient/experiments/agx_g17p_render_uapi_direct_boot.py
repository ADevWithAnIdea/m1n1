#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the focused modern render proof after the source-built compute bootstrap."""

import os


os.environ["G17P_MODERN_DIRECT_BOOTSTRAP"] = "1"

from agx_g17p_render_uapi_timestamps import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
