#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the source partial graph after a render-backed compute class-3 gate."""

import os


os.environ["M1N1DEVICE"] = "/dev/ttys004"
os.environ["G17P_PARTIAL_RENDER_CADENCE"] = "1"
os.environ["G17P_PARTIAL_RENDER_COMPUTE_CLASS3"] = "1"
os.environ["G17P_PARTIAL_ALTERNATING_TRANSPORT_CONTROL"] = "1"
os.environ["G17P_PARTIAL_PRIMARY_VM"] = "1"
os.environ["G17P_BASE_RENDER_REGISTER_NAMESPACE"] = "1"
os.environ["G17P_PARTIAL_DIRECT_REPLAY_GRAPH"] = "1"

from agx_g17p_render_uapi_partial import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
