#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute eight source-built indirect compute dispatches on one live queue."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(repeat_workloads=8))
