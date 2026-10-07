#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute two sequential fully field-built G17P indirect dispatches."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(repeat_workloads=2))
