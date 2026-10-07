#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep only native argument placement within the indirect helper graph."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(indirect_layout="native_argument"))
