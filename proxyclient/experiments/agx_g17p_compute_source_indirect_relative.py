#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Relocate the complete indirect program group with native relative layout."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(indirect_layout="relative"))
