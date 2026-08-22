#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Relocate the helper allocation while preserving binding offset 0xb0."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(indirect_layout="helper_binding_offset"))
