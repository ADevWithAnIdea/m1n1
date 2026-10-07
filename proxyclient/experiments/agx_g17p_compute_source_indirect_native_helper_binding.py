#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep only native helper-binding placement for indirect compute."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(indirect_layout="native_helper_binding"))
