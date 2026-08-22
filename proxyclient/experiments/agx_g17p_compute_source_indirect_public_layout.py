#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build indirect compute at an independent clean-room A18 layout."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(indirect_layout="public"))
