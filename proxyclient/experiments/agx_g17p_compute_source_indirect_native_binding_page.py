#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Use the native helper page but move its binding to page offset zero."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(indirect_layout="native_helper_binding_page"))
