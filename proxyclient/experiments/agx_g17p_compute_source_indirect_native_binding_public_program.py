#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep the native helper binding while moving the complete program group."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(indirect_layout="native_binding_public_program"))
