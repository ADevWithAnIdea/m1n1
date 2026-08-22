#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Positive control with the finite native-only context-2 leaf set."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        graft_native_context2_missing=True,
    ))
