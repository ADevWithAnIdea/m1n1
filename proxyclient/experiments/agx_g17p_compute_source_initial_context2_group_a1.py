#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bisect four causal candidates: bind/data half."""

from agx_g17p_compute_source_initial import main


GROUP = (0x1000000000, 0x10000000000)


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        graft_native_context2_missing=True,
        native_context2_graft_addresses=GROUP,
    ))
