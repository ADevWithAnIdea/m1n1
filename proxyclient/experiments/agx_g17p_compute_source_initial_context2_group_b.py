#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bisect populated native context-2 leaves: table/metadata group."""

from agx_g17p_compute_source_initial import main


GROUP = (
    0x10000048000,
    0x1000004C000,
    0x10000098000,
)


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        graft_native_context2_missing=True,
        native_context2_graft_addresses=GROUP,
    ))
