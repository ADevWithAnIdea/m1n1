#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Positive-control reduction retaining only populated native context-2 leaves."""

from agx_g17p_compute_source_initial import (
    NATIVE_CONTEXT2_POPULATED,
    main,
)


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        graft_native_context2_missing=True,
        native_context2_graft_addresses=NATIVE_CONTEXT2_POPULATED,
    ))
