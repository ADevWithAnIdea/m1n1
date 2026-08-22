#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run 64 distinct source-built compute workloads on one live G17P queue."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=64,
    ))
