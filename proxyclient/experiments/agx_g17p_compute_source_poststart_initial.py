#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require the first source-built CL2 command to execute after firmware start."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=1,
        secondary_opening_only=True,
        post_start_initial=True,
    ))
