#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require four compute outputs while appending to one runtime queue."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=4,
        no_late_fourth_control=True,
        secondary_opening_only=True,
        couple_runtime_ticks=True,
        persistent_runtime_queue=True,
    ))
