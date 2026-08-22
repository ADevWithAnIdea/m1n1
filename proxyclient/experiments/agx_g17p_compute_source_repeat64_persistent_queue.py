#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require 64 exact compute outputs on one append-only runtime queue."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=64,
        no_late_fourth_control=True,
        secondary_opening_only=True,
        couple_runtime_ticks=True,
        native_runtime_tick_context=True,
        persistent_runtime_queue=True,
        persistent_runtime_optional_once=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_tick_once=True,
    ))
