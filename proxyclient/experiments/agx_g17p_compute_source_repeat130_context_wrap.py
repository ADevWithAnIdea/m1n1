#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolate queue-context reuse from the later CL2 outer-ring wrap."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=130,
        client_slot_count=64,
        fast_sequential=True,
        no_late_fourth_control=True,
        secondary_opening_only=True,
        couple_runtime_ticks=True,
        native_runtime_tick_context=True,
        persistent_runtime_queue=True,
        persistent_startup_queue=True,
        persistent_runtime_optional_once=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_tick_once=True,
        persistent_runtime_context_record_count=128,
        persistent_runtime_preserve_context_reuse=True,
    ))
