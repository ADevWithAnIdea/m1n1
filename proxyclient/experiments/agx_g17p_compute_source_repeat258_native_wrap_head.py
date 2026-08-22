#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross CL2 wrap with native queue head and control history values."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=258,
        client_slot_count=64,
        fast_sequential=True,
        no_late_fourth_control=True,
        secondary_opening_only=True,
        persistent_runtime_queue=True,
        persistent_startup_queue=True,
        persistent_runtime_optional_once=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_optional_skip_ordinals=(200,),
        native_control_tail=True,
        suppress_runtime_controls=True,
        queue_index_bias=125,
    ))
