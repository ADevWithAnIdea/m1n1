#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute caller-selected direct-dispatch grids and threadgroup shapes."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=4,
        client_slot_count=4,
        client_dispatch_grids=(
            (64, 1, 1),
            (32, 1, 1),
            (48, 1, 1),
            (16, 1, 1),
        ),
        client_threadgroups=(
            (32, 1, 1),
            (16, 1, 1),
            (8, 1, 1),
            (16, 1, 1),
        ),
        fast_sequential=True,
        no_late_fourth_control=True,
        secondary_opening_only=True,
        persistent_runtime_queue=True,
        persistent_startup_queue=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_fresh_events=True,
        native_control_tail=True,
        suppress_runtime_controls=True,
        post_start_initial=True,
        strict_release_publish=True,
        drain_runtime_reports=True,
        drain_runtime_report_interval=1,
    ))
