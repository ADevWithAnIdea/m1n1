#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test whether continuously consuming firmware reports permits CL2 reuse."""

from agx_g17p_compute_source_initial import main
from agx_g17p_compute_source_repeat258_native_complete_queue import (  # noqa: F401
    NATIVE_OPTIONAL_OMISSIONS,
)


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
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_fresh_events=True,
        persistent_runtime_optional_skip_ordinals=(
            NATIVE_OPTIONAL_OMISSIONS + (256, 257)),
        native_control_tail=True,
        suppress_runtime_controls=True,
        post_start_initial=True,
        strict_release_publish=True,
        drain_runtime_reports=True,
        drain_runtime_report_interval=32,
    ))
