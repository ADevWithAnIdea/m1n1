#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the native four-workload queue cadence after its registration gate."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=4,
        secondary_opening_only=True,
        native_runtime_tick_context=True,
        no_late_fourth_control=True,
        pre_runtime_native_gate=True,
    ))
