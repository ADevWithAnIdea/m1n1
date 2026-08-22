#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run two source workloads with the modern shim's exact bootstrap options."""

import os

os.environ.setdefault("G17P_STAGE_FINGERPRINT", "1")

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=2,
        firmware_item_capacity=258,
        client_workload_capacity=2,
        secondary_opening_only=True,
        post_start_initial=True,
        native_control_tail=True,
        suppress_runtime_controls=True,
        drain_runtime_reports=True,
        drain_runtime_report_interval=1,
        persistent_runtime_queue=True,
        persistent_startup_queue=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_fresh_events=True,
        fast_sequential=True,
        strict_release_publish=True,
    ))
