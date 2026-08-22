#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the retained source-built G17P compute positive with no caller work."""

import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from agx_g17p_compute_source_initial import main as source_main  # noqa: E402


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute_source_control.py accepts no arguments")
    source_main(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=1,
        firmware_item_capacity=258,
        client_workload_capacity=2,
        secondary_opening_only=True,
        post_start_initial=True,
        native_control_tail=True,
        suppress_runtime_controls=True,
        drain_runtime_reports=True,
        drain_runtime_report_interval=1,
    )
    print(
        "SOURCE COMPUTE CONTROL PASS: exact retained add3 workload and "
        "zero capture content",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
