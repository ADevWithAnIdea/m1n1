#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gate one indirect compute submission on a preceding timeline point."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(
        repeat_workloads=3,
        client_slot_count=3,
        client_dispatch_grids=((64, 1, 1),) * 3,
        client_threadgroups=((32, 1, 1),) * 3,
        inter_submit_dependency_pair=True,
    ))
