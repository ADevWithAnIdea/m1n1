#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove valid indirect compute continues after one shader soft fault."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(
        repeat_workloads=3,
        client_slot_count=3,
        client_dispatch_grids=((64, 1, 1),) * 3,
        client_threadgroups=((32, 1, 1),) * 3,
        soft_fault_ordinal=1,
    ))
