#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove a rendered target is visible to a later indirect compute command."""

from agx_g17p_compute_source_indirect import run


if __name__ == "__main__":
    raise SystemExit(run(
        repeat_workloads=2,
        client_slot_count=2,
        client_dispatch_grids=((64, 1, 1),) * 2,
        client_threadgroups=((32, 1, 1),) * 2,
        mixed_render_compute_dependency=True,
    ))
