#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross CL2 wrap using the exact native 300-command queue identity."""

import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from agx_g17p_compute_source_initial import main  # noqa: E402
import agx_g17p_native_add3 as native  # noqa: E402


_queue_addresses = native._queue_addresses


def native_owner_queue_addresses(slot):
    spec = _queue_addresses(slot)
    if int(slot) == 0:
        spec.update({
            "queue": 0xFFFFFC20C0000180,
            "grid": 2,
            "uuid": 0x131,
        })
    return spec


native._queue_addresses = native_owner_queue_addresses


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
        couple_runtime_ticks=True,
        native_runtime_tick_context=True,
        persistent_runtime_queue=True,
        persistent_startup_queue=True,
        persistent_runtime_optional_once=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_tick_once=True,
        persistent_runtime_optional_skip_ordinals=(200,),
    ))
