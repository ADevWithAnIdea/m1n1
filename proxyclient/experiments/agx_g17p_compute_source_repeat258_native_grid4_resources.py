#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross CL2 wrap with grid-4's native job-list/control tuple."""

import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from agx_g17p_compute_source_initial import main  # noqa: E402
import agx_g17p_native_add3 as native  # noqa: E402


_queue_addresses = native._queue_addresses


def native_grid4_queue_addresses(slot):
    spec = _queue_addresses(slot)
    if int(slot) == 0:
        # Native's output-positive queue at ...0300 names the second shared
        # job-list head and the third 0x40-byte channel-control record.
        spec.update({
            "job_list": 0xFFFFFC2000000030,
            "channel_control": 0xFFFFFC20C07B8080,
            "channel_control_style": 0,
            "uuid": 0x145,
        })
    return spec


native._queue_addresses = native_grid4_queue_addresses


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
