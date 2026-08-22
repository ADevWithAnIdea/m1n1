#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross CL2 wrap with native grid-4 queue storage and full history."""

import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from agx_g17p_compute_source_initial import main  # noqa: E402
from agx_g17p_compute_source_repeat258_native_ring_history import (  # noqa: E402
    NATIVE_OPTIONAL_OMISSIONS,
)
import agx_g17p_native_add3 as native  # noqa: E402


_queue_addresses = native._queue_addresses


def native_grid4_queue_addresses(slot):
    spec = _queue_addresses(slot)
    if int(slot) == 0:
        # Complete queue identity at the output-positive native CL2 wrap. The
        # earlier resource-only experiment omitted the pointer block and item
        # ring, so its queue record was not actually native-equivalent.
        spec.update({
            "pointers": 0xFFFFFC200166A870,
            "item_ring": 0xFFFFFC20C08B2870,
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
        persistent_runtime_queue=True,
        persistent_startup_queue=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_fresh_events=True,
        # The two captured publications after slot 255 are also two-item
        # groups, so preserve the native cadence across the wrap itself.
        persistent_runtime_optional_skip_ordinals=(
            NATIVE_OPTIONAL_OMISSIONS + (256, 257)),
        native_control_tail=True,
        suppress_runtime_controls=True,
    ))
