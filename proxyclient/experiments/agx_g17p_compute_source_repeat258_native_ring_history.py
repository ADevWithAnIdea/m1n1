#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross CL2 wrap after reproducing native's complete item-count history."""

from agx_g17p_compute_source_initial import main


# Hardware-observed groups that contain descriptor + event, without the optional
# item. All other ordinals through 255 contain descriptor + optional + event.
NATIVE_OPTIONAL_OMISSIONS = (
    5, 10, 14, 15, 16, 19, 21, 25, 28, 29, 30, 33, 34, 35, 36, 37,
    41, 46, 47, 48, 51, 53, 55, 56, 57, 60, 63, 65, 70, 71, 87, 88,
    90, 96, 100, 101, 106, 109, 123, 124, 125, 126, 127, 128, 129,
    130, 131, 132, 147, 148, 149, 150, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 165, 166, 167, 168, 169, 170, 172, 173, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 186, 187, 189, 190, 191,
    194, 195, 196, 197, 199, 200, 201, 202, 203, 204, 205, 206, 208,
    210, 211, 212, 213, 218, 219, 220, 221, 222, 223, 224, 226, 227,
    228, 229, 230, 231, 232, 233, 234, 236, 239, 240, 245, 246, 247,
    248, 249, 250, 251, 253, 254, 255,
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
        persistent_runtime_optional_skip_ordinals=NATIVE_OPTIONAL_OMISSIONS,
        native_control_tail=True,
        suppress_runtime_controls=True,
    ))
