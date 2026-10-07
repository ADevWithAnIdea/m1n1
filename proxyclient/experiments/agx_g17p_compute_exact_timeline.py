#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the native pre-CL2 control timeline over the proven cold boot."""

import os


os.environ["M1N1DEVICE"] = "/dev/m1n1-neo"
os.environ["G17P_COMPUTE_PAIR1_PRELUDE"] = "1"
os.environ["G17P_COMPUTE_NATIVE_LIFECYCLE"] = "1"
os.environ["G17P_NATIVE_CONTROL_PREFIX"] = "1"
os.environ["G17P_FINAL_26_6_SECONDARY_LIFECYCLE"] = "1"
os.environ["G17P_FINAL_26_6_SECONDARY_TARGET"] = "36"
os.environ["G17P_COMPUTE_NATIVE_SCHEDULER_WIDTH"] = "1"
os.environ["G17P_COMPUTE_EXACT_OUTER_SCHEDULE"] = "1"
os.environ["G17P_NATIVE_CONTEXT2_PRIMARY_CHANNEL"] = "1"
os.environ["G17P_SHARE_BOUND_SUBMISSION_STATE"] = "0"
os.environ["G17P_SHARE_BOUND_RECORD_POOLS"] = "0"
os.environ["G17P_COMPUTE_RUNTIME_GRAPH_PHASE"] = "pre_cadence"
os.environ["G17P_COMPUTE_RUNTIME_GRAPH_LOCAL_INDEX"] = "0"
os.environ["G17P_COMPUTE_CAPTURE_RUNTIME_GRAPH"] = "0"
os.environ["G17P_COMPUTE_INACTIVE_CLASS2_RENDERS"] = "3"
os.environ["G17P_COMPUTE_POST_CLASS1_RENDERS"] = "2"
os.environ["G17P_COMPUTE_EXACT_NATIVE_CL2"] = "1"
os.environ["G17P_COMPUTE_EXACT_NATIVE_CHANNEL"] = "0"
os.environ["G17P_COMPUTE_NATIVE_CLIENT_REPLAY"] = "1"
os.environ["G17P_COMPUTE_EXACT_TIMELINE_WORK_INDICES"] = "40"
os.environ["G17P_COMPUTE_EXACT_INDEX32_WORK_COUNT"] = "1"
os.environ["G17P_COMPUTE_EXACT_TIMELINE_CHANNEL"] = "0"
os.environ["G17P_COMPUTE_EXACT_GENERATED_PREFIX"] = "1"
os.environ["G17P_COMPUTE_EXACT_BATCH_AFTER_40"] = "0"
os.environ["G17P_COMPUTE_EXACT_CONTROL_TIMELINE"] = (
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260810_031541/"
    "device_control_timeline.jsonl"
)

from agx_g17p_compute_lifecycle_archive import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
