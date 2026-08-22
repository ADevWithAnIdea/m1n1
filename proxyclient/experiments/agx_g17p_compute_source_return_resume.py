#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resume source command 2 after returning the one-command bootstrap state."""

import os

os.environ.setdefault("G17P_STAGE_FINGERPRINT", "1")

import agx_g17p_compute_source_initial as source
import agx_g17p_native_add3 as native


def main():
    state = source.main(
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
        persistent_runtime_queue=True,
        persistent_startup_queue=True,
        persistent_runtime_fresh_descriptors=True,
        persistent_runtime_fresh_events=True,
        fast_sequential=True,
        strict_release_publish=True,
        prestage_return_next=True,
        notify_prestaged_before_return=True,
        return_state=True,
    )
    retained = state["modern_direct_bootstrap"]
    if "staged" not in retained:
        raise RuntimeError("source return/resume did not retain staged state")
    prepared = retained.get("prepared_next")
    if prepared is None:
        raise RuntimeError("source return/resume did not retain prepared work")
    if not retained.get("prepared_next_notified"):
        raise RuntimeError("source return/resume did not ring retained work")
    result = native.await_next_workload(retained["backend"], prepared)
    controls = state["read_control_counters"]()
    if controls["primary"] != [171, 171, 171]:
        raise RuntimeError(
            "source return/resume control history drifted: %r" % controls)
    print(
        "SOURCE RETURN/RESUME synchronized control counters: %r" % controls,
        flush=True,
    )
    print(
        "SOURCE RETURN/RESUME PASS: command 2 exact output; queue=%r channel=%r" %
        (result["queue"], result["channel"]),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
