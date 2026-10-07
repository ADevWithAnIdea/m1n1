#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild queue two's complete partial submission and transport from source."""

import os
import sys

from agx_g17p_replay_latest_partial import execute_replay


SOURCE_SECOND_QUEUE_ARGS = (
    "--first-work-channel-pair", "2",
    "--first-work-descriptor-pair", "1",
    "--backend-queue-slot", "1",
    "--backend-first-work",
    "--backend-build-submission",
    "--build-first-optional-items",
    "--build-first-event-items",
    "--build-render-register-recipe",
    # Queue two carries eleven native lifecycle/telemetry values which the
    # source recipe intentionally emits in its tested inert form.  The
    # register numbers and every workload-facing value remain source-built.
    "--allow-register-recipe-differences",
    "--build-first-queue-transport",
    # This is the second native submission in the race-free snapshot.  The
    # queue-local item index is zero, while its global scheduler ordinal is one.
    "--backend-initial-submission-ordinal", "1",
)

SOURCE_SECOND_QUEUE_ENV = {
    # Paired render descriptors require both the per-item full-record fields
    # and the source-generated main/partial-store/resume/load tail programs.
    # The production DRM shim enables the same two established defaults.
    "G17P_NATIVE_TAIL_ITEM_FIELDS": "1",
    "G17P_STRUCTURAL_TAIL_FIELDS": "1",
}


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_replay_latest_partial_source.py accepts no arguments"
        )
    os.environ.update(SOURCE_SECOND_QUEUE_ENV)
    execute_replay(
        label="source_second_queue",
        extra_args=SOURCE_SECOND_QUEUE_ARGS,
    )


if __name__ == "__main__":
    main()
