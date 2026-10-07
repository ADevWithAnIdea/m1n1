#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Append source-built command three to the working same-queue partial replay."""

import json
import math
import os
from pathlib import Path
import struct
import sys

from agx_g17p_replay_latest_partial_same_queue import (
    DIAGNOSTIC_FLOAT_OFFSETS,
    OUTPUT_DVAS,
    SAME_QUEUE_SNAPSHOT,
    validate_same_queue_outputs,
)
from agx_g17p_replay_latest_partial import execute_replay
from agx_g17p_replay_latest_partial_source import SOURCE_SECOND_QUEUE_ENV
from agx_g17p_replay_same_queue_source_second import (
    SOURCE_SECOND_COMMAND_ARGS,
)


SOURCE_THIRD_COMMAND_ARGS = SOURCE_SECOND_COMMAND_ARGS + (
    "--backend-publish-fresh-item",
    # The two-owner capture proves independent first-item PB graphs.  Test the
    # same ownership split at global command three while keeping its persistent
    # transport queue and queue-context slot unchanged.
    "--backend-fresh-graph-per-item",
    "--backend-read-channels",
    "--backend-publish-group-number", "3",
    # The command-two snapshot leaves the packed host dispatch count at one.
    # Firmware advances only the adjacent completion words. Command three is
    # the first replay-built publication that must explicitly publish count
    # two, as the production shim does in _apply_per_group_resources().
    "--backend-packed-dispatch-count", "2",
    # Preserve the native publication protocol, not merely its final bytes:
    # fragment producer at lifecycle phase one, then TA at phase two.
    "--backend-phased-lifecycle-publication",
) + tuple(
    value
    for dva in OUTPUT_DVAS
    for value in ("--backend-clear-render-before-publish", hex(dva))
)


def validate_three_commands(attempt):
    # The initial readback proves native command one plus source command two.
    # Command three is submitted only after that semantic fence; its input
    # attachments are cleared first, so its own readback must reproduce 1..8.
    validate_same_queue_outputs(attempt)
    report = json.loads(
        (attempt / "backend_fresh_0001_render_watch.json").read_text()
    )
    by_dva = {int(record["dva"]): record for record in report}
    if set(by_dva) != set(OUTPUT_DVAS):
        raise RuntimeError("same-queue render watch set mismatch")

    values = []
    for attachment, dva in enumerate(OUTPUT_DVAS):
        record = by_dva[dva]
        if int(record["nonzero_bytes"]) == 0:
            raise RuntimeError(
                "same-queue attachment %d did not change" % attachment
            )
        body = (attempt / record["after_file"]).read_bytes()
        samples = [
            struct.unpack_from("<f", body, offset)[0]
            for offset in DIAGNOSTIC_FLOAT_OFFSETS
        ]
        expected = float(attachment + 1)
        if not all(
            math.isfinite(value) and abs(value - expected) < 0.04
            for value in samples
        ):
            raise RuntimeError(
                "same-queue attachment %d expected %.1f, got %r"
                % (attachment, expected, samples)
            )
        values.append(samples[0])
    print("SAME-QUEUE SOURCE COMMAND THREE OUTPUT PASS: %s" % values)


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_replay_same_queue_source_third.py accepts no arguments"
        )
    os.environ.update(SOURCE_SECOND_QUEUE_ENV)
    execute_replay(
        label="same_queue_source_third",
        extra_args=SOURCE_THIRD_COMMAND_ARGS,
        output_dvas=OUTPUT_DVAS,
        validate=validate_three_commands,
        snapshot=Path(SAME_QUEUE_SNAPSHOT),
        bootstrap=os.environ.get("G17P_SKIP_BOOTSTRAP") != "1",
    )


if __name__ == "__main__":
    main()
