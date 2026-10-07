#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cold-replay three native partial encoders from one command buffer."""

import json
import math
import os
from pathlib import Path
import struct

from agx_g17p_replay_latest_partial import OUTPUT_BASES, execute_replay


OUTPUT_DVAS = tuple(
    OUTPUT_BASES[0] + attachment * 0x18000 + 0x4000
    for attachment in range(8)
)
DIAGNOSTIC_FLOAT_OFFSETS = (16124, 16128)


def validate_three_encoder_outputs(attempt):
    report = json.loads((attempt / "render_watch.json").read_text())
    by_dva = {int(record["dva"]): record for record in report}
    if set(by_dva) != set(OUTPUT_DVAS):
        raise RuntimeError("three-encoder render watch set mismatch")

    values = []
    for attachment, dva in enumerate(OUTPUT_DVAS):
        record = by_dva[dva]
        if int(record["changed_bytes"]) == 0:
            raise RuntimeError("attachment %d did not change" % attachment)
        body = (attempt / record["after_file"]).read_bytes()
        samples = [
            struct.unpack_from("<f", body, offset)[0]
            for offset in DIAGNOSTIC_FLOAT_OFFSETS
        ]
        expected = 3.0 * (attachment + 1)
        if not all(
            math.isfinite(value) and abs(value - expected) < 0.06
            for value in samples
        ):
            raise RuntimeError(
                "attachment %d expected %.1f, got %r"
                % (attachment, expected, samples)
            )
        values.append(samples[0])
    print("THREE-ENCODER SAME-QUEUE OUTPUT PASS: %s" % values)


def main():
    snapshot_text = os.environ.get("G17P_THREE_ENCODER_SNAPSHOT")
    if not snapshot_text:
        raise SystemExit("set G17P_THREE_ENCODER_SNAPSHOT to the capture")
    execute_replay(
        label="three_encoders_one_command",
        snapshot=Path(snapshot_text),
        output_dvas=OUTPUT_DVAS,
        validate=validate_three_encoder_outputs,
        # Firmware reports command-buffer completion once after all three
        # render encoders, rather than one event per encoder.
        wait_for_work_events=1,
    )


if __name__ == "__main__":
    main()
