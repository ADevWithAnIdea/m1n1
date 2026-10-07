#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cold-replay two native partial commands pending on one Metal queue."""

import json
import math
from pathlib import Path
import struct
import sys

from agx_g17p_replay_latest_partial import (
    DIAGNOSTIC_FLOAT_OFFSETS,
    OUTPUT_BASES,
    execute_replay,
)


OUTPUT_DVAS = tuple(
    OUTPUT_BASES[0] + attachment * 0x18000 + 0x4000
    for attachment in range(8)
)
SAME_QUEUE_SNAPSHOT = Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_partial_same_queue_two_pending_20260828_092206"
)


def validate_same_queue_outputs(attempt: Path):
    report = json.loads((attempt / "render_watch.json").read_text())
    by_dva = {int(record["dva"]): record for record in report}
    if set(by_dva) != set(OUTPUT_DVAS):
        raise RuntimeError(
            "same-queue render watch mismatch: expected %s, got %s"
            % ([hex(dva) for dva in OUTPUT_DVAS],
               [hex(dva) for dva in sorted(by_dva)])
        )

    values = []
    for attachment, dva in enumerate(OUTPUT_DVAS):
        record = by_dva[dva]
        if int(record["changed_bytes"]) == 0:
            raise RuntimeError(
                "same-queue attachment %d did not change" % attachment
            )
        body = (attempt / record["after_file"]).read_bytes()
        samples = [
            struct.unpack_from("<f", body, offset)[0]
            for offset in DIAGNOSTIC_FLOAT_OFFSETS
        ]
        expected = float(2 * (attachment + 1))
        if not all(
            math.isfinite(value) and abs(value - expected) < 0.05
            for value in samples
        ):
            raise RuntimeError(
                "same-queue attachment %d expected %.1f, got %r"
                % (attachment, expected, samples)
            )
        values.append(samples[0])
    print("SAME-QUEUE TWO-COMMAND OUTPUT PASS: %s" % values)


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_replay_latest_partial_same_queue.py accepts no arguments"
        )
    execute_replay(
        label="same_queue_two_pending",
        output_dvas=OUTPUT_DVAS,
        validate=validate_same_queue_outputs,
        snapshot=SAME_QUEUE_SNAPSHOT,
    )


if __name__ == "__main__":
    main()
