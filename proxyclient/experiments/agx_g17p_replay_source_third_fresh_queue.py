#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run source command three as first work on a fresh queue and PB graph."""

import os
from pathlib import Path
import sys

from agx_g17p_replay_latest_partial import execute_replay
from agx_g17p_replay_latest_partial_same_queue import (
    OUTPUT_DVAS,
    SAME_QUEUE_SNAPSHOT,
)
from agx_g17p_replay_latest_partial_source import SOURCE_SECOND_QUEUE_ENV
from agx_g17p_replay_same_queue_source_third import (
    SOURCE_THIRD_COMMAND_ARGS,
    validate_three_commands,
)


SOURCE_THIRD_FRESH_QUEUE_ARGS = tuple(
    argument
    for argument in SOURCE_THIRD_COMMAND_ARGS
    if argument != "--backend-phased-lifecycle-publication"
) + (
    # The coherent two-owner replay establishes that a fresh PB graph is
    # coupled to a fresh transport owner.  Allocate the complete ownership
    # unit and announce this as that queue's opening group.
    # This checkpoint has only one logical queue owner (grids 0/1), even
    # though it has two commands.  The next owner is therefore grids 2/3.
    # Grid 4/5 is correct only in the two-owner checkpoint.
    "--backend-create-queue", "2",
    "--backend-allocate-queue-record",
    "--backend-publish-first-submit",
    # Every captured live queue leaves the has-commands word clear.  Writing
    # the old diagnostic 1/0 sequence can wedge an otherwise valid fresh
    # queue before it consumes the inner ring.
    "--backend-skip-publish-announce",
    # Queue/context/job-list/ring allocation happens after firmware starts.
    # Keep mapped pages aside after all descriptor graphs have been built.
    "--backend-reserve-pages", "2",
)


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_replay_source_third_fresh_queue.py accepts no arguments"
        )
    os.environ.update(SOURCE_SECOND_QUEUE_ENV)
    execute_replay(
        label="source_third_fresh_queue",
        extra_args=SOURCE_THIRD_FRESH_QUEUE_ARGS,
        output_dvas=OUTPUT_DVAS,
        validate=validate_three_commands,
        snapshot=Path(SAME_QUEUE_SNAPSHOT),
        bootstrap=os.environ.get("G17P_SKIP_BOOTSTRAP") != "1",
    )


if __name__ == "__main__":
    main()
