#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the hardware-tested zero-capture G17P DRM-shim render."""

import pathlib
import os
import sys
import argparse

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


if __name__ == "__main__":
    # Keep the public invocation free of flags and environment configuration.
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat-fresh", type=int, default=1)
    parser.add_argument(
        "--fresh-target-stride", type=lambda value: int(value, 0),
        default=0x100000000,
    )
    parser.add_argument(
        "--seed-channel-index", type=lambda value: int(value, 0),
        default=None,
    )
    parser.add_argument("--verify-channel-backpressure", action="store_true")
    parser.add_argument("--verify-allocation-failure", action="store_true")
    parser.add_argument(
        "--pool-b-logical-bias", type=lambda value: int(value, 0), default=0,
    )
    parser.add_argument(
        "--seed-pair1-item-index", type=lambda value: int(value, 0), default=None,
    )
    parser.add_argument("--teardown-reuse", action="store_true")
    parser.add_argument("--teardown-queue-pair", action="store_true")
    parser.add_argument("--verify-pending-teardown", action="store_true")
    parser.add_argument("--teardown-execution-context", action="store_true")
    args = parser.parse_args()
    os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
    os.environ["M1N1HEAP_RESERVE"] = "1"
    from agx_g17p_shim_submit import main

    sys.argv[1:] = [
        "--width", "64", "--height", "64",
        "--drain-staged", "--repeat-fresh", str(args.repeat_fresh),
        "--fresh-target-stride", hex(args.fresh_target_stride),
        "--drm-color-attachment", "--witness-pages", "1",
    ]
    if args.seed_channel_index is not None:
        sys.argv[1:] += ["--seed-channel-index", hex(args.seed_channel_index)]
    if args.verify_channel_backpressure:
        sys.argv[1:] += ["--verify-channel-backpressure"]
    if args.verify_allocation_failure:
        sys.argv[1:] += ["--verify-allocation-failure"]
    if args.pool_b_logical_bias:
        sys.argv[1:] += ["--pool-b-logical-bias", hex(args.pool_b_logical_bias)]
    if args.seed_pair1_item_index is not None:
        sys.argv[1:] += ["--seed-pair1-item-index", hex(args.seed_pair1_item_index)]
    if args.teardown_reuse:
        sys.argv[1:] += ["--teardown-reuse"]
    if args.teardown_queue_pair:
        sys.argv[1:] += ["--teardown-queue-pair"]
    if args.verify_pending_teardown:
        sys.argv[1:] += ["--verify-pending-teardown"]
    if args.teardown_execution_context:
        sys.argv[1:] += ["--teardown-execution-context"]
    raise SystemExit(main())
