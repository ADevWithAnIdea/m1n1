#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove a render fence orders a dependent final-26.6 compute command."""

import os
import pathlib
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"

from m1n1.agx.shim import DRMAsahiShim  # noqa: E402


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_render_then_compute_fence.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        # Import only after the ordinary render cold boot is selected because
        # the compute module fixes process-wide experiment defaults.
        from agx_g17p_compute import run_probe

        return run_probe(
            front, backend, trigger="work", render_dependency=True)


if __name__ == "__main__":
    raise SystemExit(main())
