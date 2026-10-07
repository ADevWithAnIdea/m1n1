#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test processed source lifecycle config with an otherwise field-built CL2."""

import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from agx_g17p_compute_source_initial import main  # noqa: E402


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_compute_source_initial_graft.py accepts no arguments")
    raise SystemExit(main(graft_source_config=True))
