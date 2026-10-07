#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove a nonempty UAPI sampler heap on an exact native compute dispatch."""

from agx_g17p_modern_compute import main


if __name__ == "__main__":
    raise SystemExit(main(use_sampler=True))
