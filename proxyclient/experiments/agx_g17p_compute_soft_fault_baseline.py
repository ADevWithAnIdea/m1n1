#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove the soft-fault experiment's identical mapped-output baseline."""

from agx_g17p_compute_soft_fault import main


if __name__ == "__main__":
    raise SystemExit(main(inject_soft_fault=False))
