#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test the native three-slot client hardware context table."""

from agx_g17p_compute_source_initial import main


if __name__ == "__main__":
    raise SystemExit(main(exact_client_context_table=True))
