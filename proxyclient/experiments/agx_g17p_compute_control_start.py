#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Submit the compact add3 before a second firmware control-start."""

from agx_g17p_compute import main


if __name__ == "__main__":
    raise SystemExit(main(trigger="control-start"))
