#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Zero-capture source boot followed by one exact field-built add3 submit."""

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
os.environ["G17P_NATIVE_CONTROL_PREFIX"] = "1"

from m1n1.agx.shim import DRMAsahiShim  # noqa: E402

from agx_g17p_native_add3 import (  # noqa: E402
    build_client_graph,
    submit_built,
)
from agx_g17p_native_compute_lifecycle import (  # noqa: E402
    advance_native_compute_lifecycle,
    install_late_control_graph,
)


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute_source.py accepts no arguments")
    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        client = build_client_graph(backend)
        advance_native_compute_lifecycle(
            front,
            backend,
            client,
            prepare_late_controls=lambda: install_late_control_graph(backend),
        )
        submit_built(front, backend, client)
        print(
            "SOURCE COMPUTE PASS: zero captured bytes, source-built firmware "
            "lifecycle, source-built exact add3 graph",
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
