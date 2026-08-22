#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the output-positive legacy opening at the pre-control boundary."""

import importlib.util
import os
import pathlib
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

os.environ["M1N1DEVICE"] = "/dev/m1n1-neo"
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"

# Import the common audit implementation, then remove the compact wrapper's
# import-time experiment selection before loading the ordinary cold boot.
import agx_g17p_audit_generated_first_control as audit  # noqa: E402

os.environ.pop("G17P_FINAL_26_6_CONTROL_LIFECYCLE", None)
os.environ.pop("G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE", None)


def load_boot_module():
    path = HERE / "agx_g17p_boot.py"
    name = "m1n1_g17p_drm_cold_boot"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    module = load_boot_module()
    audit.OUTPUT_PREFIX = "generated_legacy_first_control_audit"
    audit.BOUNDARY = (
        "legacy opening after both initdata acknowledgements, before control start"
    )
    module.FINAL_26_6_PRE_CONTROL_AUDIT = (
        lambda state: audit.capture_boundary(module, state))

    from m1n1.agx.shim import DRMAsahiShim

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        try:
            front.init()
        except audit.AuditComplete as result:
            print("AUDIT COMPLETE: %s" % result, flush=True)
            return 0
    raise RuntimeError("legacy pre-control audit callback was not reached")


if __name__ == "__main__":
    raise SystemExit(main())
