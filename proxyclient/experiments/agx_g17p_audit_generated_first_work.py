#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit source-built state after 0x84 and before its first work publication."""

import tempfile

import agx_g17p_audit_generated_first_control as audit
from agx_g17p_compute_relocated_control import install_relocated_boot_module


REFERENCE = (
    audit.ARTIFACTS /
    "native_first_cl0_preconsume_20260812_024043"
)


def main():
    module = install_relocated_boot_module()
    audit.REFERENCE = REFERENCE
    audit.OUTPUT_PREFIX = "generated_first_work_audit"
    audit.BOUNDARY = (
        "after source first-work preparation in the 0x84-to-0x83 interval, "
        "before producer publication"
    )
    module.FINAL_26_6_FIRST_WORK_AUDIT = (
        lambda prepared: audit.capture_boundary(module, prepared)
    )

    from m1n1.agx.shim import DRMAsahiShim

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        try:
            front.init()
        except audit.AuditComplete as result:
            print("AUDIT COMPLETE: %s" % result, flush=True)
            return 0
    raise RuntimeError("pre-first-work audit callback was not reached")


if __name__ == "__main__":
    raise SystemExit(main())
