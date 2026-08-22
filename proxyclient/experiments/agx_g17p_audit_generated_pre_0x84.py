#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture compact source state after control publication and before 0x84."""

import struct
import tempfile
import time

import agx_g17p_audit_generated_first_control as audit
from agx_g17p_compute_relocated_control import install_relocated_boot_module


def main():
    module = install_relocated_boot_module()
    state_holder = {}

    def remember_state(state):
        state_holder["state"] = state

    module.FINAL_26_6_PRE_CONTROL_AUDIT = remember_state

    def counters(instance):
        from m1n1.agx import g17p

        values = []
        for pa in instance["channel_state_pas"][
                g17p.CHANNEL_TABLE_WORK_COUNT][:3]:
            module.p.dc_civac(pa, 4)
            values.append(struct.unpack(
                "<I", bytes(module.iface.readmem(pa, 4)))[0])
        return values

    def capture_before_0x84(instances, ascs):
        expected = [[1, 1, 2], [1, 1, 19]]
        deadline = time.monotonic() + 0.1
        observed = [counters(instance) for instance in instances]
        while time.monotonic() < deadline and observed != expected:
            for asc in ascs:
                asc.work_pending()
            time.sleep(0.001)
            observed = [counters(instance) for instance in instances]
        if observed != expected:
            raise RuntimeError(
                "published pre-0x84 counters did not reach %r: %r" %
                (expected, observed)
            )
        print(
            "CONTROL PUBLISHED: %r; capturing before primary 0x84" % observed,
            flush=True,
        )
        audit.capture_boundary(module, state_holder["state"])

    module.FINAL_26_6_PRE_0X84_AUDIT = capture_before_0x84
    audit.OUTPUT_PREFIX = "generated_exact_pre_0x84_audit"
    audit.BOUNDARY = (
        "after source control publication at [1,1,2]/[1,1,19], before 0x84"
    )

    from m1n1.agx.shim import DRMAsahiShim

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        try:
            front.init()
        except audit.AuditComplete as result:
            print("AUDIT COMPLETE: %s" % result, flush=True)
            return 0
    raise RuntimeError("published pre-0x84 audit boundary was not reached")


if __name__ == "__main__":
    raise SystemExit(main())
