#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the modern compute queue/helper register block on G17P."""

import sys

# Load the source harness before any AGX module. It sets the G17 environment
# and installs the relocated cold-boot module before loading the workload
# builder; doing either import early leaves the nested boot hooks bound to a
# partially initialized module.
from agx_g17p_compute_source_initial import main as run_source_compute
import agx_g17p_native_add3 as native
from m1n1.agx import g17p_compute


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_compute_uapi_registers.py accepts no arguments")

    original = native._registers_for_workload
    overlays = []

    def uapi_registers(*args, **kwargs):
        registers = original(*args, **kwargs)
        preempt = g17p_compute.register_value(registers, 0x1A510)
        cdm = g17p_compute.register_value(registers, 0x1A420)
        registers = g17p_compute.apply_compute_uapi_registers(
            registers,
            preempt_base=preempt,
            cdm_base=cdm,
            usc_exec_base=0x10000000000,
        )
        if len(registers) != 40:
            raise RuntimeError(
                "expected 40 compute registers, got %d" % len(registers))
        expected = {
            0x10071: 0x10000000000,
            0x11841: 0,
            0x11849: 0,
            0x11F81: 0,
        }
        actual = {
            register: g17p_compute.register_value(registers, register)
            for register in g17p_compute.COMPUTE_UAPI_REGISTERS
        }
        if actual != expected:
            raise RuntimeError(
                "compute UAPI register mismatch: %r" % actual)
        overlays.append(actual)
        return registers

    native._registers_for_workload = uapi_registers

    result = run_source_compute(
        exact_client_context_table=True,
        alias_context0_queue=True,
        native_shader_attributes=True,
        repeat_workloads=3,
    )
    if len(overlays) < 3:
        raise RuntimeError(
            "expected at least three overlaid descriptors, got %d" %
            len(overlays))
    print(
        "COMPUTE UAPI REGISTERS PASS: three exact outputs with "
        "USC_EXEC_BASE_CP and zero helper registers in every descriptor",
        flush=True,
    )
    return result


if __name__ == "__main__":
    raise SystemExit(main())
