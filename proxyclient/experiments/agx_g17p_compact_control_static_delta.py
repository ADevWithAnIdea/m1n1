#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test selected stable native pre-0x84 status/config deltas without work."""

import argparse
import json
import os
import struct
import tempfile

from agx_g17p_compute_relocated_control import install_relocated_boot_module


class ControlOnlyComplete(RuntimeError):
    def __init__(self, result):
        super().__init__(json.dumps(result, sort_keys=True))
        self.result = result


GROUPS = {
    "all": ("cfg4018", "cfg4020", "cfg40b0", "fwctl", "region"),
    "config": ("cfg4018", "cfg4020", "cfg40b0"),
    "fwctl": ("fwctl",),
    "region": ("region",),
    "config_fwctl": ("cfg4018", "cfg4020", "cfg40b0", "fwctl"),
    "config_region": ("cfg4018", "cfg4020", "cfg40b0", "region"),
    "fwctl_region": ("fwctl", "region"),
    "cfg4018": ("cfg4018",),
    "cfg4020": ("cfg4020",),
    "cfg40b0": ("cfg40b0",),
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "group",
        nargs="?",
        default="all",
        choices=GROUPS,
        help="native pre-0x84 field group to apply (default: all)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    os.environ["G17P_FINAL_26_6_SECONDARY_TARGET"] = "1"
    module = install_relocated_boot_module()

    def patch_static_delta(instances, ascs):
        del ascs
        primary = instances[0]
        status_b_pa = primary["status_b_pa"]
        kern_va_base = (
            primary["state_va"] - module.g17p.NATIVE_PRIMARY_WORK_STATE_OFFSET
        )
        fwctl_va = kern_va_base + module.g17p.NATIVE_FWCTL_OFFSET
        candidates = {
            "cfg4018": (
                (status_b_pa + 0x4018,
                 struct.pack("<Q", 0x0005060100000000)),
            ),
            "cfg4020": (
                (status_b_pa + 0x4020, struct.pack("<Q", 61)),
            ),
            "cfg40b0": (
                (status_b_pa + 0x40b0, struct.pack("<Q", 5)),
            ),
            "fwctl": (
                (status_b_pa + 0x48e0, struct.pack("<Q", fwctl_va)),
                (status_b_pa + 0x48e8, struct.pack(
                    "<Q", fwctl_va + module.g17p.CONTROL_MESSAGE_SIZE)),
            ),
            "region": (
                (primary["region_c_pa"] + 0x0e50,
                 struct.pack("<I", 0x100)),
            ),
        }
        writes = tuple(
            write
            for name in GROUPS[args.group]
            for write in candidates[name]
        )
        for address, body in writes:
            module.iface.writemem(address, body)
            module.p.dc_civac(address, len(body))
        module.u.inst("dsb sy")
        print(
            "STATIC PRE-0X84 DELTA: group=%s patched %d source fields; "
            "secondary held at 1" % (args.group, len(writes)),
            flush=True,
        )

    module.FINAL_26_6_PRE_0X84_AUDIT = patch_static_delta
    original = module.publish_final_26_6_control_lifecycle

    def publish_control_only(instances, ascs, publish_primary=True,
                             first_work_callback=None):
        del first_work_callback
        result = original(
            instances,
            ascs,
            publish_primary=publish_primary,
            first_work_callback=lambda _ascs: {"work_published": False},
        )
        raise ControlOnlyComplete(result)

    module.publish_final_26_6_control_lifecycle = publish_control_only

    from m1n1.agx.shim import DRMAsahiShim

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        try:
            front.init()
        except ControlOnlyComplete as complete:
            result = complete.result
            if not result["retired"]:
                raise RuntimeError(
                    "static-delta compact control did not retire: %r" % result
                )
            if result["first_work"] != {"work_published": False}:
                raise RuntimeError("static-delta control test published work")
            print(
                "STATIC-DELTA CONTROL PASS: group=%s %s" %
                (args.group, json.dumps(result, sort_keys=True)),
                flush=True,
            )
            return 0
    raise RuntimeError("static-delta control-only boundary was not reached")


if __name__ == "__main__":
    raise SystemExit(main())
