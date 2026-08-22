#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retire the source-built final-26.6 control opening without publishing work."""

import json
import tempfile

from agx_g17p_compute_relocated_control import install_relocated_boot_module


class ControlOnlyComplete(RuntimeError):
    def __init__(self, result):
        super().__init__(json.dumps(result, sort_keys=True))
        self.result = result


def main():
    module = install_relocated_boot_module()
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
                    "source-built compact control did not retire: %r" % result
                )
            if result["first_work"] != {"work_published": False}:
                raise RuntimeError("control-only callback published work")
            print(
                "COMPACT CONTROL-ONLY PASS: %s" %
                json.dumps(result, sort_keys=True),
                flush=True,
            )
            return 0
    raise RuntimeError("compact control-only boundary was not reached")


if __name__ == "__main__":
    raise SystemExit(main())
