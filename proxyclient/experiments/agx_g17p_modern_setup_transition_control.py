#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the exact mixed transition after constructing modern UAPI state."""

import os
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"

from m1n1.agx import g17p_modern as modern  # noqa: E402
from m1n1.agx import g17p_uapi as uapi  # noqa: E402
import agx_g17p_render_to_compute_transition as control  # noqa: E402


PAGE = 0x4000
FD = 17
USC_BASE = 0x10000000000
ADDRESSES = (
    0x10000000000,
    0x100000A8000,
    0x100000C8000,
    0x100000F8000,
    0x10000030000,
    0x10000038000,
    0x10000040000,
)


class ModernSetupShim(control.DRMAsahiShim):
    def init(self):
        was_initialized = self.initialized
        result = super().init()
        if was_initialized or hasattr(self, "_modern_setup"):
            return result
        self._modern_setup = True
        os.ftruncate(self.memfd, (len(ADDRESSES) + 1) * PAGE)
        driver = self.modern
        vm = driver.create_vm(
            FD, modern.VM_END - modern.VM_KERNEL_MIN_SIZE, modern.VM_END)
        for index, address in enumerate(ADDRESSES, 1):
            bo = driver.create_bo(FD, index, (index - 1) * PAGE, PAGE)
            flags = uapi.DRM_ASAHI_BIND_READ
            if address not in (ADDRESSES[0], ADDRESSES[2]):
                flags |= uapi.DRM_ASAHI_BIND_WRITE
            driver.bind(
                FD,
                vm.vm_id,
                uapi.drm_asahi_gem_bind_op(flags, bo.handle, 0, PAGE, address),
            )
        timestamp_bo = driver.create_bo(
            FD, len(ADDRESSES) + 1, len(ADDRESSES) * PAGE, PAGE)
        driver.bind_object(
            FD,
            uapi.drm_asahi_gem_bind_object(
                uapi.DRM_ASAHI_BIND_OBJECT_OP_BIND,
                uapi.DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
                timestamp_bo.handle,
                0,
                0,
                PAGE,
                0,
                0,
            ),
        )
        driver.create_queue(FD, vm.vm_id, 0, USC_BASE)
        return result


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_modern_setup_transition_control.py accepts no arguments")
    control.DRMAsahiShim = ModernSetupShim
    return control.main()


if __name__ == "__main__":
    raise SystemExit(main())
