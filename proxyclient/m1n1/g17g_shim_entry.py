# SPDX-License-Identifier: GPL-2.0-only
"""Lazy, generation-gated entrypoint for the native G17G DRM bridge."""
from pathlib import Path
import os

from .drm_shim.g17g_ioctl import G17GIoctlShim


class Shim(G17GIoctlShim):
    def __init__(self, backing_fd, memory):
        super().__init__(backing_fd, memory, driver_factory=self._connect,
                         params=self._get_params, get_time=self._get_time)
        self.boot = None
        self.device_info = None
        self.boot_profile = os.environ.get("G17G_BOOT_PROFILE", "compute")
        if self.boot_profile not in ("compute", "mixed"):
            raise ValueError("G17G_BOOT_PROFILE must be compute or mixed")
        self.tvb_max_blocks = int(os.environ.get('G17G_TVB_MAX_BLOCKS', '1484'), 0)
        if not 3 <= self.tvb_max_blocks <= 1484:
            raise ValueError('G17G_TVB_MAX_BLOCKS must be between 3 and 1484')

    def _info_call(self, method):
        import errno
        from .drm_shim.g17g_info import G17GDeviceInfo
        driver = self._driver()
        with driver._ownership_lock:
            if driver.adapter.device_lost:
                raise OSError(errno.ENODEV, "G17G GPU reset required")
            if self.device_info is None:
                self.device_info = G17GDeviceInfo(self.boot.u)
            return getattr(self.device_info, method)()

    def _get_params(self):
        return self._info_call("get_params")

    def _get_time(self):
        return self._info_call("get_time")

    def _connect(self, backing_fd):
        # No setup side effects until the first operation requiring hardware.
        if not os.environ.get("M1N1DEVICE"):
            raise RuntimeError("set M1N1DEVICE to the target proxy connection")
        directory = Path(os.environ["G17G_CRASH_DIRECTORY"])
        if not directory.is_dir():
            raise ValueError("G17G_CRASH_DIRECTORY must already exist")
        from .proxy import UartInterface, M1N1Proxy
        from .proxyutils import bootstrap_port, ProxyUtils
        from .drm_shim.g17g_boot import G17GBootRuntime
        from .drm_shim.g17g_adapter import G17GHardwareAdapter
        from .drm_shim.g17g_modern import G17GModernDriver
        iface = UartInterface()
        proxy = M1N1Proxy(iface, debug=False)
        bootstrap_port(iface, proxy)
        u = ProxyUtils(proxy)
        self.boot = G17GBootRuntime(u, directory)
        self.boot.boot(profile=self.boot_profile)
        adapter = G17GHardwareAdapter(self.boot, lambda _file: backing_fd,
                                     tvb_growth=self.boot_profile != "mixed",
                                     tvb_max_blocks=self.tvb_max_blocks if self.boot_profile != "mixed" else None)
        return G17GModernDriver(adapter, strict_syncs=True)
