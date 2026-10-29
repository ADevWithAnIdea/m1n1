# SPDX-License-Identifier: GPL-2.0-only
"""The native entrypoint connects directly to the real firmware adapter."""

import importlib.abc
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "proxyclient"))

from m1n1.g17g_shim_entry import Shim
from m1n1.drm_shim.g17g_boot import G17GBootRuntime
from m1n1.drm_shim.g17g_adapter import G17GHardwareAdapter


class NoHypervisor(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "m1n1.setup" or fullname.startswith("m1n1.hv"):
            raise AssertionError("firmware shim imported hypervisor setup")


class TestNativeEntry(unittest.TestCase):
    def test_proxy_connection_reaches_firmware_boot_and_adapter_without_hv(self):
        with tempfile.TemporaryFile() as backing, tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, M1N1DEVICE="/unused-test-proxy",
                            G17G_CRASH_DIRECTORY=directory, G17G_BOOT_PROFILE="compute"):
                shim = Shim(backing.fileno(), Mock())
                guard = NoHypervisor()
                sys.meta_path.insert(0, guard)
                try:
                    with patch("m1n1.proxy.UartInterface") as iface, \
                         patch("m1n1.proxy.M1N1Proxy") as proxy, \
                         patch("m1n1.proxyutils.bootstrap_port") as bootstrap, \
                         patch("m1n1.proxyutils.ProxyUtils") as util, \
                         patch("m1n1.drm_shim.g17g_boot.G17GBootRuntime",
                               spec=G17GBootRuntime) as boot, \
                         patch("m1n1.drm_shim.g17g_adapter.G17GHardwareAdapter",
                               spec=G17GHardwareAdapter) as adapter:
                        driver = shim._connect(backing.fileno())
                finally:
                    sys.meta_path.remove(guard)
                iface.assert_called_once_with()
                proxy.assert_called_once_with(iface.return_value, debug=False)
                bootstrap.assert_called_once_with(iface.return_value, proxy.return_value)
                util.assert_called_once_with(proxy.return_value)
                boot.assert_called_once_with(util.return_value, Path(directory))
                boot.return_value.boot.assert_called_once_with(profile="compute")
                self.assertIs(driver.adapter, adapter.return_value)
                self.assertIs(shim.boot, boot.return_value)
                adapter.assert_called_once()
                os.close(shim.backing_fd)

    def test_no_proxy_configuration_fails_before_connection(self):
        with tempfile.TemporaryFile() as backing:
            shim = Shim(backing.fileno(), Mock())
            with patch.dict(os.environ, {}, clear=True), \
                 patch("m1n1.proxy.UartInterface") as iface:
                with self.assertRaisesRegex(RuntimeError, "M1N1DEVICE"):
                    shim._connect(backing.fileno())
                iface.assert_not_called()
            os.close(shim.backing_fd)
