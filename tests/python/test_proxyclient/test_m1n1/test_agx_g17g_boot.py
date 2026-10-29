# SPDX-License-Identifier: GPL-2.0-only
from contextlib import nullcontext
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from m1n1.drm_shim import g17g_boot as boot
from m1n1.drm_shim.g17g_crash import G17GDataOnlyCrashEndpoint
from m1n1.drm_shim.g17g_sync import G17GPublishedFault


class TestBootRuntime(unittest.TestCase):

    def test_page_ranges_validate_before_touching_proxy(self):
        self.assertEqual(boot.physical_page_runs((0x10000, 0x8000, 0xc000, 0x8000)),
                         ((0x8000, 0xc000),))
        self.assertEqual(boot.physical_page_runs(()), ())
        for pa in (0, -0x4000, 1, True, 1 << 42, "0x8000"):
            util = Mock()
            with self.assertRaises(ValueError):
                boot.publish_pages(util, (0x8000, pa))
            self.assertEqual(util.mock_calls, [])

    def test_publication_coalesces_and_orders_cache_maintenance(self):
        util = Mock()
        util.heap.guarded_malloc.return_value = nullcontext(0x800000)
        self.assertEqual(boot.publish_pages(util, (0x8000, 0xc000, 0x20000)),
                         ((0x8000, 0x8000), (0x20000, 0x4000)))
        util.iface.writemem.assert_called_once_with(
            0x800000, struct.pack("<4Q", 0x8000, 0x10000, 0x20000, 0x24000))
        self.assertEqual(util.inst.call_args_list[0].args,
                         (boot._MAINTAIN_RANGES, 0x800000, 2))
        self.assertEqual(util.inst.call_args_list[1].args, ("dsb sy",))
        self.assertEqual(util.proxy.dc_civac.call_args_list[-1].args, (0x800000, 32))

    def test_wait_is_fair_and_bounded_even_with_busy_peer(self):
        first, second = Mock(), Mock()
        order = []
        first.work.side_effect = lambda: order.append(0)
        second.work.side_effect = lambda: order.append(1)
        boot.wait_until((first, second), lambda: len(order) == 4, 1, "test")
        self.assertEqual(order, [0, 1, 0, 1])
        first.work_pending.assert_not_called()
        with patch.object(boot.time, "monotonic", side_effect=(0, 0, 2)):
            with self.assertRaisesRegex(TimeoutError, "test timeout"):
                boot.wait_until((first, second), lambda: False, 1, "test")
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                boot.wait_until((), lambda: True, timeout, "test")

    def runtime(self, directory, chip=0x8142):
        util = Mock()
        util.adt = {"/chosen": SimpleNamespace(chip_id=chip)}
        for index, (_, path, _) in enumerate(boot.INSTANCE_PATHS):
            util.adt[path] = SimpleNamespace(get_reg=lambda _: (0x100000, 0x10000))
        util.adt["/arm-io/sgx"] = SimpleNamespace(
            gfx_shared_region_base=0x200000, gfx_shared_region_size=0x80000,
            gfx_shared_l2_region_base=0x300000, gfx_handoff_base=0x304000)
        return boot.G17GBootRuntime(util, directory)

    def test_foreign_target_rejected_before_allocation_or_power(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = self.runtime(directory, 0x8140)
            with self.assertRaisesRegex(RuntimeError, "requires T8142"):
                runtime.boot()
            self.assertEqual(runtime.u.mock_calls, [])
            self.assertEqual(runtime.state, "failed")
            with self.assertRaisesRegex(RuntimeError, "one-shot"):
                runtime.boot()

    def test_boot_is_one_shot_and_never_sends_work_implicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = self.runtime(directory)
            runtime._prepare = Mock()
            runtime._validate_live_roots = Mock()
            asces = [Mock(coldboot_name=name) for name, _, _ in boot.INSTANCE_PATHS]
            for asc in asces:
                asc.fw.init_ack = True
                asc.fw.ack_message = 0x9000000000000
            with patch.object(boot, "G17GASC", side_effect=asces):
                self.assertIs(runtime.boot(dynamic_u32=42), runtime)
            self.assertEqual(runtime.state, "ready")
            runtime._prepare.assert_called_once_with(42, False)
            for asc in asces:
                asc.send.assert_called_once()
                message, endpoint = asc.send.call_args.args
                self.assertEqual(message >> 48, 0x81)
                self.assertEqual(endpoint.EP, 0x20)
                self.assertEqual([args.args for args in asc.start_ep.call_args_list],
                                 [(0x20,), (0x21,)])
            with self.assertRaisesRegex(RuntimeError, "one-shot"):
                runtime.boot()
            self.assertEqual(runtime.evidence["execution_claim"], "none")
            self.assertIsNone(runtime.evidence["captured_input"])

    def test_failure_retains_allocations_and_does_not_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = self.runtime(directory)
            runtime._prepare = Mock(side_effect=RuntimeError("failed publication"))
            with self.assertRaisesRegex(RuntimeError, "failed publication"):
                runtime.boot()
            self.assertEqual(runtime.state, "failed")
            runtime.u.free.assert_not_called()
            runtime.p.pmgr_adt_power_enable.assert_not_called()
            self.assertIn("failed publication", runtime.evidence["error"])

    def test_crash_endpoint_is_data_only(self):
        self.assertIs(boot.G17GASC.ENDPOINTS[1], G17GDataOnlyCrashEndpoint)

    def test_crash_fails_device_only_after_preserving_owned_data(self):
        from m1n1.drm_shim import g17g_crash as crash
        with tempfile.TemporaryDirectory() as directory:
            data = bytes(4096)
            asc = Mock(coldboot_name="primary", crash_output_directory=directory)
            asc.u.adt = {"/chosen": SimpleNamespace(chip_id=0x8142)}
            asc.iotranslate.return_value = [(0x10000, len(data))]
            asc.ioread.return_value = data
            endpoint = SimpleNamespace(asc=asc, iobuffer_dva=0x20000,
                                       buffer_size=4096, log=Mock())
            with patch.object(crash, "segment_metadata", return_value=()), \
                 patch.object(crash, "exclusion_ranges", return_value=()), \
                 patch.object(crash, "crash_metadata", return_value={"sha256": "test"}):
                with self.assertRaises(G17GPublishedFault) as caught:
                    G17GDataOnlyCrashEndpoint.handle_crashed(
                        endpoint, SimpleNamespace(SIZE=1, DVA=0x20000))
            self.assertEqual(caught.exception.error, -19)
            self.assertTrue(caught.exception.fatal)
            self.assertTrue(caught.exception.metadata["evidence_saved"])
            self.assertEqual((Path(directory) / "primary_crash.bin").read_bytes(), data)
            self.assertTrue((Path(directory) / "primary_crash.json").exists())
            asc.ioread.assert_called_once_with(0x20000, 4096)

    def test_runtime_has_no_experiment_or_proxy_setup_import(self):
        from m1n1.drm_shim import g17g_runtime
        for module in (boot, g17g_runtime):
            source = Path(module.__file__).read_text()
            for forbidden in ("importlib", "exec_module", "m1n1.setup", "from experiments",
                              "import experiments", "agx_g17g_coldboot_init"):
                self.assertNotIn(forbidden, source)

    def test_import_has_no_transitive_hv_capture_or_sptm_dependency(self):
        subprocess.run([sys.executable, "-c", (
            "import sys; from m1n1.drm_shim.g17g_boot import G17GBootRuntime; "
            "from m1n1.drm_shim.g17g_runtime import G17GFirstComputeRuntime; "
            "assert 'm1n1.setup' not in sys.modules; "
            "assert 'm1n1.g17g_capture' not in sys.modules; "
            "assert not any(n == 'sptm' or n.startswith('sptm.') for n in sys.modules)"
        )], check=True)

    def test_code_exclusions_preserve_both_adt_address_aliases(self):
        from m1n1.g17g_adt import ASC_NODES, exclusion_ranges, segment_metadata
        adt = {}
        for name, path in ASC_NODES:
            adt[path] = SimpleNamespace(_properties={
                "segment-names": b"__TEXT;__DATA;\0",
                "segment-ranges": (
                    struct.pack("<QQQI4x", 0x10000, 0, 0x50000, 0x4000) +
                    struct.pack("<QQQI4x", 0x80000, 0, 0x80000, 0x4000))})
        segments = segment_metadata(adt)
        self.assertEqual([(r["start"], r["end"]) for r in exclusion_ranges(segments)],
                         [(0x10000, 0x14000), (0x50000, 0x54000)])
        adt[ASC_NODES[0][1]]._properties["segment-names"] = "__DATA;__DATA"
        with self.assertRaisesRegex(RuntimeError, "no named __TEXT"):
            segment_metadata(adt)

    def test_first_compute_rejects_unimplemented_graphs_before_publication(self):
        from m1n1.drm_shim.g17g_backend import build_add_compute_graph
        from m1n1.drm_shim.g17g_runtime import G17GFirstComputeRuntime
        with tempfile.TemporaryDirectory() as directory:
            initialized = self.runtime(directory)
            initialized.state, initialized.profile = "ready", "compute"
            initialized.uat = Mock()
            initialized.plan = {"ram_pages": {}}
            initialized.synthetic_high_root = 0x40000
            runtime = G17GFirstComputeRuntime(initialized)
            graph = build_add_compute_graph()
            for key, value in (("captured_input", "capture.json"), ("channel", 4),
                               ("compute_descriptor_count", 2), ("direct_dispatch_count", 2),
                               ("native_two_publication_layout", True),
                               ("fresh_firmware_page_flags", {0x1000: "shared"})):
                with self.assertRaises(ValueError):
                    runtime.submit(dict(graph, **{key: value}))
            self.assertEqual(runtime.state, "new")
            self.assertEqual(initialized.u.mock_calls, [])

    def test_compute_boot_profile_uses_only_cpu_cache_publication(self):
        util = Mock()
        self.assertEqual(boot.publish_pages(util, (0x8000,), coprocessor=False),
                         ((0x8000, 0x4000),))
        util.proxy.dc_civac.assert_called_once_with(0x8000, 0x4000)
        util.iface.writemem.assert_not_called()
        util.inst.assert_called_once_with("dsb sy")

    def test_context_slot_dirty_key_publishes_its_owned_enclosing_page(self):
        from m1n1.drm_shim.g17g_runtime import G17GFirstComputeRuntime
        runtime = object.__new__(G17GFirstComputeRuntime)
        runtime.u = Mock()
        runtime.uat = Mock(gpu_region=0x8000, dirty={0x8010, 0x10000})
        runtime.publish = Mock()
        runtime.flush_tables(1)
        runtime.publish.assert_called_once_with((0x8000, 0x10000))
        runtime.uat.dirty = {0x10001}
        runtime.publish.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "unaligned dirty"):
            runtime.flush_tables(1)
        runtime.publish.assert_not_called()

    def test_m5_uat_geometry_is_not_selected_by_global_import_order(self):
        from m1n1.drm_shim.g17g_initdata import LEVELS
        self.assertEqual(boot.G17GUAT.L0_OFF, 42)
        self.assertEqual(boot.G17GUAT.L1_SIZE, 64)
        self.assertEqual(tuple((shift, count) for shift, count, _ in boot.G17GUAT.LEVELS[1:]),
                         LEVELS)
        # The fixed M5 executable aperture must use root entry 16, not be
        # aliased onto entry zero by a legacy three-bit (39-bit VA) mask.
        shift, count, _ = boot.G17GUAT.LEVELS[1]
        self.assertEqual((0x10000000000 >> shift) & (count - 1), 16)


    def test_compute_wait_dispatches_mailbox_instead_of_discarding_it(self):
        from m1n1.drm_shim import g17g_runtime
        runtime = object.__new__(g17g_runtime.G17GFirstComputeRuntime)
        runtime.u = Mock()
        runtime.asces = [Mock(), Mock()]
        with patch.object(g17g_runtime.g17g_stream, "read_output_word",
                          side_effect=(0, 0x447a2000)):
            runtime.kick_and_wait(0x8000, 0x008300000000000a, 1)
        runtime.asces[0].send.assert_called_once()
        for asc in runtime.asces:
            asc.work.assert_called_once()
        runtime.asces[0].work.side_effect = RuntimeError("data-only crash saved")
        with patch.object(g17g_runtime.g17g_stream, "read_output_word", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "data-only crash saved"):
                runtime.kick_and_wait(0x8000, 0x008300000000000a, 1)


if __name__ == "__main__":
    unittest.main()
