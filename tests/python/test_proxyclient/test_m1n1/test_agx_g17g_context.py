# SPDX-License-Identifier: GPL-2.0-only
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from m1n1.drm_shim.g17g_context import G17GComputeContext
from m1n1.drm_shim.g17g_memory import G17GPageBacking
from tests.python.test_proxyclient.test_m1n1 import test_agx_g17g_adapter as adapter_tests


def context(root):
    return dict(root0=root, root1=root + 0x4000,
        pages={0x10000: root + 0x8000}, table_witnesses={0x10000}, destroyed=False,
        allocations=[(root, 0x4000), (root + 0x4000, 0x4000), (root + 0x8000, 0x8000)],
        caller_mappings={0x10000: G17GPageBacking(root + 0x8000, True)})


class TestContextOwnership(unittest.TestCase):
    def setUp(self):
        self.adapter, self.queue, self.commands = adapter_tests.TestComputeAdapter().adapter()
        self.runtime = self.adapter.runtime
        self.runtime.state = "complete"
        self.runtime.uat.gpu_region = 0x100000
        self.a, self.b = context(0x20000), context(0x50000)
        self.a["context_id"], self.b["context_id"] = 1, 2
        self.runtime.resident_contexts[1] = self.a
        self.runtime.context = self.a
        self.runtime.allocations = self.a["allocations"] + self.b["allocations"]
        self.runtime.flush_tables = Mock()
        self.runtime.publish = Mock()

    def test_root_selection_checks_exact_previous_and_new_owned_slot(self):
        before, after = bytes(16), self.runtime.context_slot_image(self.b)
        with patch("m1n1.drm_shim.g17g_runtime.read_ranges", side_effect=[(before,), (after,)]):
            transition = self.runtime.select_context(self.b)
        self.assertTrue(transition["changed"])
        self.assertIs(self.runtime.context, self.b)
        self.assertIs(self.runtime.resident_contexts[1], self.a)
        self.assertIs(self.runtime.resident_contexts[2], self.b)
        self.runtime.uat.set_l0.assert_any_call(2, 0, self.b["root0"], 2)
        self.runtime.uat.set_l0.assert_any_call(2, 1, self.b["root1"], 2)
        self.runtime.flush_tables.assert_called_once_with(2)

    def test_foreign_slot_and_destroyed_root_reject_before_publication(self):
        with patch("m1n1.drm_shim.g17g_runtime.read_ranges", return_value=(b"X" * 16,)):
            with self.assertRaisesRegex(RuntimeError, "owned roots"):
                self.runtime.select_context(self.b)
        self.runtime.uat.set_l0.assert_not_called()
        self.b["destroyed"] = True
        with patch("m1n1.drm_shim.g17g_runtime.read_ranges") as read:
            with self.assertRaisesRegex(RuntimeError, "destroyed"):
                self.runtime.select_context(self.b)
            read.assert_not_called()

    def test_inactive_unbind_uses_its_own_root_and_retains_table_history(self):
        binding = SimpleNamespace(addr=0x10000, end=0x14000, size=0x4000)
        self.runtime.uat.iotranslate_root.side_effect = [[(0x58000, 0x4000)], [(None, 0x4000)]]
        self.runtime.uat.iounmap_root.return_value = 0x4000
        owner = G17GComputeContext(self.runtime, self.queue.vm, 2)
        owner.record = self.b
        owner.unmap_binding(binding)
        self.assertIs(self.runtime.context, self.a)
        self.assertEqual(self.a["pages"], {0x10000: 0x28000})
        self.assertEqual(self.b["pages"], {})
        self.assertEqual(self.b["caller_mappings"], {})
        self.assertEqual(self.b["table_witnesses"], {0x10000})
        self.runtime.uat.iotranslate.assert_not_called()
        self.runtime.uat.iounmap_root.assert_called_once_with(0x50000, 0x10000, 0x4000)

    def test_destroy_retry_does_not_write_or_read_already_freed_roots(self):
        self.runtime.u.free.side_effect = [None, RuntimeError("free failed"), None, None, None]
        with patch("m1n1.drm_shim.g17g_runtime.g17g_uat.collect_firmware_root_table_pages",
                   return_value=(0x50000, 0x70000)) as collect, patch(
                   "m1n1.drm_shim.g17g_runtime.read_ranges", return_value=(bytes(0x4000), bytes(0x4000))) as read:
            with self.assertRaisesRegex(RuntimeError, "free failed"):
                self.runtime.destroy_context(self.b)
            self.assertTrue(self.b["roots_invalidated"])
            self.assertFalse(self.b.get("released", False))
            result = self.runtime.destroy_context(self.b)
            collect.assert_called_once()
            read.assert_called_once()
        self.assertTrue(result["released"])
        self.assertEqual(result["released_allocations"], 4)
        self.assertIs(self.runtime.context, self.a)
        self.assertEqual(self.runtime.allocations, self.a["allocations"])
        self.assertEqual(self.runtime.p.memset32.call_count, 2)
        self.assertEqual(self.runtime.destroy_context(self.b), result)

    def test_destroy_active_context_detaches_slot_before_free(self):
        self.runtime.context = self.b
        self.runtime.context_id = 2
        self.runtime.resident_contexts[2] = self.b
        before = self.runtime.context_slot_image(self.b)
        with patch("m1n1.drm_shim.g17g_runtime.g17g_uat.collect_firmware_root_table_pages", return_value=(0x50000,)), patch(
                "m1n1.drm_shim.g17g_runtime.read_ranges", side_effect=[(before,), (bytes(16),),
                                                                 (bytes(0x4000), bytes(0x4000))]):
            result = self.runtime.destroy_context(self.b)
        self.assertTrue(result["released"])
        self.assertIsNone(self.runtime.context)
        self.runtime.uat.set_l0.assert_any_call(2, 0, 0, 0)
        self.runtime.uat.set_l0.assert_any_call(2, 1, 0, 0)

    def test_embedded_growth_tables_are_freed_with_their_extent_only(self):
        with patch("m1n1.drm_shim.g17g_runtime.g17g_uat.collect_firmware_root_table_pages",
                   return_value=(0x50000, 0x5c000, 0x70000)), patch(
                   "m1n1.drm_shim.g17g_runtime.read_ranges", return_value=(bytes(0x4000), bytes(0x4000))):
            result = self.runtime.destroy_context(self.b)
        self.assertTrue(result["released"])
        freed = [call.args[0] for call in self.runtime.u.free.call_args_list]
        self.assertEqual(set(freed), {0x50000, 0x54000, 0x58000, 0x70000})
        self.assertNotIn(0x5c000, freed)

    def test_never_activated_vm_destruction_is_host_only_and_cannot_recreate_owner(self):
        owner = self.adapter.context_owner(self.queue.vm)
        self.assertTrue(self.adapter.destroy_vm(None, self.queue.vm)["never_activated"])
        with self.assertRaisesRegex(RuntimeError, "destroyed"):
            self.adapter.context_owner(self.queue.vm)
        self.assertTrue(owner.destroyed)
        self.assertFalse(self.runtime.u.mock_calls)
