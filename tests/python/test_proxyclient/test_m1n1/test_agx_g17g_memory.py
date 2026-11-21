# SPDX-License-Identifier: GPL-2.0-only
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from m1n1.drm_shim.g17g_memory import G17GMemoryAdapter, G17GPageBacking, mapping_runs
from m1n1.drm_shim.g17g_modern import G17GModernDriver, PAGE_SIZE, VM_END, VM_KERNEL_MIN_SIZE
from m1n1.drm_shim.g17g_uapi import (
    drm_asahi_gem_bind_op, DRM_ASAHI_BIND_READ, DRM_ASAHI_BIND_WRITE,
    DRM_ASAHI_BIND_SINGLE_PAGE,
)


class TestCallerMemory(unittest.TestCase):
    def setUp(self):
        self.file = tempfile.TemporaryFile()
        self.addCleanup(self.file.close)
        self.file.truncate(16 * PAGE_SIZE)
        self.util = Mock()
        self.util.memalign.side_effect = (0x800000, 0x900000, 0xa00000)
        self.memory = G17GMemoryAdapter(self.util, lambda file: self.file.fileno())
        self.driver = G17GModernDriver(self.memory)
        self.vm = self.driver.create_vm(11, VM_END - VM_KERNEL_MIN_SIZE, VM_END)
        self.bos = []
        self.addCleanup(self.close_mappings)

    def close_mappings(self):
        for bo in self.bos:
            if not bo.token["mapping"].closed:
                bo.token["mapping"].close()

    def bo(self, handle=1, size=PAGE_SIZE):
        bo = self.driver.create_bo(11, handle, (handle - 1) * 4 * PAGE_SIZE, size)
        self.bos.append(bo)
        return bo

    def bind(self, bo, dva=1 << 40, size=PAGE_SIZE, offset=0,
             flags=DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE):
        return self.driver.bind(11, self.vm.vm_id,
            drm_asahi_gem_bind_op(flags, bo.handle, offset, size, dva))

    def test_bo_uses_real_shared_file_and_distinct_physical_backing(self):
        first, second = self.bo(), self.bo(2)
        first.token["mapping"][:] = b"A" * PAGE_SIZE
        second.token["mapping"][:] = b"B" * PAGE_SIZE
        self.bind(first)
        self.bind(second, (1 << 40) + PAGE_SIZE)
        pages = self.memory.materialize(self.vm)
        self.assertEqual(pages[1 << 40].pa, 0x800000)
        self.assertEqual(pages[(1 << 40) + PAGE_SIZE].pa, 0x900000)
        self.util.iface.writemem.assert_any_call(0x800000, b"A" * PAGE_SIZE)
        self.util.iface.writemem.assert_any_call(0x900000, b"B" * PAGE_SIZE)
        self.file.seek(4 * PAGE_SIZE)
        self.assertEqual(self.file.read(4), b"BBBB")

    def test_reserved_overlap_rejected_before_any_proxy_write(self):
        self.bind(self.bo())
        with self.assertRaisesRegex(ValueError, "driver-owned"):
            self.memory.materialize(self.vm, reserved=(1 << 40,))
        self.assertEqual(self.util.mock_calls, [])

    def test_single_page_alias_and_read_only_flags(self):
        bo = self.bo(size=2 * PAGE_SIZE)
        self.bind(bo, size=3 * PAGE_SIZE, offset=PAGE_SIZE,
                  flags=DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_SINGLE_PAGE)
        pages = self.memory.materialize(self.vm)
        self.assertEqual({page.pa for page in pages.values()}, {0x804000})
        self.assertFalse(any(page.writable for page in pages.values()))
        self.assertEqual(len(mapping_runs(pages)), 3)
        self.assertEqual(self.memory.pull(self.vm), 0)

    def test_mapping_runs_never_assume_contiguous_physical_backing(self):
        pages = {0x10000: G17GPageBacking(0x80000, True),
                 0x14000: G17GPageBacking(0x84000, True),
                 0x18000: G17GPageBacking(0x90000, True),
                 0x1c000: G17GPageBacking(0x94000, False)}
        self.assertEqual(mapping_runs(pages), (
            (0x10000, 0x80000, 0x8000, True),
            (0x18000, 0x90000, 0x4000, True),
            (0x1c000, 0x94000, 0x4000, False)))
        for dva, pa in ((1, 0x8000), (1 << 42, 0x8000), (0x8000, 1)):
            with self.assertRaises(ValueError):
                mapping_runs({dva: G17GPageBacking(pa, True)})

    def test_readback_copies_only_bound_slices_and_merges_aliases(self):
        bo = self.bo(size=3 * PAGE_SIZE)
        bo.token["mapping"][:] = b"A" * bo.size
        self.bind(bo, offset=PAGE_SIZE)
        self.bind(bo, dva=0x10000, offset=PAGE_SIZE)
        self.memory.materialize(self.vm)
        self.util.iface.readmem.return_value = b"B" * PAGE_SIZE
        self.assertEqual(self.memory.pull(self.vm), PAGE_SIZE)
        self.util.iface.readmem.assert_called_once_with(0x804000, PAGE_SIZE)
        self.assertEqual(bo.token["mapping"][:],
                         b"A" * PAGE_SIZE + b"B" * PAGE_SIZE + b"A" * PAGE_SIZE)

    def test_single_page_writable_readback_only_once(self):
        bo = self.bo()
        self.bind(bo, size=4 * PAGE_SIZE,
                  flags=DRM_ASAHI_BIND_WRITE | DRM_ASAHI_BIND_SINGLE_PAGE)
        self.memory.materialize(self.vm)
        self.util.iface.readmem.return_value = b"C" * PAGE_SIZE
        self.assertEqual(self.memory.pull(self.vm), PAGE_SIZE)
        self.util.iface.readmem.assert_called_once_with(0x800000, PAGE_SIZE)

    def test_lossless_transport_still_checks_full_slice_and_updates_exact_bytes(self):
        bo = self.bo()
        self.bind(bo)
        self.memory.materialize(self.vm)
        expected = bytes(64) + b"Z" * 64 + bytes(PAGE_SIZE - 128)
        reader = self.memory.readback_transport = Mock(return_value=expected)
        self.assertEqual(self.memory.pull(self.vm), PAGE_SIZE)
        reader.assert_called_once_with(0x800000, PAGE_SIZE)
        self.assertEqual(bo.token["mapping"][:], expected)
        self.assertEqual(bo.token["uploaded_image"], expected)
        self.util.iface.readmem.assert_not_called()
        reader.return_value = b"X"
        with self.assertRaisesRegex(RuntimeError, "short GPU BO readback"):
            self.memory.pull(self.vm)
        self.assertEqual(bo.token["mapping"][:], expected)

    def test_readback_coalesces_adjacent_physical_bos_not_virtual_neighbors(self):
        self.util.memalign.side_effect = (0x800000, 0x804000, 0x900000)
        first, second, third = self.bo(), self.bo(2), self.bo(3)
        for i, bo in enumerate((first, second, third)):
            self.bind(bo, (1 << 40) + i * PAGE_SIZE)
        self.memory.materialize(self.vm)
        self.util.iface.readmem.side_effect = (b"A" * PAGE_SIZE + b"B" * PAGE_SIZE,
                                                b"C" * PAGE_SIZE)
        self.assertEqual(self.memory.pull(self.vm), 3 * PAGE_SIZE)
        self.assertEqual(self.util.iface.readmem.call_args_list,
                         [((0x800000, 2 * PAGE_SIZE),), ((0x900000, PAGE_SIZE),)])
        for bo, byte in zip((first, second, third), (b"A", b"B", b"C")):
            self.assertEqual(bo.token["mapping"][:], byte * PAGE_SIZE)
        self.assertEqual(self.memory.last_readback, dict(bytes=3 * PAGE_SIZE, transport_reads=2))

    def test_readback_short_coalesced_read_never_partially_updates_bos(self):
        self.util.memalign.side_effect = (0x800000, 0x804000)
        first, second = self.bo(), self.bo(2)
        self.bind(first)
        self.bind(second, (1 << 40) + PAGE_SIZE)
        self.memory.materialize(self.vm)
        self.util.iface.readmem.return_value = b"X" * PAGE_SIZE
        with self.assertRaisesRegex(RuntimeError, "short GPU BO readback"):
            self.memory.pull(self.vm)
        self.assertEqual(first.token["mapping"][:], bytes(PAGE_SIZE))
        self.assertEqual(second.token["mapping"][:], bytes(PAGE_SIZE))

    def test_active_mapping_prevents_free_until_unmapped(self):
        bo = self.bo()
        binding = self.bind(bo)
        self.memory.materialize(self.vm)
        owner = Mock()
        self.memory.activate(self.vm, owner)
        with self.assertRaisesRegex(RuntimeError, "still reachable"):
            self.memory.destroy_bo(SimpleNamespace(fd=11), bo)
        self.util.free.assert_not_called()
        self.driver.destroy_bo(11, bo.handle)
        owner.unmap_binding.assert_called_once_with(binding)
        self.util.free.assert_called_once_with(0x800000)

    def test_failed_upload_retains_allocation_for_explicit_teardown(self):
        bo = self.bo()
        self.bind(bo)
        self.util.iface.writemem.side_effect = IOError("transport")
        with self.assertRaises(IOError):
            self.memory.materialize(self.vm)
        self.assertIs(self.memory.allocations[0x800000], bo)
        self.util.free.assert_not_called()
        self.driver.destroy_bo(11, bo.handle)
        self.util.free.assert_called_once_with(0x800000)

    def test_refresh_retired_owner_reuses_backing_without_duplicate_pins(self):
        bo = self.bo()
        binding = self.bind(bo)
        first = self.memory.materialize(self.vm)
        owner = Mock()
        self.memory.activate(self.vm, owner)
        with self.assertRaisesRegex(RuntimeError, "already has active"):
            self.memory.materialize(self.vm, allow_owner=Mock())
        second = self.memory.materialize(self.vm, allow_owner=owner)
        self.memory.activate(self.vm, owner, allow_existing=True)
        self.assertEqual(first, second)
        self.assertEqual(bo.token["active_bindings"], [binding])

    def test_invalid_backing_offset_rejected_without_adapter_writes(self):
        for offset in (-PAGE_SIZE, 1):
            with self.assertRaisesRegex(ValueError, "backing offset"):
                self.driver.create_bo(11, 1, offset, PAGE_SIZE)
        self.assertEqual(self.util.mock_calls, [])

    def test_unchanged_and_readback_updated_bos_do_not_reupload(self):
        bo = self.bo()
        self.bind(bo)
        self.memory.materialize(self.vm)
        self.util.iface.writemem.reset_mock()
        self.memory.materialize(self.vm)
        self.util.iface.writemem.assert_not_called()
        self.util.iface.readmem.return_value = b"G" * PAGE_SIZE
        self.memory.pull(self.vm)
        self.memory.materialize(self.vm)
        self.util.iface.writemem.assert_not_called()
        bo.token["mapping"][7] = 42
        self.memory.materialize(self.vm)
        self.util.iface.writemem.assert_called_once_with(0x800000, b"G" * 7 + b"*" + b"G" * (PAGE_SIZE - 8))
        self.assertEqual(self.memory.last_upload, dict(bos=1, bytes=PAGE_SIZE))

    def test_partial_readback_does_not_hide_unuploaded_caller_edits(self):
        bo = self.bo(size=2 * PAGE_SIZE)
        self.bind(bo)
        self.memory.materialize(self.vm)
        bo.token["mapping"][PAGE_SIZE] = 37
        self.util.iface.readmem.return_value = b"G" * PAGE_SIZE
        self.memory.pull(self.vm)
        self.assertEqual(bo.token["uploaded_image"][PAGE_SIZE], 0)
        self.assertEqual(bo.token["mapping"][PAGE_SIZE], 37)
        self.util.iface.writemem.reset_mock()
        self.memory.materialize(self.vm)
        self.util.iface.writemem.assert_called_once()
