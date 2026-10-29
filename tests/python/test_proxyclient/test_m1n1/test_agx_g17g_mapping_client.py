# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the shim against the actual upstream UAT, with host-only memory.

The memory proxy implements byte storage and allocation, not translation or
page-table encoding. Those operations run through the unchanged upstream UAT.
"""

from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "proxyclient"))

from m1n1.drm_shim.g17g_boot import G17GUAT, G17GBootRuntime, INSTANCE_PATHS
from m1n1.drm_shim.g17g_mapping_client import RootMappingClient
from m1n1.drm_shim.g17g_growth import allocate_tvb_backing, TVB_BLOCK_SIZE
from m1n1.drm_shim.g17g_uat import FLAGS_CONTEXT0_UXN


PAGE = 0x4000


class HostMemory:
    def __init__(self):
        self.iface = self.proxy = self
        self.pages = {}
        self.next_pa = 0x100000
        self.allocations = {}
        self.fail_size = None
        self.instructions = []
        self.adt = {
            "/chosen": SimpleNamespace(chip_id=0x8142),
            "/arm-io/sgx": SimpleNamespace(
                gpu_region_base=0x40000, gfx_shared_region_base=0x20000000,
                gfx_shared_region_size=0x80000,
                gfx_shared_l2_region_base=0x21000000, gfx_handoff_base=0x22000000),
            "/arm-io/gfx-asc": SimpleNamespace(),
            "/arm-io/gfx1-asc": SimpleNamespace(),
        }

    def memalign(self, alignment, size):
        if size == self.fail_size:
            raise MemoryError("host backing exhausted")
        address = (self.next_pa + alignment - 1) & -alignment
        self.next_pa = address + size
        self.allocations[address] = size
        return address

    def free(self, address):
        del self.allocations[address]

    def readmem(self, address, size):
        data = bytearray()
        while size:
            page, offset = address & -PAGE, address % PAGE
            count = min(size, PAGE - offset)
            data += self.pages.get(page, bytes(PAGE))[offset:offset + count]
            address, size = address + count, size - count
        return bytes(data)

    def writemem(self, address, data):
        data = memoryview(data)
        while data:
            page, offset = address & -PAGE, address % PAGE
            count = min(len(data), PAGE - offset)
            self.pages.setdefault(page, bytearray(PAGE))[offset:offset + count] = data[:count]
            address, data = address + count, data[count:]

    def read(self, address, width):
        return int.from_bytes(self.readmem(address, width // 8), "little")

    def write(self, address, value, width):
        self.writemem(address, int(value).to_bytes(width // 8, "little"))

    def read32(self, address):
        return self.read(address, 32)

    def read64(self, address):
        return self.read(address, 64)

    def memset32(self, address, value, size):
        self.writemem(address, struct.pack("<I", value) * (size // 4))

    def dc_civac(self, address, size):
        pass

    def inst(self, instruction, *args):
        self.instructions.append((instruction, args))


class TestPublicMappingClient(unittest.TestCase):
    def setUp(self):
        self.host = HostMemory()
        self.core = G17GUAT(self.host, self.host)
        self.client = RootMappingClient(self.core)
        self.root = self.host.memalign(PAGE, PAGE)

    def test_maps_42_bit_low_and_high_ranges_without_using_live_slots(self):
        slot_before = self.host.readmem(self.core.gpu_region, PAGE)
        addresses = (0x100004000, 0x10000000000, 0xfffffc20c0000000)
        for address in addresses:
            pa = self.host.memalign(PAGE, PAGE)
            self.client.iomap_at_root(self.root, address, pa, PAGE, **FLAGS_CONTEXT0_UXN)
            self.client.flush_dirty()
            self.client.invalidate_cache()
            self.assertEqual(self.client.iotranslate_root(self.root, address + 17, 33),
                             [(pa + 17, 33)])
        self.assertEqual(self.host.readmem(self.core.gpu_region, PAGE), slot_before)
        self.assertGreater(len(self.client.root_table_pages(self.root)), 1)

    def test_unmap_preserves_other_root_at_identical_va(self):
        second = self.host.memalign(PAGE, PAGE)
        first_pa, second_pa = self.host.memalign(PAGE, PAGE), self.host.memalign(PAGE, PAGE)
        for root, pa in ((self.root, first_pa), (second, second_pa)):
            self.client.iomap_at_root(root, 0x10000000000, pa, PAGE, **FLAGS_CONTEXT0_UXN)
        self.client.flush_dirty()
        self.assertEqual(self.client.iounmap_root(self.root, 0x10000000000, PAGE), PAGE)
        self.client.flush_dirty()
        self.client.invalidate_cache()
        self.assertEqual(self.client.iotranslate_root(self.root, 0x10000000000, PAGE), [(None, PAGE)])
        self.assertEqual(self.client.iotranslate_root(second, 0x10000000000, PAGE), [(second_pa, PAGE)])

    def test_live_slot_selection_uses_original_context_api(self):
        pa = self.host.memalign(PAGE, PAGE)
        self.client.iomap_at_root(self.root, 0x100004000, pa, PAGE, **FLAGS_CONTEXT0_UXN)
        self.client.set_l0(1, 0, self.root, 1)
        self.client.flush_dirty()
        self.client.invalidate_cache()
        self.assertEqual(self.client.iotranslate(1, 0x100004000, PAGE), [(pa, PAGE)])

    def test_releases_only_private_scratch_context(self):
        owned_before = dict(self.host.allocations)
        self.assertEqual(self.client.iotranslate_root(self.root, 0, PAGE), [(None, PAGE)])
        self.assertEqual(len(self.host.allocations), len(owned_before) + 1)
        self.client.release_root_view(self.root)
        self.assertEqual(self.host.allocations, owned_before)

    def test_zero_length_operations_allocate_nothing(self):
        before = dict(self.host.allocations)
        self.client.iomap_at_root(self.root, 0, 0, 0)
        self.assertEqual(self.client.iotranslate_root(self.root, 0, 0), [])
        self.assertEqual(self.client.iounmap_root(self.root, 0, 0), 0)
        self.assertEqual(self.host.allocations, before)

    def growth(self, **kwargs):
        return allocate_tvb_backing(self.host, self.host, self.host, self.host.readmem,
            root_pa=self.root, state_pa=0x80000, list_pa=0x84000, list_capacity=32,
            block_dvas=(0x1000290000,), uat=self.client, **kwargs)

    def test_tvb_growth_maps_through_real_upstream_uat(self):
        self.host.writemem(0x80000, struct.pack("<2I", 3, 3))
        result = self.growth()
        self.assertEqual(self.host.readmem(0x80000, 8), struct.pack("<2I", 4, 4))
        self.assertEqual(self.client.iotranslate_root(self.root, 0x1000290000, TVB_BLOCK_SIZE),
                         [(result["new_physical"], TVB_BLOCK_SIZE)])
        self.assertEqual(self.host.allocations[result["new_physical"]], TVB_BLOCK_SIZE)

    def test_tvb_oom_and_overlap_leave_counts_and_list_unchanged(self):
        self.host.writemem(0x80000, struct.pack("<2I", 3, 3))
        self.client.root_table_pages(self.root)
        self.host.fail_size = TVB_BLOCK_SIZE
        with self.assertRaises(MemoryError):
            self.growth()
        self.assertEqual(self.host.readmem(0x80000, 8), struct.pack("<2I", 3, 3))
        self.assertEqual(self.host.readmem(0x84000, 32), bytes(32))
        self.host.fail_size = None
        pa = self.host.memalign(PAGE, PAGE)
        self.client.iomap_at_root(self.root, 0x1000290000, pa, PAGE, **FLAGS_CONTEXT0_UXN)
        self.client.flush_dirty()
        with self.assertRaisesRegex(ValueError, "live UAT mapping"):
            self.growth()
        self.assertEqual(self.host.readmem(0x80000, 8), struct.pack("<2I", 3, 3))

    def test_full_initdata_preparation_uses_the_unchanged_uat(self):
        with tempfile.TemporaryDirectory() as directory:
            boot = G17GBootRuntime(self.host, directory)
            boot.profile = "compute"
            boot._prepare(123, verify=False)
        self.assertEqual(len(boot.plan["ram_pages"]), 608)
        self.assertIn(boot.shared_l2_pa, boot.plan["table_pages"])
        for name, _path, address in INSTANCE_PATHS:
            self.assertEqual(boot.uat.iotranslate_root(boot.synthetic_high_root, address, PAGE),
                             [(boot.plan["ram_pages"][address], PAGE)])
