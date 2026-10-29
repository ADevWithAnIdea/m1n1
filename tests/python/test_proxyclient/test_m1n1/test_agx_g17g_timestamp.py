# SPDX-License-Identifier: GPL-2.0-only
"""Timestamp ownership, mapping failure and command attribution tests."""
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from m1n1.drm_shim.g17g_memory import G17GMemoryAdapter
from m1n1.drm_shim.g17g_modern import G17GModernBO, G17GModernObject
from m1n1.drm_shim.g17g_timestamp import G17GTimestampMappings, TIMESTAMP_USER_BASE, TIMESTAMP_END
from m1n1.drm_shim.g17g_render import TIMESTAMP_APERTURE_BASE
from m1n1.drm_shim.g17g_submit import first_compute_graph
from m1n1.drm_shim.g17g_compute_queue import compute_waves

PAGE = 0x4000


class TimestampTests(unittest.TestCase):
    def setUp(self):
        self.file = tempfile.TemporaryFile()
        self.addCleanup(self.file.close)
        self.file.truncate(2 * PAGE)
        util = Mock()
        util.memalign.return_value = 0x800000
        self.adapter = G17GMemoryAdapter(util, lambda _file: self.file.fileno())
        self.adapter.device_lost = False
        self.adapter.runtime = SimpleNamespace(state="new", root=0x900000,
                                               uat=Mock(), flush_tables=Mock())
        self.manager = G17GTimestampMappings(self.adapter)
        self.bo = G17GModernBO(1, 0, 2 * PAGE, 0, 0)
        self.bo.token = self.adapter.create_bo(None, self.bo)
        self.addCleanup(self.bo.token["mapping"].close)

    def obj(self, handle=1, offset=PAGE):
        obj = G17GModernObject(handle, self.bo, offset, PAGE, 1)
        obj.token = self.manager.bind(None, obj)
        return obj

    def test_special_offset_maps_actual_bo_backing_and_reuses_after_unmap(self):
        obj = self.obj()
        runtime = self.adapter.runtime
        runtime.uat.iotranslate_root.return_value = [(None, PAGE)]
        self.bo.token["mapping"][:] = b"A" * PAGE + b"B" * PAGE
        self.manager.materialize((obj,))
        call = runtime.uat.iomap_at_root.call_args
        self.assertEqual(call.args, (runtime.root, TIMESTAMP_USER_BASE,
                                    0x800000 + PAGE, PAGE))
        self.assertEqual(self.bo.token["active_objects"], [obj])
        with self.assertRaisesRegex(RuntimeError, "reachable"):
            self.adapter.destroy_bo(None, self.bo)
        self.manager.unbind(None, obj)
        self.assertTrue(obj.token["released"])
        self.assertEqual(self.bo.token["active_objects"], [])
        self.assertEqual(self.manager.free_ranges, [(TIMESTAMP_USER_BASE, TIMESTAMP_END)])
        self.assertEqual(self.obj(2).token["address"], obj.token["address"])

    def test_failed_table_publication_retains_mapping_ownership(self):
        obj = self.obj()
        runtime = self.adapter.runtime
        runtime.uat.iotranslate_root.return_value = [(None, PAGE)]
        runtime.flush_tables.side_effect = OSError("transport")
        with self.assertRaises(OSError):
            self.manager.materialize((obj,))
        self.assertTrue(obj.token["active"])
        self.assertEqual(self.bo.token["active_objects"], [obj])
        self.adapter.device_lost = True
        with self.assertRaisesRegex(RuntimeError, "clean retirement"):
            self.manager.unbind(None, obj)
        runtime.uat.iounmap_root.assert_not_called()
        self.assertFalse(obj.token["released"])

    def test_special_only_readback_preserves_unbound_bo_bytes(self):
        obj = self.obj()
        self.bo.token["pa"] = 0x800000
        self.bo.token["mapping"][:] = b"A" * (2 * PAGE)
        self.bo.token["uploaded_image"] = b"A" * (2 * PAGE)
        self.adapter.iface.readmem.return_value = b"B" * PAGE
        self.assertEqual(self.adapter.pull(SimpleNamespace(bindings=[]), objects=(obj,)), PAGE)
        self.adapter.iface.readmem.assert_called_once_with(0x804000, PAGE)
        self.assertEqual(self.bo.token["mapping"][:], b"A" * PAGE + b"B" * PAGE)
        self.assertEqual(self.bo.token["uploaded_image"], b"A" * PAGE + b"B" * PAGE)

    def test_queue_recreation_keeps_each_commands_own_pointer_pair(self):
        first = first_compute_graph(0x10000, 0x10040, user_timestamps=(0x1234, 0x5678))
        self.assertEqual(struct.unpack_from("<2Q", first["firmware_objects"]["descriptor"], 0xf8c),
                         (0x1234, 0x5678))
        pointers = tuple((TIMESTAMP_USER_BASE + i * 16,
                          TIMESTAMP_USER_BASE + i * 16 + 8) for i in range(260))
        waves = compute_waves(((0x10000, 0x10040),) * len(pointers), 1,
                              first["addresses"], user_timestamps=pointers)
        seen = []
        for wave in waves:
            writes = dict(wave["high"])
            for record in wave["records"]:
                descriptor = writes[record["addresses"]["descriptor"]]
                seen.append(struct.unpack_from("<2Q", descriptor, 0xf8c))
        self.assertTrue(any(wave["recreate"] for wave in waves))
        self.assertEqual(tuple(seen), pointers)

    def test_render_object_pointers_preserve_stage_attribution_and_reject_release(self):
        obj = self.obj()
        command = SimpleNamespace(timestamp_objects=tuple(
            (name, obj, offset) for name, offset in
            (("vertex_start", 8), ("vertex_end", 16),
             ("fragment_start", 24), ("fragment_end", 32))))
        base = obj.token["address"]
        self.assertEqual(self.manager.render_pointers(command), dict(
            tiling_user_timestamp_start=base + 8, tiling_user_timestamp_end=base + 16,
            fragment_user_timestamp_start=base + 24, fragment_user_timestamp_end=base + 32))
        self.manager.unbind(None, obj)
        with self.assertRaisesRegex(ValueError, "released"):
            self.manager.render_pointers(command)


if __name__ == "__main__":
    unittest.main()
