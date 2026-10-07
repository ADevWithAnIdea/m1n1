# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
os.environ.setdefault("AGX_GPU", "G17")
import agx_g17p_modern_growth_owner as probe


class GrowthOwnerProbeTests(unittest.TestCase):
    def test_hook_preserves_restore_callback_and_registration_after_scheduler(self):
        memory = bytearray(0x20000)
        shared, config, records = 0x1000, 0x2000, 0x4000
        struct.pack_into("<Q", memory, shared + 0x28, 0x1000190000)
        struct.pack_into("<I", memory, shared + 0x34, 32)
        struct.pack_into("<Q", memory, config + 0x2e0, records)

        def write(address, body):
            if address == 0xfffffc20015e0000:
                address = records
            memory[address:address + len(body)] = body

        submitter = types.SimpleNamespace(channels=types.SimpleNamespace(main_config=config),
            read=lambda address, size: bytes(memory[address:address + size]), write=write)
        prepared = dict(submitter=submitter, stage_again={
            'TA': dict(kind='tiling', items=(0xa000,)),
            '3D': dict(kind='fragment', items=(0xe000,))})
        restore = lambda: None
        with tempfile.TemporaryDirectory() as artifact:
            startup = types.SimpleNamespace(boot=types.SimpleNamespace(LAST_ARTIFACT=artifact,
                SUBMISSION_ADDRESSES={"descriptor_shared_object": shared,
                                      "work_descriptor_0": (0xa000, 0xe000)},
                u=types.SimpleNamespace(inst=lambda *_args: None)),
                _scheduler=lambda current: probe.g17p_render_startup.G17PFirstRender._scheduler(
                    startup, current))

            def driver_early(current, current_prepared):
                cls = probe.g17p_render_startup.G17PFirstRender
                cls._bind_first_pool(current, current_prepared)
                cls._scheduler(current, current_prepared)
                return restore

            def caller():
                result = probe.g17p_render_startup.G17PFirstRender.early_state(startup, prepared)
                self.assertIs(result, restore)
                startup._scheduler(prepared)
                self.assertEqual(struct.unpack_from("<I", memory, shared + 0x0c)[0], 1)
                self.assertEqual(struct.unpack_from("<2I", memory, records + 0x10), (0x19000, 32))
                for address in (0xa018, 0xa304, 0xe458):
                    self.assertEqual(struct.unpack_from("<I", memory, address)[0], 1)
                return 0

            with mock.patch.object(probe.g17p_render_startup.G17PFirstRender, "early_state",
                                   side_effect=driver_early), \
                 mock.patch.object(probe.partial, "main", side_effect=caller), \
                 mock.patch.dict(os.environ, {"G17P_PROBE_POOL_OWNER": "1"}):
                self.assertEqual(probe.main(), 0)


if __name__ == "__main__":
    unittest.main()
