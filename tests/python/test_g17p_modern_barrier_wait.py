# SPDX-License-Identifier: MIT
"""Consumer-first fixture checks must not infer output from queue retirement."""
import json
import mmap
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
os.environ.setdefault("AGX_GPU", "G17")
import agx_g17p_modern_barrier_wait as wait


class BarrierWaitTests(unittest.TestCase):
    def test_real_mapping_zero_check_and_all_three_publication_profiles(self):
        for kind, mask in (("compute", 6), ("tiling", 5), ("render", 1)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                viewport = wait.batch.partial.VIEWPORT
                before = {viewport: bytes(4), 0x2000: bytes(4)}
                expected = {viewport: b"\x01" * 4, 0x2000: b"\x02" * 4}
                device = dict(before)
                bindings = {address: types.SimpleNamespace(size=4,
                    bo=types.SimpleNamespace(token={"pa": address, "map": bytearray(body)}))
                    for address, body in before.items()}
                timestamp_maps = [mmap.mmap(-1, wait.batch.PAGE) for _ in range(3)]
                self.addCleanup(lambda maps=timestamp_maps: [body.close() for body in maps])
                timestamps = [(None, types.SimpleNamespace(token={
                    "pa": 0x3000 + index, "map": body}))
                    for index, body in enumerate(timestamp_maps)]
                device.update({0x3000 + index: bytes(wait.batch.PAGE) for index in range(3)})
                entries = [dict(state_addrs=(index * 3, index * 3 + 1, index * 3 + 2))
                           for index in range(12)]
                heads = {index: 0 for index in (6, 7, 8)}
                calls = []

                def release(_opening, _class, render, _cl, _render,
                            _notify, *, producer_mask):
                    calls.append(producer_mask)
                    # Fixture must normalize the driver's fragment-first
                    # tuple before applying its CL/TA/fragment mask.
                    self.assertEqual([address for address, _body in render], [20, 23])
                    heads.update({8: int(bool(producer_mask & 1)),
                                  6: int(bool(producer_mask & 2)),
                                  7: int(bool(producer_mask & 4))})
                    if kind != "compute":
                        device[viewport] = expected[viewport]
                        device[0x3000] = struct.pack("<QQ", 1, 2) + bytes(wait.batch.PAGE - 16)

                def write(address, body):
                    heads[(address - 2) // 3] = struct.unpack("<I", body)[0]

                def publish(producer, _channel):
                    write(*producer)

                backend = types.SimpleNamespace(
                    release_dependency_window=release,
                    publish_outer_with_work=publish,
                    event_pump=None,
                    channels=types.SimpleNamespace(entries=entries, counters=lambda entry:
                        [heads[(entry["state_addrs"][2] - 2) // 3]] * 3),
                    space=types.SimpleNamespace(read=lambda address, _size: device[address],
                                                flush=lambda: None),
                    _write_dva=write, _clean_dva_range=lambda *_args: None,
                    u=types.SimpleNamespace(inst=lambda *_args: None),
                    submitter=types.SimpleNamespace(notify=lambda channel: calls.append(channel)))

                def wave(*, opening_completion_value, reuse_compute_queue):
                    self.assertEqual(opening_completion_value, 1)
                    self.assertFalse(reuse_compute_queue)
                    backend.release_dependency_window((26, struct.pack("<I", 1)), None,
                        ((23, struct.pack("<I", 1)), (20, struct.pack("<I", 1))), 10, 8)
                    backend.publish_outer_with_work((26, struct.pack("<I", 2)), 10)
                    return "finished"

                adapter = types.SimpleNamespace(_submit_dependency_wave=wave)
                caller = types.SimpleNamespace(driver=types.SimpleNamespace(adapter=adapter),
                    front=types.SimpleNamespace(g17p=backend,
                        g17p_boot_artifact=str(Path(directory) / "boot.json")), bindings=bindings)
                wait.install_probe(kind, caller, before, expected, timestamps)
                self.assertEqual(adapter._submit_dependency_wave(), "finished")
                report = json.loads((Path(directory) / "mixed_barrier_wait.json").read_text())
                self.assertTrue(report["admitted"] and report["blocked"] and report["released"])
                self.assertEqual(report["producer_mask"], mask)
                self.assertEqual(heads, {6: 1, 7: 1, 8: 2})
                self.assertIs(backend.release_dependency_window, release)
                self.assertIs(backend.publish_outer_with_work, publish)


if __name__ == "__main__":
    unittest.main()
