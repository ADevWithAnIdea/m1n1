# SPDX-License-Identifier: MIT
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient/experiments"))
from g17p_barrier_bisect import (FORMAT, PAGE, delayed_producer_control,
                               ownership_candidates, zero_page_overrides)
from agx_g17p_replay_native_barriers import EXPECTED


class BarrierBisectTests(unittest.TestCase):
    def setUp(self):
        self.dva = 0xfffffc20001d8000
        self.ram = b"\x01" + bytes(PAGE - 1)
        digest = hashlib.sha256(self.ram).hexdigest()
        self.manifest = dict(ram_sha256=digest,
            root_mappings=[dict(root_ctx_id=64, mappings=[dict(va=self.dva, blob_index=0)])],
            blob_pages=[dict(index=0, original_pa=0x100000, sha256=digest)])
        self.plan = dict(format=FORMAT, ram_sha256=digest, zero_blob_indices=[0])

    def test_zero_does_not_modify_capture(self):
        original = bytes(self.ram)
        overrides, report = zero_page_overrides(self.manifest, self.ram, self.plan)
        self.assertEqual(overrides, {0x100000: bytes(PAGE)})
        self.assertEqual(report["zeroed_bytes"], PAGE)
        self.assertEqual(self.ram, original)

    def test_client_alias_protects_physical_page(self):
        self.manifest["root_mappings"].append(dict(root_ctx_id=1,
            mappings=[dict(va=0x10000, blob_index=0)]))
        self.assertEqual(ownership_candidates(self.manifest, self.ram), [])
        with self.assertRaises(ValueError):
            zero_page_overrides(self.manifest, self.ram, self.plan)

    def test_rejects_wrong_capture_and_changed_page(self):
        for ram, sha in ((self.ram, "wrong"), (bytes(PAGE), self.plan["ram_sha256"])):
            plan = dict(self.plan, ram_sha256=sha)
            with self.assertRaises(ValueError):
                zero_page_overrides(self.manifest, ram, plan)

    def test_field_write_has_exact_preimage(self):
        plan = dict(self.plan, zero_blob_indices=[], writes=[dict(
            dva=self.dva, hex="02000000", expected_hex="01000000")])
        overrides, report = zero_page_overrides(self.manifest, self.ram, plan)
        self.assertEqual(overrides[0x100000], b"\x02" + bytes(PAGE - 1))
        self.assertEqual(len(report["writes"]), 1)
        wrong = copy.deepcopy(plan)
        wrong["writes"][0]["expected_hex"] = "03000000"
        with self.assertRaises(ValueError):
            zero_page_overrides(self.manifest, self.ram, wrong)

    def test_rejects_overlap_and_mixed_whole_page_write(self):
        write = dict(dva=self.dva, hex="02000000", expected_hex="01000000")
        for indices, writes in (([0], [write]), ([], [write, write])):
            with self.assertRaises(ValueError):
                zero_page_overrides(self.manifest, self.ram,
                                    dict(self.plan, zero_blob_indices=indices, writes=writes))

    def test_descriptor_data_allowlist_does_not_enable_arbitrary_client_page_edits(self):
        base = 0xfffffc20c0358000
        self.manifest["root_mappings"] = [
            dict(root_ctx_id=64, mappings=[dict(va=base, blob_index=0)]),
            dict(root_ctx_id=1, mappings=[dict(va=0x7000340000, blob_index=0)])]
        self.assertEqual(ownership_candidates(self.manifest, self.ram), [])
        for offset in (0xf40, 0xf50, 0xf54):
            plan = dict(self.plan, zero_blob_indices=[], writes=[dict(
                dva=base + offset, hex="02000000", expected_hex="00000000")])
            overrides, _report = zero_page_overrides(self.manifest, self.ram, plan)
            self.assertEqual(overrides[0x100000][offset:offset + 4], b"\x02\x00\x00\x00")
        for offset in (0, 0xf3f, 0xf56, 0xf58, 0x1000):
            with self.assertRaises(ValueError):
                zero_page_overrides(self.manifest, self.ram, dict(self.plan,
                    zero_blob_indices=[], writes=[dict(dva=base + offset,
                        hex="02000000", expected_hex=self.ram[offset:offset + 4].hex())]))
        with self.assertRaises(ValueError):
            zero_page_overrides(self.manifest, self.ram, self.plan)

    def test_delayed_producer_releases_only_after_complete_blocked_witness(self):
        for kind in ("compute", "tiling", "render"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                channels = [dict(name=name, captured_producer=maximum,
                                 state_addrs=(index * 3, index * 3 + 1, index * 3 + 2))
                            for index, (name, maximum) in enumerate(
                                (("TA_2", 1), ("3D_2", 1), ("CL_2", 2)))]
                words = {address: 0 for channel in channels for address in channel["state_addrs"]}
                kicks = []
                witness_read = []

                def kick(message):
                    kicks.append(message)
                    for channel in channels:
                        done, read, write = channel["state_addrs"]
                        words[done] = words[read] = words[write]

                def output():
                    witness_read.append(len(kicks))
                    body = bytearray(PAGE)
                    if kind != "compute":
                        offset, value = EXPECTED["positions"]
                        body[offset:offset + len(value)] = value
                    return bytes(body)

                report = delayed_producer_control(
                    kind, channels, words.__getitem__, words.__setitem__, kick,
                    output, lambda: None, Path(directory))
                self.assertTrue(report["passed_before_release"])
                self.assertTrue(report["released"])
                self.assertFalse(report["synthetic_signal"])
                self.assertEqual(witness_read, [len(kicks) - 3])
                self.assertEqual([words[channel["state_addrs"][2]] for channel in channels],
                                 [1, 1, 2])

    def test_delayed_producer_rejects_any_premature_consumer_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            channels = [dict(name=name, captured_producer=maximum, state_addrs=(i, i, i))
                        for i, (name, maximum) in enumerate((("TA_2", 1), ("3D_2", 1), ("CL_2", 2)))]
            words = {0: 0, 1: 0, 2: 0}
            output = bytearray(PAGE)
            offset, expected = EXPECTED["texture"]
            output[offset + len(expected) - 1] = 1
            with self.assertRaisesRegex(RuntimeError, "before its producer"):
                delayed_producer_control("compute", channels, words.__getitem__,
                    words.__setitem__, lambda _: None, lambda: bytes(output),
                    lambda: None, Path(directory))
            self.assertEqual(words[2], 0)


if __name__ == "__main__":
    unittest.main()
