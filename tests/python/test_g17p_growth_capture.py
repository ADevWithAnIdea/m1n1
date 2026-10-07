# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient/experiments"))
from g17p_growth_capture import load_capture, Snapshot, PAGE


class TwoOwnerCaptureTests(unittest.TestCase):
    def test_pool_ownership_uses_typed_pointers_not_capture_specific_addresses(self):
        snapshot = Snapshot.__new__(Snapshot)
        shared, blocks, state = 0xfffffc2000000000, 0xfffffc2000020000, 0xfffffc2000030000
        body = bytearray(PAGE)
        struct.pack_into('<I', body, 0xc, 1)
        struct.pack_into('<II', body, 0x30, 0xc000, 32)
        struct.pack_into('<II', body, 0x3c, 8, 0)
        struct.pack_into('<QQ', body, 0x44, blocks, state)
        struct.pack_into('<II', body, 0x54, 31, 0x20000)
        snapshot.mappings = {(64, shared): PAGE, (64, blocks): PAGE * 2,
                             (64, blocks + PAGE): PAGE * 3, (64, state): PAGE * 4}
        snapshot.ram = {PAGE: body, PAGE * 2: bytes(PAGE), PAGE * 3: bytes(PAGE),
                        PAGE * 4: struct.pack('<II', 8, 8) + bytes(PAGE - 8)}
        snapshot.tables, snapshot.fixed = {}, {}
        self.assertEqual(snapshot.pool(64, 1), dict(shared=shared, blocks=blocks, state=state))
        with self.assertRaisesRegex(ValueError, 'unambiguous'):
            snapshot.pool(64, 0)

    def fixture(self, directory):
        before = b"\xa5" * 0x10000
        old = struct.pack("<I", 28) + bytes(0xfffc)
        after = struct.pack("<I", 28 * 200000) + bytes(0xfffc)
        for name, body in (("before", before), ("after", after), ("old", old), ("retained", old)):
            (directory / name).write_bytes(body)
        target = dict(dva=0x10000098000, root=dict(context=1))
        report = dict(format="neo-native-growth-observation-v1", completion_marker=True,
            full_capture=True, staged_assets=dict(owners=True),
            targets={"1": dict(triangles=200000)}, markers=[],
            first_request=dict(record_hex=(struct.pack("<4I", 6, 1, 1, 0) + bytes(56)).hex()),
            publications=[dict(record_hex=(struct.pack("<5I", 8, 1, 1, 1, 0) + bytes(44)).hex())],
            snapshots=[dict(label=label, path=str(directory / label))
                       for label in ("first_work_0", "first_work_1", "reply_0")],
            samples=[dict(label="first_work_1", target=dict(target, file="before")),
                     dict(label="completed_0", exact_output=True, target=dict(file="old")),
                     dict(label="completed_1", exact_output=True, target=dict(target, file="after"),
                          earlier_outputs=[dict(owner=0, exact=True, file="retained")])])
        (directory / "manifest.json").write_text(json.dumps(report))
        return report

    def test_two_owner_capture_selects_second_work_and_checks_retained_bytes(self):
        with tempfile.TemporaryDirectory() as path, patch("g17p_growth_capture.Snapshot") as snapshot:
            directory = Path(path)
            self.fixture(directory)
            snapshot.return_value.read.return_value = b"\xa5" * 0x10000
            report, snapshots, ctx, target, before, after = load_capture(directory)
            self.assertEqual((ctx, target), (1, 0x10000098000))
            self.assertEqual(set(snapshots), {"first_work_0", "first_work", "reply_0"})
            self.assertEqual(after, struct.pack("<I", 5600000) + bytes(0xfffc))
            (directory / "retained").write_bytes(bytes(0x10000))
            with self.assertRaisesRegex(ValueError, "retained first output changed"):
                load_capture(directory)

    def test_two_owner_capture_requires_independent_completion(self):
        with tempfile.TemporaryDirectory() as path, patch("g17p_growth_capture.Snapshot"):
            directory = Path(path)
            report = self.fixture(directory)
            report["samples"][-1]["earlier_outputs"] = []
            (directory / "manifest.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "retained first output proof"):
                load_capture(directory)

    def both_fixture(self, directory):
        report = self.fixture(directory)
        report['staged_assets']['both'] = True
        report['targets']['0'] = dict(triangles=200000)
        for name in ('old', 'retained'):
            (directory / name).write_bytes((directory / 'after').read_bytes())
        report['samples'].insert(0, dict(label='first_work_0',
            target=dict(dva=0x10000080000, root=dict(context=1), file='before')))
        report['samples'][2]['target'].update(dva=0x10000080000, root=dict(context=1))
        report['publications'].insert(0, dict(record_hex=(
            struct.pack('<5I', 8, 1, 0, 1, 0) + bytes(44)).hex()))
        report['report_publications'] = [dict(record_hex=(
            struct.pack('<4I', 6, 1, owner, 0) + bytes(56)).hex()) for owner in (0, 1)]
        report['snapshots'] = [
            dict(label='first_work_0', path=str(directory / 'first_work_0')),
            dict(label='reply_0', path=str(directory / 'owner0_reply0')),
            dict(label='first_work_1', path=str(directory / 'first_work_1')),
            dict(label='reply_0', path=str(directory / 'owner1_reply0'))]
        (directory / 'manifest.json').write_text(json.dumps(report))
        return report

    def test_both_pools_counter_zero_selects_chronological_owned_reply(self):
        with tempfile.TemporaryDirectory() as path, patch('g17p_growth_capture.Snapshot') as snapshot:
            directory = Path(path)
            self.both_fixture(directory)
            snapshot.return_value.read.return_value = b'\xa5' * 0x10000
            for owner in (0, 1):
                snapshot.reset_mock()
                report, snapshots, ctx, target, before, after = load_capture(directory, owner)
                self.assertEqual(struct.unpack_from('<4I', bytes.fromhex(
                    report['first_request']['record_hex'])), (6, 1, owner, 0))
                self.assertEqual(struct.unpack_from('<5I', bytes.fromhex(
                    report['publications'][0]['record_hex'])), (8, 1, owner, 1, 0))
                self.assertEqual(target, (0x10000080000, 0x10000098000)[owner])
                paths = [call.args[0] for call in snapshot.call_args_list]
                self.assertIn(str(directory / ('owner%d_reply0' % owner)), paths)
                self.assertNotIn(str(directory / ('owner%d_reply0' % (1 - owner))), paths)
                self.assertEqual(after, struct.pack('<I', 5600000) + bytes(0xfffc))

    def test_both_pools_missing_reply_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            report = self.both_fixture(directory)
            report['snapshots'].pop()
            (directory / 'manifest.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'one snapshot per reply'):
                load_capture(directory, 0)


if __name__ == "__main__":
    unittest.main()
