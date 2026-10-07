# SPDX-License-Identifier: MIT
import copy
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient" / "m1n1" / "agx"))
import g17p_reports as reports


class ReportTests(unittest.TestCase):
    def test_owned_class1_receipt_matches_every_transaction_byte_once(self):
        prefix = reports.build_class1_registration_receipt(
            1, 0xfffffc20c0840000, 0x70019e8000)
        expected = struct.pack("<IIIQQQI", 13, 1, 1,
                               0xfffffc20c0840000, 0x70019e8000, 0x70019e8580, 0x28)
        self.assertEqual(prefix, expected)
        receipt = prefix + bytes(32)
        row = dict(slot=1, record_hex=receipt.hex())
        snapshot = {"primary_ch13": {"records": [row], "pending": 1}}
        self.assertTrue(reports.unhandled_channel13(snapshot))
        self.assertEqual(reports.unhandled_channel13(
            snapshot, owned_control_receipts=(prefix,)), [])
        self.assertTrue(reports.unhandled_channel13(
            {"secondary_ch13": snapshot["primary_ch13"]},
            owned_control_receipts=(prefix,)))
        for offset in range(len(receipt)):
            changed = bytearray(receipt)
            changed[offset] ^= 0x80
            altered = {"primary_ch13": {"records": [dict(slot=1, record_hex=changed.hex())]}}
            failures = reports.unhandled_channel13(altered, owned_control_receipts=(prefix,))
            self.assertEqual(bool(failures), offset < len(prefix), offset)
        snapshot["primary_ch13"]["records"].append(dict(row, slot=2))
        self.assertEqual(len(reports.unhandled_channel13(
            snapshot, owned_control_receipts=(prefix,))), 1)

    def test_only_identical_prekick_startup_report_is_exempt(self):
        body, read = self.fixture(0, 1)
        struct.pack_into("<3I", body, 0x2c0, 13, 1, 0)
        before = reports.snapshot_channel13(read, (0x40, 0x2c0, 0x80), 0x4ac0)
        struct.pack_into("<I", body, 0x60, 2)
        struct.pack_into("<4I", body, 0x2c0 + 0x48, 1, 3, 0, 0)
        after = reports.snapshot_channel13(read, (0x40, 0x2c0, 0x80), 0x4ac0)
        snapshot = {"primary_ch13": after}
        baseline = {"primary_ch13": before}
        self.assertTrue(reports.unhandled_channel13(snapshot))
        self.assertEqual(reports.unhandled_channel13(snapshot, startup_snapshot=baseline), [])
        for change in ("body", "backing", "consumer", "truncated"):
            modified = copy.deepcopy(before)
            if change == "body":
                modified["records"][0]["record_hex"] = bytes(72).hex()
            elif change == "backing":
                modified["records_address"] += 0x4000
            elif change == "consumer":
                modified["counters"][0]["host"] = 1
            else:
                modified["truncated"] = True
            self.assertTrue(reports.unhandled_channel13(snapshot,
                startup_snapshot={"primary_ch13": modified}), change)
        # Another type 13 during the draw is not exempt, nor is any type 7.
        for opcode in (13, 7):
            struct.pack_into("<3I", body, 0x2c0 + 0x48, opcode, 1, 0)
            updated = reports.snapshot_channel13(read, (0x40, 0x2c0, 0x80), 0x4ac0)
            failures = reports.unhandled_channel13({"primary_ch13": updated},
                                                   startup_snapshot=baseline)
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0]["opcode"], opcode)

    def test_unhandled_report_attribution_never_accepts_retirement(self):
        descriptor = 0xfffffc20c00b0000
        body = bytearray(reports.RECORD_SIZE)
        struct.pack_into("<5I", body, 0, 7, 0, 1, 1, 0x100)
        struct.pack_into("<Q", body, 0x28, descriptor)
        snapshot = {"primary_ch13": {"records": [dict(slot=0, record_hex=body.hex())]}}
        failure, = reports.unhandled_channel13(snapshot, (descriptor,))
        self.assertEqual(failure["opcode"], 7)
        self.assertEqual(failure["reported_descriptor"], descriptor)
        self.assertTrue(failure["owned_descriptor"])
        failure, = reports.unhandled_channel13(snapshot, (descriptor + 0x4000,))
        self.assertFalse(failure["owned_descriptor"])
        struct.pack_into("<I", body, 0, 1)
        snapshot["primary_ch13"]["records"][0]["record_hex"] = body.hex()
        self.assertEqual(reports.unhandled_channel13(snapshot), [])
        snapshot["primary_ch13"]["truncated"] = True
        self.assertEqual(reports.unhandled_channel13(snapshot)[0]["reason"],
                         "incomplete-report-snapshot")

    def test_short_or_unknown_reports_fail_closed(self):
        for body in (b"\1", struct.pack("<I", 99) + bytes(68)):
            snapshot = {"secondary_ch13": {"records": [dict(record_hex=body.hex())]}}
            self.assertTrue(reports.unhandled_channel13(snapshot))

    def fixture(self, head, tail):
        body = bytearray(0x8000)
        struct.pack_into("<I", body, 0x40, head)
        struct.pack_into("<I", body, 0x60, tail)
        for slot in range(256):
            struct.pack_into("<4I", body, 0x2c0 + slot * 0x48, 4, slot, 0, 0)
            body[0x2c0 + (slot + 1) * 0x48 - 1] = 0xA5
        return body, lambda address, size: bytes(body[address:address + size])

    def test_state_one_is_record_buffer_not_counter(self):
        body, read = self.fixture(0, 1)
        before = bytes(body)
        result = reports.snapshot_channel13(read, (0x40, 0x2c0, 0x80), 0x4ac0)
        self.assertEqual(result["pending"], 1)
        self.assertEqual(result["records"][0]["header"], (4, 0, 0, 0))
        self.assertEqual(len(bytes.fromhex(result["records"][0]["record_hex"])), 0x48)
        self.assertTrue(result["records"][0]["record_hex"].endswith("a5"))
        self.assertEqual(bytes(body), before)

    def test_wrapped_pending_window_and_bound(self):
        _body, read = self.fixture(255, 2)
        result = reports.snapshot_channel13(read, (0x40, 0x2c0, 0x80), 0x4ac0, limit=2)
        self.assertEqual([row["slot"] for row in result["records"]], [255, 0])
        self.assertEqual(result["pending"], 3)
        self.assertTrue(result["truncated"])

    def test_empty_and_invalid_layout(self):
        _body, read = self.fixture(1, 1)
        self.assertEqual(reports.snapshot_channel13(
            read, (0x40, 0x2c0, 0x80), 0x4ac0)["records"], [])
        with self.assertRaises(ValueError):
            reports.snapshot_channel13(read, (0x40, 0x2c0, 0x80), 0x4ac4)
        _body, read = self.fixture(256, 1)
        with self.assertRaises(ValueError):
            reports.snapshot_channel13(read, (0x40, 0x2c0, 0x80), 0x4ac0)


if __name__ == "__main__":
    unittest.main()
