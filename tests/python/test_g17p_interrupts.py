# SPDX-License-Identifier: MIT
import unittest
from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient"))
from m1n1.agx.g17p_backend import G17PInterruptService


class FakeASC:
    def __init__(self, messages=0, *, continuous=False, type42=True):
        self.messages = int(messages)
        self.continuous = bool(continuous)
        self.type42 = bool(type42)
        self.fw = SimpleNamespace(events=0)
        self.work_calls = 0

    def has_messages(self):
        return self.continuous or self.messages > 0

    def work(self):
        if not self.has_messages():
            return True
        self.work_calls += 1
        if self.messages:
            self.messages -= 1
        if self.type42:
            self.fw.events += 1
        return True


class G17PInterruptServiceTests(unittest.TestCase):
    def test_finite_mailboxes_drain_to_quiescence_and_scan_completion(self):
        ascs = (FakeASC(2), FakeASC(1))
        scans = []

        def completion_service():
            scans.append(len(scans))
            return [{"command": 7}] if len(scans) == 1 else []

        service = G17PInterruptService(ascs, completion_service, budget=8)
        result = service.drain()
        self.assertEqual(result["messages"], 3)
        self.assertEqual(result["type42"], (2, 1))
        self.assertEqual(result["completed"], ({"command": 7},))
        self.assertEqual(result["pending"], (False, False))
        self.assertTrue(result["quiescent"])
        self.assertFalse(result["reschedule"])
        self.assertGreaterEqual(len(scans), 2)

    def test_continuously_asserted_outbox_stops_at_budget(self):
        asc = FakeASC(continuous=True)
        service = G17PInterruptService((asc,), lambda: [], budget=5)
        result = service.drain()
        self.assertEqual(result["messages"], 5)
        self.assertEqual(asc.work_calls, 5)
        self.assertEqual(result["pending"], (True,))
        self.assertFalse(result["quiescent"])
        self.assertTrue(result["reschedule"])
        self.assertEqual(service.snapshot()["budget_exhaustions"], 1)

    def test_budget_one_rotates_between_firmware_instances(self):
        ascs = (FakeASC(continuous=True), FakeASC(continuous=True))
        service = G17PInterruptService(ascs, lambda: [], budget=1)
        service.drain()
        service.drain()
        self.assertEqual([asc.work_calls for asc in ascs], [1, 1])
        self.assertEqual(service.snapshot()["reschedules"], 2)

    def test_non_type42_message_is_counted_without_fabricating_event(self):
        asc = FakeASC(1, type42=False)
        service = G17PInterruptService((asc,), lambda: [], budget=2)
        result = service.drain()
        self.assertEqual(result["messages"], 1)
        self.assertEqual(result["type42"], (0,))

    def test_after_message_service_is_bounded_by_message_budget(self):
        asc = FakeASC(continuous=True)
        serviced = []
        service = G17PInterruptService(
            (asc,), lambda: [], budget=3,
            after_message=lambda owner: serviced.append(owner))
        service.drain()
        self.assertEqual(serviced, [asc, asc, asc])

    def test_invalid_budgets_are_rejected(self):
        with self.assertRaises(ValueError):
            G17PInterruptService((FakeASC(),), lambda: [], budget=0)
        service = G17PInterruptService((FakeASC(),), lambda: [])
        with self.assertRaises(ValueError):
            service.drain(0)


if __name__ == "__main__":
    unittest.main()
