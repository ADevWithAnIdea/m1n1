# SPDX-License-Identifier: MIT

import importlib.util
import pathlib
import unittest


MODULE = (pathlib.Path(__file__).parents[2] / "proxyclient" / "m1n1" /
          "agx" / "g17p_sync.py")
SPEC = importlib.util.spec_from_file_location("g17p_sync", MODULE)
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class ManualFence:
    def __init__(self, error=None):
        self.done = False
        self.error = error

    def signaled(self):
        return self.done

    def wait(self, **_kwargs):
        if not self.done:
            raise TimeoutError
        return self


class G17PSyncObjectTests(unittest.TestCase):
    def test_submission_fence_waits_for_every_command(self):
        tiling = ManualFence()
        fragment = ManualFence()
        fence = SYNC.G17PSubmissionFence(
            (tiling, fragment), name="render", metadata={"queue": 7})
        tiling.done = True
        self.assertFalse(fence.signaled())
        fragment.done = True
        self.assertTrue(fence.signaled())
        self.assertIs(fence.wait(timeout=0), fence)
        self.assertEqual(fence.snapshot()["metadata"], {"queue": 7})
        self.assertEqual(
            fence.snapshot()["state"], SYNC.G17PWorkState.COMPLETED.value)

    def test_submission_fence_propagates_command_error(self):
        compute = ManualFence(error=-5)
        compute.done = True
        fence = SYNC.G17PSubmissionFence((compute,))
        self.assertTrue(fence.signaled())
        self.assertEqual(fence.error, -5)

    def test_fatal_error_signals_only_outstanding_submissions(self):
        tracker = SYNC.G17PFenceTracker()
        completed_child = ManualFence()
        completed = tracker.track((completed_child,), metadata={"vm": 1})
        pending = tracker.track((ManualFence(),), metadata={"vm": 2})
        completed_child.done = True

        self.assertEqual(tracker.fail_all(-19), 1)
        self.assertIsNone(completed.error)
        self.assertEqual(pending.error, -19)
        self.assertTrue(pending.signaled())
        self.assertEqual(
            pending.snapshot()["state"], SYNC.G17PWorkState.FAILED.value)
        self.assertEqual(pending.snapshot()["terminal_reason"], "device-lost")
        self.assertFalse(pending.fail(-5))
        self.assertEqual(tracker.prune(), 2)

    def test_queue_error_signals_only_matching_submissions(self):
        tracker = SYNC.G17PFenceTracker()
        queue_a = tracker.track(
            (ManualFence(),), metadata={"vm": 1, "queue": 7})
        queue_b = tracker.track(
            (ManualFence(),), metadata={"vm": 1, "queue": 8})
        other_vm = tracker.track(
            (ManualFence(),), metadata={"vm": 2, "queue": 7})

        self.assertEqual(tracker.fail_matching(
            SYNC.G17PWorkError.KILLED, vm=1, queue=7), 1)
        self.assertEqual(queue_a.error, -125)
        self.assertTrue(queue_a.signaled())
        self.assertFalse(queue_b.signaled())
        self.assertFalse(other_vm.signaled())

    def test_linux_work_error_values_are_stable_on_any_host(self):
        self.assertEqual(SYNC.G17PWorkError.MMU_FAULT, -5)
        self.assertEqual(SYNC.G17PWorkError.TIMEOUT, -110)
        self.assertEqual(SYNC.G17PWorkError.KILLED, -125)
        self.assertEqual(SYNC.G17PWorkError.DEVICE_LOST, -19)
        self.assertEqual(SYNC.G17PWorkError.UNKNOWN, -61)

    def test_submission_fence_rejects_invalid_terminal_state(self):
        with self.assertRaises(ValueError):
            SYNC.G17PSubmissionFence(())
        fence = SYNC.G17PSubmissionFence((ManualFence(),))
        with self.assertRaises(ValueError):
            fence.fail(0)

    def test_rejected_work_has_attribution_but_no_fence(self):
        record = SYNC.G17PRejectedWork(
            ValueError("bad field"), "command-validation",
            {"vm_id": 2, "queue_id": 7, "command_index": 3})
        snapshot = record.snapshot()
        self.assertEqual(snapshot["state"], "rejected")
        self.assertEqual(snapshot["stage"], "command-validation")
        self.assertEqual(snapshot["metadata"]["command_index"], 3)
        self.assertIsNone(snapshot["fence"])

    def test_binary_replace_and_reset(self):
        sync = SYNC.G17PSyncObject()
        first = ManualFence()
        sync.bind(first)
        self.assertFalse(sync.signaled())
        first.done = True
        self.assertTrue(sync.signaled())

        second = ManualFence()
        sync.bind(second)
        self.assertFalse(sync.signaled())
        sync.reset()
        self.assertIsNone(sync.point())

    def test_timeline_higher_point_satisfies_lower_wait(self):
        sync = SYNC.G17PSyncObject(timeline=True)
        point_three = ManualFence()
        point_six = ManualFence()
        sync.bind(point_three, 3)
        sync.bind(point_six, 6)
        self.assertFalse(sync.signaled(4))
        point_six.done = True
        self.assertTrue(sync.signaled(4))
        self.assertEqual(sync.wait(4, timeout=0).value, 6)
        self.assertEqual(sync.query(), 6)

    def test_software_error_point_is_complete(self):
        sync = SYNC.G17PSyncObject(timeline=True)
        point = sync.signal(9, error=-5)
        self.assertTrue(sync.signaled(9))
        self.assertEqual(sync.wait(9, timeout=0).error, -5)

    def test_invalid_binary_value_and_duplicate_timeline_point(self):
        with self.assertRaises(ValueError):
            SYNC.G17PSyncObject().bind(ManualFence(), 1)
        sync = SYNC.G17PSyncObject(timeline=True)
        sync.bind(ManualFence(), 1)
        with self.assertRaises(ValueError):
            sync.bind(ManualFence(), 1)

    def test_rejected_submission_does_not_replace_out_sync(self):
        old = ManualFence()
        out_sync = SYNC.G17PSyncObject()
        old_point = out_sync.bind(old)
        plan = SYNC.G17PSubmissionSyncPlan(
            out_syncs=((out_sync, 0),))

        def reject():
            raise ValueError("invalid command buffer")

        with self.assertRaisesRegex(ValueError, "invalid command buffer"):
            plan.publish(reject, timeout=0)
        self.assertIs(out_sync.point(), old_point)
        self.assertIsNone(plan.fence)

    def test_published_submission_replaces_binary_and_adds_timeline(self):
        child = ManualFence()
        submission = SYNC.G17PSubmissionFence((child,))
        binary = SYNC.G17PSyncObject()
        timeline = SYNC.G17PSyncObject(timeline=True)
        plan = SYNC.G17PSubmissionSyncPlan(
            out_syncs=((binary, 0), (timeline, 7)))

        self.assertIs(plan.publish(lambda: submission, timeout=0), submission)
        self.assertIs(binary.point().fence, submission)
        self.assertIs(timeline.point(7).fence, submission)
        child.done = True
        self.assertEqual(timeline.query(), 7)

    def test_failed_input_sync_rejects_before_publication(self):
        failed = SYNC.G17PSyncObject()
        failed.signal(error=SYNC.G17PWorkError.MMU_FAULT)
        out_sync = SYNC.G17PSyncObject()
        called = []
        plan = SYNC.G17PSubmissionSyncPlan(
            in_syncs=((failed, 0),), out_syncs=((out_sync, 0),))

        with self.assertRaises(OSError) as caught:
            plan.publish(lambda: called.append(True), timeout=0)
        self.assertEqual(caught.exception.errno, 5)
        self.assertEqual(called, [])
        self.assertIsNone(out_sync.point())

    def test_invalid_timeline_output_rejects_before_publication(self):
        timeline = SYNC.G17PSyncObject(timeline=True)
        timeline.bind(ManualFence(), 4)
        called = []
        plan = SYNC.G17PSubmissionSyncPlan(
            out_syncs=((timeline, 4),))

        with self.assertRaisesRegex(ValueError, "already bound"):
            plan.publish(lambda: called.append(True), timeout=0)
        self.assertEqual(called, [])

    def test_logical_queue_destroy_defers_physical_release(self):
        released = []
        queue = SYNC.G17PLogicalQueue(
            release=lambda: released.append(True), name="queue 4")
        child = ManualFence()
        fence = queue.track(SYNC.G17PSubmissionFence((child,)))

        self.assertFalse(queue.destroy())
        self.assertFalse(queue.accepting)
        self.assertFalse(queue.released)
        self.assertEqual(queue.outstanding(), [fence])
        self.assertEqual(released, [])
        with self.assertRaisesRegex(RuntimeError, "destroyed"):
            queue.track(SYNC.G17PSubmissionFence((ManualFence(),)))

        child.done = True
        self.assertTrue(queue.reap())
        self.assertTrue(queue.released)
        self.assertEqual(released, [True])
        self.assertFalse(queue.reap())

    def test_idle_logical_queue_destroy_releases_immediately(self):
        released = []
        queue = SYNC.G17PLogicalQueue(release=lambda: released.append(True))

        self.assertTrue(queue.destroy())
        self.assertEqual(released, [True])

    def test_device_loss_preserves_completed_queue_fence(self):
        tracker = SYNC.G17PFenceTracker()
        completed_child = ManualFence()
        completed = tracker.track(
            (completed_child,), metadata={"queue_pair": 1})
        pending = tracker.track(
            (ManualFence(),), metadata={"queue_pair": 1})
        completed_child.done = True

        self.assertEqual(
            tracker.fail_all(SYNC.G17PWorkError.DEVICE_LOST), 1)
        self.assertIsNone(completed.error)
        self.assertEqual(pending.error, SYNC.G17PWorkError.DEVICE_LOST)


if __name__ == "__main__":
    unittest.main()
