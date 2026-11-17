# SPDX-License-Identifier: GPL-2.0-or-later
"""Submission bookkeeping without importing GPU assets or contacting hardware."""
import ast
from pathlib import Path
from types import SimpleNamespace as N
import unittest

ROOT = Path(__file__).resolve().parents[4]


class Fence:
    def __init__(self, done=False):
        self.done = done
        self.metadata = {}
        self.fences = ()

    def signaled(self):
        return self.done

    def fail(self, code, **kwargs):
        self.done = True
        self.error = code


def publisher():
    path = ROOT / 'proxyclient/m1n1/drm_shim/g17g_modern.py'
    tree = ast.parse(path.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'G17GModernDriver')
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_publish_submission')
    import errno
    namespace = dict(G17GSubmissionFence=Fence, DRM_ASAHI_CMD_RENDER=1, errno=errno)
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['_publish_submission']


class Retirement(unittest.TestCase):
    def submit(self, bos, timestamp_bos=(), *, fail=False):
        fence = Fence()
        tracked, bound = [], []
        def publish(*args, **kwargs):
            if fail:
                raise MemoryError('owned allocation fixture')
            return fence
        adapter = N(prepare_submission=lambda *_: fence, submit=publish)
        driver = N(adapter=adapter, reap_deferred=lambda: None)
        vm = N(vm_id=1, token=2, bindings=[N(bo=bo) for bo in bos])
        queue = N(vm=vm, queue_id=3, lifetime=N(track=tracked.append, reap=lambda: None))
        objects = [N(bo=bo) for bo in timestamp_bos]
        command = N(index=0, header=N(cmd_type=0),
                    timestamp_objects=[('timestamp', obj, 0) for obj in objects])
        sync = N(bind=lambda value, point: bound.append((value, point)))
        plan = N(out_syncs=((sync, 7),))
        result = publisher()(driver, N(fd=10), queue, (command,), plan)
        self.assertIs(result[0], fence)
        self.assertEqual(tracked, [fence])
        self.assertEqual(bound, [(fence, 7)])
        self.assertIs(plan.fence, fence)
        return fence

    def test_completed_history_is_bounded_and_pending_fence_is_retained(self):
        pending = Fence()
        bo = N(fences=[Fence(done=True) for _ in range(1000)] + [pending])
        current = self.submit([bo])
        self.assertEqual(bo.fences, [pending, current])

    def test_timestamp_only_bo_is_pruned_and_tracks_new_submission(self):
        bo = N(fences=[Fence(done=True)])
        current = self.submit([], [bo])
        self.assertEqual(bo.fences, [current])
        self.assertEqual(current.bos, ())
        self.assertIs(current.resources[0].bo, bo)

    def test_multiply_bound_and_timestamp_referenced_bo_tracks_fence_once(self):
        bo = N(fences=[])
        current = self.submit([bo, bo], [bo, bo])
        self.assertEqual(bo.fences, [current])
        self.assertEqual(current.bos, (bo,))

    def test_external_reference_keeps_terminal_result(self):
        completed = Fence(done=True)
        completed.error = -5
        external_sync = N(fence=completed)
        bo = N(fences=[completed])
        self.submit([bo])
        self.assertIs(external_sync.fence, completed)
        self.assertEqual(external_sync.fence.error, -5)

    def test_publication_failure_keeps_same_attached_fence(self):
        bo = N(fences=[Fence(done=True)])
        current = self.submit([bo], fail=True)
        self.assertEqual(bo.fences, [current])
        self.assertTrue(current.signaled())
        self.assertEqual(current.error, -12)


if __name__ == '__main__':
    unittest.main()
