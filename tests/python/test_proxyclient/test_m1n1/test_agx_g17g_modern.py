# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the generation-neutral Asahi UAPI boundary on T8142/G17G."""

import ctypes
import errno
from concurrent.futures import ThreadPoolExecutor
import pathlib
import sys
import threading
import unittest


sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[4] / "proxyclient")
)

from m1n1.drm_shim import g17g_modern as modern  # noqa: E402
from m1n1.drm_shim import g17g_sync as sync  # noqa: E402
from m1n1.drm_shim import g17g_uapi as uapi  # noqa: E402


class ManualFence:
    def __init__(self):
        self.done = False
        self.error = None
        self.metadata = {}

    def signaled(self):
        return self.done

    def snapshot(self):
        return {
            "signaled": self.done,
            "error": self.error,
            "metadata": dict(self.metadata),
        }


class Adapter:
    def __init__(self):
        self.calls = []
        self.children = []

    def create_vm(self, file, vm):
        self.calls.append(("create_vm", file.fd, vm.vm_id))
        return "context-%d" % vm.vm_id

    def destroy_vm(self, file, vm):
        self.calls.append(("destroy_vm", file.fd, vm.vm_id))

    def create_bo(self, file, bo):
        self.calls.append(("create_bo", file.fd, bo.handle))
        return "bo-%d" % bo.handle

    def destroy_bo(self, file, bo):
        self.calls.append(("destroy_bo", file.fd, bo.handle))

    def bind(self, file, vm, binding):
        self.calls.append(("bind", file.fd, vm.vm_id, binding.addr))
        return "binding-%x" % binding.addr

    def unbind(self, file, vm, binding):
        self.calls.append(("unbind", file.fd, vm.vm_id, binding.addr))

    def create_queue(self, file, queue):
        self.calls.append((
            "create_queue", file.fd, queue.queue_id, queue.usc_exec_base,
        ))

        def resolve_internal_range(address, size, required, label):
            del required, label
            return (
                modern.USC_EXEC_BASE <= address
                and address + size <= modern.USC_EXEC_BASE + (1 << 32)
            )

        return {"resolve_internal_range": resolve_internal_range}

    def destroy_queue(self, file, queue):
        self.calls.append(("destroy_queue", file.fd, queue.queue_id))

    def preflight(self, file, queue, commands):
        self.calls.append(("preflight", file.fd, queue.queue_id, len(commands)))

    def submit(self, file, queue, commands):
        self.calls.append(("submit", file.fd, queue.queue_id, len(commands)))
        child = ManualFence()
        self.children.append(child)
        return sync.G17GSubmissionFence((child,))


def compute_command(cdm=0x10000, attachments=(), sampler_heap=0,
                    sampler_count=0):
    payload = uapi.drm_asahi_cmd_compute()
    payload.cdm_ctrl_stream_base = cdm
    payload.cdm_ctrl_stream_end = cdm + 0x40
    payload.sampler_heap = sampler_heap
    payload.sampler_count = sampler_count
    prefix = b""
    if attachments:
        body = b"".join(item.to_bytes() for item in attachments)
        header = uapi.drm_asahi_cmd_header(
            uapi.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS,
            len(body),
            uapi.DRM_ASAHI_BARRIER_NONE,
            uapi.DRM_ASAHI_BARRIER_NONE,
        )
        prefix = header.to_bytes() + body
    header = uapi.drm_asahi_cmd_header(
        uapi.DRM_ASAHI_CMD_COMPUTE,
        len(payload.to_bytes()),
        uapi.DRM_ASAHI_BARRIER_NONE,
        uapi.DRM_ASAHI_BARRIER_NONE,
    )
    return prefix + header.to_bytes() + payload.to_bytes()


def render_command():
    payload = uapi.drm_asahi_cmd_render()
    payload.flags = uapi.DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES
    payload.vdm_ctrl_stream_base = 0x10000
    payload.isp_scissor_base = 0x20000
    payload.ppp_multisamplectl = 0x88
    payload.ppp_ctrl = 0x202
    payload.width_px = 64
    payload.height_px = 48
    payload.layers = 1
    payload.utile_width_px = 32
    payload.utile_height_px = 32
    payload.samples = 1
    payload.sample_size_B = 4
    payload.bg.usc = 0x10000
    payload.bg.rsrc_spec = 0x40
    payload.eot.usc = 0x20000
    payload.partial_bg.usc = 0x30000
    payload.partial_eot.usc = 0x40000
    header = uapi.drm_asahi_cmd_header(
        uapi.DRM_ASAHI_CMD_RENDER,
        len(payload.to_bytes()),
        uapi.DRM_ASAHI_BARRIER_NONE,
        uapi.DRM_ASAHI_BARRIER_NONE,
    )
    return header.to_bytes() + payload.to_bytes()


class G17GModernTests(unittest.TestCase):
    def setUp(self):
        self.adapter = Adapter()
        self.driver = modern.G17GModernDriver(self.adapter)
        self.vm = self.driver.create_vm(
            10,
            modern.VM_END - modern.VM_KERNEL_MIN_SIZE,
            modern.VM_END,
        )

    def bind_range(self, handle, address, size=modern.PAGE_SIZE,
                   flags=None):
        if flags is None:
            flags = uapi.DRM_ASAHI_BIND_READ | uapi.DRM_ASAHI_BIND_WRITE
        bo = self.driver.create_bo(10, handle, handle * modern.PAGE_SIZE, size)
        operation = uapi.drm_asahi_gem_bind_op(
            flags, handle, 0, size, address
        )
        return self.driver.bind(10, self.vm.vm_id, operation)

    def create_queue(self, requested_base=modern.USC_EXEC_BASE):
        return self.driver.create_queue(
            10, self.vm.vm_id, 1, requested_base
        )

    def test_exact_uapi_structure_sizes_and_extensible_tail(self):
        for structure, expected in uapi.EXPECTED_STRUCTURE_SIZES.items():
            self.assertEqual(ctypes.sizeof(structure), expected)
        payload = uapi.drm_asahi_cmd_compute()
        self.assertEqual(
            uapi.drm_asahi_cmd_compute.from_bytes(
                payload.to_bytes() + bytes(16), extensible=True
            ).to_bytes(),
            payload.to_bytes(),
        )
        with self.assertRaisesRegex(ValueError, "unknown"):
            uapi.drm_asahi_cmd_compute.from_bytes(
                payload.to_bytes() + b"\x01", extensible=True
            )

    def test_queue_rejects_relocated_execution_base_before_creation(self):
        for requested in (0, 0xDEADBEEF000):
            with self.assertRaises(OSError) as raised:
                self.create_queue(requested)
            self.assertEqual(raised.exception.errno, errno.ENOTSUP)
        self.assertFalse(self.driver.file(10).queues)
        first = self.create_queue()
        self.assertEqual(first.usc_exec_base, modern.USC_EXEC_BASE)
        calls = [call for call in self.adapter.calls
                 if call[0] == "create_queue"]
        self.assertEqual(
            [call[3] for call in calls],
            [modern.USC_EXEC_BASE],
        )

    def test_vm_bo_bind_unbind_and_queue_lifecycle(self):
        binding = self.bind_range(7, 0x1000000000, 2 * modern.PAGE_SIZE)
        queue = self.create_queue()
        with self.assertRaisesRegex(RuntimeError, "queues"):
            self.driver.destroy_vm(10, self.vm.vm_id)
        self.driver.destroy_queue(10, queue.queue_id)
        self.assertTrue(queue.lifetime.released)
        operation = uapi.drm_asahi_gem_bind_op(
            uapi.DRM_ASAHI_BIND_UNBIND,
            0,
            0,
            binding.size,
            binding.addr,
        )
        self.driver.bind(10, self.vm.vm_id, operation)
        self.assertTrue(self.driver.destroy_bo(10, binding.bo.handle))
        self.driver.destroy_vm(10, self.vm.vm_id)

    def test_compute_submit_resolves_resources_syncs_and_deferred_close(self):
        self.bind_range(30, 0x10000)
        attachment_binding = self.bind_range(31, 0x20000)
        queue = self.create_queue()
        attachment = uapi.drm_asahi_attachment(
            attachment_binding.addr, 0x100, 0, 0
        )
        output = uapi.drm_asahi_sync(
            uapi.DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ, 4, 9
        )
        fence, commands = self.driver.submit(
            10,
            queue.queue_id,
            compute_command(attachments=(attachment,)),
            out_syncs=(output,),
        )
        state = commands[0].hardware_state
        self.assertEqual(state.cdm_terminator, 0x1003C)
        self.assertEqual(state.usc_exec_base, modern.USC_EXEC_BASE)
        self.assertEqual(state.attachments, ((0x20000, 0x100),))
        self.assertIs(self.driver.file(10).syncs[4].point(9).fence, fence)
        self.driver.destroy_queue(10, queue.queue_id)
        self.assertFalse(queue.lifetime.released)
        self.assertTrue(self.driver.destroy_bo(10, attachment_binding.bo.handle))
        self.assertTrue(self.driver.deferred_bos)
        self.adapter.children[-1].done = True
        self.driver.reap_deferred()
        self.assertTrue(queue.lifetime.released)
        self.assertFalse(self.driver.deferred_bos)

    def test_rejection_is_transactional_and_attributed(self):
        self.bind_range(30, 0x10000)
        queue = self.create_queue()
        output = uapi.drm_asahi_sync(
            uapi.DRM_ASAHI_SYNC_SYNCOBJ, 5, 0
        )
        old = self.driver.signal_external_sync(10, output)
        with self.assertRaises(ValueError):
            self.driver.submit(
                10, queue.queue_id, b"bad", out_syncs=(output,)
            )
        self.assertIs(self.driver.file(10).syncs[5].point(), old)
        rejected = self.driver.rejections[-1].snapshot()
        self.assertEqual(rejected["state"], "rejected")
        self.assertEqual(rejected["stage"], "command-buffer")
        self.assertEqual(rejected["metadata"]["vm_id"], self.vm.vm_id)
        self.assertEqual(rejected["metadata"]["queue_id"], queue.queue_id)
        self.assertIsNone(rejected["fence"])

    def test_fence_owns_resources_and_output_sync_before_publication(self):
        binding = self.bind_range(30, 0x10000)
        queue = self.create_queue()
        output = uapi.drm_asahi_sync(uapi.DRM_ASAHI_SYNC_SYNCOBJ, 5, 0)
        child = sync.G17GSoftwareFence()
        pending = sync.G17GSubmissionFence((child,))
        self.adapter.prepare_submission = lambda *_args: pending

        def publish(file, selected, commands, *, fence):
            self.assertIs(fence, pending)
            self.assertIs(file.syncs[5].point().fence, pending)
            self.assertEqual(selected.lifetime.outstanding(), [pending])
            self.assertIn(pending, binding.bo.fences)
            self.assertEqual(pending.bindings, (binding,))
            self.assertEqual(child.metadata['command_index'], commands[0].index)
            self.assertFalse(pending.signaled())
            # Closing the handle during execution cannot release its backing.
            self.driver.destroy_bo(10, binding.bo.handle)
            self.assertTrue(self.driver.deferred_bos)
            self.assertNotIn(('destroy_bo', 10, 30), self.adapter.calls)
            child.signal()
            return fence

        self.adapter.submit = publish
        fence, _ = self.driver.submit(10, queue.queue_id, compute_command(), out_syncs=(output,))
        self.assertIs(fence, pending)
        self.assertTrue(fence.signaled())
        self.assertFalse(self.driver.deferred_bos)
        self.assertIn(('destroy_bo', 10, 30), self.adapter.calls)

    def test_admitted_allocation_failure_completes_the_original_fence(self):
        self.bind_range(30, 0x10000)
        queue = self.create_queue()
        output = uapi.drm_asahi_sync(uapi.DRM_ASAHI_SYNC_SYNCOBJ, 5, 0)
        pending = sync.G17GSubmissionFence((sync.G17GSoftwareFence(),))
        self.adapter.prepare_submission = lambda *_args: pending
        def fail(*_args, **_kwargs):
            raise MemoryError('allocation failed after admission')
        self.adapter.submit = fail
        fence, _ = self.driver.submit(10, queue.queue_id, compute_command(), out_syncs=(output,))
        self.assertIs(fence, pending)
        self.assertIs(self.driver.file(10).syncs[5].point().fence, pending)
        self.assertTrue(fence.signaled())
        self.assertEqual(fence.error, -errno.ENOMEM)

    def test_unknown_input_sync_is_not_fabricated_as_complete(self):
        self.bind_range(30, 0x10000)
        queue = self.create_queue()
        dependency = uapi.drm_asahi_sync(uapi.DRM_ASAHI_SYNC_SYNCOBJ, 5, 0)
        with self.assertRaisesRegex(ValueError, "has no fence"):
            self.driver.submit(10, queue.queue_id, compute_command(), in_syncs=(dependency,))
        self.assertFalse(self.adapter.children)
        self.assertIsNone(self.driver.file(10).syncs[5].point())
        self.driver.signal_external_sync(10, dependency)
        self.driver.submit(10, queue.queue_id, compute_command(), in_syncs=(dependency,))
        self.assertEqual(len(self.adapter.children), 1)

    def test_duplicate_output_point_is_rejected_before_publication(self):
        self.bind_range(30, 0x10000)
        queue = self.create_queue()
        point = uapi.drm_asahi_sync(uapi.DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ, 9, 3)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.driver.submit(10, queue.queue_id, compute_command(), out_syncs=(point, point))
        self.assertFalse(self.adapter.children)
        self.assertIsNone(self.driver.file(10).syncs[9].point(3))

    def test_close_and_remap_cannot_race_hardware_ownership(self):
        for action in ("close", "remap"):
            with self.subTest(action=action):
                self.setUp()
                binding = self.bind_range(30, 0x10000)
                queue = self.create_queue()
                entered, release, attempted, finished = (threading.Event() for _ in range(4))
                original = self.adapter.submit
                def blocked_submit(*args):
                    entered.set()
                    if not release.wait(2):
                        raise TimeoutError("test failed to release adapter")
                    return original(*args)
                self.adapter.submit = blocked_submit
                def mutate():
                    attempted.set()
                    try:
                        if action == "close":
                            return self.driver.destroy_bo(10, 30)
                        return self.driver.bind(10, self.vm.vm_id, uapi.drm_asahi_gem_bind_op(
                            uapi.DRM_ASAHI_BIND_UNBIND, 0, 0, modern.PAGE_SIZE, 0x10000))
                    finally:
                        finished.set()
                with ThreadPoolExecutor(max_workers=2) as workers:
                    submission = workers.submit(self.driver.submit, 10, queue.queue_id, compute_command())
                    self.assertTrue(entered.wait(1))
                    mutation = workers.submit(mutate)
                    try:
                        self.assertTrue(attempted.wait(1))
                        self.assertFalse(finished.wait(0.05))
                    finally:
                        release.set()
                    fence, _commands = submission.result(timeout=2)
                    if action == "close":
                        self.assertTrue(mutation.result(timeout=2))
                        self.assertIs(self.driver.deferred_bos[0]["bo"], binding.bo)
                        self.assertIn(fence, binding.bo.fences)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "pending"):
                            mutation.result(timeout=2)
                        self.assertIn(binding, self.vm.bindings)
                self.assertFalse(any(call[0] == "unbind" for call in self.adapter.calls))
                self.adapter.children[-1].done = True
                self.driver.reap_deferred()

    def pending_input(self):
        descriptor = uapi.drm_asahi_sync(uapi.DRM_ASAHI_SYNC_SYNCOBJ, 15, 0)
        obj = self.driver._sync_object(self.driver.file(10), descriptor)
        pending = sync.G17GSoftwareFence()
        obj.bind(pending)
        waiting = threading.Event()
        original = pending.wait
        def wait(**kwargs):
            waiting.set()
            return original(**kwargs)
        pending.wait = wait
        return descriptor, pending, waiting

    def test_waiting_input_does_not_lock_out_a_signaling_submit(self):
        self.bind_range(30, 0x10000)
        queue, other = self.create_queue(), self.create_queue()
        dependency, pending, waiting = self.pending_input()
        original = self.adapter.submit
        def signal_from_submit(file, owner, commands):
            if owner is other:
                pending.signal()
            return original(file, owner, commands)
        self.adapter.submit = signal_from_submit
        with ThreadPoolExecutor(max_workers=2) as workers:
            consumer = workers.submit(self.driver.submit, 10, queue.queue_id, compute_command(), (dependency,))
            try:
                self.assertTrue(waiting.wait(1))
                producer = workers.submit(self.driver.submit, 10, other.queue_id, compute_command())
                producer.result(timeout=1)
                consumer.result(timeout=1)
            finally:
                pending.signal()
        self.assertEqual([call[2] for call in self.adapter.calls if call[0] == "submit"],
                         [other.queue_id, queue.queue_id])

    def test_input_wait_keeps_original_fence_when_binary_sync_is_replaced(self):
        self.bind_range(30, 0x10000)
        queue = self.create_queue()
        dependency, pending, waiting = self.pending_input()
        with ThreadPoolExecutor(max_workers=1) as workers:
            consumer = workers.submit(self.driver.submit, 10, queue.queue_id, compute_command(), (dependency,))
            try:
                self.assertTrue(waiting.wait(1))
                self.driver.signal_external_sync(10, dependency)
                self.assertFalse(consumer.done())
                self.assertFalse(self.adapter.children)
            finally:
                pending.signal()
            consumer.result(timeout=1)

    def test_waiting_submission_revalidates_closed_bo_and_output_sync(self):
        for change in ("close", "timeline"):
            with self.subTest(change=change):
                self.setUp()
                self.bind_range(30, 0x10000)
                queue = self.create_queue()
                dependency, pending, waiting = self.pending_input()
                output = uapi.drm_asahi_sync(uapi.DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ, 16, 3)
                with ThreadPoolExecutor(max_workers=2) as workers:
                    consumer = workers.submit(self.driver.submit, 10, queue.queue_id,
                        compute_command(), (dependency,), (output,))
                    try:
                        self.assertTrue(waiting.wait(1))
                        if change == "close":
                            self.driver.destroy_bo(10, 30)
                        else:
                            prior = self.driver.signal_external_sync(10, output)
                    finally:
                        pending.signal()
                    with self.assertRaisesRegex(ValueError, "not completely mapped|already bound"):
                        consumer.result(timeout=1)
                self.assertFalse(self.adapter.children)
                if change == "timeline":
                    self.assertIs(self.driver.file(10).syncs[16].point(3), prior)

    def test_failed_physical_release_keeps_deferred_ownership(self):
        binding = self.bind_range(30, 0x10000)
        original = self.adapter.unbind
        def fail_unbind(*args):
            raise RuntimeError("GPU requires reset")
        self.adapter.unbind = fail_unbind
        with self.assertRaisesRegex(RuntimeError, "requires reset"):
            self.driver.destroy_bo(10, binding.bo.handle)
        self.assertNotIn(30, self.driver.file(10).bos)
        self.assertEqual(self.driver.deferred_bos[0]["bo"], binding.bo)
        self.assertEqual(self.driver.deferred_bos[0]["bindings"], (binding,))
        self.adapter.unbind = original
        self.driver.reap_deferred()
        self.assertFalse(self.driver.deferred_bos)

    def test_deferred_bo_does_not_pin_equal_vm_number_in_another_file(self):
        binding = self.bind_range(30, 0x10000)
        queue = self.create_queue()
        self.driver.submit(10, queue.queue_id, compute_command())
        self.driver.destroy_bo(10, binding.bo.handle)
        self.assertTrue(self.driver.deferred_bos)
        unrelated = self.driver.create_vm(20, self.vm.kernel_start, self.vm.kernel_end)
        self.assertEqual(unrelated.vm_id, self.vm.vm_id)
        self.driver.destroy_vm(20, unrelated.vm_id)
        self.assertTrue(self.driver.deferred_bos)

    def test_render_requires_owned_bindings_in_fixed_program_aperture(self):
        self.bind_range(40, 0x10000)
        self.bind_range(41, 0x20000)
        queue = self.create_queue()
        # Even a permissive adapter must not substitute for caller ownership.
        with self.assertRaisesRegex(ValueError, "not completely mapped"):
            self.driver.submit(10, queue.queue_id, render_command())
        for index in range(1, 5):
            self.bind_range(41 + index, modern.USC_EXEC_BASE + index * 0x10000,
                            flags=uapi.DRM_ASAHI_BIND_READ)
        fence, commands = self.driver.submit(
            10, queue.queue_id, render_command()
        )
        state = commands[0].hardware_state
        self.assertEqual(state.usc_exec_base, modern.USC_EXEC_BASE)
        self.assertEqual(state.width, 64)
        self.assertEqual(state.height, 48)
        self.assertEqual(state.blocks_per_utile, 2)
        self.assertEqual(state.bg_usc, 0x10000)
        self.assertFalse(fence.signaled())
        self.assertEqual(len(fence.bos), 6)

    def test_vm_window_matches_m5_geometry(self):
        self.assertEqual(modern.VM_END, (1 << 42) - 2 * modern.PAGE_SIZE)
        self.bind_range(1, modern.USC_EXEC_BASE)
        with self.assertRaisesRegex(ValueError, "outside"):
            self.bind_range(2, 1 << 42)

    def test_mixed_engine_children_keep_command_and_queue_attribution(self):
        self.bind_range(40, 0x10000)
        self.bind_range(41, 0x20000)
        for index in range(1, 5):
            self.bind_range(41 + index, modern.USC_EXEC_BASE + index * 0x10000,
                            flags=uapi.DRM_ASAHI_BIND_READ)
        queue = self.create_queue()
        children = tuple(ManualFence() for _ in range(5))
        for child, engine in zip(children, ("ta", "fragment", "compute", "ta", "fragment")):
            child.metadata["engine"] = engine
        self.adapter.submit = lambda *_: sync.G17GSubmissionFence(children)
        fence, commands = self.driver.submit(10, queue.queue_id,
            render_command() + compute_command() + render_command())
        self.assertEqual(len(fence.fences), 5)
        for child, command in zip(children, (commands[0], commands[0], commands[1], commands[2], commands[2])):
            self.assertEqual(child.metadata["command_index"], command.index)
            self.assertEqual(child.metadata["command_type"], command.header.cmd_type)
            self.assertEqual(child.metadata["queue_id"], queue.queue_id)
            self.assertEqual(child.metadata["vm_id"], self.vm.vm_id)
            self.assertEqual(child.metadata["fd"], 10)
        self.assertEqual([child.metadata["engine"] for child in children],
                         ["ta", "fragment", "compute", "ta", "fragment"])

    def test_indirect_bo_is_retained_until_submission_finishes(self):
        self.bind_range(1, 0x10000)
        indirect = self.bind_range(2, modern.USC_EXEC_BASE)
        queue = self.create_queue()
        fence, _ = self.driver.submit(10, queue.queue_id, compute_command())
        self.assertIn(indirect.bo, fence.bos)
        self.driver.destroy_bo(10, 2)
        self.assertNotIn(("destroy_bo", 10, 2), self.adapter.calls)
        self.adapter.children[0].done = True
        self.driver.reap_deferred()
        self.assertIn(("destroy_bo", 10, 2), self.adapter.calls)

    def test_closed_handles_do_not_allow_pending_vm_to_be_remapped(self):
        self.bind_range(1, 0x10000)
        queue = self.create_queue()
        self.driver.submit(10, queue.queue_id, compute_command())
        self.driver.destroy_bo(10, 1)
        self.driver.destroy_queue(10, queue.queue_id)
        with self.assertRaisesRegex(RuntimeError, "submissions are pending"):
            self.bind_range(2, 0x10000)
        self.adapter.children[0].done = True
        self.driver.reap_deferred()
        self.driver.bind(10, self.vm.vm_id,
                         uapi.drm_asahi_gem_bind_op(6, 2, 0, modern.PAGE_SIZE, 0x10000))


if __name__ == "__main__":
    unittest.main()
