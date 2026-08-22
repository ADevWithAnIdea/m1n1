# SPDX-License-Identifier: MIT

import ctypes
import errno
import importlib
import os
import pathlib
import struct
import sys
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
os.environ.setdefault("AGX_GPU", "G17")
UAPI = importlib.import_module("m1n1.agx.g17p_uapi")
MODERN = importlib.import_module("m1n1.agx.g17p_modern")
SYNC = importlib.import_module("m1n1.agx.g17p_sync")
HARDWARE = importlib.import_module("m1n1.agx.shim")
USC_EXEC_BASE = 0x1100000000


class ManualFence:
    def __init__(self):
        self.done = False
        self.error = None

    def signaled(self):
        return self.done


class Adapter:
    def __init__(self):
        self.calls = []
        self.child = None

    def __getattr__(self, name):
        if name == "submit":
            raise AttributeError

        def call(*args):
            self.calls.append((name, args))
            return "%s-token" % name
        return call

    def submit(self, file, queue, commands):
        self.calls.append(("submit", (file, queue, commands)))
        self.child = ManualFence()
        return SYNC.G17PSubmissionFence((self.child,))

    def preflight(self, file, queue, commands):
        self.calls.append(("preflight", (file, queue, commands)))


def compute_command(cdm=0x10000, cdm_barrier=UAPI.DRM_ASAHI_BARRIER_NONE,
                    timestamp_handle=0, timestamp_offset=0,
                    sampler_heap=0, sampler_count=0,
                    helper_binary=0, helper_cfg=0, helper_data=0,
                    attachments=(), flags=0):
    payload = UAPI.drm_asahi_cmd_compute()
    payload.flags = flags
    payload.cdm_ctrl_stream_base = cdm
    payload.cdm_ctrl_stream_end = cdm + 0x40
    payload.sampler_heap = sampler_heap
    payload.sampler_count = sampler_count
    payload.helper.binary = helper_binary
    payload.helper.cfg = helper_cfg
    payload.helper.data = helper_data
    payload.ts.start.handle = timestamp_handle
    payload.ts.start.offset = timestamp_offset
    header = UAPI.drm_asahi_cmd_header(
        UAPI.DRM_ASAHI_CMD_COMPUTE, len(payload.to_bytes()),
        UAPI.DRM_ASAHI_BARRIER_NONE, cdm_barrier)
    prefix = b""
    if attachments:
        body = b"".join(attachment.to_bytes() for attachment in attachments)
        attachment_header = UAPI.drm_asahi_cmd_header(
            UAPI.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS, len(body),
            UAPI.DRM_ASAHI_BARRIER_NONE, UAPI.DRM_ASAHI_BARRIER_NONE)
        prefix = attachment_header.to_bytes() + body
    return prefix + header.to_bytes() + payload.to_bytes()


def render_command(vdm=0x10000, scissor=0x20000, dbias=0,
                   oclqry=0, sampler_heap=0, sampler_count=0,
                   vertex_attachments=(), fragment_attachments=(),
                   flags=0, layers=1, utile_width=32, utile_height=32,
                   samples=1, sample_size=4, bg_usc=0x10000,
                   eot_usc=0x20000, partial_bg_usc=None,
                   partial_eot_usc=None, helper=False):
    payload = UAPI.drm_asahi_cmd_render()
    payload.flags = flags
    payload.vdm_ctrl_stream_base = vdm
    payload.isp_scissor_base = scissor
    payload.isp_dbias_base = dbias
    payload.isp_oclqry_base = oclqry
    payload.ppp_multisamplectl = 0x88
    payload.ppp_ctrl = 0x202
    payload.sampler_heap = sampler_heap
    payload.sampler_count = sampler_count
    payload.width_px = 64
    payload.height_px = 48
    payload.layers = layers
    payload.utile_width_px = utile_width
    payload.utile_height_px = utile_height
    payload.samples = samples
    payload.sample_size_B = sample_size
    payload.bg.usc = bg_usc
    payload.bg.rsrc_spec = 0x40
    payload.eot.usc = eot_usc
    payload.partial_bg.usc = (
        bg_usc if partial_bg_usc is None else partial_bg_usc)
    payload.partial_eot.usc = (
        eot_usc if partial_eot_usc is None else partial_eot_usc)
    if helper:
        payload.vertex_helper.binary = 0x4001
        payload.vertex_helper.cfg = 0x40
        payload.vertex_helper.data = 0x30000

    prefix = bytearray()
    for command_type, records in (
            (UAPI.DRM_ASAHI_SET_VERTEX_ATTACHMENTS, vertex_attachments),
            (UAPI.DRM_ASAHI_SET_FRAGMENT_ATTACHMENTS, fragment_attachments)):
        if not records:
            continue
        body = b"".join(record.to_bytes() for record in records)
        header = UAPI.drm_asahi_cmd_header(
            command_type, len(body), UAPI.DRM_ASAHI_BARRIER_NONE,
            UAPI.DRM_ASAHI_BARRIER_NONE)
        prefix.extend(header.to_bytes())
        prefix.extend(body)
    header = UAPI.drm_asahi_cmd_header(
        UAPI.DRM_ASAHI_CMD_RENDER, len(payload.to_bytes()),
        UAPI.DRM_ASAHI_BARRIER_NONE, UAPI.DRM_ASAHI_BARRIER_NONE)
    return bytes(prefix) + header.to_bytes() + payload.to_bytes()


class G17PModernDriverTests(unittest.TestCase):
    def setUp(self):
        self.adapter = Adapter()
        self.driver = MODERN.G17PModernDriver(self.adapter)
        self.vm = self.driver.create_vm(
            10, MODERN.VM_END - MODERN.VM_KERNEL_MIN_SIZE, MODERN.VM_END)

    def bind_range(self, handle, address, size=0x4000,
                   flags=UAPI.DRM_ASAHI_BIND_READ | UAPI.DRM_ASAHI_BIND_WRITE):
        bo = self.driver.create_bo(10, handle, handle * 0x4000, size)
        operation = UAPI.drm_asahi_gem_bind_op(
            flags, handle, 0, size, address)
        return self.driver.bind(10, self.vm.vm_id, operation)

    def compute_queue(self):
        return self.driver.create_queue(
            10, self.vm.vm_id, 0, USC_EXEC_BASE)

    def test_modern_entrypoint_is_selected_before_initialization(self):
        front = object.__new__(HARDWARE.DRMAsahiShim)
        front.initialized = False
        front.g17p_modern_entrypoint = False

        self.assertEqual(front.modern_enable(), 0)
        self.assertTrue(front.g17p_modern_entrypoint)
        front.initialized = True
        self.assertEqual(front.modern_enable(), -errno.EBUSY)

    def test_modern_params_advertise_upstream_39_bit_vm_window(self):
        front = object.__new__(HARDWARE.DRMAsahiShim)
        storage = ctypes.create_string_buffer(
            ctypes.sizeof(UAPI.drm_asahi_params_global))

        self.assertEqual(
            front.modern_get_params(ctypes.addressof(storage), len(storage)), 0)
        params = UAPI.drm_asahi_params_global.from_buffer_copy(storage)
        self.assertEqual(params.vm_start, 0x4000)
        self.assertEqual(params.vm_end, 0x7FFFFF8000)
        self.assertEqual(params.vm_kernel_min_size, 0x20000000)

    def test_modern_entrypoint_forces_direct_zero_capture_bootstrap(self):
        calls = []
        source = types.SimpleNamespace(
            main=lambda **kwargs: (
                calls.append(kwargs), {"artifact": "source-built"})[1])
        front = object.__new__(HARDWARE.DRMAsahiShim)
        front.g17p_modern_entrypoint = True
        front.log = lambda *_args: None

        with mock.patch.dict(
                sys.modules,
                {"agx_g17p_compute_source_initial": source}), \
                mock.patch.dict(
                    os.environ,
                    {"G17P_EXPERIMENT_RENDER_PAYLOAD_MANIFEST":
                     "/must/not/be/read"}):
            state = front.g17p_cold_boot()

        self.assertEqual(state["artifact"], "source-built")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0]["native_control_tail"])
        self.assertTrue(calls[0]["suppress_runtime_controls"])
        self.assertTrue(calls[0]["return_state"])
        self.assertIn(
            "--require-zero-capture-pages", front.G17P_COLD_BOOT_ARGS)
        self.assertEqual(
            front.G17P_COLD_BOOT_ARGS[
                front.G17P_COLD_BOOT_ARGS.index("--no-seed") + 1],
            "all")

    def test_vm_bo_bind_queue_lifecycle(self):
        bo = self.driver.create_bo(10, 7, 0x4000, 0x8000)
        op = UAPI.drm_asahi_gem_bind_op(
            UAPI.DRM_ASAHI_BIND_READ | UAPI.DRM_ASAHI_BIND_WRITE,
            bo.handle, 0, bo.size, 0x1000000000)
        binding = self.driver.bind(10, self.vm.vm_id, op)
        queue = self.driver.create_queue(
            10, self.vm.vm_id, 1, USC_EXEC_BASE)

        self.assertEqual(binding.addr, 0x1000000000)
        with self.assertRaisesRegex(RuntimeError, "queues"):
            self.driver.destroy_vm(10, self.vm.vm_id)
        self.driver.destroy_queue(10, queue.queue_id)
        self.assertTrue(queue.lifetime.released)

        unbind = UAPI.drm_asahi_gem_bind_op(
            UAPI.DRM_ASAHI_BIND_UNBIND, 0, 0, bo.size, binding.addr)
        self.driver.bind(10, self.vm.vm_id, unbind)
        self.assertTrue(self.driver.destroy_bo(10, bo.handle))
        self.driver.destroy_vm(10, self.vm.vm_id)

    def test_queue_destroy_defers_published_submission(self):
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()
        fence, _commands = self.driver.submit(
            10, queue.queue_id, compute_command())
        self.driver.destroy_queue(10, queue.queue_id)

        self.assertFalse(queue.lifetime.released)
        self.assertFalse(fence.signaled())
        self.assertEqual(fence.snapshot()["state"], "pending")
        self.assertEqual(fence.metadata["vm_id"], self.vm.vm_id)
        self.assertEqual(fence.metadata["queue_id"], queue.queue_id)
        self.assertEqual(fence.metadata["command_indices"], (1,))
        with self.assertRaises(KeyError):
            self.driver.submit(10, queue.queue_id, compute_command())
        self.adapter.child.done = True
        self.assertTrue(queue.lifetime.reap())
        self.assertTrue(queue.lifetime.released)
        self.assertEqual(fence.snapshot()["state"], "completed")

    def test_gem_close_and_vm_destroy_defer_physical_release(self):
        binding = self.bind_range(30, 0x10000)
        queue = self.compute_queue()
        fence, _commands = self.driver.submit(
            10, queue.queue_id, compute_command())

        self.driver.destroy_queue(10, queue.queue_id)
        self.assertTrue(self.driver.destroy_bo(10, binding.bo.handle))
        self.assertNotIn(binding.bo.handle, self.driver.file(10).bos)
        self.assertFalse(self.vm.bindings)
        names = [name for name, _args in self.adapter.calls]
        self.assertNotIn("unbind", names)
        self.assertNotIn("destroy_bo", names)
        with self.assertRaisesRegex(RuntimeError, "deferred"):
            self.driver.destroy_vm(10, self.vm.vm_id)

        self.adapter.child.done = True
        self.driver.reap_deferred()
        names = [name for name, _args in self.adapter.calls]
        self.assertIn("unbind", names)
        self.assertIn("destroy_bo", names)
        self.assertTrue(queue.lifetime.released)
        self.assertTrue(fence.signaled())
        self.driver.destroy_vm(10, self.vm.vm_id)

    def test_rejected_submit_does_not_replace_output_sync(self):
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()
        out = UAPI.drm_asahi_sync(UAPI.DRM_ASAHI_SYNC_SYNCOBJ, 5, 0)
        old = self.driver.signal_external_sync(10, out)

        with self.assertRaises(ValueError):
            self.driver.submit(10, queue.queue_id, b"bad", out_syncs=(out,))
        self.assertIs(self.driver.file(10).syncs[5].point(), old)
        rejected = self.driver.rejections[-1].snapshot()
        self.assertEqual(rejected["state"], "rejected")
        self.assertEqual(rejected["stage"], "command-buffer")
        self.assertEqual(rejected["metadata"]["vm_id"], self.vm.vm_id)
        self.assertEqual(rejected["metadata"]["queue_id"], queue.queue_id)
        self.assertIsNone(rejected["metadata"]["command_index"])
        self.assertIsNone(rejected["fence"])

    def test_rejected_command_records_exact_command_owner(self):
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()

        with self.assertRaisesRegex(ValueError, "sampler heap and count"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(sampler_heap=0x20000, sampler_count=0))

        rejected = self.driver.rejections[-1].snapshot()
        self.assertEqual(rejected["stage"], "command-validation")
        self.assertEqual(rejected["metadata"], {
            "fd": 10,
            "vm_id": self.vm.vm_id,
            "context_id": self.vm.token,
            "queue_id": queue.queue_id,
            "command_index": 1,
            "command_type": UAPI.DRM_ASAHI_CMD_COMPUTE,
        })

    def test_binary_and_timeline_output_points(self):
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()
        binary = UAPI.drm_asahi_sync(UAPI.DRM_ASAHI_SYNC_SYNCOBJ, 5, 0)
        timeline = UAPI.drm_asahi_sync(
            UAPI.DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ, 6, 9)
        fence, _ = self.driver.submit(
            10, queue.queue_id, compute_command(),
            out_syncs=(binary, timeline))

        self.assertIs(self.driver.file(10).syncs[5].point().fence, fence)
        self.assertIs(self.driver.file(10).syncs[6].point(9).fence, fence)
        self.adapter.child.done = True
        self.assertEqual(self.driver.file(10).syncs[6].query(), 9)

    def test_fatal_terminal_fence_keeps_vm_queue_command_attribution(self):
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()
        output = UAPI.drm_asahi_sync(
            UAPI.DRM_ASAHI_SYNC_TIMELINE_SYNCOBJ, 6, 9)
        fence, _ = self.driver.submit(
            10, queue.queue_id, compute_command(), out_syncs=(output,))

        self.assertTrue(fence.fail(
            SYNC.G17PWorkError.DEVICE_LOST, reason="device-lost"))
        snapshot = fence.snapshot()
        self.assertEqual(snapshot["state"], "failed")
        self.assertEqual(snapshot["error"], -19)
        self.assertEqual(snapshot["terminal_reason"], "device-lost")
        self.assertEqual(snapshot["metadata"]["vm_id"], self.vm.vm_id)
        self.assertEqual(snapshot["metadata"]["queue_id"], queue.queue_id)
        self.assertEqual(snapshot["metadata"]["command_indices"], (1,))
        point = self.driver.file(10).syncs[6].wait(9, timeout=0)
        self.assertEqual(point.error, -19)

    def test_binding_validation_precedes_adapter(self):
        bo = self.driver.create_bo(10, 8, 0x4000, 0x4000)
        calls = len(self.adapter.calls)
        overlap_kernel = UAPI.drm_asahi_gem_bind_op(
            UAPI.DRM_ASAHI_BIND_READ, bo.handle, 0, 0x4000,
            self.vm.kernel_start)
        with self.assertRaisesRegex(ValueError, "kernel"):
            self.driver.bind(10, self.vm.vm_id, overlap_kernel)
        self.assertEqual(len(self.adapter.calls), calls)

    def test_vm_and_gem_create_match_upstream_validation(self):
        with self.assertRaisesRegex(ValueError, "advertised"):
            self.driver.create_vm(10, 0x4000, 0x8000)
        with self.assertRaisesRegex(ValueError, "non-private"):
            self.driver.create_bo(10, 12, 0x4000, 1, vm_id=self.vm.vm_id)
        with self.assertRaisesRegex(ValueError, "flags"):
            self.driver.create_bo(10, 12, 0x4000, 1, flags=0x80)
        bo = self.driver.create_bo(10, 12, 0x4000, 1)
        self.assertEqual(bo.size, 1)

    def test_partial_unbind_splits_mapping(self):
        bo = self.driver.create_bo(10, 9, 0x4000, 0x10000)
        op = UAPI.drm_asahi_gem_bind_op(
            UAPI.DRM_ASAHI_BIND_READ | UAPI.DRM_ASAHI_BIND_WRITE,
            bo.handle, 0, bo.size, 0x1000000000)
        self.driver.bind(10, self.vm.vm_id, op)
        unbind = UAPI.drm_asahi_gem_bind_op(
            UAPI.DRM_ASAHI_BIND_UNBIND, 0, 0, 0x4000, 0x1000004000)
        self.driver.bind(10, self.vm.vm_id, unbind)

        bindings = self.vm.bindings
        self.assertEqual([(item.addr, item.size, item.bo_offset)
                          for item in bindings], [
            (0x1000000000, 0x4000, 0),
            (0x1000008000, 0x8000, 0x8000),
        ])

    def test_special_timestamp_object_and_gem_close_cleanup(self):
        bo = self.driver.create_bo(10, 11, 0x4000, 0x8000)
        op = UAPI.drm_asahi_gem_bind_object(
            UAPI.DRM_ASAHI_BIND_OBJECT_OP_BIND,
            UAPI.DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
            bo.handle, 0, 0x4000, 0x4000, 0, 0)
        obj = self.driver.bind_object(10, op)
        self.assertEqual(op.object_handle, obj.object_handle)
        self.assertIn(obj.object_handle, self.driver.file(10).objects)

        self.assertTrue(self.driver.destroy_bo(10, bo.handle))
        self.assertFalse(self.driver.file(10).objects)
        names = [name for name, _args in self.adapter.calls]
        self.assertIn("unbind_object", names)

    def test_submit_resolves_timestamp_handle_and_offset_before_adapter(self):
        bo = self.driver.create_bo(10, 11, 0x4000, 0x8000)
        op = UAPI.drm_asahi_gem_bind_object(
            UAPI.DRM_ASAHI_BIND_OBJECT_OP_BIND,
            UAPI.DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
            bo.handle, 0, 0x4000, 0x4000, 0, 0)
        obj = self.driver.bind_object(10, op)
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()

        fence, commands = self.driver.submit(
            10, queue.queue_id,
            compute_command(timestamp_handle=obj.object_handle,
                            timestamp_offset=0x38))

        self.assertEqual(commands[0].timestamp_objects,
                         (("compute_start", obj, 0x38),))
        self.assertEqual(fence.resources, (obj,))

    def test_compute_hardware_state_resolves_all_address_classes(self):
        self.bind_range(30, 0x10000)
        self.bind_range(31, 0x20000)
        self.bind_range(32, 0x30000)
        queue = self.compute_queue()
        attachment = UAPI.drm_asahi_attachment(0x30000, 0x100, 0, 0)

        fence, commands = self.driver.submit(
            10, queue.queue_id,
            compute_command(
                sampler_heap=0x20000, sampler_count=4,
                attachments=(attachment,)))

        state = commands[0].hardware_state
        self.assertEqual(state.cdm_terminator, 0x1003c)
        self.assertEqual(state.sampler_count, 4)
        self.assertEqual(state.helper_address, 0)
        self.assertEqual(
            (state.helper_binary, state.helper_cfg, state.helper_data),
            (0, 0, 0))
        self.assertEqual(state.attachments, ((0x30000, 0x100),))
        self.assertEqual(
            {binding.addr for binding in state.bindings},
            {0x10000, 0x20000, 0x30000},
        )
        self.assertEqual(fence.bindings, state.bindings)
        self.assertEqual({bo.handle for bo in fence.bos}, {30, 31, 32})

    def test_compute_validation_precedes_adapter_publication(self):
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()
        before = len(self.adapter.calls)

        malformed = UAPI.drm_asahi_attachment(0x30000, 0x100, 0, 1)
        with self.assertRaisesRegex(ValueError, "padding and flags"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(attachments=(malformed,)))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "sampler heap and count"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(sampler_heap=0x20000, sampler_count=0))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "unsupported on G17P"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(helper_data=0x30000))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "unsupported on G17P"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(
                    helper_binary=0x4001, helper_cfg=0x10000,
                    helper_data=0x30000))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "flags"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(flags=1))
        self.assertEqual(len(self.adapter.calls), before)

    def test_render_hardware_state_resolves_fields_and_lifetimes(self):
        for handle, address in enumerate((
                0x10000, 0x20000, 0x30000, 0x40000,
                0x50000, 0x60000, 0x70000, 0x80000,
                0x90000, 0xa0000, 0xb0000,
                USC_EXEC_BASE + 0x10000,
                USC_EXEC_BASE + 0x20000,
                USC_EXEC_BASE + 0x30000,
                USC_EXEC_BASE + 0x40000), start=100):
            self.bind_range(handle, address)
        queue = self.compute_queue()
        vertex = UAPI.drm_asahi_attachment(0xa0000, 0x100, 0, 0)
        fragment = UAPI.drm_asahi_attachment(0xb0000, 0x200, 0, 0)
        command = render_command(
            dbias=0x30000, oclqry=0x40000,
            sampler_heap=0x90000, sampler_count=4,
            vertex_attachments=(vertex,), fragment_attachments=(fragment,),
            flags=(UAPI.DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES |
                   UAPI.DRM_ASAHI_RENDER_DBIAS_IS_INT),
            layers=1, utile_width=32, utile_height=16,
            samples=4, sample_size=8,
            partial_bg_usc=0x30000, partial_eot_usc=0x40000)

        fence, commands = self.driver.submit(10, queue.queue_id, command)
        state = commands[0].hardware_state

        self.assertIsInstance(state, MODERN.G17PRenderHardwareState)
        self.assertEqual(state.utile_config, 0x6002)
        self.assertEqual(state.blocks_per_utile, 8)
        self.assertEqual(state.tile_config, 0x10280)
        self.assertEqual(state.sampler_count, 4)
        self.assertEqual(state.vertex_attachments, ((0xa0000, 0x100),))
        self.assertEqual(state.fragment_attachments, ((0xb0000, 0x200),))
        self.assertEqual(fence.bindings, state.bindings)
        self.assertEqual(
            {binding.addr for binding in state.bindings},
            {
                0x10000, 0x20000, 0x30000, 0x40000, 0x90000,
                0xa0000, 0xb0000,
                USC_EXEC_BASE + 0x10000,
                USC_EXEC_BASE + 0x20000,
                USC_EXEC_BASE + 0x30000,
                USC_EXEC_BASE + 0x40000,
            },
        )
        self.assertEqual(
            {bo.handle for bo in fence.bos},
            {100, 101, 102, 103, 108, 109, 110, 111, 112, 113, 114},
        )

    def test_render_validation_precedes_adapter_publication(self):
        self.bind_range(100, 0x10000)
        self.bind_range(101, 0x20000)
        self.bind_range(102, USC_EXEC_BASE + 0x10000)
        self.bind_range(103, USC_EXEC_BASE + 0x20000)
        queue = self.compute_queue()
        before = len(self.adapter.calls)

        with self.assertRaisesRegex(ValueError, "dimensions"):
            self.driver.submit(
                10, queue.queue_id,
                render_command(utile_width=8))
        self.assertEqual(len(self.adapter.calls), before)

        fence, commands = self.driver.submit(
            10, queue.queue_id,
            render_command(
                utile_width=32, utile_height=32,
                samples=4, sample_size=8))
        self.assertEqual(commands[0].hardware_state.blocks_per_utile, 16)
        before = len(self.adapter.calls)

        with self.assertRaisesRegex(ValueError, "tilebuffer limit"):
            self.driver.submit(
                10, queue.queue_id,
                render_command(
                    utile_width=32, utile_height=32,
                    samples=4, sample_size=9))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "unsupported on G17P"):
            self.driver.submit(
                10, queue.queue_id,
                render_command(helper=True))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "not completely mapped"):
            self.driver.submit(
                10, queue.queue_id,
                render_command(sampler_heap=0x90000, sampler_count=1))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "unknown render flags"):
            self.driver.submit(
                10, queue.queue_id,
                render_command(flags=1 << 31))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "partial background"):
            self.driver.submit(
                10, queue.queue_id,
                render_command(partial_bg_usc=0))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "partial end-of-tile"):
            self.driver.submit(
                10, queue.queue_id,
                render_command(partial_eot_usc=0))
        self.assertEqual(len(self.adapter.calls), before)

    def test_render_zls_layer_strides_use_packed_units(self):
        self.bind_range(100, 0x10000)
        self.bind_range(101, 0x20000)
        self.bind_range(102, USC_EXEC_BASE + 0x10000)
        self.bind_range(103, USC_EXEC_BASE + 0x20000)
        self.bind_range(104, 0x50000, size=3 * MODERN.PAGE_SIZE)
        self.bind_range(105, 0x80000, size=MODERN.PAGE_SIZE)
        queue = self.compute_queue()

        payload = UAPI.drm_asahi_cmd_render()
        payload.flags = 0
        payload.vdm_ctrl_stream_base = 0x10000
        payload.isp_scissor_base = 0x20000
        payload.ppp_multisamplectl = 0x88
        payload.ppp_ctrl = 0x202
        payload.width_px = 64
        payload.height_px = 48
        payload.layers = 3
        payload.utile_width_px = 32
        payload.utile_height_px = 32
        payload.samples = 1
        payload.sample_size_B = 4
        payload.bg.usc = 0x10000
        payload.eot.usc = 0x20000
        payload.partial_bg.usc = 0x10000
        payload.partial_eot.usc = 0x20000
        payload.depth.base = 0x50000
        payload.depth.stride = 1
        payload.depth.comp_base = 0x80000
        payload.depth.comp_stride = 0
        header = UAPI.drm_asahi_cmd_header(
            UAPI.DRM_ASAHI_CMD_RENDER, len(payload.to_bytes()),
            UAPI.DRM_ASAHI_BARRIER_NONE, UAPI.DRM_ASAHI_BARRIER_NONE)

        fence, commands = self.driver.submit(
            10, queue.queue_id, header.to_bytes() + payload.to_bytes())
        self.assertFalse(fence.signaled())
        self.assertEqual(commands[0].hardware_state.depth_stride, 1)
        self.assertEqual(commands[0].hardware_state.depth_comp_stride, 0)

        payload.depth.stride = 2
        with self.assertRaisesRegex(ValueError, "packed flags"):
            self.driver.submit(
                10, queue.queue_id, header.to_bytes() + payload.to_bytes())

    def test_queue_and_binding_ranges_follow_g17p_params(self):
        with self.assertRaisesRegex(ValueError, "4 GiB"):
            self.driver.create_queue(
                10, self.vm.vm_id, 0, USC_EXEC_BASE + 0x4000)
        with self.assertRaisesRegex(ValueError, "outside the advertised"):
            bo = self.driver.create_bo(10, 40, 0x10000, 0x4000)
            self.driver.bind(10, self.vm.vm_id, UAPI.drm_asahi_gem_bind_op(
                UAPI.DRM_ASAHI_BIND_READ, bo.handle, 0, 0x4000,
                MODERN.VM_END))

    def test_render_context_low_va_translation(self):
        translate = HARDWARE._G17PModernHardwareAdapter._render_dva
        self.assertEqual(translate(0x18000), 0x1000018000)
        self.assertEqual(translate(0x58000), 0x1000058000)
        self.assertEqual(translate(0x1000000000), 0x1000000000)
        self.assertEqual(translate(USC_EXEC_BASE + 0x130000),
                         USC_EXEC_BASE + 0x130000)

    def test_render_transport_oracle_preserves_caller_attachment(self):
        messages = []
        front = types.SimpleNamespace(
            g17p_render_transport_oracle=True,
            log=messages.append,
        )
        adapter = HARDWARE._G17PModernHardwareAdapter(front)
        attachment = types.SimpleNamespace(
            pointer=0x2ffffd8000, size=0x4000)
        drm = types.SimpleNamespace(
            fb_width=64, fb_height=64, layers=1,
            attachment_count=1, attachments=(attachment,),
            encoder_ptr=0x12340000,
            load_pipeline=0x111, store_pipeline=0x222,
            partial_reload_pipeline=0x333,
            partial_store_pipeline=0x444,
        )

        self.assertTrue(adapter._apply_render_transport_oracle(drm))
        self.assertIs(drm.attachments[0], attachment)
        self.assertEqual(drm.attachments[0].pointer, 0x2ffffd8000)
        self.assertEqual(drm.encoder_ptr, 0x1000018000)
        self.assertEqual(drm.load_pipeline, 0x01990240)
        self.assertEqual(drm.store_pipeline, 0x01990640)
        self.assertEqual(drm.partial_reload_pipeline, 0x01990240)
        self.assertEqual(drm.partial_store_pipeline, 0x01990640)
        self.assertEqual(drm.sample_size, 1)
        self.assertEqual(drm.tile_config, 0x10280)
        self.assertEqual(drm.usc_exec_base, 0x10000000000)
        self.assertIn("validated caller render", messages[0])

        drm.fb_width = 32
        with self.assertRaisesRegex(
                HARDWARE.G17PUnsupported, "one 64x64 layer"):
            adapter._apply_render_transport_oracle(drm)

    def test_invalid_timestamp_is_rejected_before_adapter_publication(self):
        bo = self.driver.create_bo(10, 11, 0x4000, 0x8000)
        op = UAPI.drm_asahi_gem_bind_object(
            UAPI.DRM_ASAHI_BIND_OBJECT_OP_BIND,
            UAPI.DRM_ASAHI_BIND_OBJECT_USAGE_TIMESTAMPS,
            bo.handle, 0, 0x4000, 0x4000, 0, 0)
        obj = self.driver.bind_object(10, op)
        self.bind_range(30, 0x10000)
        queue = self.compute_queue()
        before = len(self.adapter.calls)

        with self.assertRaisesRegex(KeyError, "timestamp object"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(timestamp_handle=0xdead,
                                timestamp_offset=0))
        self.assertEqual(len(self.adapter.calls), before)

        with self.assertRaisesRegex(ValueError, "exceeds"):
            self.driver.submit(
                10, queue.queue_id,
                compute_command(timestamp_handle=obj.object_handle,
                                timestamp_offset=obj.size - 4))
        self.assertEqual(len(self.adapter.calls), before)


if __name__ == "__main__":
    unittest.main()
