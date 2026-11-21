# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the compiled C dispatcher, caller pointers, and shared sync fences.

The adapter is deliberately asynchronous and never writes shader output. These
tests prove ioctl/lifetime semantics; they make no GPU execution claim.
"""
import ctypes
import errno
from concurrent.futures import ThreadPoolExecutor
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "proxyclient"))

from m1n1.drm_shim import g17g_uapi as api
from m1n1.drm_shim import g17g_drm_uapi as drm
from m1n1.drm_shim.g17g_ioctl import G17GIoctlShim
from m1n1.drm_shim.g17g_modern import G17GModernDriver, VM_END, VM_KERNEL_MIN_SIZE
from m1n1.drm_shim.g17g_sync import G17GSoftwareFence, G17GSubmissionFence


class Adapter:
    def __init__(self):
        self.fences = []
        self.released = []
        self.completion_error = None

    def submit(self, file, queue, commands):
        fence = G17GSoftwareFence()
        self.fences.append(fence)
        if self.completion_error is not None:
            fence.signal(error=self.completion_error)
        return G17GSubmissionFence((fence,))

    def destroy_bo(self, file, bo):
        self.released.append((file.fd, bo.handle))


class G17GNativeIoctlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT / "drm-shim/build_bridge.py")],
                       check=True, capture_output=True)
        suffix = "dylib" if sys.platform == "darwin" else "so"
        cls.lib = ctypes.PyDLL(str(ROOT / f"build/libg17g_drm_shim.{suffix}"))
        cls.lib.g17g_drm_usercopy_module.restype = ctypes.py_object
        cls.memory = cls.lib.g17g_drm_usercopy_module()
        cls.lib.g17g_drm_attach.argtypes = [ctypes.py_object]
        cls.lib.g17g_drm_open_file.restype = ctypes.c_int64
        cls.lib.g17g_drm_close_file.argtypes = [ctypes.c_uint64]
        cls.lib.g17g_drm_ioctl.argtypes = [ctypes.c_uint64, ctypes.c_ulong, ctypes.c_void_p]
        cls.lib.g17g_drm_mmap_offset.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t]
        cls.lib.g17g_drm_mmap_offset.restype = ctypes.c_int64
        cls.lib.g17g_drm_mmap_bo_flags.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t]
        cls.lib.g17g_drm_mmap_bo_flags.restype = ctypes.c_int
        cls.lib.g17g_drm_mmap_fd.argtypes = [ctypes.c_uint64, ctypes.c_uint64,
                                             ctypes.c_size_t, ctypes.POINTER(ctypes.c_int)]
        cls.lib.g17g_drm_mmap_fd.restype = ctypes.c_int
        with tempfile.TemporaryFile() as backing:
            cls.shim = G17GIoctlShim(backing.fileno(), cls.memory)
        if cls.lib.g17g_drm_attach(cls.shim):
            raise AssertionError("C bridge already has a backend")

    def setUp(self):
        import os
        os.close(self.shim.backing_fd)
        self.adapter = Adapter()
        self.driver = G17GModernDriver(self.adapter, strict_syncs=True)
        self.backing = tempfile.TemporaryFile()
        self.shim.__init__(self.backing.fileno(), self.memory, driver=self.driver)
        self.file = self.lib.g17g_drm_open_file()
        self.assertGreater(self.file, 0)

    def tearDown(self):
        for fence in self.adapter.fences:
            fence.signal()
        for identity in tuple(self.shim.files):
            self.assertEqual(self.lib.g17g_drm_close_file(identity), 0)
        self.backing.close()

    def call(self, number, arg, *, file=None):
        request = 0xc0006400 | ctypes.sizeof(arg) << 16 | number
        return self.lib.g17g_drm_ioctl(self.file if file is None else file,
                                        request, ctypes.byref(arg))

    def success(self, number, arg, **kwargs):
        self.assertEqual(self.call(number, arg, **kwargs), 0,
                         self.shim.errors[-1] if self.shim.errors else None)
        return arg

    def test_vm_bind_rejects_short_stride(self):
        vm = self.success(0x42, api.drm_asahi_vm_create(
            VM_END - VM_KERNEL_MIN_SIZE, VM_END))
        bo = self.success(0x45, api.drm_asahi_gem_create(0x4000))
        op = api.drm_asahi_gem_bind_op(6, bo.handle, 0, 0x4000, 0x10000)
        arg = api.drm_asahi_vm_bind(vm.vm_id, 1, 31, 0, ctypes.addressof(op))
        self.assertEqual(self.call(0x44, arg), -errno.EINVAL)
        arg.stride = 32
        self.success(0x44, arg)

    def test_vm_bind_retains_successful_prefix_for_retry(self):
        vm = self.success(0x42, api.drm_asahi_vm_create(
            VM_END - VM_KERNEL_MIN_SIZE, VM_END))
        bo = self.success(0x45, api.drm_asahi_gem_create(0x4000))
        owner = self.driver.file(self.file).vms[vm.vm_id]

        def bind_array(addresses):
            data = b"".join(api.drm_asahi_gem_bind_op(
                api.DRM_ASAHI_BIND_READ, bo.handle, 0, 0x4000, address).to_bytes()
                for address in addresses)
            raw = ctypes.create_string_buffer(data)
            return self.call(0x44, api.drm_asahi_vm_bind(
                vm.vm_id, len(addresses), 32, 0, ctypes.addressof(raw)))

        self.assertEqual(bind_array((0x10000, 0x14001, 0x18000)), -errno.EINVAL)
        self.assertEqual([op.addr for op in owner.bindings], [0x10000])
        existing = owner.bindings[0]
        self.assertEqual(bind_array((0x10000, 0x14000, 0x18000)), 0)
        self.assertEqual([op.addr for op in owner.bindings], [0x10000, 0x14000, 0x18000])
        self.assertIs(owner.bindings[0], existing)

    def test_closed_file_ranges_merge_across_live_gaps(self):
        gap = self.lib.g17g_drm_open_file()
        last = gap
        for _ in range(32):
            last = self.lib.g17g_drm_open_file()
            self.assertEqual(self.lib.g17g_drm_close_file(last), 0)
        self.assertEqual(self.driver.closed_files, [(gap + 1, last)])
        self.assertEqual(self.lib.g17g_drm_close_file(self.file), 0)
        self.assertEqual(self.lib.g17g_drm_close_file(gap), 0)
        self.assertEqual(self.driver.closed_files, [(self.file, last)])
        with self.assertRaises(OSError) as closed:
            self.driver.file(gap)
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def sync(self, signaled=False):
        return self.success(0xbf, drm.drm_syncobj_create(0, int(signaled))).handle

    def array_op(self, number, handles):
        array = (ctypes.c_uint32 * len(handles))(*handles)
        return self.call(number, drm.drm_syncobj_array(ctypes.addressof(array), len(array), 0))

    def wait(self, handle, *, value=None, flags=0, deadline=0):
        handles = (ctypes.c_uint32 * 1)(handle)
        if value is None:
            arg = drm.drm_syncobj_wait(ctypes.addressof(handles), deadline, 1, flags)
            return self.call(0xc3, arg)
        points = (ctypes.c_uint64 * 1)(value)
        arg = drm.drm_syncobj_timeline_wait(ctypes.addressof(handles),
            ctypes.addressof(points), deadline, 1, flags)
        return self.call(0xca, arg)

    def signal(self, handle, point):
        handles = (ctypes.c_uint32 * 1)(handle)
        points = (ctypes.c_uint64 * 1)(point)
        return self.call(0xcd, drm.drm_syncobj_timeline_array(
            ctypes.addressof(handles), ctypes.addressof(points), 1, 0))

    def query(self, handle, flags=0):
        handles = (ctypes.c_uint32 * 1)(handle)
        points = (ctypes.c_uint64 * 1)(0xdead)
        self.success(0xcb, drm.drm_syncobj_timeline_array(
            ctypes.addressof(handles), ctypes.addressof(points), 1, flags))
        return points[0]

    def test_version_discovery_lengths_truncation_and_guards_without_gpu(self):
        self.shim.driver = None
        def hardware_forbidden(_fd):
            raise AssertionError("discovery must not initialize hardware")
        self.shim.driver_factory = hardware_forbidden
        self.assertEqual(ctypes.sizeof(drm.drm_version), 64)
        arg = self.success(0x00, drm.drm_version())
        self.assertEqual((arg.version_major, arg.version_minor, arg.version_patchlevel), (1, 0, 0))
        expected = {"name": b"asahi", "date": b"0", "desc": b"G17G m1n1 DRM shim"}
        for field, value in expected.items():
            self.assertEqual(getattr(arg, field + "_len"), len(value))
        for capacity in (0, 3, 128):
            buffers = {field: ctypes.create_string_buffer(b"Z" * 130) for field in expected}
            arg = drm.drm_version()
            for field, buffer in buffers.items():
                setattr(arg, field, ctypes.addressof(buffer) + 1)
                setattr(arg, field + "_len", capacity)
            self.success(0x00, arg)
            for field, value in expected.items():
                copied = value[:capacity]
                self.assertEqual(buffers[field].raw, b"Z" + copied + b"Z" * (129 - len(copied)) + b"\0")
                self.assertEqual(getattr(arg, field + "_len"), len(value))
        self.assertIsNone(self.shim.driver)

    def test_version_discovery_faults_and_null_length_queries(self):
        arg = drm.drm_version(name_len=5, name=1)
        self.assertEqual(self.call(0x00, arg), -errno.EFAULT)
        # Kernel discovery accepts NULL even with a nonzero advertised length.
        arg = self.success(0x00, drm.drm_version(name_len=100))
        self.assertEqual(arg.name_len, 5)
        # A zero-size destination is never dereferenced.
        self.success(0x00, drm.drm_version(name=1))

    def setup_compute(self):
        vm = self.success(0x42, api.drm_asahi_vm_create(
            VM_END - VM_KERNEL_MIN_SIZE, VM_END))
        bo = self.success(0x45, api.drm_asahi_gem_create(0x4000))
        op = api.drm_asahi_gem_bind_op(6, bo.handle, 0, 0x4000, 0x10000)
        self.success(0x44, api.drm_asahi_vm_bind(vm.vm_id, 1, 32, 0, ctypes.addressof(op)))
        queue = self.success(0x48, api.drm_asahi_queue_create(0, vm.vm_id, 1))
        self.assertEqual(self.driver.file(self.file).queues[queue.queue_id].usc_exec_base, 1 << 40)
        return vm, bo, queue

    def submit(self, queue, *, inputs=(), outputs=()):
        command = api.drm_asahi_cmd_compute()
        command.cdm_ctrl_stream_base = 0x10000
        command.cdm_ctrl_stream_end = 0x10040
        body = api.drm_asahi_cmd_header(1, ctypes.sizeof(command), 0xffff, 0xffff).to_bytes() + command.to_bytes()
        cmdbuf = ctypes.create_string_buffer(body)
        syncs = (api.drm_asahi_sync * (len(inputs) + len(outputs)))(*inputs, *outputs)
        arg = api.drm_asahi_submit(ctypes.addressof(syncs), ctypes.addressof(cmdbuf),
            0, queue.queue_id, len(inputs), len(outputs), len(body), 0)
        return self.call(0x4a, arg)

    def test_bad_outer_and_nested_pointers_return_efault(self):
        self.assertEqual(self.lib.g17g_drm_ioctl(self.file, 0xc00864bf, 1), -errno.EFAULT)
        arg = drm.drm_syncobj_array(1, 1)
        self.assertEqual(self.call(0xc4, arg), -errno.EFAULT)
        self.assertEqual(self.call(0xcb, drm.drm_syncobj_timeline_array(0, 1, 1)), -errno.EFAULT)
        self.assertFalse(self.adapter.fences)

    def test_native_process_initializes_build_virtualenv_without_hardware(self):
        import os
        suffix = "dylib" if sys.platform == "darwin" else "so"
        output = ROOT / "build/g17g_native_init_test"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(ROOT / "drm-shim/native_init_test.c"),
            str(ROOT / f"build/libg17g_drm_shim.{suffix}"), "-o", str(output)],
            check=True, capture_output=True)
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "proxyclient"),
                           M1N1DEVICE="/no-hardware-may-be-opened")
        subprocess.run([str(output)], env=environment, check=True,
                       capture_output=True, timeout=10)

    def test_get_params_extensible_copy_preserves_tail_and_rejects_bad_destination(self):
        self.shim.params = bytes(range(64))
        dest = ctypes.create_string_buffer(b"x" * 96)
        self.success(0x40, api.drm_asahi_get_params(0, 0, ctypes.addressof(dest), 12))
        self.assertEqual(dest.raw[:12], bytes(range(12)))
        self.assertEqual(dest.raw[12:96], b"x" * 84)
        self.assertEqual(self.call(0x40, api.drm_asahi_get_params(0, 0, 1, 12)), -errno.EFAULT)

    def test_unknown_ioctl_padding_flags_and_short_size(self):
        self.assertEqual(self.call(0xc1, drm.drm_syncobj_create()), -errno.ENOTTY)
        self.assertEqual(self.call(0xbf, drm.drm_syncobj_create(0, 2)), -errno.EINVAL)
        self.assertEqual(self.call(0xc0, drm.drm_syncobj_destroy(1, 1)), -errno.EINVAL)
        arg = ctypes.c_uint32()
        self.assertEqual(self.call(0xbf, arg), -errno.EINVAL)

    def test_never_submitted_wait_is_not_complete(self):
        handle = self.sync()
        self.assertEqual(self.wait(handle), -errno.EINVAL)
        self.assertEqual(self.wait(handle, flags=2), -errno.ETIME)
        self.assertEqual(self.wait(handle, value=4, flags=4), -errno.ETIME)
        self.assertEqual(self.query(handle), 0)

    def test_wait_for_submit_releases_lock_and_snapshots_object(self):
        handle = self.sync()
        with ThreadPoolExecutor() as threads:
            waiting = threads.submit(self.wait, handle, flags=2,
                                     deadline=time.monotonic_ns() + 1_000_000_000)
            self.assertFalse(waiting.done())
            self.assertEqual(self.array_op(0xc5, (handle,)), 0)
            self.assertEqual(waiting.result(timeout=2), 0)

    def test_create_signal_reset_destroy_and_file_isolation(self):
        handle = self.sync(True)
        self.assertEqual(self.wait(handle), 0)
        self.assertEqual(self.array_op(0xc4, (handle,)), 0)
        self.assertEqual(self.wait(handle), -errno.EINVAL)
        other = self.lib.g17g_drm_open_file()
        self.assertEqual(self.call(0xc0, drm.drm_syncobj_destroy(handle), file=other), -errno.ENOENT)
        self.success(0xc0, drm.drm_syncobj_destroy(handle))
        self.assertEqual(self.array_op(0xc5, (handle,)), -errno.ENOENT)

    def test_failed_bulk_signal_does_not_partially_signal(self):
        handle = self.sync()
        self.assertEqual(self.array_op(0xc5, (handle, 999)), -errno.ENOENT)
        self.assertEqual(self.wait(handle), -errno.EINVAL)
        self.assertEqual(self.array_op(0xc5, ()), -errno.EINVAL)

    def test_timeline_query_signal_transfer_and_binary_view(self):
        src, dst = self.sync(), self.sync()
        self.assertEqual(self.signal(src, 5), 0)
        self.assertEqual(self.query(src), 5)
        self.assertEqual(self.query(src, 1), 5)
        self.assertEqual(self.wait(src, value=4), 0)
        self.assertEqual(self.wait(src), 0)
        self.success(0xcc, drm.drm_syncobj_transfer(src, dst, 5, 7))
        self.assertEqual(self.query(dst), 7)
        self.assertEqual(self.array_op(0xc4, (src,)), 0)
        self.assertEqual(self.wait(dst, value=7), 0)

    def test_mmap_flags_retain_writeback_and_check_gem_ownership(self):
        other = self.lib.g17g_drm_open_file()
        for flags in (0, api.DRM_ASAHI_GEM_WRITEBACK):
            bo = self.success(0x45, api.drm_asahi_gem_create(17, flags=flags))
            offset = self.success(0x46, api.drm_asahi_gem_mmap_offset(bo.handle)).offset
            for identity, length, expected in (
                    (self.file, 0x4000, flags), (self.file, 0x4001, -errno.EINVAL),
                    (other, 0x4000, -errno.EINVAL)):
                self.assertEqual(self.lib.g17g_drm_mmap_bo_flags(identity, offset, length), expected)
            mapped_flags = ctypes.c_int(-1)
            fd = self.lib.g17g_drm_mmap_fd(self.file, offset, 0x4000, ctypes.byref(mapped_flags))
            self.assertGreaterEqual(fd, 0)
            os.close(fd)
            self.assertEqual(mapped_flags.value, flags)

    def test_gem_rounding_shared_mmap_and_close_isolation(self):
        bo = self.success(0x45, api.drm_asahi_gem_create(17))
        offset = self.success(0x46, api.drm_asahi_gem_mmap_offset(bo.handle)).offset
        self.assertEqual(offset % 0x4000, 0)
        self.assertEqual(self.lib.g17g_drm_mmap_offset(self.file, offset, 0x4000), offset)
        old_file = self.driver.file(self.file).bos[bo.handle].backing_file
        fd = self.lib.g17g_drm_mmap_fd(self.file, offset, 0x4000, None)
        self.assertGreaterEqual(fd, 0)
        try:
            mapping = mmap.mmap(fd, 0x4000)
        finally:
            os.close(fd)
        self.addCleanup(mapping.close)
        mapping[:12] = b"caller bytes"
        self.assertEqual(os.pread(old_file.fileno(), 12, 0), b"caller bytes")
        other = self.lib.g17g_drm_open_file()
        self.assertEqual(self.call(0x46, api.drm_asahi_gem_mmap_offset(bo.handle), file=other), -errno.ENOENT)
        self.assertEqual(self.lib.g17g_drm_mmap_fd(other, offset, 0x4000, None), -errno.EINVAL)
        pending_map = self.lib.g17g_drm_mmap_fd(self.file, offset, 0x4000, None)
        self.assertGreaterEqual(pending_map, 0)
        try:
            self.success(0x09, drm.drm_gem_close(bo.handle))
            with mmap.mmap(pending_map, 0x4000) as late_mapping:
                self.assertEqual(late_mapping[:12], b"caller bytes")
        finally:
            os.close(pending_map)
        self.assertEqual(self.call(0x46, api.drm_asahi_gem_mmap_offset(bo.handle)), -errno.ENOENT)
        self.assertTrue(old_file.closed)
        self.assertEqual(self.lib.g17g_drm_mmap_fd(self.file, offset, 0x4000, None), -errno.EINVAL)
        for _ in range(32):
            next_bo = self.success(0x45, api.drm_asahi_gem_create(17), file=other)
            next_offset = self.success(0x46, api.drm_asahi_gem_mmap_offset(next_bo.handle), file=other).offset
            self.assertNotEqual(offset, next_offset)
            next_file = self.driver.file(other).bos[next_bo.handle].backing_file
            self.assertEqual(os.pread(next_file.fileno(), 12, 0), bytes(12))
            self.success(0x09, drm.drm_gem_close(next_bo.handle), file=other)
            self.assertTrue(next_file.closed)
        self.assertEqual(self.lib.g17g_drm_close_file(self.file), 0)
        self.assertEqual(mapping[:12], b"caller bytes")
        self.assertEqual(os.fstat(self.backing.fileno()).st_size, 0)

    def test_submit_waits_actual_fence_and_retains_gem_until_completion(self):
        vm, bo, queue = self.setup_compute()
        handle = self.sync()
        self.assertEqual(self.submit(queue, outputs=(api.drm_asahi_sync(1, handle, 3),)), 0)
        self.assertEqual(self.query(handle), 0)
        self.assertEqual(self.query(handle, 1), 3)
        self.assertEqual(self.wait(handle, value=3), -errno.ETIME)
        self.assertEqual(self.wait(handle, value=3, flags=4), 0)
        backing = self.driver.file(self.file).bos[bo.handle].backing_file
        self.success(0x09, drm.drm_gem_close(bo.handle))
        self.assertFalse(self.adapter.released)
        self.assertFalse(backing.closed)
        self.adapter.fences[-1].signal()
        self.driver.reap_deferred()
        self.assertEqual(self.adapter.released, [(self.file, bo.handle)])
        self.assertTrue(backing.closed)
        self.assertEqual(self.query(handle), 3)
        self.assertEqual(self.wait(handle, value=3), 0)

    def test_unknown_submit_sync_is_rejected_without_publication(self):
        vm, bo, queue = self.setup_compute()
        self.assertEqual(self.submit(queue, outputs=(api.drm_asahi_sync(0, 9, 0),)), -errno.ENOENT)
        self.assertFalse(self.adapter.fences)

    def test_errored_fence_signals_wait_but_fails_dependent_submit(self):
        vm, bo, queue = self.setup_compute()
        handle = self.sync()
        desc = api.drm_asahi_sync(0, handle, 0)
        self.assertEqual(self.submit(queue, outputs=(desc,)), 0)
        self.adapter.fences[-1].signal(error=-19)
        self.assertEqual(self.wait(handle), 0)
        self.assertEqual(self.submit(queue, inputs=(desc,)), -19)
        self.assertEqual(len(self.adapter.fences), 1)
        self.assertEqual(self.shim.last_fences[self.file].error, -19)

    def test_terminal_submit_error_reaches_ioctl_and_out_sync(self):
        _vm, bo, queue = self.setup_compute()
        handle = self.sync()
        failed = api.drm_asahi_sync(1, handle, 2)
        recovered = api.drm_asahi_sync(1, handle, 3)
        self.adapter.completion_error = -errno.ENOMEM
        self.assertEqual(self.submit(queue, outputs=(failed,)), -errno.ENOMEM)
        self.assertEqual(self.wait(handle, value=2), 0)
        fence = self.shim.last_fences[self.file]
        self.assertEqual(fence.error, -errno.ENOMEM)
        self.assertEqual(fence.bos, ())
        self.assertEqual(self.driver.file(self.file).bos[bo.handle].fences, [])
        self.assertEqual(self.submit(queue, inputs=(failed,)), -errno.ENOMEM)
        self.assertEqual(len(self.adapter.fences), 1)

        self.adapter.completion_error = None
        self.assertEqual(self.submit(queue, outputs=(recovered,)), 0)
        self.adapter.fences[-1].signal()
        self.assertEqual(self.submit(queue, inputs=(recovered,)), 0)
        self.assertEqual(self.lib.g17g_drm_close_file(self.file), 0)
        self.assertNotIn(self.file, self.shim.last_fences)

    def test_timeline_chain_cannot_skip_earlier_pending_fence(self):
        vm, bo, queue = self.setup_compute()
        handle = self.sync()
        self.assertEqual(self.submit(queue, outputs=(api.drm_asahi_sync(1, handle, 2),)), 0)
        self.assertEqual(self.submit(queue, outputs=(api.drm_asahi_sync(1, handle, 3),)), 0)
        self.adapter.fences[1].signal()
        self.assertEqual(self.wait(handle, value=3), -errno.ETIME)
        self.assertEqual(self.query(handle), 0)
        self.adapter.fences[0].signal()
        self.assertEqual(self.wait(handle, value=3), 0)
        self.assertEqual(self.query(handle), 3)

    def test_completed_timeline_error_does_not_poison_independent_recovery(self):
        vm, bo, queue = self.setup_compute()
        handle = self.sync()
        failed = api.drm_asahi_sync(1, handle, 2)
        recovered = api.drm_asahi_sync(1, handle, 3)
        self.assertEqual(self.submit(queue, outputs=(failed,)), 0)
        self.adapter.fences[-1].signal(error=-12)
        self.assertEqual(self.wait(handle, value=2), 0)
        self.assertEqual(self.submit(queue, outputs=(recovered,)), 0)
        self.adapter.fences[-1].signal()
        self.assertEqual(self.query(handle), 3)
        self.assertEqual(self.submit(queue, inputs=(failed,)), -12)
        self.assertEqual(self.submit(queue, inputs=(recovered,)), 0)

    def test_long_completed_timeline_through_native_query(self):
        handle = self.sync()
        for value in range(1, 1601):
            self.assertEqual(self.signal(handle, value), 0)
            if value % 100 == 0:
                self.assertEqual(self.query(handle), value)
        self.assertEqual(self.wait(handle, value=1600), 0)
        self.assertEqual(self.wait(handle, value=1), 0)
        obj = self.driver.file(self.file).syncs[handle]
        self.assertLessEqual(len(obj._points), 2)

        _vm, _bo, queue = self.setup_compute()
        earlier = api.drm_asahi_sync(1, handle, 800)
        self.assertEqual(self.submit(queue, outputs=(earlier,)), 0)
        self.assertEqual(self.query(handle), 799)
        self.assertEqual(self.wait(handle, value=799), 0)
        self.assertEqual(self.wait(handle, value=800), -errno.ETIME)
        self.assertEqual(self.wait(handle, value=1600), -errno.EINVAL)
        self.adapter.fences[-1].signal()
        self.assertEqual(self.query(handle), 800)

    def test_deep_pending_timeline_preserves_errors_and_terminal_override(self):
        handle = self.sync()
        obj = self.driver.file(self.file).syncs[handle]
        first = G17GSoftwareFence()
        obj.bind(first, 1)
        for value in range(2, 1601):
            obj.bind(G17GSoftwareFence(signaled=True), value)
        self.assertFalse(obj.point(1600).signaled())
        self.assertEqual(self.query(handle), 0)
        with self.assertRaises(TimeoutError):
            obj.point(1600).wait(timeout=0)
        first.signal(error=-19)
        self.assertEqual(self.query(handle), 1600)
        self.assertEqual(obj.point(1600).error, -19)
        self.assertEqual(self.wait(handle, value=1600), 0)
        terminal = G17GSubmissionFence((obj.point(1600).fence, G17GSoftwareFence()))
        self.assertFalse(terminal.signaled())
        self.assertTrue(terminal.fail(-5))
        outer = G17GSubmissionFence((terminal, G17GSoftwareFence(signaled=True)))
        self.assertTrue(outer.signaled())
        self.assertEqual(outer.error, -5)

    def test_fatal_gem_close_removes_each_handle_and_retains_all_backing(self):
        first = self.success(0x45, api.drm_asahi_gem_create(0x4000)).handle
        second = self.success(0x45, api.drm_asahi_gem_create(0x4000)).handle
        destroy_bo = self.adapter.destroy_bo
        def failed_retirement(file, bo):
            raise RuntimeError("GPU mapping remains reachable after fault")
        self.adapter.destroy_bo = failed_retirement
        for handle in (first, second):
            self.success(0x09, drm.drm_gem_close(handle))
            self.assertEqual(self.call(0x46, api.drm_asahi_gem_mmap_offset(handle)), -errno.ENOENT)
        self.assertEqual({record["bo"].handle for record in self.driver.deferred_bos},
                         {first, second})
        self.assertFalse(self.adapter.released)
        self.adapter.destroy_bo = destroy_bo
        self.driver.reap_deferred()
        self.assertEqual(self.adapter.released, [(self.file, first), (self.file, second)])

    def test_close_file_invalidates_waiting_submit_and_preserves_new_identity(self):
        vm, bo, queue = self.setup_compute()
        handle = self.sync()
        pending = G17GSoftwareFence()
        obj = self.driver.file(self.file).syncs[handle]
        obj.bind(pending)
        entered = threading.Event()
        original = pending.wait
        def wait(**kwargs):
            entered.set()
            return original(**kwargs)
        pending.wait = wait
        with ThreadPoolExecutor() as threads:
            future = threads.submit(self.submit, queue, inputs=(api.drm_asahi_sync(0, handle, 0),))
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.lib.g17g_drm_close_file(self.file), 0)
            new_file = self.lib.g17g_drm_open_file()
            self.assertNotEqual(new_file, self.file)
            pending.signal()
            self.assertEqual(future.result(timeout=2), -errno.EBADF)
        self.assertFalse(self.adapter.fences)
        self.assertEqual(self.call(0xbf, drm.drm_syncobj_create()), -errno.EBADF)


if __name__ == "__main__":
    unittest.main()
