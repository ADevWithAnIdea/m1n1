# SPDX-License-Identifier: GPL-2.0-only
"""In-process C DRM ioctl boundary for the independent T8142 runtime.

The native bridge copies caller memory with fault-reporting OS APIs. This
module never dereferences a raw userspace pointer with ctypes. Each ioctl GEM
has its own backing file. Compiler programs remain opaque caller data.
"""
from collections import deque
import ctypes
import errno
import os
import struct
import sys
import tempfile
import threading
import time

from . import g17g_drm_uapi as drm
from . import g17g_uapi as api
from .g17g_drm_sync import G17GDRMSyncObject
from .g17g_modern import G17GModernDriver, PAGE_SIZE
from .g17g_prime import DMABuf, DRM_CLOEXEC, DRM_RDWR, allocate_dmabuf, import_dmabuf
from .g17g_sync_file import NativeSyncobj, NativeSyncobjDevice, SyncFileFence, export_sync_file


# These are ioctl command numbers, not platform-dependent _IOC encodings.
LAYOUTS = {
    0x00: drm.drm_version,
    0x09: drm.drm_gem_close, 0x0c: drm.drm_get_cap,
    0x2d: drm.drm_prime_handle, 0x2e: drm.drm_prime_handle,
    0xbf: drm.drm_syncobj_create, 0xc0: drm.drm_syncobj_destroy,
    0xc1: drm.drm_syncobj_handle, 0xc2: drm.drm_syncobj_handle,
    0xc3: drm.drm_syncobj_wait, 0xc4: drm.drm_syncobj_array,
    0xc5: drm.drm_syncobj_array, 0xca: drm.drm_syncobj_timeline_wait,
    0xcb: drm.drm_syncobj_timeline_array, 0xcc: drm.drm_syncobj_transfer,
    0xcd: drm.drm_syncobj_timeline_array,
}
for _index, _layout in enumerate((
    api.drm_asahi_get_params, api.drm_asahi_get_time,
    api.drm_asahi_vm_create, api.drm_asahi_vm_destroy,
    api.drm_asahi_vm_bind, api.drm_asahi_gem_create,
    api.drm_asahi_gem_mmap_offset, api.drm_asahi_gem_bind_object,
    api.drm_asahi_queue_create, api.drm_asahi_queue_destroy,
    api.drm_asahi_submit,
)):
    LAYOUTS[0x40 + _index] = _layout


class G17GIoctlShim:
    def __init__(self, backing_fd, memory, *, driver=None, driver_factory=None,
                 params=None, get_time=None, native_drm_device=None):
        self.backing_fd = os.dup(backing_fd)
        self.memory = memory
        self.driver = driver
        if driver is not None:
            driver.strict_syncs = True
        self.driver_factory = driver_factory
        self.params = params
        self.get_time = get_time
        self.native_drm_device = native_drm_device if sys.platform == "linux" else None
        self.native_syncobjs = (NativeSyncobjDevice(self.native_drm_device)
                                if self.native_drm_device else None)
        self.lock = threading.RLock()
        self.files = {}
        self.next_file = 1
        # These offsets identify BOs to the interposer. Each BO maps its file
        # at offset zero, so the offset namespace reserves no file space.
        self.next_offset = PAGE_SIZE
        self.last_fences = {}
        self.errors = deque(maxlen=128)
        self.teardown_errors = deque(maxlen=128)

    def _driver(self):
        # Avoid taking the initialization lock from inside the driver's
        # ownership lock (GEM allocation takes those in the opposite order).
        if self.driver is not None:
            return self.driver
        with self.lock:
            if self.driver is None:
                if self.driver_factory is None:
                    raise OSError(errno.ENODEV, "no G17G hardware adapter")
                self.driver = self.driver_factory(self.backing_fd)
                self.driver.strict_syncs = True
            return self.driver

    def open_file(self):
        with self.lock:
            identity = self.next_file
            self.next_file += 1
            self.files[identity] = {"next_bo": 1, "next_sync": 1}
            return identity

    def _file(self, identity):
        if identity not in self.files:
            raise OSError(errno.EBADF, "closed DRM file")
        return self.files[identity]

    def close_file(self, identity):
        with self.lock:
            self._file(identity)
            del self.files[identity]
            self.last_fences.pop(identity, None)
        if self.driver is not None:
            self.driver.close_file(identity)
        return 0

    @staticmethod
    def _errno(error):
        if isinstance(error, OSError):
            return error.errno or errno.EIO
        if isinstance(error, KeyError):
            return errno.ENOENT
        if isinstance(error, (ValueError, TypeError)):
            return errno.EINVAL
        if isinstance(error, MemoryError):
            return errno.ENOMEM
        if isinstance(error, NotImplementedError):
            return errno.EOPNOTSUPP
        if isinstance(error, RuntimeError):
            return errno.EBUSY
        return errno.EIO

    def ioctl(self, identity, number, data):
        """Return (negative errno or zero, output bytes) to the C dispatcher."""
        original = bytes(data)
        try:
            self._file(identity)
            if number in (0x2d, 0x2e, 0xc1, 0xc2) and not self.native_drm_device:
                raise OSError(errno.ENOTTY, "no native Linux DRM sharing device")
            layout = LAYOUTS.get(number)
            if layout is None:
                raise OSError(errno.ENOTTY, "unsupported DRM ioctl")
            minimum = ctypes.sizeof(layout)
            if number in (0xc3, 0xca):
                minimum -= 8  # deadline_nsec was appended to drm.h later.
            if len(original) < minimum:
                raise ValueError("truncated DRM ioctl argument")
            arg = layout.from_bytes(original, extensible=True)
            if getattr(arg, "pad", 0):
                raise ValueError("DRM ioctl padding must be zero")
            self._dispatch(identity, number, arg)
            body = arg.to_bytes()
            return 0, body[:len(original)].ljust(len(original), b"\0")
        except Exception as error:
            code = self._errno(error)
            self.errors.append(dict(file=identity, ioctl=number,
                                    errno=code, error=str(error)))
            return -code, original

    def _read(self, pointer, size):
        size = int(size)
        if size > 64 * 1024 * 1024:
            raise MemoryError("ioctl copy exceeds host allocation limit")
        if size == 0:
            return b""
        return self.memory.read(int(pointer), size)

    def _array(self, pointer, count, fmt):
        size = struct.calcsize(fmt)
        raw = self._read(pointer, int(count) * size)
        return tuple(item[0] for item in struct.iter_unpack(fmt, raw))

    def _objects(self, identity, handles):
        self._file(identity)
        records = self._driver().file(identity).syncs
        return tuple(records[handle] for handle in handles)

    def _dispatch(self, identity, number, arg):
        if number == 0x00:
            # Match Linux drm_copy_field: bounded copies without a trailing
            # NUL, report full lengths, and permit NULL length-query buffers.
            # Discovery describes this shim and never starts the GPU.
            arg.version_major, arg.version_minor, arg.version_patchlevel = 1, 0, 0
            for field, value in (("name", b"asahi"), ("date", b"0"),
                                 ("desc", b"G17G m1n1 DRM shim")):
                capacity = int(getattr(arg, field + "_len"))
                pointer = int(getattr(arg, field))
                if capacity and pointer:
                    self.memory.write(pointer, value[:capacity])
                setattr(arg, field + "_len", len(value))
            return
        if number == 0x0c:
            if arg.capability not in (0x5, 0x10, 0x13, 0x14):
                raise ValueError("unsupported DRM capability")
            if arg.capability == 0x5:
                arg.value = 3 if self.native_drm_device else 0
            else:
                arg.value = int(arg.capability in (0x13, 0x14))
            return
        if number in (0x2d, 0x2e):
            return self._prime_ioctl(identity, number, arg)
        if number in (0xc1, 0xc2):
            if arg.flags == 0:
                return self._opaque_sync_ioctl(identity, number, arg)
            if arg.flags != 1:
                raise ValueError("unsupported syncobj FD flags")
            return self._sync_file_ioctl(identity, number, arg)
        if number == 0x40:
            if arg.param_group:
                raise ValueError("unknown Asahi parameter group")
            if self.params is None:
                raise NotImplementedError("live M5 parameter discovery pending")
            data = self.params() if callable(self.params) else self.params
            self.memory.write(int(arg.pointer), bytes(data)[:arg.size])
            return
        if number == 0x41:
            if arg.flags:
                raise ValueError("unknown get-time flags")
            if self.get_time is None:
                raise NotImplementedError("GPU timestamp clock qualification pending")
            arg.gpu_timestamp = self.get_time()
            return
        driver = self._driver()
        if number == 0x42:
            arg.vm_id = driver.create_vm(identity, arg.kernel_start, arg.kernel_end).vm_id
        elif number == 0x43:
            driver.destroy_vm(identity, arg.vm_id)
        elif number == 0x44:
            if arg.stride < ctypes.sizeof(api.drm_asahi_gem_bind_op):
                raise ValueError("VM bind stride is smaller than a bind operation")
            size = int(arg.num_binds) * int(arg.stride)
            if arg.num_binds > 4096 or size > 1024 * 1024:
                raise ValueError("VM bind array exceeds its size limit")
            raw = self._read(arg.userptr, size)
            with driver._ownership_lock:
                if arg.vm_id not in driver.file(identity).vms:
                    raise KeyError("unknown VM")
                # Committed operations remain visible when a later one fails.
                for index in range(0, size, arg.stride):
                    operation = api.drm_asahi_gem_bind_op.from_bytes(
                        raw[index:index + arg.stride], extensible=True)
                    driver.bind(identity, arg.vm_id, operation)
        elif number == 0x45:
            with self.lock:
                size = (int(arg.size) + PAGE_SIZE - 1) & -PAGE_SIZE
                if not size or size >= 1 << 63 or self.next_offset + size >= 1 << 63:
                    raise ValueError("invalid GEM size")
                if self.native_drm_device and not arg.flags & api.DRM_ASAHI_GEM_VM_PRIVATE:
                    backing = allocate_dmabuf(self.native_drm_device, size, PAGE_SIZE)
                else:
                    backing = tempfile.TemporaryFile()
                    try:
                        os.ftruncate(backing.fileno(), size)
                    except BaseException:
                        backing.close()
                        raise
                self._create_backed_bo(driver, identity, size, backing, arg.flags, arg.vm_id, arg)

        elif number == 0x46:
            if arg.flags:
                raise ValueError("unknown mmap-offset flags")
            arg.offset = driver.file(identity).bos[arg.handle].memfd_offset
        elif number == 0x47:
            driver.bind_object(identity, arg)
        elif number == 0x48:
            if arg.flags:
                raise ValueError("unknown queue flags")
            arg.queue_id = driver.create_queue(identity, arg.vm_id, arg.priority,
                                               arg.usc_exec_base).queue_id
        elif number == 0x49:
            driver.destroy_queue(identity, arg.queue_id)
        elif number == 0x4a:
            if arg.flags:
                raise ValueError("unknown submit flags")
            raw = self._read(arg.syncs, (int(arg.in_sync_count) + arg.out_sync_count) * 16)
            syncs = tuple(api.drm_asahi_sync.from_bytes(raw[i:i + 16])
                          for i in range(0, len(raw), 16))
            commands = self._read(arg.cmdbuf, arg.cmdbuf_size)
            fence, _commands = driver.submit(identity, arg.queue_id, commands,
                syncs[:arg.in_sync_count], syncs[arg.in_sync_count:])
            with self.lock:
                if identity in self.files:
                    self.last_fences[identity] = fence
            # Terminal errors are available before a synchronous submit returns.
            # Report the errno here while preserving the already-published
            # fence for waits and dependent submissions.
            if fence.signaled() and fence.error is not None:
                raise OSError(-int(fence.error), "G17G submission completed with an error")
        elif number == 0x09:
            try:
                if not driver.destroy_bo(identity, arg.handle):
                    raise KeyError("unknown GEM handle")
            except (OSError, RuntimeError) as error:
                if arg.handle in driver.file(identity).bos or not any(
                        record["file"].fd == identity and record["bo"].handle == arg.handle
                        for record in driver.deferred_bos):
                    raise
                # GEM_CLOSE has removed the handle. Physical retirement can
                # remain deferred after a terminal fault without undoing that
                # successful close or releasing GPU-reachable backing.
                self.teardown_errors.append(dict(file=identity, handle=arg.handle,
                                                  error=str(error)))
        else:
            self._sync_ioctl(identity, number, arg)

    def _create_backed_bo(self, driver, identity, size, backing, flags, vm_id, arg):
        try:
            file = self._file(identity)
            handle, offset = file["next_bo"], self.next_offset
            driver.create_bo(identity, handle, offset, size, flags, vm_id, backing_file=backing)
        except BaseException:
            backing.close()
            raise
        self.next_offset += size
        file["next_bo"] += 1
        arg.handle = handle

    def _prime_ioctl(self, identity, number, arg):
        if number == 0x2d and arg.flags & ~(DRM_CLOEXEC | DRM_RDWR):
            raise ValueError("unknown PRIME export flags")
        driver = self._driver()
        with self.lock, driver._ownership_lock:
            self._file(identity)
            bos = driver.file(identity).bos
            if number == 0x2d:
                backing = bos[arg.handle].backing_file
                if not isinstance(backing, DMABuf):
                    raise OSError(errno.EINVAL, "GEM backing is private")
                exported = os.dup(backing.fileno())
                try:
                    os.set_inheritable(exported, not arg.flags & DRM_CLOEXEC)
                except BaseException:
                    os.close(exported)
                    raise
                arg.fd = exported
                return
            backing = import_dmabuf(arg.fd)
            size = backing.size
            if not size or size % PAGE_SIZE or self.next_offset + size >= 1 << 63:
                backing.close()
                raise ValueError("dma-buf size is not a whole number of shim pages")
            for bo in bos.values():
                if isinstance(bo.backing_file, DMABuf) and bo.backing_file.key == backing.key:
                    backing.close()
                    arg.handle = bo.handle
                    return
            self._create_backed_bo(driver, identity, size, backing, api.DRM_ASAHI_GEM_WRITEBACK, 0, arg)

    def _sync_ioctl(self, identity, number, arg):
        driver = self._driver()
        if number in (0xc3, 0xca):
            return self._wait(identity, number, arg)
        with driver._ownership_lock:
            file = self._file(identity)
            objects = driver.file(identity).syncs
            if number == 0xbf:
                if arg.flags & ~1:
                    raise ValueError("unknown syncobj create flags")
                handle = file["next_sync"]
                if self.native_syncobjs is not None:
                    native = self.native_syncobjs.create(arg.flags)
                    obj = NativeSyncobj(self.native_syncobjs, native)
                else:
                    obj = G17GDRMSyncObject()
                    if arg.flags & 1:
                        obj.signal()
                objects[handle] = obj
                file["next_sync"] += 1
                arg.handle = handle
            elif number == 0xc0:
                del objects[arg.handle]
            elif number in (0xc4, 0xc5, 0xcb, 0xcd):
                if not arg.count_handles:
                    raise ValueError("syncobj array cannot be empty")
                handles = self._array(arg.handles, arg.count_handles, "<I")
                selected = self._objects(identity, handles)
                if number == 0xcb:
                    if arg.flags & ~1:
                        raise ValueError("unknown syncobj query flags")
                    values = tuple(obj.query(last_submitted=bool(arg.flags & 1))
                                   for obj in selected)
                    self.memory.write(arg.points, b"".join(struct.pack("<Q", value)
                                                          for value in values))
                elif number == 0xcd:
                    if arg.flags:
                        raise ValueError("unknown timeline signal flags")
                    points = self._array(arg.points, len(selected), "<Q")
                    for obj, value in zip(selected, points):
                        obj.signal(value)
                else:
                    for obj in selected:
                        obj.reset() if number == 0xc4 else obj.signal()
            elif number == 0xcc:
                if arg.flags:
                    raise ValueError("unsupported syncobj transfer flags")
                src, dst = self._objects(identity, (arg.src_handle, arg.dst_handle))
                point = src.point(arg.src_point)
                if point is None:
                    raise ValueError("source syncobj point has no fence")
                dst.bind(point.fence, arg.dst_point)
            else:
                raise OSError(errno.ENOTTY, "unsupported syncobj ioctl")

    def _opaque_sync_ioctl(self, identity, number, arg):
        driver = self._driver()
        with driver._ownership_lock:
            file = self._file(identity)
            if number == 0xc1:
                (obj,) = self._objects(identity, (arg.handle,))
                arg.fd = obj.export_fd()
            else:
                handle = self.native_syncobjs.import_fd(arg.fd)
                arg.handle = file["next_sync"]
                driver.file(identity).syncs[arg.handle] = NativeSyncobj(self.native_syncobjs, handle)
                file["next_sync"] += 1

    def _sync_file_ioctl(self, identity, number, arg):
        driver = self._driver()
        with driver._ownership_lock:
            (obj,) = self._objects(identity, (arg.handle,))
            if number == 0xc2:
                obj.bind(SyncFileFence(arg.fd))
                return
            point = obj.point(0)
            if point is None:
                raise ValueError("syncobj contains no fence")
            arg.fd = export_sync_file(self.native_syncobjs, point.fence)

    def _wait(self, identity, number, arg):
        if not arg.count_handles or arg.flags & ~(0xf if number == 0xca else 0xb):
            raise ValueError("invalid syncobj wait count or flags")
        handles = self._array(arg.handles, arg.count_handles, "<I")
        values = (self._array(arg.points, arg.count_handles, "<Q")
                  if number == 0xca else (0,) * len(handles))
        driver = self._driver()
        with driver._ownership_lock:
            selected = self._objects(identity, handles)
            # Existing fences remain referenced across reset/replacement and
            # handle destruction. WAIT_FOR_SUBMIT waits on the captured object.
            points = [obj.point(value) for obj, value in zip(selected, values)]
            if not arg.flags & (2 | 4) and any(point is None for point in points):
                raise ValueError("syncobj wait has no submitted fence")
        while True:
            with driver._ownership_lock:
                for i, point in enumerate(points):
                    if point is None:
                        points[i] = selected[i].point(values[i])
                ready = [i for i, point in enumerate(points) if point is not None
                         and (arg.flags & 4 or point.signaled())]
                if ready and (not arg.flags & 1 or len(ready) == len(points)):
                    # DRM waits report terminal completion, including errored
                    # fences. The fence retains its error for dependent work.
                    arg.first_signaled = ready[0]
                    return
            if arg.timeout_nsec >= 0 and time.monotonic_ns() >= arg.timeout_nsec:
                raise OSError(errno.ETIME, "DRM syncobj wait timed out")
            time.sleep(0.0001)

    def mmap_offset(self, identity, offset, size):
        self.mmap_bo_flags(identity, offset, size)
        return offset

    def mmap_bo_flags(self, identity, offset, size):
        self._file(identity)
        with self._driver()._ownership_lock:
            return self._mmap_bo(identity, offset, size).flags

    def mmap_bo_fd(self, identity, offset, size):
        self._file(identity)
        with self._driver()._ownership_lock:
            bo = self._mmap_bo(identity, offset, size)
            return os.dup(bo.backing_file.fileno()), bo.flags

    def _mmap_bo(self, identity, offset, size):
        self._file(identity)
        for bo in self.driver.file(identity).bos.values():
            if offset == bo.memfd_offset and 0 < size <= bo.size:
                return bo
        raise OSError(errno.EINVAL, "mmap does not name this file's live GEM object")
