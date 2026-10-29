# SPDX-License-Identifier: GPL-2.0-only
"""In-process C DRM ioctl boundary for the independent T8142 runtime.

The native bridge copies caller memory with fault-reporting OS APIs. This
module never dereferences a raw userspace pointer with ctypes. GEM storage is
the bridge's shared backing file; compiler programs remain opaque caller data.
"""
import ctypes
import errno
import os
import struct
import threading
import time

from . import g17g_drm_uapi as drm
from . import g17g_uapi as api
from .g17g_drm_sync import G17GDRMSyncObject
from .g17g_modern import G17GModernDriver, PAGE_SIZE


# These are ioctl command numbers, not platform-dependent _IOC encodings.
LAYOUTS = {
    0x00: drm.drm_version,
    0x09: drm.drm_gem_close, 0x0c: drm.drm_get_cap,
    0xbf: drm.drm_syncobj_create, 0xc0: drm.drm_syncobj_destroy,
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
                 params=None, get_time=None):
        self.backing_fd = os.dup(backing_fd)
        self.memory = memory
        self.driver = driver
        if driver is not None:
            driver.strict_syncs = True
        self.driver_factory = driver_factory
        self.params = params
        self.get_time = get_time
        self.lock = threading.RLock()
        self.files = {}
        self.next_file = 1
        # Never recycle offsets while a caller mmap may survive GEM_CLOSE.
        # Reuse requires explicit mmap ownership, separately from GPU fences.
        self.next_offset = (os.fstat(self.backing_fd).st_size + PAGE_SIZE - 1) & -PAGE_SIZE
        self.next_offset = max(PAGE_SIZE, self.next_offset)
        self.last_fences = {}
        self.errors = []
        self.teardown_errors = []

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
        if self.driver is not None:
            self.driver.close_file(identity)
        self.last_fences.pop(identity, None)
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
            # No PRIME/export/eventfd capability is fabricated. Basic and
            # timeline waits are serviced by this same object's real fences.
            if arg.capability not in (0x5, 0x10, 0x13, 0x14):
                raise ValueError("unsupported DRM capability")
            arg.value = int(arg.capability in (0x13, 0x14))
            if arg.capability == 0x10:  # ADDFB2_MODIFIERS is irrelevant here.
                arg.value = 0
            return
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
            if not arg.stride:
                raise ValueError("VM bind stride is zero")
            raw = self._read(arg.userptr, int(arg.num_binds) * int(arg.stride))
            operations = tuple(api.drm_asahi_gem_bind_op.from_bytes(
                raw[index:index + arg.stride], extensible=True)
                for index in range(0, len(raw), arg.stride))
            for operation in operations:
                driver.bind(identity, arg.vm_id, operation)
        elif number == 0x45:
            with self.lock:
                file = self._file(identity)
                handle = file["next_bo"]
                size = (int(arg.size) + PAGE_SIZE - 1) & -PAGE_SIZE
                if not size or size >= 1 << 63 or self.next_offset + size >= 1 << 63:
                    raise ValueError("invalid GEM size")
                offset = self.next_offset
                os.ftruncate(self.backing_fd, offset + size)
                driver.create_bo(identity, handle, offset, size, arg.flags, arg.vm_id)
                self.next_offset = offset + size
                file["next_bo"] += 1
                arg.handle = handle
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
            self.last_fences[identity] = fence
            # Publication succeeded: asynchronous errors live on the output
            # fence. Never turn this into a clean fence or discard attribution.
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
        self._file(identity)
        with self._driver()._ownership_lock:
            for bo in self.driver.file(identity).bos.values():
                if offset == bo.memfd_offset and 0 < size <= bo.size:
                    return offset
        raise OSError(errno.EINVAL, "mmap does not name this file's live GEM object")
