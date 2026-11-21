# SPDX-License-Identifier: GPL-2.0-or-later
"""Linux sync-file transport for the synchronous host shim."""
import ctypes
import errno
import fcntl
import os
import struct
import threading
import weakref

from .g17g_drm_sync import G17GDRMSyncObject
from .g17g_sync import G17GSoftwareFence, G17GSyncPoint


SYNC_IOC_FILE_INFO = 0xc0383e04
DRM_IOCTL_SYNCOBJ_CREATE = 0xc00864bf
DRM_IOCTL_SYNCOBJ_DESTROY = 0xc00864c0
DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD = 0xc01064c1
DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE = 0xc01064c2
DRM_IOCTL_SYNCOBJ_RESET = 0xc01064c4
DRM_IOCTL_SYNCOBJ_SIGNAL = 0xc01064c5
DRM_IOCTL_SYNCOBJ_QUERY = 0xc01864cb
DRM_IOCTL_SYNCOBJ_TRANSFER = 0xc02064cc
DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL = 0xc01864cd
DRM_SYNCOBJ_CREATE_SIGNALED = 1
DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE = 1


class SyncFileFence(G17GSoftwareFence):
    def __init__(self, fd):
        super().__init__()
        self.fd = os.dup(fd)
        self._close = weakref.finalize(self, os.close, self.fd)
        try:
            self.signaled()
        except BaseException:
            self._close()
            raise

    def signaled(self):
        if not self._signaled:
            info = fcntl.ioctl(self.fd, SYNC_IOC_FILE_INFO, bytes(56))
            status = struct.unpack_from("=i", info, 32)[0]
            if status:
                self.signal(error=status if status < 0 else None)
        return self._signaled

    def dup(self):
        return os.dup(self.fd)


class NativeSyncobjDevice:
    """A single native DRM file owns the shim's Linux syncobj handles."""

    def __init__(self, path):
        self.path = path
        self.fd = None
        self.lock = threading.Lock()

    def ioctl(self, request, data):
        with self.lock:
            if self.fd is None:
                self.fd = os.open(self.path, os.O_RDWR | os.O_CLOEXEC)
                weakref.finalize(self, os.close, self.fd)
        return fcntl.ioctl(self.fd, request, data)

    def create(self, flags=0):
        result = self.ioctl(DRM_IOCTL_SYNCOBJ_CREATE, struct.pack("=II", 0, flags))
        return struct.unpack_from("=I", result)[0]

    def destroy(self, handle):
        self.ioctl(DRM_IOCTL_SYNCOBJ_DESTROY, struct.pack("=II", handle, 0))

    def export_fd(self, handle, flags=0):
        result = self.ioctl(DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD,
                            struct.pack("=IIiI", handle, flags, -1, 0))
        return struct.unpack_from("=i", result, 8)[0]

    def import_fd(self, fd, *, handle=0, flags=0):
        result = self.ioctl(DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE,
                            struct.pack("=IIiI", handle, flags, fd, 0))
        return struct.unpack_from("=I", result)[0]

    def transfer(self, source, target, source_point, target_point):
        self.ioctl(DRM_IOCTL_SYNCOBJ_TRANSFER,
                   struct.pack("=IIQQII", source, target, source_point, target_point, 0, 0))

    def array(self, request, handle, *, point=None, flags=0):
        native_handle = ctypes.c_uint32(handle)
        if point is None:
            self.ioctl(request, struct.pack("=QII", ctypes.addressof(native_handle), 1, 0))
            return
        native_point = ctypes.c_uint64(point)
        self.ioctl(request, struct.pack("=QQII", ctypes.addressof(native_handle),
                                       ctypes.addressof(native_point), 1, flags))
        return native_point.value


class NativeSyncobj(G17GDRMSyncObject):
    """A live Linux syncobj with a local record for unexportable shim errors."""

    def __init__(self, device, handle):
        super().__init__()
        self.device = device
        self.handle = handle
        weakref.finalize(self, device.destroy, handle)

    def export_fd(self):
        return self.device.export_fd(self.handle)

    def reset(self):
        self.device.array(DRM_IOCTL_SYNCOBJ_RESET, self.handle)
        super().reset()

    def _replace_local(self, value):
        if not value:
            super().reset()
        else:
            del self._points[self._find(value):]
            self._binary = None

    def signal(self, value=0, error=None):
        self.validate_bind(value)
        if error is not None:
            return self.bind(G17GSoftwareFence(signaled=True, error=error), value)
        self._signal_native(value)
        self._replace_local(value)

    def _signal_native(self, value):
        if value:
            self._check_native_timeline(value)
            self.device.array(DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL, self.handle, point=value)
        else:
            self.device.array(DRM_IOCTL_SYNCOBJ_SIGNAL, self.handle)

    def _check_native_timeline(self, value):
        # Advancing a native timeline across an unexportable shim error
        # would make native waits on the failed point appear successful.
        for _, point in self._points[:self._find(value)]:
            if point.signaled() and point.error is not None:
                raise OSError(-int(point.error), "native timeline has an unexportable failed point")

    def bind(self, fence, value=0):
        self.validate_bind(value)
        if isinstance(fence, SyncFileFence):
            if not value:
                self.device.import_fd(fence.fd, handle=self.handle, flags=1)
            else:
                self._check_native_timeline(value)
                handle = self.device.create()
                try:
                    self.device.import_fd(fence.fd, handle=handle, flags=1)
                    self.device.transfer(handle, self.handle, 0, value)
                finally:
                    self.device.destroy(handle)
            self._replace_local(value)
        elif fence.signaled() and fence.error is None:
            self.signal(value)
        else:
            if not value:
                # An opaque peer waiting for the new fence must never see
                # a successful fence from a previous binary submission.
                self.reset()
            return super().bind(fence, value)
        return G17GSyncPoint(value, fence)

    def finish(self, point):
        if (point is super().point(point.value) and
                point.signaled() and point.error is None):
            self._signal_native(point.value)
            if point.value:
                del self._points[self._find(point.value)]
            if point is self._binary:
                self._binary = None

    def point(self, value=0):
        local = super().point(value)
        if local is not None and (not value or local.value == value):
            return local
        temporary = self.device.create() if value else None
        try:
            if temporary is not None:
                self.device.transfer(self.handle, temporary, value, 0)
            fd = self.device.export_fd(temporary if value else self.handle, flags=1)
        except OSError as error:
            if error.errno in (errno.EINVAL, errno.ENOENT):
                return local
            raise
        finally:
            if temporary is not None:
                self.device.destroy(temporary)
        try:
            return G17GSyncPoint(value, SyncFileFence(fd))
        finally:
            os.close(fd)

    def query(self, *, last_submitted=False):
        native = self.device.array(DRM_IOCTL_SYNCOBJ_QUERY, self.handle,
                                   point=0, flags=int(last_submitted))
        return max(native, super().query(last_submitted=last_submitted))


def export_sync_file(device, fence):
    if isinstance(fence, SyncFileFence):
        return fence.dup()
    if not fence.signaled():
        raise OSError(errno.EAGAIN, "local shim fence is still pending")
    if fence.error is not None:
        raise OSError(-int(fence.error), "local shim fence completed with an error")
    # The proxy completes work before returning to its callers. Export the
    # kernel's real signaled fence after observing successful retirement.
    handle = device.create(DRM_SYNCOBJ_CREATE_SIGNALED)
    try:
        return device.export_fd(handle, DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE)
    finally:
        device.destroy(handle)
