# SPDX-License-Identifier: GPL-2.0-or-later
"""Linux DRM-backed dma-bufs for the host side of the proxy."""
from contextlib import contextmanager
import errno
import fcntl
import os
import struct


DRM_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
DRM_RDWR = os.O_RDWR
DMA_BUF_IOCTL_SYNC = 0x40086200
DMA_BUF_SYNC_READ = 1
DMA_BUF_SYNC_WRITE = 2
DMA_BUF_SYNC_END = 4
DRM_IOCTL_PRIME_HANDLE_TO_FD = 0xc00c642d
DRM_IOCTL_MODE_CREATE_DUMB = 0xc02064b2


class DMABuf:
    def __init__(self, fd):
        info = os.fstat(fd)
        self.fd = fd
        self.size = info.st_size
        self.key = (info.st_dev, info.st_ino)

    def fileno(self):
        return self.fd

    @property
    def closed(self):
        return self.fd < 0

    def close(self):
        if not self.closed:
            fd, self.fd = self.fd, -1
            os.close(fd)

    def _sync(self, flags):
        while True:
            try:
                fcntl.ioctl(self.fd, DMA_BUF_IOCTL_SYNC, struct.pack("=Q", flags))
                return
            except (InterruptedError, BlockingIOError):
                pass

    @contextmanager
    def cpu_access(self, flags):
        self._sync(flags)
        try:
            yield
        finally:
            self._sync(flags | DMA_BUF_SYNC_END)


def import_dmabuf(fd):
    owned = os.dup(fd)
    try:
        buffer = DMABuf(owned)
        # The kernel validates the FD type and the exporter supports coherent
        # CPU access. No caller bytes are inspected at this point.
        with buffer.cpu_access(DMA_BUF_SYNC_READ):
            pass
        return buffer
    except BaseException:
        os.close(owned)
        raise


def allocate_dmabuf(device, size, page_size):
    # A linear dumb GEM with one shim page per row supplies writable backing
    # for the proxy. Applications provide format and stride when importing.
    drm = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    try:
        request = struct.pack("=6IQ", size // page_size, page_size // 4, 32, 0, 0, 0, 0)
        result = fcntl.ioctl(drm, DRM_IOCTL_MODE_CREATE_DUMB, request)
        *_, handle, _pitch, actual_size = struct.unpack("=6IQ", result)
        if actual_size != size:
            raise OSError(errno.EINVAL, "native DRM allocation has unexpected size")
        request = struct.pack("=IIi", handle, DRM_CLOEXEC | DRM_RDWR, -1)
        result = fcntl.ioctl(drm, DRM_IOCTL_PRIME_HANDLE_TO_FD, request)
        owned = struct.unpack("=IIi", result)[2]
        try:
            buffer = DMABuf(owned)
            if buffer.size != size:
                raise OSError(errno.EINVAL, "exported dma-buf has unexpected size")
            return buffer
        except BaseException:
            os.close(owned)
            raise
    finally:
        os.close(drm)
