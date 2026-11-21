# SPDX-License-Identifier: GPL-2.0-only
"""DRM syncobj fence references, shared by the C ioctl and Asahi submit paths.

DRM does not assign a permanent binary/timeline type to an object. Point zero
addresses its current fence, and nonzero points address the fence chain. Keep
this separate from the explicit binary/timeline objects used by experiments.
"""

from bisect import bisect_left

from .g17g_sync import (
    G17GSoftwareFence, G17GSubmissionFence, G17GSyncObject, G17GSyncPoint,
)


class G17GDRMSyncObject(G17GSyncObject):
    drm_syncobj = True

    def __init__(self):
        super().__init__(timeline=True)
        # Entries are sorted by their end point. A range with more than one
        # value represents consecutive, successfully completed submissions.
        self._points = []

    def validate_bind(self, value=0):
        if not 0 <= int(value) < 1 << 64:
            raise ValueError("DRM sync point is outside u64")

    def bind(self, fence, value=0):
        self.validate_bind(value)
        if not isinstance(fence, (G17GSoftwareFence, G17GSubmissionFence)):
            raise TypeError("DRM syncobj requires a completion fence")
        value = int(value)
        if not value:
            self._points.clear()
        elif self._binary is not None and not self._binary.fence.signaled():
            # A later timeline point includes all preceding unsignaled work.
            # Completed errors stay on their own point; they must not poison
            # an independently submitted later fence forever.
            fence = G17GSubmissionFence((self._binary.fence, fence),
                                         name="DRM timeline chain")
        point = G17GSyncPoint(value, fence)
        self._binary = point
        if value:
            # Unordered additions start a new sequence, as dma_fence_chain
            # does when the preceding sequence number is >= the new value.
            index = self._find(value)
            if index < len(self._points):
                first, last = self._points[index]
                del self._points[index:]
                if first < value:
                    self._points.append((first, G17GSyncPoint(value - 1, last.fence)))
            self._merge_completed_tail()
            self._points.append((value, point))
        return point

    def _find(self, value):
        return bisect_left(self._points, value, key=lambda item: item[1].value)

    def _merge_completed_tail(self):
        while len(self._points) >= 2:
            first, last = self._points[-1]
            prev_first, prev = self._points[-2]
            if first != prev.value + 1 or not (
                    last.signaled() and last.error is None and prev.signaled() and prev.error is None):
                break
            self._points[-2:] = [(prev_first, last)]

    def signal(self, value=0, error=None):
        return self.bind(G17GSoftwareFence(signaled=True, error=error), value)

    def reset(self):
        self._binary = None
        self._points.clear()

    def point(self, value=0):
        self.validate_bind(value)
        value = int(value)
        if not value:
            return self._binary
        index = self._find(value)
        if index == len(self._points):
            return None
        first, last = self._points[index]
        point = max(first, value)
        return last if point == last.value else G17GSyncPoint(point, last.fence)

    def signaled(self, value=0):
        point = self.point(value)
        return point is not None and point.signaled()

    def query(self, *, last_submitted=False):
        if last_submitted:
            return 0 if self._binary is None else self._binary.value
        for _first, last in reversed(self._points):
            if last.signaled():
                return last.value
        return 0
