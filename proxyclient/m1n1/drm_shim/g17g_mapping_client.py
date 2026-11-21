# SPDX-License-Identifier: GPL-2.0-only
"""Use the existing UAT API for driver-owned roots without changing UAT.

A private context table lets the upstream context-based API address a root
which is not installed in a live device slot. This module contains no page
table walker, descriptor encoder, or overrides of UAT methods.
"""

import copy
from threading import RLock


class RootMappingClient:
    def __init__(self, uat):
        self._uat = uat
        self._views = {}
        self._lock = RLock()

    def __getattr__(self, name):
        return getattr(self._uat, name)

    def _view(self, root):
        if type(root) is not int or root <= 0 or root % self.PAGE_SIZE:
            raise ValueError("driver root must be a physical page")
        view = self._views.get(root)
        if view is None:
            view = copy.copy(self._uat)
            view.gpu_region = int(self.u.memalign(self.PAGE_SIZE, self.PAGE_SIZE))
            self.p.memset32(view.gpu_region, 0, self.PAGE_SIZE)
            view.initialized = True
            view.dirty_ranges = {}
            # These slots are private host scratch, never a device context.
            view.set_l0(0, 0, root)
            view.set_l0(0, 1, root)
            self._views[root] = view
        # invalidate_cache() replaces the dictionary on the original client.
        view.pt_cache = self._uat.pt_cache
        return view

    def iomap_at_root(self, root, address, physical, size, ctx=None, **flags):
        if size == 0:
            return
        with self._lock:
            view = self._view(root)
            view.iomap_at(0, address, physical, size, **flags)
            if ctx is not None and size:
                self._uat.dirty_ranges.setdefault(ctx, []).append((address, size))

    def iotranslate_root(self, root, address, size):
        if size == 0:
            return []
        with self._lock:
            return self._view(root).iotranslate(0, address, size)

    def iounmap_root(self, root, address, size, ctx=None):
        if type(size) is not int or size < 0:
            raise ValueError("invalid driver unmap size")
        if size == 0:
            return 0
        if address % self.PAGE_SIZE:
            raise ValueError("unaligned driver unmap")
        with self._lock:
            view = self._view(root)
            unmapped = 0
            for page in range(address, address + size, self.PAGE_SIZE):
                if view.iotranslate(0, page, self.PAGE_SIZE) == [(None, self.PAGE_SIZE)]:
                    continue
                # VALID is a normal keyword of the public iomap_at API.
                view.iomap_at(0, page, 0, self.PAGE_SIZE, VALID=0)
                unmapped += self.PAGE_SIZE
            if ctx is not None and unmapped:
                self._uat.dirty_ranges.setdefault(ctx, []).append((address, size))
            return unmapped

    def root_table_pages(self, root):
        with self._lock:
            pages = {root}
            def found(start, end, index, pte, level, sparse):
                pages.add(int(pte.offset()))
            self._view(root).foreach_table(0, found)
            return tuple(sorted(pages))

    def invalidate_root_walk_cache(self):
        # No private walk cache exists. Use the unchanged public cache API.
        self._uat.invalidate_cache()

    def release_root_view(self, root):
        with self._lock:
            view = self._views.pop(root, None)
            if view is not None:
                # This releases only the scratch context table, not the root.
                self._uat.pt_cache.pop(view.gpu_region, None)
                self._uat.dirty.discard(view.gpu_region)
                self.u.free(view.gpu_region)
