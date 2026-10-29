# SPDX-License-Identifier: GPL-2.0-only
"""Special timestamp BO mappings in the T8142 firmware address space.

Firmware writes directly to the caller BO's physical backing. Host readback
copies those bytes unchanged; it never substitutes CPU time or shader output.
The private render completion namespace is reserved separately from caller BOs.
"""
import errno

from .g17g_boot import PAGE_SIZE, publish_pages
from .g17g_render import TIMESTAMP_APERTURE_BASE
from .g17g_uat import FLAGS_SHARED_UXN

TIMESTAMP_END = TIMESTAMP_APERTURE_BASE + 0x4000000
# Four words per logical render, whose namespace is 1..65535. Reserve virtual
# space only; the runtime allocates private physical pages as jobs need them.
TIMESTAMP_USER_BASE = TIMESTAMP_APERTURE_BASE + 0x200000


class G17GTimestampMappings:
    def __init__(self, adapter):
        self.adapter = adapter
        self.free_ranges = [(TIMESTAMP_USER_BASE, TIMESTAMP_END)]

    def bind(self, file, obj):
        for index, (start, end) in enumerate(self.free_ranges):
            if obj.size <= end - start:
                self.free_ranges[index:index + 1] = ([] if start + obj.size == end
                                                     else [(start + obj.size, end)])
                return dict(address=start, active=False, released=False)
        raise OSError(errno.ENOSPC, "G17G firmware timestamp aperture exhausted")

    @staticmethod
    def objects(commands):
        seen, objects = set(), []
        for command in commands:
            for _name, obj, _offset in command.timestamp_objects:
                if id(obj) not in seen:
                    seen.add(id(obj))
                    objects.append(obj)
        return tuple(objects)

    @staticmethod
    def compute_pointers(command):
        pointers = {name: obj.token["address"] + offset
                    for name, obj, offset in command.timestamp_objects
                    if not obj.token["released"]}
        if len(pointers) != len(command.timestamp_objects):
            raise ValueError("compute timestamp object was released")
        return pointers.get("compute_start", 0), pointers.get("compute_end", 0)

    @staticmethod
    def render_pointers(command):
        names = dict(vertex_start="tiling_user_timestamp_start",
                     vertex_end="tiling_user_timestamp_end",
                     fragment_start="fragment_user_timestamp_start",
                     fragment_end="fragment_user_timestamp_end")
        pointers = {}
        for name, obj, offset in command.timestamp_objects:
            if obj.token["released"]:
                raise ValueError("render timestamp object was released")
            pointers[names[name]] = obj.token["address"] + offset
        return pointers

    def materialize(self, objects):
        adapter, runtime = self.adapter, self.adapter.runtime
        uploaded, seen, changed = [], set(), False
        for obj in objects:
            token, bo = obj.token, obj.bo
            if token["released"]:
                raise ValueError("timestamp object was released")
            pa = adapter._allocate(bo)
            if id(bo) not in seen:
                seen.add(id(bo))
                body = bo.token["mapping"][:]
                if body != bo.token.get("uploaded_image"):
                    (adapter.upload_transport or adapter.iface.writemem)(pa, body)
                    publish_pages(adapter.u, range(pa, pa + bo.token["size"], PAGE_SIZE),
                                  coprocessor=False)
                    uploaded.append((bo.token, body))
            if token["active"]:
                continue
            # Validate all leaves before mutation. Record physical ownership
            # before the first fallible mapping or table-cache operation.
            for offset in range(0, obj.size, PAGE_SIZE):
                if runtime.uat.iotranslate_root(runtime.root, token["address"] + offset, PAGE_SIZE) != [(None, PAGE_SIZE)]:
                    raise RuntimeError("timestamp reservation overlaps an existing firmware mapping")
            token["active"] = True
            bo.token.setdefault("active_objects", []).append(obj)
            runtime.uat.iomap_at_root(runtime.root, token["address"], pa + obj.offset,
                                     obj.size, **FLAGS_SHARED_UXN)
            if not hasattr(runtime, "timestamp_pages"):
                runtime.timestamp_pages = {}
            for offset in range(0, obj.size, PAGE_SIZE):
                runtime.timestamp_pages[token["address"] + offset] = pa + obj.offset + offset
            changed = True
        if changed:
            runtime.flush_tables(0x40)
        for token, body in uploaded:
            token["uploaded_image"] = body

    def unbind(self, file, obj):
        token, runtime = obj.token, self.adapter.runtime
        if token["released"]:
            return
        if token["active"]:
            if self.adapter.device_lost or runtime.state not in ("new", "complete"):
                raise RuntimeError("cannot release GPU-reachable timestamp backing before clean retirement")
            runtime.uat.iounmap_root(runtime.root, token["address"], obj.size)
            runtime.flush_tables(0x40)
            if runtime.uat.iotranslate_root(runtime.root, token["address"], obj.size) != [(None, obj.size)]:
                raise RuntimeError("timestamp object still has a firmware mapping")
            for offset in range(0, obj.size, PAGE_SIZE):
                del runtime.timestamp_pages[token["address"] + offset]
            obj.bo.token["active_objects"].remove(obj)
            token["active"] = False
        ranges = sorted(self.free_ranges + [(token["address"], token["address"] + obj.size)])
        merged = []
        for start, end in ranges:
            if merged and start == merged[-1][1]:
                merged[-1] = merged[-1][0], end
            else:
                merged.append((start, end))
        self.free_ranges = merged
        token["released"] = True
