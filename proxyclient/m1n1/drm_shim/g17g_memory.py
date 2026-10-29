# SPDX-License-Identifier: GPL-2.0-only
"""Caller BO ownership and physical backing for the G17G UAPI adapter.

Bindings are logical until a serialized submission installs its UAT roots.
There is no capture, shader, experiment, global proxy, or implicit work here.
The DRM interposer supplies its actual shared backing fd for each DRM file.
"""

from dataclasses import dataclass
import mmap

from .g17g_boot import PAGE_SIZE, physical_page_runs, publish_pages
from .g17g_uapi import DRM_ASAHI_BIND_SINGLE_PAGE, DRM_ASAHI_BIND_WRITE


@dataclass(frozen=True)
class G17GPageBacking:
    pa: int
    writable: bool


def mapping_runs(pages):
    """Merge only matching DVA, physical and permission continuity."""
    physical_page_runs(item.pa for item in pages.values())
    runs = []
    for dva, item in sorted(pages.items()):
        if type(dva) is not int or not 0 < dva < (1 << 42) or dva % PAGE_SIZE:
            raise ValueError("invalid caller GPU page")
        if (runs and dva == runs[-1][0] + runs[-1][2]
                and item.pa == runs[-1][1] + runs[-1][2]
                and item.writable == runs[-1][3]):
            start, pa, size, writable = runs[-1]
            runs[-1] = (start, pa, size + PAGE_SIZE, writable)
        else:
            runs.append((dva, item.pa, PAGE_SIZE, item.writable))
    return tuple(runs)


class G17GMemoryAdapter:
    """Memory callbacks shared by the serialized hardware command adapters.

No command submission callback is supplied by this base class. An owner must
attach a real runtime before exposing submissions. Successful materialization
does not mean that a GPU context has been activated or a command executed.
"""

    def __init__(self, util, backing_fd):
        self.u, self.p, self.iface = util, util.proxy, util.iface
        self.backing_fd = backing_fd
        self.allocations = {}
        self.next_context = 1
        self.readback_transport = None
        self.upload_transport = None

    def create_vm(self, file, vm):
        # File-private logical ID, not a firmware hardware context number.
        context = self.next_context
        self.next_context += 1
        return context

    def create_bo(self, file, bo):
        mapping = mmap.mmap(self.backing_fd(file), bo.size, offset=bo.memfd_offset)
        return dict(mapping=mapping, pa=None, size=(bo.size + PAGE_SIZE - 1) & -PAGE_SIZE,
                    active_bindings=[])

    def destroy_bo(self, file, bo):
        token = bo.token
        if token["active_bindings"] or token.get("active_objects"):
            raise RuntimeError("cannot release backing still reachable from a UAT")
        if token["pa"] is not None:
            self.u.free(token["pa"])
            del self.allocations[token["pa"]]
            token["pa"] = None
        token["mapping"].close()

    def bind(self, file, vm, binding):
        return dict(active=None)

    def unbind(self, file, vm, binding):
        active = binding.token["active"]
        if active is not None:
            active.unmap_binding(binding)
            binding.bo.token["active_bindings"].remove(binding)
            binding.token["active"] = None

    def unbind_many(self, file, vm, bindings):
        owners = {}
        for binding in bindings:
            active = binding.token["active"]
            if active is not None:
                owners.setdefault(active, []).append(binding)
        for owner, owned in owners.items():
            owner.unmap_bindings(tuple(owned))
            for binding in owned:
                binding.bo.token["active_bindings"].remove(binding)
                binding.token["active"] = None

    def _allocate(self, bo):
        token = bo.token
        if token["pa"] is None:
            pa = int(self.u.memalign(PAGE_SIZE, token["size"]))
            token["pa"] = pa
            token["uploaded_image"] = None
            # Record ownership before the first fallible proxy operation.
            self.allocations[pa] = bo
            self.p.memset32(pa, 0, token["size"])
        return token["pa"]

    def materialize(self, vm, *, reserved=(), allow_owner=None):
        """Upload BOs and return owned page mappings; do not touch GPU PTEs."""
        reserved = set(reserved)
        for binding in vm.bindings:
            if reserved.intersection(range(binding.addr, binding.end, PAGE_SIZE)):
                raise ValueError("caller binding overlaps driver-owned GPU pages")
            if binding.token["active"] is not None and binding.token["active"] is not allow_owner:
                raise RuntimeError("VM already has active caller mappings")
        pages, seen, published, updated = {}, set(), set(), []
        for binding in vm.bindings:
            bo = binding.bo
            pa = self._allocate(bo)
            if id(bo) not in seen:
                seen.add(id(bo))
                body = bo.token["mapping"][:]
                if body != bo.token.get("uploaded_image"):
                    (self.upload_transport or self.iface.writemem)(pa, body)
                    published.update(range(pa, pa + bo.token["size"], PAGE_SIZE))
                    updated.append((bo.token, body))
            for offset in range(0, binding.size, PAGE_SIZE):
                bo_offset = binding.bo_offset + (
                    0 if binding.flags & DRM_ASAHI_BIND_SINGLE_PAGE else offset)
                pages[binding.addr + offset] = G17GPageBacking(
                    pa + bo_offset, bool(binding.flags & DRM_ASAHI_BIND_WRITE))
        mapping_runs(pages)  # Validate all caller mappings before PTE installation.
        publish_pages(self.u, published, coprocessor=False)
        # Cache only after successful publication. GPU readback below patches
        # these bytes too, so unchanged caller BOs need no redundant upload.
        for token, body in updated:
            token["uploaded_image"] = body
        self.last_upload = dict(bos=len(updated), bytes=sum(len(body) for _token, body in updated))
        return pages

    def activate(self, vm, owner, *, allow_existing=False):
        """Record successful PTE installation, so GEM close cannot free it."""
        for binding in vm.bindings:
            if binding.token["active"] is not None and not (
                    allow_existing and binding.token["active"] is owner):
                raise RuntimeError("caller binding already installed")
        for binding in vm.bindings:
            if binding.token["active"] is owner:
                continue
            binding.token["active"] = owner
            binding.bo.token["active_bindings"].append(binding)

    def pull(self, vm, *, objects=()):
        """Copy all writable mappings back after real completion, once per BO.

        Attachments are not exhaustive: shader writes can be indirect. Partial
        bindings only copy their owned BO slice; SINGLE_PAGE copies one page.
        """
        intervals = {}
        for obj in objects:
            record = intervals.setdefault(id(obj.bo), (obj.bo, []))
            record[1].append((obj.offset, obj.offset + obj.size))
        for binding in vm.bindings:
            if not binding.flags & DRM_ASAHI_BIND_WRITE:
                continue
            size = PAGE_SIZE if binding.flags & DRM_ASAHI_BIND_SINGLE_PAGE else binding.size
            record = intervals.setdefault(id(binding.bo), (binding.bo, []))
            record[1].append((binding.bo_offset, binding.bo_offset + size))
        slices = []
        for bo, spans in intervals.values():
            merged = []
            for start, end in sorted(spans):
                if merged and start <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
                else:
                    merged.append((start, end))
            if bo.token["pa"] is None:
                raise RuntimeError("cannot read back a BO without physical backing")
            for start, end in merged:
                pa = bo.token["pa"] + start
                slices.append((pa, end - start, bo, start))
        # Adjacent *owned* physical slices can share one transport read even
        # when they belong to different GEMs. Never bridge an unbound gap or
        # infer physical continuity from neighboring GPU virtual addresses.
        runs = []
        for pa, size, bo, start in sorted(slices, key=lambda item: item[0]):
            if runs and pa < runs[-1][0] + runs[-1][1]:
                raise RuntimeError("distinct caller readback slices overlap physically")
            if runs and pa == runs[-1][0] + runs[-1][1]:
                runs[-1][1] += size
                runs[-1][2].append((pa, size, bo, start))
            else:
                runs.append([pa, size, [(pa, size, bo, start)]])
        copied = calls = 0
        for pa, size, destinations in runs:
            self.p.dc_ivac(pa, size)
            self.u.inst("dsb sy")
            if self.readback_transport is None:
                data = bytes(self.iface.readmem(pa, size))
                calls += 1
            else:
                # The optional lossless transport scans every owned byte and
                # omits only proven-zero lines from the wire representation.
                fragments = []
                for offset in range(0, size, 0x100000):
                    length = min(0x100000, size - offset)
                    fragment = bytes(self.readback_transport(pa + offset, length))
                    if len(fragment) != length:
                        raise RuntimeError("short GPU BO readback")
                    fragments.append(fragment)
                    calls += 1
                data = b"".join(fragments)
            if len(data) != size:
                raise RuntimeError("short GPU BO readback")
            for address, length, bo, start in destinations:
                end = start + length
                body = data[address - pa:address - pa + length]
                bo.token["mapping"][start:end] = body
                if bo.token.get("uploaded_image") is not None:
                    known = bytearray(bo.token["uploaded_image"])
                    known[start:end] = body
                    bo.token["uploaded_image"] = bytes(known)
                copied += length
        self.last_readback = dict(bytes=copied, transport_reads=calls)
        return copied
