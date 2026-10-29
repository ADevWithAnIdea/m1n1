# SPDX-License-Identifier: GPL-2.0-only
"""Placement of source-described private objects in a UAPI VM's kernel arena.

The source recipes use stable object addresses. These are allocation labels,
not additional reservations in userspace. Only declared private pointer fields
are relocated; caller command streams, program pointers and BO bytes are opaque.
"""
import struct

PAGE = 0x4000
MASK = (1 << 42) - 1
RESOURCE_BASE = 0x1000000000


class G17GVMLayout:
    FIXED_SUPPORT = 0x10000000000
    SHIFTED_FIELDS = {0xfffffc20015f0000: 7, 0xfffffc20015f0020: 7}

    def __init__(self, start, end):
        if (start | end) & (PAGE - 1) or end - start < 0x20000000:
            raise ValueError('invalid VM kernel arena')
        self.start, self.end = start, end
        self.private, self.scene_pages = set(), set()
        self.fields, self.block_pages, self.primary = {}, {}, {}

    def reserve(self, pages):
        # The USC execution aperture is fixed independently of VM placement.
        pages = set(pages) - {self.FIXED_SUPPORT}
        if any(page & (PAGE-1) for page in pages):
            raise ValueError('unaligned private allocation label')
        if (len(self.private | pages) * PAGE) > self.end-self.start:
            raise MemoryError('VM kernel arena exhausted')
        self.private.update(pages)

    def address(self, value):
        address = value & MASK
        if address & -PAGE not in self.private:
            return value
        # TA and FR must use the same scene offset, even when multiple
        # numerical aliases happen to name the same physical page.
        if address & -PAGE in self.scene_pages:
            address -= RESOURCE_BASE
        return (value & ~MASK) | (1 << 42) | address

    def _qword(self, data, offset, *, relative=False):
        value = struct.unpack_from('<Q', data, offset)[0]
        if relative:
            if not value & (1 << 39) and (RESOURCE_BASE+(value & MASK)) & -PAGE in self.private:
                value |= 1 << 39
        else:
            value = self.address(value)
        struct.pack_into('<Q', data, offset, value)

    def descriptor(self, body):
        data = bytearray(body)
        selector, = struct.unpack_from('<I', body)
        if selector == 3 and len(body) >= 0xfe0:
            from m1n1.drm_shim import g17g_compute as compute
            registers = {0x1a510, 0x1a4d0, 0x1a4d8, 0x1a4e0, 0x1a4e8,
                         0x14070, 0x10229, 0x140a8, 0x10099, 0x10091,
                         0x0a5c1, 0x0a5c9}
            for start, count in ((compute.COMPUTE_REGISTER_START, 40),
                                 (compute.COMPUTE_SECONDARY_REGISTER_START, 4)):
                for offset in range(start, start + count * 12, 12):
                    if struct.unpack_from('<I', data, offset)[0] in registers:
                        self._qword(data, offset + 4)
            # Register-list links use firmware context zero's global alias,
            # independently of the submitting VM's GPU payload mappings.
            for offset in (0xed8,):
                self._qword(data, offset)
        elif selector == 0 and len(body) == 0x9c0:
            relative = {0x1c039, 0x1c9c8, 0x1c0a1, 0x1c031, 0x1c9c0,
                        0x1c079, 0x1c9d8, 0x1ca30, 0x16c39, 0x1c910}
            for start, count in ((0x60, 73), (0x3cc, 9)):
                for offset in range(start, start + count * 12, 12):
                    number, = struct.unpack_from('<I', data, offset)
                    if number in relative or number == 0x14318:
                        self._qword(data, offset + 4, relative=number in relative)
            for offset in (0x780,):
                self._qword(data, offset)
        elif selector == 1 and len(body) == 0x2240:
            absolute = {0x16098, 0x16429, 0x16060, 0x14080, 0x16461, 0x16090}
            for offset in range(0xa0, 0xa0 + 89 * 12, 12):
                number, = struct.unpack_from('<I', data, offset)
                if number in absolute or number == 0x1ca28:
                    self._qword(data, offset + 4, relative=number == 0x1ca28)
            for offset in (0x40,):
                self._qword(data, offset)
        return bytes(data)

    def global_fields(self, address, body):
        """Register fields from explicit host-built allocator object schemas."""
        if len(body) < PAGE:
            return
        from m1n1.drm_shim import g17g_postcontrol as post
        if address in (0xfffffc20c08c0000, 0xfffffc20c08c8000,
                       0xfffffc20c08d0000, 0xfffffc20c08d8000):
            words = struct.unpack_from('<6I', body)
            if words in ((0x11, 0, 0x22, 0, 0x33, 0), (0x12, 0, 0x23, 0, 0x34, 0)):
                self.block_pages[address] = 8
            elif words in (tuple(range(0x11, 0x17)), tuple(range(0x12, 0x18))):
                self.block_pages[address] = 4
        # Opcode20 buffer base is split at +14/+18, forming an unaligned
        # qword. Its high flags start at +1c and are outside that pointer.
        if (struct.unpack_from('<Q', body, 0x18)[0] >> 48 == 8 and
                struct.unpack_from('<Q', body, 0x30)[0] & MASK in self.private):
            for offset in (0x14, 0x30):
                self.fields[address + offset] = False
        # The pool-B array holds an absolute status pointer and a resource
        # base-relative metadata pointer in every 0x80-byte record.
        if address in (post.TARGET_RECORD_ARRAY_PAGE, 0xfffffc20c08c0000):
            first, = struct.unpack_from('<Q', body)
            if RESOURCE_BASE <= first < RESOURCE_BASE + 0x4000000:
                for index in range(post.TARGET_RECORD_ARRAY_COUNT):
                    self.fields[address + index * 0x80] = False
                    self.fields[address + index * 0x80 + 0x28] = True
        if address in (0xfffffc20c08e8000, 0xfffffc20c08f0000):
            pointer, = struct.unpack_from('<Q', body, 0x28)
            if RESOURCE_BASE <= pointer < RESOURCE_BASE + 0x4000000:
                self.fields[address + 0x28] = False
                self.fields[address + 0x84] = True

    def global_bytes(self, address, body):
        self.global_fields(address, body)
        data = bytearray(body)
        for field, relative in self.fields.items():
            offset = field - address
            if 0 <= offset <= len(data) - 8:
                self._qword(data, offset, relative=relative)
        for field, shift in self.SHIFTED_FIELDS.items():
            offset = field - address
            if 0 <= offset <= len(data) - 8:
                value, = struct.unpack_from('<Q', data, offset)
                if value:
                    struct.pack_into('<Q', data, offset, self.address(value << shift) >> shift)
        for page, width in self.block_pages.items():
            fmt = '<I' if width == 4 else '<Q'
            for offset in range(max(0, page-address), min(len(data), page+PAGE-address)-width+1, width):
                value = struct.unpack_from(fmt, data, offset)[0]
                if not value & (1 << 24) and (RESOURCE_BASE+value*0x8000) & -PAGE in self.private:
                    struct.pack_into(fmt, data, offset, value | (1 << 24))
        offset = 0xfffffc20015e8000-address
        if 0 <= offset <= len(data)-8:
            value = struct.unpack_from('<Q', data, offset)[0]
            family = RESOURCE_BASE + ((value & 0xffffffff) << 4)
            if family & -PAGE in self.private:
                struct.pack_into('<Q', data, offset, value | (1 << 63))
        return bytes(data)

    @staticmethod
    def private_pointer_page(address):
        from m1n1.drm_shim import g17g_backend as backend
        lists = (0x7200000000, backend.COMPUTE_PREDECESSOR_PARTIAL_ADDRESS_LIST_BASE)
        tables = (backend.COMPUTE_CLIENT_STATE,
                  backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_TABLE)
        return address in tables or any(base <= address < base + 0x400000 for base in lists)

    def private_bytes(self, address, body):
        if len(body) == 0x1000 and struct.unpack_from('<I', body)[0] == 3:
            return body
        if self.private_pointer_page(address):
            data = bytearray(body)
            # Both schemas have qword address entries; zero padding is inert.
            for offset in range(0, len(data) - 7, 8):
                self._qword(data, offset)
            return bytes(data)
        return body

    def describe(self, graphs):
        """Collect owned fields before rewriting any publication bytes."""
        for graph in graphs:
            self.reserve(graph.get('private_dvas', ()))
            params = graph.get('parameters')
            if params is not None and params.buffers is not None:
                self.scene_pages.update(params.buffers.pages)
            for field in ('source_global_pages', 'fresh_global_pages', 'late_global_pages', 'service_input_pages'):
                for address, body in graph.get(field, {}).items():
                    self.global_fields(address, body)
            for name, body in graph.get('firmware_objects', {}).items():
                self.global_fields(graph['addresses'][name], body)

    def map_private(self, runtime, context, pages=None):
        """Retain source labels on the host; expose only arena and TTBR1 VAs."""
        from . import g17g_uat
        known = context.setdefault('private_placements', {})
        candidates = self.private & set(context['pages']) if pages is None else self.private & set(pages)
        changed = {label for label in candidates if known.get(label) != context['pages'][label]}
        for label in sorted(changed):
            self.primary.setdefault(label, self.start+len(self.primary)*PAGE)
        primary_addresses = set(self.primary.values())
        for label in sorted(changed):
            pa = context['pages'][label]
            primary = self.primary.setdefault(label, self.start+len(self.primary)*PAGE)
            if primary+PAGE > self.end:
                raise MemoryError('VM kernel arena exhausted')
            if (label in context['table_witnesses'] and label not in primary_addresses
                    and label not in context['caller_mappings']):
                runtime.uat.iounmap_root(context['root0'], label, PAGE)
            runtime.uat.iomap_at_root(context['root0'], primary, pa, PAGE, **g17g_uat.FLAGS_CONTEXT0_UXN)
            aliases = {label}
            if label >= RESOURCE_BASE:
                aliases.add(label-RESOURCE_BASE)
            for alias in aliases:
                runtime.uat.iomap_at_root(context['root1'], alias, pa, PAGE, **g17g_uat.FLAGS_CONTEXT0_UXN)
            context.setdefault('high_table_witnesses', set()).update(aliases)
            context['table_witnesses'].add(primary)
            known[label] = pa
        # A source recipe may numerically overlap an already assigned primary
        # address or a caller VA. Restore those owners after staging new backing.
        for label, primary in self.primary.items():
            if primary in changed and label in known:
                runtime.uat.iomap_at_root(context['root0'], primary, known[label], PAGE,
                                         **g17g_uat.FLAGS_CONTEXT0_UXN)
        for label in changed & set(context['caller_mappings']):
            page = context['caller_mappings'][label]
            runtime.uat.iomap_at_root(context['root0'],label,page.pa,PAGE,
                **(g17g_uat.FLAGS_CONTEXT0_UXN if page.writable else g17g_uat.FLAGS_CONTEXT0_EXECUTABLE))
        context.setdefault('private_labels', set()).update(candidates)
        return changed

    def relocate_context(self, runtime, context, *, pages=None):
        candidates = self.private & set(context['pages']) if pages is None else self.private & set(pages)
        known = context.setdefault('private_placements', {})
        dirty = []
        for label in sorted(candidates):
            pa = context['pages'][label]
            if known.get(label) == pa or not self.private_pointer_page(label):
                continue
            body = runtime.read(pa, PAGE)
            rewritten = self.private_bytes(label, body)
            if rewritten != body:
                runtime.iface.writemem(pa, rewritten)
                dirty.append(pa)
        runtime.publish(dirty)
        self.map_private(runtime, context, candidates)
        runtime.flush_tables(context.get('context_id', 1))

    def transform_graph(self, graph, context_id):
        from .g17g_context import descriptor_context
        def descriptor(body):
            return descriptor_context(self.descriptor(body), context_id)
        for field in ('firmware_objects', 'firmware_pages', 'items'):
            if field not in graph:
                continue
            graph[field] = dict(graph[field])
            for name, body in graph[field].items():
                if name not in ('descriptor', 'tiling_descriptor', 'fragment_descriptor') or not body:
                    continue
                size = {'descriptor': 0x1000, 'tiling_descriptor': 0x9c0, 'fragment_descriptor': 0x2240}[name]
                graph[field][name] = descriptor(body[:size])+body[size:]
        for field in ('high', 'low'):
            if field not in graph:
                continue
            graph[field] = tuple((address, descriptor(body) if len(body) in (0x9c0, 0x1000, 0x2240)
                and struct.unpack_from('<I', body)[0] in (0, 1, 3) else
                self.private_bytes(address, body) if field == 'low' else body)
                for address, body in graph[field])
        if 'context1_writes' in graph:
            graph['context1_writes'] = dict(graph['context1_writes'])
            from . import g17g_backend as backend
            for address, body in graph['context1_writes'].items():
                if address == backend.COMPUTE_DESCRIPTOR_LOW and body and struct.unpack_from('<I', body)[0] == 3:
                    graph['context1_writes'][address] = descriptor(body[:0x1000])+body[0x1000:]
                else:
                    graph['context1_writes'][address] = self.private_bytes(address, body)
        for field in ('work_lifecycle_qwords', 'lifecycle_qwords'):
            if field in graph:
                graph['source_'+field] = graph[field]
                graph[field] = {page: tuple((offset, *(struct.unpack('<Q', self.global_bytes(
                    page+offset, struct.pack('<Q', value)))[0] for value in (before, after)))
                    for offset, before, after in rows) for page, rows in graph[field].items()}
