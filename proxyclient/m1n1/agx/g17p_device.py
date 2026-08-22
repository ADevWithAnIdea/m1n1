# SPDX-License-Identifier: MIT
"""Bring a T8140/G17P accelerator up, as a backend rather than an experiment.

Everything here is established on hardware and already exercised by
`experiments/agx_g17p_coldboot.py`; this module exists because that script is not
callable. A shim front end needs an object it can construct and ask for an address
space, not a thousand-line script with fifty options. The steps are documented in
`docs/t8140-g17p-firmware-abi-spec.md`.

What this covers is the initialisation half, up to and including handing each
firmware instance its descriptor. It deliberately stops there. Firmware on a
host-brought-up machine accepts the descriptor and then declines its start
notification, so nothing past that point can be exercised yet, and this module does
not pretend otherwise: `start_service` performs the documented notification and
reports whether the ring was serviced rather than assuming it.

The address-space and object parts are usable now regardless of that blocker, which
is why they are separated out.
"""

import struct

from ..malloc import Heap
from ..hw.uat import UAT, MemoryAttr
from . import g17p
from . import g17p_initdata as build

PAGE = 0x4000


class AbsentHandoff:
    """Stand-in for the translation-table handoff, which this part does not use.

    The handoff exists to arbitrate two agents editing one set of tables, and its
    lock only completes when firmware publishes its half. On this part firmware
    never does, so a host that waits for it hangs. The host side of the region is
    still written, by :meth:`G17PDevice.write_handoff`, because a normally started
    platform has those fields set.
    """

    def __init__(self):
        self.initialized = True

    def initialize(self):
        pass

    def lock(self):
        class _Null:
            def __enter__(self_inner):
                return None

            def __exit__(self_inner, *exc):
                return False

        return _Null()

    def prepare_cache_flush(self, addr, size):
        return 0

    def complete_cache_flush(self, slot):
        pass


class G17PAddressSpace:
    """An address space the host owns, and the objects placed in it.

    This is the piece a front end needs first and the piece that does not depend on
    the unresolved start-notification problem. Allocation is bump-pointer because
    firmware cares about the relations between objects, several of which are fixed
    offsets rather than free choices, and a general allocator would obscure them.
    """

    def __init__(self, u, context, base_va):
        self.u = u
        self.iface = u.iface
        self.p = u.proxy
        self.context = context
        self.va = base_va
        self.objects = []
        self.mirror_space = None

        self.uat = UAT(self.iface, u)
        self.uat.allocator = Heap(base_va + 0x80000000,
                                  base_va + 0x81000000, PAGE)

    def use_absent_handoff(self):
        self.uat.handoff = AbsentHandoff()

    def adopt_live_tables(self):
        """Take the translation roots a running firmware is already using.

        A fresh process builds itself a new root table, so nothing a previous process mapped
        resolves through it and the first read of live firmware state fails as unmapped. The roots
        in use are in the hardware context table in the gpu-region, two 64-bit words per context,
        so they can be read back rather than replaced.

        Returns the pair adopted, or None when the context's entry is empty, which means no
        firmware has been started with these tables.
        """
        from ..hw.uat import TTBR

        base = self.uat.gpu_region + self.context * 16
        low = TTBR(self.uat.p.read64(base))
        high = TTBR(self.uat.p.read64(base + 8))
        if not low.VALID:
            return None
        self.uat.ttbr0_base = low.BADDR << 1
        if high.VALID:
            self.uat.ttbr1_base = high.BADDR << 1
        # Mark the tables as already initialised. UAT.init() clears the kernel page tables, which
        # is right when building a world and destroys one that already exists: it is what unmapped
        # firmware's own pages the moment an attached process allocated anything.
        self.uat.initialized = True
        self.uat.invalidate_cache()
        self.uat.invalidate_root_walk_cache()
        print("  adopted the live translation roots: ttbr0 %#x, ttbr1 %#x"
              % (self.uat.ttbr0_base, self.uat.ttbr1_base))
        return (self.uat.ttbr0_base, self.uat.ttbr1_base)

    def clone_for_context(self, context, base_va=None):
        """Clone this live low-half page-table tree into an independent context."""
        context = int(context)
        if context == self.context:
            raise ValueError("a cloned address space needs a distinct context id")
        clone = type(self)(
            self.u, context, self.va if base_va is None else int(base_va))
        clone.use_absent_handoff()
        clone.uat.initialized = True
        clone.uat.ttbr1_base = self.uat.ttbr1_base

        def clone_table(source, level):
            page = self.uat.PAGE_SIZE
            self.p.dc_civac(source, page)
            data = bytearray(self.iface.readmem(source, page))
            _offset, count, pte_type = self.uat.LEVELS[level]
            for index in range(count):
                offset = index * 8
                pte = pte_type(struct.unpack_from("<Q", data, offset)[0])
                if (not pte.valid() or pte.block()
                        or level + 1 >= len(self.uat.LEVELS)):
                    continue
                child = clone_table(pte.offset(), level + 1)
                pte.set_offset(child)
                struct.pack_into("<Q", data, offset, int(pte))
            destination = self.u.memalign(page, page)
            self.iface.writemem(destination, data)
            self.p.dc_civac(destination, page)
            return destination

        clone.uat.ttbr0_base = clone_table(self.uat.ttbr0_base, 1)
        clone.uat.set_l0(context, 0, clone.uat.ttbr0_base, context)
        clone.uat.set_l0(context, 1, clone.uat.ttbr1_base, context)
        clone.uat.flush_dirty()
        clone.uat.invalidate_cache()
        self.u.inst("dsb sy")
        self.u.inst("tlbi vmalle1os")
        self.u.inst("dsb sy")
        print("  cloned context %d low root %#x -> context %d root %#x" %
              (self.context, self.uat.ttbr0_base,
               context, clone.uat.ttbr0_base), flush=True)
        return clone

    def bind(self, bind_all=True):
        """Bind the translation context, and optionally every context.

        Which context each firmware instance walks with is not established, so
        binding all of them removes the question from the result.
        """
        self.uat.bind_context(self.context, self.uat.ttbr0_base)
        if bind_all:
            for ctx in range(1, self.uat.NUM_CONTEXTS):
                if ctx == self.context:
                    continue
                self.uat.set_l0(ctx, 0, self.uat.ttbr0_base, ctx)
                self.uat.set_l0(ctx, 1, self.uat.ttbr1_base, ctx)
        self.uat.flush_dirty()
        self.uat.invalidate_cache()

    def alloc(self, size, name, align=None):
        """Place one object and map it. Returns (va, pa)."""
        size = (size + PAGE - 1) & ~(PAGE - 1)
        if align:
            self.va = (self.va + align - 1) & ~(align - 1)
        pa = self.u.memalign(PAGE, size)
        self.p.memset32(pa, 0, size)
        self.p.dc_civac(pa, size)
        va = self.va
        self.uat.iomap_at(self.context, va, pa, size,
                          AttrIndex=MemoryAttr.Shared, AP=1)
        if self.mirror_space is not None:
            self.mirror_space.uat.iomap_at(
                self.mirror_space.context, va, pa, size,
                AttrIndex=MemoryAttr.Shared, AP=1)
        self.va += size
        self.objects.append({"name": name, "va": va, "pa": pa, "size": size})
        return va, pa

    def alloc_at(self, va, size, name, **flags):
        """Map a fresh object at an explicit device address.

        Render-context layouts can place an object inside a 16 KiB page. Allocate
        and map the complete page span while returning the logical object address
        and its corresponding physical offset.
        """
        va = int(va)
        size = int(size)
        page_va = va & ~(PAGE - 1)
        page_offset = va - page_va
        map_size = (page_offset + size + PAGE - 1) & ~(PAGE - 1)
        map_end = page_va + map_size
        for obj in self.objects:
            obj_page = int(obj.get("map_va", obj["va"])) & ~(PAGE - 1)
            obj_size = int(obj.get("map_size", obj["size"]))
            if page_va < obj_page + obj_size and obj_page < map_end:
                raise RuntimeError(
                    "%s at %#x overlaps %s at %#x"
                    % (name, va, obj["name"], obj["va"])
                )

        page_pa = self.u.memalign(PAGE, map_size)
        self.p.memset32(page_pa, 0, map_size)
        self.p.dc_civac(page_pa, map_size)
        map_flags = {
            "AttrIndex": MemoryAttr.Shared,
            "AP": 2,
            "nG": 1,
        }
        map_flags.update(flags)
        self.uat.iomap_at(
            self.context, page_va, page_pa, map_size, **map_flags
        )
        if self.mirror_space is not None:
            self.mirror_space.uat.iomap_at(
                self.mirror_space.context, page_va, page_pa, map_size,
                **map_flags
            )
        pa = page_pa + page_offset
        self.objects.append({
            "name": name,
            "va": va,
            "pa": pa,
            "size": size,
            "map_va": page_va,
            "map_pa": page_pa,
            "map_size": map_size,
            "flags": map_flags,
        })
        return va, pa

    def map_existing_at(self, va, pa, size, name, single_page=False, **flags):
        """Map existing physical BO backing at a caller-selected GPU VA."""
        va = int(va)
        pa = int(pa)
        size = int(size)
        if not size or (va | pa | size) & (PAGE - 1):
            raise ValueError(
                "existing mappings must be nonempty and page aligned")
        end = va + size
        for obj in self.objects:
            obj_va = int(obj.get("map_va", obj["va"])) & ~(PAGE - 1)
            obj_size = int(obj.get("map_size", obj["size"]))
            if va < obj_va + obj_size and obj_va < end:
                raise RuntimeError(
                    "%s at %#x overlaps %s at %#x" %
                    (name, va, obj["name"], obj["va"]))

        map_flags = {
            "AttrIndex": MemoryAttr.Shared,
            "AP": 2,
            "nG": 1,
            "UXN": 1,
            "OS": 1,
        }
        map_flags.update(flags)

        def map_into(space):
            if single_page:
                for offset in range(0, size, PAGE):
                    space.uat.iomap_at(
                        space.context, va + offset, pa, PAGE, **map_flags)
            else:
                space.uat.iomap_at(
                    space.context, va, pa, size, **map_flags)

        map_into(self)
        if self.mirror_space is not None:
            map_into(self.mirror_space)
        mapping = {
            "name": name,
            "va": va,
            "pa": pa,
            "size": size,
            "map_va": va,
            "map_pa": pa,
            "map_size": size,
            "single_page": bool(single_page),
            "flags": map_flags,
        }
        self.objects.append(mapping)
        return mapping

    def unmap(self, mapping):
        """Remove one owned mapping and make its DVA unavailable to hardware."""
        if mapping not in self.objects:
            return False

        map_va = int(mapping.get("map_va", mapping["va"])) & ~(PAGE - 1)
        map_pa = int(mapping.get("map_pa", mapping["pa"])) & ~(PAGE - 1)
        map_size = int(mapping.get("map_size", mapping["size"]))
        single_page = bool(mapping.get("single_page", False))

        def verify_and_unmap(space):
            translated = space.uat.iotranslate(
                space.context, map_va, map_size)
            expected = map_pa
            covered = 0
            for pa, length in translated:
                expected = map_pa if single_page else map_pa + covered
                if pa != expected:
                    raise RuntimeError(
                        "%s at %#x no longer owns mapping %#x -> %#x" % (
                            mapping["name"], mapping["va"],
                            map_va + covered, pa if pa is not None else 0))
                covered += length
            if covered != map_size:
                raise RuntimeError(
                    "%s mapping covers %#x bytes, expected %#x" % (
                        mapping["name"], covered, map_size))
            space.uat.iounmap(space.context, map_va, map_size)

        verify_and_unmap(self)
        if self.mirror_space is not None:
            verify_and_unmap(self.mirror_space)

        self.uat.flush_dirty()
        self.uat.invalidate_cache()
        if self.mirror_space is not None:
            self.mirror_space.uat.flush_dirty()
            self.mirror_space.uat.invalidate_cache()
        contexts = {self.context}
        if self.mirror_space is not None:
            contexts.add(self.mirror_space.context)
        for context in contexts:
            self.u.inst("tlbi aside1os, x0", context << 48)
        # Complete every invalidation before the caller can recycle this DVA.
        self.u.inst("dsb sy")
        self.objects.remove(mapping)
        return True

    def write(self, pa, data):
        self.iface.writemem(pa, data)
        self.p.dc_civac(pa, len(data))

    def read(self, pa, size):
        # A BO may have been written by the GPU since the host last touched it.
        # Invalidate, without cleaning, so a stale CPU line cannot overwrite the
        # device result while drm-shim pulls an attachment back to its memfd.
        # Bound each debug-USB response as well: an interrupted multi-megabyte
        # MEMREAD keeps streaming after its host process exits and poisons the
        # next proxy connection with the orphaned payload.
        chunks = []
        for offset in range(0, size, PAGE):
            length = min(PAGE, size - offset)
            self.p.dc_ivac(pa + offset, length)
            chunks.append(bytes(self.iface.readmem(pa + offset, length)))
        return b"".join(chunks)

    def map_register_windows(self):
        """Map every window the hardware-data table names, as device memory.

        Firmware reaches its own registers through that table and has no fixed
        address to fall back on, so the windows must be both mapped and declared.
        Doing only one of the two is what produced this project's early faults. Two
        windows are not granule aligned and share an offset within their page, so
        mapping the containing page places both sides correctly.
        """
        entries = {}
        for slot, phys, device_va, size, unk_18, flag in g17p.REGISTER_WINDOWS:
            page_phys = phys & ~(PAGE - 1)
            page_va = device_va & ~(PAGE - 1)
            span = (((device_va + size) - page_va) + PAGE - 1) & ~(PAGE - 1)
            self.uat.iomap_at(self.context, page_va, page_phys, span,
                              AttrIndex=MemoryAttr.Device, AP=1)
            entries[slot] = {"phys": phys, "device_va": device_va, "size": size,
                             "flag": flag, "unk_18": unk_18}
        self.uat.flush_dirty()
        return entries

    def flush(self):
        self.uat.flush_dirty()
        self.uat.invalidate_cache()
        if self.mirror_space is not None:
            self.mirror_space.uat.flush_dirty()
            self.mirror_space.uat.invalidate_cache()


class G17PInstanceObjects:
    """The descriptor objects for one firmware instance.

    The two instances are not symmetric. The second is control-only: no work
    channels, no address array, no region triple addresses, a different root kind,
    no second status block, and a different opening control opcode. It also carries
    one pointer the first does not, into the first instance's third auxiliary view.
    """

    def __init__(self, space, index, name, shared):
        self.space = space
        self.index = index
        self.name = name
        self.shared = shared
        self.secondary = index != 0

        self.main_va, self.main_pa = space.alloc(
            build.MAIN_SIZE, "%s_main" % name)
        self.status_a_va, self.status_a_pa = space.alloc(
            PAGE, "%s_status_a" % name)
        if not self.secondary:
            self.status_b_va, self.status_b_pa = space.alloc(
                PAGE, "%s_status_b" % name)
        else:
            self.status_b_va, self.status_b_pa = 0, None

        self.state_va, self.state_pa = space.alloc(
            g17p.CHANNEL_STATE_STRIDE * build.CHANNEL_TABLE_ENTRIES,
            "%s_channel_state" % name)
        work_span = g17p.RING_STRIDE * g17p.CHANNEL_TABLE_WORK_COUNT
        others = build.CHANNEL_TABLE_ENTRIES - g17p.CHANNEL_TABLE_WORK_COUNT
        self.ring_va, self.ring_pa = space.alloc(
            work_span + others * g17p.SERVICE_RING_SIZE,
            "%s_channel_rings" % name)
        self.work_span = work_span

    def ring_for(self, index):
        """Where one channel's ring lives.

        Device control is the exception: its ring is embedded in the main object at
        a fixed offset, and the opcode the builder places there is that ring's first
        entry rather than a scalar field.
        """
        if index == g17p.CHANNEL_TABLE_WORK_COUNT:
            return self.main_va + build.MAIN_INTERVAL
        if index < g17p.CHANNEL_TABLE_WORK_COUNT:
            return self.ring_va + index * g17p.RING_STRIDE
        return (self.ring_va + self.work_span
                + (index - g17p.CHANNEL_TABLE_WORK_COUNT)
                * g17p.SERVICE_RING_SIZE)

    def channel_table(self):
        """The seventeen entries, with the trailing two left as hardware has them."""
        table = []
        for index in range(build.CHANNEL_TABLE_ENTRIES):
            block = self.state_va + index * g17p.CHANNEL_STATE_STRIDE
            states = [block + i * g17p.CHANNEL_ENTRY_STATE_SPACING
                      for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT)]
            ring = self.ring_for(index)
            if index == g17p.CHANNEL_PARTIAL_ENTRY:
                states, ring = [states[0], 0, 0], 0
            elif index > g17p.CHANNEL_PARTIAL_ENTRY:
                states, ring = [0, 0, 0], 0
            table.append((states, ring))
        return table

    @property
    def control_ring_pa(self):
        return self.main_pa + build.MAIN_INTERVAL

    @property
    def control_producer_pa(self):
        return (self.state_pa
                + g17p.CHANNEL_TABLE_WORK_COUNT * g17p.CHANNEL_STATE_STRIDE
                + g17p.CHANNEL_STATE_PRODUCER * g17p.CHANNEL_ENTRY_STATE_SPACING)

    def build(self, root_va, root_pa, extra_addr=0):
        """Write this instance's main object, status blocks and root."""
        space = self.space
        channels = self.channel_table()

        if self.secondary:
            main = build.build_secondary_main_config(
                self.shared["hwdata_va"], self.shared["hwdata_va"], channels,
                list(g17p.SECONDARY_REGION_TRIPLES), extra_addr)
        else:
            main = build.build_main_config(
                self.shared["hwdata_va"], self.shared["hwdata_va"], channels,
                self.shared["addr_array"], self.shared["region_triples"])
        space.write(self.main_pa, main)

        space.write(self.status_a_pa, build.build_status_block(extra=False))
        if self.status_b_pa is not None:
            space.write(self.status_b_pa, build.build_status_block())

        space.write(root_pa, build.build_root(
            version=list(g17p.ROOT_VERSION_VALUES),
            region_a=self.shared["region_a_va"],
            main_config=self.main_va,
            region_c=self.shared["region_c_va"],
            status_a=self.status_a_va,
            status_b=self.status_b_va,
            kind=self.index))
        self.root_va, self.root_pa = root_va, root_pa

    def stage_opening_control(self):
        """Put the opening control entry in the ring before the descriptor.

        A working host stages this and sets the producer before it hands over the
        descriptor, not after. One entry, not several: the several seen in a running
        system have accumulated.
        """
        opcode = (g17p.CONTROL_MESSAGE_INIT_SECONDARY if self.secondary
                  else g17p.CONTROL_MESSAGE_INIT)
        entry = bytearray(g17p.CONTROL_MESSAGE_SIZE)
        struct.pack_into("<I", entry, g17p.CONTROL_MESSAGE_TYPE, opcode)
        self.space.write(self.control_ring_pa, bytes(entry))
        self.space.p.write32(self.control_producer_pa, 1)
        self.space.p.dc_civac(self.control_producer_pa, 8)
        return opcode

    def control_indices(self):
        """The control channel's read, second-read and write indices."""
        base = (self.state_pa
                + g17p.CHANNEL_TABLE_WORK_COUNT * g17p.CHANNEL_STATE_STRIDE)
        self.space.p.dc_civac(base, g17p.CHANNEL_STATE_STRIDE)
        raw = self.space.read(base, g17p.CHANNEL_STATE_STRIDE)
        return tuple(struct.unpack_from(
            "<I", raw, i * g17p.CHANNEL_ENTRY_STATE_SPACING)[0]
            for i in range(g17p.CHANNEL_ENTRY_STATE_COUNT))
