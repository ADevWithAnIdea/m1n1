# SPDX-License-Identifier: GPL-2.0-only
"""Explicit G17G first-compute publication over the independent boot runtime.

This first integration stage accepts a firmware-only graph naming opaque
caller CDM bounds and physical BO mappings. Standalone compute continuation
and queue recreation are integrated; mixed work remains separate. No experiment
module is imported.
"""

import math
import struct
import time

from m1n1.fw.asc.base import ASCMessage1
from m1n1.hw.uat import TTBR
from . import g17g, g17g_backend, g17g_compute, g17g_initdata
from . import g17g_postcontrol, g17g_stream, g17g_uat
from .g17g_boot import PAGE_SIZE, publish_pages, wait_until
from .g17g_memory import G17GPageBacking, mapping_runs
from .g17g_sync import G17GPublishedFault
from .g17g_submit import first_compute_completion, continued_compute_completion
from .g17g_compute_queue import write_pages
from .g17g_transfer import write_publications, read_ranges


class G17GFirstComputeRuntime:
    def __init__(self, boot):
        if boot.state != "ready" or boot.profile not in ("compute", "mixed"):
            raise ValueError("first compute requires the ready compute boot profile")
        self.boot = boot
        self.u, self.p, self.iface, self.uat = boot.u, boot.p, boot.iface, boot.uat
        self.asces = boot.asces
        self.root = boot.synthetic_high_root
        self.pages = dict(boot.plan["ram_pages"])
        self.state = "new"
        self.completed = 0
        self.allocations = []
        self.context = None
        self.context_id = 1
        self.resident_contexts = {}
        self.layout = None
        self.evidence = {"captured_input": None, "execution_claim": "none"}

    def publish(self, pages):
        return publish_pages(self.u, pages, coprocessor=self.boot.profile == "mixed")

    def observe(self, phase):
        observer = getattr(self, "observer", None)
        if observer is not None:
            observer(phase)

    def alloc(self, size):
        pa = int(self.u.memalign(PAGE_SIZE, size))
        self.allocations.append((pa, size))
        self.p.memset32(pa, 0, size)
        return pa

    def pa(self, address):
        page = address & -PAGE_SIZE
        timestamps = getattr(self, "timestamp_pages", {})
        return (timestamps[page] if page in timestamps else self.pages[page]) + (address & (PAGE_SIZE - 1))

    def read(self, pa, size):
        self.p.dc_ivac(pa, size)
        self.u.inst("dsb sy")
        return bytes(self.iface.readmem(pa, size))

    def write(self, address, body):
        if self.layout is not None:
            body = self.layout.global_bytes(address, body)
        pages = set()
        offset = 0
        while offset < len(body):
            dva = address + offset
            size = min(PAGE_SIZE - dva % PAGE_SIZE, len(body) - offset)
            pa = self.pa(dva)
            self.iface.writemem(pa, body[offset:offset + size])
            pages.add(pa & -PAGE_SIZE)
            offset += size
        return pages

    @staticmethod
    def physical_writes(writes, pages):
        """Resolve all fragments before the target scatter can touch memory."""
        result = []
        for address, body in writes:
            offset = 0
            while offset < len(body):
                dva = address + offset
                count = min(PAGE_SIZE - dva % PAGE_SIZE, len(body) - offset)
                pa = pages[dva & -PAGE_SIZE] + dva % PAGE_SIZE
                result.append((pa, body[offset:offset + count]))
                offset += count
        return tuple(result)

    def flush_tables(self, ctx):
        # UAT caches the two-entry L0 context slot at gpu_region + ctx*16,
        # not at the enclosing physical page base used for publication.
        dirty = tuple(int(pa) for pa in self.uat.dirty)
        if any(pa % PAGE_SIZE and pa != int(self.uat.gpu_region) + ctx * 16
               for pa in dirty):
            raise RuntimeError("unexpected unaligned dirty UAT object")
        pages = tuple(sorted({pa & -PAGE_SIZE for pa in dirty}))
        self.uat.flush_dirty()
        self.uat.invalidate_cache()
        self.uat.invalidate_root_walk_cache()
        self.publish(pages)
        self.u.inst("tlbi aside1os, x0", ctx << 48)
        self.u.inst("dsb sy")
        return pages

    def channel_state(self, channel=12):
        states, _ring = self.boot.fields["primary_main_fields"]["channels"][channel]
        fields = self.read_fields({index: (dva, 4) for index, dva in enumerate(states)})
        return tuple(struct.unpack("<I", fields[index])[0] for index in range(3))

    def prepare_control(self, timeout, generation=0xb4, *, defer_start=False,
                        allocation_family=0, resource_units=0x1a,
                        deferred_dvas=(), deferred_aliases=()):
        if self.channel_state() != (0, 0, 1):
            raise RuntimeError("first compute does not own the initial service cursor")
        if not defer_start:
            for asc in self.asces:
                asc.send(g17g.MSG_TYPE_89 << 48, ASCMessage1(EP=0x21))
                asc.work()
            wait_until(self.asces, lambda: self.channel_state() == (1, 1, 1),
                       timeout, "compute control start")

        patched = set()
        for address, entries in g17g_postcontrol.build_existing_postcontrol_qwords(
                allocation_family, resource_units).items():
            for offset, value in entries:
                patched.update(self.write(address + offset, struct.pack("<Q", value)))
        self.publish(patched)
        images = g17g_postcontrol.build_postcontrol_pages(generation)
        base = self.alloc(len(images) * PAGE_SIZE)
        flags_by_class = {
            g17g_postcontrol.FLAG_CLASS_SHARED_UXN: g17g_uat.FLAGS_SHARED_UXN,
            g17g_postcontrol.FLAG_CLASS_SHARED_EXECUTABLE: g17g_uat.FLAGS_SHARED_EXECUTABLE,
            g17g_postcontrol.FLAG_CLASS_NORMAL_UXN: g17g_uat.FLAGS_NORMAL_UXN,
        }
        new = {}
        for index, (address, body) in enumerate(images.items()):
            if address in self.pages:
                raise RuntimeError("post-control page already owned")
            new[address] = base + index * PAGE_SIZE
            self.iface.writemem(new[address], self.layout.global_bytes(address, body)
                               if self.layout is not None else body)
        self.publish(new.values())
        for address, pa in new.items():
            if address in deferred_dvas:
                continue
            flags = flags_by_class[g17g_postcontrol.flag_class_for_address(address)]
            self.uat.iomap_at_root(self.root, address, pa, PAGE_SIZE, **flags)
        self.pages.update(new)
        self.flush_tables(0x40)
        for low, high in g17g_postcontrol.build_context0_aliases().items():
            if low in deferred_aliases:
                continue
            self.uat.iomap_at_root(self.boot.context0_low_root, low, self.pages[high],
                                  PAGE_SIZE, **g17g_uat.FLAGS_CONTEXT0_UXN)
        self.flush_tables(0)

    def prepare_firmware(self, graph):
        addresses = graph["addresses"]
        fresh = {addresses[name]: g17g_uat.FLAGS_SHARED_UXN
                 for name in ("class2_support", "class2_state")}
        fresh.update({dva: g17g_uat.FLAGS_NORMAL_UXN
                      for dva in g17g_backend.COMPUTE_SOURCE_NEW_ZERO_GLOBAL_PAGES})
        for dva in fresh:
            if self.uat.iotranslate_root(self.root, dva, PAGE_SIZE) != [(None, PAGE_SIZE)]:
                raise RuntimeError("first-compute fresh firmware page already mapped")
        new_pages = set()
        for dva, flags in fresh.items():
            pa = self.alloc(PAGE_SIZE)
            self.pages[dva] = pa
            new_pages.add(pa)
            self.uat.iomap_at_root(self.root, dva, pa, PAGE_SIZE, **flags)
        for dva, body in graph["source_global_pages"].items():
            new_pages.update(self.write(dva, body))
        for name, body in graph["firmware_objects"].items():
            new_pages.update(self.write(addresses[name], body))
        for name, patches in graph["firmware_patches"].items():
            for offset, body in patches:
                new_pages.update(self.write(addresses[name] + offset, body))
        channel = g17g.build_channel_entry(tuple(
            addresses["state"] + g17g_compute.COMPUTE_CHANNEL_STATE_OFFSET + offset
            for offset in (0, 0x10, 0x20)),
            addresses["channel_ring"] + g17g_compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET)
        new_pages.update(self.write(g17g_initdata.PRIMARY_MAIN_ADDRESS +
            g17g.CHANNEL_TABLE_OFFSET + 8 * g17g.CHANNEL_ENTRY_SIZE, channel))
        self.publish(new_pages)
        self.flush_tables(0x40)

    def context_dvas(self, graph, caller_pages, shared_pages=()):
        """Do not synthesize unbound compiler pages from a source topology.

        Legacy direct experiments retain their explicit topology. The UAPI
        layout owns only private objects and caller mappings in the USC range;
        template shader/code/table leaves are not driver allocations.
        """
        dvas = set(graph['context1_dvas'])
        if self.layout is not None:
            owned = (set(graph['private_dvas']) | set(caller_pages) |
                     set(shared_pages) | set(g17g_backend.context1_page_images(graph)))
            dvas = {dva for dva in dvas if dva < 0x10000000000 or dva in owned}
        return dvas

    def prepare_context(self, graph, caller_pages=None, *, install=True, shared_pages=None):
        images = g17g_backend.context1_page_images(graph)
        caller_pages = dict(caller_pages or {})
        shared_pages = dict(shared_pages or {})
        dvas = tuple(sorted(self.context_dvas(graph, caller_pages, shared_pages)))
        labels = set(graph['private_dvas']) if self.layout is not None else set()
        if set(shared_pages) & ((set(caller_pages)-labels) | set(images)) or not set(shared_pages) <= set(dvas):
            raise ValueError("shared context aliases overlap caller/images or escape topology")
        mapping_runs(shared_pages)
        if (set(caller_pages)-labels) & set(images):
            raise ValueError("driver images would overwrite caller BO contents")
        if not set(caller_pages) <= set(dvas):
            raise ValueError("caller page absent from submission context")
        mapping_runs(caller_pages)
        allocation_start = len(self.allocations)
        root0, root1 = self.alloc(PAGE_SIZE), self.alloc(PAGE_SIZE)
        private = tuple(dva for dva in dvas if (dva not in caller_pages or dva in labels) and dva not in shared_pages)
        base = self.alloc(len(private) * PAGE_SIZE)
        pages = {dva: base + index * PAGE_SIZE for index, dva in enumerate(private)}
        pages.update({dva: item.pa for dva, item in caller_pages.items() if dva not in labels})
        pages.update({dva: item.pa for dva, item in shared_pages.items()})
        context = dict(root0=root0, root1=root1, pages=pages,
                       context_id=self.context_id, layout=self.layout,
                       allocations=list(self.allocations[allocation_start:]),
                       table_witnesses=set(dvas), destroyed=False,
                       caller_mappings=dict(caller_pages))
        context['private_labels'] = labels & set(pages)
        for dva, body in images.items():
            self.iface.writemem(pages[dva], body)
        self.publish(pages.values())
        read_only = set(graph["context1_read_only_dvas"])
        mappings = {dva: G17GPageBacking(pa, dva not in read_only)
                    for dva, pa in pages.items()}
        mappings.update(caller_pages)
        mappings.update(shared_pages)
        for dva, pa, size, writable in mapping_runs(mappings):
            flags = g17g_uat.FLAGS_CONTEXT0_UXN if writable else g17g_uat.FLAGS_CONTEXT0_EXECUTABLE
            self.uat.iomap_at_root(root0, dva, pa, size, **flags)
        self.flush_tables(self.context_id)
        self.publish((root1,))
        if self.layout is not None:
            self.layout.relocate_context(self, context)
        if install:
            self.select_context(context, require_empty=True)
        witnesses = set(caller_pages) | set(shared_pages)
        for spec in graph.get("dispatch_outputs", ()):
            witnesses.update(spec[name] for name in ("buffer_a", "buffer_b", "output"))
        for dva in witnesses:
            pa = caller_pages[dva].pa if dva in caller_pages else pages[dva]
            if self.uat.iotranslate_root(root0, dva, PAGE_SIZE) != [(pa, PAGE_SIZE)]:
                raise RuntimeError("compute context translation mismatch")
        return context

    @staticmethod
    def context_slot_image(context):
        if context is None:
            return bytes(16)
        return struct.pack("<2Q", *(int(TTBR(BADDR=context[key] >> 1, ASID=context.get("context_id", 1), VALID=1))
                                   for key in ("root0", "root1")))

    def select_context(self, context, *, require_empty=False):
        """Select source-owned private roots at a serialized idle boundary."""
        if context is not None and context.get("destroyed"):
            raise RuntimeError("cannot activate a destroyed compute VM")
        if not require_empty and self.state != "complete":
            raise RuntimeError("context switch requires clean compute retirement")
        context_id = self.context_id if context is None else context.get('context_id', 1)
        slot = int(self.uat.gpu_region) + context_id*16
        before = read_ranges(self.u, self.p, self.iface, ((slot, 16),))[0]
        prior = self.resident_contexts.get(context_id)
        expected = self.context_slot_image(prior)
        if before != expected or require_empty and prior is not None:
            raise RuntimeError("context slot no longer names this runtime's owned roots")
        target = self.context_slot_image(context)
        if target != before:
            for index, key in enumerate(('root0', 'root1')):
                self.uat.set_l0(context_id, index, 0 if context is None else context[key],
                                0 if context is None else context_id)
            self.flush_tables(context_id)
            self.publish((int(self.uat.gpu_region),))
        after = read_ranges(self.u, self.p, self.iface, ((slot, 16),))[0]
        if after != target:
            raise RuntimeError("context root publication did not read back exactly")
        if context is None:
            self.resident_contexts.pop(context_id, None)
        else:
            self.resident_contexts[context_id] = context
        self.context, self.context_id = context, context_id
        self.layout = None if context is None else context.get('layout')
        return dict(before=before.hex(), after=after.hex(), firmware_context_id=context_id,
                    changed=(before != after), resident_slots=sorted(self.resident_contexts))

    def destroy_context(self, context):
        """Invalidate an idle root pair, then free only its owned allocations."""
        if context.get("released"):
            return dict(context["tombstone"])
        if self.state != "complete":
            raise RuntimeError("cannot destroy compute VM before clean retirement")
        if context.get("partial_pending_service"):
            raise RuntimeError("render VM arena is retained until the next service retirement")
        slot = context.get('context_id', 1)
        installed = self.resident_contexts.get(slot)
        if installed is not None and installed is not context:
            raise RuntimeError('context slot belongs to another root owner')
        if installed is context:
            active, active_id, active_layout = self.context, self.context_id, self.layout
            self.context_id = slot
            self.select_context(None)
            if active is not context:
                self.context, self.context_id, self.layout = active, active_id, active_layout
        roots = (context["root0"], context["root1"])
        if "release_allocations" not in context:
            tables = set(g17g_uat.collect_firmware_root_table_pages(
                self.uat, roots[0], context["table_witnesses"])) - set(roots)
            if context.get('high_table_witnesses'):
                tables.update(set(g17g_uat.collect_firmware_root_table_pages(
                    self.uat, roots[1], context['high_table_witnesses'])) - set(roots))
            # Reactive TVB growth can place new page tables in the tail of
            # its backing extent. Those pages are views, not separate heap
            # allocations, and must not be freed twice.
            tables = {pa for pa in tables if not any(base <= pa < base + size
                      for base, size in context["allocations"])}
            context["release_allocations"] = list(context["allocations"]) + [
                (pa, PAGE_SIZE) for pa in sorted(tables)]
            context["release_count"] = len(context["release_allocations"])
        context["destroyed"] = True
        if not context.get("roots_invalidated"):
            for root in roots:
                self.p.memset32(root, 0, PAGE_SIZE)
            self.publish(roots)
            self.uat.invalidate_cache()
            self.uat.invalidate_root_walk_cache()
            self.u.inst("tlbi aside1os, x0", context.get("context_id", 1) << 48)
            self.u.inst("dsb sy")
            if any(any(body) for body in read_ranges(self.u, self.p, self.iface,
                                                     tuple((root, PAGE_SIZE) for root in roots))):
                raise RuntimeError("destroyed compute root is not entirely invalid")
            context["roots_invalidated"] = True
        while context["release_allocations"]:
            allocation = context["release_allocations"][-1]
            self.u.free(allocation[0])
            if allocation in self.allocations:
                self.allocations.remove(allocation)
            context["release_allocations"].pop()
        for root in roots:
            self.uat.release_root_view(root)
        context["released"] = True
        context["tombstone"] = dict(roots=roots, roots_zero_before_free=True,
            released=True, released_allocations=context["release_count"], firmware_context_id=context.get("context_id", 1))
        return dict(context["tombstone"])

    def update_caller_mappings(self, caller_pages, *, context=None):
        """Only change PTEs whose owned backing or permissions changed.

        This runtime is the sole root writer; unbind removes the cached entry.
        The caller flushes tables before publication. A failed update is
        terminal for this runtime and cannot reuse the speculative table state.
        """
        context = self.context if context is None else context
        known = context.setdefault("caller_mappings", {})
        changed = {dva: page for dva, page in caller_pages.items() if known.get(dva) != page}
        for dva, pa, size, writable in mapping_runs(changed):
            flags = g17g_uat.FLAGS_CONTEXT0_UXN if writable else g17g_uat.FLAGS_CONTEXT0_EXECUTABLE
            self.uat.iomap_at_root(context["root0"], dva, pa, size, ctx=context.get("context_id", 1), **flags)
        context["pages"].update({dva: page.pa for dva, page in changed.items()
                                 if dva not in context.get('private_labels', ())})
        context.setdefault("table_witnesses", set()).update(changed)
        known.update(changed)
        return len(changed)

    def prepare_service(self, timeout):
        states, ring = self.boot.fields["primary_main_fields"]["channels"][12]
        bodies = g17g.build_first_compute_service_records()
        groups = (bodies[:3],) + tuple((body,) for body in bodies[3:])
        cursor = 1
        self.evidence["service"] = []
        for group in groups:
            if self.channel_state() != (cursor,) * 3:
                raise RuntimeError("first-compute service cursor is not owned")
            changed = set()
            for index, body in enumerate(group, cursor):
                pa = self.pa(ring + index * g17g.SERVICE_RECORD_SIZE)
                if any(self.read(pa, len(body))):
                    raise RuntimeError("first-compute service slot is not empty")
                changed.update(self.write(ring + index * g17g.SERVICE_RECORD_SIZE, body))
            target = cursor + len(group)
            changed.update(self.write(states[2], struct.pack("<I", target)))
            self.publish(changed)
            published = self.channel_state()
            if published not in ((cursor, cursor, target), (target,) * 3):
                raise RuntimeError("unexpected service publication state")
            notified = published != (target,) * 3
            if notified:
                self.asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
                wait_until(self.asces, lambda: self.channel_state() == (target,) * 3,
                           timeout, "compute service")
            self.evidence["service"].append(dict(target=target, notified=notified))
            cursor = target

    def retire_initial_globals(self):
        addresses = g17g_backend.COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES
        for root in self.boot.firmware_roots.values():
            for dva in addresses:
                if self.uat.iotranslate_root(root, dva, PAGE_SIZE) != [(self.pages[dva], PAGE_SIZE)]:
                    raise RuntimeError("unowned initial global retirement")
        for dva in addresses:
            if self.uat.iounmap_root(self.root, dva, PAGE_SIZE) != PAGE_SIZE:
                raise RuntimeError("initial global retirement size mismatch")
        self.flush_tables(0x40)
        for root in self.boot.firmware_roots.values():
            for dva in addresses:
                if self.uat.iotranslate_root(root, dva, PAGE_SIZE) != [(None, PAGE_SIZE)]:
                    raise RuntimeError("retired global remains mapped")

    def kick_and_wait(self, output_pa, work, timeout):
        # This is one first-work submission, not a per-generation batch loop.
        # Preserve and dispatch every mailbox message: the older render wait
        # drains raw FIFO words, which could discard a crash notification.
        self.asces[0].send(work, ASCMessage1(EP=0x21))
        wait_until(self.asces,
                   lambda: bool(g17g_stream.read_output_word(self.u, output_pa)),
                   timeout, "first-compute output")

    def fault_status(self):
        base = int(self.u.adt["/arm-io/sgx"].get_reg(0)[0])
        raw = int(self.p.read64(base + 0xd8c0))
        address_raw = int(self.p.read64(base + 0xd8c8))
        # Preserve numeric fields. Do not reuse the old 40-bit sign extension
        # for the independently verified M5 42-bit UAT aperture.
        return dict(info=raw, address_raw=address_raw, faulted=bool(raw & 1))

    def retirement_state(self, graph):
        addresses = graph["addresses"]
        states, _ring = self.boot.fields["primary_main_fields"]["channels"][8]
        fields = {index: (dva, 4) for index, dva in enumerate(states)}
        fields.update(pointers=(addresses["pointers"], 0x44), queue=(addresses["queue"] + 0x1c, 4))
        data = self.read_fields(fields)
        return dict(channel=tuple(struct.unpack("<I", data[index])[0] for index in range(3)),
            pointers=tuple(struct.unpack_from("<I", data["pointers"], offset)[0]
                           for offset in (0, 0x30, 0x40)),
            queue_limit=struct.unpack("<I", data["queue"])[0])

    def completion_observation(self, graph):
        return self.completion_observations((graph,))[0]

    def read_fields(self, fields):
        """Gather exact owned fields once, without reading intervening data."""
        ranges, references = {}, {}
        for name, (address, size) in fields.items():
            if type(size) is not int or size <= 0:
                raise ValueError("owned field must have a positive size")
            fragments = []
            while size:
                count = min(size, PAGE_SIZE - address % PAGE_SIZE)
                key = self.pa(address), count
                ranges.setdefault(key, len(ranges))
                fragments.append(ranges[key])
                address, size = address + count, size - count
            references[name] = fragments
        images = read_ranges(self.u, self.p, self.iface, tuple(ranges))
        return {name: b"".join(images[index] for index in fragments)
                for name, fragments in references.items()}

    def completion_observations(self, records):
        """Read only owned firmware data, never a potentially gated MMIO bank."""
        records = tuple(records)
        fields = {}
        for index, record in enumerate(records):
            addresses = record["addresses"]
            for name in ("dispatch_a", "dispatch_b", "status_a", "status_b"):
                fields[index, name] = addresses[name], 16
            fields[index, "descriptor_tail"] = addresses["descriptor"] + 0xf00, 0xe0
        states, _ring = self.boot.fields["primary_main_fields"]["channels"][13]
        fields["report_state"] = states[0], 0x24
        data = self.read_fields(fields)
        state = data["report_state"]
        consumer, producer = struct.unpack_from("<I", state)[0], struct.unpack_from("<I", state, 0x20)[0]
        reports = dict(consumer=consumer, producer=producer, state_hex=state.hex())
        if not 0 <= consumer < 256 or not 0 <= producer < 256:
            raise RuntimeError("invalid first-work report cursors")
        count = (producer - consumer) % 256
        if count > 64:
            raise RuntimeError("compute report interval exceeds owned wave")
        report_data = self.read_fields({index: (states[1] + ((consumer + index) % 256) * 0x48, 0x48)
                                       for index in range(count)})
        reports["records"] = [report_data[index].hex() for index in range(count)]
        return tuple(dict({name: data[index, name].hex() for name in
            ("dispatch_a", "dispatch_b", "status_a", "status_b", "descriptor_tail")}, reports=reports,
            sampler_input=g17g_compute.build_compute_sampler_input(
                records[index].get('sampler_heap', 0), records[index].get('sampler_count', 0)).hex())
            for index in range(len(records)))

    def execute(self, graph, caller_pages, *, timeout=2.0, activate=None):
        """Publish an opaque caller command; never inspect shader/output bytes.

        The caller/test checks semantic results independently. Retirement is
        a fence boundary, not a claim that any output changed. This currently
        handles first standalone compute only; later lifecycles are separate.
        """
        if self.state != "new" or getattr(self.boot, "submission_owner", None) is not None:
            raise RuntimeError("first-compute runtime is one-shot")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("compute timeout must be finite and positive")
        if (graph.get("format") != "m1n1-g17g-first-compute-firmware-v1" or
                graph.get("captured_input") is not None or graph["channel"] != 8 or
                graph["compute_descriptor_count"] != (0 if graph.get('empty_transport') else 1)):
            raise ValueError("expected firmware-only first-compute graph")
        mapping_runs(caller_pages)
        if self.layout is None and set(caller_pages) & set(graph["private_dvas"]):
            raise ValueError("caller mapping overlaps private driver objects")
        if not set(caller_pages) <= set(graph["context1_dvas"]):
            raise ValueError("caller page absent from submission context")
        self.boot.submission_owner = self
        self.state = "publishing"
        started = time.monotonic()
        self.evidence["command_publication_started"] = False
        try:
            # Fresh-reset ownership is checked by the boot/runtime state.
            # The SGX bank is not readable at the dual-initdata-ACK boundary:
            # an early d8c0 read causes a bus error before the first work kick.
            # Inspect it only after the explicit shared-memory fault report.
            self.evidence["fault_before"] = "not read before first GPU work"
            self.prepare_control(timeout)
            self.evidence["command_publication_started"] = True
            self.prepare_firmware(graph)
            # Pin before any PTE becomes visible, including a failed install.
            if activate is not None:
                activate(self)
            self.prepare_context(graph, caller_pages)
            self.prepare_service(timeout)
            self.retire_initial_globals()
            initial = self.retirement_state(graph)
            self.evidence["retirement_before"] = initial
            if graph.get('empty_transport'):
                if initial != dict(channel=(0, 0, 0), pointers=(0, 0, 0), queue_limit=0):
                    raise RuntimeError('new compute transport is not empty')
                self.state = 'complete'
                self.completed = 0
                self.compute_history_count = 0
                self.queue_addresses = graph['addresses']
                self.private_dvas = set(graph['private_dvas'])
                self.evidence['completion_claim'] = 'empty transport; no command published'
                return self.evidence
            self.evidence["completion_before"] = self.completion_observation(graph)
            if initial != dict(channel=(0, 0, 1), pointers=(0, 0, 3), queue_limit=0):
                raise RuntimeError("first command lacks an unconsumed retirement boundary")
            work = (g17g.MSG_WORK_KICK << 48) | 0xa
            self.evidence["kick"] = work
            self.asces[0].send(work, ASCMessage1(EP=0x21))

            def retired():
                current = self.retirement_state(graph)
                self.evidence["retirement_after"] = current
                return current == dict(channel=(1, 1, 1), pointers=(3, 3, 3), queue_limit=3)

            wait_until(self.asces, retired, timeout, "compute retirement")
            # A command-fetch UAT fault can retire every cursor. A clean
            # retirement must not silently turn that known failure into success.
            for asc in self.asces:
                asc.work()
            outcome = None
            def completion_ready():
                nonlocal outcome
                self.evidence["completion_after"] = self.completion_observation(graph)
                outcome = first_compute_completion(self.evidence["completion_before"],
                                                   self.evidence["completion_after"])
                return outcome is not None
            wait_until(self.asces, completion_ready, timeout, "owned compute completion")
            if outcome == "fault":
                # This MMIO bank is only qualified for the reported-fault
                # boundary; never read it on successful or idle paths.
                fault = self.fault_status()
                self.evidence["fault_after"] = fault
                address = fault["address_raw"] << 6
                if fault["faulted"] and graph["cdm_base"] <= address < graph["cdm_end"]:
                    raise G17GPublishedFault.command_fetch_mmu(**fault)
                raise G17GPublishedFault("unclassified-compute-report", fatal=True, metadata=fault)
            self.state = "complete"
            self.completed = 1
            self.queue_addresses = graph["addresses"]
            self.compute_retirement = self.evidence['retirement_after']
            if 'resident_queue' in graph:
                graph['resident_queue'].commit(graph)
                self.compute_queue = graph['resident_queue']
            self.private_dvas = set(graph["private_dvas"])
            self.evidence["completion_claim"] = "owned compute report and mirrored completion stamps"
        except Exception as error:
            self.state = "failed"
            self.evidence["error"] = "%s: %s" % (type(error).__name__, error)
            raise
        finally:
            self.evidence.update(state=self.state, elapsed=time.monotonic() - started)
        return self.evidence

    def execute_wave(self, wave, caller_pages, *, timeout=2.0, activate=None):
        """Reuse the source queue without interpreting caller command bytes.

        Release the whole bounded wave, then check retirement and all owned
        completion words at the end. There is no per-command proxy wait.
        """
        if self.state != "complete" or self.completed != wave["completed"]:
            raise RuntimeError("compute wave does not follow this owner's clean completion")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("compute timeout must be finite and positive")
        private = self.private_dvas | write_pages(wave["low"])
        if self.layout is None and private & set(caller_pages):
            raise ValueError("caller mapping overlaps driver compute continuation")
        mapping_runs(caller_pages)
        started = time.monotonic()
        self.evidence = dict(captured_input=None, execution_claim="none",
                             command_publication_started=False, ordinal=wave["final"])
        self.state = "publishing"
        records = wave["records"]
        record = records[-1]
        try:
            self.evidence["retirement_before"] = self.retirement_state(
                {"addresses": wave["previous_addresses"]})
            if self.evidence["retirement_before"] != wave["retirement_before"]:
                raise RuntimeError("compute predecessor transport has not retired")
            pairs = []
            for key in ("primary_main_fields", "secondary_main_fields"):
                for channel in (13, 14):
                    states, _ring = self.boot.fields[key]["channels"][channel]
                    for index in (0, 2):
                        pairs.append((self.pa(states[index]), self.pa(states[index] + 0x20)))
            self.evidence["report_ack"] = g17g_stream.acknowledge_report_pairs(
                self.u, self.p, self.iface, pairs)
            self.observe("wave_before")
            self.evidence["command_publication_started"] = True
            self.private_dvas = private
            # All new private allocations are zeroed and retained if any
            # later operation fails. Caller pages are never synthesized.
            new_pages = set()
            for dva in sorted(write_pages(wave["high"]) - set(self.pages)):
                pa = self.alloc(PAGE_SIZE)
                self.uat.iomap_at_root(self.root, dva, pa, PAGE_SIZE,
                    **wave["page_flags"].get(dva, g17g_uat.FLAGS_NORMAL_UXN))
                self.pages[dva] = pa
                new_pages.add(pa)
            existing = self.context.get('private_labels', set(self.context['pages'])) if self.layout is not None else set(self.context['pages'])
            for dva in sorted(write_pages(wave["low"]) - set(existing)):
                pa = self.alloc(PAGE_SIZE)
                self.uat.iomap_at_root(self.context["root0"], dva, pa, PAGE_SIZE,
                                      ctx=self.context_id, **g17g_uat.FLAGS_CONTEXT0_UXN)
                self.context["pages"][dva] = pa
                self.context["allocations"].append((pa, PAGE_SIZE))
                self.context["table_witnesses"].add(dva)
                new_pages.add(pa)
                self.context.setdefault('private_labels', set()).add(dva)
            if activate is not None:
                activate(self)
            self.evidence["changed_caller_mappings"] = self.update_caller_mappings(caller_pages)
            publications = self.physical_writes(wave["high"], self.pages) + self.physical_writes(
                wave["low"], self.context["pages"])
            self.evidence["body_publications"] = write_publications(
                self.u, self.p, self.iface, publications)
            new_pages.update(pa & -PAGE_SIZE for pa, _body in publications)
            self.publish(new_pages)
            if 'resident_alias' in wave:
                low, high = wave['resident_alias']
                for page in write_pages(wave['high']):
                    if high <= page < high+0x40000:
                        self.uat.iomap_at_root(self.boot.context0_low_root, low+page-high,
                            self.pages[page], PAGE_SIZE, **g17g_uat.FLAGS_CONTEXT0_EXECUTABLE)
                self.flush_tables(0)
            self.flush_tables(self.context_id)
            self.flush_tables(0x40)
            if self.layout is not None:
                self.layout.relocate_context(self, self.context)
            self.observe("wave_staged")
            before = self.completion_observations(records)
            self.evidence["completion_before_all"] = before
            self.evidence["completion_before"] = before[-1]
            releases = self.physical_writes(wave["release"], self.pages)
            self.evidence["release_publications"] = write_publications(
                self.u, self.p, self.iface, releases)
            release_pages = {pa & -PAGE_SIZE for pa, _body in releases}
            self.publish(release_pages)
            self.asces[0].send((g17g.MSG_WORK_KICK << 48) | 0xa, ASCMessage1(EP=0x21))
            def retired():
                self.evidence["retirement_after"] = self.retirement_state(record)
                return self.evidence["retirement_after"] == wave["retirement_after"]
            wait_until(self.asces, retired, timeout, "continued compute retirement")
            outcomes = None
            def complete():
                nonlocal outcomes
                after = self.completion_observations(records)
                self.evidence["completion_after_all"] = after
                self.evidence["completion_after"] = after[-1]
                queue_id = wave['resident_queue'].compute_id if 'resident_queue' in wave else 0
                outcomes = tuple(continued_compute_completion(old, new, max_reports=len(records), queue_id=queue_id)
                                 for old, new in zip(before, after))
                return "fault" in outcomes or all(outcome == "complete" for outcome in outcomes)
            wait_until(self.asces, complete, timeout, "continued compute completion")
            if "fault" in outcomes:
                fault = self.fault_status()
                self.evidence["fault_after"] = fault
                for command in records:
                    if fault["faulted"] and command["cdm_base"] <= fault["address_raw"] << 6 < command["cdm_end"]:
                        self.evidence["fault_ordinal"] = command["ordinal"]
                        raise G17GPublishedFault.command_fetch_mmu(**fault)
                raise G17GPublishedFault("unclassified-compute-report", fatal=True, metadata=fault)
            self.completed = wave["final"]
            self.queue_addresses = dict(wave["addresses"])
            self.compute_retirement = wave['retirement_after']
            self.compute_queue_completed = wave['resident_value_completed'] if 'resident_alias' in wave else None
            if 'resident_queue' in wave:
                wave['resident_queue'].commit(wave)
                self.compute_queue = wave['resident_queue']
            self.evidence.update(queue_epoch=wave["epoch"], recreated_queue=wave["recreate"])
            self.state = "complete"
            self.evidence["completion_claim"] = "owned continued report and mirrored completion stamps"
        except Exception as error:
            self.state = "failed"
            self.evidence["error"] = "%s: %s" % (type(error).__name__, error)
            raise
        finally:
            self.evidence.update(state=self.state, elapsed=time.monotonic() - started)
            self.observe("wave_after")
        return self.evidence

    def unmap_binding(self, binding):
        return self.unmap_bindings((binding,))

    def unmap_bindings(self, bindings, *, context=None):
        """Validate all ownership first, then publish one page-table update."""
        if self.state != "complete":
            raise RuntimeError("cannot unmap caller backing before clean retirement")
        bindings = tuple(bindings)
        if not bindings:
            return
        context = self.context if context is None else context
        if context is None or context.get("destroyed"):
            raise RuntimeError("cannot unmap a destroyed compute VM")
        pages = context["pages"]
        def translate(dva, size, *, refresh_invalid=True):
            return (self.uat.iotranslate(context.get("context_id", 1), dva, size)
                    if context is self.context else self.uat.iotranslate_root(context["root0"], dva, size))
        for binding in bindings:
            for dva in range(binding.addr, binding.end, PAGE_SIZE):
                owned = context.get('caller_mappings', {}).get(dva)
                if translate(dva, PAGE_SIZE) != [(owned.pa if owned is not None else pages[dva], PAGE_SIZE)]:
                    raise RuntimeError("caller mapping no longer matches owned physical page")
        for binding in bindings:
            count = self.uat.iounmap_root(context["root0"], binding.addr, binding.size)
            if count != binding.size:
                raise RuntimeError("caller unmap size mismatch")
        self.flush_tables(context.get("context_id", 1))
        for binding in bindings:
            # flush_tables discarded every host table cache. Fetch each
            # published table once, then test all leaves from that snapshot;
            # this direct owner permits no concurrent PTE writer.
            if translate(binding.addr, binding.size, refresh_invalid=False) != [(None, binding.size)]:
                raise RuntimeError("caller unmap remains translatable")
        for binding in bindings:
            for dva in range(binding.addr, binding.end, PAGE_SIZE):
                if dva not in context.get('private_labels', ()):
                    del pages[dva]
                context.get("caller_mappings", {}).pop(dva, None)

    def submit(self, graph, *, timeout=2.0, caller_pages=None):
        if self.state != "new":
            raise RuntimeError("first-compute runtime is one-shot")
        if getattr(self.boot, "submission_owner", None) is not None:
            raise RuntimeError("this boot already has a submission owner")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("compute timeout must be finite and positive")
        if (graph.get("captured_input") is not None or graph["channel"] != 8 or
                graph["compute_descriptor_count"] != 1 or graph["direct_dispatch_count"] != 1 or
                graph["native_two_publication_layout"] or graph["fresh_firmware_page_flags"] or
                graph.get("context1_physical_overrides")):
            raise ValueError("only the source standalone first-compute graph is supported")
        if caller_pages:
            mapping_runs(caller_pages)
            if set(caller_pages) & set(g17g_backend.context1_page_images(graph)):
                raise ValueError("driver images would overwrite caller BO contents")
            if not set(caller_pages) <= set(graph["context1_dvas"]):
                raise ValueError("caller page absent from submission context")
        self.boot.submission_owner = self
        self.state = "publishing"
        started = time.monotonic()
        try:
            self.prepare_control(timeout)
            self.prepare_firmware(graph)
            self.prepare_context(graph, caller_pages)
            spec = graph["dispatch_outputs"][0]
            output_pa = self.context["pages"][spec["output"]]
            before = self.read(output_pa, PAGE_SIZE)
            self.output_before = before
            if any(before):
                raise RuntimeError("first-compute output is not freshly zeroed")
            self.prepare_service(timeout)
            self.retire_initial_globals()
            work = (g17g.MSG_WORK_KICK << 48) | 0xa
            self.evidence["output_pa"] = output_pa
            self.evidence["kick"] = work
            try:
                self.kick_and_wait(output_pa, work, timeout)
            finally:
                after = self.read(output_pa, PAGE_SIZE)
                self.output_after = after
            expected = struct.pack("<64f", *spec["expected_values"]) + bytes(PAGE_SIZE - 256)
            if after != expected or after == before:
                raise RuntimeError("first-compute output differs from caller oracle")
            self.state = "complete"
            self.evidence.update(output_dva=spec["output"], exact_output_bytes=len(after),
                                 execution_claim="exact caller output mutation")
        except Exception as error:
            self.state = "failed"
            self.evidence["error"] = "%s: %s" % (type(error).__name__, error)
            # Preserve pending data-only crash evidence before any later reset.
            for asc in self.asces:
                asc.work()
            raise
        finally:
            self.evidence.update(state=self.state, elapsed=time.monotonic() - started)
        return self.evidence
