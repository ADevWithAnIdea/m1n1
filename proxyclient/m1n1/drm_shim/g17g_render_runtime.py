# SPDX-License-Identifier: GPL-2.0-only
"""Independent standalone render opening using opaque caller BO mappings."""
import math
import copy
import struct
import time

from m1n1.fw.asc.base import ASCMessage1
from . import g17g, g17g_backend as backend, g17g_initdata, g17g_postcontrol, g17g_render as render, g17g_uat
from .g17g_boot import PAGE_SIZE, wait_until
from .g17g_memory import G17GPageBacking
from .g17g_runtime import G17GFirstComputeRuntime
from .g17g_render_submit import first_render_completion, RENDER_TRANSPORT_CAPACITY, PARTIAL_COMPLETION_POOL_OFFSET
from .g17g_sync import G17GPublishedFault, G17GWorkError
from .g17g_transfer import write_publications
from .g17g_compute_queue import write_pages
from .g17g_render_queue import transport_head, recreate_transport


class G17GFirstRenderRuntime(G17GFirstComputeRuntime):
    """Share allocation/transport mechanics, not compute's lifecycle."""

    def publish_writes(self, writes):
        if self.layout is not None:
            writes = tuple((address, self.layout.global_bytes(address, body)) for address, body in writes)
        physical = self.physical_writes(tuple(writes), self.pages)
        result = write_publications(self.u, self.p, self.iface, physical)
        self.publish({pa & -PAGE_SIZE for pa, _body in physical})
        return result

    def map_globals(self, addresses, *, fresh):
        addresses = tuple(addresses)
        for dva in addresses:
            if self.uat.iotranslate_root(self.root, dva, PAGE_SIZE) != [(None, PAGE_SIZE)]:
                raise RuntimeError("render global mapping is already present at %#x" % dva)
            if fresh:
                if dva in self.pages:
                    raise RuntimeError("fresh render global already has an owner")
                self.pages[dva] = self.alloc(PAGE_SIZE)
            self.uat.iomap_at_root(self.root, dva, self.pages[dva], PAGE_SIZE,
                                  **g17g_uat.FLAGS_NORMAL_UXN)
        self.publish(self.pages[dva] for dva in addresses)
        self.flush_tables(0x40)

    def unmap_globals(self, addresses):
        addresses = tuple(addresses)
        for dva in addresses:
            if self.uat.iotranslate_root(self.root, dva, PAGE_SIZE) != [(self.pages[dva], PAGE_SIZE)]:
                raise RuntimeError("retired render global does not name owned backing")
        for dva in addresses:
            if self.uat.iounmap_root(self.root, dva, PAGE_SIZE) != PAGE_SIZE:
                raise RuntimeError("render global unmap length mismatch")
        self.flush_tables(0x40)
        for root in self.boot.firmware_roots.values():
            for dva in addresses:
                if self.uat.iotranslate_root(root, dva, PAGE_SIZE) != [(None, PAGE_SIZE)]:
                    raise RuntimeError("retired render global still translates")

    def prepare_render_context(self, graph, caller_pages, *, install=True):
        """Allocate private payloads; share explicit FW aliases/address records."""
        shared = {low: G17GPageBacking(self.pages[high], True)
                  for low, high in graph["context1_aliases"].items()}
        graph = dict(graph, context1_dvas=tuple(sorted(
            set(graph["context1_dvas"]) | set(caller_pages))))
        if not graph["parameters"].partial_mode:
            # The retained firmware allocator advances one global ring of
            # GPU addresses. Those addresses resolve through the selected
            # VM's private operand pages; only the address records are shared.
            # Keep their ownership with the transport, outside any VM's
            # allocation list, so destroying one VM cannot free this ring.
            images = dict(graph["context1_writes"])
            if not hasattr(self, "render_address_lists"):
                if not install or self.context is not None:
                    raise RuntimeError("retained renderer lost its address-list owner")
                dvas = render.RENDER_ADDRESS_LIST_STORAGE_DVAS
                if not set(dvas) <= set(graph["private_dvas"]):
                    raise RuntimeError("address-list storage escaped private topology")
                base = self.alloc(render.RENDER_ADDRESS_LIST_STORAGE_SIZE)
                self.render_address_lists = {dva: G17GPageBacking(base+index*PAGE_SIZE, True)
                                             for index, dva in enumerate(dvas)}
                for dva in render.RENDER_ADDRESS_LIST_PAGE_DVAS:
                    self.iface.writemem(self.render_address_lists[dva].pa, images[dva])
                self.publish(item.pa for item in self.render_address_lists.values())
            for dva in self.render_address_lists:
                images.pop(dva, None)
            shared.update(self.render_address_lists)
            graph["context1_writes"] = images
        return self.prepare_context(graph, caller_pages, shared_pages=shared, install=install)

    def prepare_render(self, graph, caller_pages, activate):
        self.map_globals(graph["pre_service_zero_dvas"], fresh=True)
        self.map_globals(graph["fresh_global_pages"], fresh=True)
        self.publish_writes((*graph["source_global_pages"].items(), *graph["fresh_global_pages"].items()))
        writes = []
        for index, channel in enumerate(graph["channels"]):
            state = backend.RENDER_STATE_PAGE + backend.RENDER_STATE_OFFSETS[index]
            ring = backend.RENDER_CHANNEL_RING_PAGES[index] + backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[index]
            entry = g17g.build_channel_entry((state, state + 0x10, state + 0x20), ring)
            writes.append((g17g_initdata.PRIMARY_MAIN_ADDRESS + g17g.CHANNEL_TABLE_OFFSET +
                           channel * g17g.CHANNEL_ENTRY_SIZE, entry))
        self.publish_writes(writes)
        if activate is not None:
            activate(self)
        self.prepare_render_context(graph, caller_pages)
        # The service consumes these mutable inputs before actual work bytes
        # become visible. Check every full source object before replacing it.
        package = g17g_postcontrol.build_postcontrol_pages(graph["token"])
        fields = {dva: (dva, len(body)) for dva, body in graph["service_input_pages"].items()}
        before = self.read_fields(fields)
        if any(before[dva] != (self.layout.global_bytes(dva, package[dva]) if self.layout is not None
                              else package[dva]) for dva in before):
            raise RuntimeError("first-render service input predecessor changed")
        self.publish_writes(graph["service_input_pages"].items())
        self.unmap_globals(graph["pre_service_retired_dvas"])

    def service(self, graph, timeout):
        deferred = graph.get("deferred_control_start", False)
        initial = self.channel_state()
        if initial != ((0, 0, 1) if deferred else (1, 1, 1)):
            raise RuntimeError("first render service does not own cursor one")
        states, ring = self.boot.fields["primary_main_fields"]["channels"][12]
        entries = tuple((ring + index * g17g.SERVICE_RECORD_SIZE, body)
                        for index, body in enumerate(graph["service_records"], 1))
        before = self.read_fields({index: (dva, len(body)) for index, (dva, body) in enumerate(entries)})
        if any(any(body) for body in before.values()):
            raise RuntimeError("first render service slot is not empty")
        target = len(entries) + 1
        seed = tuple((dva, struct.pack("<I", 1)) for dva in states[:2]) if deferred else ()
        self.publish_writes((*entries, *seed, (states[2], struct.pack("<I", target))))
        if deferred:
            for asc in self.asces:
                asc.send(g17g.MSG_TYPE_89 << 48, ASCMessage1(EP=0x21))
        else:
            self.asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
        wait_until(self.asces, lambda: self.channel_state() == (target,) * 3,
                   timeout, "render opening service")
        self.service_cursor = target

    def prepare_work(self, graph):
        transitions = {dva + offset: (before, after)
                       for dva, rows in graph["work_lifecycle_qwords"].items()
                       for offset, before, after in rows}
        observed = self.read_fields({dva: (dva, 8) for dva in transitions})
        pending = []
        for dva, (before, after) in transitions.items():
            value = struct.unpack("<Q", observed[dva])[0]
            if value not in (before, after):
                raise RuntimeError("first-render lifecycle source mismatch at %#x: %#x" % (dva, value))
            if value != after:
                pending.append((dva, struct.pack("<Q", after)))
        self.publish_writes(pending)
        work = [(graph["firmware_addresses"][name], body) for name, body in graph["firmware_pages"].items()]
        work.extend((graph["firmware_patch_addresses"][name] + offset, body)
                    for name, patches in graph["firmware_patches"].items() for offset, body in patches)
        self.publish_writes(work)
        self.map_globals(backend.RENDER_POST_SERVICE_NEW_ZERO_GLOBAL_PAGES, fresh=True)
        self.map_globals(graph["pre_service_retired_dvas"], fresh=False)
        self.unmap_globals(backend.RENDER_SOURCE_RETIRED_GLOBAL_PAGES)
        status = render.FRAGMENT_STATUS
        if self.uat.iounmap_root(self.root, status, PAGE_SIZE) != PAGE_SIZE:
            raise RuntimeError("render status permission transition failed")
        self.uat.iomap_at_root(self.root, status, self.pages[status], PAGE_SIZE,
                              **g17g_uat.FLAGS_SHARED_EXECUTABLE)
        self.flush_tables(0x40)
        # The qualified retained-queue opening exchanges these two zero
        # scratch leaves before work one; keep it for subsequent submissions.
        retired = backend.RENDER_PRE_SERVICE_NEW_ZERO_GLOBAL_PAGES[-2:]
        restored = backend.RENDER_SOURCE_RETIRED_GLOBAL_PAGES[6:8]
        if any(any(body) for body in self.read_fields({dva: (dva, PAGE_SIZE) for dva in restored}).values()):
            raise RuntimeError("first-render replacement scratch is not zero")
        self.unmap_globals(retired)
        self.map_globals(restored, fresh=False)
        self.publish_writes(graph["late_global_pages"].items())
        from .g17g_resident_queue import prepare_render
        prepare_render(self, graph)

    def retirement(self):
        fields = {}
        for index in (0, 1):
            queue = g17g_postcontrol.QUEUE_PAGE + index * g17g.QUEUE_RECORD_STRIDE
            pointer = g17g_postcontrol.QUEUE_POINTER_PAGE + index * 0x2870
            if hasattr(self, 'render_transport'):
                queue, pointer = (self.render_transport[index][name] for name in ('queue', 'pointers'))
            fields["q", index] = queue + 0x1c, 4
            for field, offset in enumerate((0, 0x30, 0x40)):
                fields["p", index, field] = pointer + offset, 4
            for field, offset in enumerate((0, 0x10, 0x20)):
                fields["c", index, field] = backend.RENDER_STATE_PAGE + backend.RENDER_STATE_OFFSETS[index] + offset, 4
        data = {key: struct.unpack("<I", body)[0] for key, body in self.read_fields(fields).items()}
        return dict(queue=[data["q", i] for i in (0, 1)],
            pointers=[[data["p", i, j] for j in range(3)] for i in (0, 1)],
            channels=[[data["c", i, j] for j in range(3)] for i in (0, 1)])

    def completion(self, graph):
        return self.completions((graph,))[0]

    def ack_retired_reports(self, *, engine_masks=(1, 2, 3)):
        """Return only snapshotted report credits at a quiescent boundary.

        Preserve the primary records and reject pending faults/growth before
        publishing any acknowledgement. Do not reread a moving producer in
        target code and accidentally consume a report arriving after validation.
        """
        from .g17g_stream import write_control_records
        if hasattr(self, 'render_transport'):
            ta, fr = (item['qid'] for item in self.render_transport)
            engine_masks = (*engine_masks, 1<<ta, 1<<fr, (1<<ta)|(1<<fr))
        if getattr(self, 'compute_queue', None):
            engine_masks = (*engine_masks, 1<<self.compute_queue.compute_id)
        addresses = []
        for main in ("primary_main_fields", "secondary_main_fields"):
            for channel in (13, 14):
                states, _ring = self.boot.fields[main]["channels"][channel]
                addresses.extend((main, channel, index, states[index]) for index in (0, 2))
        data = self.read_fields({index: (address, 0x24) for index, (_main, _channel, _slot, address)
                                in enumerate(addresses)})
        consumer, producer = struct.unpack_from("<I", data[0])[0], struct.unpack_from("<I", data[0], 0x20)[0]
        count = (producer - consumer) % 256
        if not 0 <= consumer < 256 or not 0 <= producer < 256 or count > 128:
            raise RuntimeError("retired render report interval exceeds owned bound")
        states, _ring = self.boot.fields["primary_main_fields"]["channels"][13]
        records = self.read_fields({index: (states[1] + ((consumer + index) % 256) * 0x48, 0x48)
                                   for index in range(count)})
        for index, body in records.items():
            words = struct.unpack_from("<4I", body)
            if not (words in tuple((1, mask, 0, 0) for mask in engine_masks) or
                    (consumer + index == 0 and words[:2] == (13, 1))):
                raise RuntimeError("unhandled report must not be acknowledged as retired render work")
        writes, credits = [], []
        for index, (main, channel, slot, address) in enumerate(addresses):
            old, peer = struct.unpack_from("<I", data[index])[0], struct.unpack_from("<I", data[index], 0x20)[0]
            credits.append(dict(main=main, channel=channel, slot=slot, address=address, before=old, peer=peer))
            if old != peer:
                writes.append((self.pa(address), struct.pack("<I", peer)))
        if writes:
            write_control_records(self.u, self.p, self.iface, writes)
        return dict(credits=credits, records=[records[i].hex() for i in range(count)],
                    changed=len(writes), consumer=consumer, producer=producer)

    def completions(self, graphs):
        graphs = tuple(graphs)
        states, _ring = self.boot.fields["primary_main_fields"]["channels"][13]
        fields = dict(dispatch_a=(render.DISPATCH_A, 16),
            dispatch_b=(render.DISPATCH_B, 16), timestamps=(render.STATUS_A, 16),
            reports=(states[0], 0x24))
        for index, graph in enumerate(graphs):
            fields[index, "tiling_tail"] = graph["firmware_addresses"]["tiling_descriptor"] + 0x8d8, 0x80
            fields[index, "fragment_tail"] = graph["firmware_addresses"]["fragment_descriptor"] + 0x2178, 0xc8
            if graph.get("completion_timestamps") is not None:
                addresses = graph.get("completion_timestamp_addresses")
                if addresses is None:
                    fields[index, "execution_timestamps"] = graph["completion_timestamps"], 32
                else:
                    for word, address in enumerate(addresses):
                        fields[index, "execution_timestamp", word] = address, 8
                fields[index, "partial_completion"] = render.render_pool_a_allocation(graph.get("ordinal", 1))[1] + PARTIAL_COMPLETION_POOL_OFFSET, 4
                fields[index, "partial_overflow_count"] = graph["firmware_addresses"]["fragment_descriptor"] + 0x20f4, 4
            elif not graph["parameters"].partial_mode and graph.get("ordinal", 1) >= 3:
                fields[index, "completion_counter"] = render.render_pool_a_allocation(graph["ordinal"])[1] + PARTIAL_COMPLETION_POOL_OFFSET, 4
        data = self.read_fields(fields)
        for index, graph in enumerate(graphs):
            if graph.get("completion_timestamp_addresses") is not None:
                data[index, "execution_timestamps"] = b"".join(
                    data.pop((index, "execution_timestamp", word)) for word in range(4))
        status = data.pop("reports")
        consumer, producer = struct.unpack_from("<I", status)[0], struct.unpack_from("<I", status, 0x20)[0]
        count = (producer - consumer) % 256
        if not 0 <= consumer < 256 or not 0 <= producer < 256 or count > 128:
            raise RuntimeError("first-render report interval exceeds owned bound")
        records = self.read_fields({i: (states[1] + ((consumer + i) % 256) * 0x48, 0x48) for i in range(count)})
        common = {name: data[name].hex() for name in ("dispatch_a", "dispatch_b", "timestamps")}
        common["reports"] = dict(consumer=consumer, producer=producer,
                                 records=[records[i].hex() for i in range(count)])
        return tuple(dict(common, **({"execution_timestamp_addresses": graph["completion_timestamp_addresses"]}
                                    if graph.get("completion_timestamp_addresses") is not None else {}),
                          **{kind: data[index, kind].hex()
                                    for kind in ("tiling_tail", "fragment_tail", "execution_timestamps", "partial_completion", "partial_overflow_count", "completion_counter")
                                    if (index, kind) in data})
                     for index, graph in enumerate(graphs))

    def execute(self, graph, caller_pages, *, timeout=5, activate=None):
        if self.state != "new" or getattr(self.boot, "submission_owner", None) is not None:
            raise RuntimeError("render opening requires a fresh source-owned boot")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("render timeout must be finite and positive")
        if graph.get("captured_input") is not None or graph["format"] != "m1n1-g17g-first-render-firmware-v1":
            raise ValueError("render opening requires the firmware-only source graph")
        self.boot.submission_owner = self
        self.private_dvas = set(graph["private_dvas"])
        self.state = "publishing"
        started = time.monotonic()
        self.evidence["command_publication_started"] = False
        try:
            self.prepare_control(timeout, graph["token"],
                                 defer_start=graph.get("deferred_control_start", False))
            self.evidence["command_publication_started"] = True
            self.prepare_render(graph, caller_pages, activate)
            self.service(graph, timeout)
            self.prepare_work(graph)
            if graph["parameters"].partial_mode:
                from .g17g_tvb_runtime import G17GTVBPool
                self.tvb_pool = G17GTVBPool(self, allow_growth=graph["parameters"].request_tvb_growth,
                                          max_blocks=getattr(self, "tvb_max_blocks", None))
                self.tvb_pool.begin(graph)
            before = self.completion(graph)
            self.evidence["completion_before"] = copy.deepcopy(before)
            self.evidence["retirement_before"] = self.retirement()
            if self.evidence["retirement_before"] != dict(queue=[0, 0], pointers=[[0, 0, 3]] * 2, channels=[[0, 0, 1]] * 2):
                raise RuntimeError("render opening is not an unconsumed six-item group")
            self.asces[0].send(0x0083000000000008, ASCMessage1(EP=0x21))
            outcome = None
            def complete():
                nonlocal outcome
                if hasattr(self, "tvb_pool"):
                    self.tvb_pool.step(before)
                after = self.completion(graph)
                self.evidence["completion_after"] = after
                if hasattr(self, "tvb_pool"):
                    outcome = self.tvb_pool.limit_outcome(after)
                    if outcome == "pending":
                        return False
                    if outcome == "out_of_memory":
                        return self.retirement() == dict(queue=[3, 3], pointers=[[3, 3, 3]] * 2,
                                                         channels=[[1, 1, 1]] * 2)
                outcome = first_render_completion(before, after, pending_growth=hasattr(self, "tvb_pool"))
                return outcome is not None
            wait_until(self.asces, complete, timeout, "owned render completion")
            if outcome == "fault":
                fault = self.fault_status()
                self.evidence["fault_after"] = fault
                address = fault["address_raw"] << 6
                vdm = graph["parameters"].vdm_ctrl_stream_base
                if fault["faulted"] and vdm <= address < (vdm & -PAGE_SIZE) + PAGE_SIZE:
                    self.evidence['fault_ordinal'] = 1
                    raise G17GPublishedFault.command_fetch_mmu(**fault)
                raise G17GPublishedFault("render-opening-report", fatal=True, metadata=fault)
            self.evidence["retirement_after"] = self.retirement()
            if self.evidence["retirement_after"] != dict(queue=[3, 3], pointers=[[3, 3, 3]] * 2, channels=[[1, 1, 1]] * 2):
                raise RuntimeError("completed render transport has not retired")
            self.completed = 1
            self.last_render_completion = self.evidence["completion_after"]
            self.partial_mode = graph["parameters"].partial_mode
            self.last_render_context = self.context
            self.private_dvas.update(graph["private_dvas"])
            self.state = "complete"
            if outcome == "out_of_memory":
                self.evidence["memory_limit_quiescent"] = True
                raise G17GPublishedFault("tvb-memory-limit", G17GWorkError.OUT_OF_MEMORY,
                    recoverable=True, metadata=dict(ordinal=1, exchange=self.evidence["tvb"]))
        except Exception as error:
            if not (isinstance(error, G17GPublishedFault) and error.kind == "tvb-memory-limit" and
                    error.recoverable and self.state == "complete" and
                    self.evidence.get("memory_limit_quiescent") is True):
                self.state = "failed"
            self.evidence["error"] = "%s: %s" % (type(error).__name__, error)
            raise
        finally:
            self.evidence.update(state=self.state, elapsed=time.monotonic() - started)
        return self.evidence

    def guarded_qwords(self, rows, *, second_stage=False):
        """Preflight every owned source qword before changing a stage."""
        if hasattr(self, "tvb_pool"):
            rows = self.tvb_pool.lifecycle_qwords(rows)
        expected = {page + offset: (before, after)
                    for page, entries in rows.items() for offset, before, after in entries}
        data = self.read_fields({dva: (dva, 8) for dva in expected})
        observed = {dva: struct.unpack("<Q", body)[0] for dva, body in data.items()}
        # These are the source-owned retained-opening alternatives documented
        # by the successful ordinary/ZLS repeat, not an unchecked native-state
        # overwrite. The allocation pair has a separately validated shape.
        alternatives = {
            0xfffffc200002f120: 0x20000, 0xfffffc200002f3e0: 0,
            0xfffffc20001a0080: 0x100000001,
            0xfffffc20c0808000: 0, 0xfffffc20c0808030: 0,
            0xfffffc20c0808040: 0, 0xfffffc20c0808070: 0,
        } if second_stage else {}
        mismatches = []
        for dva, (before, after) in expected.items():
            value = observed[dva]
            valid = value in (before, after) or (dva in alternatives and value == alternatives[dva])
            if second_stage:
                valid |= backend.is_post_first_render_lifecycle_source_value(
                    dva & -PAGE_SIZE, dva % PAGE_SIZE, value, before)
                if dva == 0xfffffc200002f3e0:
                    valid |= value == 8
            if second_stage and dva == backend.RENDER_POST_FIRST_ALLOCATOR_PAGE + 8:
                valid |= backend.is_post_first_render_allocator_resource(value)
                if valid and not getattr(self, "partial_mode", False):
                    # Both halves are live address-ring cursors. Work one
                    # consumes a variable number of entries; replacing its
                    # result with a native snapshot skips or reissues pages.
                    # Validate the owned pair, then leave it with firmware.
                    expected[dva] = (before, value)
            if second_stage and getattr(self, "partial_mode", False):
                from .g17g_partial_runtime import postservice_preimage_is_owned
                valid |= postservice_preimage_is_owned(self, dva, value)
            if not valid:
                mismatches.append(dict(dva=dva, expected=before, after=after, observed=value))
        self.evidence.setdefault("guarded_stages", []).append(dict(
            before={hex(dva): value for dva, value in observed.items()}, mismatches=mismatches))
        if mismatches:
            raise RuntimeError("render stage source mismatch: %r" % mismatches)
        self.publish_writes((dva, struct.pack("<Q", after)) for dva, (_before, after) in expected.items()
                            if observed[dva] != after)

    def execute_wave(self, graph, caller_pages, *, timeout=5, activate=None):
        """Retained render queue; no caller program or target knowledge."""
        if graph["format"] == "m1n1-g17g-render-wave-v1":
            from .g17g_render_batch import execute_render_wave
            return execute_render_wave(self, graph, caller_pages, timeout=timeout, activate=activate)
        ordinal = graph["ordinal"]
        if (self.state != "complete" or self.completed != ordinal - 1 or self.boot.submission_owner is not self
                or graph["format"] != "m1n1-g17g-second-render-firmware-v1" or graph.get("captured_input") is not None):
            raise RuntimeError("continued render requires its live preceding owner")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("render timeout must be finite and positive")
        partial = graph.get("partial_transition", False)
        if partial != getattr(self, "partial_mode", False) or ordinal >= 0x10000:
            raise RuntimeError("continued render changes its owned allocation lifecycle")
        transport_start = graph.get("transport_start", 1)
        recreation = None
        if transport_start != getattr(self, "transport_start", 1) and not graph.get('resident_render_routed'):
            recreation = recreate_transport(self, transport_start)
        history = None
        if partial and self.completed >= 5:
            from .g17g_partial_runtime import restore_history_mappings
            history = restore_history_mappings(self)
        started = time.monotonic()
        self.evidence = dict(captured_input=None, ordinal=ordinal, command_publication_started=True)
        if recreation is not None:
            self.evidence["transport_recreation"] = recreation
        if history is not None:
            self.evidence["history_mappings"] = history
        self.state = "publishing"
        try:
            head, counter = transport_head(ordinal - 1, transport_start), backend.render_channel_counter(ordinal - 1)
            published_counter = backend.render_channel_counter(ordinal)
            expected = getattr(self, 'render_retirement', dict(queue=[head] * 2, pointers=[[head] * 3] * 2, channels=[[counter] * 3] * 2))
            if self.retirement() != expected:
                raise RuntimeError("preceding render is not quiescent before continuation")
            if activate is not None:
                activate(self)
            from .g17g_render_buffers import ensure_render_buffers
            ensure_render_buffers(self, graph["parameters"])
            self.evidence["changed_caller_mappings"] = self.update_caller_mappings(caller_pages)
            self.flush_tables(self.context_id)
            if partial and 3 <= ordinal <= 5:
                from .g17g_partial_runtime import prepare_partial_warmup, retire_partial_warmup
                prepare_partial_warmup(self, ordinal)
            def publish_graph():
                from .g17g_resident_queue import prepare_render
                prepare_render(self, graph)
                missing = write_pages(graph["high"]) - set(self.pages)
                if missing:
                    self.map_globals(sorted(missing), fresh=True)
                self.publish_writes(graph["high"])
                physical_low = self.physical_writes(graph["low"], self.context["pages"])
                write_publications(self.u, self.p, self.iface, physical_low)
                self.publish({pa & -PAGE_SIZE for pa, _body in physical_low})
            # Recurrent admission observes this group's new objects. Opening
            # group two alone publishes them after its one-time service stage.
            if ordinal > 2:
                publish_graph()
            if partial and ordinal == 2:
                from .g17g_partial_runtime import prepare_second_partial, retire_first_partial
                prepare_second_partial(self, timeout)
            else:
                service_cursor = self.service_cursor
                if self.channel_state() != (service_cursor,) * 3:
                    raise RuntimeError("continued render service cursor differs")
                states, ring = self.boot.fields["primary_main_fields"]["channels"][12]
                record = backend.build_render_generation_service_record(ordinal)
                address = ring + service_cursor * g17g.SERVICE_RECORD_SIZE
                if ordinal == 2 and any(self.read_fields({0: (address, len(record))})[0]):
                    raise RuntimeError("second render service slot is not empty")
                next_service = backend.render_service_counter(service_cursor + 1)
                self.publish_writes(((address, record), (states[2], struct.pack("<I", next_service))))
                self.asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
                wait_until(self.asces, lambda: self.channel_state() == (next_service,) * 3, timeout, "continued render service")
                self.service_cursor = next_service
            if ordinal == 2:
                if partial and self.evidence.get("partial_allocation", {}).get("minimal"):
                    # Earliest-boundary path: publish only the new
                    # pool records, retaining firmware's live first-work state.
                    self.publish_writes((
                        (render.RENDER_POOL_A_RING_BASE + 0x208, struct.pack("<2Q", 1, 0x50)),
                        (render.RENDER_POOL_B_RING_BASE + 0x148, struct.pack("<Q", 0x100000000)),
                    ))
                else:
                    self.guarded_qwords(backend.build_second_render_minimal_postservice_qwords(), second_stage=True)
                    self.guarded_qwords(backend.build_second_render_publication_qwords())
                    self.guarded_qwords(backend.build_second_render_minimal_work_qwords())
                publish_graph()
                if partial:
                    retire_first_partial(self)
            elif partial and ordinal <= 5:
                retire_partial_warmup(self, ordinal)
            elif partial:
                # From work six the independently characterized recurrence
                # keeps arena A live: no rebind, retirement or payload reset.
                self.evidence["partial_retained_arena"] = "A"
            self.publish_writes(graph["release"])
            if graph.get('resident_render_routed'):
                head = graph['resident_render_before']
            if self.layout is not None:
                self.layout.reserve(self.private_dvas)
                self.layout.relocate_context(self, self.context)
            if hasattr(self, "tvb_pool"):
                if 'resident_render_transport' in graph:
                    ta, fr = (item['qid'] for item in graph['resident_render_transport'])
                    self.tvb_pool.notification_masks = (1<<ta, 1<<fr)
                    self.tvb_pool.fragment_slot, self.tvb_pool.terminal_mask = fr, (1<<ta)|(1<<fr)
                self.tvb_pool.begin(graph)
            before = self.completion(graph)
            self.evidence["completion_before"] = copy.deepcopy(before)
            self.evidence["retirement_before"] = self.retirement()
            if self.evidence["retirement_before"] != dict(queue=[head] * 2, pointers=[[head, head, head + 3]] * 2, channels=[[counter, counter, published_counter]] * 2):
                raise RuntimeError("continued render work was not published coherently")
            self.asces[0].send(0x0083000000000008, ASCMessage1(EP=0x21))
            outcome = None
            def complete():
                nonlocal outcome
                if hasattr(self, "tvb_pool"):
                    self.tvb_pool.step(before)
                after = self.completion(graph)
                self.evidence["completion_after"] = after
                if hasattr(self, "tvb_pool"):
                    outcome = self.tvb_pool.limit_outcome(after)
                    if outcome == "pending":
                        return False
                    if outcome == "limit_followup_retired":
                        if first_render_completion(before, after, ordinal=ordinal, pending_growth=True) != "complete":
                            return False
                        outcome = "out_of_memory"
                        self.evidence['memory_limit_completion'] = 'owned type9, fresh private completion and retirement'
                    if outcome == "out_of_memory":
                        return self.retirement() == dict(queue=[head + 3] * 2,
                            pointers=[[head + 3] * 3] * 2, channels=[[published_counter] * 3] * 2)
                outcome = first_render_completion(before, after, ordinal=ordinal,
                                                   pending_growth=hasattr(self, "tvb_pool"))
                if outcome == "complete" and partial:
                    self.evidence["completion_rule"] = (
                        "fresh pool-A final state, owned TA/FR timestamp writes and clean retirement"
                        if graph.get("completion_timestamps") is not None else
                        "fresh descriptor mirror write plus clean retirement; prior interval may be retained")
                    return self.retirement() == dict(queue=[head + 3] * 2,
                        pointers=[[head + 3] * 3] * 2, channels=[[published_counter] * 3] * 2)
                return outcome is not None
            wait_until(self.asces, complete, timeout, "owned continued-render completion")
            if outcome == "fault":
                fault = self.fault_status()
                self.evidence["fault_after"] = fault
                address = fault["address_raw"] << 6
                vdm = graph["parameters"].vdm_ctrl_stream_base
                if fault["faulted"] and vdm <= address < (vdm & -PAGE_SIZE) + PAGE_SIZE:
                    self.evidence['fault_ordinal'] = ordinal
                    raise G17GPublishedFault.command_fetch_mmu(**fault)
                raise G17GPublishedFault("continued-render-report", fatal=True, metadata=fault)
            self.evidence["retirement_after"] = self.retirement()
            if self.evidence["retirement_after"] != dict(queue=[head + 3] * 2, pointers=[[head + 3] * 3] * 2, channels=[[published_counter] * 3] * 2):
                raise RuntimeError("continued render transport did not retire")
            self.completed = ordinal
            self.last_render_context = self.context
            self.context["partial_pending_service"] = (
                partial and ordinal < 5 and bool(getattr(self, "render_context_switches", 0)))
            self.last_render_completion = self.evidence["completion_after"]
            self.state = "complete"
            if outcome == "out_of_memory":
                self.evidence["memory_limit_quiescent"] = True
                raise G17GPublishedFault("tvb-memory-limit", G17GWorkError.OUT_OF_MEMORY,
                    recoverable=True, metadata=dict(ordinal=ordinal, exchange=self.evidence["tvb"]))
        except Exception as error:
            if not (isinstance(error, G17GPublishedFault) and error.kind == "tvb-memory-limit" and
                    error.recoverable and self.state == "complete" and
                    self.evidence.get("memory_limit_quiescent") is True):
                self.state = "failed"
            self.evidence["error"] = "%s: %s" % (type(error).__name__, error)
            raise
        finally:
            self.evidence.update(state=self.state, elapsed=time.monotonic() - started)
        return self.evidence
