# SPDX-License-Identifier: GPL-2.0-only
"""Owned compute/ordinary/partial transitions with retained engine transports."""
import copy
import struct
import time
from m1n1.fw.asc.base import ASCMessage1
from . import g17g, g17g_backend as backend, g17g_postcontrol, g17g_uat, g17g_render as render, g17g_initdata
from .g17g_boot import PAGE_SIZE as PAGE, wait_until
from .g17g_memory import G17GPageBacking
from .g17g_render_runtime import G17GFirstRenderRuntime
from .g17g_runtime import G17GFirstComputeRuntime
from .g17g_mixed_submit import mixed_partial_completion, validate_mixed_compute_history, MIXED_COMPUTE_LIMIT
from .g17g_render_submit import PARTIAL_COMPLETION_POOL_OFFSET
from .g17g_render_queue import transport_head, recreate_transport
from .g17g_sync import G17GPublishedFault, G17GWorkError
from .g17g_transfer import write_publications


class G17GMixedRuntime(G17GFirstRenderRuntime):
    def __init__(self, boot):
        if boot.profile != 'mixed':
            raise ValueError('mixed runtime requires its source-qualified boot family')
        super().__init__(boot)
        self.engine = 'compute'
        self.compute_history_count = 1

    def prepare_control(self, timeout, generation=0x146, **kwargs):
        from .g17g_history import prepare_mixed_history
        prepare_mixed_history(self)
        deferred = (set(backend.COMPUTE_TO_PARTIAL_RENDER_NEW_GLOBAL_PAGES)
                    - set(backend.COMPUTE_PREDECESSOR_RENDER_INHERITED_GLOBAL_PAGES))
        super().prepare_control(timeout, 0x146, allocation_family=1, resource_units=0x16,
            deferred_dvas=deferred,
            deferred_aliases=backend.build_compute_predecessor_partial_render_context0_aliases())

    def prepare_service(self, timeout):
        if self.channel_state() != (1, 1, 1):
            raise RuntimeError('mixed compute must precede standalone service registration')
        self.evidence['service'] = []

    def retire_initial_globals(self):
        retained = sorted(set(backend.COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES)
                          & set(backend.COMPUTE_MIXED_FIRST_TYPE84_BEFORE_GLOBAL_PAGES))[:2]
        retired = []
        for address in backend.COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES:
            if address in retained:
                continue
            mapped = self.uat.iotranslate_root(self.root, address, PAGE)
            if mapped == [(None, PAGE)]:
                continue
            if mapped != [(self.pages[address], PAGE)]:
                raise RuntimeError('mixed compute retirement changed ownership')
            self.uat.iounmap_root(self.root, address, PAGE)
            retired.append(address)
        self.flush_tables(0x40)
        self.evidence['retained_globals'] = retained
        self.evidence['retired_globals'] = retired

    def execute(self, graph, caller_pages, *, timeout=5, activate=None):
        if self.engine != 'compute':
            raise RuntimeError('mixed opening already consumed')
        self.compute_context_template = graph
        return G17GFirstComputeRuntime.execute(self, graph, caller_pages, timeout=timeout, activate=activate)

    def ensure_globals(self, pages, flags=None):
        flags = flags or {}
        for address, body in pages.items():
            mapped = self.uat.iotranslate_root(self.root, address, PAGE)
            if mapped == [(None, PAGE)]:
                if address not in self.pages:
                    self.pages[address] = self.alloc(PAGE)
                self.uat.iomap_at_root(self.root, address, self.pages[address], PAGE,
                    **g17g_uat.RAM_FLAG_CLASSES[flags.get(address, 'normal_uxn')])
            elif mapped != [(self.pages.get(address), PAGE)]:
                raise RuntimeError('mixed global allocation changed ownership at %#x' % address)
            elif any(self.read_fields({0: (address, PAGE)})[0]):
                raise RuntimeError('mixed fresh global is not zero at %#x' % address)
        self.publish_writes(pages.items())
        self.flush_tables(0x40)

    def prepare_mixed_context(self, caller_pages):
        """Create private roots from the same recipe as first mixed admission.

        Firmware queues and history already belong to the running device.
        Only initialize this VM's low objects; never replay control or replace
        another VM's caller pages to manufacture a mixed context.
        """
        graph = dict(self.compute_context_template)
        graph['context1_dvas'] = tuple(sorted(set(graph['context1_dvas']) | set(caller_pages)))
        context = self.prepare_context(graph, caller_pages, install=False)
        self.prepare_mixed_render_context(context, caller_pages)
        return context

    def adopt_mixed_layout(self):
        """Admit rendering after the preceding compute queue has retired.

        Mixed compute uses a separate robustness arena. Retain the old backing
        until VM teardown while releasing its source label. Queue/history stay
        live; caller shader mappings do not participate in this transition.
        """
        if self.state != 'complete' or self.engine != 'compute' or self.mixed_layout:
            raise RuntimeError('mixed transition requires retired compute')
        from .g17g_compute_queue import transport_state
        if self.retirement_state({'addresses': self.queue_addresses}) != getattr(self, 'compute_retirement', transport_state(self.completed)):
            raise RuntimeError('mixed transition has a live compute queue')
        template = dict(self.compute_context_template)
        template['context1_writes'] = dict(template['context1_writes'])
        retired = {backend.COMPUTE_ROBUSTNESS}
        template['private_dvas'] = tuple(dva for dva in template['private_dvas'] if dva not in retired)
        self.compute_context_template = template
        self.private_dvas.difference_update(retired)
        self.mixed_layout = True

    def prepare_mixed_render_context(self, context, caller_pages):
        graph = getattr(self, 'render_context_template', None)
        if graph is not None and not context.get('mixed_render_ready'):
            self.extend_context(graph, caller_pages, context=context)

    def extend_context(self, graph, caller_pages, *, context=None):
        context = self.context if context is None else context
        images = dict(graph['context1_writes'])
        layout = context.get('layout')
        labels = set(graph['private_dvas']) if layout is not None else set()
        if not graph['parameters'].partial_mode and render.RENDER_BASE10_SUPPORT_DVA not in caller_pages:
            images[render.RENDER_BASE10_SUPPORT_DVA] = render.build_render_base10_support_page()
        if set(images) & (set(caller_pages)-labels):
            raise ValueError('mixed private images overlap caller bindings')
        aliases = {low: self.pages[high] for low, high in graph['context1_aliases'].items()}
        # The retained allocator advances one address-record ring across
        # submissions, just as in the ordinary-render experiment. Its entries
        # contain GPU addresses; the operand payloads resolve in private roots.
        # Allocate the ring once with the transport, never with a VM.
        if not hasattr(self, 'mixed_address_lists'):
            start = backend.COMPUTE_PREDECESSOR_PARTIAL_ADDRESS_LIST_BASE
            size = render.RENDER_ADDRESS_LIST_STORAGE_SIZE
            dvas = tuple(range(start, start + size, PAGE))
            if not set(dvas) <= set(graph['private_dvas']):
                raise RuntimeError('mixed address ring escaped its source topology')
            base = self.alloc(size)
            self.mixed_address_lists = {dva: base + index * PAGE for index, dva in enumerate(dvas)}
            writes = self.physical_writes(tuple((dva, images[dva]) for dva in dvas if dva in images),
                                         self.mixed_address_lists)
            write_publications(self.u, self.p, self.iface, writes)
            self.publish(self.mixed_address_lists.values())
        aliases.update(self.mixed_address_lists)
        for dva in self.mixed_address_lists:
            images.pop(dva, None)
        new = self.context_dvas(graph, caller_pages, aliases) - set(context['pages']) - set(aliases) - set(caller_pages)
        new.update(labels & set(caller_pages) - context.get('private_labels', set()) - set(aliases))
        if new:
            base = self.alloc(len(new) * PAGE)
            context['allocations'].append((base, len(new) * PAGE))
            for index, dva in enumerate(sorted(new)):
                context['pages'][dva] = base + index * PAGE
        for dva, pa in aliases.items():
            if dva in context['caller_mappings'] and dva not in labels:
                raise ValueError('mixed alias overlaps caller backing')
            context['pages'][dva] = pa
        # Private arena initialization never includes a caller compiler page.
        writes = self.physical_writes(tuple(images.items()), context['pages'])
        write_publications(self.u, self.p, self.iface, writes)
        self.publish(pa for pa, _body in writes)
        readonly = set(graph['context1_read_only_dvas'])
        for dva in new | set(aliases):
            self.uat.iomap_at_root(context['root0'], dva, context['pages'][dva], PAGE,
                **(g17g_uat.FLAGS_CONTEXT0_EXECUTABLE if dva in readonly else g17g_uat.FLAGS_CONTEXT0_UXN))
        self.private_dvas.update(graph['private_dvas'])
        context['table_witnesses'].update(new | set(aliases))
        context.setdefault('private_labels', set()).update((new | set(aliases)) & labels)
        self.update_caller_mappings(caller_pages, context=context)
        layout = context.get('layout')
        if layout is not None:
            layout.reserve(graph['private_dvas'])
            layout.relocate_context(self, context)
        self.flush_tables(context.get('context_id', self.context_id))
        context['mixed_render_ready'] = True
        self.render_context_template = graph

    def mixed_lifecycle(self, graph):
        rows = graph['work_lifecycle_qwords']
        live = self.read_fields({page + off: (page + off, 8)
                                for page, items in rows.items() for off, _before, _after in items})
        self.evidence['lifecycle_before'] = {hex(a): b.hex() for a,b in live.items()}
        report_consumer = self.boot.fields['primary_main_fields']['channels'][13][0][0]
        writes = []
        source_values = {page+offset: (before, after)
            for page, items in graph.get('source_work_lifecycle_qwords', {}).items()
            for offset, before, after in items}
        for page, items in rows.items():
            for off, before, after in items:
                address = page + off
                value = struct.unpack('<Q', live[address])[0]
                admitted = value in (before, after)
                # The first render may introduce this private alias after a
                # compute-only boot. Accept its exact owned source transition.
                admitted |= value in source_values.get(address, ())
                if address == report_consumer:
                    # This is the host report-credit cursor, not a fixed
                    # first-render generation. Retain the producer snapshot
                    # acknowledged after validating the completed compute work.
                    after = self.evidence['compute_reports']['producer']
                    admitted = value == after
                if (page, off) == (0xfffffc20015f0000, 8):
                    # Both allocator cursors advance by 0x60 per compute.
                    # Preserve them when changing the resource family; never
                    # rewind a completed second command to the first cursor.
                    cursor = self.completed * 0x60
                    after = ((0x1600 + cursor) << 32) | cursor
                    admitted = value in (after,((0x1a00 + cursor) << 32) | cursor)
                    if self.completed == 1:
                        admitted |= value in (0x160000000000,0x1a0000000000)
                if (page, off) == (backend.RENDER_LIVE_ADMISSION_PAGE, backend.RENDER_LIVE_ADMISSION_QWORD_OFFSET):
                    admitted |= 0 < value >> 32 <= 0xffff and 0 < value & 0xffffffff <= 0xffff
                if not admitted:
                    raise RuntimeError('mixed lifecycle mismatch at %#x: %#x != %#x/%#x' % (address,value,before,after))
                if value != after:
                    writes.append((address, struct.pack('<Q', after)))
        self.publish_writes(writes)

    def mixed_retirement(self):
        layout = backend._mixed_render_layout(compute_predecessor=True)
        fields = {}
        for i, kind in enumerate(('tiling','fragment')):
            queue = g17g_postcontrol.QUEUE_PAGE + layout[kind + '_physical_queue_index'] * g17g.QUEUE_RECORD_STRIDE
            pointer = layout[kind + '_pointer']
            if hasattr(self, 'render_transport'):
                queue, pointer = (self.render_transport[i][name] for name in ('queue', 'pointers'))
            fields['q',i] = queue + 0x1c, 4
            for j, off in enumerate((0, 0x30, 0x40)):
                fields['p',i,j] = pointer + off, 4
            for j, off in enumerate((0, 0x10, 0x20)):
                fields['c',i,j] = backend.RENDER_STATE_PAGE + backend.RENDER_STATE_OFFSETS[i] + off, 4
        data = {k: struct.unpack('<I',v)[0] for k,v in self.read_fields(fields).items()}
        return dict(queue=[data['q',i] for i in (0,1)],
                    pointers=[[data['p',i,j] for j in range(3)] for i in (0,1)],
                    channels=[[data['c',i,j] for j in range(3)] for i in (0,1)])

    def expected_mixed_retirement(self, ordinal, transport_start=None):
        if hasattr(self, 'render_retirement') and ordinal == self.render_completed:
            return self.render_retirement
        if hasattr(self, 'render_pending_retirement') and ordinal == getattr(self, 'render_completed', 0)+1:
            return self.render_pending_retirement
        if transport_start is None:
            transport_start = getattr(self, 'render_transport_start', 1)
        head = transport_head(ordinal, transport_start)
        counter = backend.render_channel_counter(ordinal)
        return dict(queue=[head]*2, pointers=[[head]*3]*2, channels=[[counter]*3]*2)

    def completion(self, graph):
        result = super().completion(graph)
        address = render.render_pool_a_allocation(graph.get('ordinal',1))[1] + PARTIAL_COMPLETION_POOL_OFFSET
        result['partial_completion'] = self.read_fields({0:(address,4)})[0].hex()
        # First compute contributes one to this shared pool word. With no
        # compute predecessor it starts at zero; paired TA/FR adds two.
        result['partial_completion_target'] = 3 if graph.get('ordinal',1) == 1 and self.completed else 2
        return result

    def partial_outcome(self, before, after):
        if hasattr(self, 'tvb_pool'):
            outcome = self.tvb_pool.limit_outcome(after)
            if outcome == 'pending':
                return None
            if outcome in ('out_of_memory', 'fault'):
                return outcome
            if outcome == 'limit_followup_retired':
                return ('out_of_memory' if mixed_partial_completion(before, after,
                    pending_growth=True) == 'complete' else None)
        return mixed_partial_completion(before, after, pending_growth=hasattr(self, 'tvb_pool'))

    def raise_memory_limit(self, ordinal):
        # The caller has already checked both engine queues and the TVB
        # service's owned negative-reply/follow-up transaction.
        self.evidence['memory_limit_quiescent'] = True
        raise G17GPublishedFault('tvb-memory-limit', G17GWorkError.OUT_OF_MEMORY,
            recoverable=True, metadata=dict(ordinal=ordinal, exchange=self.evidence['tvb']))

    def checked_compute_history(self):
        history = self.read_fields({0:(backend.RENDER_SECOND_SERVICE_HISTORY_PAGE,PAGE)})[0]
        if self.completed == 0:
            if any(history):
                raise RuntimeError('unstarted compute queue has nonempty history')
            return history
        validate_mixed_compute_history(history,self.completed,self.compute_history_count,
            queue_address=self.queue_addresses['queue'],
            queue_completed=getattr(self, 'compute_queue_completed', None),
            queue_id=(self.compute_queue.compute_id if getattr(self, 'compute_queue', None) else 0),
            previous_history=getattr(self,'compute_previous_history',None))
        return history

    def begin_render_pool(self, graph):
        from .g17g_resident_queue import prepare_render
        if graph.get('resident_render_opening') or graph.get('ordinal', 1) == 1:
            prepare_render(self, graph)
        # Ordinary and partial work share the retained transport. An ordinary
        # first render must not prevent a later partial render from obtaining
        # the same reactive pool service used by a partial first render.
        if graph['parameters'].request_tvb_growth and not hasattr(self, 'tvb_pool'):
            from .g17g_tvb_runtime import G17GTVBPool
            self.tvb_pool = G17GTVBPool(self, max_blocks=getattr(self, 'tvb_max_blocks', None),
                state_address=0xfffffc2001628000, list_address=0xfffffc20c08c8000,
                growth_base=0x1100000000, notification_masks=(2, 4),
                fragment_slot=2, terminal_mask=6,
                require_first_terminal=bool(self.completed))
        if hasattr(self, 'tvb_pool'):
            if 'resident_render_transport' in graph:
                ta, fr = (item['qid'] for item in graph['resident_render_transport'])
                self.tvb_pool.notification_masks = (1<<ta, 1<<fr)
                self.tvb_pool.fragment_slot, self.tvb_pool.terminal_mask = fr, (1<<ta)|(1<<fr)
            self.tvb_pool.begin(graph)

    def execute_wave(self, graph, caller_pages, *, timeout=5, activate=None):
        if graph.get('format') == 'm1n1-g17g-mixed-partial-continuation-v1':
            return self.execute_partial_continuation(graph,caller_pages,timeout=timeout,activate=activate)
        if graph.get('format') == 'm1n1-g17g-mixed-compute-wave-v1' and self.engine in ('compute','partial'):
            # A short wave overwrites its prefix, leaving the previously
            # retired suffix intact. Preserve only history we validated while
            # its preceding compute queue was quiescent.
            if not getattr(self,'render_completed',0) and self.completed <= MIXED_COMPUTE_LIMIT:
                self.compute_previous_history = self.checked_compute_history()
            transition = self.prepare_compute_return(timeout) if self.engine == 'partial' else None
            render_before = self.mixed_retirement() if getattr(self,'render_completed',0) else None
            result = G17GFirstComputeRuntime.execute_wave(self,graph,caller_pages,timeout=timeout,activate=activate)
            if render_before is not None:
                render_after = self.mixed_retirement()
                self.evidence['retained_render'] = dict(before=render_before,after=render_after)
                if render_after != render_before:
                    self.state = 'failed'
                    raise RuntimeError('mixed compute changed the retained render transport')
            self.engine = 'compute'
            if transition is not None:
                self.evidence['compute_return'] = transition
            self.compute_history_count = len(graph['records'])
            return result
        if (self.engine != 'compute' or self.state != 'complete' or not 0 <= self.completed <= MIXED_COMPUTE_LIMIT
                or graph['format'] != 'm1n1-g17g-mixed-partial-firmware-v1'):
            raise NotImplementedError('mixed render opening requires a quiescent compute transport')
        self.evidence = dict(captured_input=None, command_publication_started=True)
        started = time.monotonic()
        self.state = 'publishing'
        try:
            if activate is not None:
                activate(self)
            self.evidence['compute_predecessor'] = self.retirement_state({'addresses': self.queue_addresses})
            from .g17g_compute_queue import transport_state
            if self.evidence['compute_predecessor'] != getattr(self, 'compute_retirement', transport_state(self.completed)):
                raise RuntimeError('mixed render predecessor has not retired')
            self.evidence['compute_reports'] = self.ack_retired_reports(engine_masks=(1,))
            history_pages = {}
            for address in backend.COMPUTE_MIXED_FIRST_TYPE84_BEFORE_GLOBAL_PAGES:
                if address == backend.RENDER_SECOND_SERVICE_HISTORY_PAGE:
                    history = self.checked_compute_history()
                    self.evidence['compute_history'] = history[:0x40*self.completed].hex()
                    continue
                history_pages[address] = bytes(PAGE)
            self.ensure_globals(history_pages)
            self.ensure_globals(graph['fresh_global_pages'], graph['fresh_global_page_flags'])
            for low, high in graph['firmware_alias_extensions'].items():
                if self.uat.iotranslate_root(self.boot.context0_low_root, low, PAGE) != [(None,PAGE)]:
                    raise RuntimeError('mixed scratch alias already present')
                self.uat.iomap_at_root(self.boot.context0_low_root, low, self.pages[high], PAGE,
                                      **g17g_uat.FLAGS_CONTEXT0_EXECUTABLE)
            self.flush_tables(0)
            self.extend_context(graph, caller_pages)
            self.mixed_lifecycle(graph)
            self.publish_writes(graph['fresh_global_pages'].items())
            writes = []
            preserved = {}
            for name, original in graph['firmware_pages'].items():
                address = graph['firmware_addresses'][name]
                body = bytearray(original)
                for offset, size in graph['firmware_live_preserve_ranges'].get(name, ()):
                    live = self.read_fields({0:(address+offset,size)})[0]
                    body[offset:offset+size] = live
                    preserved[hex(address+offset)] = live.hex()
                writes.append((address, bytes(body)))
            self.evidence['preserved_compute'] = preserved
            for name, patches in graph['firmware_patches'].items():
                writes.extend((graph['firmware_patch_addresses'][name]+offset, body) for offset,body in patches)
            for i, channel in enumerate(graph['channels']):
                state = backend.RENDER_STATE_PAGE + backend.RENDER_STATE_OFFSETS[i]
                ring = backend.RENDER_CHANNEL_RING_PAGES[i] + backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[i]
                writes.append((g17g_initdata.PRIMARY_MAIN_ADDRESS + g17g.CHANNEL_TABLE_OFFSET + channel*g17g.CHANNEL_ENTRY_SIZE,
                               g17g.build_channel_entry((state,state+0x10,state+0x20),ring)))
            self.publish_writes(writes)
            self.unmap_globals(backend.COMPUTE_SOURCE_NEW_ZERO_GLOBAL_PAGES)
            self.publish_writes(graph['late_global_pages'].items())
            states, ring = self.boot.fields['primary_main_fields']['channels'][12]
            if self.channel_state() != (1,1,1):
                raise RuntimeError('mixed service registration lost cursor one')
            entries = tuple((ring+(index+1)*g17g.SERVICE_RECORD_SIZE, body)
                            for index,body in enumerate(graph['service_records']))
            if any(any(body) for body in self.read_fields({i:(a,len(b)) for i,(a,b) in enumerate(entries)}).values()):
                raise RuntimeError('mixed service slots already owned')
            self.publish_writes(entries)
            for target in range(2,9):
                self.publish_writes(((states[2],struct.pack('<I',target)),))
                self.asces[0].send(0x0084000000000011,ASCMessage1(EP=0x21))
                wait_until(self.asces,lambda:self.channel_state()==(target,)*3,timeout,'mixed render registration')
            self.service_cursor = 8
            self.begin_render_pool(graph)
            before = self.completion(graph)
            self.evidence['completion_before'] = copy.deepcopy(before)
            if struct.unpack('<I',bytes.fromhex(before['partial_completion']))[0] != int(bool(self.completed)):
                raise RuntimeError('mixed partial counter differs from its initial value')
            self.evidence['retirement_before'] = self.mixed_retirement()
            self.asces[0].send(0x0083000000000008,ASCMessage1(EP=0x21))
            outcome = None
            def complete():
                nonlocal outcome
                if hasattr(self, 'tvb_pool'):
                    self.tvb_pool.step(before)
                after = self.completion(graph)
                self.evidence['completion_after'] = after
                outcome = self.partial_outcome(before, after)
                if outcome in ('complete', 'out_of_memory'):
                    self.evidence['retirement_after'] = self.mixed_retirement()
                    return self.evidence['retirement_after'] == dict(
                        queue=[3,3],pointers=[[3,3,3]]*2,channels=[[1,1,1]]*2)
                return outcome == 'fault'
            wait_until(self.asces,complete,timeout,'mixed partial completion')
            if outcome == 'fault':
                self.raise_partial_fault(graph,'mixed-partial-report')
            self.evidence['retirement_after'] = self.mixed_retirement()
            if self.evidence['retirement_after'] != dict(queue=[3,3],pointers=[[3,3,3]]*2,channels=[[1,1,1]]*2):
                raise RuntimeError('mixed render retirement incomplete')
            self.render_completed = 1
            self.engine = 'partial'
            self.partial_mode = True
            self.state = 'complete'
            if outcome == 'out_of_memory':
                self.raise_memory_limit(1)
        except Exception as error:
            if not (isinstance(error, G17GPublishedFault) and error.kind == 'tvb-memory-limit' and
                    error.recoverable and self.state == 'complete' and
                    self.evidence.get('memory_limit_quiescent') is True):
                self.state = 'failed'
            self.evidence['error'] = '%s: %s' % (type(error).__name__,error)
            raise
        finally:
            self.evidence.update(state=self.state,elapsed=time.monotonic()-started)
        return self.evidence


    def execute_partial_continuation(self, graph, caller_pages, *, timeout=5, activate=None):
        ordinal = graph['ordinal']
        if (self.engine not in ('compute','partial') or self.state != 'complete' or
                self.render_completed != ordinal-1 or self.boot.submission_owner is not self):
            raise RuntimeError('mixed partial continuation lacks its completed owner')
        started = time.monotonic()
        self.evidence = dict(captured_input=None,ordinal=ordinal,command_publication_started=False)
        try:
            transport_start = graph.get('transport_start', 1)
            if transport_start != getattr(self, 'render_transport_start', 1) and not graph.get('resident_render_routed'):
                recreate_transport(self, transport_start, mixed=True)
            expected = self.expected_mixed_retirement(ordinal-1)
            self.evidence['retirement_before'] = self.mixed_retirement()
            if self.evidence['retirement_before'] != expected or self.channel_state() != (self.service_cursor,)*3:
                raise RuntimeError('mixed partial predecessor is not quiescent')
            self.evidence['reports_ack'] = self.ack_retired_reports(engine_masks=(1,2,4,6))
            if activate is not None:
                activate(self)
            from .g17g_render_buffers import ensure_render_buffers
            ensure_render_buffers(self, graph['parameters'])
            self.evidence['changed_caller_mappings'] = self.update_caller_mappings(caller_pages)
            self.flush_tables(self.context_id)
            self.evidence['command_publication_started'] = True
            self.state = 'publishing'
            from .g17g_resident_queue import prepare_render
            prepare_render(self, graph)
            from .g17g_compute_queue import write_pages
            missing = write_pages(graph['high'])-set(self.pages)
            if missing:
                self.map_globals(sorted(missing),fresh=True)
            self.publish_writes(graph['high'])
            states,ring = self.boot.fields['primary_main_fields']['channels'][12]
            slot = ring+self.service_cursor*g17g.SERVICE_RECORD_SIZE
            # All three service cursors were checked above. The next slot is
            # available even when its bytes retain a consumed prior record.
            next_service = backend.render_service_counter(self.service_cursor+1)
            self.publish_writes(((slot,graph['service_record']),(states[2],struct.pack('<I',next_service))))
            self.asces[0].send(0x0084000000000011,ASCMessage1(EP=0x21))
            wait_until(self.asces,lambda:self.channel_state()==(next_service,)*3,timeout,'mixed continuation service')
            self.service_cursor = next_service
            self.publish_writes(graph['release'])
            self.begin_render_pool(graph)
            before = self.completion(graph)
            self.evidence['completion_before'] = copy.deepcopy(before)
            after_retirement = self.expected_mixed_retirement(ordinal)
            self.asces[0].send(0x0083000000000008,ASCMessage1(EP=0x21))
            outcome = None
            def complete():
                nonlocal outcome
                if hasattr(self, 'tvb_pool'):
                    self.tvb_pool.step(before)
                after = self.completion(graph)
                self.evidence['completion_after'] = after
                outcome = self.partial_outcome(before, after)
                self.evidence['retirement_after'] = self.mixed_retirement()
                return outcome == 'fault' or (outcome in ('complete', 'out_of_memory') and
                                              self.evidence['retirement_after']==after_retirement)
            wait_until(self.asces,complete,timeout,'mixed partial continuation completion')
            if outcome == 'fault':
                self.raise_partial_fault(graph,'mixed-partial-continuation-report')
            self.render_completed = ordinal
            self.engine = 'partial'
            self.state = 'complete'
            if outcome == 'out_of_memory':
                self.raise_memory_limit(ordinal)
        except Exception as error:
            if not (isinstance(error, G17GPublishedFault) and error.kind == 'tvb-memory-limit' and
                    error.recoverable and self.state == 'complete' and
                    self.evidence.get('memory_limit_quiescent') is True):
                self.state = 'failed'
            self.evidence['error'] = '%s: %s' % (type(error).__name__,error)
            raise
        finally:
            self.evidence.update(state=self.state,elapsed=time.monotonic()-started)
        return self.evidence


    def prepare_compute_return(self, timeout):
        """Retire mixed TA/FR before admitting the retained compute queue."""
        ordinal = self.render_completed
        expected = self.expected_mixed_retirement(ordinal)
        if self.state != 'complete' or self.mixed_retirement() != expected:
            raise RuntimeError('compute return lacks a completed mixed render')
        cursor = self.service_cursor
        if self.channel_state() != (cursor,)*3:
            raise RuntimeError('compute return service ring is not quiescent')
        evidence = dict(render_completed=ordinal,compute_completed=self.completed,
                        reports=self.ack_retired_reports(engine_masks=(1,2,4,6)))
        states,ring = self.boot.fields['primary_main_fields']['channels'][12]
        address = ring+cursor*g17g.SERVICE_RECORD_SIZE
        self.evidence['command_publication_started'] = True
        record = g17g.build_service_opcode2e_record(self.completed+1,word_0c=1)
        next_service = backend.render_service_counter(cursor+1)
        self.publish_writes(((address,record),(states[2],struct.pack('<I',next_service))))
        self.asces[0].send(0x0084000000000011,ASCMessage1(EP=0x21))
        wait_until(self.asces,lambda:self.channel_state()==(next_service,)*3,timeout,'mixed compute return service')
        self.service_cursor = next_service
        evidence['service_cursor'] = self.service_cursor
        return evidence


    def raise_partial_fault(self, graph, kind):
        """Attribute only the reported fault in this command's owned VDM page."""
        fault = self.fault_status()
        self.evidence['fault_after'] = fault
        address = fault['address_raw'] << 6
        vdm = graph['parameters'].vdm_ctrl_stream_base
        if fault['faulted'] and vdm <= address < (vdm & -PAGE)+PAGE:
            self.evidence['fault_ordinal'] = graph.get('ordinal',1)
            raise G17GPublishedFault.command_fetch_mmu(**fault)
        raise G17GPublishedFault(kind,fatal=True,metadata=fault)


class G17GSharedComputeRuntime(G17GMixedRuntime):
    """Common control lifecycle for compute and later rendering."""
    def __init__(self, boot):
        G17GFirstComputeRuntime.__init__(self, boot)
        self.engine = 'compute'
        self.compute_history_count = 1

    def execute(self, graph, caller_pages, *, timeout=5, activate=None):
        result = super().execute(graph, caller_pages, timeout=timeout, activate=activate)
        self.mixed_layout = graph.get('mixed_layout', False)
        return result

    def publish(self, pages):
        from .g17g_boot import publish_pages
        return publish_pages(self.u, pages, coprocessor=True)

    def execute_wave(self, graph, caller_pages, *, timeout=5, activate=None):
        if 'records' in graph and 'format' not in graph:
            graph = dict(graph, format='m1n1-g17g-mixed-compute-wave-v1')
        return super().execute_wave(graph, caller_pages, timeout=timeout, activate=activate)
