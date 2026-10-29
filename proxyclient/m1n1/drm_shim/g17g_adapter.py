# SPDX-License-Identifier: GPL-2.0-only
"""Modern UAPI to the independent G17G runtime, without test shader inputs.

Standalone compute, bounded ordinary render batches, and serialized
direct/partial submissions with reactive TVB allocation are integrated.
Compute, ordinary render and partial caller timestamp objects use directly
mapped caller backing in the firmware timestamp aperture. Command types select
bounded compute and ordinary/partial-render sequences in any order,
including render-first groups within one ioctl. Standalone partial
work handles bounded TVB exhaustion with attributed ENOMEM and later recovery.
LOW/MEDIUM priority changes are applied only after predecessor retirement.
Render VMs keep private roots and payloads. Retained ordinary and mixed
allocators share their address-record rings; partial warm-up retirement keeps
the preceding VM's arena until its service consumes it.
Full UAPI coverage still requires the remaining hardware qualifications.
"""
import errno
import math
from dataclasses import replace

from .g17g_memory import G17GMemoryAdapter
from .g17g_mixed_runtime import G17GSharedComputeRuntime
from .g17g_submit import first_compute_graph
from .g17g_compute_queue import compute_waves, write_pages
from .g17g_sync import G17GPublishedFault, G17GSoftwareFence, G17GSubmissionFence, G17GWorkError
from .g17g_uapi import DRM_ASAHI_CMD_COMPUTE, DRM_ASAHI_CMD_RENDER
from .g17g_sparse_read import SparseRead
from .g17g_transfer import write_publications
from .g17g_context import G17GComputeContext
from .g17g_timestamp import G17GTimestampMappings

class G17GHardwareAdapter(G17GMemoryAdapter):
    def __init__(self, boot, backing_fd, *, timeout=5.0, tvb_growth=True, tvb_max_blocks=None):
        if type(tvb_growth) is not bool:
            raise ValueError("TVB allocation policy must be boolean")
        if tvb_max_blocks is not None and (type(tvb_max_blocks) is not int or
                not 3 <= tvb_max_blocks <= 2048 or not tvb_growth or boot.profile == "mixed"):
            raise ValueError("TVB memory limit requires standalone reactive allocation")
        super().__init__(boot.u, backing_fd)
        # Driver allocation policy, not a new userspace command field.
        self.tvb_growth = tvb_growth
        self.tvb_max_blocks = tvb_max_blocks
        self.boot, self.timeout = boot, timeout
        if boot.profile == "mixed":
            from .g17g_mixed_runtime import G17GMixedRuntime
            self.runtime = G17GMixedRuntime(boot)
        else:
            self.runtime = G17GSharedComputeRuntime(boot)
        self.device_lost = False
        self.last_graph = None
        self.last_wave = None
        self.last_waves = ()
        self.owner_vm = None
        self.owner_priority = None
        self.contexts = {}
        self.queues = {}
        self.timestamps = G17GTimestampMappings(self)
        self.sparse_reader = SparseRead(self.u, self.iface)
        self.readback_transport = self.sparse_reader.read
        self.upload_transport = lambda pa, body: write_publications(self.u, self.p, self.iface, ((pa, body),))

    def context_owner(self, vm):
        owner = self.contexts.get(id(vm))
        if owner is None:
            used = {item.slot for item in self.contexts.values() if not item.destroyed}
            slot = next((slot for slot in range(1, 64) if slot not in used), None)
            if slot is None:
                raise OSError(errno.ENOSPC, 'all resident GPU context slots are owned')
            owner = self.contexts[id(vm)] = G17GComputeContext(self.runtime, vm, slot)
        owner.assert_live()
        return owner

    def bind_object(self, file, obj):
        return self.timestamps.bind(file, obj)

    def queue_owner(self, queue):
        from .g17g_resident_queue import G17GResidentQueue
        owner = self.queues.get(id(queue))
        if owner is None:
            # Each owner reserves three IDs. The integrated render report
            # service currently supports the low 32 notification bits.
            if len(self.queues) >= 32//3:
                raise OSError(errno.ENOSPC, 'resident firmware queue namespace exhausted')
            owner = self.queues[id(queue)] = G17GResidentQueue(len(self.queues))
            owner.logical_queue = queue
        if owner.destroyed:
            raise RuntimeError('cannot submit a destroyed firmware queue')
        return owner

    def destroy_queue(self, file, queue):
        owner = self.queues.get(id(queue))
        if owner is not None:
            owner.destroyed = True

    def unbind_object(self, file, obj):
        return self.timestamps.unbind(file, obj)

    def destroy_vm(self, file, vm):
        owner = self.contexts.get(id(vm))
        if owner is None:
            owner = self.context_owner(vm)
        result = owner.destroy()
        if self.owner_vm is vm:
            self.owner_vm = None
        return result

    def preflight_mixed(self, file, queue, commands):
        from itertools import groupby
        from . import g17g_backend as backend
        from .g17g_compute_queue import compute_waves
        from .g17g_mixed_submit import (mixed_compute_graph, mixed_partial_graph,
            continued_mixed_partial_graph, MIXED_COMPUTE_LIMIT, MIXED_RENDER_LIMIT,
            MIXED_COMPUTE_SCHEDULER)
        from .g17g_render_submit import render_parameters
        from .g17g_render_buffers import next_render_buffer_base
        from .g17g_render_queue import CAPACITY as RENDER_CAPACITY
        if not commands:
            raise ValueError("mixed submit requires commands")
        self.runtime.tvb_max_blocks = self.tvb_max_blocks if self.tvb_growth else None
        priority = 3 if queue.priority == 0 else 2
        counts = {kind: sum(item.header.cmd_type == kind for item in commands)
                  for kind in (DRM_ASAHI_CMD_COMPUTE, DRM_ASAHI_CMD_RENDER)}
        if sum(counts.values()) != len(commands):
            raise NotImplementedError("unsupported mixed command type")
        if self.runtime.state == 'new':
            completed, rendered = 0, 0
        elif self.runtime.state == 'complete' and self.runtime.engine in ('compute', 'partial'):
            completed = self.runtime.completed
            rendered = getattr(self.runtime, 'render_completed', 0)
        else:
            raise NotImplementedError("mixed continuation requires a completed engine")
        if completed + counts[DRM_ASAHI_CMD_COMPUTE] > MIXED_COMPUTE_LIMIT:
            raise NotImplementedError("mixed compute exceeds its retained transport qualification")
        if rendered + counts[DRM_ASAHI_CMD_RENDER] > MIXED_RENDER_LIMIT:
            raise NotImplementedError("mixed partial work exceeds its retained transport qualification")
        for command in commands:
            if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE:
                state = command.hardware_state
                if state.helper_binary:
                    raise NotImplementedError("compute helpers are unsupported on G17G")

        # Plan the entire ordered submit before publication. Local counters
        # describe future waves without modifying the retained runtime owner.
        if self.runtime.state == 'new' and commands[0].header.cmd_type == DRM_ASAHI_CMD_COMPUTE:
            command = commands[0]
            state = command.hardware_state
            graph = mixed_compute_graph(state.cdm_base, state.cdm_end, priority=priority,
                                        user_timestamps=self.timestamps.compute_pointers(command),
                                        sampler_heap=state.sampler_heap, sampler_count=state.sampler_count)
            graph['mixed_layout'] = True
            completed, pending, addresses = 1, commands[1:], graph['addresses']
        elif self.runtime.state == 'new':
            graph = mixed_compute_graph(None, None, priority=priority, empty=True)
            graph['mixed_layout'] = True
            pending, addresses = commands, graph['addresses']
        else:
            graph = dict(private_dvas=tuple(sorted(self.runtime.private_dvas)))
            pending, addresses = commands, self.runtime.queue_addresses
            if not getattr(self.runtime, 'mixed_layout', self.boot.profile == 'mixed'):
                retired = {backend.COMPUTE_ROBUSTNESS}
                graph['private_dvas'] = tuple(dva for dva in graph['private_dvas'] if dva not in retired)
        # The first-admission compute scheduler shares the render pool-A arena.
        # Continued compute needs independent records while that pool is live.
        if completed <= backend.COMPUTE_QUEUE_COMMAND_CAPACITY:
            addresses = dict(addresses, scheduler=MIXED_COMPUTE_SCHEDULER)
        private = set(graph['private_dvas'])
        waves = []
        render_transport_start = getattr(self.runtime, 'render_transport_start', 1)
        for kind, group in groupby(pending, key=lambda item: item.header.cmd_type):
            group = tuple(group)
            if kind == DRM_ASAHI_CMD_COMPUTE:
                compute_groups = compute_waves(tuple((item.hardware_state.cdm_base, item.hardware_state.cdm_end)
                                          for item in group), completed, addresses, priority=priority,
                    user_timestamps=tuple(self.timestamps.compute_pointers(item) for item in group),
                    robustness_base=backend.COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS,
                    samplers=tuple((item.hardware_state.sampler_heap, item.hardware_state.sampler_count)
                                   for item in group))
                for wave in compute_groups:
                    wave['format'] = 'm1n1-g17g-mixed-compute-wave-v1'
                    private.update(write_pages(wave['low']))
                    waves.append(wave)
                completed, addresses = wave['final'], wave['addresses']
            else:
                for command in group:
                    if rendered-render_transport_start+1 == RENDER_CAPACITY:
                        render_transport_start = rendered+1
                    params = render_parameters(command.hardware_state,
                        buffer_base=next_render_buffer_base(private))
                    params = replace(params,
                        request_tvb_growth=self.tvb_growth and params.partial_mode,
                        fragment_sync_grow=self.runtime.tvb_max_blocks is not None,
                        **self.timestamps.render_pointers(command))
                    wave = (continued_mixed_partial_graph(params, rendered + 1,
                                private_dvas=private, priority=priority,
                                transport_start=render_transport_start) if rendered else
                            mixed_partial_graph(params, priority=priority))
                    private.update(wave['private_dvas'])
                    rendered += 1
                    waves.append(wave)
        reserved = tuple(sorted(private))
        graph['private_dvas'] = reserved
        for wave in waves:
            if 'private_dvas' in wave:
                wave['private_dvas'] = reserved
        self.context_owner(queue.vm)
        from .g17g_barriers import apply_submission_barriers
        apply_submission_barriers(commands, graph, waves)
        self.last_graph, self.last_waves = graph, tuple(waves)
        self.last_wave = waves[-1] if waves else None

    def uses_mixed_layout(self, queue, commands):
        """Admit rendering to the shared transport, then retain that family.

        Compute-only queues keep their existing transport capacity. BO contents
        and placement never select an engine or an allocation family.
        """
        if self.boot.profile == 'mixed':
            return True
        if not isinstance(self.runtime, G17GSharedComputeRuntime):
            return False
        if getattr(self.runtime, 'mixed_layout', False):
            return True
        return any(command.header.cmd_type == DRM_ASAHI_CMD_RENDER for command in commands)

    def preflight(self, file, queue, commands):
        queue_owner = self.queue_owner(queue)
        # Preflight may plan several queues before the first publication. The
        # boot transport belongs to whichever queue actually submits first.
        if self.runtime.state == 'new' and queue_owner.index:
            first = next(item for item in self.queues.values() if item.index == 0)
            first.index, first.compute_id = queue_owner.index, queue_owner.compute_id
            queue_owner.index, queue_owner.compute_id = 0, 0
        self._preflight(file, queue, commands)
        owner = self.context_owner(queue.vm)
        graph = self.last_graph
        from .g17g_compute_queue import transport_state
        if self.runtime.state == 'new' and 'firmware_objects' in graph:
            graph['resident_queue'] = queue_owner
            graph['resident_completed'] = graph['compute_descriptor_count']
            completed = graph['resident_completed']
            previous = transport_state(completed)
            previous_addresses = graph['addresses']
        else:
            completed = queue_owner.completed
            previous = getattr(self.runtime, 'compute_retirement', transport_state(self.runtime.completed))
            previous_addresses = getattr(self.runtime, 'queue_addresses', None)
        for wave in self.last_waves:
            if 'low' not in wave or 'retirement_after' not in wave:
                continue
            if len(self.queues) > 1:
                completed = queue_owner.bind_compute_wave(wave, completed, previous)
                wave['previous_addresses'] = previous_addresses
            else:
                completed += len(wave['records'])
                wave.update(resident_queue=queue_owner, resident_completed=completed)
            previous = wave['retirement_after']
            previous_addresses = wave['addresses']
        self.runtime.context_id, self.runtime.layout = owner.slot, owner.layout
        graphs, seen = [], set()
        def visit(graph):
            if id(graph) in seen:
                return
            seen.add(id(graph))
            graphs.append(graph)
            if graph.get('format') == 'm1n1-g17g-render-wave-v1':
                for record in graph['records']:
                    visit(record)
        for graph in (self.last_graph, *self.last_waves):
            visit(graph)
        from .g17g_resident_queue import bind_render_graph
        rendered = getattr(queue_owner, 'render_completed', 0)
        for graph in graphs:
            if 'items' in graph and 'parameters' in graph:
                rendered = bind_render_graph(queue_owner, graph, rendered, route=len(self.queues)>1)
        # Re-resolve explicit barriers after assigning the actual queue values.
        from .g17g_barriers import apply_submission_barriers, bound_record, with_dependencies
        for graph in graphs:
            for bindings in graph.get('dependency_jobs', ()):
                original = bound_record(graph, bindings[0])
                bound_record(graph, bindings[0], with_dependencies(original, (), replace=True))
        apply_submission_barriers(commands, self.last_graph, self.last_waves)
        owner.layout.describe(graphs)
        for graph in graphs:
            owner.layout.transform_graph(graph, owner.slot)

    def _preflight(self, file, queue, commands):
        if self.device_lost:
            raise OSError(errno.ENODEV, "G17G GPU reset required")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("compute timeout must be finite and positive")
        if self.uses_mixed_layout(queue, commands):
            return self.preflight_mixed(file, queue, commands)
        render_command = 1 <= len(commands) <= 64 and all(command.header.cmd_type == DRM_ASAHI_CMD_RENDER for command in commands)
        if render_command:
            from .g17g_render_submit import first_render_graph, continued_render_graph, render_parameters, RENDER_TRANSPORT_CAPACITY
            from .g17g_render_batch import render_wave
            from .g17g_render_runtime import G17GFirstRenderRuntime
            from .g17g_render_buffers import next_render_buffer_base
            planned_private = set() if self.runtime.state == "new" else set(self.runtime.private_dvas)
            params = []
            for command in commands:
                item = render_parameters(command.hardware_state,
                    buffer_base=next_render_buffer_base(planned_private))
                if item.buffers is not None:
                    planned_private.update(item.buffers.pages)
                params.append(item)
            params = tuple(params)
            params = tuple(replace(item, **self.timestamps.render_pointers(command)) if command.timestamp_objects else item
                           for item, command in zip(params, commands))
            params = tuple(replace(item, request_tvb_growth=self.tvb_growth) if item.partial_mode else item
                           for item in params)
            if self.tvb_max_blocks is not None and self.tvb_growth:
                params = tuple(replace(item, fragment_sync_grow=True) if item.partial_mode else item
                               for item in params)
            partial = any(item.partial_mode for item in params)
            live_partial = getattr(self.runtime, "partial_mode", False)
            if (any(item.partial_mode != partial for item in params) or
                    (self.runtime.state != "new" and
                     (partial != live_partial or (partial and not 1 <= self.runtime.completed < 0xffff)))):
                raise NotImplementedError("partial continuation integration pending")
            minimal_partial = getattr(self.runtime, "minimal_partial_continuation", False) is True
            waves = []
            if self.runtime.state == "new":
                graph = first_render_graph(params[0], priority=3 if queue.priority == 0 else 2,
                                           private_completion=params[0].partial_mode,
                                           external_timestamps=bool(commands[0].timestamp_objects))
                self.select_unstarted_runtime(G17GFirstRenderRuntime)
                self.runtime.tvb_max_blocks = self.tvb_max_blocks if self.tvb_growth else None
                completed, remaining = 1, params[1:]
                private = set(graph["private_dvas"]) | planned_private
            elif (type(self.runtime) is G17GFirstRenderRuntime and self.runtime.state == "complete"
                  and 1 <= self.runtime.completed < 0xffff):
                completed, remaining = self.runtime.completed, params
                private = set(self.runtime.private_dvas) | planned_private
                graph = None
            else:
                raise NotImplementedError("render engine transition is not integrated")
            if completed + len(remaining) >= 0x10000:
                raise NotImplementedError("render logical ordinal exceeds its namespace")
            transport_start = getattr(self.runtime, "transport_start", 1)
            if completed - transport_start + 1 == RENDER_TRANSPORT_CAPACITY:
                transport_start = completed + 1
            if completed == 1 and remaining:
                if partial:
                    from .g17g_backend import expand_second_direct_render_context1_dvas
                    private.update(expand_second_direct_render_context1_dvas())
                waves.append(continued_render_graph(remaining[0], 2, private_dvas=private,
                    priority=3 if queue.priority == 0 else 2))
                completed, remaining = 2, remaining[1:]
                # The source's work-two service establishes the retained
                # lifecycle before later commands in this same ioctl run.
                # Planning must use that future state, not the pre-ioctl flag.
                minimal_partial = partial
            while partial and remaining and (completed < 5 or len(remaining) == 1 or self.tvb_growth):
                from .g17g_partial_runtime import warmup_dvas
                if completed - transport_start + 1 == RENDER_TRANSPORT_CAPACITY:
                    transport_start = completed + 1
                if completed < 5:
                    private.update(warmup_dvas(completed + 1))
                waves.append(continued_render_graph(remaining[0], completed + 1,
                    private_dvas=private, priority=3 if queue.priority == 0 else 2,
                    retain_partial_slot=not minimal_partial,
                    transport_start=transport_start))
                completed, remaining = completed + 1, remaining[1:]
            while remaining:
                if completed - transport_start + 1 == RENDER_TRANSPORT_CAPACITY:
                    transport_start = completed + 1
                if len(self.queues) > 1:
                    waves.append(continued_render_graph(remaining[0], completed+1, private_dvas=private,
                        priority=3 if queue.priority == 0 else 2, retain_partial_slot=not partial,
                        transport_start=transport_start))
                    completed, remaining = completed+1, remaining[1:]
                    continue
                limit = min(64 if partial else 32, RENDER_TRANSPORT_CAPACITY - (completed - transport_start + 1))
                part, remaining = remaining[:limit], remaining[limit:]
                waves.append(render_wave(part, completed, private_dvas=private,
                    priority=3 if queue.priority == 0 else 2, transport_start=transport_start))
                completed += len(part)
            waves = tuple(waves)
            if graph is None:
                graph = waves[0]
        elif not 1 <= len(commands) <= 64 or any(command.header.cmd_type != DRM_ASAHI_CMD_COMPUTE for command in commands):
            raise NotImplementedError("adapter requires compute commands or one first render")
        for command in commands:
            state = command.hardware_state
            if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE and state.helper_binary:
                raise NotImplementedError("compute helpers are unsupported on G17G")
        bounds = tuple((command.hardware_state.cdm_base, command.hardware_state.cdm_end)
                       for command in commands if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE)
        stamps = tuple(self.timestamps.compute_pointers(command) for command in commands
                       if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE)
        samplers = tuple((command.hardware_state.sampler_heap, command.hardware_state.sampler_count)
                         for command in commands if command.header.cmd_type == DRM_ASAHI_CMD_COMPUTE)
        if render_command:
            pass
        elif self.runtime.state == "new":
            self.select_unstarted_runtime(G17GSharedComputeRuntime)
            graph = first_compute_graph(*bounds[0], priority=3 if queue.priority == 0 else 2,
                                        user_timestamps=stamps[0], sampler_heap=samplers[0][0],
                                        sampler_count=samplers[0][1])
            waves = compute_waves(bounds[1:], 1, graph["addresses"], priority=3 if queue.priority == 0 else 2,
                                  user_timestamps=stamps[1:], samplers=samplers[1:])
            private = set(graph["private_dvas"])
        elif self.runtime.state == "complete":
            if type(self.runtime) is not G17GSharedComputeRuntime:
                raise NotImplementedError("mixed render/compute runtime integration pending")
            waves = compute_waves(bounds, self.runtime.completed, self.runtime.queue_addresses,
                                  priority=3 if queue.priority == 0 else 2, user_timestamps=stamps,
                                  samplers=samplers)
            graph = waves[0]
            private = self.runtime.private_dvas
        else:
            raise NotImplementedError("failed compute continuation requires reset")
        self.context_owner(queue.vm)
        for wave in waves:
            private = private | write_pages(wave["low"])
        graph["private_dvas"] = tuple(sorted(private))
        self.last_graph = graph
        from .g17g_barriers import apply_submission_barriers
        apply_submission_barriers(commands, graph, waves)
        self.last_waves = waves
        self.last_wave = waves[-1] if waves else None

    def select_unstarted_runtime(self, runtime_class):
        if type(self.runtime) is runtime_class:
            return
        if self.runtime.state != "new" or any(owner.record is not None for owner in self.contexts.values()):
            raise RuntimeError("cannot replace a published runtime")
        self.runtime = runtime_class(self.boot)
        for owner in self.contexts.values():
            owner.runtime = self.runtime

    def prepare_submission(self, file, queue, commands):
        """Allocate pending fences before any job becomes firmware-visible.

        The UAPI owner attaches the BOs, queue and output syncs before calling
        submit. Completion may then occur immediately without racing ownership.
        """
        slot = self.context_owner(queue.vm).slot
        children = tuple(G17GSoftwareFence(metadata=dict(engine=engine, firmware_context_id=slot))
            for command in commands for engine in (
                ("ta", "fragment") if command.header.cmd_type == DRM_ASAHI_CMD_RENDER else ("compute",)))
        return G17GSubmissionFence(children, name="G17G UAPI submission")

    def submit(self, file, queue, commands, *, fence=None):
        # Rebuild/revalidate at the real ownership boundary, after input waits.
        self.preflight(file, queue, commands)
        graph = self.last_graph
        owner = self.context_owner(queue.vm)
        continuing = self.runtime.state == "complete"
        pages = self.materialize(queue.vm,
                                 allow_owner=owner)
        objects = self.timestamps.objects(commands)
        self.timestamps.materialize(objects)
        if not continuing:
            graph["context1_dvas"] = tuple(sorted(set(graph["context1_dvas"]) | set(pages)))
        fence = self.prepare_submission(file, queue, commands) if fence is None else fence
        children = fence.fences
        if fence.signaled() or len(children) != sum(
                2 if command.header.cmd_type == DRM_ASAHI_CMD_RENDER else 1 for command in commands):
            raise ValueError('submission fence does not name the pending hardware jobs')
        attempts = []
        transition = None
        self.runtime.evidence["command_publication_started"] = False
        try:
            if (continuing and self.uses_mixed_layout(queue, commands) and
                    not getattr(self.runtime, 'mixed_layout', self.boot.profile == 'mixed')):
                self.runtime.adopt_mixed_layout()
            if not continuing:
                self.runtime.execute(graph, pages, timeout=self.timeout,
                                     activate=lambda _runtime: self.activate(queue.vm, owner))
                from .g17g_resident_queue import commit_render
                commit_render(self.runtime, graph)
                owner.record = self.runtime.context
                attempts.append(dict(self.runtime.evidence))
                self.owner_vm, self.owner_priority = queue.vm, queue.priority
            elif self.owner_vm is not queue.vm:
                # Keep inactive VMs' bindings pinned to their own root owner,
                # not to whichever context happens to be selected currently.
                self.runtime.evidence["command_publication_started"] = True
                self.activate(queue.vm, owner, allow_existing=True)
                if owner.record is None:
                    if self.uses_mixed_layout(queue, commands):
                        owner.record = self.runtime.prepare_mixed_context(pages)
                    elif commands[0].header.cmd_type == DRM_ASAHI_CMD_RENDER:
                        from .g17g_render_submit import first_render_graph, render_parameters
                        initial = first_render_graph(render_parameters(commands[0].hardware_state),
                            priority=3 if queue.priority == 0 else 2)
                        owner.record = self.runtime.prepare_render_context(initial, pages, install=False)
                    else:
                        initial = first_compute_graph(commands[0].hardware_state.cdm_base,
                            commands[0].hardware_state.cdm_end, priority=3 if queue.priority == 0 else 2)
                        initial["context1_dvas"] = tuple(sorted(set(initial["context1_dvas"]) | set(pages)))
                        owner.record = self.runtime.prepare_context(initial, pages, install=False)
                elif self.uses_mixed_layout(queue, commands):
                    self.runtime.prepare_mixed_render_context(owner.record, pages)
                from .g17g_render_runtime import G17GFirstRenderRuntime
                if getattr(self.runtime, "partial_mode", False) and type(self.runtime) is G17GFirstRenderRuntime:
                    from .g17g_partial_runtime import prepare_partial_context
                    prepare_partial_context(self.runtime, owner.record, self.runtime.completed + 1)
                    self.runtime.render_context_switches = getattr(self.runtime, "render_context_switches", 0) + 1
                if hasattr(self.runtime, "tvb_pool"):
                    self.runtime.tvb_pool.prepare_context(owner.record)
                transition = self.runtime.select_context(owner.record)
                self.owner_vm = queue.vm
            for wave in self.last_waves:
                self.runtime.execute_wave(wave, pages, timeout=self.timeout,
                    activate=lambda _runtime: self.activate(queue.vm, owner, allow_existing=True))
                from .g17g_resident_queue import commit_render
                commit_render(self.runtime, wave)
                attempts.append(dict(self.runtime.evidence))
            if objects:
                self.pull(queue.vm, objects=objects)
            else:
                self.pull(queue.vm)
            for child in children:
                child.signal()
            self.owner_priority = queue.priority
        except Exception as error:
            self.runtime.evidence['error'] = '%s: %s' % (type(error).__name__, error)
            if not self.runtime.evidence.get("command_publication_started"):
                raise
            recovered = (isinstance(error, G17GPublishedFault) and
                error.kind == "tvb-memory-limit" and error.error == G17GWorkError.OUT_OF_MEMORY and
                error.recoverable and not error.fatal and self.runtime.state == "complete" and
                self.runtime.evidence.get("memory_limit_quiescent") is True)
            if recovered:
                # The source type7/type9 abort can follow partial stores and
                # completed timestamp writes. At proven quiescence those
                # bytes belong to the caller even though its fence is ENOMEM.
                # Leaving stale shared BOs here also uploads stale data on the
                # next independent submit. Readback is a driver obligation.
                try:
                    if objects:
                        self.pull(queue.vm, objects=objects)
                    else:
                        self.pull(queue.vm)
                except Exception as readback_error:
                    self.runtime.evidence['failed_readback'] = dict(
                        error=str(readback_error), completed_fault=error.snapshot())
                    error = readback_error
                    recovered = False
            if recovered:
                from .g17g_resident_queue import commit_render
                commit_render(self.runtime, self.last_wave or graph)
                self.owner_vm, self.owner_priority = queue.vm, queue.priority
            else:
                self.device_lost = True
                self.runtime.state = "failed"
            code = (int(error.error) if isinstance(error, G17GPublishedFault)
                    else int(G17GWorkError.TIMEOUT) if isinstance(error, TimeoutError)
                    else int(G17GWorkError.CHANNEL))
            # Fatal publications retain mapped backing until reset. A proved
            # quiescent memory-limit failure permits subsequent independent
            # work, while this fence keeps its error.
            fence.fail(code, reason=str(error))
            if isinstance(error, G17GPublishedFault):
                fence.metadata["fault"] = error.snapshot()
        finally:
            # First admission can fail after the roots are installed. Keep its
            # BO owner associated with those roots even on a fatal error fence.
            if not continuing and self.runtime.context is not None:
                owner.record = self.runtime.context
        fence.metadata.update(runtime=dict(self.runtime.evidence),
                              runtime_attempts=attempts,
                              caller_upload=dict(getattr(self, "last_upload", {})),
                              caller_readback=dict(getattr(self, "last_readback", {})),
                              readback_wire_bytes=self.sparse_reader.wire_bytes,
                              context_switch=transition,
                              firmware_context_id=owner.slot, device_lost=self.device_lost,
                              kernel_range=(owner.layout.start, owner.layout.end),
                              private_pages=len(owner.layout.primary),
                              resident_slots=sorted(self.runtime.resident_contexts),
                              firmware_queues=dict(compute=self.queue_owner(queue).compute_id,
                                  render=[item['qid'] for item in getattr(self.queue_owner(queue), 'render_addresses', ())]))
        return fence
