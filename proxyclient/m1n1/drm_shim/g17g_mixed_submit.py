# SPDX-License-Identifier: GPL-2.0-only
"""Firmware-only compute-to-render construction for the mixed boot family.

Programs and resource/attachment contents remain opaque caller mappings. The
runtime owns the transition between these graphs; building one does not publish
work or imply execution. No experiment or caller asset builder is imported.
"""
from dataclasses import replace
import struct
from . import g17g_backend as backend, g17g_render as render, g17g_context1, g17g_compute as compute
from .g17g_submit import first_compute_graph
from .g17g_render_submit import first_render_graph

PAGE = 0x4000
MIXED_COMPUTE_LIMIT = 130
MIXED_RENDER_LIMIT = 860
# Retained render pool-A owns the original compute scheduler arena.
# Continued compute gets a disjoint page; the runtime allocates its backing.
MIXED_COMPUTE_SCHEDULER = 0xfffffc20c1200000


def expand(runs):
    return {base + index * PAGE for base, count, *_ in runs for index in range(count)}


def validate_mixed_compute_history(history, completed, count=1, *, queue_address=backend.COMPUTE_QUEUE_PAGE,
                                   previous_history=None, queue_completed=None, queue_id=0):
    """The mixed history slot retains the latest completed compute wave."""
    if (len(history) != PAGE or not 1 <= count <= completed <= MIXED_COMPUTE_LIMIT or
            (previous_history is not None and len(previous_history) != PAGE)):
        raise ValueError('mixed compute history extent changed')
    expected_tail = bytes(PAGE-count*0x40) if previous_history is None else previous_history[count*0x40:]
    if history[count*0x40:] != expected_tail:
        raise ValueError('mixed compute history tail extent changed')
    start = backend.compute_queue_start_ordinal(backend.compute_queue_epoch(completed))
    if completed-count+1 < start:
        raise ValueError('mixed compute history wave crosses queue lifetimes')
    for index,ordinal in enumerate(range(completed-count+1,completed+1)):
        words = struct.unpack_from('<8Q',history,index*0x40)
        descriptor = (backend.COMPUTE_DESCRIPTOR_PAGE if ordinal == 1 else
                      backend.compute_submission_addresses(ordinal)['descriptor'])
        # The scheduler selects bank0/1; a longer wave need not alternate.
        # Keep the exact ordinal/tag, supported bank range and owned pointers.
        local = (ordinal-start+1 if queue_completed is None else queue_completed-count+index+1)
        if (words[0] & ((1 << 56) - 1) != (local << 48) | (queue_id << 9) | 0x33 or
                words[0] >> 56 not in (0, 1) or words[1] != 0x20):
            raise ValueError('mixed compute history generation changed: %s, local=%d' %
                             (tuple(hex(word) for word in words), local))
        if words[6:] != (descriptor,queue_address):
            raise ValueError('mixed compute history owner changed')
        if not 0 < words[2] < words[3] < words[4] < words[5]:
            raise ValueError('mixed compute history interval changed')


def mixed_compute_graph(cdm_base, cdm_end, *, priority=2, user_timestamps=(0, 0), empty=False,
                        sampler_heap=0, sampler_count=0):
    graph = first_compute_graph(cdm_base, cdm_end, priority=priority,
                                user_timestamps=user_timestamps,
                                robustness=backend.COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS,
                                empty=empty, sampler_heap=sampler_heap, sampler_count=sampler_count)
    graph['context1_dvas'] = tuple(sorted(
        (set(graph['context1_dvas']) - expand(backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_REMOVED_RUNS))
        | expand(backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_ADDED_RUNS)))
    graph['context1_read_only_dvas'] = tuple(sorted(
        (set(graph['context1_read_only_dvas']) - expand(backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_REMOVED_RUNS))
        | expand(backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_ADDED_RUNS)))
    # Caller CDM/preemption placement is independent of the retained allocation
    # recipe. Never delete an explicitly owned private page through that recipe.
    graph['context1_dvas'] = tuple(sorted(set(graph['context1_dvas']) | set(graph['private_dvas'])))
    return graph


def mixed_partial_graph(params, *, priority=2):
    """First ordinary or partial work in the compute-predecessor allocation family."""
    params = replace(params, tiling_lifecycle=backend.COMPUTE_PREDECESSOR_RENDER_LIFECYCLE,
                     auxiliary_object=backend.COMPUTE_PREDECESSOR_PARTIAL_AUXILIARY_OBJECT)
    external_timestamps = any((params.tiling_user_timestamp_start,params.tiling_user_timestamp_end,
                               params.fragment_user_timestamp_start,params.fragment_user_timestamp_end))
    graph = first_render_graph(params,priority=priority,external_timestamps=external_timestamps)

    transport = backend.build_render_transport(params, mixed_compute_pending=True,
        compute_predecessor=True, descriptor_sequence_bias=1)
    low = dict(graph['context1_writes'])
    # The mixed auxiliary page is compiler/resource state supplied by the
    # caller; unlike standalone scratch it must not be zeroed by the driver.
    low.pop(params.auxiliary_object, None)
    low.pop(render.RENDER_BASE10_SUPPORT_DVA, None)
    for address in render.build_render_address_list_pages(operand_count=render.PARTIAL_RENDER_OPERAND_COUNT):
        low.pop(address, None)
    low.pop(render.RENDER_OPERAND_TABLE_DVA, None)
    low.update(render.build_render_address_list_pages(
        buffer_base=backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE,
        address_list_base=backend.COMPUTE_PREDECESSOR_PARTIAL_ADDRESS_LIST_BASE,
        operand_count=render.PARTIAL_RENDER_OPERAND_COUNT))
    low[backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_TABLE] = render.build_render_operand_table(
        buffer_base=backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE,
        operand_count=render.PARTIAL_RENDER_OPERAND_COUNT)
    extra = expand(backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_RUNS
                   + backend.COMPUTE_PREDECESSOR_PARTIAL_ZERO_RESERVATION_RUNS
                   + backend.COMPUTE_PREDECESSOR_PARTIAL_RETAINED_CONTEXT1_RUNS)
    excluded = expand(backend.COMPUTE_PREDECESSOR_PARTIAL_RETIRED_CONTEXT1_RUNS)
    aliases = dict(g17g_context1.POSTCONTROL_ALIASES)
    aliases.update(backend.COMPUTE_PREDECESSOR_PARTIAL_CONTEXT1_ALIASES)
    aliases = {low: high for low, high in aliases.items() if low not in excluded}
    for address in excluded | set(aliases):
        low.pop(address, None)
    dvas = (set(graph['context1_dvas']) | extra | set(low) | set(aliases)) - excluded
    caller_low = {0x1000000000, 0x1000018000, 0x1000048000, 0x1000058000, 0x1000068000}
    private = {dva for dva in dvas if dva < 0x10000000000 and dva not in caller_low} | set(low) | set(aliases)
    readonly = set(graph['context1_read_only_dvas']) - excluded
    for base, count, read_only in backend.COMPUTE_PREDECESSOR_PARTIAL_PERMISSION_RUNS:
        for address in range(base, base + count * PAGE, PAGE):
            if read_only:
                readonly.add(address)
            else:
                readonly.discard(address)
    graph.update(transport)
    graph.update(format='m1n1-g17g-mixed-partial-firmware-v1', parameters=params,
        context1_writes=low, context1_dvas=tuple(sorted(dvas)),
        context1_read_only_dvas=tuple(sorted(readonly)),
        context1_aliases=aliases, private_dvas=tuple(sorted(private)),
        completion_timestamps=None, completion_timestamp_addresses=None,
        work_lifecycle_qwords=backend.build_compute_predecessor_partial_render_work_lifecycle_qwords(),
        service_records=backend.build_compute_to_partial_render_service_records())
    from .g17g_barriers import record_binding
    layout = backend._mixed_render_layout(compute_predecessor=True)
    graph['dependency_jobs'] = (tuple(record_binding('late_global_pages', layout[kind+'_firmware_scratch'],
        0x200, generation=1) for kind in ('tiling', 'fragment')),)
    from .g17g_shim import G17GShimBackend
    return G17GShimBackend._retarget_submission_priority(graph, priority)


def mixed_partial_completion(before, after, *, pending_growth=False):
    """Mixed FR completion uses its initially clear descriptor mirror.

    The compute dispatch prefix and global time words are retained shared
    state. A clean report interval, final pool counter and fresh FR mirror are required; after
    report credit return, successful completions need not emit a new report.
    The runtime also requires both owned queues to retire before returning.
    """
    old, new = before['reports'], after['reports']
    if new['consumer'] != old['consumer']:
        raise ValueError('mixed report consumer changed owner')
    count = (new['producer'] - old['producer']) % 256
    if count > 2 or len(new['records']) != len(old['records']) + count:
        raise ValueError('unexpected mixed report interval')
    if new['records'][:len(old['records'])] != old['records']:
        raise ValueError('mixed prior reports changed')
    types = [struct.unpack_from('<I',bytes.fromhex(body))[0] for body in new['records']]
    if 4 in types:
        return 'fault'
    if any(kind not in ((1, 6) if pending_growth else (1,)) for kind in types):
        raise ValueError('unclassified mixed completion report')
    if 6 in types:
        return None
    initial_counter = struct.unpack('<I',bytes.fromhex(before['partial_completion']))[0]
    target_counter = before['partial_completion_target']
    if (initial_counter,target_counter) not in ((1,3),(0,2)):
        raise ValueError('mixed partial counter is not at its initial boundary')
    if struct.unpack('<I',bytes.fromhex(after['partial_completion']))[0] != target_counter:
        return None
    initial = bytes.fromhex(before['fragment_tail'])[0x7f:0x8f]
    if initial != bytes(16):
        raise ValueError('mixed FR descriptor mirror was not initially clear')
    start,end = struct.unpack_from('<2Q',bytes.fromhex(after['fragment_tail']),0x7f)
    return 'complete' if 0 < start <= end else None


def continued_mixed_partial_graph(params, ordinal, *, private_dvas, priority=2, transport_start=1):
    """Append a paired work group while retaining the mixed operand arena."""
    if not 2 <= ordinal <= MIXED_RENDER_LIMIT:
        raise NotImplementedError('mixed retained partial continuation exceeds its transport qualification')
    from . import g17g, g17g_postcontrol as post
    from .g17g_render_queue import transport_head
    head = transport_head(ordinal, transport_start)
    layout = backend._mixed_render_layout(compute_predecessor=True)
    slot = ordinal - 1
    params = replace(params,
        tiling_lifecycle=backend.COMPUTE_PREDECESSOR_RENDER_LIFECYCLE + slot*((2 << 32)+3),
        auxiliary_object=backend.COMPUTE_PREDECESSOR_PARTIAL_AUXILIARY_OBJECT)
    ta,fr = render.render_tiling_allocation_index(ordinal),render.render_fragment_allocation_index(ordinal)
    pa,pa_addr = render.render_pool_a_allocation(ordinal)
    pb, _standalone_address = render.render_pool_b_allocation(ordinal)
    pb_addr = layout['descriptor_objects'][2] - 0x80 + pb*0x80
    items = render.build_clear_work_items(params,layout['token'],
        submission_ordinal=ordinal,event_group=ordinal,optional_submission_ordinal=ordinal+1,
        optional_first_record=False,optional_context_id=layout['optional_context_id'],
        optional_secondary_context_id=layout['optional_secondary_context_id'],
        optional_lifecycle_ordinal=slot,queue_context_index=slot,
        submission_index=slot % render.RENDER_SUBMISSION_COUNTER_COUNT,parameter_index=slot % render.RENDER_PARAMETER_SLOT_COUNT,pool_a_index=pa,pool_b_index=pb,
        pool_a_address=pa_addr,pool_b_address=pb_addr,register_resource_index=pb,
        tiling_descriptor_index=ta,fragment_descriptor_index=fr,
        queue_indices=layout['queue_indices'],
        tiling_context_scratch=layout['tiling_context_scratch'],tiling_firmware_scratch=layout['tiling_firmware_scratch'],
        fragment_context_scratch=layout['fragment_context_scratch'],fragment_firmware_scratch=layout['fragment_firmware_scratch'],
        tiling_status_base=layout['tiling_status'],fragment_status_base=layout['fragment_status'],
        tiling_register_status_base=layout['tiling_register_status'],fragment_register_status_base=layout['fragment_register_status'],
        descriptor_objects=layout['descriptor_objects'],shared_control=layout['shared_control'],
        descriptor_resource_address_offset=layout['resource_address_offset'],
        descriptor_context_id=backend.RENDER_MIXED_CONTEXT_ID,descriptor_sequence_bias=1)
    addresses = dict(tiling_descriptor=backend.RENDER_TILING_DESCRIPTOR_PAGE+ta*render.TILING_DESCRIPTOR_SIZE,
                     fragment_descriptor=backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE+fr*render.FRAGMENT_DESCRIPTOR_SIZE)
    for kind in ('tiling','fragment'):
        addresses[kind+'_optional'] = layout[kind+'_optional']+(slot % render.RENDER_OPTIONAL_ITEM_PAIR_COUNT)*2*render.OPTIONAL_ITEM_SIZE
        addresses[kind+'_event'] = layout[kind+'_event']+(slot % render.RENDER_EVENT_ITEM_PAIR_COUNT)*2*render.EVENT_ITEM_SIZE
    writes = [(addresses[name],body) for name,body in items.items()]
    writes.extend(((pa_addr+8,struct.pack('<2Q',1,0x50)),(pb_addr+0x48,struct.pack('<Q',0x100000000))))
    releases = []
    for index,kind in enumerate(('tiling','fragment')):
        queue = post.QUEUE_PAGE+layout[kind+'_physical_queue_index']*g17g.QUEUE_RECORD_STRIDE
        writes.append(g17g.queue_priority_write(queue, priority))
        writes.extend(((layout[kind+'_item_ring']+(head-3)*8,
                        struct.pack('<3Q',*(addresses[kind+suffix] for suffix in ('_optional','_descriptor','_event')))),
                       (layout[kind+'_pointer']+0x40,struct.pack('<I',head)),
                       (backend.RENDER_CHANNEL_RING_PAGES[index]+backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[index]+(slot % backend.RENDER_CHANNEL_RING_SLOT_COUNT)*g17g.RING_SLOT_SIZE,
                        backend.build_render_stream_ring_slot(layout['queue_indices'][index],head,queue_address=queue,first_submit=False,engine_kind=index)),
                       (layout[kind+'_firmware_scratch']+render.render_queue_context_item_offset(slot % render.RENDER_QUEUE_CONTEXT_ITEM_COUNT),
                        render.build_render_queue_context_item(kind,addresses[kind+'_descriptor'],item_index=slot,descriptor_index=(ta,fr)[index],
                            queue_index=layout['queue_indices'][index],queue_address=queue,context_id=layout['scratch_context_id'])),
                       (layout[kind+'_status']+(slot % render.RENDER_SUBMISSION_COUNTER_COUNT)*0x40,bytes(0x40))))
        releases.append((backend.RENDER_STATE_PAGE+backend.RENDER_STATE_OFFSETS[index]+0x20,struct.pack('<I',backend.render_channel_counter(ordinal))))
    private_dvas = set(private_dvas)
    if params.buffers is not None:
        private_dvas.update(params.buffers.pages)
    from .g17g_barriers import high_record_binding
    jobs = (tuple(high_record_binding(writes, layout[kind+'_firmware_scratch'] +
        render.render_queue_context_item_offset(slot % render.RENDER_QUEUE_CONTEXT_ITEM_COUNT),
        generation=transport_start) for kind in ('tiling', 'fragment')),)
    return dict(format='m1n1-g17g-mixed-partial-continuation-v1',captured_input=None,
        dependency_jobs=jobs,
        parameters=params,ordinal=ordinal,transport_start=transport_start,items=items,firmware_addresses=addresses,
        high=tuple(writes),release=tuple(releases),private_dvas=tuple(private_dvas),
        completion_timestamps=None,completion_timestamp_addresses=None,
        service_record=g17g.build_service_opcode2e_record(ordinal),firmware_priority=priority)
