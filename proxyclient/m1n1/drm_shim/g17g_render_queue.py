# SPDX-License-Identifier: GPL-2.0-only
"""Recreate only the finite paired render transport after quiescence."""
import struct

from . import g17g, g17g_backend as backend, g17g_compute, g17g_postcontrol as post, g17g_uat
from .g17g_transfer import write_publications

PAGE = 0x4000
CAPACITY = backend.RENDER_INNER_RING_ITEM_COUNT // 3


def transport_head(completed, start=1):
    if (type(completed) is not int or type(start) is not int or
            not 1 <= start <= completed + 1 <= 0x10000 or
            completed - start + 1 > CAPACITY):
        raise ValueError("render transport interval exceeds its finite ring")
    return (completed - start + 1) * 3


def transport_pages(token):
    queue = bytearray(PAGE)
    for index in range(2):
        body = g17g_compute.build_compute_queue_record(
            post.POINTER_BLOCK_ADDRESSES[index], post.ITEM_RING_ADDRESSES[index],
            post.QUEUE_ADDRESS_10_PAGE, post.QUEUE_ADDRESS_70_PAGE, token)
        offset = index * g17g.QUEUE_RECORD_STRIDE
        queue[offset:offset + len(body)] = body
        struct.pack_into("<I", queue, offset + g17g.QUEUE_LIMIT_OFFSET, 0)
    pointers = bytearray(PAGE)
    body = g17g.build_pointer_block(field_00=0, field_30=0, field_40=0)
    for address in post.POINTER_BLOCK_ADDRESSES:
        offset = address - post.QUEUE_POINTER_PAGE
        pointers[offset:offset + len(body)] = body
    return {post.QUEUE_PAGE: bytes(queue), post.QUEUE_POINTER_PAGE: bytes(pointers),
            post.QUEUE_ITEM_RING_PAGE: bytes(PAGE), post.QUEUE_ITEM_RING_PAGE + PAGE: bytes(PAGE)}


def mixed_transport_addresses():
    return (post.QUEUE_PAGE, post.QUEUE_POINTER_PAGE, post.QUEUE_POINTER_PAGE + PAGE,
            post.QUEUE_ITEM_RING_PAGE, post.QUEUE_ITEM_RING_PAGE + PAGE)


def mixed_transport_pages(owned):
    """Replace TA1/FR2 records in copies of quiescent, host-owned live pages.

    Compute0 shares the queue, pointer and item-ring pages. Every byte outside
    the two render queues' explicit extents must survive their replacement.
    """
    if set(owned) != set(mixed_transport_addresses()) or any(len(b) != PAGE for b in owned.values()):
        raise ValueError('mixed recreation requires five complete owned transport pages')
    pages = {dva: bytearray(body) for dva, body in owned.items()}
    def put(address, body):
        while body:
            count = min(len(body), PAGE-address%PAGE)
            pages[address & -PAGE][address%PAGE:address%PAGE+count] = body[:count]
            address, body = address+count, body[count:]
    layout = backend._mixed_render_layout(compute_predecessor=True)
    for kind in ('tiling', 'fragment'):
        queue_address = post.QUEUE_PAGE+layout[kind+'_physical_queue_index']*g17g.QUEUE_RECORD_STRIDE
        queue = bytearray(g17g_compute.build_compute_queue_record(
            layout[kind+'_pointer'], layout[kind+'_item_ring'],
            post.QUEUE_ADDRESS_10_PAGE, post.QUEUE_ADDRESS_70_PAGE, layout['token']))
        struct.pack_into('<I', queue, g17g.QUEUE_LIMIT_OFFSET, 0)
        offset = queue_address % PAGE
        # Keep the complete five-field priority family from this owned queue.
        queue[0x28:0x40] = owned[post.QUEUE_PAGE][offset+0x28:offset+0x40]
        put(queue_address, queue)
        put(layout[kind+'_pointer'], g17g.build_pointer_block(field_00=0, field_30=0, field_40=0))
        put(layout[kind+'_item_ring'], bytes(backend.RENDER_INNER_RING_ITEM_COUNT*8))
    return {dva: bytes(body) for dva, body in pages.items()}


def recreate_transport(runtime, start, *, mixed=False):
    """Keep old backing owned; replace render pages and preserve context.

    Completion witnesses belong to the preceding submissions. This transition
    checks their quiescent transport and ownership before replacing any leaf;
    it does not infer execution from empty rings.
    """
    start_attribute = 'render_transport_start' if mixed else 'transport_start'
    prior_start = getattr(runtime, start_attribute, 1)
    completed = runtime.render_completed if mixed else runtime.completed
    retirement = runtime.mixed_retirement if mixed else runtime.retirement
    if (runtime.state != "complete" or runtime.boot.submission_owner is not runtime or
            start != completed + 1 or start <= prior_start):
        raise RuntimeError("render transport recreation lacks its completed owner")
    head = transport_head(completed, prior_start)
    counter = backend.render_channel_counter(completed)
    expected = dict(queue=[head] * 2, pointers=[[head] * 3] * 2, channels=[[counter] * 3] * 2)
    evidence = dict(prior_start=prior_start, start=start, rebinds=[])
    runtime.evidence["transport_recreation"] = evidence
    def phase(name):
        evidence["phase"] = name
        observer = getattr(runtime, "observe", None)
        if observer is not None:
            observer("render-transport-" + name)
    phase("quiescence")
    evidence["before"] = retirement()
    if evidence["before"] != expected or runtime.channel_state() != (runtime.service_cursor,) * 3:
        raise RuntimeError("render transport recreation is not quiescent")
    phase("reports")
    # Validate pending firmware reports through owned RAM, as at ordinary
    # batch boundaries. A healthy idle boundary does not require SGX MMIO.
    evidence["reports"] = (runtime.ack_retired_reports(engine_masks=(1,2,4,6)) if mixed
                           else runtime.ack_retired_reports())
    phase("ownership")
    if mixed:
        from .g17g_compute_queue import transport_state
        compute_graph = dict(addresses=runtime.queue_addresses)
        evidence['compute_before'] = runtime.retirement_state(compute_graph)
        if evidence['compute_before'] != getattr(runtime, 'compute_retirement', transport_state(runtime.completed)):
            raise RuntimeError('mixed recreation requires the retained compute queue to be quiescent')
        addresses = mixed_transport_addresses()
    else:
        bodies = transport_pages(backend.PARTIAL_RENDER_TOKEN if runtime.partial_mode else backend.RENDER_DEFAULT_TOKEN)
        addresses = tuple(bodies)
    roots = set(runtime.boot.firmware_roots.values()) | {runtime.root}
    old = {dva: runtime.pages[dva] for dva in addresses}
    for dva, pa in old.items():
        if any(runtime.uat.iotranslate_root(root, dva, PAGE) != [(pa, PAGE)] for root in roots):
            raise RuntimeError("render transport backing changed ownership")
    if mixed:
        if set(old.values()) & set(runtime.context['pages'].values()):
            raise RuntimeError('mixed transport has an unhandled context alias')
        bodies = mixed_transport_pages(runtime.read_fields({dva: (dva, PAGE) for dva in addresses}))
    runtime.evidence["command_publication_started"] = True
    runtime.state = "recreating"
    try:
        phase("allocation")
        base = runtime.alloc(len(bodies) * PAGE)
        fresh = {dva: base + index * PAGE for index, dva in enumerate(bodies)}
        if set(fresh.values()) & set(runtime.pages.values()):
            raise RuntimeError("new render transport aliases existing backing")
        phase("publication")
        write_publications(runtime.u, runtime.p, runtime.iface,
                           ((fresh[dva], body) for dva, body in bodies.items()))
        runtime.publish(fresh.values())
        phase("replacement")
        for dva, pa in fresh.items():
            if runtime.uat.iounmap_root(runtime.root, dva, PAGE) != PAGE:
                raise RuntimeError("render transport unmap length differs")
            flags = (g17g_uat.FLAGS_SHARED_UXN if post.flag_class_for_address(dva) == post.FLAG_CLASS_SHARED_UXN
                     else g17g_uat.FLAGS_NORMAL_UXN)
            runtime.uat.iomap_at_root(runtime.root, dva, pa, PAGE, **flags)
            runtime.pages[dva] = pa
            evidence["rebinds"].append(dict(dva=dva, old_pa=old[dva], new_pa=pa))
        phase("table-flush")
        runtime.flush_tables(0x40)
        runtime.flush_tables(0)
        phase("verification")
        for dva, pa in fresh.items():
            if any(runtime.uat.iotranslate_root(root, dva, PAGE) != [(pa, PAGE)] for root in roots):
                raise RuntimeError("recreated render transport differs between firmware roots")
        after = dict(queue=[0] * 2, pointers=[[0] * 3] * 2, channels=[[counter] * 3] * 2)
        if retirement() != after or runtime.channel_state() != (runtime.service_cursor,) * 3:
            raise RuntimeError("recreated render transport changed persistent state")
        if mixed:
            evidence['compute_after'] = runtime.retirement_state(compute_graph)
            if evidence['compute_after'] != evidence['compute_before']:
                raise RuntimeError('mixed recreation changed the retained compute transport')
        setattr(runtime, start_attribute, start)
        runtime.state = "complete"
        evidence["after"] = after
        phase("complete")
        runtime.transport_recreations = getattr(runtime, "transport_recreations", []) + [evidence]
        return evidence
    except Exception:
        runtime.state = "failed"
        runtime.evidence["transport_recreation"] = evidence
        raise
