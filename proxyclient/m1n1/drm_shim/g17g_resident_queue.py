# SPDX-License-Identifier: GPL-2.0-only
"""Queue-owned firmware transports on the device's shared work channels."""
import struct
from . import g17g, g17g_backend as backend, g17g_compute as compute, g17g_uat
from .g17g_barriers import high_record_binding
from .g17g_compute_queue import RESIDENT_COMMAND_CAPACITY

PAGE = 0x4000
ARENA = 0xfffffc2200000000
LOW_ARENA = 0x6000000000
STRIDE = 0x100000
COMPUTE_ROLLOVER_BASE = 0x02000000
COMPUTE_ROLLOVER_BANK_SIZE = 0x60000
COMPUTE_TRANSPORT_NAMES = ('queue', 'pointers', 'item_ring', 'queue_context', 'optional')


class G17GResidentQueue:
    def __init__(self, index):
        self.index = index
        self.compute_id = index * 3
        self.completed = 0
        self.context_base = 0
        self.addresses = None
        self.compute_epoch = 0
        self.compute_generation = compute.COMPUTE_QUEUE_GENERATION
        self.low_alias = None

    def compute_addresses(self, source):
        if self.index == 0:
            return dict(source)
        base = ARENA+self.index*STRIDE
        return dict(source, queue=base, pointers=base+PAGE, item_ring=base+2*PAGE,
                    queue_context=base+3*PAGE, optional=base+0x50000)

    def bind_compute_wave(self, wave, completed, previous_state, previous_resident=None):
        """Keep descriptor allocation global; give the queue its own cursors."""
        source = wave['addresses']
        if previous_resident is None:
            addresses = self.addresses
            context_base, epoch = self.context_base, self.compute_epoch
            generation = self.compute_generation
            # The adapter can swap the boot queue onto index zero.
            low_alias = self.low_alias
            if low_alias is None:
                low_alias = (backend.COMPUTE_QUEUE_CONTEXT_LOW if self.index == 0 else
                             LOW_ARENA + self.index * STRIDE)
        else:
            addresses = previous_resident['addresses']
            context_base = previous_resident['resident_context_base']
            epoch = previous_resident['resident_compute_epoch']
            generation = previous_resident['resident_compute_generation']
            low_alias = previous_resident['resident_alias'][0]
        rollover = completed - context_base == RESIDENT_COMMAND_CAPACITY
        support = source['shared_support']
        if rollover:
            epoch += 1
            context_base = completed
            generation = g17g.positive_serial(
                generation + backend.COMPUTE_NEW_QUEUE_GENERATION_STRIDE, 16)
            offset = (COMPUTE_ROLLOVER_BASE + self.index * STRIDE +
                      (epoch - 1) % 2 * COMPUTE_ROLLOVER_BANK_SIZE)
            base = ARENA + offset
            target = dict(source, queue=base, pointers=base+PAGE, item_ring=base+2*PAGE,
                          queue_context=addresses['queue_context'], optional=base+3*PAGE)
            support = base+4*PAGE
            wave['resident_compute_predecessor'] = addresses
        else:
            target = self.compute_addresses(source) if addresses is None else dict(source, **{
                name: addresses[name] for name in COMPUTE_TRANSPORT_NAMES})
        qid = self.compute_id
        high, jobs = [], []
        records = wave['records']
        first = completed == 0 or rollover
        final = completed+len(records)
        final_value = final-context_base
        if 2*final_value+1 > compute.COMPUTE_ITEM_RING_ENTRY_COUNT:
            raise ValueError('compute wave spans two resident queue lifetimes')

        def retarget_descriptor(body):
            descriptor = bytearray(body)
            struct.pack_into('<I', descriptor, 0xf54, qid)
            if rollover:
                struct.pack_into('<Q', descriptor, 0xfb2, support)
            return bytes(descriptor)

        # The adapter resolves explicit barriers after queue assignment.
        priority = None
        for address, body in wave['high']:
            if address == source['queue']+0x28:
                priority = body
        for address, body in wave['high']:
            if (source['item_ring'] <= address < source['item_ring']+PAGE or
                source['queue_context'] <= address < source['queue_context']+0x40000 or
                address in (source['queue']+0x28, source['optional'], source['pointers'], source['queue'])):
                continue
            if any(address == record['addresses']['descriptor'] for record in records):
                body = retarget_descriptor(body)
            elif any(address == record['addresses']['event'] for record in records):
                body = bytearray(body)
                struct.pack_into('<I', body, 4, 0x10000 | qid)
                body = bytes(body)
            elif source['channel_ring'] <= address < source['channel_ring']+0x10000 and len(body) == g17g.RING_SLOT_SIZE:
                # Filled below with the exact local item limit for this job.
                continue
            high.append((address, body))
        if first:
            if rollover:
                high.extend((
                    (target['item_ring'], bytes(PAGE)),
                    (support, compute.build_compute_shared_support(backend.COMPUTE_CLIENT_STATE,
                        addresses['pointers'], active=(wave['completed'] + 1) & 0xffffffff))))
            high.extend(((target['queue'], compute.build_compute_queue_record(
                target['pointers'], target['item_ring'], source['job_list'], source['queue_aux'],
                queue_generation=generation)),
                (target['pointers'], g17g.build_pointer_block(field_00=0, field_30=0, field_40=0)),
                (target['item_ring'], struct.pack('<Q', target['optional'])),
                (target['optional'], compute.build_compute_optional(low_alias, target['queue_context'],
                    support, source['queue_aux'], queue_index=qid, first_queue=not rollover,
                    submission_ordinal=g17g.positive_serial(wave['completed'] + 1, 16) if rollover else 1,
                    token=generation))))
        if priority is not None:
            high.append((target['queue']+0x28, priority))
        # Descriptor/scheduler storage rotates globally, independently of
        # this queue's ring. The retired queue must follow that scheduler's
        # current list and control object before publishing the next job.
        high.extend(((target['queue']+0x10, struct.pack('<Q', source['job_list'])),
                     (target['queue']+0x70, struct.pack('<Q', source['queue_aux']))))
        for index, record in enumerate(records, completed):
            local = index-context_base
            addresses = record['addresses']
            descriptor, event = addresses['descriptor'], addresses['event']
            body = compute.build_compute_queue_context_item(descriptor, target['queue'], item_index=local, queue_index=qid)
            context_address = target['queue_context']+compute.compute_queue_context_item_offset(index)
            high.append((context_address, body))
            jobs.append((high_record_binding(high, context_address),))
            high.append((target['item_ring']+(1+2*local)*8, struct.pack('<2Q', descriptor, event)))
            channel_address = source['channel_ring']+compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET+backend.compute_channel_slot_index(record['ordinal'])*g17g.RING_SLOT_SIZE
            high.append((channel_address, (compute.build_compute_channel_slot if first and index == completed else
                compute.build_compute_repeat_channel_slot)(target['queue'], queue_index=qid, item_limit=2*(local+1)+1)))
            record['addresses'] = dict(addresses, **{name: target[name] for name in
                ('queue','pointers','item_ring','queue_context','optional')})
        wave.update(high=tuple(high), addresses=target, dependency_jobs=tuple(jobs),
            retirement_before=previous_state,
            retirement_after=dict(channel=wave['retirement_after']['channel'], pointers=(2*final_value+1,)*3, queue_limit=2*final_value+1),
            resident_queue=self, resident_completed=final, resident_value_completed=final_value,
            resident_context_base=context_base, resident_compute_epoch=epoch,
            resident_compute_generation=generation,
            resident_alias=(low_alias, target['queue_context']))
        wave['release'] = ((target['pointers']+g17g.POINTER_FIELD_40, struct.pack('<I', 2*final_value+1)), wave['release'][-1])
        low = []
        for address, body in wave['low']:
            if len(body) == 0x1000 and struct.unpack_from('<I', body)[0] == 3:
                body = retarget_descriptor(body)
            low.append((address, body))
        wave['low'] = tuple(low)
        wave['page_flags'] = dict(wave['page_flags'])
        wave['page_flags'][target['pointers'] & -PAGE] = g17g_uat.FLAGS_SHARED_UXN
        return final

    def commit(self, wave):
        self.completed, self.addresses = wave['resident_completed'], dict(wave['addresses'])
        if 'resident_alias' in wave:
            self.context_base = wave['resident_context_base']
            self.compute_epoch = wave['resident_compute_epoch']
            self.compute_generation = wave['resident_compute_generation']
            self.low_alias = wave['resident_alias'][0]
        else:
            # A single queue may already have rotated its legacy transport
            # before another queue is created. Preserve the current local
            # progress value as well as its monotonic context-ring cursor.
            state = wave.get('retirement_after')
            local = (state['queue_limit']-1)//2 if state is not None else self.completed
            self.context_base = self.completed-local
            self.compute_generation = backend.compute_queue_generation(wave.get('epoch', 0))


def render_source(graph):
    from . import g17g_render as render, g17g_postcontrol as post
    mixed = graph['format'].startswith('m1n1-g17g-mixed-')
    layout = backend._mixed_render_layout(compute_predecessor=True) if mixed else None
    result = []
    for index, kind in enumerate(('tiling', 'fragment')):
        optional = graph['items'][kind+'_optional']
        qid = struct.unpack_from('<H', optional, 0x18)[0]
        result.append(dict(qid=qid, queue=post.QUEUE_PAGE+qid*g17g.QUEUE_RECORD_STRIDE,
            pointers=layout[kind+'_pointer'] if mixed else post.POINTER_BLOCK_ADDRESSES[index],
            item_ring=layout[kind+'_item_ring'] if mixed else post.ITEM_RING_ADDRESSES[index],
            low=struct.unpack_from('<Q', optional, 8)[0],
            context=struct.unpack_from('<Q', optional, 0x10)[0]))
    return tuple(result)


def bind_render_graph(owner, graph, completed, *, route):
    """Keep resource/descriptor lifetimes global and dependencies queue-local."""
    from . import g17g_render as render
    from .g17g_barriers import bound_record
    source = render_source(graph)
    target = getattr(owner, 'render_addresses', None)
    if target is None:
        target = source if owner.index == 0 else tuple(dict(
            qid=owner.compute_id+index+1,
            queue=ARENA+0x10000000+owner.index*STRIDE+index*0x40000,
            pointers=ARENA+0x10000000+owner.index*STRIDE+index*0x40000+PAGE,
            item_ring=ARENA+0x10000000+owner.index*STRIDE+index*0x40000+2*PAGE,
            context=ARENA+0x10000000+owner.index*STRIDE+index*0x40000+3*PAGE,
            low=LOW_ARENA+0x10000000+owner.index*STRIDE+index*0x40000)
            for index in range(2))
    graph.update(resident_render_queue=owner, resident_render_transport=target,
                 resident_render_completed=completed+1, resident_render_before=completed*3)
    if not route:
        from .g17g_render_queue import transport_head
        graph['resident_render_before'] = transport_head(graph.get('ordinal', 1)-1, graph.get('transport_start', 1))
        return completed+1
    capacity = backend.RENDER_INNER_RING_ITEM_COUNT//3
    generation, inner_index = divmod(completed, capacity)
    graph['resident_render_before'] = inner_index*3
    graph['resident_render_recreate'] = generation > 0 and inner_index == 0
    ordinal = graph.get('ordinal', 1)
    value = completed + 1
    serial = render.render_event_serial(value)
    originals = tuple(bound_record(graph, binding) for binding in graph['dependency_jobs'][0])
    items = dict(graph['items'])
    addresses = dict(graph['firmware_addresses'])
    opening = 'high' not in graph
    if opening:
        mixed = graph['format'].startswith('m1n1-g17g-mixed-')
        layout = backend._mixed_render_layout(compute_predecessor=True) if mixed else None
        for index, kind in enumerate(('tiling', 'fragment')):
            addresses[kind+'_optional'] = (layout[kind+'_optional'] if mixed else
                backend.RENDER_OPTIONAL_PAGE+(1-index)*render.OPTIONAL_ITEM_SIZE)
            addresses[kind+'_event'] = (layout[kind+'_event'] if mixed else
                backend.RENDER_EVENT_PAGE+(1-index)*render.EVENT_ITEM_SIZE)
    extra, bindings = [], []
    for index, kind in enumerate(('tiling', 'fragment')):
        src, dst = source[index], target[index]
        qid = dst['qid']
        if completed == 0:
            # The shared scheduler list is already retained by the device.
            from . import g17g_postcontrol as post
            extra.extend(((dst['queue'], g17g.apply_queue_priority(compute.build_compute_queue_record(
                dst['pointers'], dst['item_ring'], post.QUEUE_ADDRESS_10_PAGE,
                post.QUEUE_ADDRESS_70_PAGE, struct.unpack_from('<H', items[kind+'_optional'], 0x5a)[0]),
                graph.get('firmware_priority', 2))),
                (dst['pointers'], g17g.build_pointer_block(field_00=0, field_30=0, field_40=0))))
        extra.append(g17g.queue_priority_write(dst['queue'], graph.get('firmware_priority', 2)))
        optional = bytearray(items[kind+'_optional'])
        struct.pack_into('<2Q', optional, 8, dst['low'], dst['context'])
        for offset, field_value in ((0x18,qid),(0x1a,int(completed==0)),(0x2a,completed & 0xffff),
                              (0x2e,(completed&255)<<8),(0x52,int(completed==0)),(0x62,int(completed==0))):
            struct.pack_into('<H', optional, offset, field_value)
        # These are copies of queue progress, distinct from global descriptor,
        # pool and status allocation indices. Abort follows all of the copies.
        mixed = graph['format'].startswith('m1n1-g17g-mixed-')
        struct.pack_into('<H', optional, 0x3e, g17g.positive_serial(value + int(mixed), 16))
        if index == 0:
            struct.pack_into('<H', optional, 0x76, completed & 0xffff)
            struct.pack_into('<H', optional, 0x7e, qid//2)
            struct.pack_into('<H', optional, 0x82, qid+1)
        items[kind+'_optional'] = bytes(optional)
        event = bytearray(items[kind+'_event'])
        struct.pack_into('<I', event, 4, 0x10000|qid)
        struct.pack_into('<I', event, 8, (serial<<8)|2)
        items[kind+'_event'] = bytes(event)
        descriptor = bytearray(items[kind+'_descriptor'])
        if index == 0:
            struct.pack_into('<I', descriptor, 0x79c, qid+1)
            for offset, stamp in ((0x7a0,serial<<8),(0x7a8,serial),(0x7b0,(serial&255)*0x101)):
                struct.pack_into('<I', descriptor, offset, stamp)
            for offset in (0x8b7,0x8c6,0x8cb):
                descriptor[offset] = serial & 255
            struct.pack_into('<2Q', descriptor, 0x8a6, render.DISPATCH_A+qid*4, render.DISPATCH_B+qid*4)
            struct.pack_into('<I', descriptor, 0x8ba, qid)
        else:
            for offset, stamp in ((0x2150,serial<<8),(0x2160,serial),(0x2164,(serial&255)<<8)):
                struct.pack_into('<I', descriptor, offset, stamp)
            struct.pack_into('<2Q', descriptor, 0x2140, render.DISPATCH_A+qid*4, render.DISPATCH_B+qid*4)
            struct.pack_into('<I', descriptor, 0x2154, qid)
        items[kind+'_descriptor'] = bytes(descriptor)
        # Recreation retires the old pair before starting its dependency
        # timeline over. Event stamps and registration still use queue progress.
        body = bytearray(originals[index])
        struct.pack_into('<Q', body, 0, 0x1000000000000000|(qid<<42)|4*(inner_index+1))
        struct.pack_into('<Q', body, 0x18, dst['queue'])
        struct.pack_into('<I', body, 0x20, 1 if index == 0 else 3)
        body[0x28:0x40] = bytes(0x18)
        if index == 0:
            struct.pack_into('<Q', body, 0x28, (qid<<40)|inner_index)
        else:
            struct.pack_into('<2Q', body, 0x28, ((qid-1)<<40)|(inner_index+1), (qid<<40)|inner_index)
        struct.pack_into('<Q', body, 0x180, 1 if index == 0 else 5)
        context_address = dst['context']+render.render_queue_context_item_offset(completed % render.RENDER_QUEUE_CONTEXT_ITEM_COUNT)
        extra.append((context_address, bytes(body)))
        bindings.append(context_address)
        extra.extend(((dst['item_ring']+inner_index*24, struct.pack('<3Q', *(
            addresses[kind+suffix] for suffix in ('_optional','_descriptor','_event')))),
            (dst['pointers']+0x40, struct.pack('<I', (inner_index+1)*3)),
            (backend.RENDER_CHANNEL_RING_PAGES[index]+backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[index]+
             ((ordinal-1)%backend.RENDER_CHANNEL_RING_SLOT_COUNT)*g17g.RING_SLOT_SIZE,
             backend.build_render_stream_ring_slot(qid,(inner_index+1)*3,queue_address=dst['queue'],
                 first_submit=completed==0,engine_kind=index))))
    def transport_write(address):
        return any(src['queue'] <= address < src['queue']+g17g.QUEUE_RECORD_STRIDE or
            src['pointers'] <= address < src['pointers']+0x48 or
            src['item_ring'] <= address < src['item_ring']+backend.RENDER_INNER_RING_ITEM_COUNT*8 or
            src['context'] <= address < src['context']+0x20000 for src in source)
    item_addresses = {addresses[name] for name in items}
    high = [(address, body) for address, body in graph.get('high', ())
            if not transport_write(address) and address not in item_addresses and not any(
                base+off <= address < base+off+backend.RENDER_CHANNEL_RING_SLOT_COUNT*g17g.RING_SLOT_SIZE
                for base,off in zip(backend.RENDER_CHANNEL_RING_PAGES,backend.RENDER_CHANNEL_RING_SLOT_OFFSETS))]
    high.extend((addresses[name],body) for name,body in items.items())
    high.extend(extra)
    graph.update(items=items, high=tuple(high), firmware_addresses=addresses,
        resident_render_routed=True, resident_render_opening=opening,
        dependency_jobs=(tuple(high_record_binding(high,address,generation=generation) for address in bindings),))
    return completed+1


def prepare_render(runtime, graph):
    if 'resident_render_transport' not in graph:
        return
    target = graph['resident_render_transport']
    if graph.get('resident_render_routed'):
        if graph.get('resident_render_recreate'):
            recreate_render(runtime, target)
        from .g17g_compute_queue import write_pages
        missing = write_pages(graph['high'])-set(runtime.pages)
        if missing:
            runtime.map_globals(sorted(missing), fresh=True)
        for dst in target:
            runtime.uat.iomap_at_root(runtime.root,dst['pointers']&-PAGE,
                runtime.pages[dst['pointers']&-PAGE],PAGE,**g17g_uat.FLAGS_SHARED_UXN)
            for page in write_pages(graph['high']):
                if dst['context'] <= page < dst['context']+0x20000:
                    # Firmware and the GPU both update these records. Match
                    # the original context's shared, non-executable mapping:
                    # normal memory retires draws but stalls a TVB-limit abort.
                    runtime.uat.iomap_at_root(runtime.root,page,
                        runtime.pages[page],PAGE,**g17g_uat.FLAGS_SHARED_UXN)
                    runtime.uat.iomap_at_root(runtime.boot.context0_low_root,dst['low']+page-dst['context'],
                        runtime.pages[page],PAGE,**g17g_uat.FLAGS_CONTEXT0_EXECUTABLE)
        runtime.flush_tables(0)
        runtime.flush_tables(0x40)
        if graph['resident_render_opening']:
            runtime.publish_writes(graph['high'])
        attribute = 'render_transport_start' if graph['format'].startswith('m1n1-g17g-mixed-') else 'transport_start'
        setattr(runtime, attribute, graph.get('transport_start', 1))
    runtime.render_transport = target
    count = graph['resident_render_before']//3+1
    counter = backend.render_channel_counter(graph.get('ordinal',1))
    runtime.render_pending_retirement = dict(queue=[count*3]*2,pointers=[[count*3]*3]*2,channels=[[counter]*3]*2)


def recreate_render(runtime, transports):
    """Replace only a retired queue pair's finite rings, preserving neighbors."""
    from .g17g_compute_queue import write_pages
    from .g17g_render_queue import replacement_backing
    from .g17g_transfer import write_publications
    fields = {}
    for i, dst in enumerate(transports):
        fields[i,0] = dst['queue']+0x1c, 4
        for j,off in enumerate((0,0x30,0x40),1):
            fields[i,j] = dst['pointers']+off,4
    before = runtime.read_fields(fields)
    capacity = (backend.RENDER_INNER_RING_ITEM_COUNT//3)*3
    if any(struct.unpack('<I',body)[0] != capacity for body in before.values()):
        raise RuntimeError('resident render ring is not retired at its capacity')
    writes = []
    for dst in transports:
        old = runtime.read_fields({0:(dst['queue'],g17g.QUEUE_RECORD_STRIDE)})[0]
        generation = struct.unpack_from('<Q',old,0x40)[0]>>32
        job_list = struct.unpack_from('<Q',old,0x10)[0]
        channel_control = struct.unpack_from('<Q',old,0x70)[0]
        fresh = bytearray(compute.build_compute_queue_record(dst['pointers'],dst['item_ring'],
            job_list,channel_control,generation))
        struct.pack_into('<I',fresh,0x1c,0)
        fresh[0x28:0x40] = old[0x28:0x40]
        writes.extend(((dst['queue'],bytes(fresh)),
            (dst['pointers'],g17g.build_pointer_block(field_00=0,field_30=0,field_40=0)),
            (dst['item_ring'],bytes(backend.RENDER_INNER_RING_ITEM_COUNT*8))))
    pages = {address:bytearray(body) for address,body in runtime.read_fields(
        {address:(address,PAGE) for address in write_pages(writes)}).items()}
    for address,body in writes:
        while body:
            size = min(len(body),PAGE-address%PAGE)
            pages[address&-PAGE][address%PAGE:address%PAGE+size] = body[:size]
            address,body = address+size,body[size:]
    addresses = tuple(sorted(pages))
    previous = {address: runtime.pages[address] for address in addresses}
    roots = set(runtime.boot.firmware_roots.values()) | {runtime.root}
    for address, pa in previous.items():
        if any(runtime.uat.iotranslate_root(root, address, PAGE) != [(pa, PAGE)]
               for root in roots):
            raise RuntimeError('resident render ring backing changed ownership')

    fresh, reused = replacement_backing(runtime, addresses)
    write_publications(runtime.u,runtime.p,runtime.iface,((fresh[a],bytes(body)) for a,body in pages.items()))
    runtime.publish(fresh.values())
    pointer_pages = {dst['pointers']&-PAGE for dst in transports}
    for address,pa in fresh.items():
        if runtime.uat.iounmap_root(runtime.root, address, PAGE) != PAGE:
            raise RuntimeError('resident render ring unmap length differs')
        runtime.uat.iomap_at_root(runtime.root,address,pa,PAGE,
            **(g17g_uat.FLAGS_SHARED_UXN if address in pointer_pages else g17g_uat.FLAGS_NORMAL_UXN))
        runtime.pages[address] = pa
    runtime.flush_tables(0x40)
    runtime.flush_tables(0)
    for address, pa in fresh.items():
        if any(runtime.uat.iotranslate_root(root, address, PAGE) != [(pa, PAGE)]
               for root in roots):
            raise RuntimeError('replacement render ring differs between firmware roots')
    if any(any(body) for body in runtime.read_fields(fields).values()):
        raise RuntimeError('resident render ring reset did not publish')
    runtime.evidence['resident_ring_backing_reused'] = reused
    runtime.evidence['resident_ring_recreation'] = [dst['qid'] for dst in transports]


def commit_render(runtime, graph):
    if graph.get('format') == 'm1n1-g17g-render-wave-v1':
        for record in graph['records']:
            commit_render(runtime, record)
        return
    if 'resident_render_queue' not in graph:
        return
    owner = graph['resident_render_queue']
    owner.render_completed = graph['resident_render_completed']
    owner.render_addresses = graph['resident_render_transport']
    count = graph['resident_render_before']+3
    counter = backend.render_channel_counter(graph.get('ordinal', 1))
    runtime.render_retirement = dict(queue=[count]*2,pointers=[[count]*3]*2,channels=[[counter]*3]*2)
