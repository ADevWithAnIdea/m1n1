# SPDX-License-Identifier: GPL-2.0-only
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from m1n1.drm_shim import g17g_backend as backend
from m1n1.drm_shim.g17g_submit import first_compute_graph
from m1n1.drm_shim.g17g_compute_queue import (
    RESIDENT_COMMAND_CAPACITY, compute_wave, compute_waves, transport_state,
)
from m1n1.drm_shim.g17g_resident_queue import G17GResidentQueue, bind_render_graph, prepare_render, recreate_render
from m1n1.drm_shim.g17g_barriers import context_dependencies, bound_record, apply_submission_barriers
from m1n1.drm_shim.g17g_mixed_submit import mixed_partial_graph, continued_mixed_partial_graph, validate_mixed_compute_history
from m1n1.drm_shim.g17g_vm_layout import G17GVMLayout, PAGE
from m1n1.drm_shim.g17g_memory import G17GPageBacking
from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_COMPUTE, DRM_ASAHI_CMD_RENDER, DRM_ASAHI_BARRIER_NONE


class TestResidentQueues(unittest.TestCase):
    def test_render_recreation_reuses_retired_backing(self):
        memory = {}
        pages = {}
        allocations = []
        translations = Tables()
        translations.iotranslate_root = lambda root, dva, size: [(translations.leaves[root, dva], size)]
        root = 1
        capacity = (backend.RENDER_INNER_RING_ITEM_COUNT // 3) * 3
        transports = []
        for index in range(2):
            address = 0x100000 + index * 3 * PAGE
            transports.append(dict(qid=index + 4, queue=address, pointers=address + PAGE,
                                   item_ring=address + 2 * PAGE))
            for page in range(address, address + 3 * PAGE, PAGE):
                pa = 0x800000 + page
                memory[pa] = bytearray(PAGE)
                pages[page] = pa
                translations.iomap_at_root(root, page, pa, PAGE)

        def alloc(size):
            pa = 0xa00000 + len(allocations) * PAGE
            for offset in range(0, size, PAGE):
                allocations.append(pa + offset)
                memory[pa + offset] = bytearray(PAGE)
            return pa

        def read_fields(fields):
            return {key: bytes(memory[pages[dva & -PAGE]][dva % PAGE:dva % PAGE + size])
                    for key, (dva, size) in fields.items()}

        def write_pages(_u, _p, _iface, writes):
            for pa, body in writes:
                memory[pa][:] = body

        runtime = SimpleNamespace(root=root, pages=pages, uat=translations,
            boot=SimpleNamespace(firmware_roots={0: root}), evidence={}, resident_contexts={},
            render_transport_banks={}, alloc=alloc, read_fields=read_fields, flush_tables=lambda _: None,
            u=None, p=None, iface=None, publish=lambda _: None)
        backing = []
        with patch('m1n1.drm_shim.g17g_transfer.write_publications', side_effect=write_pages):
            for _ in range(5):
                for transport in transports:
                    struct.pack_into('<I', memory[pages[transport['queue']]], 0x1c, capacity)
                    for offset in (0, 0x30, 0x40):
                        struct.pack_into('<I', memory[pages[transport['pointers']]], offset, capacity)
                    memory[pages[transport['queue']]][0x200] = 0x5a
                recreate_render(runtime, transports)
                backing.append(tuple(pages.values()))
                for transport in transports:
                    self.assertEqual(memory[pages[transport['queue']]][0x200], 0x5a)
        self.assertEqual(len(allocations), 2 * len(pages))
        self.assertEqual(backing[::2], [backing[0]] * 3)
        self.assertEqual(backing[1::2], [backing[1]] * 2)
        self.assertTrue(runtime.evidence['resident_ring_backing_reused'])

    def test_late_render_queue_has_local_abort_identity_and_global_storage(self):
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        first = mixed_partial_graph(params)
        graph = continued_mixed_partial_graph(params, 2, private_dvas=first['private_dvas'])
        storage = graph['firmware_addresses'].copy()
        work_index = graph['items']['tiling_descriptor'][0x48:0x50]
        bind_render_graph(G17GResidentQueue(1), graph, 0, route=True)
        ta, fr = graph['dependency_jobs'][0]
        self.assertEqual(context_dependencies(bound_record(graph, ta)), ((), (4, 0)))
        self.assertEqual(context_dependencies(bound_record(graph, fr)), (((4, 1),), (5, 0)))
        for kind, stamp_offset, qid in (('tiling', 0x7a0, 4), ('fragment', 0x2150, 5)):
            event = graph['items'][kind+'_event']
            self.assertEqual(struct.unpack_from('<2I', event, 4), (0x10000 | qid, 0x102))
            self.assertEqual(struct.unpack_from('<I', graph['items'][kind+'_descriptor'], stamp_offset)[0], 0x100)
            self.assertEqual(graph['firmware_addresses'][kind+'_descriptor'], storage[kind+'_descriptor'])
        self.assertEqual(graph['items']['tiling_descriptor'][0x48:0x50], work_index)
        self.assertEqual(graph['ordinal'], 2)

    def test_render_context_mapping_preserves_abort_coherence(self):
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        graph = mixed_partial_graph(params)
        bind_render_graph(G17GResidentQueue(1), graph, 0, route=True)
        mappings = {}
        def map_page(root, dva, pa, size, **flags):
            mappings[root, dva] = (pa, flags)
        runtime = SimpleNamespace(root=1, boot=SimpleNamespace(context0_low_root=2), pages={},
            uat=SimpleNamespace(iomap_at_root=map_page), flush_tables=lambda ctx: None,
            publish_writes=lambda writes: None)
        def allocate(addresses, *, fresh):
            runtime.pages.update((address, 0x800000+i*PAGE) for i,address in enumerate(addresses))
        runtime.map_globals = allocate
        prepare_render(runtime, graph)
        for transport in graph['resident_render_transport']:
            pa, flags = mappings[1, transport['context']]
            self.assertEqual(flags['AttrIndex'], 2)
            self.assertEqual(flags['UXN'], 1)
            self.assertEqual(mappings[2, transport['low']][0], pa)
            self.assertEqual(runtime.pages[transport['context']], pa)

    def test_render_recreation_restarts_dependencies_but_preserves_event_stamps(self):
        capacity = backend.RENDER_INNER_RING_ITEM_COUNT // 3
        owner = G17GResidentQueue(1)
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        first = mixed_partial_graph(params)
        graph = continued_mixed_partial_graph(params, capacity + 3,
            private_dvas=first['private_dvas'], transport_start=capacity + 1)

        bind_render_graph(owner, graph, capacity, route=True)

        self.assertTrue(graph['resident_render_recreate'])
        self.assertEqual(graph['resident_render_completed'], capacity + 1)
        tiling, fragment = graph['dependency_jobs'][0]
        self.assertEqual((tiling['generation'], fragment['generation']), (1, 1))
        self.assertEqual(context_dependencies(bound_record(graph, tiling)), ((), (4, 0)))
        self.assertEqual(context_dependencies(bound_record(graph, fragment)), (((4, 1),), (5, 0)))
        for binding, qid in ((tiling, 4), (fragment, 5)):
            self.assertEqual(struct.unpack_from('<Q', bound_record(graph, binding))[0],
                             0x1000000000000000 | qid << 42 | 4)
        for kind in ('tiling', 'fragment'):
            self.assertEqual(struct.unpack_from('<I', graph['items'][kind + '_event'], 8)[0],
                             (capacity + 1) << 8 | 2)

    def test_local_queue_counter_and_global_channel_are_independent(self):
        first = first_compute_graph(0x100000,0x100040)
        wave = compute_wave(((0x200000,0x200040),),1,first['addresses'])
        owner = G17GResidentQueue(1)
        owner.bind_compute_wave(wave,0,transport_state(1))
        self.assertEqual(wave['retirement_after'],dict(channel=(2,)*3,pointers=(3,)*3,queue_limit=3))
        record = bound_record(wave,wave['dependency_jobs'][0][0])
        self.assertEqual(context_dependencies(record),((),(3,0)))
        self.assertNotEqual(wave['addresses']['queue'],first['addresses']['queue'])
        self.assertFalse(any(address == first['addresses']['pointers']+0x40 for address,body in wave['release']))
        descriptor = dict(wave['high'])[wave['records'][0]['addresses']['descriptor']]
        self.assertEqual(struct.unpack_from('<I',descriptor,0xf54)[0],3)
        self.assertEqual(struct.unpack_from('<Q',descriptor,0xee0)[0],0x20003c)

    def test_cross_engine_barrier_uses_assigned_queue_and_local_completion(self):
        first = first_compute_graph(0x100000,0x100040)
        wave = compute_wave(((0x200000,0x200040),),1,first['addresses'])
        owner = G17GResidentQueue(1)
        owner.bind_compute_wave(wave,0,transport_state(1))
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        render = mixed_partial_graph(params)
        bind_render_graph(owner,render,0,route=True)
        commands = tuple(SimpleNamespace(index=i+1,payload=SimpleNamespace(flags=0),
            header=SimpleNamespace(cmd_type=kind,
            vdm_barrier=DRM_ASAHI_BARRIER_NONE,cdm_barrier=barrier)) for i,(kind,barrier) in enumerate((
                (DRM_ASAHI_CMD_COMPUTE,DRM_ASAHI_BARRIER_NONE),(DRM_ASAHI_CMD_RENDER,1))))
        apply_submission_barriers(commands,wave,(render,))
        ta,fr = render['dependency_jobs'][0]
        self.assertEqual(context_dependencies(bound_record(render,ta)),(((3,1),),(4,0)))
        self.assertEqual(context_dependencies(bound_record(render,fr)),(((4,1),),(5,0)))

    def test_resident_queue_follows_scheduler_storage_rotation(self):
        first = first_compute_graph(0x100000,0x100040)
        owner = G17GResidentQueue(0)
        owner.addresses = first['addresses']
        wave = compute_wave(((0x200000,0x200040),),127,first['addresses'])
        scheduler = wave['addresses'].copy()
        owner.bind_compute_wave(wave,64,transport_state(127))
        self.assertEqual(wave['addresses']['queue'],first['addresses']['queue'])
        writes = dict(wave['high'])
        for offset,name in ((0x10,'job_list'),(0x70,'queue_aux')):
            self.assertEqual(struct.unpack('<Q',writes[first['addresses']['queue']+offset])[0],
                             scheduler[name])
        self.assertEqual(wave['retirement_after']['queue_limit'],131)

    def test_history_checks_the_owned_queue_id_and_local_value(self):
        descriptor = backend.compute_submission_addresses(2)['descriptor']
        address = 0xfffffc2200100000
        body = struct.pack('<8Q',(1<<48)|(3<<9)|0x33,0x20,10,20,30,40,descriptor,address)+bytes(PAGE-64)
        validate_mixed_compute_history(body,2,queue_completed=1,queue_id=3,queue_address=address)
        for changes in (dict(queue_id=0),dict(queue_completed=2),dict(queue_address=address+PAGE)):
            args = dict(queue_completed=1,queue_id=3,queue_address=address)
            args.update(changes)
            with self.assertRaises(ValueError):
                validate_mixed_compute_history(body,2,**args)
        body = struct.pack('<Q', 0x10633) + body[8:]
        validate_mixed_compute_history(body, 2, queue_completed=256, queue_id=3, queue_address=address)
        with self.assertRaises(ValueError):
            validate_mixed_compute_history(body, 2, queue_completed=257, queue_id=3, queue_address=address)

    def test_late_second_queue_preserves_prior_transport_generation(self):
        first = first_compute_graph(0x100000,0x100040)
        owner = G17GResidentQueue(0)
        old = compute_wave(((0x200000,0x200040),),127,first['addresses'])
        old['resident_completed'] = 128
        owner.commit(old)
        wave = compute_wave(((0x300000,0x300040),),129,old['addresses'])
        owner.bind_compute_wave(wave,128,transport_state(129))
        self.assertEqual(owner.context_base,127)
        self.assertEqual(wave['resident_value_completed'],2)
        self.assertEqual(wave['retirement_after']['queue_limit'],5)
        record = bound_record(wave,wave['dependency_jobs'][0][0])
        self.assertEqual(context_dependencies(record),((),(0,1)))
        writes = dict(wave['high'])
        from m1n1.drm_shim.g17g_compute import compute_queue_context_item_offset
        self.assertIn(old['addresses']['queue_context']+compute_queue_context_item_offset(128),writes)

    def test_full_resident_compute_ring_retires_before_switching_banks(self):
        first = first_compute_graph(0x100000, 0x100040)
        owner = G17GResidentQueue(1)
        owner.addresses = owner.compute_addresses(first['addresses'])
        commands = ((0x300000, 0x300040),) * 3
        capacity = RESIDENT_COMMAND_CAPACITY
        def addresses(ordinal):
            return dict(first['addresses'], **backend.compute_recreated_queue_addresses(
                backend.compute_queue_epoch(ordinal)))

        before = transport_state(650)
        waves = compute_waves(commands, 650, addresses(650), resident_used=capacity - 1)
        self.assertEqual([len(wave['records']) for wave in waves], [1, 2])
        last, next_wave = waves
        count = owner.bind_compute_wave(last, capacity - 1, before)
        owner.bind_compute_wave(next_wave, count, last['retirement_after'], last)
        self.assertEqual(last['addresses']['queue'], owner.addresses['queue'])
        self.assertEqual(last['retirement_after']['queue_limit'], capacity * 2 + 1)
        self.assertEqual(next_wave['resident_compute_predecessor'], last['addresses'])
        self.assertEqual(next_wave['retirement_after']['queue_limit'], 5)
        self.assertEqual(next_wave['retirement_before'], last['retirement_after'])
        first_slot = bound_record(next_wave, next_wave['dependency_jobs'][0][0])
        self.assertEqual(context_dependencies(first_slot), ((), (3, 0)))

        banks = [next_wave['addresses']['queue']]
        for epoch in (2, 3):
            owner.commit(next_wave)
            at_capacity = owner.context_base + capacity
            completed = 650 + (epoch - 1) * capacity
            next_wave = compute_wave(commands[:1], completed, addresses(completed))
            owner.bind_compute_wave(next_wave, at_capacity, before)
            self.assertEqual(next_wave['resident_compute_epoch'], epoch)
            banks.append(next_wave['addresses']['queue'])
        self.assertNotEqual(banks[0], banks[1])
        self.assertEqual(banks[0], banks[2])


class Tables:
    def __init__(self):
        self.leaves = {}

    def iomap_at_root(self,root,dva,pa,size,**flags):
        for off in range(0,size,PAGE):
            self.leaves[root,dva+off] = pa+off

    def iounmap_root(self,root,dva,size):
        for off in range(0,size,PAGE):
            self.leaves.pop((root,dva+off),None)
        return size


class TestVMPlacement(unittest.TestCase):
    def fixture(self,start,labels,caller=None):
        layout = G17GVMLayout(start,start+0x20000000)
        layout.reserve(labels)
        context = dict(root0=1,root1=2,pages=dict(labels),caller_mappings=caller or {},table_witnesses=set(labels))
        tables = Tables()
        for dva,pa in labels.items():
            tables.iomap_at_root(1,dva,pa,PAGE)
        runtime = SimpleNamespace(u=None,uat=tables)
        layout.map_private(runtime,context)
        return layout,context,tables

    def test_primary_arena_can_overlap_the_recipe_labels(self):
        labels = {0x1000008000:0x800000,0x100000c000:0x804000}
        layout,context,tables = self.fixture(0x100000c000,labels)
        self.assertNotIn((1,0x1000008000),tables.leaves)
        self.assertEqual(tables.leaves[1,0x100000c000],0x800000)
        self.assertEqual(tables.leaves[1,0x1000010000],0x804000)
        self.assertEqual(tables.leaves[2,0x100000c000],0x804000)

    def test_caller_at_a_private_label_keeps_distinct_backing(self):
        label = 0x1000008000
        layout,context,tables = self.fixture(0x200004000,{label:0x800000},
                                            {label:G17GPageBacking(0x900000,False)})
        self.assertEqual(tables.leaves[1,label],0x900000)
        self.assertEqual(tables.leaves[1,layout.primary[label]],0x800000)
        self.assertEqual(tables.leaves[2,label],0x800000)
        self.assertEqual(context['pages'][label],0x800000)
