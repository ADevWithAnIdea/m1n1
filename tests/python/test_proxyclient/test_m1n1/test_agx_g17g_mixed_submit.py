# SPDX-License-Identifier: GPL-2.0-only
import copy
from dataclasses import replace
import struct
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from m1n1.drm_shim import g17g_backend as backend, g17g_render as render
from m1n1.drm_shim.g17g_mixed_submit import mixed_compute_graph, mixed_partial_graph, mixed_partial_completion, validate_mixed_compute_history, continued_mixed_partial_graph


class TestMixedFirmware(unittest.TestCase):
    def test_first_render_preserves_acknowledged_compute_report_cursor(self):
        from types import SimpleNamespace
        from m1n1.drm_shim import g17g_defaults
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        runtime = object.__new__(G17GMixedRuntime)
        runtime.boot = SimpleNamespace(fields=g17g_defaults.canonical_preinit_fields())
        consumer = runtime.boot.fields['primary_main_fields']['channels'][13][0][0]
        graph = dict(work_lifecycle_qwords={consumer & -0x4000: ((consumer & 0x3fff, 0, 1),)})
        writes = []
        runtime.publish_writes = lambda rows: writes.extend(rows)
        for cursor in (0, 1, 63, 66, 255):
            runtime.evidence = dict(compute_reports=dict(producer=cursor))
            runtime.read_fields = lambda fields: {consumer: struct.pack('<Q',cursor)}
            runtime.mixed_lifecycle(graph)
            self.assertEqual(writes, [], 'acknowledged credits must not rewind to one')
        runtime.read_fields = lambda fields: {consumer: struct.pack('<Q',1)}
        with self.assertRaisesRegex(RuntimeError, 'lifecycle mismatch'):
            runtime.mixed_lifecycle(graph)
        self.assertEqual(writes, [])
        self.assertIn(hex(consumer),runtime.evidence['lifecycle_before'])

    def test_mixed_vdm_fault_is_attributed_without_guessing_other_faults(self):
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_sync import G17GPublishedFault
        runtime = object.__new__(G17GMixedRuntime)
        runtime.evidence = {}
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        fault = dict(address_raw=(params.vdm_ctrl_stream_base+0x80)>>6,faulted=True)
        runtime.fault_status = lambda: fault
        with self.assertRaises(G17GPublishedFault) as result:
            runtime.raise_partial_fault(dict(parameters=params,ordinal=4),'mixed-other')
        self.assertEqual((result.exception.kind,result.exception.error),('command-fetch-uat',-19))
        self.assertEqual(runtime.evidence['fault_ordinal'],4)
        runtime.evidence = {}
        fault['address_raw'] = (params.vdm_ctrl_stream_base+0x4000)>>6
        with self.assertRaises(G17GPublishedFault) as result:
            runtime.raise_partial_fault(dict(parameters=params),'mixed-other')
        self.assertEqual(result.exception.kind,'mixed-other')
        self.assertNotIn('fault_ordinal',runtime.evidence)

    def test_mixed_continuation_keeps_engine_separate_from_queue_index(self):
        from m1n1.drm_shim import g17g, g17g_postcontrol as post
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        graph = continued_mixed_partial_graph(params,2,private_dvas=())
        high = dict(graph['high'])
        layout = backend._mixed_render_layout(compute_predecessor=True)
        pool_b = layout['descriptor_objects'][2]+0x80
        self.assertEqual(struct.unpack_from('<Q',graph['items']['tiling_descriptor'],0x28)[0],pool_b)
        self.assertEqual(struct.unpack_from('<Q',graph['items']['fragment_descriptor'],0x30)[0],pool_b)
        self.assertIn(pool_b+0x48,high)
        for index in (0,1):
            address = backend.RENDER_CHANNEL_RING_PAGES[index]+backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[index]+g17g.RING_SLOT_SIZE
            record = high[address]
            self.assertEqual(struct.unpack_from('<2I',record,0x10),(index,((index+1)<<16)|6))
            self.assertEqual(struct.unpack_from('<Q',record,8)[0],post.QUEUE_PAGE+(index+1)*g17g.QUEUE_RECORD_STRIDE)
            kind = ('tiling','fragment')[index]
            scratch = high[layout[kind+'_firmware_scratch']+render.render_queue_context_item_offset(1)]
            self.assertEqual(struct.unpack_from('<Q',scratch,0x18)[0],post.QUEUE_PAGE+(index+1)*g17g.QUEUE_RECORD_STRIDE)
            self.assertEqual(struct.unpack_from('<Q',scratch,0)[0] >> 42 & 0xff,index+1)
        self.assertNotIn(post.QUEUE_PAGE,high)
        self.assertNotIn(backend.COMPUTE_DESCRIPTOR_PAGE,high)

    def test_mixed_timestamp_destinations_remain_caller_owned(self):
        from m1n1.drm_shim.g17g_timestamp import TIMESTAMP_USER_BASE
        base = TIMESTAMP_USER_BASE
        params = replace(backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters'],
            tiling_user_timestamp_start=base+8,tiling_user_timestamp_end=base+16,
            fragment_user_timestamp_start=base+0x4008,fragment_user_timestamp_end=base+0x4010)
        graph = mixed_partial_graph(params)
        self.assertEqual(struct.unpack_from('<2Q',graph['items']['tiling_descriptor'],0x90e),(base+8,base+16))
        self.assertEqual(struct.unpack_from('<2Q',graph['items']['fragment_descriptor'],0x21a8),(base+0x4008,base+0x4010))
        for writes in (graph['context1_writes'],graph['fresh_global_pages'],graph['late_global_pages']):
            self.assertFalse(any(address < base+0x8000 and base < address+len(body)
                                 for address,body in writes.items()))

    def test_mixed_pool_b_reuses_only_its_eighty_owned_records(self):
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        base = backend._mixed_render_layout(compute_predecessor=True)['descriptor_objects'][2] - 0x80
        for ordinal in (64, 79, 80, 81, 128):
            graph = continued_mixed_partial_graph(params, ordinal, private_dvas=())
            expected = base + (ordinal % 80)*0x80
            self.assertEqual(struct.unpack_from('<Q',graph['items']['tiling_descriptor'],0x28)[0],expected)
            self.assertEqual(struct.unpack_from('<Q',graph['items']['fragment_descriptor'],0x30)[0],expected)
            self.assertIn(expected+0x48,dict(graph['high']))
            self.assertTrue(base <= expected < base+80*0x80)

    def test_mixed_render_wraps_storage_without_rewinding_logical_work(self):
        from m1n1.drm_shim import g17g
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        layout = backend._mixed_render_layout(compute_predecessor=True)
        for ordinal in (241, 242, 255, 256, 257, 426, 427, 512, 513, 852, 853, 860):
            start = ((ordinal-1)//426)*426+1
            graph = continued_mixed_partial_graph(params, ordinal, private_dvas=(),transport_start=start)
            high = dict(graph['high'])
            for i, kind in enumerate(('tiling', 'fragment')):
                ring = backend.RENDER_CHANNEL_RING_PAGES[i]+backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[i]
                self.assertIn(ring+((ordinal-1)%256)*g17g.RING_SLOT_SIZE, high)
                self.assertEqual(struct.unpack('<I',high[layout[kind+'_pointer']+0x40])[0],(ordinal-start+1)*3)
                self.assertEqual(graph['firmware_addresses'][kind+'_optional'],
                    layout[kind+'_optional']+((ordinal-1)%256)*2*render.OPTIONAL_ITEM_SIZE)
            self.assertEqual([struct.unpack('<I',body)[0] for _,body in graph['release']],
                             [ordinal%256]*2)

    def test_mixed_history_tracks_latest_completed_owner(self):
        for completed in (1,2,4,8,32):
            descriptor = (backend.COMPUTE_DESCRIPTOR_PAGE if completed == 1 else
                          backend.compute_submission_addresses(completed)['descriptor'])
            history = struct.pack('<8Q',(completed<<48)|0x33,0x20,100,110,120,130,
                                  descriptor,backend.COMPUTE_QUEUE_PAGE)+bytes(0x4000-0x40)
            validate_mixed_compute_history(history,completed)
            other_bank = bytearray(history)
            other_bank[7] = 1
            validate_mixed_compute_history(other_bank,completed)
            other_bank[7] = 2
            with self.assertRaisesRegex(ValueError,'generation'):
                validate_mixed_compute_history(other_bank,completed)
            with self.assertRaisesRegex(ValueError,'generation'):
                validate_mixed_compute_history(history,2 if completed==1 else 1)
            wrong = bytearray(history)
            struct.pack_into('<Q',wrong,0x30,descriptor+0x40)
            with self.assertRaisesRegex(ValueError,'owner'):
                validate_mixed_compute_history(wrong,completed)
            with self.assertRaisesRegex(ValueError,'extent'):
                validate_mixed_compute_history(history[:-1]+b'\x01',completed)
        records = b''.join(struct.pack('<8Q',((index&1)<<56)|(ordinal<<48)|0x33,0x20,
                          100+index*100,110+index*100,120+index*100,130+index*100,
                          backend.compute_submission_addresses(ordinal)['descriptor'],backend.COMPUTE_QUEUE_PAGE)
                          for index,ordinal in enumerate((2,3,4)))
        history = records+bytes(0x4000-len(records))
        validate_mixed_compute_history(history,4,3)
        with self.assertRaisesRegex(ValueError,'extent'):
            validate_mixed_compute_history(history,4,1)

    def test_mixed_history_keeps_validated_tail_and_queue_local_ordinals(self):
        def record(ordinal,local,queue):
            return struct.pack('<8Q',(local<<48)|0x33,0x20,100,110,120,130,
                backend.compute_submission_addresses(ordinal)['descriptor'],queue)
        previous = b''.join(record(n,n,backend.COMPUTE_QUEUE_PAGE) for n in range(65,128)).ljust(0x4000,b'\0')
        validate_mixed_compute_history(previous,127,63)
        queue = backend.compute_recreated_queue_addresses(1)['queue']
        current = b''.join(record(n,n-127,queue) for n in range(128,131))+previous[3*0x40:]
        validate_mixed_compute_history(current,130,3,queue_address=queue,previous_history=previous)
        with self.assertRaisesRegex(ValueError,'extent'):
            validate_mixed_compute_history(current,130,3,queue_address=queue)
        wrong = bytearray(current);wrong[3*0x40+0x10] ^= 1
        with self.assertRaisesRegex(ValueError,'extent'):
            validate_mixed_compute_history(wrong,130,3,queue_address=queue,previous_history=previous)
        wrong = bytearray(current);struct.pack_into('<Q',wrong,0,(128<<48)|0x33)
        with self.assertRaisesRegex(ValueError,'generation'):
            validate_mixed_compute_history(wrong,130,3,queue_address=queue,previous_history=previous)
        with self.assertRaisesRegex(ValueError,'owner'):
            validate_mixed_compute_history(current,130,3,previous_history=previous)

    def test_mixed_compute_continuation_keeps_robustness_off_caller_vdm(self):
        from m1n1.drm_shim.g17g_compute_queue import compute_wave, write_pages
        first = mixed_compute_graph(0x10000188000,0x10000188030)
        wave = compute_wave(((0x10000188100,0x10000188130),),1,first['addresses'],
            robustness_base=backend.COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS)
        self.assertNotIn(0x1000018000,write_pages(wave['low']))
        self.assertIn(backend.COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS,write_pages(wave['low']))
        self.assertEqual(wave['retirement_after'],dict(channel=(2,2,2),pointers=(5,5,5),queue_limit=5))

    def test_private_graphs_never_build_caller_assets_or_reserve_mixed_vdm(self):
        caller = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)
        params = caller['parameters']
        source = backend.render_context1_page_images(caller)
        with ExitStack() as stack:
            for name in ('build_add_compute_graph','build_clear_render_products',
                         'build_partial_render_products','build_earliest_mixed_partial_render_products',
                         'build_compute_predecessor_partial_compute_graph'):
                stack.enter_context(patch.object(backend,name,side_effect=AssertionError('caller asset construction')))
            compute = mixed_compute_graph(0x10000188000,0x10000188030)
            partial = mixed_partial_graph(params)
        private = set(compute['private_dvas']) | set(partial['private_dvas'])
        self.assertLessEqual(set(partial['private_dvas']),set(partial['context1_dvas']))
        self.assertLessEqual(set(partial['context1_aliases']),set(partial['context1_dvas']))
        self.assertNotIn(params.vdm_ctrl_stream_base & -0x4000,private)
        self.assertNotIn(params.auxiliary_object,private)
        self.assertNotIn(0x10000000000,private)
        self.assertNotIn(0x10000000000,compute['context1_writes'])
        self.assertIn(backend.COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS,private)
        for address,body in partial['context1_writes'].items():
            self.assertEqual(body,source.get(address,bytes(0x4000)),hex(address))
        self.assertEqual(partial['firmware_live_preserve_ranges']['queue'],((0,0x80),))
        self.assertEqual(partial['items'],caller['items'])
        self.assertEqual(partial['firmware_pages'],caller['firmware_pages'])

    def test_retained_compute_dispatch_never_hides_fault_or_missing_fragment_mirror(self):
        before = dict(dispatch_a=struct.pack('<4I',0x100,0,0,0).hex(),
            timestamps=struct.pack('<2Q',50,60).hex(),
            partial_completion=struct.pack('<I',1).hex(),
            partial_completion_target=3,
            reports=dict(consumer=1,producer=1,records=[]),fragment_tail=bytes(0xc8).hex())
        tail=bytearray(0xc8)
        struct.pack_into('<2Q',tail,0x7f,100,140)
        after = dict(before,fragment_tail=tail.hex(),partial_completion=struct.pack('<I',3).hex(),reports=dict(consumer=1,producer=2,
                     records=[(struct.pack('<I',1)+bytes(0x44)).hex()]))
        self.assertEqual(mixed_partial_completion(before,after),'complete')
        self.assertIsNone(mixed_partial_completion(before,dict(after,partial_completion=before['partial_completion'])))
        self.assertIsNone(mixed_partial_completion(before,dict(after,partial_completion=struct.pack('<I',2).hex())))
        self.assertIsNone(mixed_partial_completion(before,dict(after,fragment_tail=bytes(0xc8).hex())))
        self.assertEqual(mixed_partial_completion(before,dict(after,reports=before['reports'])),'complete')
        fault=copy.deepcopy(after)
        fault['reports']['records']=[(struct.pack('<I',4)+bytes(0x44)).hex()]
        self.assertEqual(mixed_partial_completion(before,fault),'fault')
        growth = copy.deepcopy(after)
        growth['reports']['records'] = [(struct.pack('<4I',6,1,0,1)+bytes(0x38)).hex()]
        with self.assertRaisesRegex(ValueError, 'unclassified'):
            mixed_partial_completion(before, growth)
        self.assertIsNone(mixed_partial_completion(before, growth, pending_growth=True))
        growth['reports']['producer'] += 1
        growth['reports']['records'] += fault['reports']['records']
        self.assertEqual(mixed_partial_completion(before, growth, pending_growth=True), 'fault')
        with self.assertRaisesRegex(ValueError,'initially clear'):
            mixed_partial_completion(dict(before,fragment_tail=tail.hex()),after)

    def test_mixed_retirement_uses_queue_consumer_and_both_stage_pointers(self):
        from m1n1.drm_shim import g17g, g17g_postcontrol
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        runtime = object.__new__(G17GMixedRuntime)
        layout = backend._mixed_render_layout(compute_predecessor=True)
        memory = {}
        for i,kind in enumerate(('tiling','fragment')):
            queue = g17g_postcontrol.QUEUE_PAGE + layout[kind+'_physical_queue_index']*g17g.QUEUE_RECORD_STRIDE
            memory[queue+0x1c] = 3
            for off in (0,0x30,0x40):
                memory[layout[kind+'_pointer']+off] = 3
            for off in (0,0x10,0x20):
                memory[backend.RENDER_STATE_PAGE+backend.RENDER_STATE_OFFSETS[i]+off] = 1
        runtime.read_fields = lambda fields: {key:struct.pack('<I',memory.get(address,0))
                                             for key,(address,size) in fields.items()}
        self.assertEqual(runtime.mixed_retirement(),dict(queue=[3,3],pointers=[[3,3,3]]*2,channels=[[1,1,1]]*2))
