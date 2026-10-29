# SPDX-License-Identifier: GPL-2.0-only
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from m1n1.drm_shim import g17g, g17g_backend as backend, g17g_compute as compute
from m1n1.drm_shim.g17g_adapter import G17GHardwareAdapter
from m1n1.drm_shim.g17g_memory import G17GPageBacking
from m1n1.drm_shim.g17g_runtime import G17GFirstComputeRuntime
from m1n1.drm_shim.g17g_submit import first_compute_graph, first_compute_completion
from m1n1.drm_shim.g17g_sync import G17GPublishedFault
from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_COMPUTE, DRM_ASAHI_BARRIER_NONE


class TestComputeAdapter(unittest.TestCase):
    def test_firmware_objects_match_established_first_compute(self):
        old = backend.build_add_compute_graph()
        new = first_compute_graph(backend.COMPUTE_CDM,
            backend.COMPUTE_CDM + old["cdm_size"], preempt_base=backend.COMPUTE_RESOURCE)
        for key in ("addresses", "firmware_objects", "firmware_patches", "source_global_pages"):
            self.assertEqual(new[key], old[key], key)
        for key in ("dispatch_outputs", "expected_values", "shader_addresses", "values_a", "values_b"):
            self.assertNotIn(key, new)

    def test_builder_does_not_construct_test_program_or_read_caller_stream(self):
        with patch.object(backend, "build_add_compute_graph", side_effect=AssertionError), \
             patch.object(compute, "build_add_shader_program", side_effect=AssertionError), \
             patch.object(compute, "build_compute_pipeline_support", side_effect=AssertionError), \
             patch.object(compute, "build_buffer_resource_tables", side_effect=AssertionError), \
             patch.object(compute, "build_cdm_stream", side_effect=AssertionError):
            graph = first_compute_graph(0x12340000, 0x12340044)
        body = graph["firmware_objects"]["descriptor"]
        self.assertEqual(struct.unpack_from("<Q", body, 0xee0)[0], 0x12340040)
        self.assertNotIn(0x12340000, graph["context1_writes"])

    def test_empty_compute_transport_has_no_dummy_command_or_work_kick(self):
        from m1n1.drm_shim.g17g_compute_queue import transport_state
        with patch.object(compute, 'build_compute_registers', side_effect=AssertionError), \
             patch.object(compute, 'build_compute_descriptor', side_effect=AssertionError):
            graph = first_compute_graph(None, None, empty=True)
        adapter, _, _ = self.adapter()
        runtime = G17GFirstComputeRuntime(adapter.boot)
        for name in ('prepare_control', 'prepare_firmware', 'prepare_context',
                     'prepare_service', 'retire_initial_globals'):
            setattr(runtime, name, Mock())
        runtime.retirement_state = Mock(return_value=transport_state(0))
        evidence = runtime.execute(graph, {})
        self.assertEqual((runtime.state, runtime.completed), ('complete', 0))
        self.assertEqual(graph['compute_descriptor_count'], 0)
        self.assertNotIn('descriptor', graph['firmware_objects'])
        self.assertNotIn('event', graph['firmware_objects'])
        self.assertEqual(struct.unpack_from('<3Q', graph['firmware_objects']['item_ring']),
                         (graph['addresses']['optional'], 0, 0))
        self.assertIn('no command published', evidence['completion_claim'])
        for asc in runtime.asces:
            asc.send.assert_not_called()

    def test_compute_to_render_transition_requires_retirement_and_preserves_backing(self):
        from m1n1.drm_shim.g17g_compute_queue import transport_state
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, commands = self.adapter()
        adapter.preflight(None, queue, commands)
        graph = adapter.last_graph
        runtime = adapter.runtime
        runtime.state, runtime.completed, runtime.mixed_layout = 'complete', 3, False
        runtime.queue_addresses = graph['addresses']
        runtime.private_dvas = set(graph['private_dvas'])
        runtime.compute_context_template = graph
        runtime.context = dict(pages={backend.COMPUTE_ROBUSTNESS: 0x800000},
                               allocations=[(0x800000, 0x4000)])
        adapter.owner_vm = queue.vm
        render = SimpleNamespace(header=SimpleNamespace(cmd_type=DRM_ASAHI_CMD_RENDER,
            vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE),
            hardware_state=None, timestamp_objects=())
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',
                   return_value=backend.build_partial_render_products()['parameters']):
            adapter.preflight(None, queue, (render,))
        self.assertFalse(runtime.mixed_layout)
        self.assertNotIn(backend.COMPUTE_ROBUSTNESS, adapter.last_graph['private_dvas'])
        runtime.retirement_state = Mock(return_value=transport_state(2))
        with self.assertRaisesRegex(RuntimeError, 'live compute queue'):
            runtime.adopt_mixed_layout()
        self.assertFalse(runtime.mixed_layout)
        runtime.retirement_state.return_value = transport_state(3)
        runtime.adopt_mixed_layout()
        self.assertTrue(runtime.mixed_layout)
        self.assertEqual(runtime.context['pages'][backend.COMPUTE_ROBUSTNESS], 0x800000)
        self.assertEqual(runtime.context['allocations'], [(0x800000, 0x4000)])
        self.assertEqual(set(graph['private_dvas']) - runtime.private_dvas,
                         {backend.COMPUTE_ROBUSTNESS})
        self.assertNotIn(compute.COMPUTE_PIPELINE_SUPPORT_DVA, graph['context1_writes'])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_uapi_context_does_not_allocate_unbound_compiler_template_pages(self):
        from m1n1.drm_shim.g17g_mixed_submit import mixed_compute_graph
        adapter, queue, commands = self.adapter()
        adapter.preflight(None, queue, commands)
        runtime = adapter.runtime
        graph = adapter.last_graph
        support = compute.COMPUTE_PIPELINE_SUPPORT_DVA
        for source in (graph, mixed_compute_graph(0x10000, 0x10040)):
            self.assertNotIn(support, source['private_dvas'])
            self.assertNotIn(support, source['context1_writes'])
            absent = runtime.context_dvas(source, {})
            self.assertNotIn(support, absent)
            self.assertTrue(set(source['private_dvas']) <= absent)
            self.assertIn(support, runtime.context_dvas(source,
                {support: G17GPageBacking(0x90000000, False)}))
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)

    def test_first_queue_priority_uses_returned_retargeted_objects(self):
        for priority in (2, 3):
            graph = first_compute_graph(0x10000, 0x10040, priority=priority)
            queue = graph["firmware_objects"]["queue"]
            self.assertEqual(g17g.parse_queue_priority(queue[:g17g.QUEUE_RECORD_SIZE])["priority"], priority)
            self.assertEqual(graph["firmware_priority"], priority)
            # Retargeting must not modify the adjacent post-control record.
            original = backend.build_add_compute_graph()["firmware_objects"]["queue"]
            self.assertEqual(queue[g17g.QUEUE_RECORD_SIZE:], original[g17g.QUEUE_RECORD_SIZE:])

    def test_priority_switch_publishes_only_the_complete_owned_profile(self):
        from m1n1.drm_shim import g17g_postcontrol as post
        from m1n1.drm_shim.g17g_render_submit import continued_render_graph
        from m1n1.drm_shim.g17g_mixed_submit import continued_mixed_partial_graph
        adapter, queue, commands = self.adapter()
        adapter.preflight(None, queue, commands)
        initial = adapter.last_graph
        adapter.runtime.state,adapter.runtime.completed = 'complete',1
        adapter.runtime.queue_addresses = initial['addresses']
        adapter.runtime.private_dvas = set(initial['private_dvas'])
        adapter.owner_vm,adapter.owner_priority = queue.vm,1
        queue.priority = 0
        adapter.preflight(None,queue,commands)
        graphs = [(adapter.last_waves[0],(initial['addresses']['queue'],))]
        params = backend.build_partial_render_products()['parameters']
        graphs += [(continued_render_graph(params,3,private_dvas=(),priority=3),
                    (post.QUEUE_PAGE,post.QUEUE_PAGE+g17g.QUEUE_RECORD_STRIDE)),
                   (continued_mixed_partial_graph(params,3,private_dvas=(),priority=3),
                    (post.QUEUE_PAGE+g17g.QUEUE_RECORD_STRIDE,post.QUEUE_PAGE+2*g17g.QUEUE_RECORD_STRIDE))]
        for graph,addresses in graphs:
            high = dict(graph['high'])
            for address in addresses:
                before = bytes((i*7)&255 for i in range(g17g.QUEUE_RECORD_SIZE))
                after = bytearray(before)
                body = high[address+0x28]
                self.assertEqual(len(body),0x18)
                after[0x28:0x40] = body
                self.assertEqual(g17g.parse_queue_priority(after)['priority'],3)
                self.assertEqual(after[:0x28],before[:0x28])
                self.assertEqual(after[0x40:],before[0x40:])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def adapter(self):
        boot = SimpleNamespace(state="ready", profile="compute", submission_owner=None,
            u=Mock(), p=Mock(), iface=Mock(), uat=Mock(), asces=(Mock(), Mock()),
            synthetic_high_root=0x80000, plan={"ram_pages": {}})
        adapter = G17GHardwareAdapter(boot, lambda file: 0)
        state = SimpleNamespace(cdm_base=0x10000, cdm_end=0x10040,
                                sampler_heap=0, sampler_count=0, helper_binary=0)
        command = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_COMPUTE),
                                  hardware_state=state, timestamp_objects=())
        vm = SimpleNamespace(kernel_start=0x3ffdfff8000, kernel_end=0x3ffffff8000, bindings=[])
        queue = SimpleNamespace(priority=1, vm=vm)
        return adapter, queue, (command,)

    def test_render_vm_switch_uses_fresh_private_state_and_explicit_aliases(self):
        from m1n1.drm_shim import g17g_context1
        from m1n1.drm_shim.g17g_render_submit import first_render_graph
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, _commands = self.adapter()
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        adapter.select_unstarted_runtime(G17GFirstRenderRuntime)
        params = backend.build_clear_render_products()['parameters']
        command = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                  hardware_state=None, timestamp_objects=())
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters', return_value=params):
            adapter.preflight(None, queue, (command,))
            runtime = adapter.runtime
            runtime.state, runtime.completed = 'complete', 1
            runtime.private_dvas = set(adapter.last_graph['private_dvas'])
            adapter.owner_vm = SimpleNamespace(kernel_start=0x3ffdfff8000, kernel_end=0x3ffffff8000, bindings=[])
            adapter.preflight(None, queue, (command,))
        self.assertEqual(adapter.last_waves[0]['ordinal'], 2)
        runtime.pages = {high: 0x80000000+index*0x4000
                         for index, high in enumerate(g17g_context1.POSTCONTROL_ALIASES.values())}
        from m1n1.drm_shim import g17g_render as render
        runtime.render_address_lists = {dva: G17GPageBacking(0x82000000+index*0x4000, True)
                                       for index, dva in enumerate(render.RENDER_ADDRESS_LIST_STORAGE_DVAS)}
        caller = {params.target_dva: G17GPageBacking(0x90000000, True)}
        runtime.prepare_context = Mock(return_value='fresh private roots')
        graph = first_render_graph(params)
        self.assertEqual(runtime.prepare_render_context(graph, caller, install=False), 'fresh private roots')
        args, kwargs = runtime.prepare_context.call_args
        self.assertIs(args[1], caller)
        self.assertFalse(kwargs['install'])
        shared = {low: G17GPageBacking(runtime.pages[high], True)
                  for low, high in g17g_context1.POSTCONTROL_ALIASES.items()}
        shared.update(runtime.render_address_lists)
        self.assertEqual(kwargs['shared_pages'], shared)
        images = dict(graph['context1_writes'])
        for dva in runtime.render_address_lists:
            images.pop(dva, None)
        self.assertEqual(args[0]['context1_writes'], images)
        self.assertNotEqual(images, graph['context1_writes'])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_render_address_ring_owns_full_storage_across_private_contexts(self):
        from m1n1.drm_shim import g17g_context1, g17g_render as render
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        from m1n1.drm_shim.g17g_render_submit import first_render_graph
        adapter, _queue, _commands = self.adapter()
        runtime = G17GFirstRenderRuntime(adapter.boot)
        runtime.pages = {high: 0x80000000+index*0x4000
                         for index, high in enumerate(g17g_context1.POSTCONTROL_ALIASES.values())}
        runtime.alloc = Mock(return_value=0x90000000)
        runtime.publish = Mock()
        runtime.prepare_context = Mock()
        graph = first_render_graph(backend.build_clear_render_products()['parameters'])
        runtime.prepare_render_context(graph, {})
        runtime.alloc.assert_called_once_with(0x400000)
        self.assertEqual(len(runtime.render_address_lists), 256)
        self.assertEqual(runtime.render_address_lists[0x72003fc000].pa, 0x903fc000)
        self.assertEqual(runtime.iface.writemem.call_count, 4)
        published, kwargs = runtime.prepare_context.call_args
        self.assertFalse(set(published[0]['context1_writes']) & set(runtime.render_address_lists))
        self.assertEqual(set(runtime.render_address_lists),
                         set(render.RENDER_ADDRESS_LIST_STORAGE_DVAS))
        ring = dict(runtime.render_address_lists)
        runtime.prepare_render_context(graph, {}, install=False)
        # New VMs must preserve the GPU's recycled metadata, including the
        # initially zero tail, rather than reconstructing a startup list.
        runtime.alloc.assert_called_once()
        self.assertEqual(runtime.iface.writemem.call_count, 4)
        self.assertEqual(runtime.render_address_lists, ring)

    def test_command_types_select_transport_independently_of_shader_bindings(self):
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, commands = self.adapter()
        support = compute.COMPUTE_PIPELINE_SUPPORT_DVA
        queue.vm.bindings = [SimpleNamespace(addr=support, end=support + 0x4000)]
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None, timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters', return_value=params):
            adapter.preflight(None, queue, commands + (render,) + commands)
        graph = adapter.last_graph
        self.assertTrue(graph['mixed_layout'])
        self.assertNotIn(support, graph['private_dvas'])
        self.assertNotIn(support, graph['context1_writes'])
        self.assertTrue(adapter.last_waves[0]['parameters'].request_tvb_growth)
        # Planning a batch must not commit its allocation family.
        self.assertFalse(getattr(adapter.runtime, 'mixed_layout', False))
        queue.vm.bindings = []
        adapter.preflight(None, queue, commands)
        self.assertNotIn(support, adapter.last_graph['private_dvas'])
        self.assertNotIn(support, adapter.last_graph['context1_writes'])
        standalone = adapter.last_graph
        queue.vm.bindings = [SimpleNamespace(addr=support, end=support+0x4000)]
        adapter.preflight(None, queue, commands)
        self.assertEqual(standalone, adapter.last_graph)
        queue.vm.bindings = []
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters', return_value=params):
            adapter.preflight(None, queue, commands + (render,) + commands)
        self.assertEqual(graph, adapter.last_graph)
        self.assertTrue(adapter.tvb_growth)
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_default_mixed_layout_is_retained_after_first_publication(self):
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, commands = self.adapter()
        support = compute.COMPUTE_PIPELINE_SUPPORT_DVA
        queue.vm.bindings = [SimpleNamespace(addr=support, end=support + 0x4000)]
        adapter.preflight(None, queue, commands)
        adapter.runtime.queue_addresses = adapter.last_graph['addresses']
        adapter.runtime.private_dvas = set(adapter.last_graph['private_dvas'])
        adapter.runtime.state, adapter.runtime.completed = 'complete', 1
        adapter.runtime.mixed_layout = True
        adapter.owner_vm, adapter.owner_priority = queue.vm, queue.priority
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None, timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters', return_value=params):
            adapter.preflight(None, queue, (render,) + commands)
        self.assertEqual([wave['format'] for wave in adapter.last_waves], [
            'm1n1-g17g-mixed-partial-firmware-v1', 'm1n1-g17g-mixed-compute-wave-v1'])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_compute_batches_reserve_all_private_writes_before_publication(self):
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_compute_queue import write_pages
        adapter,queue,commands = self.adapter()
        adapter.boot.profile = 'mixed'
        adapter.select_unstarted_runtime(G17GMixedRuntime)
        adapter.preflight(None,queue,commands*4)
        first = adapter.last_graph
        self.assertEqual(len(adapter.last_waves),1)
        wave = adapter.last_waves[0]
        self.assertEqual((wave['completed'],wave['final']),(1,4))
        self.assertEqual(len(wave['records']),3)
        self.assertLessEqual(write_pages(wave['low']),set(first['private_dvas']))
        self.assertNotIn(0x1000018000,first['private_dvas'])
        adapter.runtime.state = 'complete'
        adapter.runtime.completed = 2
        adapter.runtime.queue_addresses = first['addresses']
        adapter.runtime.private_dvas = set(first['private_dvas'])
        adapter.owner_vm,adapter.owner_priority = queue.vm,queue.priority
        adapter.preflight(None,queue,commands*2)
        self.assertEqual((adapter.last_waves[0]['completed'],adapter.last_waves[0]['final']),(2,4))
        adapter.preflight(None,queue,commands*6)
        self.assertEqual(adapter.last_waves[0]['final'],8)
        self.assertLessEqual(write_pages(adapter.last_waves[0]['low']),set(adapter.last_graph['private_dvas']))
        adapter.runtime.completed = 130
        with self.assertRaisesRegex(NotImplementedError,'mixed compute exceeds'):
            adapter.preflight(None,queue,commands*63)
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_engine_batch_preflights_final_render_before_any_publication(self):
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter,queue,commands = self.adapter()
        adapter.boot.profile = 'mixed'
        adapter.select_unstarted_runtime(G17GMixedRuntime)
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None,timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',return_value=params):
            adapter.preflight(None,queue,commands*4+(render,))
            self.assertTrue(adapter.last_waves[-1]['parameters'].request_tvb_growth)
            adapter.tvb_growth = False
            adapter.preflight(None,queue,commands*4+(render,))
            self.assertEqual(len(adapter.last_waves),2)
            self.assertEqual(adapter.last_waves[0]['final'],4)
            self.assertEqual(adapter.last_waves[1]['format'],'m1n1-g17g-mixed-partial-firmware-v1')
            self.assertEqual(adapter.last_graph['private_dvas'],adapter.last_waves[1]['private_dvas'])
            adapter.preflight(None,queue,(render,)+commands)
            self.assertTrue(adapter.last_graph['empty_transport'])
            self.assertEqual(adapter.last_graph['compute_descriptor_count'], 0)
            self.assertNotIn('descriptor', adapter.last_graph['firmware_objects'])
            self.assertIsNone(adapter.last_graph['cdm_base'])
            self.assertEqual([wave['format'] for wave in adapter.last_waves], [
                'm1n1-g17g-mixed-partial-firmware-v1', 'm1n1-g17g-mixed-compute-wave-v1'])
            self.assertEqual(adapter.last_waves[-1]['completed'], 0)
            self.assertEqual(adapter.last_waves[-1]['final'], 1)
        self.assertEqual(adapter.runtime.state,'new')
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_recurrence_keeps_separate_engine_ordinals_and_vm_owner(self):
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter,queue,commands = self.adapter()
        adapter.boot.profile = 'mixed'
        adapter.select_unstarted_runtime(G17GMixedRuntime)
        adapter.tvb_growth = False
        adapter.preflight(None,queue,commands)
        adapter.runtime.queue_addresses = adapter.last_graph['addresses']
        adapter.runtime.private_dvas = set(adapter.last_graph['private_dvas'])
        adapter.runtime.state,adapter.runtime.engine = 'complete','partial'
        adapter.runtime.completed,adapter.runtime.render_completed = 1,2
        adapter.owner_vm,adapter.owner_priority = queue.vm,queue.priority
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None,timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',return_value=params):
            adapter.preflight(None,queue,(render,))
            self.assertEqual(adapter.last_wave['ordinal'],3)
            adapter.preflight(None,queue,commands)
            self.assertEqual((adapter.last_wave['completed'],adapter.last_wave['final']),(1,2))
            adapter.runtime.engine = 'compute'
            adapter.preflight(None,queue,(render,))
            self.assertEqual(adapter.last_wave['ordinal'],3)
            adapter.owner_vm = object()
            adapter.preflight(None,queue,(render,))
            self.assertEqual(adapter.last_wave['ordinal'], 3)
            self.assertEqual(queue.vm.bindings, [])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_ordered_submit_plans_both_engine_returns_without_publication(self):
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, commands = self.adapter()
        adapter.boot.profile = 'mixed'
        adapter.select_unstarted_runtime(G17GMixedRuntime)
        adapter.tvb_growth = False
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None, timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters', return_value=params):
            adapter.preflight(None, queue, commands + (render, render) + commands*2 + (render,))
        waves = adapter.last_waves
        self.assertEqual([wave['format'] for wave in waves], [
            'm1n1-g17g-mixed-partial-firmware-v1',
            'm1n1-g17g-mixed-partial-continuation-v1',
            'm1n1-g17g-mixed-compute-wave-v1',
            'm1n1-g17g-mixed-partial-continuation-v1'])
        self.assertEqual((waves[1]['ordinal'], waves[2]['completed'],
                          waves[2]['final'], waves[3]['ordinal']), (2, 1, 3, 3))
        from m1n1.drm_shim.g17g_mixed_submit import MIXED_COMPUTE_SCHEDULER
        self.assertEqual(waves[2]['addresses']['scheduler'], MIXED_COMPUTE_SCHEDULER)
        # The completed R2 pool remains live across compute return. No C2/C3
        # scheduler publication may overwrite that retained allocation.
        for address, body in waves[2]['high']:
            if MIXED_COMPUTE_SCHEDULER <= address < MIXED_COMPUTE_SCHEDULER + 0x4000:
                for render_address, render_body in waves[1]['high']:
                    self.assertFalse(address < render_address + len(render_body)
                                     and render_address < address + len(body))
        self.assertEqual(adapter.runtime.state, 'new')
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_preflight_plans_render_recreation_inside_one_ioctl(self):
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter,queue,commands = self.adapter()
        adapter.boot.profile = 'mixed'
        adapter.select_unstarted_runtime(G17GMixedRuntime)
        adapter.preflight(None,queue,commands)
        adapter.runtime.queue_addresses = adapter.last_graph['addresses']
        adapter.runtime.private_dvas = set(adapter.last_graph['private_dvas'])
        adapter.runtime.state,adapter.runtime.engine = 'complete','partial'
        adapter.runtime.completed,adapter.runtime.render_completed = 1,425
        adapter.owner_vm,adapter.owner_priority = queue.vm,queue.priority
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None,timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',return_value=params):
            adapter.preflight(None,queue,(render,render)+commands+(render,))
        self.assertEqual([(w['ordinal'],w['transport_start']) for w in adapter.last_waves if 'ordinal' in w],
                         [(426,1),(427,427),(428,427)])
        self.assertEqual((adapter.runtime.completed,adapter.runtime.render_completed),(1,425))
        self.assertFalse(hasattr(adapter.runtime,'render_transport_start'))
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_compute_crosses_its_own_queue_lifetime_after_render(self):
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter,queue,commands = self.adapter()
        adapter.boot.profile = 'mixed'
        adapter.select_unstarted_runtime(G17GMixedRuntime)
        adapter.preflight(None,queue,commands)
        adapter.runtime.queue_addresses = adapter.last_graph['addresses']
        adapter.runtime.private_dvas = set(adapter.last_graph['private_dvas'])
        adapter.runtime.state,adapter.runtime.engine = 'complete','partial'
        adapter.runtime.completed,adapter.runtime.render_completed = 125,1
        adapter.owner_vm,adapter.owner_priority = queue.vm,queue.priority
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None,timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',return_value=params):
            adapter.preflight(None,queue,commands*5+(render,))
        first,second,last = adapter.last_waves
        self.assertEqual((first['completed'],first['final'],second['completed'],second['final']),(125,127,127,130))
        self.assertFalse(first['recreate'])
        self.assertTrue(second['recreate'])
        self.assertEqual(last['ordinal'],2)
        self.assertEqual(second['previous_addresses'],first['addresses'])
        self.assertEqual((adapter.runtime.completed,adapter.runtime.render_completed),(125,1))
        self.assertTrue(any(a==backend.COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS+127*0x40 for a,_ in second['low']))
        adapter.runtime.queue_addresses = second['addresses']
        adapter.runtime.completed = 129
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',return_value=params):
            adapter.preflight(None,queue,commands+(render,))
        following = adapter.last_waves[0]
        self.assertFalse(following['recreate'])
        self.assertEqual(following['addresses']['scheduler'],backend.compute_recreated_queue_addresses(1)['scheduler'])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_late_invalid_render_rejects_entire_submit_before_publication(self):
        from dataclasses import replace
        from m1n1.drm_shim.g17g_mixed_runtime import G17GMixedRuntime
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, commands = self.adapter()
        adapter.boot.profile = 'mixed'
        adapter.select_unstarted_runtime(G17GMixedRuntime)
        adapter.tvb_growth = False
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None, timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',
                   side_effect=(params, replace(params, width=0))):
            with self.assertRaises(ValueError):
                adapter.preflight(None, queue, commands + (render,) + commands + (render,))
        self.assertIsNone(adapter.last_graph)
        self.assertEqual(adapter.runtime.state, 'new')
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_mixed_ordinary_then_partial_keeps_each_grammar_and_caller_support(self):
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, commands = self.adapter()
        support = compute.COMPUTE_PIPELINE_SUPPORT_DVA
        queue.vm.bindings = [SimpleNamespace(addr=support,end=support+0x4000)]
        render = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                 hardware_state=None,timestamp_objects=())
        ordinary = backend.build_clear_render_products()['parameters']
        partial = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',side_effect=(ordinary,partial)):
            adapter.preflight(None,queue,commands+(render,render))
        first, second = adapter.last_waves
        self.assertFalse(first['parameters'].partial_mode)
        self.assertFalse(first['parameters'].request_tvb_growth)
        self.assertTrue(second['parameters'].partial_mode)
        self.assertTrue(second['parameters'].request_tvb_growth)
        self.assertNotIn(support,first['context1_writes'])
        self.assertNotIn(support,first['private_dvas'])
        self.assertEqual(adapter.runtime.state,'new')
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_growth_batch_keeps_every_command_as_a_host_serviced_wave(self):
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter,queue,_ = self.adapter()
        adapter.select_unstarted_runtime(G17GFirstRenderRuntime)
        adapter.runtime.state = 'complete'
        adapter.runtime.completed = 5
        adapter.runtime.partial_mode = True
        adapter.runtime.minimal_partial_continuation = True
        adapter.runtime.private_dvas = set(backend.expand_third_direct_render_context1_dvas())
        adapter.owner_vm,adapter.owner_priority = queue.vm,queue.priority
        command = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                  hardware_state=None,timestamp_objects=())
        params = backend.build_partial_render_products()['parameters']
        with patch('m1n1.drm_shim.g17g_render_submit.render_parameters',return_value=params):
            adapter.preflight(None,queue,(command,)*4)
        self.assertEqual([wave['ordinal'] for wave in adapter.last_waves],[6,7,8,9])
        self.assertTrue(all(wave['parameters'].request_tvb_growth for wave in adapter.last_waves))
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_initial_partial_batch_preserves_source_warmup_order(self):
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        adapter, queue, _ = self.adapter()
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        adapter.select_unstarted_runtime(G17GFirstRenderRuntime)
        params = backend.build_partial_render_products()["parameters"]
        command = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                  hardware_state=None, timestamp_objects=())
        with patch("m1n1.drm_shim.g17g_render_submit.render_parameters", return_value=params):
            adapter.preflight(None, queue, (command,) * 8)
            self.assertEqual([wave['ordinal'] for wave in adapter.last_waves], list(range(2, 9)))
            self.assertEqual(adapter.runtime.state, 'new')
            self.assertFalse(getattr(adapter.runtime, 'minimal_partial_continuation', False))
            adapter.tvb_growth = False
            adapter.preflight(None, queue, (command,) * 8)
            self.assertEqual([wave['ordinal'] for wave in adapter.last_waves[:4]], [2, 3, 4, 5])
            batch = adapter.last_waves[4]
            self.assertEqual([record['ordinal'] for record in batch['records']], [6, 7, 8])
            # Reservation includes every arena reached during warm-up, even
            # though none has been allocated or published during planning.
            from m1n1.drm_shim.g17g_partial_runtime import warmup_dvas
            for ordinal in (3, 4, 5):
                self.assertTrue(set(warmup_dvas(ordinal)) <= set(adapter.last_graph['private_dvas']))
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)
        self.assertFalse(adapter.iface.mock_calls)

    def test_second_partial_plans_private_labels_without_reserving_caller_vas(self):
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        adapter, queue, _ = self.adapter()
        params = backend.build_partial_render_products()["parameters"]
        command = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                  hardware_state=None, timestamp_objects=())
        adapter.select_unstarted_runtime(G17GFirstRenderRuntime)
        adapter.runtime.state, adapter.runtime.completed, adapter.runtime.partial_mode = "complete", 1, True
        adapter.runtime.private_dvas = set()
        adapter.owner_vm, adapter.owner_priority = queue.vm, queue.priority
        with patch("m1n1.drm_shim.g17g_render_submit.render_parameters", return_value=params):
            adapter.preflight(None, queue, (command,))
            self.assertTrue(set(backend.expand_second_direct_render_context1_dvas()) <=
                            set(adapter.last_graph["private_dvas"]))
            dva = backend.expand_second_direct_render_context1_dvas()[-1]
            queue.vm.bindings = [SimpleNamespace(addr=dva, end=dva + 0x4000)]
            adapter.preflight(None, queue, (command,))
            self.assertIn(dva, adapter.context_owner(queue.vm).layout.private)
            adapter.runtime.completed = 5
            with self.assertRaisesRegex(NotImplementedError, "partial continuation"):
                adapter.preflight(None, queue, (command,))
            adapter.runtime.minimal_partial_continuation = True
            adapter.runtime.private_dvas = set(backend.expand_third_direct_render_context1_dvas())
            queue.vm.bindings = []
            for completed in (5, 6, 63, 64, 255, 425):
                adapter.runtime.completed = completed
                adapter.preflight(None, queue, (command,))
                self.assertEqual(adapter.last_graph["ordinal"], completed + 1)
                from m1n1.drm_shim.g17g_compute_queue import write_pages
                self.assertEqual(set(adapter.last_graph["private_dvas"]),
                    adapter.runtime.private_dvas | write_pages(adapter.last_graph["low"]))
            adapter.runtime.completed = 426
            adapter.preflight(None, queue, (command,))
            self.assertEqual(adapter.last_graph["ordinal"], 427)
            self.assertEqual(adapter.last_graph["transport_start"], 427)
            adapter.runtime.completed = 5
            adapter.preflight(None, queue, (command, command))
            self.assertEqual([wave['ordinal'] for wave in adapter.last_waves],[6,7])
            adapter.tvb_growth = False
            adapter.preflight(None, queue, (command, command))
            self.assertEqual(len(adapter.last_waves), 1)
            self.assertEqual([row["ordinal"] for row in adapter.last_graph["records"]], [6,7])
            adapter.preflight(None, queue, (command,) * 64)
            self.assertEqual(len(adapter.last_waves), 1)
            self.assertEqual(adapter.last_graph["final"], 69)
            adapter.runtime.completed = 421
            adapter.preflight(None, queue, (command,) * 64)
            self.assertEqual([(w["completed"], w["final"], w["transport_start"])
                              for w in adapter.last_waves], [(421, 426, 1), (426, 485, 427)])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)

    def test_preflight_rejects_unported_work_before_proxy_or_allocation(self):
        adapter, queue, commands = self.adapter()
        with self.assertRaises(NotImplementedError):
            adapter.preflight(None, queue, commands * 65)
        self.assertEqual(adapter.u.mock_calls, [])
        commands[0].hardware_state.sampler_count = 1
        with self.assertRaisesRegex(ValueError, 'sampler heap/count'):
            adapter.preflight(None, queue, commands)
        commands[0].hardware_state.sampler_count = 0
        commands[0].hardware_state.helper_binary = 1
        with self.assertRaises(NotImplementedError):
            adapter.preflight(None, queue, commands)
        self.assertEqual(adapter.u.mock_calls, [])

    def test_sampler_states_reach_first_and_batched_compute_in_both_layouts(self):
        for mixed in (False, True):
            adapter, queue, template = self.adapter()
            if mixed:
                support = compute.COMPUTE_PIPELINE_SUPPORT_DVA
                queue.vm.bindings = [SimpleNamespace(addr=support, end=support+0x4000)]
            states = ((0x220008, 1), (0, 0), (0x240008, 2), (0x260008, 1024))
            commands = tuple(SimpleNamespace(**{**vars(template[0]), 'hardware_state':
                SimpleNamespace(**{**vars(template[0].hardware_state), 'sampler_heap':heap,
                                   'sampler_count':count})}) for heap,count in states)
            adapter.preflight(None, queue, commands)
            descriptors = [adapter.last_graph['firmware_objects']['descriptor']]
            for wave in adapter.last_waves:
                high = dict(wave['high'])
                descriptors.extend(high[row['addresses']['descriptor']] for row in wave['records'])
            self.assertEqual([struct.unpack_from('<QII', body, 0xf2c) for body in descriptors],
                             [(heap,count,count+1 if count else 0) for heap,count in states])
            self.assertFalse(adapter.u.mock_calls)
            self.assertFalse(adapter.p.mock_calls)
            self.assertFalse(adapter.iface.mock_calls)

    def test_ordinary_waves_split_at_natural_transport_recreation(self):
        from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_CMD_RENDER
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        adapter, queue, _ = self.adapter()
        params = backend.build_clear_render_products()["parameters"]
        command = SimpleNamespace(header=SimpleNamespace(vdm_barrier=DRM_ASAHI_BARRIER_NONE, cdm_barrier=DRM_ASAHI_BARRIER_NONE, cmd_type=DRM_ASAHI_CMD_RENDER),
                                  hardware_state=None, timestamp_objects=())
        adapter.select_unstarted_runtime(G17GFirstRenderRuntime)
        runtime = adapter.runtime
        runtime.state, runtime.completed, runtime.partial_mode = "complete", 421, False
        runtime.private_dvas = set()
        adapter.owner_vm, adapter.owner_priority = queue.vm, queue.priority
        with patch("m1n1.drm_shim.g17g_render_submit.render_parameters", return_value=params):
            adapter.preflight(None, queue, (command,) * 8)
            self.assertEqual([(wave["completed"], wave["final"], wave["transport_start"])
                              for wave in adapter.last_waves], [(421,426,1), (426,429,427)])
            runtime.completed, runtime.transport_start = 852, 427
            adapter.preflight(None, queue, (command,))
            self.assertEqual([(wave["completed"], wave["final"], wave["transport_start"])
                              for wave in adapter.last_waves], [(852,853,853)])
        self.assertFalse(adapter.u.mock_calls)
        self.assertFalse(adapter.p.mock_calls)

    def test_private_allocation_labels_do_not_reserve_caller_addresses(self):
        adapter, queue, commands = self.adapter()
        adapter.preflight(None, queue, commands)
        low = min(adapter.last_graph["private_dvas"])
        for start, end in ((low-0x4000,low), (low,low+0x4000),
                           (low-0x4000,low+0x4000), (0x10000,0x14000)):
            queue.vm.bindings = [SimpleNamespace(addr=start,end=end)]
            adapter.preflight(None, queue, commands)
        self.assertFalse(adapter.u.mock_calls)

    def test_submit_has_no_output_oracle_and_pulls_before_signaling(self):
        adapter, queue, commands = self.adapter()
        adapter.materialize = Mock(return_value={})
        order = []
        adapter.runtime.execute = Mock(side_effect=lambda *a, **k: order.append("execute"))
        adapter.pull = Mock(side_effect=lambda vm: order.append("pull"))
        fence = adapter.submit(None, queue, commands)
        self.assertEqual(order, ["execute", "pull"])
        self.assertTrue(fence.signaled())
        self.assertIsNone(fence.error)
        self.assertNotIn("expected_values", adapter.last_graph)

    def test_published_command_fault_returns_error_fence_and_loses_device(self):
        adapter, queue, commands = self.adapter()
        adapter.materialize = Mock(return_value={})
        def fail(*args, **kwargs):
            adapter.runtime.evidence["command_publication_started"] = True
            raise G17GPublishedFault.command_fetch_mmu()
        adapter.runtime.execute = Mock(side_effect=fail)
        adapter.pull = Mock()
        fence = adapter.submit(None, queue, commands)
        self.assertTrue(fence.signaled())
        self.assertEqual(fence.error, -19)
        self.assertTrue(adapter.device_lost)
        adapter.pull.assert_not_called()
        with self.assertRaises(OSError):
            adapter.preflight(None, queue, commands)

    def test_prepublication_failure_creates_no_fence(self):
        adapter, queue, commands = self.adapter()
        adapter.materialize = Mock(side_effect=MemoryError)
        with self.assertRaises(MemoryError):
            adapter.submit(None, queue, commands)
        self.assertFalse(adapter.device_lost)

    def test_memory_limit_keeps_device_only_after_runtime_proves_quiescence(self):
        for quiescent in (False, True):
            adapter, queue, commands = self.adapter()
            adapter.materialize = Mock(return_value={})
            def fail(*args, **kwargs):
                adapter.runtime.evidence.update(command_publication_started=True,
                                                 memory_limit_quiescent=quiescent)
                adapter.runtime.state = 'complete'
                raise G17GPublishedFault('tvb-memory-limit', -12, recoverable=True)
            adapter.runtime.execute = Mock(side_effect=fail)
            adapter.pull = Mock()
            fence = adapter.submit(None, queue, commands)
            self.assertTrue(fence.signaled())
            self.assertEqual(fence.error, -12)
            self.assertEqual(adapter.device_lost, not quiescent)
            self.assertEqual(adapter.runtime.state, 'complete' if quiescent else 'failed')
            if quiescent:
                self.assertIs(adapter.owner_vm, queue.vm)
                self.assertEqual(adapter.owner_priority, queue.priority)
                adapter.pull.assert_called_once_with(queue.vm)
            else:
                adapter.pull.assert_not_called()

    def test_memory_limit_readback_failure_keeps_backing_pinned(self):
        adapter, queue, commands = self.adapter()
        adapter.materialize = Mock(return_value={})
        def fail(*args, **kwargs):
            adapter.runtime.evidence.update(command_publication_started=True,
                                             memory_limit_quiescent=True)
            adapter.runtime.state = 'complete'
            raise G17GPublishedFault('tvb-memory-limit', -12, recoverable=True)
        adapter.runtime.execute = Mock(side_effect=fail)
        adapter.pull = Mock(side_effect=OSError('readback transport failed'))
        fence = adapter.submit(None, queue, commands)
        self.assertTrue(fence.signaled())
        self.assertEqual(fence.error, -5)
        self.assertTrue(adapter.device_lost)
        self.assertEqual(adapter.runtime.state, 'failed')
        saved = adapter.runtime.evidence['failed_readback']['completed_fault']
        self.assertEqual(saved['error'], -12)
        self.assertTrue(saved['recoverable'])

    def test_reported_fault_does_not_complete_successfully_despite_retired_cursors(self):
        adapter, _queue, _commands = self.adapter()
        runtime = adapter.runtime
        graph = first_compute_graph(0x10000, 0x10040)
        runtime.prepare_control = Mock()
        runtime.prepare_firmware = Mock()
        runtime.prepare_context = Mock()
        runtime.prepare_service = Mock()
        runtime.retire_initial_globals = Mock()
        before, after = self.completion_data()
        after["reports"]["records"] = [(struct.pack("<4I", 4, 0, 0, 0xffffffff) + bytes(56)).hex()]
        runtime.completion_observation = Mock(side_effect=(before, after))
        runtime.retirement_state = Mock(side_effect=(
            dict(channel=(0, 0, 1), pointers=(0, 0, 3), queue_limit=0),
            dict(channel=(1, 1, 1), pointers=(3, 3, 3), queue_limit=3)))
        runtime.fault_status = Mock(return_value=dict(
            faulted=True, address_raw=0x10000 >> 6, info=1))
        with self.assertRaises(G17GPublishedFault) as raised:
            runtime.execute(graph, {})
        self.assertEqual(raised.exception.error, -19)
        self.assertEqual(runtime.state, "failed")
        self.assertEqual(runtime.evidence["execution_claim"], "none")
        runtime.asces[0].work.assert_called_once_with()
        runtime.fault_status.assert_called_once_with()

    def test_published_timeout_uses_linux_not_host_errno(self):
        adapter, queue, commands = self.adapter()
        adapter.materialize = Mock(return_value={})
        def fail(*args, **kwargs):
            adapter.runtime.evidence["command_publication_started"] = True
            raise TimeoutError("completion")
        adapter.runtime.execute = Mock(side_effect=fail)
        fence = adapter.submit(None, queue, commands)
        self.assertEqual(fence.error, -110)

    def test_multi_command_submit_releases_one_continuation_wave_then_pulls(self):
        adapter, queue, commands = self.adapter()
        adapter.materialize = Mock(return_value={})
        order = []
        adapter.runtime.execute = Mock(side_effect=lambda *a, **k: order.append("first"))
        adapter.runtime.execute_wave = Mock(side_effect=lambda *a, **k: order.append("wave"))
        adapter.pull = Mock(side_effect=lambda vm: order.append("pull"))
        fence = adapter.submit(None, queue, commands * 4)
        self.assertEqual(order, ["first", "wave", "pull"])
        self.assertEqual(len(adapter.last_wave["records"]), 3)
        self.assertEqual(len(fence.fences), 4)
        self.assertTrue(all(child.signaled() for child in fence.fences))

    def test_stale_prior_publication_does_not_turn_preflight_error_into_device_loss(self):
        adapter, queue, commands = self.adapter()
        adapter.runtime.evidence["command_publication_started"] = True
        adapter.timeout = float("nan")
        with self.assertRaises(ValueError):
            adapter.submit(None, queue, commands)
        self.assertFalse(adapter.device_lost)

    def test_large_uapi_submit_has_one_wave_and_one_aggregate_fence(self):
        adapter, queue, commands = self.adapter()
        adapter.materialize = Mock(return_value={})
        adapter.runtime.execute = Mock()
        adapter.runtime.execute_wave = Mock()
        adapter.pull = Mock()
        fence = adapter.submit(None, queue, commands * 16)
        waves = [call.args[0] for call in adapter.runtime.execute_wave.call_args_list]
        self.assertEqual([len(wave["records"]) for wave in waves], [15])
        self.assertEqual([wave["final"] for wave in waves], [16])
        self.assertEqual(len(fence.fences), 16)
        self.assertTrue(fence.signaled())
        self.assertIsNone(fence.error)
        adapter.pull.assert_called_once_with(queue.vm)

    def test_owned_field_gather_handles_noncontiguous_pages_without_gap_reads(self):
        adapter, _queue, _commands = self.adapter()
        runtime = adapter.runtime
        runtime.pages = {0x4000: 0x10000, 0x8000: 0x30000}
        with patch("m1n1.drm_shim.g17g_runtime.read_ranges", side_effect=lambda _u, _p, _i, ranges:
                tuple(bytes([1 if pa < 0x30000 else 2]) * size for pa, size in ranges)) as gather:
            data = runtime.read_fields({"first": (0x7ff0, 32), "overlap": (0x7ff8, 8), "last": (0x8010, 4)})
        self.assertEqual(data["first"], bytes([1]) * 16 + bytes([2]) * 16)
        self.assertEqual(data["overlap"], bytes([1]) * 8)
        self.assertEqual(data["last"], bytes([2]) * 4)
        self.assertEqual(gather.call_count, 1)
        self.assertEqual(gather.call_args.args[3], ((0x13ff0, 16), (0x30000, 16), (0x13ff8, 8), (0x30010, 4)))

    def test_publication_scatters_validate_all_page_fragments(self):
        pages = {0x4000: 0x10000, 0x8000: 0x30000}
        writes = ((0x7ff0, b"A" * 16 + b"B" * 8), (0x8020, b"C" * 4))
        self.assertEqual(G17GFirstComputeRuntime.physical_writes(writes, pages),
                         ((0x13ff0, b"A" * 16), (0x30000, b"B" * 8), (0x30020, b"C" * 4)))
        with self.assertRaises(KeyError):
            G17GFirstComputeRuntime.physical_writes(writes, {0x4000: 0x10000})

    def test_unchanged_caller_ptes_are_not_rewritten_but_permission_changes_are(self):
        adapter, _queue, _commands = self.adapter()
        runtime = adapter.runtime
        runtime.context = dict(root0=0x80000, pages={})
        pages = {0x4000: G17GPageBacking(0x10000, True)}
        self.assertEqual(runtime.update_caller_mappings(pages), 1)
        runtime.uat.iomap_at_root.assert_called_once()
        runtime.uat.iomap_at_root.reset_mock()
        self.assertEqual(runtime.update_caller_mappings(pages), 0)
        runtime.uat.iomap_at_root.assert_not_called()
        pages[0x4000] = G17GPageBacking(0x10000, False)
        self.assertEqual(runtime.update_caller_mappings(pages), 1)
        runtime.uat.iomap_at_root.assert_called_once()
        runtime.uat.iomap_at_root.reset_mock()
        pages[0x4000] = G17GPageBacking(0x30000, False)
        self.assertEqual(runtime.update_caller_mappings(pages), 1)
        self.assertEqual(runtime.context["pages"][0x4000], 0x30000)

    def test_success_never_reads_sgx(self):
        adapter, _queue, _commands = self.adapter()
        runtime = adapter.runtime
        for name in ("prepare_control", "prepare_firmware", "prepare_context",
                     "prepare_service", "retire_initial_globals"):
            setattr(runtime, name, Mock())
        runtime.completion_observation = Mock(side_effect=self.completion_data())
        runtime.retirement_state = Mock(side_effect=(
            dict(channel=(0, 0, 1), pointers=(0, 0, 3), queue_limit=0),
            dict(channel=(1, 1, 1), pointers=(3, 3, 3), queue_limit=3)))
        runtime.fault_status = Mock(side_effect=AssertionError("gated MMIO"))
        runtime.execute(first_compute_graph(0x10000, 0x10040), {})
        runtime.fault_status.assert_not_called()
        self.assertEqual(runtime.state, "complete")

    def test_batch_unmap_has_one_flush_and_validates_all_mappings_before_writes(self):
        adapter, _queue, _commands = self.adapter()
        runtime = adapter.runtime
        runtime.state = "complete"
        runtime.context = dict(root0=0x20000, pages={0x10000: 0x40000, 0x18000: 0x80000})
        runtime.context["caller_mappings"] = {dva: G17GPageBacking(pa, True)
                                               for dva, pa in runtime.context["pages"].items()}
        bindings = tuple(SimpleNamespace(addr=a, end=a + 0x4000, size=0x4000)
                         for a in (0x10000, 0x18000))
        runtime.uat.iotranslate.side_effect = (
            [(0x40000, 0x4000)], [(0x80000, 0x4000)], [(None, 0x4000)], [(None, 0x4000)])
        runtime.uat.iounmap_root.return_value = 0x4000
        runtime.flush_tables = Mock()
        runtime.unmap_bindings(bindings)
        runtime.flush_tables.assert_called_once_with(1)
        self.assertEqual(runtime.context["pages"], {})
        self.assertEqual(runtime.context["caller_mappings"], {})
        self.assertEqual(runtime.uat.iounmap_root.call_count, 2)

        runtime.context["pages"] = {0x10000: 0x40000, 0x18000: 0x80000}
        runtime.uat.iounmap_root.reset_mock()
        runtime.uat.iotranslate.side_effect = ([(0x40000, 0x4000)], [(None, 0x4000)])
        with self.assertRaisesRegex(RuntimeError, "no longer matches"):
            runtime.unmap_bindings(bindings)
        runtime.uat.iounmap_root.assert_not_called()

    @staticmethod
    def completion_data():
        before = {name: bytes(16).hex() for name in
                  ("dispatch_a", "dispatch_b", "status_a", "status_b")}
        before["reports"] = dict(producer=0, consumer=0, records=[])
        after = dict(before)
        after["dispatch_a"] = (struct.pack("<I", 0x100) + bytes(12)).hex()
        after["status_a"] = struct.pack("<QQ", 100, 200).hex()
        after["status_b"] = struct.pack("<QQ", 200, 0).hex()
        tail = bytearray(0xe0)
        struct.pack_into("<QQ", tail, 0x2c, 100, 200)
        after["descriptor_tail"] = tail.hex()
        after["reports"] = dict(producer=1, consumer=0, records=[
            (struct.pack("<4I", 1, 1, 0, 0) + b"X" * 56).hex()])
        return before, after

    def test_completion_requires_report_stamp_and_mirrored_timestamps(self):
        before, after = self.completion_data()
        self.assertEqual(first_compute_completion(before, after), "complete")
        for field in ("dispatch_a", "status_a", "status_b"):
            invalid = dict(after, **{field: bytes(16).hex()})
            self.assertIsNone(first_compute_completion(before, invalid))
        invalid = dict(after, descriptor_tail=bytes(0xe0).hex())
        self.assertIsNone(first_compute_completion(before, invalid))
        invalid = dict(after, reports=dict(producer=0, consumer=0, records=[]))
        self.assertIsNone(first_compute_completion(before, invalid))

    def test_wrong_report_owner_cannot_complete(self):
        before, after = self.completion_data()
        after["reports"]["records"] = [(struct.pack("<4I", 1, 3, 0, 0) + bytes(56)).hex()]
        with self.assertRaisesRegex(ValueError, "unclassified"):
            first_compute_completion(before, after)
