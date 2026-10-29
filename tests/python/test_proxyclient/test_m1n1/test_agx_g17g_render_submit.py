# SPDX-License-Identifier: GPL-2.0-only
from dataclasses import replace
from contextlib import ExitStack
import copy
import struct
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from m1n1.drm_shim import g17g_backend as backend, g17g_render as render
from m1n1.drm_shim.g17g_render_submit import first_render_graph, second_render_graph, continued_render_graph, render_parameters, first_render_completion
from m1n1.drm_shim.g17g_shim import G17GShimBackend


class TestFirstRenderFirmware(unittest.TestCase):
    def test_subpage_arrays_and_optional_depth_bias_reach_fragment_descriptor(self):
        baseline = backend.build_partial_render_products()['parameters']
        for dbias in (0, 0x1804000008, 0x1804000108):
            params = replace(baseline, scissor_array=0x1804000008, depth_bias_array=dbias)
            params.validate()
            graph = first_render_graph(params)
            body = graph['firmware_pages']['fragment_descriptor']
            self.assertEqual(struct.unpack_from('<Q', body, 0x1d30)[0], 0x1804000008)
            self.assertEqual(struct.unpack_from('<Q', body, 0x1d20)[0], dbias)
        for scissor, dbias in ((0, 0), (0x1804000004, 0), (0x1804000008, 4)):
            with self.assertRaises(ValueError):
                replace(baseline, scissor_array=scissor, depth_bias_array=dbias).validate()

    def test_vdm_native_offset_is_39_bits_without_truncation(self):
        baseline = backend.build_partial_render_products()['parameters']
        for address in (0x1100018004, 0x7000018004, 0x8ffffffffc):
            params = replace(baseline, vdm_ctrl_stream_base=address)
            registers = dict(render.build_tiling_registers(params))
            self.assertEqual(registers[0x1c880], address-render.VDM_RESOURCE_BASE)
        for address in (0x4004, 0x9000000000, 0x10004018004, 0x1100018002):
            with self.assertRaises(ValueError):
                replace(baseline, vdm_ctrl_stream_base=address).validate()

    def test_shared_transport_keeps_mixed_queues_separate_without_caller_assets(self):
        params = backend.build_partial_render_products()["parameters"]
        with ExitStack() as stack:
            for owner, name in (
                (backend, "build_clear_render_products"),
                (backend, "build_partial_render_products"),
                (backend, "build_earliest_mixed_render_caller_pages"),
                (render, "build_clear_pipeline_page"),
                (render, "build_clear_state_page"),
                (backend.g17g_render_compiler, "build_clear_compiler_pages"),
            ):
                stack.enter_context(patch.object(owner, name,
                    side_effect=AssertionError("transport constructed caller assets")))
            for options, queues in (
                ({}, (0xfffffc20c0000000, 0xfffffc20c0000080)),
                (dict(mixed_compute_pending=True),
                 (0xfffffc20c0000080, 0xfffffc20c0000100)),
                (dict(mixed_compute_pending=True, compute_publication_count=2),
                 (0xfffffc20c0000080, 0xfffffc20c0000180)),
                (dict(mixed_compute_pending=True, compute_predecessor=True),
                 (0xfffffc20c0000080, 0xfffffc20c0000100)),
            ):
                graph = backend.build_render_transport(params, **options)
                self.assertIs(graph["parameters"], params)
                self.assertFalse({"context1_writes", "attachments", "zls_outputs",
                                  "timestamp_outputs"} & graph.keys())
                for name, queue in zip(("channel_ring_6", "channel_ring_7"), queues):
                    patches = graph["firmware_patches"][name]
                    self.assertEqual(len(patches), 1)
                    self.assertEqual(struct.unpack_from("<Q", patches[0][1], 8)[0], queue)
                if options.get("compute_predecessor"):
                    # A live compute queue must survive later render publication.
                    self.assertEqual(graph["source_global_pages"], {})
                    self.assertEqual(graph["firmware_live_preserve_ranges"]["queue"], ((0, 0x80),))
                    self.assertEqual(len(graph["fresh_global_pages"]), 36)

    def test_mixed_transition_qwords_do_not_construct_test_products(self):
        with patch.object(backend, "build_earliest_mixed_partial_render_products",
                          side_effect=AssertionError("transition constructed test products")):
            rows = backend.build_compute_predecessor_partial_render_inter_epoch_qwords()
        self.assertEqual({page + offset: value for page, entries in rows.items()
                          for offset, value, _label in entries}, {
            0xfffffc20015e8000: 0x3000024000,
            0xfffffc20015f0020: 0xe4035400,
            0xfffffc20015f0028: 0x240000000000,
            0xfffffc20015f0030: 0x8000000002400,
            0xfffffc20c0796648: 0xfffffc20c0000080,
            0xfffffc20c0796650: 0x0101000300000000,
            0xfffffc20c079c648: 0xfffffc20c0000100,
            0xfffffc20c079c650: 0x0102000300000001,
        })

    def test_partial_caller_timestamps_preserve_destinations_and_private_namespace(self):
        from m1n1.drm_shim.g17g_timestamp import TIMESTAMP_USER_BASE
        from m1n1.drm_shim.g17g_render_submit import partial_timestamp_destinations
        base = TIMESTAMP_USER_BASE
        params = replace(backend.build_partial_render_products()["parameters"],
                         tiling_user_timestamp_start=base + 8,
                         tiling_user_timestamp_end=base + 16,
                         fragment_user_timestamp_start=base + 0x4008,
                         fragment_user_timestamp_end=base + 0x4010)
        first = first_render_graph(params, private_completion=True, external_timestamps=True)
        later = continued_render_graph(params, 513, private_dvas=(), retain_partial_slot=False,
                                       transport_start=427)
        for graph in (first, later):
            self.assertEqual(graph["completion_timestamp_addresses"],
                             (base + 8, base + 16, base + 0x4008, base + 0x4010))
            self.assertEqual(struct.unpack_from("<2Q", graph["items"]["tiling_descriptor"], 0x90e),
                             (base + 8, base + 16))
            self.assertEqual(struct.unpack_from("<2Q", graph["items"]["fragment_descriptor"], 0x21a8),
                             (base + 0x4008, base + 0x4010))
        self.assertEqual(set(first["fresh_global_pages"]), {render.TIMESTAMP_APERTURE_BASE})
        self.assertEqual(dict(later["high"])[later["completion_timestamps"]], bytes(32))
        self.assertFalse(any(address < base + 0x8000 and base < address + len(body)
                             for address, body in later["high"]))
        _, private, _ = partial_timestamp_destinations(params, 65535)
        self.assertLessEqual(private + 32, TIMESTAMP_USER_BASE)
        with self.assertRaisesRegex(ValueError, "private storage"):
            partial_timestamp_destinations(replace(params, fragment_user_timestamp_end=base - 8), 1)

    def test_partial_timestamp_completion_accepts_reused_and_aliased_caller_words(self):
        from m1n1.drm_shim.g17g_timestamp import TIMESTAMP_USER_BASE
        report = (struct.pack("<I", 1) + bytes(0x44)).hex()
        before = dict(reports=dict(consumer=0, producer=1, records=[report]),
                      execution_timestamps=(b"\x5a" * 32).hex(), partial_completion=bytes(4).hex(),
                      execution_timestamp_addresses=(TIMESTAMP_USER_BASE + 8,) * 4)
        after = dict(before, execution_timestamps=struct.pack("<4Q", 130, 130, 130, 130).hex(),
                     partial_completion=struct.pack("<I", 2).hex())
        self.assertEqual(first_render_completion(before, after, 3), "complete")
        self.assertIsNone(first_render_completion(before, dict(after, partial_completion=bytes(4).hex()), 3))
        self.assertIsNone(first_render_completion(before, dict(after,
                          execution_timestamps=before["execution_timestamps"]), 3))

    def test_external_timestamps_preserve_caller_backing_and_exact_destinations(self):
        from m1n1.drm_shim.g17g_timestamp import TIMESTAMP_END
        base = render.TIMESTAMP_APERTURE_BASE + 0x8000
        params = replace(self.params(), tiling_user_timestamp_start=base + 8,
                         tiling_user_timestamp_end=base + 16,
                         fragment_user_timestamp_start=base + 0x4008,
                         fragment_user_timestamp_end=base + 0x4010)
        graph = first_render_graph(params, external_timestamps=True)
        self.assertEqual(graph["fresh_global_pages"], {})
        self.assertIsNone(graph["completion_timestamps"])
        self.assertEqual(struct.unpack_from("<2Q", graph["items"]["tiling_descriptor"], 0x90e),
                         (base + 8, base + 16))
        self.assertEqual(struct.unpack_from("<2Q", graph["items"]["fragment_descriptor"], 0x21a8),
                         (base + 0x4008, base + 0x4010))
        with self.assertRaisesRegex(ValueError, "outside"):
            first_render_graph(replace(params, fragment_user_timestamp_end=TIMESTAMP_END),
                               external_timestamps=True)
        with self.assertRaisesRegex(ValueError, "partial"):
            first_render_graph(params, private_completion=True, external_timestamps=True)

    def test_history_restoration_preserves_backing_and_rejects_changed_ownership(self):
        from m1n1.drm_shim import g17g_defaults, g17g_initdata
        from m1n1.drm_shim.g17g_partial_runtime import restore_history_mappings
        for error in (None, "foreign_root", "changed_descriptor", "failed_owner"):
            fields = g17g_defaults.canonical_preinit_fields()
            records = fields["hwdata_fields"]["region_records"]
            addresses = [record["address_0c"] + offset for record in records
                         for offset in range(0, 0x20000, 0x4000)]
            pages = {dva: 0x100000000 + i * 0x4000 for i, dva in enumerate(addresses)}
            missing = {addresses[4], addresses[20]}
            roots = (1, 2, 3)
            mappings = {(root, dva): [(None if dva in missing else pa, 0x4000)]
                        for root in roots for dva, pa in pages.items()}
            bodies = {i: g17g_initdata.build_region_record(**record) for i, record in enumerate(records)}
            runtime = SimpleNamespace(partial_mode=True, completed=5, state="complete", root=1,
                pages=pages, boot=SimpleNamespace(fields=fields, firmware_roots=dict(primary=2, secondary=3)),
                read_fields=Mock(return_value=bodies), uat=SimpleNamespace(
                    iotranslate_root=lambda root,dva,size:mappings[root,dva]))
            runtime.boot.submission_owner = runtime
            def publish(dvas, *, fresh):
                self.assertFalse(fresh)
                self.assertEqual(set(dvas), missing)
                for root in roots:
                    for dva in dvas:
                        mappings[root, dva] = [(pages[dva], 0x4000)]
            runtime.map_globals = Mock(side_effect=publish)
            if error == "foreign_root": mappings[2, addresses[-1]] = [(0xdead0000, 0x4000)]
            if error == "changed_descriptor":
                bodies[0] = g17g_initdata.build_region_record(**dict(records[0], address_0c=addresses[0]+0x4000))
            if error == "failed_owner": runtime.state = "failed"
            if error:
                with self.assertRaises(RuntimeError): restore_history_mappings(runtime)
                runtime.map_globals.assert_not_called()
            else:
                result = restore_history_mappings(runtime)
                self.assertEqual({row["dva"]:row["pa"] for row in result["restored"]},
                                 {dva:pages[dva] for dva in missing})
                self.assertIs(restore_history_mappings(runtime), result)
                runtime.map_globals.assert_called_once()

    def test_private_completion_does_not_require_growth_or_change_caller_pipelines(self):
        params = backend.build_partial_render_products()["parameters"]
        self.assertFalse(params.request_tvb_growth)
        graph = first_render_graph(params, private_completion=True)
        self.assertEqual(graph["completion_timestamps"], render.TIMESTAMP_APERTURE_BASE + 8)
        self.assertFalse(graph["parameters"].request_tvb_growth)
        self.assertEqual(graph["parameters"].partial_load_pipeline, params.partial_load_pipeline)
        self.assertEqual(graph["parameters"].partial_load_pipeline_bind, params.partial_load_pipeline_bind)
        grown = first_render_graph(replace(params, request_tvb_growth=True), private_completion=True)
        before, after = graph["items"]["tiling_descriptor"], grown["items"]["tiling_descriptor"]
        self.assertEqual([i for i, (a, b) in enumerate(zip(before, after)) if a != b], [0x892])

    def test_partial_caller_rebuilds_only_its_vdm_stream(self):
        from _g17g_render_callers import caller_vdm_page
        from m1n1.drm_shim import g17g_encoder as encoder
        for vertices in (3, 1500000):
            source = backend.build_partial_render_products(direct_draw=encoder.G17GDirectDraw(vertex_count=vertices))
            params = source["parameters"]
            expected = backend.render_context1_page_images(source)[params.vdm_ctrl_stream_base & -0x4000]
            self.assertEqual(caller_vdm_page(params, vertices), expected)
        million = caller_vdm_page(params, 3000000)
        changes = [i for i, (old, new) in enumerate(zip(expected, million)) if old != new]
        count_offset = params.vdm_ctrl_stream_base % 0x4000 + encoder.DIRECT_DRAW_RECORD_OFFSET + 4
        self.assertTrue(changes)
        self.assertTrue(all(count_offset <= i < count_offset + 4 for i in changes))

    def test_second_operand_reset_is_private_bounded_and_one_packed_publication(self):
        from m1n1.drm_shim.g17g_partial_runtime import reset_operand_payloads
        dvas = tuple(backend.RENDER_SECOND_OPERAND_BASE + i * render.RENDER_OPERAND_STRIDE + offset
                     for i in range(render.PARTIAL_RENDER_OPERAND_COUNT)
                     for offset in range(0, render.RENDER_OPERAND_SIZE, 0x4000))
        self.assertEqual(len(dvas), 2304)
        for fault in (None, "private", "caller", "alias", "global", "ordinal"):
            runtime = SimpleNamespace(partial_mode=True, completed=1, private_dvas=set(dvas),
                context=dict(pages={dva: 0x100000000 + i * 0x4000 for i, dva in enumerate(dvas)},
                             caller_mappings={}), pages={}, evidence={}, u=object(), p=object(),
                iface=object(), publish=Mock())
            if fault == "private": runtime.private_dvas.remove(dvas[0])
            if fault == "caller": runtime.context["caller_mappings"][dvas[0]] = SimpleNamespace(pa=0x100000000)
            if fault == "alias": runtime.context["pages"][dvas[1]] = runtime.context["pages"][dvas[0]]
            if fault == "global": runtime.pages[0xfffffc2000000000] = runtime.context["pages"][dvas[0]]
            if fault == "ordinal": runtime.completed = 5
            writes = []
            with patch("m1n1.drm_shim.g17g_partial_runtime.write_publications",
                       side_effect=lambda u,p,iface,rows: writes.extend(rows)) as publish:
                if fault:
                    with self.assertRaises(ValueError): reset_operand_payloads(runtime)
                    publish.assert_not_called()
                    runtime.publish.assert_not_called()
                else:
                    reset_operand_payloads(runtime)
                    publish.assert_called_once()
                    runtime.publish.assert_called_once()
                    self.assertEqual(len(writes), 2304)
                    self.assertTrue(all(body == bytes(0x4000) for pa, body in writes))
                    self.assertEqual(runtime.evidence["operand_reset"]["bytes"], 0x2400000)

    def test_private_timestamp_completion_requires_both_intervals_and_fault_dominates(self):
        report = (struct.pack("<I", 1) + bytes(0x44)).hex()
        before = dict(reports=dict(consumer=0, producer=1, records=[report]),
                      execution_timestamps=bytes(32).hex(), partial_completion=bytes(4).hex())
        for stamps, expected in (((100, 110, 120, 130), "complete"),
                ((100, 120, 110, 130), "complete"), ((100, 120, 110, 0), None),
                ((0, 0, 110, 130), None), ((100, 140, 110, 130), None)):
            after = dict(before, execution_timestamps=struct.pack("<4Q", *stamps).hex(),
                         partial_completion=struct.pack("<I", 2).hex())
            self.assertEqual(first_render_completion(before, after, 3), expected)
        with self.assertRaisesRegex(ValueError, "initially clear"):
            first_render_completion(after, after, 3)
        after["reports"] = dict(consumer=0, producer=2,
            records=[report, (struct.pack("<I", 4) + bytes(0x44)).hex()])
        self.assertEqual(first_render_completion(before, after, 3), "fault")

    def test_partial_spill_timestamps_cannot_signal_the_final_fence(self):
        # Real second-job sample: both valid intervals and all transport
        # cursors had retired, but only an intermediate sum was visible.
        before = dict(reports=dict(consumer=1, producer=1, records=[]),
                      execution_timestamps=bytes(32).hex(), partial_completion=bytes(4).hex())
        after = dict(before, execution_timestamps=struct.pack("<4Q",
            12391050875, 12428094125, 12392847000, 12433953708).hex())
        for word in (0, 1, 0xffffffff):
            self.assertIsNone(first_render_completion(before,
                dict(after, partial_completion=struct.pack("<I", word).hex()), 2))
        final = dict(after, partial_completion=struct.pack("<I", 2).hex())
        self.assertEqual(first_render_completion(before, final, 2), "complete")
        with self.assertRaisesRegex(ValueError, "partial completion word"):
            first_render_completion(dict(before, partial_completion=final["partial_completion"]), final, 2)
        recycled = dict(before, partial_completion=final["partial_completion"])
        self.assertEqual(first_render_completion(recycled, final, 2, published_partial_state=0), "complete")
        with self.assertRaisesRegex(ValueError, "partial completion word"):
            first_render_completion(recycled, final, 2, published_partial_state=2)
        fault = dict(final, reports=dict(consumer=1, producer=2,
            records=[(struct.pack("<I", 4) + bytes(0x44)).hex()]))
        self.assertEqual(first_render_completion(before, fault, 2), "fault")

    def test_partial_retained_interval_still_requires_fresh_mirror_and_checks_faults(self):
        report = (struct.pack("<I", 1) + bytes(0x44)).hex()
        before = dict(dispatch_a=struct.pack("<4I", 0x200, 0x200, 0, 0).hex(),
            timestamps=struct.pack("<2Q", 100, 120).hex(), fragment_tail=bytes(0xc8).hex(),
            reports=dict(consumer=0, producer=1, records=[report]))
        after = copy.deepcopy(before)
        tail = bytearray(0xc8)
        struct.pack_into("<2Q", tail, 0x7f, 110, 120)
        after["fragment_tail"] = tail.hex()
        self.assertIsNone(first_render_completion(before, after, 2))
        self.assertIsNone(first_render_completion(before, before, 2, retained_interval=(110, 120)))
        self.assertEqual(first_render_completion(before, after, 2, retained_interval=(110, 120)), "complete")
        self.assertIsNone(first_render_completion(before, after, 2, retained_interval=(111, 120)))
        struct.pack_into("<2Q", tail, 0x7f, 105, 115)
        partial = dict(after, fragment_tail=tail.hex())
        self.assertEqual(first_render_completion(before, partial, 2, retained_interval=(105, 115)), "complete")
        self.assertIsNone(first_render_completion(before, partial, 2))
        after["reports"] = dict(consumer=0, producer=2,
            records=[report, (struct.pack("<I", 4) + bytes(0x44)).hex()])
        self.assertEqual(first_render_completion(before, after, 2, retained_interval=(110, 120)), "fault")

    def test_second_partial_graph_keeps_opaque_programs_and_matches_reference(self):
        params = backend.build_partial_render_products()["parameters"]
        params = replace(params, store_pipeline=params.store_pipeline + 0x140,
                         partial_store_pipeline=params.partial_store_pipeline + 0x140,
                         load_pipeline_bind=params.load_pipeline_bind + 0xe0)
        expected = render.build_clear_work_items(
            replace(params, tiling_lifecycle=params.tiling_lifecycle + (2 << 32) + 0x18,
                tiling_user_timestamp_start=render.TIMESTAMP_APERTURE_BASE + 0x28,
                tiling_user_timestamp_end=render.TIMESTAMP_APERTURE_BASE + 0x30,
                fragment_user_timestamp_start=render.TIMESTAMP_APERTURE_BASE + 0x38,
                fragment_user_timestamp_end=render.TIMESTAMP_APERTURE_BASE + 0x40),
            backend.PARTIAL_RENDER_TOKEN, submission_ordinal=2, event_group=2,
            shared_control=backend.direct_render_service_object(2))
        with patch.object(backend, "build_second_direct_render_caller_pages", side_effect=AssertionError):
            graph = continued_render_graph(params, 2, private_dvas=())
        self.assertTrue(graph["partial_transition"])
        self.assertEqual(graph["items"], expected)
        for field in ("store_pipeline", "partial_store_pipeline", "load_pipeline_bind", "partial_load_pipeline_bind"):
            self.assertEqual(getattr(params, field), getattr(graph["parameters"], field))
        for ordinal in (3, 4, 5):
            generated = continued_render_graph(params, ordinal, private_dvas=())
            timestamps = render.TIMESTAMP_APERTURE_BASE + 8 + (ordinal - 1) * 32
            expected = render.build_clear_work_items(
                replace(params, tiling_lifecycle=backend.direct_render_tiling_lifecycle(ordinal),
                    tiling_user_timestamp_start=timestamps, tiling_user_timestamp_end=timestamps + 8,
                    fragment_user_timestamp_start=timestamps + 16, fragment_user_timestamp_end=timestamps + 24),
                backend.PARTIAL_RENDER_TOKEN, submission_ordinal=ordinal, event_group=ordinal,
                tiling_descriptor_index=1, fragment_descriptor_index=1,
                parameter_index=ordinal - 1, pool_a_index=ordinal - 1, pool_b_index=ordinal - 1,
                register_resource_index=ordinal - 1,
                shared_control=backend.direct_render_service_object(ordinal))
            self.assertEqual(generated["items"], expected)
        with self.assertRaisesRegex(NotImplementedError, "partial"):
            continued_render_graph(params, 6, private_dvas=())

    def test_minimal_partial_continuation_uses_its_own_descriptor_and_pool_records(self):
        params = backend.build_partial_render_products()["parameters"]
        for ordinal in (3, 4, 5):
            graph = continued_render_graph(params, ordinal, private_dvas=(), retain_partial_slot=False)
            va = graph["firmware_addresses"]
            self.assertEqual(va["tiling_descriptor"], backend.RENDER_TILING_DESCRIPTOR_PAGE + (ordinal-1)*render.TILING_DESCRIPTOR_SIZE)
            self.assertEqual(va["fragment_descriptor"], backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE + (ordinal-1)*render.FRAGMENT_DESCRIPTOR_SIZE)
            self.assertEqual(struct.unpack_from("<Q", graph["items"]["fragment_descriptor"], 0x21ce)[0],
                             backend.direct_render_service_object(ordinal))
            writes = dict(graph["high"])
            pool_a = render.render_pool_a_allocation(ordinal)[1]
            pool_b = render.render_pool_b_allocation(ordinal)[1]
            self.assertEqual(writes[pool_a + 8], struct.pack("<2Q", 1, 0x50))
            self.assertEqual(writes[pool_b + 0x48], struct.pack("<Q", 0x100000000))
        with self.assertRaises(ValueError):
            continued_render_graph(params, 3, private_dvas=(), retain_partial_slot=1)

    def test_recurrent_graph_keeps_caller_operands_and_resets_only_retired_private_slots(self):
        params = self.params()
        for ordinal in (3, 36, 37, 64):
            graph = continued_render_graph(params, ordinal, private_dvas=())
            effective = graph["parameters"]
            for field in ("store_pipeline", "store_pipeline_bind", "load_pipeline", "load_pipeline_bind",
                          "vdm_ctrl_stream_base", "scissor_array", "depth_buffer"):
                self.assertEqual(getattr(effective, field), getattr(params, field))
            self.assertEqual(effective.tiling_lifecycle,
                0xc801000103 + (ordinal - 2) * ((2 << 32) + 3))
            writes = dict(graph["high"])
            for base in (render.TILING_STATUS, render.FRAGMENT_STATUS):
                self.assertEqual(writes[base + (ordinal - 1) * 0x40], bytes(0x40))
            if ordinal > render.RENDER_PARAMETER_SLOT_COUNT:
                self.assertEqual(graph["low"], tuple((dva, bytes(size))
                    for dva, size in render.build_render_recycled_parameter_ranges(
                        (ordinal - 1) % render.RENDER_PARAMETER_SLOT_COUNT)))

    def test_minimal_partial_after_five_retains_a_and_uses_independent_work_storage(self):
        params = backend.build_partial_render_products()["parameters"]
        for ordinal in (6, 7, 32, 36, 64):
            graph = continued_render_graph(params, ordinal, private_dvas=(0x7200000000,),
                                           retain_partial_slot=False)
            self.assertEqual(graph["private_dvas"], (0x7200000000,))
            self.assertEqual(graph["parameters"].partial_load_pipeline, params.partial_load_pipeline)
            self.assertEqual(struct.unpack_from("<Q", graph["items"]["fragment_descriptor"], 0x21ce)[0],
                             backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT)
            self.assertEqual(graph["firmware_addresses"]["tiling_descriptor"],
                             backend.RENDER_TILING_DESCRIPTOR_PAGE + (ordinal-1)*render.TILING_DESCRIPTOR_SIZE)

    def test_second_completion_requires_new_timestamp_mirrors_not_prefilled_dispatch(self):
        done = (struct.pack("<I", 1) + bytes(0x44)).hex()
        before = dict(dispatch_a=struct.pack("<4I", 0x200, 0x200, 0, 0).hex(),
            timestamps=struct.pack("<2Q", 100, 120).hex(), fragment_tail=bytes(0xc8).hex(),
            reports=dict(consumer=0, producer=1, records=[done]))
        tail = bytearray(0xc8)
        struct.pack_into("<2Q", tail, 0x7f, 140, 160)
        after = dict(before, timestamps=struct.pack("<2Q", 130, 160).hex(), fragment_tail=tail.hex(),
            reports=dict(consumer=0, producer=2, records=[done, done]))
        self.assertEqual(first_render_completion(before, after, 2), "complete")
        for field in ("timestamps", "fragment_tail"):
            self.assertIsNone(first_render_completion(before, dict(after, **{field: before[field]}), 2))
        # The real retained source lifecycle posts its report before the kick
        # and retains the first shared start timestamp. Only its new fragment
        # descriptor's fresh mirror interval plus the shared end can qualify.
        retained = dict(after, reports=before["reports"], timestamps=struct.pack("<2Q", 100, 160).hex())
        self.assertEqual(first_render_completion(before, retained, 2), "complete")
        bad = dict(retained, reports=dict(consumer=0, producer=2,
            records=[done, (struct.pack("<I", 4) + bytes(0x44)).hex()]))
        self.assertEqual(first_render_completion(before, bad, 2), "fault")
        # A stale but internally consistent first interval is not completion.
        struct.pack_into("<2Q", tail, 0x7f, 110, 120)
        self.assertIsNone(first_render_completion(before,
            dict(after, timestamps=before["timestamps"], fragment_tail=tail.hex()), 2))

    def test_batch_completion_requires_each_fresh_mirror_and_the_final_shared_end(self):
        before = dict(dispatch_a=bytes(16).hex(), timestamps=struct.pack("<2Q", 100, 120).hex(),
            fragment_tail=bytes(0xc8).hex(), reports=dict(consumer=0, producer=0, records=[]))
        tail = bytearray(0xc8)
        struct.pack_into("<2Q", tail, 0x7f, 140, 160)
        after = dict(before, dispatch_a=struct.pack("<4I", 0x600, 0x600, 0, 0).hex(),
            timestamps=struct.pack("<2Q", 100, 260).hex(), fragment_tail=tail.hex())
        self.assertEqual(first_render_completion(before, after, 3, final_ordinal=6), "complete")
        self.assertIsNone(first_render_completion(before, after, 6, final_ordinal=6))
        self.assertIsNone(first_render_completion(before,
            dict(after, fragment_tail=before["fragment_tail"]), 3, final_ordinal=6))
        # Pool-A reuse leaves shared admission history at work36, although
        # work64's independent descriptor and output have actually completed.
        struct.pack_into("<2Q", tail, 0x7f, 240, 260)
        recycled = dict(after, dispatch_a=struct.pack("<4I", 0x2400, 0x2400, 0, 0).hex(),
                        fragment_tail=tail.hex())
        self.assertEqual(first_render_completion(before, recycled, 64), "complete")
        self.assertIsNone(first_render_completion(before,
            dict(recycled, fragment_tail=before["fragment_tail"]), 64))

    def test_render_wave_contains_firmware_only_records(self):
        from m1n1.drm_shim.g17g_render_batch import render_wave
        parameters = tuple(replace(self.params(), depth_clear_value_bits=index)
                           for index in range(4))
        wave = render_wave(parameters, 2, private_dvas=(0x4000,))
        self.assertEqual([record["ordinal"] for record in wave["records"]], [3, 4, 5, 6])
        self.assertEqual([record["parameters"].depth_clear_value_bits for record in wave["records"]], list(range(4)))
        self.assertEqual((wave["completed"], wave["final"], wave["captured_input"]), (2, 6, None))
        for count, completed in ((0, 2), (33, 2), (2, 425), (4, 1)):
            with self.assertRaises(NotImplementedError):
                render_wave((self.params(),) * count, completed, private_dvas=())

    def test_ordinary_counter_requires_both_engine_increments_and_preserves_faults(self):
        from m1n1.drm_shim.g17g_render_submit import ordinary_completion_target
        before = dict(dispatch_a=bytes(16).hex(), timestamps=struct.pack("<2Q", 100, 120).hex(),
            fragment_tail=bytes(0xc8).hex(), reports=dict(consumer=0, producer=0, records=[]))
        tail = bytearray(0xc8)
        struct.pack_into("<2Q", tail, 0x7f, 140, 160)
        for initial in (0, 2, 4, 0xfffffffc):
            old = dict(before, completion_counter=struct.pack("<I", initial).hex())
            self.assertEqual(ordinary_completion_target(old), initial + 2)
            done = dict(old, timestamps=struct.pack("<2Q", 100, 160).hex(), fragment_tail=tail.hex(),
                completion_counter=struct.pack("<I", initial + 2).hex())
            self.assertEqual(first_render_completion(old, done, 3), "complete")
            for incomplete in (initial, initial + 1):
                pending = dict(done, completion_counter=struct.pack("<I", incomplete).hex())
                self.assertIsNone(first_render_completion(old, pending, 3))
                fault = (struct.pack("<I", 4) + bytes(0x44)).hex()
                self.assertEqual(first_render_completion(old, dict(pending,
                    reports=dict(consumer=0, producer=1, records=[fault])), 3), "fault")
            self.assertIsNone(first_render_completion(old,
                dict(done, fragment_tail=before["fragment_tail"]), 3))

    def test_ordinary_counter_rejects_inflight_and_wrapping_predecessors(self):
        from m1n1.drm_shim.g17g_render_submit import ordinary_completion_target
        for value in (1, 3, 0xfffffffe, 0xffffffff):
            with self.assertRaises(ValueError):
                ordinary_completion_target(dict(completion_counter=struct.pack("<I", value).hex()))

    def test_recycled_ordinary_mirror_requires_clear_publication_and_new_interval(self):
        from m1n1.drm_shim.g17g_render_submit import ordinary_published_fragment_interval
        graph = continued_render_graph(self.params(), 242, private_dvas=())
        self.assertEqual(ordinary_published_fragment_interval(graph), bytes(16))
        address = graph["firmware_addresses"]["fragment_descriptor"]
        writes = list(graph["high"])
        for index, (dva, body) in enumerate(writes):
            if dva == address:
                dirty = bytearray(body)
                dirty[0x21f7] = 1
                writes[index] = (dva, bytes(dirty))
        for high in (writes, (), graph["high"] + ((address + 0x21f7, bytes(16)),)):
            with self.assertRaises(ValueError):
                ordinary_published_fragment_interval(dict(graph, high=high))
        tail = bytearray(0xc8)
        struct.pack_into("<2Q", tail, 0x7f, 10, 20)
        before = dict(dispatch_a=bytes(16).hex(), timestamps=struct.pack("<2Q", 10, 120).hex(),
            fragment_tail=tail.hex(), completion_counter=struct.pack("<I", 12).hex(),
            reports=dict(consumer=0, producer=0, records=[]))
        struct.pack_into("<2Q", tail, 0x7f, 140, 160)
        after = dict(before, fragment_tail=tail.hex(), timestamps=struct.pack("<2Q", 10, 160).hex(),
                     completion_counter=struct.pack("<I", 14).hex())
        with self.assertRaisesRegex(ValueError, "not initially clear"):
            first_render_completion(before, after, 242)
        self.assertEqual(first_render_completion(before, after, 242,
            published_fragment_interval=bytes(16)), "complete")
        for stale in (dict(after, fragment_tail=before["fragment_tail"]),
                      dict(after, completion_counter=before["completion_counter"])):
            self.assertIsNone(first_render_completion(before, stale, 242,
                published_fragment_interval=bytes(16)))

    def test_partial_wave_requires_retained_fixed_pool_and_has_fresh_completion_storage(self):
        from m1n1.drm_shim.g17g_render_batch import render_wave
        params = backend.build_partial_render_products()["parameters"]
        wave = render_wave((params, params), 5, private_dvas=())
        self.assertTrue(wave["partial"])
        self.assertEqual([r["ordinal"] for r in wave["records"]], [6, 7])
        self.assertEqual(len({r["completion_timestamps"] for r in wave["records"]}), 2)
        wide = render_wave((params,) * 64, 200, private_dvas=())
        self.assertEqual((wide["completed"], wide["final"]), (200, 264))
        self.assertEqual(len({r["completion_timestamps"] for r in wide["records"]}), 64)
        for count, completed in ((65, 5), (64, 363)):
            with self.assertRaises(NotImplementedError):
                render_wave((params,) * count, completed, private_dvas=())
        for values, completed in (((params,), 4), ((replace(params, request_tvb_growth=True),), 5),
                                   ((params, self.params()), 5)):
            with self.assertRaisesRegex(NotImplementedError, "partial batches"):
                render_wave(values, completed, private_dvas=())

    def test_partial_batch_sequences_actual_admissions_and_private_end_stamps(self):
        from m1n1.drm_shim.g17g_render_batch import render_wave, execute_render_wave, retirement
        from m1n1.drm_shim.g17g_compute_queue import write_pages
        params = backend.build_partial_render_products()["parameters"]
        wave = render_wave((params, params), 5, private_dvas=())
        channels = [None] * 13
        channels[12] = ((0x1000, 0x1010, 0x1020), 0x8000)
        pages = {dva: dva for row in wave["records"] for dva in write_pages(row["high"])}
        runtime = SimpleNamespace(state="complete", completed=5, partial_mode=True,
            service_cursor=7, ack_retired_reports=Mock(return_value={}),
            minimal_partial_continuation=True, boot=SimpleNamespace(fields=dict(primary_main_fields=dict(channels=channels))),
            pages=pages, context=dict(pages={}), u=Mock(), p=Mock(), iface=Mock(), asces=(),
            retirement=Mock(side_effect=(retirement(5), retirement(7))), channel_state=lambda:(7,7,7),
            update_caller_mappings=Mock(return_value=0), flush_tables=Mock(), pa=lambda dva:dva,
            completions=lambda records: tuple({} for _ in records), physical_writes=lambda rows,pages:tuple(rows))
        runtime.boot.submission_owner = runtime
        commands = []
        def sequence(u,p,iface,asces,rows,**kwargs):
            commands.extend(rows)
            return {"completed":2}
        def wait(asces,predicate,timeout,label):
            self.assertTrue(predicate())
        with patch("m1n1.drm_shim.g17g_render_batch.g17g_stream.run_render_stream_sequence", side_effect=sequence), \
             patch("m1n1.drm_shim.g17g_partial_runtime.restore_history_mappings", return_value={}), \
             patch("m1n1.drm_shim.g17g_render_batch.first_render_completion", return_value="complete"), \
             patch("m1n1.drm_shim.g17g_render_batch.wait_until", side_effect=wait):
            execute_render_wave(runtime, wave, {})
        self.assertEqual([fields[3] for fields,pubs,witnesses in commands], [8,9])
        for index, ((fields, pubs, witnesses), row) in enumerate(zip(commands, wave["records"])):
            self.assertIn(0x8000 + (7+index)*0x40, {pa for pa,body,flags in pubs})
            self.assertEqual(witnesses, ((render.render_pool_a_allocation(row["ordinal"])[1]+0xc, 2),))
            from m1n1.drm_shim.g17g_stream import RENDER_STREAM_DEFER_COMPLETION, RENDER_STREAM_FINAL_STATE
            self.assertFalse(fields[18] & RENDER_STREAM_DEFER_COMPLETION)
            self.assertTrue(fields[18] & RENDER_STREAM_FINAL_STATE)
        self.assertEqual(runtime.service_cursor, 9)
        self.assertEqual(runtime.completed, 7)
        self.assertEqual(runtime.state, "complete")

    def test_render_ring_namespaces_wrap_independently_and_keep_logical_identity(self):
        from m1n1.drm_shim import g17g, g17g_postcontrol
        params = backend.build_partial_render_products()["parameters"]
        for ordinal in (64, 65, 80, 241, 242, 243, 255, 256, 257, 426):
            graph = continued_render_graph(params, ordinal, private_dvas=(), retain_partial_slot=False)
            writes, slot = dict(graph["high"]), ordinal - 1
            self.assertEqual(graph["firmware_addresses"]["tiling_descriptor"],
                backend.RENDER_TILING_DESCRIPTOR_PAGE + (slot % 242) * render.TILING_DESCRIPTOR_SIZE)
            self.assertEqual(graph["firmware_addresses"]["fragment_descriptor"],
                backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE + (slot % 241) * render.FRAGMENT_DESCRIPTOR_SIZE)
            self.assertLess(graph["completion_timestamps"] + 32, render.TIMESTAMP_APERTURE_BASE + 0x4000)
            for index, kind in enumerate(("tiling", "fragment")):
                scratch = (render.TILING_FIRMWARE_SCRATCH, render.FRAGMENT_FIRMWARE_SCRATCH)[index]
                body = writes[scratch + ((slot + 1) % 256) * 0x200]
                self.assertEqual(body, render.build_render_queue_context_item(kind,
                    graph["firmware_addresses"][kind + "_descriptor"], item_index=slot,
                    descriptor_index=slot % (242, 241)[index]))
                address = backend.RENDER_CHANNEL_RING_PAGES[index] + backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[index]
                self.assertIn(address + slot % 256 * g17g.RING_SLOT_SIZE, writes)
                self.assertEqual(writes[g17g_postcontrol.ITEM_RING_ADDRESSES[index] + slot * 24],
                    struct.pack("<3Q", *(graph["firmware_addresses"][kind + suffix] for suffix in ("_optional", "_descriptor", "_event"))))
                self.assertEqual(dict(graph["release"])[backend.RENDER_STATE_PAGE + backend.RENDER_STATE_OFFSETS[index] + 0x20],
                                 struct.pack("<I", ordinal % 256))

    def test_render_sequence_wraps_service_and_defers_recycled_outer_slots(self):
        from m1n1.drm_shim.g17g_render_batch import render_wave, execute_render_wave, retirement
        from m1n1.drm_shim.g17g_compute_queue import write_pages
        for partial, completed, cursor, targets in ((True, 255, 1, (2,3)), (False, 250, 253, (254,255)),
                                                    (False, 252, 255, (0,1))):
            params = backend.build_partial_render_products()["parameters"] if partial else self.params()
            wave = render_wave((params, params), completed, private_dvas=())
            channels = [None] * 13
            channels[12] = ((0x1000,0x1010,0x1020), 0x8000)
            runtime = SimpleNamespace(state="complete", completed=completed, partial_mode=partial,
                minimal_partial_continuation=True, service_cursor=cursor, ack_retired_reports=Mock(return_value={}),
                boot=SimpleNamespace(fields=dict(primary_main_fields=dict(channels=channels))),
                pages={dva:dva for row in wave["records"] for dva in write_pages(row["high"])},
                context=dict(pages={}), u=Mock(), p=Mock(), iface=Mock(), asces=(),
                retirement=Mock(side_effect=(retirement(completed), retirement(completed+2))),
                channel_state=lambda:(cursor,)*3, update_caller_mappings=Mock(return_value=0), flush_tables=Mock(),
                pa=lambda dva:dva, completions=lambda records:tuple(
                    {} if partial else dict(completion_counter=struct.pack("<I", 2*index).hex())
                    for index, _ in enumerate(records)),
                physical_writes=lambda rows,pages:tuple(rows))
            runtime.boot.submission_owner = runtime
            commands = []
            def sequence(u,p,iface,asces,rows,**kwargs):
                commands.extend(rows)
                return {}
            with patch("m1n1.drm_shim.g17g_render_batch.g17g_stream.run_render_stream_sequence", side_effect=sequence), \
                 patch("m1n1.drm_shim.g17g_partial_runtime.restore_history_mappings", return_value={}), \
                 patch("m1n1.drm_shim.g17g_render_batch.first_render_completion", return_value="complete"), \
                 patch("m1n1.drm_shim.g17g_render_batch.wait_until", side_effect=lambda a,f,t,s:self.assertTrue(f())):
                execute_render_wave(runtime, wave, {})
            self.assertEqual(tuple(fields[3] for fields,pubs,witnesses in commands), targets)
            self.assertEqual(runtime.service_cursor, targets[-1])
            from m1n1.drm_shim.g17g_stream import RENDER_STREAM_DEFER_COMPLETION, RENDER_STREAM_FINAL_STATE
            for index, (fields, pubs, witnesses) in enumerate(commands):
                self.assertEqual(bool(fields[18] & RENDER_STREAM_FINAL_STATE), partial)
                self.assertFalse(fields[18] & RENDER_STREAM_DEFER_COMPLETION)
                address = (render.render_pool_a_allocation(completed+index+1)[1]+0xc if partial else
                           wave["records"][index]["firmware_addresses"]["fragment_descriptor"]+0x21ff)
                self.assertEqual(witnesses, ((address, 2 if partial else 0),))
            if partial:
                self.assertEqual([(fields[9],fields[10]) for fields,pubs,witnesses in commands], [(255,0),(0,1)])
                self.assertEqual(sum(flags == 3 for pa,body,flags in commands[1][1]), 2)
            else:
                service = {pa:body for fields,pubs,witnesses in commands for pa,body,flags in pubs if 0x8000 <= pa < 0xc000}
                self.assertEqual([struct.unpack_from("<I",body)[0] for body in service.values()], [0x2e,0x2e])

    def test_report_credits_preserve_faults_and_do_not_follow_a_moving_producer(self):
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        channels = {}
        for main, base in (("primary_main_fields",0x1000),("secondary_main_fields",0x5000)):
            table = [None] * 15
            for channel, offset in ((13,0),(14,0x1000)):
                table[channel] = ((base+offset, base+offset+0x100000, base+offset+0x100),0)
            channels[main] = dict(channels=table)
        first = struct.pack("<4I",13,1,0,0) + bytes(0x38)
        for kind in (1,4,6,13):
            terminal = struct.pack("<4I",kind,3,0,0) + bytes(0x38)
            late_producer = [2]
            def read(fields):
                if fields and next(iter(fields.values()))[1] == 0x24:
                    return {i:struct.pack("<I28xI",0,late_producer[0] if i == 0 else 1) for i in fields}
                late_producer[0] = 3  # a new fault arrives after our snapshot
                return {0:first,1:terminal}
            runtime = SimpleNamespace(boot=SimpleNamespace(fields=channels), read_fields=read,
                pa=lambda address:address+0x800000, u=Mock(), p=Mock(), iface=Mock())
            with patch("m1n1.drm_shim.g17g_stream.write_control_records") as publish:
                if kind != 1:
                    with self.assertRaisesRegex(RuntimeError,"unhandled report"):
                        G17GFirstRenderRuntime.ack_retired_reports(runtime)
                    publish.assert_not_called()
                else:
                    result = G17GFirstRenderRuntime.ack_retired_reports(runtime)
                    self.assertEqual(result["records"],[first.hex(),terminal.hex()])
                    self.assertEqual(dict(publish.call_args.args[3])[0x801000],struct.pack("<I",2))
                    self.assertEqual(result["changed"],8)

    def test_second_graph_appends_objects_and_queue_records_without_caller_builders(self):
        from m1n1.drm_shim import g17g, g17g_postcontrol
        params = self.params()
        with patch.object(backend, "build_clear_render_products", side_effect=AssertionError), patch.object(
                render, "build_clear_state_page", side_effect=AssertionError):
            graph = second_render_graph(params, private_dvas=(0x4000,))
        expected = render.build_clear_work_items(replace(params,
            tiling_lifecycle=params.tiling_lifecycle + (2 << 32) + 0x18),
            backend.RENDER_DEFAULT_TOKEN, submission_ordinal=2, event_group=2)
        self.assertEqual(graph["items"], expected)
        writes = dict(graph["high"])
        for name, body in expected.items():
            self.assertEqual(writes[graph["firmware_addresses"][name]], body)
        for index in (0, 1):
            self.assertEqual(writes[g17g_postcontrol.POINTER_BLOCK_ADDRESSES[index] + 0x40], struct.pack("<I", 6))
            slot = writes[backend.RENDER_CHANNEL_RING_PAGES[index]
                + backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[index] + g17g.RING_SLOT_SIZE]
            self.assertEqual(slot, g17g.build_ring_slot(g17g_postcontrol.QUEUE_ADDRESSES[index],
                index, (index << g17g.RING_SLOT_QUEUE_INDEX_SHIFT) | 6))
        self.assertEqual(graph["low"], ())
        other = second_render_graph(replace(params, clear_rgba=(255, 0, 0, 255),
            target_dva=params.target_dva + 0x4000), private_dvas=(0x4000,))
        self.assertEqual(graph["high"], other["high"])

    def test_completion_ignores_owned_history_but_requires_new_report_and_fresh_pair(self):
        history = (struct.pack("<I", 13) + bytes(0x44)).hex()
        done = (struct.pack("<I", 1) + bytes(0x44)).hex()
        before = dict(dispatch_a=bytes(16).hex(), timestamps=bytes(16).hex(),
                      fragment_tail=bytes(0xc8).hex(),
                      reports=dict(consumer=0, producer=1, records=[history]))
        tail = bytearray(0xc8)
        struct.pack_into("<2Q", tail, 0x7f, 110, 120)
        after = dict(dispatch_a=struct.pack("<4I", 0x100, 0x100, 0, 0).hex(),
                     timestamps=struct.pack("<2Q", 100, 120).hex(), fragment_tail=tail.hex(),
                     reports=dict(consumer=0, producer=2, records=[history, done]))
        self.assertEqual(first_render_completion(before, after), "complete")
        stale = copy.deepcopy(after)
        stale["reports"] = before["reports"]
        self.assertIsNone(first_render_completion(before, stale))
        for field in ("dispatch_a", "timestamps", "fragment_tail"):
            missing = copy.deepcopy(after)
            missing[field] = before[field]
            self.assertIsNone(first_render_completion(before, missing))
        fault = copy.deepcopy(after)
        fault["reports"]["records"][-1] = (struct.pack("<I", 4) + bytes(0x44)).hex()
        self.assertEqual(first_render_completion(before, fault), "fault")
        foreign = copy.deepcopy(after)
        foreign["reports"]["records"][0] = done
        with self.assertRaisesRegex(ValueError, "historical"):
            first_render_completion(before, foreign)

    def test_ordinary_uapi_translation_matches_reference_without_a_target_parameter(self):
        products, params = self.uapi_roundtrip(self.params())
        self.assertEqual((params.target_dva, params.clear_state_page, params.clear_rgba), (0, 0, (0, 0, 0, 0)))
        self.assert_firmware_equal(products, params)

    def uapi_roundtrip(self, parameters):
        from _g17g_render_callers import command_bytes
        from m1n1.drm_shim import g17g_modern as modern, g17g_uapi as api
        products = backend.build_clear_render_products(parameters)
        driver = modern.G17GModernDriver(Mock())
        vm = driver.create_vm(1, modern.VM_END - modern.VM_KERNEL_MIN_SIZE, modern.VM_END)
        private = set(first_render_graph(parameters)["private_dvas"])
        for index, dva in enumerate(backend.render_context1_page_images(products), 1):
            if dva not in private:
                driver.create_bo(1, index, (index - 1) * 0x4000, 0x4000)
                driver.bind(1, vm.vm_id, api.drm_asahi_gem_bind_op(
                    api.DRM_ASAHI_BIND_READ | api.DRM_ASAHI_BIND_WRITE, index, 0, 0x4000, dva))
        queue = driver.create_queue(1, vm.vm_id, 1)
        command = api.parse_command_buffer(command_bytes(parameters))[0]
        state = driver._resolve_render_hardware_state(queue, command).hardware_state
        return products, render_parameters(state)

    def assert_firmware_equal(self, products, params):
        graph = first_render_graph(params)
        original = products["parameters"]
        # UAPI values must survive independently of the driver's allocation
        # family. Both ordinary and spilling jobs now use the complete family.
        expected = replace(original, partial_mode=True, tib_bytes=32,
            aux_fb_flags=0x10c000, auxiliary_object=0x10000300000,
            tiling_lifecycle=0xce010000f3, buffers=params.buffers,
            scissor_array=original.resolved_scissor_array(),
            depth_bias_array=original.resolved_depth_bias_array())
        reference = G17GShimBackend._retarget_submission_priority(
            backend.build_render_transport(expected, backend.PARTIAL_RENDER_TOKEN), 2)
        self.assertEqual(graph["items"], reference["items"])
        self.assertEqual(graph["firmware_pages"], reference["firmware_pages"])
        self.assertEqual(graph["firmware_patches"], reference["firmware_patches"])

    def test_uapi_preserves_independent_zls_dimensions_and_other_scalar_state(self):
        from _g17g_render_callers import caller_case
        base = self.params()
        variants = [caller_case(case)[0]["parameters"] for case in ("store", "load-store")]
        variants += [replace(variants[0], depth_dimensions=render.encode_zls_dimensions(32, 48),
            depth_aux_buffer=backend.RENDER_ZLS_DEPTH_AUX_DVA,
            stencil_aux_buffer=backend.RENDER_ZLS_STENCIL_AUX_DVA,
            depth_flags=variants[0].depth_flags | render.ZLS_STORE_DEPTH_COMPRESSED | render.ZLS_STORE_STENCIL_COMPRESSED,
            sampler_array=0x10000410000, sampler_count=3, occlusion_query_base=0x10000414000),
            replace(base, width=32, height=48, layers=2, utile_width=16, utile_height=16,
                    samples=2, sample_size=4, multisample_control=0xa82,
                    merge_upper_x_bits=0x3d123456, merge_upper_y_bits=0x3e654321),
            replace(base, process_empty_tiles=False, depth_bias_is_integer=True,
                    store_pipeline_bind=0x123, load_pipeline_bind=0xffff800000000067,
                    partial_store_pipeline_bind=0x456, partial_load_pipeline_bind=0xffff800000000078)]
        for original in variants:
            with self.subTest(original=original):
                products, actual = self.uapi_roundtrip(original)
                self.assertEqual(actual.depth_dimensions, original.depth_dimensions)
                self.assert_firmware_equal(products, actual)

    def params(self):
        return render.G17GClearRenderParameters(target_dva=0x10000018000,
            clear_state_page=0x10000110000, clear_rgba=(17, 34, 51, 68),
            store_pipeline=0x10000130400, load_pipeline=0x10000130200,
            auxiliary_object=0x10000248000, tiling_lifecycle=0xc6010000eb)

    def test_all_firmware_objects_match_reference_across_render_state_families(self):
        initial = self.params()
        variants = (initial, replace(initial, width=32, height=48, layers=2,
            utile_width=16, utile_height=16, samples=2, sample_size=4),
            replace(initial, depth_buffer=0x10000400000, stencil_buffer=0x10000404000,
                depth_flags=render.ZLS_STORE_DEPTH | render.ZLS_STORE_STENCIL,
                depth_dimensions=render.encode_zls_dimensions(64, 64),
                depth_clear_value_bits=0x3f400000, stencil_clear_value=0x57,
                sampler_array=0x10000410000, sampler_count=3, occlusion_query_base=0x10000414000,
                tiling_user_timestamp_start=render.TIMESTAMP_APERTURE_BASE + 0x80))
        for params in variants:
            for priority in (2, 3):
                with self.subTest(params=params, priority=priority):
                    reference = G17GShimBackend._retarget_submission_priority(
                        backend.build_clear_render_products(params), priority)
                    graph = first_render_graph(params, priority=priority)
                    for key in ("items", "firmware_addresses", "firmware_pages",
                                "firmware_patches", "firmware_patch_addresses", "source_global_pages",
                                "late_global_pages", "fresh_global_pages", "fresh_global_page_flags"):
                        self.assertEqual(graph[key], reference[key], key)
                    self.assertTrue(set(graph["context1_writes"]) < set(reference["context1_writes"]))
                    for dva, body in graph["context1_writes"].items():
                        self.assertEqual(body, reference["context1_writes"][dva])

    def test_no_caller_payload_builder_is_called_or_target_color_encoded(self):
        with patch("m1n1.drm_shim.g17g_backend.build_clear_render_products", side_effect=AssertionError), patch(
                "m1n1.drm_shim.g17g_render_compiler.build_clear_compiler_pages", side_effect=AssertionError), patch(
                "m1n1.drm_shim.g17g_render.build_clear_pipeline_page", side_effect=AssertionError), patch(
                "m1n1.drm_shim.g17g_render.build_clear_state_page", side_effect=AssertionError), patch(
                "m1n1.drm_shim.g17g_render.build_render_scissor_page", side_effect=AssertionError):
            a = first_render_graph(self.params())
            b = first_render_graph(replace(self.params(), target_dva=0x10000318000,
                clear_state_page=0x10000310000, clear_rgba=(255, 0, 100, 19)))
        a.pop("parameters"), b.pop("parameters")
        self.assertEqual(a, b)
        for address in (0x1000018000, 0x1000058000, 0x10000018000,
                        0x10000110000, 0x10000130000, 0x10000140000, 0x10000298000):
            self.assertNotIn(address, a["context1_writes"])
            self.assertNotIn(address, a["private_dvas"])
        self.assertFalse(set(a["context1_writes"]) & set(a["context1_aliases"]))

    def test_unqualified_priorities_are_not_silently_accepted(self):
        with self.assertRaises(ValueError):
            first_render_graph(self.params(), priority=0)

    def test_partial_opening_matches_firmware_reference_without_caller_builders(self):
        products = backend.build_partial_render_products()
        params = products["parameters"]
        with patch.object(backend, "build_partial_render_products", side_effect=AssertionError), patch(
                "m1n1.drm_shim.g17g_partial_assets.build_partial_context_pages", side_effect=AssertionError), patch(
                "m1n1.drm_shim.g17g_encoder.build_partial_bound_state_pages", side_effect=AssertionError):
            graph = first_render_graph(params)
        for key in ("items", "firmware_pages", "firmware_addresses", "source_global_pages", "late_global_pages"):
            self.assertEqual(graph[key], products[key], key)
        expected_images = backend.render_context1_page_images(products)
        for dva, body in graph["context1_writes"].items():
            self.assertEqual(body, expected_images.get(dva, bytes(len(body))), hex(dva))
        for dva in (0x1000000000, 0x1000018000, 0x1000048000, 0x1000058000, 0x1000068000,
                    params.target_dva, params.clear_state_page, params.store_pipeline & -0x4000):
            self.assertNotIn(dva, graph["private_dvas"])
            self.assertNotIn(dva, graph["context1_writes"])
        self.assertTrue(graph["deferred_control_start"])
        self.assertEqual([struct.unpack_from("<I", body)[0] for body in graph["service_records"]], [0x15, 0x15])

    def test_partial_uapi_roundtrip_needs_no_out_of_band_mode_or_caller_addresses(self):
        from _g17g_render_callers import command_bytes
        from m1n1.drm_shim import g17g_modern as modern, g17g_uapi as api
        products = backend.build_partial_render_products()
        graph = first_render_graph(products["parameters"])
        driver = modern.G17GModernDriver(Mock())
        vm = driver.create_vm(1, modern.VM_END - modern.VM_KERNEL_MIN_SIZE, modern.VM_END)
        for index, dva in enumerate(backend.render_context1_dvas(products), 1):
            if dva in graph["private_dvas"]:
                continue
            driver.create_bo(1, index, index * 0x4000, 0x4000)
            driver.bind(1, vm.vm_id, api.drm_asahi_gem_bind_op(6, index, 0, 0x4000, dva))
        queue = driver.create_queue(1, vm.vm_id, 1)
        command = api.parse_command_buffer(command_bytes(products["parameters"]))[0]
        state = driver._resolve_render_hardware_state(queue, command).hardware_state
        params = render_parameters(state)
        self.assertTrue(params.partial_mode)
        self.assertEqual((params.target_dva, params.clear_state_page, params.clear_rgba), (0, 0, (0, 0, 0, 0)))
        self.assert_firmware_equal(products, params)

    def test_general_render_buffers_match_native_sizes_and_are_disjoint(self):
        from m1n1.drm_shim.g17g_render_buffers import render_buffers, next_render_buffer_base
        first = render_buffers(replace(self.params(), width=256, height=256), 0x1010000000)
        self.assertEqual((first.metadata - first.tilemap, first.tpc_size), (0x1000, 0x800))
        second = render_buffers(replace(self.params(), width=1920, height=1080),
                                next_render_buffer_base(first.pages))
        self.assertEqual((second.metadata - second.tilemap, second.tpc_size), (0x4000, 0x6000))
        self.assertFalse(set(first.pages) & set(second.pages))
        self.assertEqual(len(second.pages), 4)

    def test_explicit_render_buffers_do_not_inherit_mixed_family_displacement(self):
        from m1n1.drm_shim.g17g_render_buffers import render_buffers
        from m1n1.drm_shim.g17g_mixed_submit import mixed_partial_graph
        params = replace(self.params(), width=1920, height=1080)
        params = replace(params, buffers=render_buffers(params, 0x1010000000))
        graph = mixed_partial_graph(params)
        ta = graph['items']['tiling_descriptor']
        fr = graph['items']['fragment_descriptor']
        ta_regs = dict(struct.iter_unpack('<IQ', ta[0x60:0x60+73*12]))
        fr_regs = dict(struct.iter_unpack('<IQ', fr[0xa0:0xa0+89*12]))
        self.assertEqual(ta_regs[0x1c039], 0x10000000)
        self.assertEqual(ta_regs[0x1c0a1], 0x1000c000)
        self.assertEqual(struct.unpack_from('<2Q', ta, 0x780), (0x101000c000, 0x6000))
        self.assertEqual(fr_regs[0x16429], 0x1010000000)
        self.assertEqual(fr_regs[0x16098], 0x1010004000)
        self.assertTrue(set(params.buffers.pages) <= set(graph['private_dvas']))


class TestFirstRenderRuntime(unittest.TestCase):
    def runtime(self):
        from m1n1.drm_shim.g17g_render_runtime import G17GFirstRenderRuntime
        boot = SimpleNamespace(state="ready", profile="compute", submission_owner=None,
            u=Mock(), p=Mock(), iface=Mock(), uat=Mock(), asces=(Mock(), Mock()),
            synthetic_high_root=0x80000, plan={"ram_pages": {}})
        return G17GFirstRenderRuntime(boot)

    def test_ordinary_second_work_preserves_live_address_ring_cursors(self):
        allocator = backend.RENDER_POST_FIRST_ALLOCATOR_PAGE + 8
        other = 0xfffffc2000024e40
        rows = {allocator - 8: ((8, 0x1f3800000138, 0x1fb0000001b0),),
                other & -0x4000: ((other % 0x4000, 1, 2),)}
        # Actual first-render advances occur on either side of the old
        # snapshot's 0x1b0. Neither cursor may be moved independently of
        # firmware's address records, including on the idempotent path.
        for count in (0x198, 0x1a0, 0x1a8, 0x1b0, 0x1b8, 0x1c8, 0x1e0):
            with self.subTest(count=count):
                runtime = self.runtime()
                runtime.partial_mode, runtime.completed = False, 1
                value = ((0x1e00 + count) << 32) | count
                memory = {allocator: value, other: 1}
                runtime.read_fields = lambda fields: {
                    dva: struct.pack("<Q", memory[dva]) for dva in fields}
                writes = []
                runtime.publish_writes = lambda rows: writes.extend(rows)
                runtime.guarded_qwords(rows, second_stage=True)
                self.assertEqual(writes, [(other, struct.pack("<Q", 2))])
                self.assertEqual(runtime.evidence["guarded_stages"][0]["before"][hex(allocator)], value)

        runtime.read_fields = lambda fields: {
            dva: struct.pack("<Q", 0x1fb8000001a0 if dva == allocator else 1)
            for dva in fields}
        writes.clear()
        with self.assertRaisesRegex(RuntimeError, "source mismatch"):
            runtime.guarded_qwords(rows, second_stage=True)
        self.assertEqual(writes, [])

    def test_partial_postservice_reset_requires_owned_completed_service(self):
        for value, ready, accepted in ((0x171c000003, True, True),
                (0x12cdaf000ea2, True, True), (0x164c000003, False, False)):
            runtime = self.runtime()
            runtime.partial_mode, runtime.completed = True, 1
            runtime.boot.submission_owner = runtime
            runtime.evidence["partial_allocation"] = dict(service_retired=10 if ready else 3)
            runtime.read_fields = lambda fields: {dva: struct.pack("<Q", value) for dva in fields}
            runtime.publish_writes = Mock()
            rows = {0xfffffc20c07c0000: ((0x28, 0x648000001, 0x87a000003),)}
            if accepted:
                runtime.guarded_qwords(rows, second_stage=True)
                self.assertTrue(runtime.publish_writes.called)
            else:
                with self.assertRaisesRegex(RuntimeError, "source mismatch"):
                    runtime.guarded_qwords(rows, second_stage=True)
                self.assertFalse(runtime.publish_writes.called)
        from m1n1.drm_shim.g17g_partial_runtime import postservice_preimage_is_owned
        runtime.evidence["partial_allocation"] = dict(service_retired=10, history_relocated=bytes(0x4000).hex())
        self.assertTrue(postservice_preimage_is_owned(runtime, backend.RENDER_SECOND_SERVICE_HISTORY_PAGE, 0))
        self.assertFalse(postservice_preimage_is_owned(runtime, backend.RENDER_SECOND_SERVICE_HISTORY_PAGE, 1))
        self.assertFalse(postservice_preimage_is_owned(runtime, 0xfffffc200002f4d0, 123))
        runtime.boot.submission_owner = None
        self.assertFalse(postservice_preimage_is_owned(runtime, 0xfffffc20c07c0028, 123))

    def test_second_partial_allocation_has_no_caller_writes_and_retires_only_private_leaves(self):
        self.check_second_partial_allocation(minimal=False)

    def test_minimal_second_partial_uses_one_admission_without_copied_history(self):
        self.check_second_partial_allocation(minimal=True)

    def check_second_partial_allocation(self, *, minimal):
        from m1n1.drm_shim.g17g_partial_runtime import prepare_second_partial, retire_first_partial
        runtime = self.runtime()
        runtime.completed, runtime.partial_mode = 1, True
        old = backend.expand_second_direct_retired_context1_dvas()
        new = backend.expand_second_direct_render_context1_dvas()
        high = ((backend.RENDER_SECOND_SERVICE_STATE, backend.RENDER_SECOND_SERVICE_OBJECT) if minimal
                else backend.expand_second_direct_render_high_dvas())
        runtime.private_dvas = set(old)
        runtime.context = dict(root0=0x4000, pages={dva: 0x800000 + i * 0x4000 for i, dva in enumerate(old)},
                               allocations=[], table_witnesses=set(old), caller_mappings={})
        runtime.boot.firmware_roots = {0: 0x80000, 1: 0x90000}
        channels = [None] * 13
        channels[12] = ((0x1000, 0x1010, 0x1020), 0x8000)
        runtime.boot.fields = dict(primary_main_fields=dict(channels=channels))
        runtime.uat.iotranslate_root.return_value = [(None, 0x4000)]
        first = struct.pack("<8Q", 0x1000000000013, 0x20, 1, 2, 3, 5,
                            backend.RENDER_TILING_DESCRIPTOR_PAGE, 0xfffffc20c0000000)
        history = backend.build_second_direct_render_service_history(first + bytes(0x4000 - len(first)))
        runtime.read_fields = lambda fields: {key: history if dva == backend.RENDER_FIRST_SERVICE_HISTORY_PAGE
                                               else bytes(size) for key, (dva, size) in fields.items()}
        target = 4 if minimal else 10
        runtime.channel_state = Mock(side_effect=((3, 3, 3), (target, target, target)))
        runtime.alloc = Mock(side_effect=(0x1000000, 0x2000000))
        runtime.publish = runtime.flush_tables = Mock()
        runtime.publish_writes = Mock()
        def wait(_asces, predicate, _timeout, _label):
            self.assertTrue(predicate())
        with patch("m1n1.drm_shim.g17g_partial_runtime.wait_until", side_effect=wait), patch(
                "m1n1.drm_shim.g17g_partial_runtime.write_publications"), patch.object(
                backend, "build_second_direct_render_caller_pages", side_effect=AssertionError), patch.object(
                backend, "build_second_direct_render_service_history",
                side_effect=AssertionError if minimal else None,
                wraps=backend.build_second_direct_render_service_history), patch(
                "m1n1.drm_shim.g17g_partial_runtime.reset_operand_payloads") as reset:
            if minimal:
                prepare_second_partial(runtime, 5)
                reset.assert_called_once_with(runtime)
            else:
                prepare_second_partial(runtime, 5, minimal=False)
                reset.assert_not_called()
        self.assertEqual(set(runtime.context["pages"]), set(old) | set(new))
        self.assertEqual(set(runtime.pages), set(high))
        self.assertEqual(runtime.context["allocations"], [(0x1000000, len(new) * 0x4000)])
        self.assertEqual(runtime.asces[0].send.call_count, 1 if minimal else 7)
        self.assertEqual(runtime.asces[1].send.call_count, 0)
        writes = dict(runtime.publish_writes.call_args_list[-1].args[0])
        self.assertEqual(writes[0x1020], struct.pack("<I", target))
        self.assertEqual(runtime.publish_writes.call_count, 1 if minimal else 2)
        runtime.uat.iotranslate_root.side_effect = lambda root, dva, size: [(runtime.context["pages"][dva], size)]
        runtime.uat.iounmap_root.return_value = 0x4000
        runtime.unmap_globals = Mock()
        retained = {dva: runtime.context["pages"][dva] for dva in
                    ((0x7200200000, 0x7200204000) if minimal else ())}
        retire_first_partial(runtime)
        self.assertEqual(set(runtime.context["pages"]), set(new) | set(retained))
        self.assertEqual({dva: runtime.context["pages"][dva] for dva in retained}, retained)
        self.assertEqual({call.args[1] for call in runtime.uat.iounmap_root.call_args_list},
                         set(old) - set(retained))
        self.assertEqual(runtime.uat.iounmap_root.call_count, 294 - len(retained))
        runtime.unmap_globals.assert_called_once_with((0xfffffc2001608000, 0xfffffc20c08b0000) if minimal
                                                      else backend.RENDER_SECOND_PRESERVICE_RETIRED_GLOBAL_PAGES)

    def test_partial_warmup_preserves_caller_compiler_allocation_and_both_service_slots(self):
        self.check_partial_warmup(minimal=False)

    def test_minimal_partial_warmup_rebinds_only_current_pair_and_retires_previous(self):
        self.check_partial_warmup(minimal=True)

    def check_partial_warmup(self, *, minimal):
        from m1n1.drm_shim.g17g_partial_runtime import prepare_partial_warmup, retire_partial_warmup, warmup_dvas
        runtime = self.runtime()
        runtime.partial_mode, runtime.completed = True, 2
        runtime.minimal_partial_continuation = minimal
        prior = backend.expand_fourth_direct_render_context1_dvas()
        caller = {0x10000140000 + index * 0x4000: 0x4000000 + index * 0x4000 for index in range(28)}
        runtime.private_dvas = set(prior)
        runtime.context = dict(root0=0x4000, pages=dict(caller), allocations=[], table_witnesses=set(),
                               caller_mappings=dict(caller))
        runtime.context["pages"].update({dva: 0x2000000 + index * 0x4000 for index, dva in enumerate(prior)})
        runtime.boot.firmware_roots = {0: 0x80000, 1: 0x90000}
        high = (*backend.expand_third_direct_render_high_dvas(), *backend.expand_fourth_direct_render_high_dvas())
        runtime.pages.update({dva: 0x3000000 + index * 0x4000 for index, dva in enumerate(high)})
        runtime.uat.iotranslate_root.side_effect = lambda root, dva, size: [(
            runtime.context["pages"][dva] if root == 0x4000 else None if minimal else runtime.pages[dva], size)]
        runtime.uat.iounmap_root.return_value = 0x4000
        runtime.publish = runtime.flush_tables = Mock()
        runtime.publish_writes = Mock()
        runtime.alloc = Mock(side_effect=(0x5000000, 0x6000000, 0x7000000))
        runtime.unmap_globals = Mock()
        with patch("m1n1.drm_shim.g17g_partial_runtime.write_publications"), patch(
                "m1n1.drm_shim.g17g_partial_runtime.reset_operand_payloads") as reset:
            for ordinal in (3, 4, 5):
                prepare_partial_warmup(runtime, ordinal)
                retire_partial_warmup(runtime, ordinal)
                self.assertEqual(set(runtime.context["pages"]), set(warmup_dvas(ordinal)) | set(caller))
                self.assertEqual(runtime.context["caller_mappings"], caller)
                self.assertEqual(set(runtime.pages), set(high))
                self.assertEqual(runtime.evidence["partial_warmup"]["caller_pages_retired"], 0)
                self.assertEqual(runtime.evidence["partial_warmup"]["retained_high_pairs"], 1 if minimal else 2)
                runtime.completed += 1
            self.assertEqual(reset.call_count, 3 if minimal else 0)
        if minimal:
            self.assertEqual(runtime.unmap_globals.call_count, 3)
            self.assertEqual(runtime.unmap_globals.call_args_list[0].args[0],
                             backend.expand_fourth_direct_render_high_dvas())
            self.assertEqual(runtime.unmap_globals.call_args_list[1].args[0],
                             backend.expand_third_direct_render_high_dvas())
        else:
            runtime.unmap_globals.assert_not_called()
        self.assertFalse(runtime.u.free.called)

    def test_direct_opening_publishes_service_before_sole_control_start_pair(self):
        runtime = self.runtime()
        graph = first_render_graph(backend.build_partial_render_products()["parameters"])
        channels = [None] * 13
        channels[12] = ((0x1000, 0x1010, 0x1020), 0x8000)
        runtime.boot.fields = dict(primary_main_fields=dict(channels=channels))
        runtime.channel_state = Mock(side_effect=((0, 0, 1), (3, 3, 3)))
        runtime.read_fields = lambda fields: {key: bytes(size) for key, (_, size) in fields.items()}
        actions = []
        runtime.publish_writes = lambda writes: actions.append(("publish", tuple(writes)))
        for index, asc in enumerate(runtime.asces):
            asc.send.side_effect = lambda message, _endpoint, index=index: actions.append(("send", index, message))
        def wait(_asces, predicate, _timeout, _label):
            self.assertTrue(predicate())
        with patch("m1n1.drm_shim.g17g_render_runtime.wait_until", side_effect=wait):
            runtime.service(graph, 5)
        self.assertEqual([action[0] for action in actions], ["publish", "send", "send"])
        self.assertEqual(actions[1:], [("send", 0, 0x89 << 48), ("send", 1, 0x89 << 48)])
        self.assertEqual(dict(actions[0][1])[0x1020], struct.pack("<I", 3))
        for address in (0x1000, 0x1010):
            self.assertEqual(dict(actions[0][1])[address], struct.pack("<I", 1))

    def test_fault_report_uses_command_fetch_classification_not_default_unknown(self):
        from m1n1.drm_shim.g17g_sync import G17GPublishedFault
        params = TestFirstRenderFirmware().params()
        graph = first_render_graph(params)
        before = dict(dispatch_a=bytes(16).hex(), timestamps=bytes(16).hex(),
                      reports=dict(consumer=0, producer=0, records=[]))
        after = dict(reports=dict(consumer=0, producer=1,
                     records=[(struct.pack("<I", 4) + bytes(0x44)).hex()]))
        for address, expected_error in ((params.vdm_ctrl_stream_base + 0x80, -19),
                                        (params.vdm_ctrl_stream_base + 0x4000, -61)):
            with self.subTest(address=address):
                runtime = self.runtime()
                for method in ("prepare_control", "prepare_render", "service", "prepare_work"):
                    setattr(runtime, method, Mock())
                runtime.completion = Mock(side_effect=(before, after))
                runtime.retirement = Mock(return_value=dict(
                    queue=[0, 0], pointers=[[0, 0, 3]] * 2, channels=[[0, 0, 1]] * 2))
                runtime.fault_status = Mock(return_value=dict(faulted=True, info=1, address_raw=address >> 6))
                def wait(_asces, predicate, _timeout, _label):
                    self.assertTrue(predicate())
                with patch("m1n1.drm_shim.g17g_render_runtime.wait_until", side_effect=wait):
                    with self.assertRaises(G17GPublishedFault) as failure:
                        runtime.execute(graph, {})
                self.assertEqual(failure.exception.error, expected_error)
                self.assertTrue(failure.exception.fatal)
                self.assertEqual(runtime.state, "failed")
                runtime.fault_status.assert_called_once()
                # No second retirement observation can substitute for an
                # execution fence after an owned fault report.
                runtime.retirement.assert_called_once()

    def test_report_observer_uses_payload_state_member_not_trailing_ring(self):
        runtime = self.runtime()
        channels = [None] * 14
        channels[13] = ((0x1000, 0x8000, 0x2000), 0xf000)
        runtime.boot.fields = dict(primary_main_fields=dict(channels=channels))
        fields = {key: bytes(16) for key in (
            "dispatch_a", "dispatch_b", "timestamps", (0, "tiling_tail"), (0, "fragment_tail"))}
        fields["reports"] = struct.pack("<I28xI", 0, 1)
        runtime.read_fields = Mock(side_effect=(fields, {0: bytes(0x48)}))
        runtime.completion(first_render_graph(TestFirstRenderFirmware().params()))
        self.assertEqual(runtime.read_fields.call_args.args[0], {0: (0x8000, 0x48)})

    def test_batch_sequencer_preserves_mailboxes_and_rejects_overflow(self):
        from contextlib import contextmanager
        from m1n1.drm_shim.g17g_stream import run_render_stream_sequence
        base = 0x100000
        @contextmanager
        def allocation(_size):
            yield base
        for overflow, capacity in ((0, None), (1, None), (0, 65536), (1, 65536)):
            memory = bytearray()
            iface = Mock()
            iface.dev = None
            iface.writemem.side_effect = lambda pa, body: memory.extend(body)
            iface.readmem.side_effect = lambda pa, size: bytes(memory[pa - base:pa - base + size])
            def execute(_asm, commands_pa, count, _inbox, _control):
                command = struct.unpack_from("<29Q", memory)
                self.assertEqual((commands_pa, count), (base, 1))
                self.assertEqual(command[19], base + 29 * 8)
                self.assertEqual(command[28] - command[27], 16 + 24 * (capacity or 512))
                mailbox = command[27] - base
                struct.pack_into("<2Q", memory, mailbox, command[27] + 16 + 48, overflow)
                struct.pack_into("<6Q", memory, mailbox + 16, 0, 0x42000000000000, 0x20, 1, 0x1234, 1)
                return 0
            util = SimpleNamespace(heap=SimpleNamespace(guarded_malloc=allocation), exec=execute)
            asces = tuple(SimpleNamespace(asc=SimpleNamespace(_base=0x10000 * (i + 1))) for i in range(2))
            messages = []
            def upload(_util, _proxy, _iface, writes):
                from m1n1.drm_shim.g17g_transfer import zero_runs
                writes = tuple(writes)
                self.assertEqual(len(writes), 1)
                pa, encoded = writes[0]
                self.assertEqual(pa, base)
                # Exercise the actual lossless record splitter and reconstruct
                # the complete immutable staging image in this CPU mock.
                rebuilt = bytearray(len(encoded))
                for address, size, body in zero_runs(writes):
                    rebuilt[address - base:address - base + size] = bytes(size) if body is None else body
                self.assertEqual(rebuilt, encoded)
                memory.extend(rebuilt)
                return 1
            def run():
                with patch("m1n1.drm_shim.g17g_transfer.write_publications", side_effect=upload):
                    return run_render_stream_sequence(util, Mock(), iface, asces,
                        (((0,) * 13 + (3,) + (0,) * 5, (), ()),), mailbox_capture=messages,
                        mailbox_capacity=capacity)
            if overflow:
                with self.assertRaisesRegex(RuntimeError, "overflow"):
                    run()
            else:
                self.assertEqual(run()["proxy_call_count"], 1)
            self.assertEqual(messages, [(0, 0x42000000000000, 0x20), (1, 0x1234, 1)])
        for capacity in (0, -1, 1048577, True):
            with self.assertRaisesRegex(ValueError, "capacity"):
                run()

    def test_sequencer_io_deadline_covers_target_waits_and_is_restored(self):
        from contextlib import contextmanager
        from m1n1.drm_shim.g17g_stream import run_render_stream_sequence
        @contextmanager
        def allocation(_size):
            yield 0x100000
        for count in (1, 31):
            for prior_timeout in (0.1, 900.0, None):
                for fails in (False, True):
                    with self.subTest(count=count, prior=prior_timeout, fails=fails):
                        serial = SimpleNamespace(timeout=prior_timeout)
                        iface = SimpleNamespace(dev=serial)
                        def execute(*_args):
                            if prior_timeout is None:
                                self.assertIsNone(serial.timeout)
                            else:
                                # All four target waits may elapse in each
                                # command; keep time for the final reply too.
                                self.assertGreater(serial.timeout, count * (2 + 2 + 5 + 2))
                                self.assertGreaterEqual(serial.timeout, prior_timeout)
                            if fails:
                                raise OSError("transport failure")
                            return 0
                        util = SimpleNamespace(heap=SimpleNamespace(guarded_malloc=allocation), exec=execute)
                        asces = tuple(SimpleNamespace(asc=SimpleNamespace(_base=0x10000 * (i + 1))) for i in range(2))
                        commands = tuple(((0,) * 13 + (i + 3,) + (0,) * 5, (), ()) for i in range(count))
                        with patch("m1n1.drm_shim.g17g_transfer.write_publications"):
                            if fails:
                                with self.assertRaisesRegex(OSError, "transport failure"):
                                    run_render_stream_sequence(util, Mock(), iface, asces, commands)
                            else:
                                self.assertEqual(run_render_stream_sequence(util, Mock(), iface, asces, commands)["command_count"], count)
                        self.assertEqual(serial.timeout, prior_timeout)

    def test_stage_checks_all_guards_before_any_write(self):
        runtime = self.runtime()
        runtime.read_fields = Mock(return_value={0x1000: struct.pack("<Q", 1), 0x1008: struct.pack("<Q", 99)})
        runtime.publish_writes = Mock()
        rows = {0x1000: ((0, 1, 2), (8, 1, 2))}
        with self.assertRaisesRegex(RuntimeError, "source mismatch"):
            runtime.guarded_qwords(rows)
        runtime.publish_writes.assert_not_called()
        runtime.read_fields.return_value[0x1008] = struct.pack("<Q", 2)
        runtime.publish_writes.side_effect = lambda writes: self.assertEqual(
            tuple(writes), ((0x1000, struct.pack("<Q", 2)),))
        runtime.guarded_qwords(rows)
