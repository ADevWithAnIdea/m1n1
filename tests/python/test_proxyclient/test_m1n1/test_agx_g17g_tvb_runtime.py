# SPDX-License-Identifier: GPL-2.0-only
import copy
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from m1n1.drm_shim.g17g_tvb_runtime import G17GTVBPool, _OwnedAllocator, GROWTH_BASE
from m1n1.drm_shim.g17g_render_submit import first_render_completion


class TestTVBRuntime(unittest.TestCase):
    def test_limit_reply_is_bound_to_published_work_and_only_echoes_cookie(self):
        from m1n1.drm_shim import g17g_backend as backend, g17g_defaults
        from m1n1.drm_shim.g17g_render_submit import first_render_graph, continued_render_graph
        first = first_render_graph(backend.build_partial_render_products()['parameters'])
        second = continued_render_graph(first['parameters'], 2, private_dvas=first['private_dvas'])
        for ordinal, graph, queue, pool_address in (
                (1, first, 0xfffffc20c0000080, 0xfffffc20c08e8000),
                (2, second, 0xfffffc20c0000000, 0xfffffc20c08a8200)):
            runtime = self.runtime()
            runtime.boot = SimpleNamespace(fields=g17g_defaults.canonical_preinit_fields())
            runtime.publish_writes = Mock()
            runtime.channel_state = lambda: (10, 10, 10)
            runtime.read_fields.return_value = {0: bytes(4)}
            pool = G17GTVBPool(runtime, max_blocks=13)
            pool.begin(graph)
            body = bytearray(72)
            struct.pack_into('<5I', body, 0, 7, 0, 1, 1, ordinal * 0x100)
            struct.pack_into('<2Q', body, 24, queue, pool_address)
            struct.pack_into('<Q', body, 48, graph['firmware_addresses']['fragment_descriptor'])
            struct.pack_into('<I', body, 64, 1)
            reply = pool.service.limit_handler(bytes(body))
            self.assertEqual(reply['ordinal'], ordinal)
            self.assertEqual(struct.unpack_from('<IIQI', reply['command']), (9, 1, queue, ordinal * 0x100))
            for offset in (12, 16, 48):
                changed = bytearray(body)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'unattributed'):
                    pool.service.limit_handler(bytes(changed))
            cookie = bytes.fromhex('4079070000fcffff')
            body[24:32] = cookie
            body[32:40] = bytes.fromhex('5c79070000fcffff')
            self.assertEqual(pool.service.limit_handler(bytes(body))['command'][8:16], cookie)
            runtime.publish_writes.assert_not_called()

    def test_mixed_limit_uses_published_fragment_slot_and_opaque_cookie(self):
        from m1n1.drm_shim import g17g_backend as backend, g17g_defaults
        from m1n1.drm_shim.g17g_mixed_submit import mixed_partial_graph, continued_mixed_partial_graph
        params = backend.build_earliest_mixed_partial_render_products(compute_predecessor=True)['parameters']
        first = mixed_partial_graph(params)
        second = continued_mixed_partial_graph(params, 2, private_dvas=first['private_dvas'])
        for ordinal, graph in enumerate((first, second), 1):
            runtime = self.runtime()
            runtime.boot = SimpleNamespace(fields=g17g_defaults.canonical_preinit_fields())
            runtime.publish_writes = Mock()
            runtime.channel_state = lambda: (10, 10, 10)
            runtime.read_fields.return_value = {0: bytes(4)}
            pool = G17GTVBPool(runtime, max_blocks=13, fragment_slot=2, terminal_mask=6)
            pool.begin(graph)
            body = bytearray(72)
            struct.pack_into('<5I', body, 0, 7, 0, 1, 2, ordinal << 8)
            body[24:32] = bytes.fromhex('4079070000fcffff')
            struct.pack_into('<Q', body, 48, graph['firmware_addresses']['fragment_descriptor'])
            struct.pack_into('<I', body, 64, 1)
            reply = pool.service.limit_handler(bytes(body))
            self.assertEqual(reply['command'][8:16], body[24:32])
            self.assertEqual(pool.service.terminal_mask, 6)
            body[12] = 1
            with self.assertRaisesRegex(ValueError, 'unattributed'):
                pool.service.limit_handler(bytes(body))
            runtime.publish_writes.assert_not_called()

    def test_memory_limit_does_not_allocate_or_claim_terminal_before_exchange(self):
        runtime = self.runtime()
        pool = G17GTVBPool(runtime, max_blocks=3)
        pool.service = SimpleNamespace(limit_handler=Mock(), replies=[], limit_report=None, terminal=None)
        reply = pool.prepare(bytes(72), 0)
        self.assertEqual(struct.unpack_from('<5I', reply['command']), (8, 0, 0, 1, 0))
        self.assertEqual((reply['old_count'], reply['new_count']), (3, 3))
        self.assertEqual(runtime.allocations, [])
        after = dict(reports=dict(records=[]))
        self.assertIsNone(pool.limit_outcome(after))
        pool.service.replies.append(dict(negative_reply=True))
        self.assertEqual(pool.limit_outcome(after), 'pending')
        pool.service.limit_report = dict(ordinal=1)
        self.assertEqual(pool.limit_outcome(after), 'pending')
        pool.service.terminal = dict(slot=9)
        pool.service.cursor, pool.service.producer = 10, 0x10000
        pool.service.u32 = lambda address: 10
        runtime.channel_state = lambda: (10, 10, 11)
        self.assertEqual(pool.limit_outcome(after), 'pending')
        runtime.channel_state = lambda: (10, 10, 10)
        self.assertEqual(pool.limit_outcome(after), 'out_of_memory')
        pool.service.terminal = None
        pool.require_first_terminal = False
        self.assertEqual(pool.limit_outcome(after), 'limit_followup_retired')
        runtime.channel_state = lambda: (10, 10, 11)
        self.assertEqual(pool.limit_outcome(after), 'pending')
        runtime.channel_state = lambda: (10, 10, 10)
        pool.require_first_terminal = True
        self.assertEqual(pool.limit_outcome(after), 'pending')
        pool.service.limit_report = dict(ordinal=2)
        self.assertEqual(pool.limit_outcome(after), 'limit_followup_retired')
        after['reports']['records'] = [(struct.pack('<I', 4) + bytes(68)).hex()]
        self.assertEqual(pool.limit_outcome(after), 'fault')

    def test_fixed_pool_rejects_unexpected_capacity_request_before_any_mutation(self):
        runtime = self.runtime()
        pool = G17GTVBPool(runtime, allow_growth=False)
        with self.assertRaisesRegex(RuntimeError, "fixed-pool"):
            pool.prepare(bytes(72), 0)
        runtime.read_fields.assert_not_called()
        self.assertEqual(runtime.allocations, [])

    def runtime(self):
        return SimpleNamespace(u=Mock(), p=Mock(), iface=Mock(), uat=Mock(), layout=None, context_id=1,
            allocations=[], context=dict(root0=0x10000, pages={}, allocations=[], table_witnesses=set()),
            private_dvas=set(), pa=lambda va: va, read=Mock(), evidence={"tvb": {"consumed_reports": []}},
            service_cursor=10, read_fields=Mock(return_value={0: struct.pack("<2I", 3, 3)}))

    def test_allocation_is_pinned_even_if_later_publication_fails(self):
        runtime = self.runtime()
        runtime.u.memalign.return_value = 0x200000
        owner = _OwnedAllocator(runtime)
        self.assertEqual(owner.memalign(0x8000, 0x504000), 0x200000)
        self.assertEqual(runtime.allocations, [(0x200000, 0x504000)])
        self.assertEqual(runtime.context["allocations"], runtime.allocations)

    def test_growth_preserves_caller_pages_and_tracks_all_private_leaves(self):
        runtime = self.runtime()
        runtime.context["pages"][0x70000] = 0x80000
        pool = G17GTVBPool(runtime)
        result = dict(new_physical=0x200000, allocation_bytes=0x504000,
                      new_uat_tables=[0x700000], command=bytes(64))
        with patch("m1n1.drm_shim.g17g_tvb_runtime.allocate_growth_reply", return_value=result) as allocate:
            pool.prepare(bytes(72), 0)
        self.assertEqual(pool.counter, 1)
        self.assertEqual(len(runtime.private_dvas), 320)
        self.assertEqual(runtime.context["table_witnesses"], runtime.private_dvas)
        self.assertEqual(runtime.context["pages"][GROWTH_BASE], 0x200000)
        self.assertEqual(runtime.context["pages"][0x70000], 0x80000)
        self.assertEqual(allocate.call_args.kwargs["expected_counter"], 0)
        runtime.uat.invalidate_cache.assert_called_once()
        with self.assertRaisesRegex(RuntimeError, "overlaps"):
            pool.prepare(bytes(72), 1)

    def test_placed_growth_tracks_source_tables_in_high_root_only(self):
        runtime = self.runtime()
        runtime.layout = Mock()
        runtime.context['root1'] = 0x900000
        runtime.publish_writes = Mock()
        pool = G17GTVBPool(runtime)
        result = dict(new_physical=0x200000, allocation_bytes=0x504000,
                      new_uat_tables=[0x700000], command=bytes(64))
        with patch('m1n1.drm_shim.g17g_tvb_runtime.allocate_growth_reply', return_value=result) as allocate:
            pool.prepare(bytes(72), 0)
        self.assertEqual(allocate.call_args.kwargs['root_pa'], 0x900000)
        self.assertEqual(runtime.context['table_witnesses'], set())
        self.assertEqual(runtime.context['high_table_witnesses'], runtime.private_dvas)
        runtime.layout.relocate_context.assert_called_once()

    def test_mixed_growth_uses_its_owned_state_list_and_disjoint_backing(self):
        runtime = self.runtime()
        state, block_list, base = 0xfffffc2001628000, 0xfffffc20c08c8000, 0x1100000000
        pool = G17GTVBPool(runtime, state_address=state, list_address=block_list,
                           growth_base=base, notification_masks=(2, 4, 6))
        result = dict(new_physical=0x200000, allocation_bytes=0x504000,
                      new_uat_tables=[0x700000], command=bytes(64))
        with patch('m1n1.drm_shim.g17g_tvb_runtime.allocate_growth_reply', return_value=result) as allocate:
            pool.prepare(bytes(72), 0)
        runtime.read_fields.assert_called_once_with({0: (state, 8)})
        self.assertEqual(allocate.call_args.kwargs['state_pa'], state)
        self.assertEqual(allocate.call_args.kwargs['list_pa'], block_list)
        self.assertEqual(runtime.context['pages'][base], 0x200000)
        self.assertNotIn(GROWTH_BASE, runtime.private_dvas)

    def test_preallocation_exhaustion_replies_without_publishing_fake_capacity(self):
        runtime = self.runtime()
        pool = G17GTVBPool(runtime)
        with patch("m1n1.drm_shim.g17g_tvb_runtime.allocate_growth_reply", side_effect=MemoryError("no backing")):
            result = pool.prepare(bytes(72), 0)
        self.assertEqual(struct.unpack_from("<5I", result["command"]), (8, 1, 0, 1, 0))
        self.assertEqual((result["old_count"], result["new_count"], result["bytes"]), (3, 3, 0))
        self.assertEqual((pool.counter, runtime.allocations, runtime.context["pages"]), (1, [], {}))
        runtime.uat.invalidate_cache.assert_not_called()

    def test_postallocation_memory_failure_is_not_replied_as_unchanged_pool(self):
        runtime = self.runtime()
        pool = G17GTVBPool(runtime)
        def fail(*args, **kwargs):
            runtime.allocations.append((0x200000, 0x500000))
            raise MemoryError("failure after allocation")
        with patch("m1n1.drm_shim.g17g_tvb_runtime.allocate_growth_reply", side_effect=fail):
            with self.assertRaisesRegex(MemoryError, "after allocation"):
                pool.prepare(bytes(72), 0)
        self.assertEqual(pool.counter, 0)
        self.assertFalse(pool.replies)
        self.assertEqual(runtime.allocations, [(0x200000, 0x500000)])

    def test_consumption_rebases_only_report_floor_not_timestamp_preimages(self):
        runtime = self.runtime()
        pool = G17GTVBPool(runtime)
        body = struct.pack("<4I", 6, 1, 0, 0) + bytes(56)
        runtime.read_fields.return_value = {0: body}
        service = SimpleNamespace(producer=0x1020, records=0x10000, cursor=7,
            u32=lambda _address: 9, next_command_slot=11, last_report=dict(slot=7, record_hex=body.hex()))
        service.step = Mock(side_effect=lambda: setattr(service, "cursor", 8))
        pool.service = service
        before = dict(reports=dict(consumer=0, producer=7, records=[(struct.pack("<I", 1) + bytes(68)).hex()]),
                      execution_timestamps=bytes(32).hex())
        self.assertTrue(pool.step(before))
        self.assertEqual(before["reports"], dict(consumer=8, producer=8, records=[]))
        self.assertEqual(before["execution_timestamps"], bytes(32).hex())
        self.assertEqual(runtime.service_cursor, 11)
        # The new fault at slot8 is not consumed or hidden by this service.
        runtime.read_fields.return_value = {0: struct.pack("<I", 4) + bytes(68)}
        old = copy.deepcopy(before)
        self.assertFalse(pool.step(before))
        self.assertEqual(before, old)
        self.assertEqual(service.step.call_count, 1)

    def test_preexisting_fault_is_not_rebased_away_by_new_service_records(self):
        runtime = self.runtime()
        pool = G17GTVBPool(runtime)
        pool.service = Mock()
        before = dict(reports=dict(consumer=0, producer=1,
            records=[(struct.pack("<I", 4) + bytes(68)).hex()]), execution_timestamps=bytes(32).hex())
        old = copy.deepcopy(before)
        self.assertFalse(pool.step(before))
        self.assertEqual(before, old)
        pool.service.step.assert_not_called()
        runtime.read_fields.assert_not_called()

    def test_pending_growth_cannot_complete_and_new_fault_still_wins(self):
        before = dict(reports=dict(consumer=5, producer=5, records=[]), execution_timestamps=bytes(32).hex())
        growth = (struct.pack("<4I", 6, 1, 0, 3) + bytes(56)).hex()
        after = dict(reports=dict(consumer=5, producer=6, records=[growth]),
                     execution_timestamps=struct.pack("<4Q", 10, 20, 15, 30).hex())
        self.assertIsNone(first_render_completion(before, after, 3, pending_growth=True))
        with self.assertRaisesRegex(ValueError, "unclassified"):
            first_render_completion(before, after, 3)
        after["reports"] = dict(consumer=5, producer=7,
            records=[growth, (struct.pack("<I", 4) + bytes(68)).hex()])
        self.assertEqual(first_render_completion(before, after, 3, pending_growth=True), "fault")

    def test_live_service_excludes_report_exemplars_not_other_lifecycle_checks(self):
        from m1n1.drm_shim import g17g_backend as backend, g17g_defaults
        runtime = self.runtime()
        runtime.boot = SimpleNamespace(fields=g17g_defaults.canonical_preinit_fields())
        rows = backend.build_second_render_minimal_postservice_qwords()
        filtered = G17GTVBPool(runtime).lifecycle_qwords(rows)
        removed = {page + row[0] for page in rows for row in rows[page] if row not in filtered[page]}
        self.assertEqual(removed, {0xfffffc200002c000 + offset for offset in
            (0x31e0, 0x34d0, 0x34e8, 0x34f0, 0x34f8, 0x3500, 0x3508, 0x3510)})
        self.assertTrue(any(row[0] == 0x33e0 for row in filtered[0xfffffc200002c000]))

    def test_separate_engine_report_is_consumed_without_becoming_completion(self):
        for mask in (1, 2):
            runtime = self.runtime()
            pool = G17GTVBPool(runtime)
            body = struct.pack("<4I", 1, mask, 0, 0) + bytes(56)
            runtime.read_fields.return_value = {0: body}
            service = SimpleNamespace(producer=0x1020, records=0x10000, cursor=255,
                consumer=0x1000, u32=lambda _address: 1, next_command_slot=None, write=Mock(), step=Mock())
            pool.service = service
            before = dict(reports=dict(consumer=255, producer=255, records=[]),
                          execution_timestamps=bytes(32).hex())
            self.assertTrue(pool.step(before))
            service.write.assert_called_once_with(0x1000, bytes(4))
            service.step.assert_not_called()
            self.assertEqual(service.cursor, 0)
            self.assertEqual(before["execution_timestamps"], bytes(32).hex())
            self.assertEqual(runtime.evidence["tvb"]["consumed_reports"][0]["slot"], 255)
