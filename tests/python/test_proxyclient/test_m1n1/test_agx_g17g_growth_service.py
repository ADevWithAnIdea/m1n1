# SPDX-License-Identifier: GPL-2.0-only
import struct
from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from m1n1.drm_shim.g17g_growth import (
    allocate_growth_reply, allocate_tvb_backing, build_growth_ack, build_growth_reply,
    build_idle_tvb_metadata,
    build_growth_failure_ack, build_growth_limit_followup,
)
from m1n1.drm_shim.g17g_growth_service import TVBGrowthService, pump_asces_once
from m1n1.drm_shim.g17g_crash import crash_metadata
from m1n1.drm_shim.g17g_stream import write_control_record, write_control_records, read_output_word


class TestGrowthService(unittest.TestCase):
    def test_real_client_heap_exhaustion_releases_only_diagnostic_reservations(self):
        from m1n1.malloc import Heap
        from _g17g_heap_pressure import ExhaustAtAllocation
        heap = Heap(0x8000, 0x100000)
        prior = heap.malloc(0x2000)
        before = list(heap.blocks)
        util = SimpleNamespace(heap=heap, memalign=heap.memalign)
        pressure = ExhaustAtAllocation(util)
        with self.assertRaisesRegex(Exception, "Out of memory"):
            pressure.memalign(0x8000, 0x80000)
        self.assertEqual(heap.blocks, before)
        self.assertEqual(pressure.evidence['gpu_visible_reservation_bytes'], 0)
        self.assertEqual(pressure.evidence['reserved_bytes'], pressure.evidence['free_bytes_after_release'])
        self.assertNotEqual(heap.memalign(0x8000, 0x80000), prior)

    def native_limit_body(self):
        return bytes.fromhex('070000000000000001000000010000000001000020fcffff800000c020fcffff00808ec020fcffff0080100000fcffff00000bc020fcffff00000000000000000100000000000000')

    def native_limit_command(self, body):
        return build_growth_limit_followup(body, queue_dva=0xfffffc20c0000080,
            pool_dva=0xfffffc20c08e8000, fragment_dva=0xfffffc20c00b0000,
            event_slot=1, event_value=0x100)

    def test_owned_limit_followup_validates_before_building(self):
        body = self.native_limit_body()
        self.assertEqual(self.native_limit_command(body),
                         struct.pack('<IIQI', 9, 1, 0xfffffc20c0000080, 0x100) + bytes(44))
        for offset in (0, 4, 8, 12, 16, 24, 32, 48, 56, 64):
            changed = bytearray(body); changed[offset] ^= 1
            with self.assertRaises(ValueError): self.native_limit_command(changed)
        for field in ('queue_dva', 'pool_dva', 'fragment_dva', 'event_slot', 'event_value'):
            kwargs = dict(queue_dva=0xfffffc20c0000080, pool_dva=0xfffffc20c08e8000,
                          fragment_dva=0xfffffc20c00b0000, event_slot=1, event_value=0x100)
            kwargs[field] = -1
            with self.assertRaises(ValueError): build_growth_limit_followup(body, **kwargs)

    def test_service_native_limit_is_failure_not_success_and_producer_last(self):
        service, put, writes, prepare, notify = self.service()
        service.limit_handler = lambda body: dict(command=self.native_limit_command(body))
        prepare.return_value = dict(command=build_growth_failure_ack(1, 0, 0))
        put(0x1020, struct.pack('<I', 2))
        put(0x10048, struct.pack('<4I', 6, 1, 0, 0) + bytes(56))
        self.assertFalse(service.step())
        self.assertTrue(service.replies[-1]['negative_reply'])
        put(0x2000, struct.pack('<I', 3))
        put(0x1020, struct.pack('<I', 3))
        put(0x10090, self.native_limit_body())
        self.assertFalse(service.step())
        self.assertEqual([a for a, _ in writes[-3:]], [0x40c0, 0x1000, 0x2020])
        self.assertEqual(writes[-3][1], self.native_limit_command(self.native_limit_body()))
        self.assertEqual(service.limit_report['report_slot'], 2)
        self.assertEqual(service.next_command_slot, 4)
        put(0x1020, struct.pack('<I', 4))
        put(0x100d8, struct.pack('<4I', 1, 3, 0, 0) + bytes(56))
        self.assertTrue(service.step())
        self.assertEqual(service.terminal['slot'], 3)
        self.assertEqual(service.next_command_slot, 4)
        self.assertEqual(notify.call_count, 2)

    def test_service_rejects_unenabled_negative_and_unowned_limit_without_publication(self):
        service, put, writes, prepare, notify = self.service()
        prepare.return_value = dict(command=build_growth_failure_ack(1, 0, 0))
        put(0x1020, struct.pack('<I', 2))
        put(0x10048, struct.pack('<4I', 6, 1, 0, 0) + bytes(56))
        with self.assertRaises(ValueError): service.step()
        self.assertEqual(writes, [])
        service.limit_handler = lambda body: dict(command=self.native_limit_command(body))
        put(0x10048, self.native_limit_body())
        with self.assertRaises(ValueError): service.step()
        service.replies = [dict(negative_reply=True)]
        malformed = bytearray(self.native_limit_body()); malformed[24] ^= 1
        put(0x10048, malformed)
        with self.assertRaises(ValueError): service.step()
        self.assertEqual(writes, [])
        notify.assert_not_called()
        self.assertEqual(service.cursor, 1)

    def test_mixed_limit_terminal_requires_its_engine_mask_and_zero_tail(self):
        service, put, writes, prepare, notify = self.service()
        service.terminal_mask = 6
        service.limit_report = dict(ordinal=1)
        put(0x1020, struct.pack('<I', 2))
        put(0x10048, struct.pack('<4I', 1, 3, 0, 0) + bytes(56))
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            service.step()
        put(0x10048, struct.pack('<4I', 1, 6, 0, 0) + bytes(55) + b'\x01')
        with self.assertRaisesRegex(ValueError, 'terminal'):
            service.step()
        self.assertEqual(writes, [])
        self.assertEqual(service.cursor, 1)
        put(0x10048, struct.pack('<4I', 1, 6, 0, 0) + bytes(56))
        self.assertTrue(service.step())
        self.assertEqual(service.terminal['slot'], 1)
        self.assertEqual(writes, [(0x1000, struct.pack('<I', 2))])
        prepare.assert_not_called()
        notify.assert_not_called()

    def test_idle_tvb_metadata_uses_32k_units_and_preserves_non_capacity_words(self):
        for count in (3, 13, 38):
            dvas = [0x1000088000 + i * 0x88000 for i in range(count)]
            idle = build_idle_tvb_metadata(dvas)
            expected = tuple(unit for i in range(count)
                             for unit in range(17 * (i + 1), 17 * (i + 1) + 16))
            self.assertEqual(struct.unpack('<%dI' % (count * 16), idle['unit_list']), expected)
            self.assertEqual(idle['info_fields'], tuple((offset, struct.pack('<I', value))
                for offset, value in ((0x34, count * 16), (0x3c, count), (0x54, count * 16 - 1))))
        for dvas in ([], [0x1000088001], [0x1000088000] * 2,
                     [0x1000088000, 0x1000090000]):
            with self.assertRaises(ValueError): build_idle_tvb_metadata(dvas)

    def test_coherent_control_write_is_bounded_and_uses_only_owned_source(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        util.heap.guarded_malloc.side_effect = lambda size: nullcontext(0x10008000000)
        util.exec.return_value = 0
        for pa, data in ((0x10000000000, bytes(4)), (0x1000000007c, bytes(64))):
            write_control_record(util, proxy, iface, pa, data)
            iface.writemem.assert_called_with(0x10008000000, data)
            self.assertEqual(util.exec.call_args.args[1:], (pa, 0x10008000000, len(data)))
        before = util.mock_calls[:], proxy.mock_calls[:], iface.mock_calls[:]
        for pa, size in ((0, 4), (True, 4), (3, 4), (1 << 42, 4),
                         ((1 << 42) - 4, 8), (0x10000000000, 0),
                         (0x10000000000, 3), (0x10000000000, 68)):
            with self.assertRaises(ValueError):
                write_control_record(util, proxy, iface, pa, bytes(size))
        self.assertEqual(before, (util.mock_calls, proxy.mock_calls, iface.mock_calls))

    def test_mailbox_sweep_never_starves_a_peer_or_drains_forever(self):
        calls = []
        def asc(name, pending):
            return SimpleNamespace(
                has_messages=lambda: calls.append(name + ":check") or pending,
                work=lambda: calls.append(name + ":work"))
        # Continuously ready mailboxes still get at most one work call each;
        # no timing cutoff can discard the second member of the sweep.
        pump_asces_once((asc("primary", True), asc("secondary", True)))
        self.assertEqual(calls, ["primary:check", "primary:work",
                                 "secondary:check", "secondary:work"])
        calls.clear()
        pump_asces_once((asc("primary", False), asc("secondary", True)))
        self.assertEqual(calls, ["primary:check", "secondary:check", "secondary:work"])

    def test_control_batch_preserves_order_and_uses_one_immutable_table(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        source = 0x10008000000
        util.heap.guarded_malloc.side_effect = lambda size: nullcontext(source)
        util.exec.return_value = 0
        writes = ((0x1000000007c, bytes(64)), (0x10000008000, bytes(4)),
                  (0x1000000c020, struct.pack('<I', 3)))
        write_control_records(util, proxy, iface, writes)
        body = iface.writemem.call_args.args[1]
        self.assertEqual(len(body), 144)
        offset = 72
        for i, (pa, data) in enumerate(writes):
            self.assertEqual(struct.unpack_from('<3Q', body, i * 24),
                             (pa, source + offset, len(data)))
            self.assertEqual(body[offset:offset + len(data)], data)
            offset += len(data)
        iface.writemem.assert_called_once_with(source, body)
        proxy.dc_civac.assert_called_once_with(source, len(body))
        util.exec.assert_called_once()
        self.assertEqual(util.exec.call_args.args[1:], (source, 3))

    def test_invalid_late_batch_entry_and_private_source_alias_never_publish(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        source = 0x10008000000
        util.heap.guarded_malloc.side_effect = lambda size: nullcontext(source)
        for writes in ((), ((4, bytes(4)),) * 17,
                       ((4, bytes(4)), (3, bytes(4))),
                       ((4, bytes(4)), (source + 100, bytes(4)))):
            with self.assertRaises(ValueError):
                write_control_records(util, proxy, iface, writes)
        iface.writemem.assert_not_called()
        proxy.dc_civac.assert_not_called()
        util.exec.assert_not_called()

    def test_batched_service_publication_is_producer_last_before_notify(self):
        service, put, writes, prepare, notify = self.service()
        order = []
        service.publish = lambda entries: order.append(('publish', entries))
        notify.side_effect = lambda: order.append(('notify',))
        service.read = Mock(wraps=service.read)
        put(0x1020, struct.pack('<I', 2))
        put(0x10048, struct.pack('<4I', 6, 1, 0, 0) + bytes(56))
        service.step()
        self.assertEqual([entry[0] for entry in order], ['publish', 'notify'])
        self.assertEqual([a for a, _ in order[0][1]], [0x4080, 0x1000, 0x2020])
        self.assertEqual(order[0][1][-1][1], struct.pack('<I', 3))
        self.assertEqual(writes, [])
        self.assertIn(((0x2000, 0x24),), service.read.call_args_list)

    def test_crash_metadata_does_not_follow_firmware_pointers(self):
        registers = SimpleNamespace(pc=0xfffffc0000005338, far=0x20,
            sp=0xfffffc00000779e0, esr=0x96000004, psr=0x60000244, regs=list(range(31)))
        decoded = SimpleNamespace(entries=[
            SimpleNamespace(type="Crg8", payload=registers),
            SimpleNamespace(type="Ccdp", payload=object()),
        ])
        with patch('m1n1.drm_shim.g17g_crash.CrashLog.parse', return_value=decoded):
            record = crash_metadata(b'only crash data')
        self.assertEqual(record['records'][0]['far'], 0x20)
        self.assertEqual(record['records'][1], dict(type='Ccdp'))
        self.assertFalse(record['firmware_pointer_reads'])

    def service(self, cursor=1, tail=2, failure=False):
        memory, writes = {}, []
        def put(address, data):
            for i, byte in enumerate(data): memory[address + i] = byte
        def read(address, size):
            return bytes(memory.get(address + i, 0) for i in range(size))
        def write(address, data):
            writes.append((address, data)); put(address, data)
        put(0x1020, struct.pack('<I', cursor))
        put(0x2000, struct.pack('<I', tail))
        put(0x2020, struct.pack('<I', tail))
        prepare = Mock(return_value=dict(command=struct.pack('<5I', 8, 1, 0, 1, 0) + bytes(44)))
        if failure: prepare.side_effect = MemoryError('test allocation failure')
        notify = Mock()
        service = TVBGrowthService(read, write, prepare, notify, Mock(),
            channel12=((0x2000, 0x2010, 0x2020), 0x4000),
            channel13=((0x1000, 0x10000, 0x1040), 0x14800))
        return service, put, writes, prepare, notify

    def test_publication_order_and_current_ring_slots(self):
        for cursor, tail in ((1, 2), (255, 255)):
            with self.subTest(cursor=cursor):
                service, put, writes, prepare, notify = self.service(cursor, tail)
                self.assertFalse(service.step())
                put(0x1020, struct.pack('<I', (cursor + 1) & 255))
                put(0x10000 + cursor * 0x48, struct.pack('<4I', 6, 1, 0, 0) + bytes(56))
                self.assertFalse(service.step())
                self.assertEqual([a for a, _data in writes], [0x4000 + tail * 0x40, 0x1000, 0x2020])
                self.assertEqual(bytes.fromhex(service.replies[0]['request_hex']),
                                 struct.pack('<4I', 6, 1, 0, 0) + bytes(56))
                self.assertEqual(writes[-1][1], struct.pack('<I', (tail + 1) & 255))
                notify.assert_called_once()
                next_slot = (cursor + 1) & 255
                put(0x10000 + next_slot * 0x48, struct.pack('<4I', 1, 3, 0, 0) + bytes(56))
                put(0x1020, struct.pack('<I', (cursor + 2) & 255))
                self.assertTrue(service.step())
                self.assertEqual(service.terminal['slot'], next_slot)

    def test_allocation_failure_does_not_ack_or_consume(self):
        service, put, writes, prepare, notify = self.service(failure=True)
        put(0x1020, struct.pack('<I', 2))
        put(0x10048, struct.pack('<4I', 6, 1, 0, 0) + bytes(56))
        with self.assertRaises(MemoryError): service.step()
        self.assertEqual(writes, [])
        notify.assert_not_called()
        self.assertEqual(service.cursor, 1)

    def test_explicit_expected_counter_rejects_a_reset_before_any_reply(self):
        for observed in (0, 2):
            service, put, writes, prepare, notify = self.service()
            service = TVBGrowthService(service.read, service.write, prepare, notify, service.pump,
                channel12=(service.command_states, service.command_ring),
                channel13=((service.consumer, service.records, 0x1040), service.other_report_ring),
                first_counter=2)
            prepare.return_value = dict(command=build_growth_ack(1, 0, 2), counter=2)
            put(0x1020, struct.pack('<I', 2))
            put(0x10048, struct.pack('<4I', 6, 1, 0, observed) + bytes(56))
            if observed == 0:
                with self.assertRaises(ValueError): service.step()
                self.assertEqual(writes, [])
                prepare.assert_not_called()
            else:
                self.assertFalse(service.step())
                prepare.assert_called_once_with(struct.pack('<4I', 6, 1, 0, 2) + bytes(56), 2)
                self.assertEqual(service.replies[0]['counter'], 2)

    def test_caller_witness_bounds_service_without_inventing_a_terminal_report(self):
        service, _put, writes, prepare, notify = self.service()
        finished = Mock(return_value=True)
        result = service.run(timeout=1, finished=finished)
        self.assertEqual(result['stopped_by'], 'caller-witness')
        self.assertIsNone(result['terminal'])
        self.assertIn('none', result['execution_claim'])
        self.assertEqual(writes, [])
        prepare.assert_not_called()
        notify.assert_not_called()
        finished.assert_called_once()

    def test_bounded_refusal_train_wraps_both_rings_without_resetting_request_counter(self):
        service, put, writes, prepare, notify = self.service()
        service = TVBGrowthService(service.read, service.write, prepare, notify, service.pump,
            channel12=(service.command_states, service.command_ring),
            channel13=((service.consumer, service.records, 0x1040), service.other_report_ring),
            request_limit=260)
        for counter in range(260):
            cursor = (counter + 1) & 255
            put(0x1020, struct.pack('<I', (cursor + 1) & 255))
            put(0x10000 + cursor * 0x48, struct.pack('<4I', 6, 1, 0, counter) + bytes(56))
            prepare.return_value = dict(command=build_growth_ack(1, 0, counter), counter=counter,
                                        old_count=3, new_count=3)
            self.assertFalse(service.step())
            put(0x2000, struct.pack('<I', (counter + 3) & 255))  # peer consumed ACK
        self.assertEqual(notify.call_count, 260)
        self.assertEqual(service.replies[254]['reply_slot'], 0)
        self.assertEqual(service.replies[255]['report_slot'], 0)
        self.assertEqual(service.replies[-1]['counter'], 259)
        self.assertIsNone(service.terminal)
        before = list(writes)
        put(0x1020, struct.pack('<I', (service.cursor + 1) & 255))
        put(0x10000 + service.cursor * 0x48, struct.pack('<4I', 6, 1, 0, 260) + bytes(56))
        with self.assertRaisesRegex(RuntimeError, '260-request'): service.step()
        self.assertEqual(writes, before)

    def test_invalid_request_budget_fails_before_io(self):
        read = Mock()
        for budget in (0, -1, True, 513, 1.5):
            with self.assertRaises(ValueError):
                TVBGrowthService(read, Mock(), Mock(), Mock(), Mock(),
                    channel12=((1, 2, 3), 4), channel13=((5, 6, 7), 8), request_limit=budget)
        read.assert_not_called()

    def test_output_word_probe_is_one_coherent_target_call(self):
        util = Mock()
        util.exec.return_value = 0x4af42400
        self.assertEqual(read_output_word(util, 0x10001237f00), 0x4af42400)
        util.exec.assert_called_once()
        self.assertEqual(util.exec.call_args.args[1:], (0x10001237f00,))
        for address in (0, True, 3, 1 << 42):
            with self.assertRaises(ValueError): read_output_word(util, address)
        self.assertEqual(util.exec.call_count, 1)

    def test_explicit_capacity_refusal_and_retry_have_distinct_counters(self):
        service, put, writes, prepare, notify = self.service()
        prepare.side_effect = [
            dict(command=build_growth_ack(1, 0, 0), old_count=3, new_count=3),
            dict(command=build_growth_ack(1, 0, 1), old_count=3, new_count=4),
        ]
        for counter in range(2):
            put(0x1020, struct.pack('<I', counter + 2))
            put(0x10000 + (counter + 1) * 0x48,
                struct.pack('<4I', 6, 1, 0, counter) + bytes(56))
            self.assertFalse(service.step())
        self.assertEqual([c.args[1] for c in prepare.call_args_list], [0, 1])
        self.assertEqual([r['new_count'] for r in service.replies], [3, 4])
        self.assertEqual([r['reply_slot'] for r in service.replies], [2, 3])
        self.assertEqual(notify.call_count, 2)
        self.assertIsNone(service.terminal)

    def test_ack_is_not_a_capacity_or_completion_claim(self):
        self.assertEqual(build_growth_ack(1, 0, 17),
                         struct.pack('<5I', 8, 1, 0, 1, 17) + bytes(44))
        self.assertEqual(build_growth_ack(2, 0, 17),
                         struct.pack('<5I',8,1,0,2,17)+bytes(44))
        for args in ((True, 0, 0), (1, 0, -1), (64, 0, 0), (1, 1, 0)):
            with self.assertRaises(ValueError): build_growth_ack(*args)

    def test_wrong_identifiers_and_full_reply_ring_are_not_published(self):
        for vm_id, head in ((2, 2), (1, 3)):
            service, put, writes, prepare, notify = self.service()
            put(0x1020, struct.pack('<I', 2))
            put(0x2000, struct.pack('<I', head))
            put(0x10048, struct.pack('<4I', 6, vm_id, 0, 0) + bytes(56))
            with self.assertRaises((ValueError, RuntimeError)): service.step()
            prepare.assert_not_called()
            self.assertEqual(writes, [])







    def test_block_dva_cannot_wrap_the_42_bit_uat_walk(self):
        # Addresses outside the low root's extent must not alias a live walk
        # through masking of root/intermediate indices.
        for va in (1 << 42, (1 << 42) - 0x8000):
            with self.assertRaises(ValueError):
                build_growth_reply(1, 0, 0, 3, [va])
        self.assertEqual(len(build_growth_reply(1, 0, 0, 3,
            [(1 << 42) - 0x80000])['block_ids']), 8)


if __name__ == '__main__':
    unittest.main()
