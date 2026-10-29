# SPDX-License-Identifier: GPL-2.0-only
import struct
import unittest
from unittest.mock import patch

from m1n1.drm_shim import g17g, g17g_backend as backend, g17g_compute as compute
from m1n1.drm_shim.g17g_compute_queue import compute_wave, compute_waves, write_pages
from m1n1.drm_shim.g17g_submit import continued_compute_completion


class TestComputeQueue(unittest.TestCase):
    def test_sampler_inputs_follow_commands_across_a_transport_split(self):
        states = ((0x200008,1), (0,0), (0x220008,2), (0x240008,1024))
        waves = compute_waves(((0x10000,0x10040),)*4,126,backend.compute_addresses(),samplers=states)
        self.assertEqual([wave['final'] for wave in waves], [127,130])
        observed = []
        for wave in waves:
            high,low = dict(wave['high']),dict(wave['low'])
            for row in wave['records']:
                descriptor = high[row['addresses']['descriptor']]
                self.assertEqual(descriptor,low[backend.compute_submission_addresses(row['ordinal'])['descriptor_low']])
                observed.append(struct.unpack_from('<QII',descriptor,0xf2c))
        self.assertEqual(observed,[(heap,count,count+1 if count else 0) for heap,count in states])
        for heap,count in ((1,1),(0,1),(0x20000,0),(0x20000,1025)):
            with self.assertRaises(ValueError):
                compute_wave(((0x10000,0x10040),),1,backend.compute_addresses(),samplers=((heap,count),))

    def test_first_compute_wave_starts_empty_queue_without_skipping_a_command(self):
        addresses = backend.compute_addresses()
        wave = compute_wave(((0x20000, 0x20030), (0x30000, 0x30030)), 0, addresses)
        self.assertEqual([record['ordinal'] for record in wave['records']], [1, 2])
        self.assertEqual(wave['retirement_before'],
                         dict(channel=(0, 0, 0), pointers=(0, 0, 0), queue_limit=0))
        self.assertEqual(wave['retirement_after'],
                         dict(channel=(2, 2, 2), pointers=(5, 5, 5), queue_limit=5))
        high = dict(wave['high'])
        slot = addresses['channel_ring'] + compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET
        self.assertEqual(high[slot], compute.build_compute_channel_slot(addresses['queue']))
        self.assertEqual(high[slot+g17g.RING_SLOT_SIZE], compute.build_compute_repeat_channel_slot(addresses['queue'], item_limit=5))

    def test_wave_constructs_only_firmware_objects_for_opaque_commands(self):
        addresses = backend.compute_addresses()
        with patch.object(backend, "build_add_compute_graph", side_effect=AssertionError), \
             patch.object(compute, "build_add_shader_program", side_effect=AssertionError), \
             patch.object(compute, "build_cdm_stream", side_effect=AssertionError):
            wave = compute_wave(((0x20000, 0x20030),), 1, addresses)
        high, low = dict(wave["high"]), dict(wave["low"])
        sub = backend.compute_submission_addresses(2)
        descriptor = high[sub["descriptor"]]
        self.assertEqual(descriptor, low[sub["descriptor_low"]])
        self.assertEqual(struct.unpack_from("<Q", descriptor, 0xee0)[0], 0x2002c)
        self.assertEqual(struct.unpack_from("<Q", descriptor, 4)[0], 1)
        self.assertEqual(struct.unpack_from("<I", descriptor, 0xf50)[0], 0x200)
        self.assertEqual(struct.unpack_from("<I", descriptor, 0xf58)[0], 0)
        self.assertEqual(high[addresses["item_ring"] + 24], struct.pack("<2Q", sub["descriptor"], sub["event"]))
        self.assertEqual(wave["release"][0], (addresses["pointers"] + 0x40, struct.pack("<I", 5)))
        self.assertNotIn(0x20000, write_pages(wave["low"]))

    def test_wave_does_not_cross_queue_capacity_or_scheduler_width(self):
        addresses = backend.compute_addresses()
        for commands, completed in (((), 1), (((0x20000, 0x20030),) * 2, 126),
                                    (((0x20000, 0x20030),) * 21, 127),
                                    (((0x20000, 0x20030),) * 65, 1)):
            with self.assertRaises(ValueError):
                compute_wave(commands, completed, addresses)

    def test_queue_recreation_resets_local_identity_preserves_global(self):
        original = backend.compute_addresses()
        wave = compute_wave(((0x20000, 0x20030),), 127, original, priority=3)
        high = dict(wave["high"])
        sub = backend.compute_submission_addresses(128)
        new = wave["addresses"]
        descriptor = high[sub["descriptor"]]
        self.assertEqual(struct.unpack_from("<I", descriptor, 0xf50)[0], 0x100)
        self.assertEqual(struct.unpack_from("<I", descriptor, 0xf60)[0], 128)
        self.assertEqual(struct.unpack_from("<Q", descriptor, 0xfb2)[0], new["queue_support"])
        self.assertEqual(struct.unpack_from("<Q", high[new["queue_support"]], 0x4c)[0], original["pointers"])
        self.assertEqual(wave["retirement_before"]["pointers"], (255,) * 3)
        self.assertEqual(wave["retirement_after"]["pointers"], (3,) * 3)
        from m1n1.drm_shim import g17g
        self.assertEqual(g17g.parse_queue_priority(high[new["queue"]][:g17g.QUEUE_RECORD_SIZE])["priority"], 3)

    def test_batches_split_only_at_queue_or_twenty_record_scheduler_boundaries(self):
        bounds = ((0x20000, 0x20030),) * 64
        waves = compute_waves(bounds, 120, backend.compute_addresses())
        self.assertEqual([w["final"] for w in waves], [127, 147, 167, 184])
        self.assertEqual([w["recreate"] for w in waves], [False, True, False, False])
        self.assertEqual(waves[2]["previous_addresses"], waves[1]["addresses"])
        after = compute_wave(bounds[:1], 255, waves[-1]["addresses"])
        self.assertEqual(after["retirement_after"]["channel"], (0,) * 3)

    def test_continued_completion_requires_fresh_timestamps_not_next_first_event(self):
        before = {name: bytes(16).hex() for name in ("dispatch_a", "dispatch_b", "status_a", "status_b")}
        before["dispatch_a"] = (struct.pack("<I", 0x100) + bytes(12)).hex()
        before["reports"] = dict(producer=1, consumer=1, records=[])
        before["descriptor_tail"] = bytes(0xe0).hex()
        tail = bytearray(0xe0)
        struct.pack_into("<QQ", tail, 0x2c, 10, 20)
        after = dict(before,
                     status_a=struct.pack("<QQ", 10, 20).hex(),
                     status_b=struct.pack("<QQ", 20, 0).hex(), descriptor_tail=tail.hex(),
                     reports=dict(producer=1, consumer=1, records=[]))
        self.assertEqual(continued_compute_completion(before, after), "complete")
        sampler = struct.pack('<QII',0x200008,2,3)
        initial_tail = bytearray.fromhex(before['descriptor_tail'])
        initial_tail[0x2c:0x3c] = sampler
        sampled_before = dict(before, descriptor_tail=initial_tail.hex(), sampler_input=sampler.hex())
        self.assertEqual(continued_compute_completion(sampled_before,after),'complete')
        with self.assertRaisesRegex(ValueError,'published sampler input'):
            continued_compute_completion(dict(sampled_before,sampler_input=bytes(16).hex()),after)
        clean = (struct.pack("<4I", 1, 1, 0, 0) + bytes(56)).hex()
        resident = (struct.pack('<4I',1,8,0,0)+bytes(56)).hex()
        after['reports'] = dict(producer=2,consumer=1,records=[resident])
        self.assertEqual(continued_compute_completion(before,after,queue_id=3),'complete')
        with self.assertRaisesRegex(ValueError,'unclassified'):
            continued_compute_completion(before,after,queue_id=0)
        after["reports"] = dict(producer=3, consumer=1, records=[clean, clean])
        self.assertEqual(continued_compute_completion(before, after, max_reports=3), "complete")
        with self.assertRaisesRegex(ValueError, "report count"):
            continued_compute_completion(before, after)
        after["status_a"] = bytes(16).hex()
        self.assertIsNone(continued_compute_completion(before, after, max_reports=3))
        after["reports"] = dict(producer=2, consumer=1, records=[
            (struct.pack("<4I", 4, 0, 0, 0xffffffff) + bytes(56)).hex()])
        self.assertEqual(continued_compute_completion(before, after), "fault")
