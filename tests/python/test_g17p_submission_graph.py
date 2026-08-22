# SPDX-License-Identifier: MIT

import os
import pathlib
import hashlib
import struct
import sys
import unittest
from unittest import mock


os.environ.setdefault("AGX_GPU", "G17")

EXPERIMENTS = pathlib.Path(__file__).parents[2] / "proxyclient" / "experiments"
PROXYCLIENT = pathlib.Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(PROXYCLIENT))
sys.path.insert(0, str(EXPERIMENTS))

from m1n1.agx.g17p_backend import G17PPairedWorkBuilder, G17PWorkBuilder
from m1n1.agx.g17p_shim import G17PShimBackend
from m1n1.agx import g17p, g17p_compute, g17p_encoder, g17p_submission
from m1n1.agx.g17p_render import (
    G17PRenderParameters,
    build_render_class4_observed_state,
    build_render_class2_prestate,
    build_render_class4_register_program,
    select_render_class4_registers,
    build_fragment_registers,
    build_fragment_partial_load_registers,
    build_fragment_partial_resume_registers,
    build_fragment_partial_store_registers,
    build_direct_bind0,
    build_direct_bind_group,
    build_tiling_registers,
    build_viewport,
)
import agx_g17p_native_add3 as NATIVE


class G17PSubmissionGraphTests(unittest.TestCase):

    def test_second_compute_uses_an_independent_queue_graph(self):
        startup = NATIVE._queue_addresses(0)
        second = NATIVE._queue_addresses(NATIVE._queue_slot(1))

        self.assertEqual(NATIVE._queue_slot(1), 1)
        for name in (
                "queue", "pointers", "item_ring", "context_low",
                "context_high", "descriptor", "optional", "event"):
            self.assertNotEqual(startup[name], second[name], name)

    def test_nonvirgin_initial_compute_cleans_published_outer_slot(self):
        entry = {
            "ring_addr": NATIVE.OUTER_RING,
            "state_addrs": (0x1000, 0x1010, 0x1020),
        }
        channels = type("Channels", (), {
            "by_name": lambda _self, name: entry if name == "CL_2" else None,
            "counters": lambda _self, _entry: [1, 1, 1],
        })()
        staged = []
        notified = []
        submitter = type("Submitter", (), {
            "stage": lambda _self, *_args, **_kwargs: {
                "slot": 1,
                "producer": 2,
                "write_after": 3,
            },
            "notify": lambda _self, channel: notified.append(channel),
        })()
        backend = type("Backend", (), {
            "channels": channels,
            "submitter": submitter,
            "_clean_dva_range": lambda _self, address, size:
                staged.append((address, size)),
            "u": type("Unit", (), {
                "inst": lambda _self, _instruction: None,
            })(),
        })()
        queue = type("Queue", (), {
            "initial_spec": {
                "descriptor": 0x2000,
                "optional": 0x3000,
                "event": 0x4000,
                "item_ring": 0x5000,
                "pointers": 0x6000,
            },
        })()

        with mock.patch.object(NATIVE, "G17PQueueFence") as fence_class:
            fence_class.return_value.signaled.return_value = False
            NATIVE.stage_built(backend, queue, require_virgin=False)

        self.assertIn(
            (NATIVE.OUTER_RING + g17p.RING_SLOT_SIZE,
             g17p.RING_SLOT_SIZE),
            staged,
        )
        self.assertNotIn(
            (NATIVE.OUTER_RING, g17p.RING_SLOT_SIZE), staged)
        self.assertEqual(notified, [NATIVE.WORK_DOORBELL_CHANNEL])

    def test_queue_priority_profiles_serialize_as_one_field_family(self):
        expected = {
            0: (0, 0, 0xffffffffffff0000, 1, 1),
            1: (1, 1, 0xffffffff00000000, 0, 0),
        }
        for priority, values in expected.items():
            profile = g17p.queue_priority_profile(priority)
            record = g17p.build_queue_record(
                0x1000, 0x2000, 0x3000, 0x4000, **profile)
            actual = (
                struct.unpack_from("<I", record, g17p.QUEUE_PRIORITY)[0],
                struct.unpack_from("<I", record, g17p.QUEUE_UNK_2C)[0],
                struct.unpack_from("<Q", record, g17p.QUEUE_UNK_30)[0],
                struct.unpack_from("<I", record, g17p.QUEUE_UNK_38)[0],
                struct.unpack_from("<I", record, g17p.QUEUE_PRIO5)[0],
            )
            self.assertEqual(actual, values)
            self.assertEqual(
                struct.unpack_from("<i", record, g17p.QUEUE_UNK_44)[0], -1)

        with self.assertRaisesRegex(ValueError, "0..3"):
            g17p.queue_priority_profile(4)

    def test_compact_control_header_is_independent_of_class_selector(self):
        body = g17p_compute.build_compute_compact_control_support(
            2, 0x7000208000, 0, 0xFFFFFC2001600000,
            active=0, resource_class=0x19, cursor=0xB8, final_kind=3,
            header_value=1,
        )
        self.assertEqual(struct.unpack_from("<I", body, 0x00)[0], 1)
        self.assertEqual(struct.unpack_from("<I", body, 0x10)[0], 2)

    def test_paired_pool_selection_wraps_publication_with_descriptor(self):
        # The native partial opening's nineteenth item is the first one whose
        # logical Pool-A record crosses the 35-record physical pool.
        self.assertEqual(
            g17p_submission.paired_item_pool_record_indices(18),
            (1, 18),
        )
        self.assertEqual(
            g17p_submission.paired_item_pool_record_indices(
                18, record_indices=(36, 18)),
            (1, 18),
        )

    def test_explicit_recycled_records_outlive_logical_pool_capacity(self):
        memory = {}
        next_address = 0x100000

        def alloc(size, _name):
            nonlocal next_address
            address = next_address
            next_address += (size + 0xfff) & ~0xfff
            return address

        builder = G17PWorkBuilder(
            alloc, lambda address, body: memory.__setitem__(
                address, bytes(body)), kind="fragment", queue_pair=0)
        builder.build_pools(0x200000, 0x300000, 0x400000)
        descriptor, _support_a, _support_b = builder.item(
            35, (0x500000, 0x510000), (), 0x600000, 0x700000,
            record_indices=(0, 35),
        )
        body = memory[descriptor]
        self.assertEqual(struct.unpack_from("<Q", body, 0x20)[0],
                         builder.array_a)
        self.assertEqual(struct.unpack_from("<Q", body, 0x30)[0],
                         builder.array_b
                         + 35 * g17p_submission.ARRAY_B_STRIDE)

    def test_fragment_builder_preserves_pipeline_register_values(self):
        memory = {}
        next_address = 0x100000

        def alloc(size, _name):
            nonlocal next_address
            address = next_address
            next_address += (size + 0xfff) & ~0xfff
            return address

        def write(address, body):
            memory[address] = bytes(body)

        builder = G17PWorkBuilder(
            alloc, write, kind="fragment", queue_pair=0)
        builder.build_pools(0x200000, 0x300000, 0x400000)
        registers = (
            (0x01739, 1),
            (0x10009, 0xa000),
            (0x15379, 0),
            (0x15381, 0x100001e8480),
            (0x15369, 0xffff800000000040),
            (0x15371, 0x100001e8280),
        )
        descriptor, _support_a, _support_b = builder.item(
            0, (0x500000, 0x510000), registers, 0x600000, 0x700000)
        body = memory[descriptor]

        decoded = tuple(
            struct.unpack_from(
                "<IQ", body,
                g17p_submission.DESCRIPTOR_LAYOUT["fragment"]["registers"]
                + index * g17p_submission.REGISTER_ENTRY_SIZE,
            )
            for index in range(len(registers))
        )
        self.assertEqual(decoded, registers)
        self.assertEqual(body[0xc8], 0x80)
        self.assertEqual(body[0xe0], 0x80)

    def test_pair2_status_bases_match_executing_partial_capture(self):
        self.assertEqual(
            G17PWorkBuilder.PAIR_STATUS_BASES["tiling"][2],
            0xFFFFFC2001690000,
        )
        self.assertEqual(
            G17PWorkBuilder.PAIR_STATUS_BASES["fragment"][2],
            0xFFFFFC20016B0000,
        )
        self.assertNotEqual(
            G17PWorkBuilder.PAIR_STATUS_BASES["fragment"][2],
            0xFFFFFC2001698000,
        )

    def test_pair2_next_descriptor_advances_local_identity(self):
        body = g17p_submission.build_descriptor(
            "tiling",
            (0x1000, 0x2000, 0x3000, 0x4000),
            (),
            size=0x9C0,
            submit_sequence=3,
            context_id=3,
            submission_ordinal=1,
            queue_pair=2,
        )

        self.assertEqual(struct.unpack_from("<Q", body, 0x04)[0], 3)
        self.assertEqual(struct.unpack_from("<I", body, 0x18)[0], 2)
        self.assertEqual(struct.unpack_from("<I", body, 0x48)[0], 1)
        self.assertEqual(struct.unpack_from("<I", body, 0x304)[0], 2)
        for offset in (0x370, 0x37C, 0x388):
            self.assertEqual(struct.unpack_from("<I", body, offset)[0], 0x301)

    def test_descriptor_tail_uses_actual_noncanonical_queue_grids(self):
        memory = {}
        next_address = 0x100000

        def alloc(size, _name):
            nonlocal next_address
            address = next_address
            next_address += (size + 0xfff) & ~0xfff
            return address

        def write(address, body):
            memory[address] = bytes(body)

        builder = G17PPairedWorkBuilder(alloc, write, queue_pair=0)
        builder.build_submission_graph()
        builder.tiling.write_item_fields = True
        builder.fragment.write_item_fields = True
        optional = {
            "context_scratch": 0x7000000000,
            "firmware_scratch": 0xFFFFFC2000200000,
            "shared_control": 0xFFFFFC20C0800000,
            "channel_control": 0xFFFFFC20C07B8000,
        }
        pair = builder.item(
            0,
            None,
            (),
            (),
            optional,
            optional,
            context_id=3,
            queue_pair=0,
            queue_grid_pair=(9, 10),
        )

        tiling = memory[pair["tiling"][0]]
        fragment = memory[pair["fragment"][0]]
        tiling_optional = memory[pair["tiling"][1]]
        fragment_optional = memory[pair["fragment"][1]]
        self.assertEqual(struct.unpack_from("<I", tiling, 0x08BA)[0], 9)
        self.assertEqual(struct.unpack_from("<I", tiling, 0x079C)[0], 10)
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2154)[0], 10)
        self.assertEqual(struct.unpack_from("<H", tiling_optional, 0x18)[0], 9)
        self.assertEqual(struct.unpack_from("<H", fragment_optional, 0x18)[0], 10)

    def test_optional_queue_ordinal_is_independent_of_graph_ordinal(self):
        memory = {}
        next_address = 0x100000

        def alloc(size, _name):
            nonlocal next_address
            address = next_address
            next_address += (size + 0xfff) & ~0xfff
            return address

        def write(address, body):
            memory[address] = bytes(body)

        builder = G17PPairedWorkBuilder(alloc, write, queue_pair=1)
        builder.build_submission_graph()
        optional = {
            "context_scratch": 0x7000000000,
            "firmware_scratch": 0xFFFFFC2000200000,
            "shared_control": 0xFFFFFC20C0800000,
            "channel_control": 0xFFFFFC20C07B8000,
        }
        pair = builder.item(
            0,
            None,
            (),
            (),
            optional,
            optional,
            context_id=1,
            queue_pair=1,
            queue_grid_pair=(0, 1),
            optional_item_index=1,
        )

        for kind in ("tiling", "fragment"):
            body = memory[pair[kind][1]]
            self.assertEqual(struct.unpack_from("<H", body, 0x2a)[0], 1)
            self.assertEqual(struct.unpack_from("<H", body, 0x2e)[0], 0x100)
            for offset in (0x1a, 0x52, 0x62):
                self.assertEqual(struct.unpack_from("<H", body, offset)[0], 0)

    def test_native_context4_graph_does_not_alias_class4_control(self):
        graph = {
            name: (address, size)
            for name, address, size in G17PShimBackend.MUX_PAIR4_GRAPH
        }
        self.assertEqual(
            graph["submission_primary_index"],
            (0xFFFFFC20C09A8000, 0x4000),
        )
        self.assertNotEqual(
            graph["submission_primary_index"][0],
            G17PShimBackend.NATIVE_PAIR4_SHARED_CONTROL,
        )
        self.assertEqual(
            graph["descriptor_shared_object"],
            (0xFFFFFC20C0940000, 0x88),
        )

    def test_shared_object_carries_pair_local_primary_index_low_alias(self):
        high = 0xFFFFFC20C0668000
        body = g17p_submission.build_shared_object(
            (high, 0xFFFFFC20C066C000, 0xFFFFFC20C0670000,
             0xFFFFFC20C0674000),
            pair_index=3,
        )

        self.assertEqual(struct.unpack_from("<Q", body, 0x20)[0], high)
        self.assertEqual(
            struct.unpack_from("<Q", body, 0x28)[0], 0x1001330000)

    def test_native_context4_tiling_optional_record(self):
        body = g17p_submission.build_optional_item(
            "tiling",
            0x70005F0000,
            0xFFFFFC2000390000,
            0xFFFFFC20C0928000,
            0xFFFFFC20C07B8100,
            tiling_shared_object=0xFFFFFC20C0940000,
            grid_index=11,
            submission_ordinal=0x93D,
            context_id=4,
            uuid=0x197,
            scheduler_class=2,
            queue_context_index=2,
            queue_context_phase=0,
            first_record=True,
            lifecycle_ordinal=0x96F,
            queue_namespace=4,
        )

        self.assertEqual(struct.unpack_from("<I", body, 0)[0], 0x0F)
        self.assertEqual(struct.unpack_from("<2Q", body, 0x08), (
            0x70005F0000, 0xFFFFFC2000390000))
        self.assertEqual(struct.unpack_from("<Q", body, 0x36)[0],
                         0xFFFFFC20C0928000)
        self.assertEqual(struct.unpack_from("<Q", body, 0x4A)[0],
                         0xFFFFFC20C07B8100)
        self.assertEqual(struct.unpack_from("<Q", body, 0x6E)[0],
                         0xFFFFFC20C0940000)
        expected_u16 = {
            0x18: 11, 0x1A: 1, 0x1E: 2, 0x26: 1,
            0x2A: 2, 0x2E: 0, 0x32: 4, 0x3E: 0x93D,
            0x46: 2, 0x52: 1, 0x56: 4, 0x5A: 0x197, 0x5E: 2,
            0x62: 1, 0x66: 1, 0x76: 0x96F, 0x7E: 4, 0x82: 12,
        }
        self.assertEqual(
            {offset: struct.unpack_from("<H", body, offset)[0]
             for offset in expected_u16},
            expected_u16,
        )

    def test_native_context4_queue_context_records(self):
        tiling = g17p_submission.build_queue_context_item(
            "tiling",
            descriptor=0xFFFFFC20C00447C0,
            queue=0xFFFFFC20C0000840,
            pair=4,
            item_index=2,
            context_id=4,
            grid_index=11,
        )
        fragment = g17p_submission.build_queue_context_item(
            "fragment",
            descriptor=0xFFFFFC20C01DFF80,
            queue=0xFFFFFC20C0000900,
            pair=4,
            item_index=0,
            context_id=4,
            grid_index=12,
        )

        def words(body):
            return {
                offset: struct.unpack_from(
                    "<Q", body,
                    offset - g17p_submission.QUEUE_CONTEXT_ITEM_BASE)[0]
                for offset in range(0x200, 0x380, 8)
                if struct.unpack_from(
                    "<Q", body,
                    offset - g17p_submission.QUEUE_CONTEXT_ITEM_BASE)[0]
            }

        self.assertEqual(words(tiling), {
            0x200: 0x10002C000000000C,
            0x210: 0xFFFFFC20C00447C0,
            0x218: 0xFFFFFC20C0000840,
            0x220: 0xFFFF0C0400000001,
            0x228: 0x00000B0000000002,
            0x350: 0x0002380380001641,
            0x378: 0x003FFFFFFFFFFFFF,
        })
        self.assertEqual(words(fragment), {
            0x200: 0x1000300000000004,
            0x210: 0xFFFFFC20C01DFF80,
            0x218: 0xFFFFFC20C0000900,
            0x220: 0xFFFF180400000003,
            0x228: 0x00000B0000000003,
            0x230: 0x00000C0000000000,
            0x350: 0x0002B0038000E401,
            0x358: 0x000080038000E43A,
            0x360: 0x0000B8038000E473,
            0x368: 0x000050038000E4AC,
            0x378: 0x003FFFFFFFFFFFFF,
        })

    def test_optional_u16_overrides_split_native_identity_fields(self):
        body = g17p_submission.build_optional_item(
            "fragment",
            0x7000500000,
            0xFFFFFC20002A0000,
            0xFFFFFC20C08D0000,
            0xFFFFFC20C07B80C0,
            grid_index=5,
            submission_ordinal=0x25,
            context_id=3,
            uuid=0x186,
            scheduler_class=2,
            u16_overrides={0x46: 1, 0x56: 2},
        )

        self.assertEqual(struct.unpack_from("<H", body, 0x32)[0], 3)
        self.assertEqual(struct.unpack_from("<H", body, 0x46)[0], 1)
        self.assertEqual(struct.unpack_from("<H", body, 0x56)[0], 2)
        self.assertEqual(struct.unpack_from("<H", body, 0x5E)[0], 2)

    def test_partial_pair2_queue_context_splits_graph_and_locator_contexts(self):
        body = g17p_submission.build_queue_context_item(
            "fragment",
            descriptor=0xFFFFFC20C0107C40,
            queue=0xFFFFFC20C00003C0,
            pair=2,
            item_index=0,
            context_id=2,
            grid_index=5,
            locator_context_id=3,
        )

        def word(offset):
            return struct.unpack_from(
                "<Q", body,
                offset - g17p_submission.QUEUE_CONTEXT_ITEM_BASE)[0]

        self.assertEqual(word(0x220), 0xFFFF180200000003)
        self.assertEqual(word(0x228), 0x0000040000000001)
        self.assertEqual(word(0x230), 0x0000050000000000)
        self.assertEqual(word(0x350), 0x0002B003800077E7)
        self.assertEqual(word(0x358), 0x0000800380007820)
        self.assertEqual(word(0x360), 0x0000B80380007859)
        self.assertEqual(word(0x368), 0x0000500380007892)

    def test_pair1_index_extents_cover_native_firmware_growth(self):
        graph = {
            name: (address, size)
            for name, address, size in G17PShimBackend.MUX_PAIR1_GRAPH
        }
        self.assertEqual(
            graph["submission_primary_index"],
            (0xFFFFFC20C0888000, 4 * g17p_submission.FIRMWARE_PAGE_SIZE),
        )
        self.assertEqual(
            graph["submission_secondary_index"],
            (0xFFFFFC20C0878000, 2 * g17p_submission.FIRMWARE_PAGE_SIZE),
        )

    def test_partial_opening_rebinds_first_scheduler_owner(self):
        backend = object.__new__(G17PShimBackend)
        backend.native_partial_opening_queue_applied = False
        writes = {}
        cleans = []
        backend._write_dva = lambda address, body: writes.__setitem__(
            address, bytes(body))
        backend._clean_dva_range = lambda address, size: cleans.append(
            (address, size))
        backend.u = type("Unit", (), {"inst": lambda _self, _op: None})()

        def queue(address):
            return type("Queue", (), {
                "address": address,
                "job_list_addr": 0xFFFFFC2000000018,
                "record": {
                    "job_list_addr": 0xFFFFFC2000000018,
                    "uuid": 0xA6,
                    "context_addr": 0xFFFFFC20C07B8040,
                },
            })()

        tiling = queue(0xFFFFFC20C0000000)
        fragment = queue(0xFFFFFC20C00000C0)
        backend._apply_native_partial_opening_queue({
            "tiling": (None, tiling),
            "fragment": (None, fragment),
        })

        expected_head = G17PShimBackend.NATIVE_PARTIAL_OPENING_JOB_LIST
        expected_control = G17PShimBackend.CHANNEL_CONTROL_BASE
        self.assertEqual(writes[expected_head],
                         g17p.build_job_list(expected_head))
        for item in (tiling, fragment):
            self.assertEqual(item.job_list_addr, expected_head)
            self.assertEqual(item.record["job_list_addr"], expected_head)
            self.assertEqual(item.record["uuid"], 0xAC)
            self.assertEqual(item.record["context_addr"], expected_control)
            self.assertEqual(
                writes[item.address + g17p.QUEUE_JOB_LIST_ADDR],
                struct.pack("<Q", expected_head),
            )
            self.assertEqual(
                writes[item.address + g17p.QUEUE_CONTEXT_ADDR],
                struct.pack("<Q", expected_control),
            )
            self.assertEqual(
                writes[item.address + g17p.QUEUE_UUID],
                struct.pack("<I", 0xAC),
            )
        self.assertIn((expected_head, g17p.JOB_LIST_SIZE), cleans)
        self.assertTrue(backend.native_partial_opening_queue_applied)

    def test_fixed_queue_second_context_uses_descriptor_locators(self):
        tiling = g17p_submission.build_queue_context_item(
            "tiling",
            descriptor=0xFFFFFC20C00189C0,
            queue=0xFFFFFC20C0000000,
            pair=0,
            item_index=1,
            context_id=1,
            grid_index=0,
        )
        fragment = g17p_submission.build_queue_context_item(
            "fragment",
            descriptor=0xFFFFFC20C00B2240,
            queue=0xFFFFFC20C00000C0,
            pair=0,
            item_index=1,
            context_id=1,
            grid_index=1,
        )

        def word(body, offset):
            return struct.unpack_from(
                "<Q", body,
                offset - g17p_submission.QUEUE_CONTEXT_ITEM_BASE)[0]

        # Queue-local state still describes item one on fixed grids 0/1.
        self.assertEqual(word(tiling, 0x200), 8)
        self.assertEqual(word(tiling, 0x228), 1)
        self.assertEqual(word(fragment, 0x200), 0x0400040000000008)
        self.assertEqual(word(fragment, 0x228), 2)
        self.assertEqual(word(fragment, 0x230), 0x0000010000000001)

        # The locator family independently names descriptor array slot one.
        self.assertEqual(word(tiling, 0x350), 0x0002380380000051)
        self.assertEqual(word(fragment, 0x208), 0x000000E0001351C0)
        self.assertEqual(word(fragment, 0x350), 0x0002B00380004D17)
        self.assertEqual(word(fragment, 0x358), 0x0000100380004D50)
        self.assertEqual(word(fragment, 0x360), 0x0000100380004D89)
        self.assertEqual(word(fragment, 0x368), 0x0000100380004DC2)

    def test_partial_pair2_graph_profile_has_exact_source_built_objects(self):
        graph = {
            name: (address, size)
            for name, address, size in G17PShimBackend.PARTIAL_PAIR2_GRAPH
        }
        self.assertEqual(graph["submission_primary_index"],
                         (0xFFFFFC20C08F0000, 0x4000))
        self.assertEqual(graph["submission_secondary_index"],
                         (0xFFFFFC20C08E0000, 0x4000))
        self.assertEqual(graph["record_pool_a"],
                         (0xFFFFFC20C08C8100, 0x2300))
        self.assertEqual(graph["record_pool_b"],
                         (0xFFFFFC20C08D8080, 0x2780))
        self.assertEqual(graph["descriptor_shared_object"],
                         (0xFFFFFC20C0908000, 0x88))

        leaves = g17p_submission.build_context2_submission_leaf_pages()
        hashes = {
            name: hashlib.sha256(body).hexdigest()
            for name, body in leaves.items()
        }
        self.assertEqual(hashes, {
            "primary_index":
                "11b047ecdea25a84ea6348d103833685fd6824a98a269409cef0c84c311520d4",
            "secondary_index":
                "5530984935f2ae2c166854c7ef1a07973450b9531ca66cc48b0196ef2e21c9e3",
            "pool_a_slots":
                "06eb5fea361a9acf8caae80e1f114716229f000f2bae78ee47e370a1c6058069",
            "pool_b_slots":
                "4fe7b59af6de3b665b67788cc2f99892ab827efae3a467342b3bb4e3bc8e5bfe",
            "shared_slots":
                "e0ecafa4083395c4c3503b7c1ea85c30bff56e4161dda6ebc593863fdc684461",
            "flag":
                "dfc53015b39cdf85a8eec8608cd7413330a8e260e8954bc315aedd85bd8954a0",
        })

        table = g17p_submission.build_partial_operand_table(0x7000220000)
        self.assertEqual(len(table), 0x4000)
        self.assertEqual(struct.unpack_from("<Q", table, 0)[0],
                         0x1000007000220000)
        self.assertEqual(struct.unpack_from("<Q", table, 27 * 0x40)[0],
                         0x1000007001df8000)
        self.assertFalse(any(table[28 * 0x40:]))

        directory = g17p_submission.build_partial_operand_page_directory(
            0x7000220000)
        self.assertEqual(len(directory), 4 * 0x4000)
        pointers = struct.unpack_from("<7168Q", directory)
        self.assertEqual(pointers[0], 0x7000220000)
        self.assertEqual(pointers[255], 0x700031f000)
        self.assertEqual(pointers[256], 0x7000328000)
        self.assertEqual(pointers[-1], 0x7001ef7000)
        self.assertFalse(any(directory[7168 * 8:]))

    def test_render_class4_observed_state_matches_native_layout(self):
        table = 0x7000208000
        state = 0xFFFFFC2001680000
        body = build_render_class4_observed_state(
            table, state, context_word=1)

        self.assertEqual(len(body), 0x70)
        self.assertEqual(struct.unpack_from("<I", body, 0x00)[0], 6)
        self.assertEqual(struct.unpack_from("<I", body, 0x08)[0], 1)
        self.assertEqual(struct.unpack_from("<I", body, 0x10)[0], 2)
        self.assertEqual(
            struct.unpack_from("<4Q", body, 0x18),
            (0x0004000000000070, 0x0000160000000000,
             0x0000160000000000, table),
        )
        self.assertEqual(struct.unpack_from("<II", body, 0x40), (4, 1))
        self.assertEqual(struct.unpack_from("<I", body, 0x48)[0], 0xB0)
        self.assertEqual(struct.unpack_from("<Q", body, 0x4C)[0], state)
        self.assertEqual(struct.unpack_from("<I", body, 0x60)[0], 3)

    def test_render_class2_prestate_matches_native_predecessor_layout(self):
        body = build_render_class2_prestate(
            0x7000940000, 0xfffffc2001680000,
            0x7000738000, context_word=3)
        self.assertEqual(len(body), 0x70)
        self.assertEqual(struct.unpack_from("<I", body, 0x00)[0], 2)
        self.assertEqual(struct.unpack_from("<I", body, 0x08)[0], 3)
        self.assertEqual(struct.unpack_from("<I", body, 0x14)[0], 0x738000)
        self.assertEqual(
            struct.unpack_from("<Q", body, 0x30)[0], 0x7000940000)
        self.assertEqual(struct.unpack_from("<I", body, 0x48)[0], 0xb8)
        self.assertEqual(
            struct.unpack_from("<Q", body, 0x4c)[0],
            0xfffffc2001680000)
        self.assertFalse(any(body[0x64:]))

    def test_render_class4_program_selects_contiguous_fragment_writes(self):
        from m1n1.agx.g17p_render import RENDER_CLASS4_REGISTER_NUMBERS

        values = tuple(
            (number, 0x1000000000000000 + index)
            for index, number in enumerate(RENDER_CLASS4_REGISTER_NUMBERS)
        )
        fragment = ((0xDEAD, 1),) + values + ((0xBEEF, 2),)
        self.assertEqual(select_render_class4_registers(fragment), values)
        encoded = build_render_class4_register_program(fragment)
        self.assertEqual(len(encoded), 32 * 12)
        self.assertEqual(
            tuple(struct.unpack_from("<IQ", encoded, index * 12)
                  for index in range(32)),
            values,
        )
        with self.assertRaisesRegex(ValueError, "no complete class-4"):
            select_render_class4_registers(values[:-1])

    def test_direct_render_encoder_matches_coherent_native_triangle(self):
        context_base = 0x1000000000
        params = g17p_encoder.G17PEncoderParameters(
            context_base=context_base,
            binds=[
                g17p_encoder.G17PBindPair(context_base + offset, control)
                for offset, control in (
                    (0x40, 0x700),
                    (0x58000, 0x500),
                    (0x5801c, 0x700),
                    (0x58030, 0x500),
                    (0x5804c, 0xa00),
                    (0x68900, 0x300),
                    (0x58060, 0x200),
                    (0x5806c, 0x200),
                )
            ],
            draw_state=context_base + 0x48000,
            vertex_count=3,
            instance_count=1,
            opcode=g17p_encoder.DRAW_OPCODE_DIRECT,
            header_state=0x4a00,
            header_class=0x404,
        )
        expected_words = (
            0x4000002e, 0, 0x01000000, 0x4a00,
            0x404, 0, 0, 0x500,
            0x40, 0x700, 0x58000, 0x500,
            0x5801c, 0x700, 0x58030, 0x500,
            0x5804c, 0xa00, 0x68900, 0x300,
            0x58060, 0x200, 0x5806c, 0x200,
            0x48000, 0x61c40600, 3, 1,
            0, 0xc0000000, 0, 0,
            0, 0, 0,
        )
        expected = struct.pack("<%dI" % len(expected_words), *expected_words)

        stream = g17p_encoder.build_encoder(params)
        self.assertEqual(len(stream), g17p_encoder.ENCODER_SIZE)
        self.assertEqual(stream, expected)

        parsed = g17p_encoder.parse_encoder(stream, context_base)
        self.assertEqual(parsed.opcode, g17p_encoder.DRAW_OPCODE_DIRECT)
        self.assertEqual(parsed.draw_state, context_base + 0x48000)
        self.assertEqual(parsed.vertex_count, 3)
        self.assertEqual(parsed.instance_count, 1)
        self.assertEqual(parsed.vertex_start, 0)
        self.assertEqual(parsed.primitive, g17p_encoder.PRIMITIVE_TRIANGLE)
        self.assertEqual(g17p_encoder.build_encoder(parsed), expected)

    def test_direct_render_bind_profiles_patch_only_measured_words(self):
        from m1n1.agx.g17p_render import build_bind0, build_bind_group

        cases = (
            (build_bind0(), build_direct_bind0(), {
                0x2c8: 0, 0x300: 0xfcc0, 0x340: 0,
                0x344: 0, 0x348: 0, 0x380: 0,
            }),
            (build_bind_group(), build_direct_bind_group(), {
                0x04: 0, 0x08: 0, 0x14: 0x4e19,
                0x20: 0, 0x2c: 4, 0x5c: 0x1ffff,
            }),
        )
        for baseline, direct, expected in cases:
            changed_words = {
                offset: struct.unpack_from("<I", direct, offset)[0]
                for offset in range(0, len(direct), 4)
                if direct[offset:offset + 4] != baseline[offset:offset + 4]
            }
            self.assertEqual(changed_words, expected)

    def test_indirect_runtime_cannot_skip_command_local_optional(self):
        with self.assertRaisesRegex(ValueError, "command-local optional"):
            NATIVE.stage_next_workload(
                None,
                {"indirect_dispatch": True},
                None,
                1,
                persistent_runtime_optional_once=True,
            )

    def test_compute_user_timestamp_pointer_offsets(self):
        registers = [
            (0x1A510, 0x10000000000),
            (0x1A420, 0x10000004000),
            (0x1A540, 0x10000000001),
            (0x1A440, 0),
            (0x0A5C1, 1),
            (0x0A5C9, 2),
            (0x10099, 3),
            (0x10091, 4),
        ]
        body = g17p_compute.build_compute_descriptor(
            registers,
            scheduler_record=0xFFFFFC2000004000,
            low_alias=0x7000000000,
            cdm_terminator=0x10000004000,
            user_timestamp_start=0xFFFFFC2181400010,
            user_timestamp_end=0xFFFFFC2181400018,
        )
        self.assertEqual(
            struct.unpack_from("<2Q", body, 0xF8C),
            (0xFFFFFC2181400010, 0xFFFFFC2181400018),
        )

    def test_compute_uapi_register_overlay_is_ordered_and_counted(self):
        base = (
            (0x1A510, 0x10000000000),
            (0x1A420, 0x10000004000),
            (0x1A4D0, 0x10000001480),
            (0x1A4D8, 0x10000001488),
            (0x1A4E0, 0x10000001490),
            (0x1A4E8, 0x10000001498),
            (0x1A440, 0x24201),
            (0x1A540, 0x10000000001),
            (0x10099, 0x7000000000),
            (0x10091, 0x7000004000),
            (0x0A5C1, 0x7000008000),
            (0x0A5C9, 0x700000C000),
        )
        registers = g17p_compute.apply_compute_uapi_registers(
            base,
            preempt_base=0x20000000000,
            cdm_base=0x10000100000,
            usc_exec_base=0x10000000000,
            helper_binary=0x4001,
            helper_data=0x10000200000,
            helper_cfg=0x10000,
        )
        self.assertEqual(registers[6:10], (
            (0x10071, 0x10000000000),
            (0x11841, 0x4001),
            (0x11849, 0x10000200000),
            (0x11F81, 0x10000),
        ))
        self.assertEqual(registers[0], (0x1A510, 0x20000000000))
        self.assertEqual(registers[5], (0x1A4E8, 0x20000001498))

        body = g17p_compute.build_compute_descriptor(
            registers,
            scheduler_record=0xFFFFFC2000000000,
            low_alias=0x7000000000,
            cdm_terminator=0x10000100000,
        )
        packed_count = struct.unpack_from(
            "<I", body, g17p_compute.COMPUTE_PRIMARY_COUNT)[0]
        self.assertEqual(packed_count & 0xffff, len(registers))
        self.assertEqual(
            packed_count >> 16,
            len(registers) * g17p_compute.COMPUTE_REGISTER_SIZE,
        )

    def test_compute_sampler_encoder_parameters(self):
        registers = [
            (0x1A510, 0x10000000000),
            (0x1A420, 0x10000004000),
            (0x1A540, 0x10000000001),
            (0x1A440, 0),
            (0x0A5C1, 1),
            (0x0A5C9, 2),
            (0x10099, 3),
            (0x10091, 4),
        ]
        body = g17p_compute.build_compute_descriptor(
            registers,
            scheduler_record=0xFFFFFC2000000000,
            low_alias=0x7000000000,
            cdm_terminator=0x10000004000,
            sampler_array=0x10000020000,
            sampler_count=4,
        )
        self.assertEqual(
            struct.unpack_from("<QII", body, 0xF2C),
            (0x10000020000, 4, 5),
        )

    def test_compute_sampler_encoder_parameters_validate_pair(self):
        registers = [
            (0x1A510, 0x10000000000),
            (0x1A420, 0x10000004000),
            (0x1A540, 0x10000000001),
            (0x1A440, 0),
            (0x0A5C1, 1),
            (0x0A5C9, 2),
            (0x10099, 3),
            (0x10091, 4),
        ]
        with self.assertRaisesRegex(ValueError, "both be zero or nonzero"):
            g17p_compute.build_compute_descriptor(
                registers,
                scheduler_record=0xFFFFFC2000000000,
                low_alias=0x7000000000,
                cdm_terminator=0x10000004000,
                sampler_array=0x10000020000,
            )

    def test_compute_register_program_carries_all_queue_state(self):
        registers = g17p_compute.build_compute_register_program(
            preempt_base=0x2fff0000000,
            cdm_base=0x10002000000,
            dispatch_identity=0x0200021D0300023F,
            context_id=3,
            work_ordinal=7,
            robustness=0x2fff0010000,
            operand_state_base=0x2fff0020000,
            usc_exec_base=0x10000000000,
            helper_binary=0x4081,
            helper_data=0x10003000000,
            helper_cfg=0x40,
            execution_gate=1,
        )

        self.assertEqual(len(registers), 40)
        self.assertEqual(registers[:10], (
            (0x1A510, 0x2fff0000000),
            (0x1A420, 0x10002000000),
            (0x1A4D0, 0x2fff0001480),
            (0x1A4D8, 0x2fff0001488),
            (0x1A4E0, 0x2fff0001490),
            (0x1A4E8, 0x2fff0001498),
            (0x10071, 0x10000000000),
            (0x11841, 0x4081),
            (0x11849, 0x10003000000),
            (0x11F81, 0x40),
        ))
        self.assertEqual(
            g17p_compute.register_value(registers, 0x10201), 0x307)
        self.assertEqual(
            g17p_compute.register_value(registers, 0x10229),
            0x2fff0032800)

    def test_render_user_timestamp_pointer_offsets(self):
        values = {
            "ta_user_timestamp_start": 0x1111222233334444,
            "ta_user_timestamp_end": 0x5555666677778888,
            "fragment_user_timestamp_start": 0x9999aaaabbbbcccc,
            "fragment_user_timestamp_end": 0xddddeeeeffff0000,
        }
        parameters = G17PRenderParameters(
            width=1, height=1, context_base=0,
            tilemap=0, heapmeta=0, tpc=0,
            deflake_1=0, deflake_2=0, deflake_3=0,
            encoder=0, ta_status=0,
            store_pipeline_bind=0, store_pipeline=0,
            load_pipeline_bind=0, load_pipeline=0,
            scissor_array=0, depth_bias_array=0, aux_fb=0,
            fragment_status=0, **values)

        tiling = bytearray(G17PWorkBuilder.BODY_STRIDE["tiling"])
        G17PWorkBuilder(None, None, kind="tiling")._write_structural_tail(
            tiling, parameters, {0x10111: 0})
        fragment = bytearray(G17PWorkBuilder.BODY_STRIDE["fragment"])
        G17PWorkBuilder(None, None, kind="fragment")._write_structural_tail(
            fragment, parameters, {})

        self.assertEqual(struct.unpack_from("<QQ", tiling, 0x090e), (
            values["ta_user_timestamp_start"],
            values["ta_user_timestamp_end"],
        ))
        self.assertEqual(struct.unpack_from("<QQ", fragment, 0x21a8), (
            values["fragment_user_timestamp_start"],
            values["fragment_user_timestamp_end"],
        ))

    def test_render_item_tail_fields_are_index_derived(self):
        tiling = bytearray(G17PWorkBuilder.BODY_STRIDE["tiling"])
        G17PWorkBuilder(None, None, kind="tiling")._write_item_tail_fields(
            tiling, 0, 2
        )
        self.assertEqual(struct.unpack_from("<II", tiling, 0x79c), (5, 0x100))
        self.assertEqual(struct.unpack_from("<I", tiling, 0x7a8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", tiling, 0x7b0)[0], 0x101)
        self.assertEqual(struct.unpack_from("<I", tiling, 0x8c0)[0], 0)

        fragment = bytearray(G17PWorkBuilder.BODY_STRIDE["fragment"])
        G17PWorkBuilder(None, None, kind="fragment")._write_item_tail_fields(
            fragment, 3, 2
        )
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2150)[0], 0x400)
        self.assertEqual(struct.unpack_from("<III", fragment, 0x215c), (
            1, 4, 0x400,
        ))
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2170)[0], 3)

    def test_render_partial_pipeline_tail_offsets(self):
        parameters = G17PRenderParameters(
            width=1, height=1, context_base=0,
            tilemap=0, heapmeta=0, tpc=0x90,
            deflake_1=0, deflake_2=0, deflake_3=0,
            encoder=0, ta_status=0,
            store_pipeline_bind=0x10, store_pipeline=0x20,
            load_pipeline_bind=0x30, load_pipeline=0x40,
            partial_load_pipeline_bind=0x50,
            partial_load_pipeline=0x60,
            partial_store_pipeline_bind=0x70,
            partial_store_pipeline=0x80,
            scissor_array=0, depth_bias_array=0, aux_fb=0,
            fragment_status=0,
        )
        tiling = bytearray(G17PWorkBuilder.BODY_STRIDE["tiling"])
        G17PWorkBuilder(None, None, kind="tiling")._write_structural_tail(
            tiling, parameters, {0x10111: 0}
        )
        self.assertEqual(struct.unpack_from("<Q", tiling, 0x0780)[0], 0x90)

        fragment = bytearray(G17PWorkBuilder.BODY_STRIDE["fragment"])
        G17PWorkBuilder(None, None, kind="fragment")._write_structural_tail(
            fragment, parameters, {}
        )
        self.assertEqual(fragment[0x2100], 0)
        self.assertEqual(fragment[0x2124], 1)
        self.assertEqual(struct.unpack_from("<QQ", fragment, 0x1e78), (
            0x30, 0x40,
        ))
        self.assertEqual(struct.unpack_from("<QQ", fragment, 0x1ea8), (
            0x50, 0x60,
        ))
        self.assertEqual(struct.unpack_from("<I", fragment, 0x1f78)[0], 0x10)
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x1f7c)[0], 0x20)
        self.assertEqual(struct.unpack_from("<I", fragment, 0x1f98)[0], 0x70)
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x1f9c)[0], 0x80)
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x1fac)[0],
            0x1000000300,
        )

        programs = (
            (0x0ec8, 0x07c0,
             build_fragment_partial_store_registers(parameters)),
            (0x15e8, 0x0ee0,
             build_fragment_partial_resume_registers(parameters)),
            (0x1d08, 0x1600,
             build_fragment_partial_load_registers(parameters)),
        )
        for header_offset, program_offset, expected in programs:
            encoded_size, count = divmod(
                struct.unpack_from("<I", fragment, header_offset)[0],
                1 << 16,
            )
            self.assertEqual(count, len(expected))
            self.assertEqual(encoded_size, len(expected) * 12)
            self.assertEqual(
                tuple(struct.unpack_from(
                    "<IQ", fragment, program_offset + index * 12)
                    for index in range(count)),
                tuple(expected),
            )

    def test_render_uapi_geometry_and_register_overlay(self):
        parameters = G17PRenderParameters(
            width=64, height=64, context_base=0,
            tilemap=0x10000, heapmeta=0x20000, tpc=0x30000,
            deflake_1=0x40000, deflake_2=0x50000,
            deflake_3=0x60000, encoder=0x70000, ta_status=0x80000,
            store_pipeline_bind=0x11, store_pipeline=0x22,
            load_pipeline_bind=0x33, load_pipeline=0x44,
            scissor_array=0x90000, depth_bias_array=0xa0000,
            aux_fb=0xb0000, fragment_status=0xc0000,
            layers=3, utile_width=16, utile_height=16,
            samples=4, sample_size=8, utile_config=0x5002,
            multisample_control=0x1234, ppp_control=0x5678,
            tib_blocks=16, tile_config=0x10281,
            occlusion_query_base=0xd0000,
            depth_buffer=0xe0000, depth_aux_buffer=0xf0000,
            depth_stride=0x1000, depth_aux_stride=0x200,
            stencil_buffer=0x100000, stencil_aux_buffer=0x110000,
            stencil_stride=0x800, stencil_aux_stride=0x100,
            depth_flags=0x123456789,
            depth_dimensions=0x44556677,
            depth_clear_value_bits=0x3f000000,
            stencil_clear_value=0x5a,
            merge_upper_x_bits=0x11111111,
            merge_upper_y_bits=0x22222222,
            emit_uapi_fields=True,
        )

        tiling = dict(build_tiling_registers(parameters))
        fragment = dict(build_fragment_registers(parameters))

        self.assertEqual(tiling[0x1c0b1], 80)
        self.assertEqual(tiling[0x1c0a9], 128)
        self.assertEqual(tiling[0x10169], 0xe002)
        self.assertEqual(fragment[0x100b1], 0x80008)
        self.assertEqual(fragment[0x15131], 0x11111111)
        self.assertEqual(fragment[0x15139], 0x22222222)
        self.assertEqual(fragment[0x15311], 0xd0000)
        self.assertEqual(fragment[0x15401], 0x1000)
        self.assertEqual(fragment[0x15411], 0x200)
        self.assertEqual(fragment[0x15409], 0x800)
        self.assertEqual(fragment[0x15419], 0x100)

    def test_fragment_tail_tib_capacity_scalar(self):
        for tib_blocks, expected in (
            (4, 0x0800000300),
            (8, 0x1000000300),
            (16, 0x2000000300),
        ):
            parameters = G17PRenderParameters(
                width=1, height=1, context_base=0,
                tilemap=0, heapmeta=0, tpc=0,
                deflake_1=0, deflake_2=0, deflake_3=0,
                encoder=0, ta_status=0,
                store_pipeline_bind=0, store_pipeline=0,
                load_pipeline_bind=0, load_pipeline=0,
                scissor_array=0, depth_bias_array=0, aux_fb=0,
                fragment_status=0, tib_blocks=tib_blocks,
            )
            fragment = bytearray(
                G17PWorkBuilder.BODY_STRIDE["fragment"])
            G17PWorkBuilder(
                None, None, kind="fragment")._write_structural_tail(
                    fragment, parameters, {})
            self.assertEqual(
                struct.unpack_from("<Q", fragment, 0x1fac)[0], expected)

    def test_render_pair3_uses_measured_recycled_status_slots(self):
        parameters = G17PRenderParameters(
            width=1, height=1, context_base=0,
            tilemap=0, heapmeta=0, tpc=0,
            deflake_1=0, deflake_2=0, deflake_3=0,
            encoder=0, ta_status=0,
            store_pipeline_bind=0, store_pipeline=0,
            load_pipeline_bind=0, load_pipeline=0,
            scissor_array=0, depth_bias_array=0, aux_fb=0,
            fragment_status=0, queue_pair=3,
            native_status_registers=True,
        )
        self.assertEqual(
            dict(build_tiling_registers(parameters))[0x14318],
            0x1000078001,
        )
        self.assertEqual(
            dict(build_fragment_registers(parameters))[0x14080],
            0x10001A8001,
        )

    def test_render_status_namespace_is_independent_of_queue_namespace(self):
        parameters = G17PRenderParameters(
            width=1, height=1, context_base=0,
            tilemap=0, heapmeta=0, tpc=0,
            deflake_1=0, deflake_2=0, deflake_3=0,
            encoder=0, ta_status=0,
            store_pipeline_bind=0, store_pipeline=0,
            load_pipeline_bind=0, load_pipeline=0,
            scissor_array=0, depth_bias_array=0, aux_fb=0,
            fragment_status=0, queue_pair=1, queue_item_index=3,
            status_queue_pair=0, status_item_index=0,
            native_pair_registers=True, native_status_registers=True,
        )
        tiling = dict(build_tiling_registers(parameters))
        fragment = dict(build_fragment_registers(parameters))

        # Cycle and record-index registers retain pair 1, item 3.
        self.assertEqual(tiling[0x1ca30], 0x178020 + 0x5e0000 + 0x60)
        self.assertEqual(tiling[0x1c910], 0x80005 + 0x140 + 0xc)
        self.assertEqual(fragment[0x1ca28], 0x178020 + 0x5e0000 + 0x60)
        # Only the low status-array addresses restart at pair 0, item 0.
        self.assertEqual(tiling[0x14318], 0x1000078001)
        self.assertEqual(fragment[0x14080], 0x10001a8001)

    def test_render_sampler_encoder_parameters(self):
        parameters = G17PRenderParameters(
            width=1, height=1, context_base=0,
            tilemap=0, heapmeta=0, tpc=0,
            deflake_1=0, deflake_2=0, deflake_3=0,
            encoder=0, ta_status=0,
            store_pipeline_bind=0, store_pipeline=0,
            load_pipeline_bind=0, load_pipeline=0,
            scissor_array=0, depth_bias_array=0, aux_fb=0,
            fragment_status=0,
            sampler_array=0x10000020000, sampler_count=4,
            process_empty_tiles=False,
        )
        tiling = bytearray(G17PWorkBuilder.BODY_STRIDE["tiling"])
        G17PWorkBuilder(None, None, kind="tiling")._write_structural_tail(
            tiling, parameters, {0x10111: 0})
        fragment = bytearray(G17PWorkBuilder.BODY_STRIDE["fragment"])
        G17PWorkBuilder(None, None, kind="fragment")._write_structural_tail(
            fragment, parameters, {})

        self.assertEqual(
            struct.unpack_from("<QII", tiling, 0x87a),
            (0x10000020000, 4, 5),
        )
        self.assertEqual(
            struct.unpack_from("<QII", fragment, 0x2114),
            (0x10000020000, 4, 5),
        )
        self.assertEqual(fragment[0x2100], 1)
        self.assertEqual(fragment[0x2124], 0)

    def test_render_viewport_uses_current_tile_grid(self):
        page = build_viewport(128, 37)
        self.assertEqual(
            struct.unpack_from("<III", page, 0x900),
            (0x00000c00, 0x80000003, 0x00000001),
        )
        self.assertEqual(
            struct.unpack_from("<ffff", page, 0x910),
            (64.0, 64.0, 18.5, -18.5),
        )
        with self.assertRaisesRegex(ValueError, "positive"):
            build_viewport(0, 37)

    def test_rebuild_restores_registered_graph_without_allocating(self):
        memory = {}
        allocations = []
        next_address = 0x100000

        def alloc(size, name):
            nonlocal next_address
            address = next_address
            next_address += (size + 0xfff) & ~0xfff
            allocations.append((address, size, name))
            return address

        def write(address, body):
            memory[address] = bytes(body)

        builder = G17PPairedWorkBuilder(alloc, write, queue_pair=2)
        built = builder.build_submission_graph(
            index_group_ranges=((0x11, 6), (0x3c, 2)),
            shared_count=8,
        )
        secondary = built["pages"]["secondary_index"]
        builder.bind_runtime_control_page(secondary)
        self.assertEqual(
            builder.tiling.tail_pointer_overrides[0x0934], secondary)
        self.assertEqual(
            builder.fragment.tail_pointer_overrides[0x21ce], secondary)
        expected = dict(memory)
        allocation_count = len(allocations)

        for address, body in tuple(memory.items()):
            memory[address] = bytes([0xa5]) * len(body)

        rebuilt = builder.rebuild_submission_graph()

        self.assertEqual(memory, expected)
        self.assertEqual(len(allocations), allocation_count)
        self.assertEqual(rebuilt["pages"], built["pages"])
        self.assertEqual(rebuilt["pools"], (
            built["pools"]["pool_a"], built["pools"]["pool_b"]))
        self.assertEqual(rebuilt["shared"], built["shared"])
        self.assertEqual(
            builder.tiling.tail_pointer_overrides[0x0934], secondary)
        self.assertEqual(
            builder.fragment.tail_pointer_overrides[0x21ce], secondary)


if __name__ == "__main__":
    unittest.main()
