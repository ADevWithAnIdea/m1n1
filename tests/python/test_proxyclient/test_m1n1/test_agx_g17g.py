# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the observed T8142/G17G numeric ABI layouts."""

import hashlib
import struct
import pathlib
import sys
import unittest
import dataclasses

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[4] / "proxyclient"))

from m1n1.drm_shim import g17g  # noqa: E402
from m1n1.drm_shim import g17g_backend  # noqa: E402
from m1n1.drm_shim import g17g_compute  # noqa: E402
from m1n1.drm_shim import g17g_context1  # noqa: E402
from m1n1.drm_shim import g17g_defaults  # noqa: E402
from m1n1.drm_shim import g17g_direct_pair_assets  # noqa: E402
from m1n1.drm_shim import g17g_encoder  # noqa: E402
from m1n1.drm_shim import g17g_initdata  # noqa: E402
from m1n1.drm_shim import g17g_mixed_partial_assets  # noqa: E402
from m1n1.drm_shim import g17g_mixed_render_assets  # noqa: E402
from m1n1.drm_shim import g17g_partial_assets  # noqa: E402
from m1n1.drm_shim import g17g_partial_repeat_assets  # noqa: E402
from m1n1.drm_shim import g17g_postcontrol  # noqa: E402
from m1n1.drm_shim import g17g_render  # noqa: E402
from m1n1.drm_shim import g17g_render_compiler  # noqa: E402
from m1n1.drm_shim import g17g_stream  # noqa: E402
from m1n1.drm_shim import g17g_sync  # noqa: E402
from m1n1.drm_shim import g17g_uat  # noqa: E402
from m1n1.drm_shim.g17g_shim import (  # noqa: E402
    G17GShimBackend,
    G17GUnsupported,
)


def write_u40(data, offset, value):
    data[offset:offset + 5] = value.to_bytes(5, "little")


class TestG17GLayouts(unittest.TestCase):
    def test_first_report_type_is_not_completion_or_an_errno(self):
        for opcode in (1, 4, 6, 13, 0x55):
            with self.subTest(opcode=opcode):
                report = g17g.parse_render_report_status(struct.pack("<I", opcode))
                self.assertEqual(report["status"], opcode)
                self.assertEqual(report["first_record_type_1"], opcode == 1)
                self.assertEqual(report["first_record_type_4"], opcode == 4)
                self.assertIsNone(report["fault_error"])
                self.assertNotIn("complete", report)
                self.assertNotIn("parameter_buffer_exhausted", report)
        with self.assertRaisesRegex(ValueError, "at least"):
            g17g.parse_render_report_status(b"\x01\x00\x00")

    def test_old_truncated_render_report_does_not_invent_enomem(self):
        fault = g17g_sync.G17GPublishedFault.unclassified_render_failure(
            status=4,
            operand_count=0,
        )
        self.assertEqual(fault.kind, "unclassified-render-report")
        self.assertEqual(fault.error, g17g_sync.G17GWorkError.UNKNOWN)
        self.assertNotEqual(fault.error, g17g_sync.G17GWorkError.OUT_OF_MEMORY)
        self.assertFalse(fault.recoverable)
        self.assertFalse(fault.fatal)
        self.assertEqual(fault.snapshot()["metadata"]["status"], 4)

    def test_render_output_wait_accepts_qword_witness(self):
        class FakeUtils:
            def exec(self, _asm, physical_address, primary, secondary, message):
                self.physical_address = physical_address
                self.asc_bases = (primary, secondary)
                self.message = message
                return 0x1234

        class FakeInterface:
            dev = None

        class FakeASC:
            def __init__(self, base):
                self.asc = type("ASC", (), {"_base": base})()

        utils = FakeUtils()
        message = 0x83000000000008
        result = g17g_stream.kick_and_wait_for_render_output(
            utils,
            FakeInterface(),
            0x1008,
            (FakeASC(0x2000), FakeASC(0x3000)),
            message,
            ordinal=21,
        )
        self.assertEqual(utils.physical_address, 0x1008)
        self.assertEqual(utils.asc_bases, (0x2000, 0x3000))
        self.assertEqual(utils.message, message)
        self.assertEqual(result["ordinal"], 21)
        self.assertEqual(result["observed"], 0x1234)
        self.assertEqual(result["kick_message"], message)
        self.assertEqual(result["host_read_count"], 0)

    def test_render_kick_and_output_wait_share_one_target_call(self):
        class FakeUtils:
            def exec(self, _asm, physical_address, primary, secondary, message):
                self.args = (physical_address, primary, secondary, message)
                return 0x5678

        class FakeInterface:
            dev = None

        class FakeASC:
            def __init__(self, base):
                self.asc = type("ASC", (), {"_base": base})()

        utils = FakeUtils()
        message = 0x83000000000008
        result = g17g_stream.kick_and_wait_for_render_output(
            utils,
            FakeInterface(),
            0x1008,
            (FakeASC(0x2000), FakeASC(0x3000)),
            message,
            ordinal=6,
        )
        self.assertEqual(utils.args, (0x1008, 0x2000, 0x3000, message))
        self.assertEqual(result["kick_message"], message)
        self.assertEqual(result["kick_endpoint"], 0x21)
        self.assertEqual(result["host_read_count"], 0)

    def test_render_output_wait_rejects_sub_qword_alignment(self):
        with self.assertRaisesRegex(ValueError, "output witness physical"):
            g17g_stream.kick_and_wait_for_render_output(
                None, None, 0x1004, (), 0x83000000000008
            )

    def test_render_service_wait_sends_and_converges_on_target(self):
        class FakeUtils:
            def exec(self, _asm, *args):
                self.args = args
                expected = args[-1]
                return (
                    (1 << 63)
                    | expected
                    | (expected << 16)
                    | (expected << 32)
                )

        class FakeInterface:
            dev = None

        class FakeASC:
            def __init__(self, base):
                self.asc = type("ASC", (), {"_base": base})()

        utils = FakeUtils()
        result = g17g_stream.notify_and_wait_for_render_service(
            utils,
            FakeInterface(),
            (0x1000, 0x1010, 0x1020),
            (FakeASC(0x4000), FakeASC(0x5000)),
            0x8B,
            ordinal=387,
        )
        self.assertEqual(
            utils.args,
            (0x1000, 0x4000, 0x5000, 0x8B),
        )
        self.assertEqual(result["ordinal"], 387)
        self.assertEqual(result["observed"], [0x8B] * 3)
        self.assertEqual(result["host_read_count"], 0)
        self.assertEqual(result["proxy_call_count"], 1)

    def test_render_service_wait_preserves_timeout_state(self):
        class FakeUtils:
            def exec(self, _asm, *_args):
                return 0x8A | (0x8A << 16) | (0x8B << 32)

        class FakeInterface:
            dev = None

        class FakeASC:
            def __init__(self, base):
                self.asc = type("ASC", (), {"_base": base})()

        with self.assertRaises(g17g_stream.RenderStreamTimeout) as caught:
            g17g_stream.notify_and_wait_for_render_service(
                FakeUtils(),
                FakeInterface(),
                (0x1000, 0x1010, 0x1020),
                (FakeASC(0x4000), FakeASC(0x5000)),
                0x8B,
                ordinal=387,
            )
        self.assertEqual(caught.exception.phase, "service convergence")
        self.assertEqual(caught.exception.ordinal, 387)
        self.assertEqual(caught.exception.detail, (0x8A, 0x8A, 0x8B, 0x8B))

    def test_render_service_rollover_defers_then_converges_first_consumer(self):
        class FakeUtils:
            def __init__(self):
                self.calls = []

            def exec(self, _asm, *args):
                self.calls.append(args)
                expected = args[-1] & 0xFF
                first = 0x8A if args[-1] & 0x100 else expected
                return (
                    (1 << 63)
                    | first
                    | (expected << 16)
                    | (expected << 32)
                )

        class FakeInterface:
            dev = None

        class FakeASC:
            def __init__(self, base):
                self.asc = type("ASC", (), {"_base": base})()

        utils = FakeUtils()
        asces = (FakeASC(0x4000), FakeASC(0x5000))
        deferred = g17g_stream.notify_and_wait_for_render_service(
            utils,
            FakeInterface(),
            (0x1000, 0x1010, 0x1020),
            asces,
            0x8B,
            ordinal=246,
            defer_first_consumer=True,
        )
        converged = g17g_stream.wait_for_render_service_convergence(
            utils,
            FakeInterface(),
            (0x1000, 0x1010, 0x1020),
            asces,
            0x8B,
            ordinal=246,
        )
        self.assertEqual(utils.calls[0][-1], 0x18B)
        self.assertEqual(utils.calls[1][-1], 0x28B)
        self.assertEqual(deferred["observed"], [0x8A, 0x8B, 0x8B])
        self.assertTrue(deferred["deferred_first_consumer"])
        self.assertEqual(converged["observed"], [0x8B] * 3)
        self.assertIsNone(converged["notification_message"])

    def test_direct_vdm_encoder_matches_earliest_native_page(self):
        source = g17g_encoder.validate_native_direct_vdm_page()
        native = g17g_partial_assets.build_partial_context_pages()[
            g17g_encoder.VDM_STREAM_DVA
        ]
        self.assertEqual(source, native)
        self.assertEqual(
            hashlib.sha256(source).hexdigest(),
            g17g_encoder.NATIVE_PARTIAL_PAGE_SHA256,
        )

    def test_direct_vdm_encoder_accepts_caller_draw_cardinality(self):
        page = g17g_encoder.build_direct_vdm_page(
            g17g_encoder.G17GDirectDraw(
                vertex_count=3, instance_count=2, vertex_start=7,
            )
        )
        self.assertEqual(
            struct.unpack_from("<III", page, 0x90),
            (3, 2, 7),
        )
        self.assertEqual(struct.unpack_from("<I", page, 0xA0)[0], 0xC0000000)
        self.assertFalse(any(page[0xA4:]))

    def test_partial_vdm_bound_state_pages_match_earliest_native_pages(self):
        source = g17g_encoder.build_partial_bound_state_pages()
        native = g17g_partial_assets.build_partial_context_pages()
        self.assertEqual(set(source), set(g17g_encoder.PARTIAL_STATE_PAGE_SHA256))
        for address, page in source.items():
            self.assertEqual(page, native[address])
            self.assertEqual(
                hashlib.sha256(page).hexdigest(),
                g17g_encoder.PARTIAL_STATE_PAGE_SHA256[address],
            )
        moved = g17g_encoder.build_partial_bound_state_pages(0x100003A0700)
        self.assertEqual(
            struct.unpack_from("<I", moved[0x1000058000], 0x134)[0],
            0xE81C,
        )
        with self.assertRaisesRegex(ValueError, "invalid USC address"):
            g17g_encoder.build_partial_bound_state_pages(0x100003A0704)


    def test_bgra8_clear_pixel_encoding(self):
        self.assertEqual(
            g17g_render.encode_bgra8_unorm_pixel((0x11, 0x22, 0x33, 0x44)),
            bytes.fromhex("33221144"),
        )
        self.assertEqual(
            struct.unpack(
                "<I",
                g17g_render.encode_bgra8_unorm_pixel(
                    (0x11, 0x22, 0x33, 0x44)
                ),
            )[0],
            0x44112233,
        )

    def test_render_firmware_scratch_pages_match_native_boundary(self):
        tiling = g17g_render.build_tiling_firmware_scratch_page()
        fragment = g17g_render.build_fragment_firmware_scratch_page()
        self.assertEqual(len(tiling), 0x4000)
        self.assertEqual(len(fragment), 0x4000)
        self.assertEqual(
            hashlib.sha256(tiling).hexdigest(),
            "3f2fa6289270e41b331517489348692ed514a115de6ba9ef7f82a042454820fb",
        )
        self.assertEqual(
            hashlib.sha256(fragment).hexdigest(),
            "04786e1b5079cd1aaab58622c8e0320642d1fb85edd8add50cb9648c0deb36da",
        )

    def test_second_render_queue_context_items_match_native_publication(self):
        cases = (
            (
                "tiling",
                g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE,
                {
                    0x00: 0x1000000000000008,
                    0x10: 0xFFFFFC20C0018000,
                    0x18: 0xFFFFFC20C0000000,
                    0x20: 0xFFFF0C0000000001,
                    0x28: 0x0000000000000001,
                    0x150: 0x0002780390000051,
                    0x178: 0x003FFFFFFFFFFFFF,
                    0x180: 0x0000000000000001,
                },
            ),
            (
                "fragment",
                g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE,
                {
                    0x00: 0x1000040000000008,
                    0x10: 0xFFFFFC20C00B0000,
                    0x18: 0xFFFFFC20C0000080,
                    0x20: 0xFFFF180000000003,
                    0x28: 0x0000000000000002,
                    0x30: 0x0000010000000001,
                    0x150: 0x0002B80390004D17,
                    0x158: 0x0000880390004D50,
                    0x160: 0x0000C00390004D89,
                    0x168: 0x0000600390004DC2,
                    0x178: 0x003FFFFFFFFFFFFF,
                    0x180: 0x0000000000000005,
                },
            ),
        )
        for kind, descriptor_address, expected in cases:
            item = g17g_render.build_render_queue_context_item(
                kind, descriptor_address, item_index=1
            )
            self.assertEqual(len(item), 0x200)
            self.assertEqual(
                {
                    offset: struct.unpack_from("<Q", item, offset)[0]
                    for offset in expected
                },
                expected,
            )

    def test_render_queue_pair_one_encodes_grid_and_descriptor_namespaces(self):
        products = g17g_backend.build_partial_render_products()
        descriptor_objects = (
            0xFFFFFC20C1000100,
            0xFFFFFC20C1008000,
            0xFFFFFC20C1004080,
            0xFFFFFC20C1006800,
        )
        items = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 3
            ),
            products["token"],
            submission_ordinal=3,
            submission_index=0,
            event_group=3,
            descriptor_index=2,
            parameter_index=2,
            pool_a_index=2,
            pool_b_index=2,
            queue_indices=(2, 3),
            queue_context_index=0,
            channel_control=0xFFFFFC20C07C0040,
            tiling_context_scratch=0x7200488000,
            tiling_firmware_scratch=0xFFFFFC2000228000,
            fragment_context_scratch=0x72004B0000,
            fragment_firmware_scratch=0xFFFFFC2000250000,
            tiling_status_base=0xFFFFFC2001638000,
            fragment_status_base=0xFFFFFC2001650000,
            status_index=0,
            tiling_register_status_base=0x1000660000,
            fragment_register_status_base=0x1000838000,
            register_status_index=0,
            descriptor_objects=descriptor_objects,
            register_pair_index=1,
            register_resource_index=0,
        )
        tiling_optional = items["tiling_optional"]
        fragment_optional = items["fragment_optional"]
        self.assertEqual(
            {
                offset: struct.unpack_from("<H", tiling_optional, offset)[0]
                for offset in (0x18, 0x2A, 0x2E, 0x3E, 0x76, 0x7E, 0x82)
            },
            {
                0x18: 2,
                0x2A: 0,
                0x2E: 0,
                0x3E: 3,
                0x76: 2,
                0x7E: 1,
                0x82: 3,
            },
        )
        self.assertEqual(
            {
                offset: struct.unpack_from("<H", fragment_optional, offset)[0]
                for offset in (0x18, 0x2A, 0x2E, 0x3E)
            },
            {0x18: 3, 0x2A: 0, 0x2E: 0, 0x3E: 3},
        )
        self.assertEqual(
            struct.unpack_from("<Q", tiling_optional, 0x4A)[0],
            0xFFFFFC20C07C0040,
        )
        self.assertEqual(
            struct.unpack_from("<Q", tiling_optional, 0x6E)[0],
            descriptor_objects[1],
        )
        self.assertEqual(
            struct.unpack_from("<2Q", tiling_optional, 0x08),
            (0x7200488000, 0xFFFFFC2000228000),
        )
        self.assertEqual(
            struct.unpack_from("<2Q", fragment_optional, 0x08),
            (0x72004B0000, 0xFFFFFC2000250000),
        )
        self.assertEqual(
            struct.unpack_from("<I", items["tiling_event"], 0x04)[0],
            0x10002,
        )
        self.assertEqual(
            struct.unpack_from("<I", items["fragment_event"], 0x04)[0],
            0x10003,
        )
        self.assertEqual(
            struct.unpack_from("<I", items["tiling_descriptor"], 0x79C)[0],
            3,
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["tiling_descriptor"], 0x8A6)[0],
            g17g_render.DISPATCH_A + 8,
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["tiling_descriptor"], 0x8AE)[0],
            g17g_render.DISPATCH_B + 8,
        )
        self.assertEqual(
            struct.unpack_from("<I", items["tiling_descriptor"], 0x8BA)[0],
            2,
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["fragment_descriptor"], 0x2140)[0],
            g17g_render.DISPATCH_A + 12,
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["fragment_descriptor"], 0x2148)[0],
            g17g_render.DISPATCH_B + 12,
        )
        self.assertEqual(
            struct.unpack_from("<I", items["fragment_descriptor"], 0x2154)[0],
            3,
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["tiling_descriptor"], 0x945)[0],
            0xFFFFFC2001638000,
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["fragment_descriptor"], 0x21DF)[0],
            0xFFFFFC2001650000,
        )
        self.assertEqual(
            struct.unpack_from("<4Q", items["fragment_descriptor"], 0x20),
            (
                descriptor_objects[0] + 2 * 0x100,
                descriptor_objects[1],
                descriptor_objects[2] + 2 * 0x80,
                descriptor_objects[3],
            ),
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["tiling_descriptor"], 0x10)[0],
            descriptor_objects[0] + 2 * 0x100,
        )
        self.assertEqual(
            struct.unpack_from("<3Q", items["tiling_descriptor"], 0x20),
            (
                descriptor_objects[1],
                descriptor_objects[2] + 2 * 0x80,
                descriptor_objects[3],
            ),
        )
        for name, register_offset, register_count, register_number, expected in (
            (
                "tiling_descriptor", 0x60,
                g17g_render.TILING_REGISTER_COUNT, 0x1CA30, 0x800040,
            ),
            (
                "tiling_descriptor", 0x60,
                g17g_render.TILING_REGISTER_COUNT, 0x16C39, 0x800040,
            ),
            (
                "tiling_descriptor", 0x60,
                g17g_render.TILING_REGISTER_COUNT, 0x1C910, 0x668041,
            ),
            ("tiling_descriptor", 0x3CC, 9, 0x14318, 0x1000660001),
            (
                "fragment_descriptor", 0xA0,
                g17g_render.FRAGMENT_REGISTER_COUNT, 0x14080, 0x1000838001,
            ),
            (
                "fragment_descriptor", 0xA0,
                g17g_render.FRAGMENT_REGISTER_COUNT, 0x1CA28, 0x800040,
            ),
        ):
            body = items[name]
            registers = {
                struct.unpack_from("<I", body, register_offset + index * 12)[0]:
                struct.unpack_from("<Q", body, register_offset + index * 12 + 4)[0]
                for index in range(register_count)
            }
            self.assertEqual(registers[register_number], expected)

        cases = (
            (
                "tiling",
                g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE
                + 2 * g17g_render.TILING_DESCRIPTOR_SIZE,
                2,
                0xFFFFFC20C0000100,
                {
                    0x00: 0x1000080000000004,
                    0x18: 0xFFFFFC20C0000100,
                    0x20: 0xFFFF0C0100000001,
                    0x28: 0x0000020000000000,
                    0x150: 0x000278039000009F,
                },
            ),
            (
                "fragment",
                g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE
                + 2 * g17g_render.FRAGMENT_DESCRIPTOR_SIZE,
                3,
                0xFFFFFC20C0000180,
                {
                    0x00: 0x10000C0000000004,
                    0x18: 0xFFFFFC20C0000180,
                    0x20: 0xFFFF180100000003,
                    0x28: 0x0000020000000001,
                    0x30: 0x0000030000000000,
                    0x150: 0x0002B80390004E29,
                    0x158: 0x0000880390004E62,
                    0x160: 0x0000C00390004E9B,
                    0x168: 0x0000600390004ED4,
                },
            ),
        )
        for kind, descriptor, queue_index, queue_address, expected in cases:
            body = g17g_render.build_render_queue_context_item(
                kind,
                descriptor,
                item_index=0,
                queue_index=queue_index,
                queue_address=queue_address,
                descriptor_index=2,
            )
            self.assertEqual(
                {
                    offset: struct.unpack_from("<Q", body, offset)[0]
                    for offset in expected
                },
                expected,
            )

    def test_second_render_external_publication_matches_native_boundary(self):
        transitions = g17g_backend.build_second_render_publication_qwords()
        self.assertEqual(
            transitions,
            {
                g17g_postcontrol.ADDRESS_TABLE_PAGE: (
                    (0x208, 0x0, 0x1),
                    (0x210, 0x0, 0x50),
                ),
                g17g_postcontrol.TARGET_RECORD_ARRAY_PAGE: (
                    (0x148, 0x0, 0x100000000),
                ),
            },
        )
        self.assertEqual(sum(map(len, transitions.values())), 3)

    def test_repeat_render_zero_reservation_matches_reduced_boundary(self):
        dvas = g17g_backend.expand_render_repeat_zero_reservation_dvas()
        self.assertEqual(len(dvas), 117 * 32)
        self.assertEqual(dvas[0], 0x1000290000)
        self.assertEqual(dvas[31], 0x100030C000)
        self.assertEqual(dvas[32], 0x1000318000)
        self.assertEqual(dvas[-1], 0x10040AC000)
        self.assertEqual(
            hashlib.sha256(
                b"".join(struct.pack("<Q", address) for address in dvas)
            ).hexdigest(),
            g17g_backend.RENDER_REPEAT_ZERO_RESERVATION_DVA_SHA256,
        )
        self.assertEqual(
            g17g_backend.RENDER_REPEAT_ZERO_RESERVATION_PTE_FLAGS,
            {
                "VALID": 1,
                "TYPE": 1,
                "AttrIndex": 2,
                "AP": 2,
                "SH": 0,
                "AF": 1,
                "nG": 1,
                "PXN": 0,
                "UXN": 1,
                "OS": 1,
            },
        )

    def test_transport_descriptor_storage_restarts_without_logical_restart(self):
        self.assertEqual(
            g17g_render.render_transport_descriptor_index(248, 248, 0),
            248,
        )
        self.assertEqual(
            g17g_render.render_transport_descriptor_index(249, 0, 1),
            0,
        )
        self.assertEqual(
            g17g_render.render_transport_descriptor_index(252, 3, 1),
            3,
        )
        with self.assertRaises(ValueError):
            g17g_render.render_transport_descriptor_index(256, 256, 0)

    def test_repeat_render_reservation_index_page_is_host_generated(self):
        body = g17g_backend.build_render_repeat_reservation_index_page()
        values = struct.unpack("<4096I", body)
        self.assertEqual(len(body), 0x4000)
        self.assertEqual(values[:48], tuple(
            value
            for start in (0x11, 0x22, 0x33)
            for value in range(start, start + 0x10)
        ))
        self.assertEqual(values[48:64], tuple(range(0x52, 0x62)))
        self.assertEqual(values[-1], 0x111D)
        self.assertTrue(all(value % 0x11 != 0xD for value in values[48:]))
        self.assertEqual(
            hashlib.sha256(body).hexdigest(),
            g17g_backend.RENDER_REPEAT_RESERVATION_INDEX_SHA256,
        )
        self.assertEqual(
            g17g_backend.RENDER_REPEAT_RESERVATION_INDEX_LOW,
            g17g_backend.PARTIAL_RENDER_POSTCONTROL_ALIAS_DVA,
        )
        self.assertEqual(
            g17g_backend.RENDER_REPEAT_RESERVATION_INDEX_HIGH,
            g17g_backend.PARTIAL_RENDER_POSTCONTROL_ALIAS_HIGH,
        )

    def test_repeat_render_prework_qword_transition_is_host_built(self):
        sources = {}
        for address, entries in (
            g17g_backend.RENDER_REPEAT_PREWORK_QWORD_TRANSITIONS.items()
        ):
            source = bytearray(0x4000)
            for offset, before_value, _after_value in entries:
                struct.pack_into("<Q", source, offset, before_value)
            sources[address] = bytes(source)
        page14 = bytearray(sources[0xFFFFFC20015E8000])
        struct.pack_into("<Q", page14, 0x0, 0x0000003000023800)
        sources[0xFFFFFC20015E8000] = bytes(page14)
        fragment = bytearray(
            sources[g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE]
        )
        struct.pack_into("<Q", fragment, 0x2110, 0x12345678FFFFFFFF)
        struct.pack_into("<Q", fragment, 0x21F8, 0xABCDEF0123456789)
        sources[g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE] = bytes(fragment)

        results = g17g_backend.apply_render_repeat_prework_qword_transitions(
            sources
        )
        result = results[0xFFFFFC20015E8000]
        self.assertEqual(
            struct.unpack_from("<Q", result, 0)[0], 0x0000003000023800
        )
        self.assertEqual(struct.unpack_from("<Q", result, 8)[0], 0)
        fragment = results[g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE]
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x2110)[0],
            0x12345678FFFFFFFF,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x21F8)[0],
            0xABCDEF0123456789,
        )
        for address, entries in (
            g17g_backend.RENDER_REPEAT_PREWORK_QWORD_TRANSITIONS.items()
        ):
            for offset, _before_value, after_value in entries:
                self.assertEqual(
                    struct.unpack_from("<Q", results[address], offset)[0],
                    after_value,
                )
        broken = bytearray(sources[0xFFFFFC20015E8000])
        struct.pack_into("<Q", broken, 8, 0x8)
        broken_sources = dict(sources)
        broken_sources[0xFFFFFC20015E8000] = bytes(broken)
        with self.assertRaisesRegex(ValueError, "source mismatch"):
            g17g_backend.apply_render_repeat_prework_qword_transitions(
                broken_sources
            )

    def test_repeat_render_pristine_page_reset_uses_host_asset(self):
        pages = g17g_backend.build_render_repeat_pristine_context1_pages()
        self.assertEqual(set(pages), {0x100001B8000})
        self.assertEqual(
            hashlib.sha256(pages[0x100001B8000]).hexdigest(),
            "2fdd53dea11d7ddc17c97157e0a055ac8bc41ec81f6313fb0371cef3c5b3e957",
        )
        self.assertEqual(
            pages[0x100001B8000],
            g17g_partial_assets.build_partial_context_pages()[0x100001B8000],
        )

    def test_direct_pair_prework_is_only_the_caller_ordinal(self):
        recipe = g17g_backend.RENDER_DIRECT_PAIR_PREWORK_QWORD_TRANSITIONS
        self.assertEqual(set(recipe), {0x1000058000})
        source = bytearray(0x4000)
        struct.pack_into("<Q", source, 0x130, 0x00007A1C01000000)
        pages = g17g_backend.apply_render_repeat_prework_qword_transitions(
            {0x1000058000: bytes(source)}, recipe
        )
        self.assertEqual(
            struct.unpack_from("<Q", pages[0x1000058000], 0x130)[0],
            0x00007A3501000000,
        )

    def test_direct_pair_fragment_admission_is_three_guarded_qwords(self):
        recipe = (
            g17g_backend.RENDER_DIRECT_PAIR_FRAGMENT_QWORD_TRANSITIONS
        )
        self.assertEqual(
            set(recipe), {g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE}
        )
        entries = recipe[g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE]
        self.assertEqual(
            tuple(offset for offset, _before, _after in entries),
            (0x2308, 0x2320, 0x2328),
        )
        source = bytearray(0x4000)
        for offset, before, _after in entries:
            struct.pack_into("<Q", source, offset, before)
        struct.pack_into("<Q", source, 0x23D0, 0x0010C00000015021)
        pages = g17g_backend.apply_render_repeat_prework_qword_transitions(
            {
                g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE:
                    bytes(source)
            },
            recipe,
        )
        result = pages[g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE]
        for offset, _before, after in entries:
            self.assertEqual(
                struct.unpack_from("<Q", result, offset)[0], after
            )
        self.assertEqual(
            struct.unpack_from("<Q", result, 0x23D0)[0],
            0x0010C00000015021,
        )

    def test_direct_pair_service_topology_has_host_leaf_attributes(self):
        caller = g17g_backend.expand_second_direct_render_context1_dvas()
        retired = (
            g17g_backend.expand_second_direct_retired_context1_dvas()
        )
        high = g17g_backend.expand_second_direct_render_high_dvas()
        self.assertEqual(len(caller), 294)
        self.assertEqual(len(retired), 294)
        self.assertFalse(set(caller) & set(retired))
        caller_flags = g17g_backend.second_direct_render_leaf_flags(
            "context1-selector0", caller[0]
        )
        self.assertEqual(caller_flags["AttrIndex"], 2)
        self.assertEqual(caller_flags["AP"], 2)
        self.assertEqual(caller_flags["nG"], 1)
        for address in high:
            flags = g17g_backend.second_direct_render_leaf_flags(
                "context64-selector1", address
            )
            self.assertEqual(flags["AP"], 1)
            self.assertEqual(flags["nG"], 0)
            self.assertEqual(
                flags["AttrIndex"],
                2 if address == g17g_backend.RENDER_SECOND_SERVICE_STATE
                else 0,
            )

    def test_third_direct_service_topology_is_source_generated(self):
        caller = g17g_backend.expand_third_direct_render_context1_dvas()
        retired = g17g_backend.expand_third_direct_retired_context1_dvas()
        high = g17g_backend.expand_third_direct_render_high_dvas()
        self.assertEqual(len(caller), 260)
        self.assertEqual(len(retired), 288)
        self.assertEqual(high, (
            g17g_backend.RENDER_THIRD_DIRECT_SERVICE_STATE,
            g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT,
        ))
        self.assertFalse(set(caller) & set(retired))
        self.assertEqual(
            set(retired),
            set(range(0x72028B0000, 0x7202CB0000, 0x4000))
            | set(range(0x7202CB8000, 0x7202CC8000, 0x4000))
            | set(range(0x10000140000, 0x100001B0000, 0x4000)),
        )
        pages = g17g_backend.third_direct_render_context1_page_images()
        self.assertEqual(
            tuple(
                (address, hashlib.sha256(body).hexdigest())
                for address, body in pages.items()
            ),
            (
                (0x7202490000, "3973833467713602606e1e40245b6f9104492bb3ad5320a7c50abcb7ae38c988"),
                (0x7202494000, "b33fb5efea81bb657e989bded36b213abfd7fcc5e1b8b82db87df8179fdfd442"),
                (0x7202498000, "283e520b9f6eef2976f649a59a734a8560a51b8c8dd60876c96cb2688061ebb1"),
                (0x720249C000, "bb375a21ca7d060ea39c2312c6150e783b53a60cb9d0cf32601ec8083436279b"),
                (0x72024A0000, "ff8acd727ee4ef326e9cd09574b7e8e60613a94868a227ab67af493ec3143ca2"),
                (0x7202898000, "8aec68246fe407f83722caacfe697821f83d3b793d0b1bc18e9feed95faa05e0"),
            ),
        )
        service = g17g_backend.build_third_direct_render_service_pages()
        self.assertEqual(
            hashlib.sha256(
                service[g17g_backend.RENDER_THIRD_DIRECT_SERVICE_STATE]
            ).hexdigest(),
            "716ad7538f92bb3cb749146290fa25419ab65b4dfe2cffc980566194d825e0a3",
        )
        self.assertEqual(
            hashlib.sha256(
                service[g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT]
            ).hexdigest(),
            "ef3c2823349b556c2f2b53fe457679e8f469f1f1aa8f041a9ae500cc1d593244",
        )
        for address in high:
            flags = g17g_backend.third_direct_render_leaf_flags(
                "context64-selector1", address
            )
            self.assertEqual(flags["AP"], 1)
            self.assertEqual(
                flags["AttrIndex"],
                2 if address == g17g_backend.RENDER_THIRD_DIRECT_SERVICE_STATE
                else 0,
            )

    def test_fourth_direct_service_topology_republishes_b_from_source(self):
        caller = g17g_backend.expand_fourth_direct_render_context1_dvas()
        retired = g17g_backend.expand_fourth_direct_retired_context1_dvas()
        high = g17g_backend.expand_fourth_direct_render_high_dvas()
        self.assertEqual(len(caller), 260)
        self.assertEqual(len(retired), 260)
        self.assertFalse(set(caller) & set(retired))
        self.assertEqual(
            caller,
            tuple(range(0x72028B0000, 0x7202CB0000, 0x4000))
            + tuple(range(0x7202CB8000, 0x7202CC8000, 0x4000)),
        )
        self.assertEqual(
            retired,
            g17g_backend.expand_third_direct_render_context1_dvas(),
        )
        self.assertEqual(high, (
            g17g_backend.RENDER_SECOND_SERVICE_STATE,
            g17g_backend.RENDER_SECOND_SERVICE_OBJECT,
        ))
        pages = g17g_backend.fourth_direct_render_context1_page_images()
        self.assertEqual(
            {
                address: hashlib.sha256(body).hexdigest()
                for address, body in pages.items()
            },
            {
                0x72028B0000:
                    "3973833467713602606e1e40245b6f9104492bb3ad5320a7c50abcb7ae38c988",
                0x72028B4000:
                    "b33fb5efea81bb657e989bded36b213abfd7fcc5e1b8b82db87df8179fdfd442",
                0x72028B8000:
                    "283e520b9f6eef2976f649a59a734a8560a51b8c8dd60876c96cb2688061ebb1",
                0x72028BC000:
                    "bb375a21ca7d060ea39c2312c6150e783b53a60cb9d0cf32601ec8083436279b",
                0x72028C0000:
                    "ff8acd727ee4ef326e9cd09574b7e8e60613a94868a227ab67af493ec3143ca2",
                0x7202CB8000:
                    "8aec68246fe407f83722caacfe697821f83d3b793d0b1bc18e9feed95faa05e0",
            },
        )
        service = g17g_backend.build_fourth_direct_render_service_pages()
        self.assertEqual(
            hashlib.sha256(
                service[g17g_backend.RENDER_FOURTH_DIRECT_SERVICE_STATE]
            ).hexdigest(),
            "716ad7538f92bb3cb749146290fa25419ab65b4dfe2cffc980566194d825e0a3",
        )
        self.assertEqual(
            hashlib.sha256(
                service[g17g_backend.RENDER_FOURTH_DIRECT_SERVICE_OBJECT]
            ).hexdigest(),
            "4785da5ea2d5c196d5bb2f4b169b1857f765e6ac1457b5b1fc549e8c5b40f5f5",
        )
        for address in high:
            flags = g17g_backend.fourth_direct_render_leaf_flags(
                "context64-selector1", address
            )
            self.assertEqual(flags["AP"], 1)
            self.assertEqual(
                flags["AttrIndex"],
                2 if address == g17g_backend.RENDER_FOURTH_DIRECT_SERVICE_STATE
                else 0,
            )

    def test_direct_render_lifecycle_warmup_rejoins_recurrent_cadence(self):
        self.assertEqual(
            tuple(
                g17g_backend.direct_render_tiling_lifecycle(ordinal)
                for ordinal in range(1, 8)
            ),
            (
                0xCE010000F3,
                0xD00100010E,
                0xD201000127,
                0xD401000140,
                0xD601000159,
                0xD801000116,
                0xDA01000119,
            ),
        )
        with self.assertRaises(ValueError):
            g17g_backend.direct_render_tiling_lifecycle(0)

    def test_direct_render_service_object_settles_on_a_after_warmup(self):
        self.assertEqual(
            tuple(
                g17g_backend.direct_render_service_object(ordinal)
                for ordinal in range(1, 9)
            ),
            (
                g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT,
                g17g_backend.RENDER_FOURTH_DIRECT_SERVICE_OBJECT,
                g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT,
                g17g_backend.RENDER_FOURTH_DIRECT_SERVICE_OBJECT,
                g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT,
                g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT,
                g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT,
                g17g_backend.RENDER_THIRD_DIRECT_SERVICE_OBJECT,
            ),
        )
        with self.assertRaises(ValueError):
            g17g_backend.direct_render_service_object(0)

    def test_repeat_render_context_pages_are_host_generated(self):
        pages = g17g_backend.build_render_repeat_context1_pages()
        self.assertEqual(set(pages), {
            0x10000000000,
            0x100001B8000,
            0x100001C8000,
            0x100001E8000,
        })
        self.assertEqual(
            pages[0x100001B8000],
            g17g_partial_assets.build_partial_context_pages()[0x100001B8000],
        )
        repeat_pages = (
            g17g_partial_repeat_assets.build_partial_repeat_context_pages()
        )
        self.assertEqual(
            {address: pages[address] for address in repeat_pages},
            repeat_pages,
        )
        self.assertEqual(
            {
                address: hashlib.sha256(body).hexdigest()
                for address, body in repeat_pages.items()
            },
            {
                0x10000000000:
                    "9eaf92eb8dcd171268d36d63623a9a9924b3fd74b7451080cf3b5c5a35977c69",
                0x100001C8000:
                    "6a95f99a73e4b0f34b61da52626448e9cb1b5eab0f912b9538a96929ff8eba85",
                0x100001E8000:
                    "e4540d3c5c39a2884537a11f598377a48580ef59c5d7970ed88d6d825da5c64b",
            },
        )

    def test_second_direct_render_caller_pages_are_host_generated(self):
        pages = g17g_backend.build_second_direct_render_caller_pages()
        expected_hashes = {
            address: values[4]
            for address, values in (
                g17g_direct_pair_assets.DIRECT_PAIR_CONTEXT_RANGES.items()
            )
        }
        expected_hashes[0x1000058000] = (
            g17g_backend.RENDER_DIRECT_PAIR_ORDINAL_PAGE_SHA256
        )
        self.assertEqual(
            {address: hashlib.sha256(body).hexdigest()
             for address, body in pages.items()},
            expected_hashes,
        )
        self.assertTrue(all(len(body) == 0x4000 for body in pages.values()))

    def test_allocation_second_render_postservice_matches_early_boundary(self):
        transitions = (
            g17g_backend.build_second_render_allocation_postservice_qwords()
        )
        self.assertEqual(len(transitions), 9)
        self.assertEqual(sum(map(len, transitions.values())), 20)
        self.assertEqual(
            g17g_backend.RENDER_LIVE_ADMISSION_PAGE,
            0xFFFFFC20C0790000,
        )
        self.assertEqual(
            g17g_backend.RENDER_LIVE_ADMISSION_QWORD_OFFSET, 0x78
        )
        self.assertEqual(g17g_backend.RENDER_LIVE_ADMISSION_LOW32, 0x1F40)
        self.assertEqual(
            transitions[0xFFFFFC200002C000],
            (
                (0x3120, 0x2, 0x0002000000000200),
                (0x31C0, 0x1, 0x3),
                (0x33C0, 0x0, 0x37),
            ),
        )
        self.assertNotIn(g17g_postcontrol.QUEUE_PAGE, transitions)
        self.assertNotIn(g17g_backend.RENDER_OPTIONAL_PAGE, transitions)
        self.assertNotIn(g17g_backend.COMPUTE_GLOBAL_STATE, transitions)
        self.assertEqual(g17g_backend.build_second_render_token_qwords(), {})
        self.assertEqual(
            transitions[g17g_initdata.REGION_20_ADDRESS],
            ((0x80, 0x0000000100000000, 0x0000000200000001),),
        )
        self.assertEqual(
            transitions[0xFFFFFC20015E0000][4],
            (0xE00, 0x2, 0x3),
        )
        self.assertEqual(
            transitions[0xFFFFFC20C0788000],
            (
                (0x2738, 0xC080800000000072, 0xC07E800000000072),
                (0x2758, 0xC083000000000072, 0xC081000000000072),
                (0x2778, 0xC085800000000072, 0xC083800000000072),
                (0x2798, 0xC088000000000072, 0xC086000000000072),
            ),
        )
        self.assertEqual(
            transitions[0xFFFFFC20C0790000],
            ((0x98, 0x0, 0x1),),
        )
        self.assertEqual(
            transitions[0xFFFFFC20015E0000],
            (
                (0x000, 0xFF, 0x400),
                (0x008, 0xFF, 0x400),
                (0x400, 0x0000000100000001, 0x0000000200000002),
                (0x600, 0x2, 0x4),
                (0xE00, 0x2, 0x3),
                (0xE20, 0x1, 0x2),
                (0xE28, 0x1, 0x2),
            ),
        )
        self.assertEqual(
            transitions[g17g_backend.COMPUTE_GLOBAL_SCHEDULER_SLOT],
            ((0x8, 0x0, 0x2),),
        )
        self.assertEqual(
            transitions[0xFFFFFC2001618000],
            ((0x60, 0x0, 0x1),),
        )
        self.assertEqual(
            transitions[0xFFFFFC2001628000],
            ((0x0, 0x1, 0x2),),
        )
        self.assertEqual(
            transitions[0xFFFFFC20C08E8000],
            ((0x8, 0xFFFFFFFF00000001, 0x1),),
        )

    def test_minimal_second_render_advances_fragment_stage_after_service(self):
        transitions = (
            g17g_backend.build_second_render_minimal_postservice_qwords()
        )
        self.assertEqual(
            transitions[0xFFFFFC200002C000],
            (
                (0x3118, 0x0000000600000000, 0x0000000800000000),
                (0x3120, 0x0000000000000002, 0x0200000000000002),
                (0x31E0, 0x2, 0x3),
                (0x33E0, 0x2D, 0x50),
                (0x34D0, 0x0, 0x0000000300000001),
                (0x34E8, 0x0, 0x1),
                (0x34F0, 0x0, 0xFFFFFC20C07D8004),
                (0x34F8, 0x0, 0x00000000010000FE),
                (0x3500, 0x0, 0x200),
                (0x3508, 0x0, 0x1),
                (0x3510, 0x0, 0x1),
            ),
        )
        self.assertEqual(
            transitions[g17g_backend.RENDER_SECOND_SERVICE_HISTORY_PAGE],
            (
                (0x000, 0x0001000000000013, 0x0002000000000013),
                (0x030, 0xFFFFFC20C0018000, 0xFFFFFC20C00189C0),
                (0x040, 0x0001000000000223, 0x0102000000000223),
                (0x070, 0xFFFFFC20C00B0000, 0xFFFFFC20C00B2240),
            ),
        )
        self.assertEqual(
            transitions[g17g_postcontrol.QUEUE_ADDRESS_70_PAGE],
            (
                (0x008, 0x001C00005DC00000, 0x000000005DC00000),
                (0x020, 0xA802000000000000, 0x5202000000000000),
                (0x028, 0x0000000648000001, 0x000000087A000003),
            ),
        )
        self.assertEqual(sum(map(len, transitions.values())), 40)

        self.assertEqual(
            g17g_backend.build_second_render_minimal_work_qwords(),
            {
                g17g_postcontrol.ADDRESS_TABLE_PAGE: (
                    (0x208, 0x1, 0x0000000200000001),
                    (0x220, 0x0, 0x0000000100000000),
                    (0x2A0, 0x0, 0xFFFFFC2000000000),
                    (0x2A8, 0x0, 0x00000000010000FF),
                    (0x2B0, 0x0, 0x00000000010000FE),
                    (0x2C0, 0x0, 0x1),
                ),
            },
        )

    def test_first_render_service_history_relocation_uses_live_record(self):
        live_times = (0x728CAEF4, 0x728CAF19, 0x728CAF2F, 0x728CAFC7)
        record = struct.pack(
            "<8Q",
            0x0001000000000013,
            0x20,
            *live_times,
            g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000000,
        )
        page = g17g_backend.build_relocated_first_render_service_history(
            record
        )
        self.assertEqual(len(page), 0x4000)
        self.assertEqual(page[:0x40], record)
        self.assertFalse(any(page[0x40:]))
        complete = (
            g17g_backend.build_relocated_first_render_service_history(
                record, include_fragment=True
            )
        )
        tiling_duration = live_times[3] - live_times[2]
        synthetic_fragment_times = (
            live_times[3] + 0x60,
            live_times[3] + 0x70,
            live_times[3] + 0x78,
            live_times[3] + 0x78 + 4 * tiling_duration,
        )
        self.assertEqual(
            struct.unpack_from("<8Q", complete, 0x40),
            (
                0x0001000000000223,
                0x20,
                *synthetic_fragment_times,
                g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE,
                0xFFFFFC20C0000080,
            ),
        )
        self.assertFalse(any(complete[0x80:]))
        completion = (
            g17g_backend.build_first_render_fragment_completion_qwords(record)
        )
        self.assertEqual(
            completion[g17g_postcontrol.QUEUE_PAGE],
            ((0xE8, 0, 4 * tiling_duration),),
        )
        self.assertEqual(
            completion[g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE],
            (
                (0x2114, 0, synthetic_fragment_times[2]),
                (0x211C, 0, synthetic_fragment_times[3]),
            ),
        )
        self.assertEqual(
            completion[g17g_render.STATUS_A & ~0x3FFF],
            (
                (0xE40, 0, 1),
                (0xE50, 0, synthetic_fragment_times[3]),
            ),
        )
        fragment_times = tuple(value + 0x100 for value in live_times)
        fragment_record = struct.pack(
            "<8Q",
            0x0001000000000223,
            0x20,
            *fragment_times,
            g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000080,
        )
        live_fragment = (
            g17g_backend.build_first_render_fragment_completion_qwords(
                record, fragment_record
            )
        )
        self.assertEqual(
            live_fragment[g17g_postcontrol.QUEUE_PAGE],
            ((0xE8, 0, fragment_times[3] - fragment_times[2]),),
        )
        self.assertEqual(
            live_fragment[g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE],
            (
                (0x2114, 0, fragment_times[2]),
                (0x211C, 0, fragment_times[3]),
            ),
        )
        for bad in (
            record[:-1],
            struct.pack("<Q", 0) + record[8:],
            record[:0x10] + struct.pack("<4Q", 4, 3, 2, 1) + record[0x30:],
            record[:0x30] + struct.pack("<Q", 0) + record[0x38:],
        ):
            with self.assertRaises(ValueError):
                g17g_backend.build_relocated_first_render_service_history(
                    bad
                )
            with self.assertRaises(ValueError):
                g17g_backend.build_first_render_fragment_completion_qwords(
                    bad
                )

    def test_second_direct_render_service_history_preserves_live_records(self):
        first = struct.pack(
            "<8Q",
            0x0001000000000013,
            0x20,
            1, 2, 3, 5,
            g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000000,
        )
        tiling_only = first + bytes(g17g_backend.PAGE_SIZE - len(first))
        synthesized = (
            g17g_backend.build_second_direct_render_service_history(
                tiling_only
            )
        )
        self.assertEqual(synthesized[:len(first)], first)
        self.assertNotEqual(
            synthesized[
                g17g_backend.RENDER_SERVICE_HISTORY_RECORD_SIZE:
                2 * g17g_backend.RENDER_SERVICE_HISTORY_RECORD_SIZE
            ],
            bytes(g17g_backend.RENDER_SERVICE_HISTORY_RECORD_SIZE),
        )
        self.assertEqual(
            g17g_backend.build_second_direct_render_service_history(
                synthesized
            ),
            synthesized,
        )
        stage_one = bytearray(synthesized)
        struct.pack_into("<Q", stage_one, 0x40, 0x0101000000000223)
        self.assertEqual(
            g17g_backend.build_second_direct_render_service_history(
                stage_one
            ),
            bytes(stage_one),
        )

        exhausted = struct.pack(
            "<8Q",
            g17g_backend.RENDER_PARTIAL_FRAGMENT_HISTORY_HEADER,
            0x20,
            0x38238D3A, 0x38238D62, 0x38238D6A, 0x382963A1,
            g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000080,
        )
        exhausted_page = exhausted + bytes(
            g17g_backend.PAGE_SIZE - len(exhausted)
        )
        self.assertEqual(
            g17g_backend.build_second_direct_render_service_history(
                exhausted_page
            ),
            exhausted_page,
        )
        bad_exhausted = bytearray(exhausted_page)
        struct.pack_into("<Q", bad_exhausted, 0x30, 0)
        with self.assertRaisesRegex(ValueError, "exhausted.*targets"):
            g17g_backend.build_second_direct_render_service_history(
                bad_exhausted
            )

    def test_failed_render_history_keeps_observed_descriptor_tags(self):
        page = bytearray(0x4000)
        for i, (header, descriptor, queue) in enumerate((
            (0x0101000000000263, g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE | 1, 0xfffffc20c0000080),
            (0x0001000000000013, g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE, 0xfffffc20c0000000),
            (0x01010000000002e3, g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE | 1, 0xfffffc20c0000080),
        )):
            struct.pack_into("<8Q", page, i * 64, header, 0x20,
                             10 + i * 10, 11 + i * 10, 12 + i * 10, 13 + i * 10,
                             descriptor, queue)
        self.assertEqual(g17g_backend.build_second_direct_render_service_history(
            page, failed_fragment=True), bytes(page))
        self.assertEqual(g17g_backend.build_second_direct_render_service_pages(
            page, failed_fragment=True)[g17g_backend.RENDER_SECOND_SERVICE_HISTORY_PAGE], bytes(page))
        with self.assertRaises(ValueError):
            g17g_backend.build_second_direct_render_service_history(page)
        for offset in (0x30, 0x38, 0xb0):
            bad = bytearray(page)
            bad[offset] ^= 2
            with self.assertRaises(ValueError):
                g17g_backend.build_second_direct_render_service_history(bad, failed_fragment=True)

    def test_partial_render_service_history_preserves_all_live_records(self):
        for continuations in (0, 1, 8, 253):
            headers = ([0x0101000000000263]
                       + [0x01010000000002A3] * continuations
                       + [0x0001000000000013, 0x00010000000002E3])
            records = []
            for index, header in enumerate(headers):
                tiling = header == 0x0001000000000013
                records.append(struct.pack("<8Q", header, 0x20,
                    *range(index * 4 + 1, index * 4 + 5),
                    (g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE if tiling else
                     g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE),
                    0xFFFFFC20C0000000 if tiling else 0xFFFFFC20C0000080))
            body = b"".join(records).ljust(g17g_backend.PAGE_SIZE, b"\0")
            self.assertEqual(g17g_backend.build_second_direct_render_service_history(body), body)
            pages = g17g_backend.build_second_direct_render_service_pages(body)
            self.assertEqual(pages[g17g_backend.RENDER_SECOND_SERVICE_HISTORY_PAGE], body)
            alternate = bytearray(body)
            struct.pack_into("<Q", alternate, (len(records) - 1) * 0x40,
                             0x01010000000002E3)
            self.assertEqual(g17g_backend.preserve_partial_render_service_history(alternate),
                             bytes(alternate))
            for offset, value in ((0, 0), (8, 0), (0x10, 0), (0x30, 0),
                                  (len(records) * 0x40 - 0x40, 0x999)):
                bad = bytearray(body)
                struct.pack_into("<Q", bad, offset, value)
                with self.assertRaises(ValueError):
                    g17g_backend.preserve_partial_render_service_history(bad)
        hole = bytearray(body)
        hole[0x40:0x80] = bytes(0x40)
        with self.assertRaisesRegex(ValueError, "hole"):
            g17g_backend.preserve_partial_render_service_history(hole)

    def test_post_first_render_lifecycle_matches_early_native_boundary(self):
        first_work = (
            g17g_backend.build_first_render_work_lifecycle_qwords()
        )
        self.assertEqual(len(first_work), 8)
        self.assertEqual(sum(map(len, first_work.values())), 18)
        self.assertEqual(
            first_work[0xFFFFFC200002C000],
            ((0x3120, 0x0, 0x0000000000020000),),
        )
        self.assertEqual(
            first_work[g17g_backend.COMPUTE_GLOBAL_SCHEDULER_SLOT],
            ((0x0, 0x0000000100000000, 0x0000000200000000),),
        )
        self.assertEqual(
            first_work[g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS],
            ((0x48, 0x0160800000000068, 0x0160800000000078),),
        )
        self.assertEqual(
            first_work[0xFFFFFC20015F0000],
            (
                (0x8, 0x00001A0000000000, 0x00001E0000000000),
                (0x10, 0x0008000000001A00, 0x0008000000001E00),
            ),
        )

        mixed = g17g_backend.build_first_mixed_render_work_lifecycle_qwords()
        partial = (
            g17g_backend
            .build_first_mixed_partial_render_work_lifecycle_qwords()
        )
        allocator = 0xFFFFFC20015F0000
        self.assertEqual(set(partial), set(mixed))
        self.assertEqual(
            sum(map(len, partial.values())),
            sum(map(len, mixed.values())),
        )
        self.assertEqual(
            [entry for entry in partial[allocator] if entry[0] == 0x20],
            [(0x20, 0x00000000E4010E00, 0x00000000E4010E00)],
        )
        self.assertEqual(
            [entry for entry in partial[allocator] if entry[0] != 0x20],
            [entry for entry in mixed[allocator] if entry[0] != 0x20],
        )
        compute_predecessor = (
            g17g_backend
            .build_compute_predecessor_partial_render_work_lifecycle_qwords()
        )
        self.assertEqual(
            compute_predecessor[0xFFFFFC200002C000],
            (
                (0x3120, 0, 0x0002000000010000),
                (0x31C0, 0, 1),
            ),
        )
        self.assertEqual(
            compute_predecessor[0xFFFFFC20015E8000],
            ((0, 0x0000003000024000, 0x0000003000024000),),
        )
        self.assertEqual(
            compute_predecessor[
                g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS
            ],
            (
                (0x20, 0x00001A0000000000, 0x0000166000000060),
                (0x28, 0x00001A0000000000, 0x0000160000000000),
            ),
        )
        self.assertEqual(
            compute_predecessor[g17g_postcontrol.QUEUE_PAGE],
            ((0x40, 0x00000119FFFFFFFF, 0x00000016FFFFFFFF),),
        )
        self.assertEqual(
            compute_predecessor[g17g_backend.RENDER_OPTIONAL_PAGE],
            ((0x58, 0x0002000001190000, 0x0002000000160000),),
        )
        self.assertEqual(
            compute_predecessor[0xFFFFFC20015F0000][0],
            (0x08, 0x00001A6000000060, 0x0000166000000060),
        )
        inter_epoch = (
            g17g_backend
            .build_compute_predecessor_partial_render_inter_epoch_qwords()
        )
        self.assertEqual(sum(map(len, inter_epoch.values())), 8)
        self.assertEqual(
            inter_epoch[0xFFFFFC20015E8000],
            ((0, 0x0000003000024000, "allocation-lifecycle"),),
        )
        self.assertEqual(
            inter_epoch[0xFFFFFC20015F0000],
            (
                (0x20, 0x00000000E4035400, "allocation-lifecycle"),
                (0x28, 0x0000240000000000, "allocation-lifecycle"),
                (0x30, 0x0008000000002400, "allocation-lifecycle"),
            ),
        )
        self.assertEqual(
            inter_epoch[g17g_backend.RENDER_CHANNEL_RING_PAGES[0]],
            (
                (0x2648, 0xFFFFFC20C0000080, "channel_ring_6"),
                (0x2650, 0x0101000300000000, "channel_ring_6"),
            ),
        )
        self.assertEqual(
            inter_epoch[g17g_backend.RENDER_CHANNEL_RING_PAGES[1]],
            (
                (0x648, 0xFFFFFC20C0000100, "channel_ring_7"),
                (0x650, 0x0102000300000001, "channel_ring_7"),
            ),
        )
        aliases = (
            g17g_backend
            .build_compute_predecessor_partial_render_context0_aliases()
        )
        products = (
            g17g_backend.build_earliest_mixed_partial_render_products(
                compute_predecessor=True
            )
        )
        self.assertEqual(products["firmware_alias_extensions"], aliases)
        self.assertEqual(len(aliases), 16)
        self.assertEqual(
            aliases[g17g_backend.RENDER_MIXED_TILING_CONTEXT_SCRATCH],
            g17g_backend.RENDER_MIXED_TILING_FIRMWARE_SCRATCH,
        )
        self.assertEqual(
            aliases[
                g17g_backend.RENDER_MIXED_FRAGMENT_CONTEXT_SCRATCH
                + 7 * g17g_backend.PAGE_SIZE
            ],
            g17g_backend.RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH
            + 7 * g17g_backend.PAGE_SIZE,
        )
        transitions = (
            g17g_backend.build_post_first_render_lifecycle_qwords()
        )
        self.assertEqual(len(transitions), 17)
        self.assertEqual(sum(map(len, transitions.values())), 52)
        self.assertEqual(
            transitions[0xFFFFFC200002C000][:3],
            (
                (0x3118, 0x0000000600000000, 0x0000000400000000),
                (0x3120, 0x0000000000020000, 0x2),
                (0x31C0, 0x0, 0x1),
            ),
        )
        scheduler = {
            offset: (before, after)
            for offset, before, after in transitions[0xFFFFFC200002C000]
        }
        self.assertEqual(
            scheduler[0x34A8],
            (0x0, 0xFFFFFC20C07D8004),
        )
        self.assertEqual(scheduler[0x33E0], (0x0, 0x2D))
        self.assertEqual(
            transitions[g17g_postcontrol.QUEUE_ADDRESS_70_PAGE],
            (
                (0x20, 0x0002000000000000, 0xA802000000000000),
                (0x28, 0x0, 0x0000000670000001),
            ),
        )
        self.assertEqual(
            transitions[g17g_initdata.REGION_20_ADDRESS],
            ((0x80, 0x0000000100000001, 0x0000000100000000),),
        )
        self.assertEqual(
            transitions[g17g_backend.COMPUTE_GLOBAL_DISPATCH_A],
            ((0x0, 0x0, 0x0000010000000100),),
        )
        self.assertEqual(
            transitions[0xFFFFFC20C08E8000],
            (
                (0x0, 0x0, 0x0000000100000001),
                (0x8, 0x0000000000000001, 0xFFFFFFFF00000001),
            ),
        )
        self.assertEqual(
            transitions[0xFFFFFC20C07A4000],
            (
                (0x3160, 0x0000000200000001, 0x0),
                (0x3168, 0x0000000100000003, 0x0000000100000000),
            ),
        )
        self.assertEqual(
            transitions[g17g_render.FRAGMENT_STATUS],
            (
                (0x0, 0x0, 0x000000D2000006F7),
                (0x10, 0x0, 0x000000D2000006F7),
            ),
        )
        transitions = g17g_backend.build_post_first_render_lifecycle_qwords((
            0x00001E0000000000,
            0x0008000000001E00,
            0x0,
        ))
        self.assertEqual(len(transitions), 18)
        self.assertEqual(sum(map(len, transitions.values())), 55)
        self.assertEqual(
            transitions[g17g_backend.RENDER_POST_FIRST_ALLOCATOR_PAGE],
            (
                (0x8, 0x00001E0000000000, 0x00001F3000000130),
                (0x10, 0x0008000000001E00, 0x0008000000001E00),
                (0x18, 0x0, 0x0),
            ),
        )
        self.assertEqual(
            transitions[g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS],
            (
                (0x40, 0x0000000100000000, 0x0),
                (0x50, 0x00000001FFFFFC20, 0x00000002FFFFFC20),
                (0x20, 0x00001A0000000000, 0x00001F3000000130),
                (0x28, 0x00001A0000000000, 0x00001E0000000000),
            ),
        )
        for resource in (
            0x00001E0000000000,
            0x00001F1800000118,
            0x00001F2000000120,
            0x00001F3800000138,
            0x00001FC0000001C0,
            0x00001FC8000001C8,
            0x00001FD8000001D8,
        ):
            self.assertTrue(
                g17g_backend.is_post_first_render_allocator_resource(resource)
            )
        live_allocator = (
            g17g_backend.build_post_first_render_lifecycle_qwords((
                0x00001F1800000118,
                0x0008000000001E00,
                0x0,
            ))
        )
        self.assertEqual(
            live_allocator[g17g_backend.RENDER_POST_FIRST_ALLOCATOR_PAGE][0],
            (0x8, 0x00001F1800000118, 0x00001F3000000130),
        )
        for allocator in (
            (0x00001E4000000240, 0x0008000000001E00, 0x0),
            (0x00001F1900000118, 0x0008000000001E00, 0x0),
            (0x00003E0000002000, 0x0008000000001E00, 0x0),
            (0x00001E0000000000, 0x00080000000019D9, 0x0),
            (0x00001E0000000000, 0x0008000000001E00, 0x1),
        ):
            with self.assertRaises(ValueError):
                g17g_backend.build_post_first_render_lifecycle_qwords(
                    allocator
                )
        self.assertEqual(
            len({
                address + offset
                for address, entries in transitions.items()
                for offset, _before, _after in entries
            }),
            55,
        )

        minimal = (
            g17g_backend.build_post_first_render_minimal_lifecycle_qwords((
                0x00001E0000000000,
                0x0008000000001E00,
                0x0,
            ))
        )
        self.assertEqual(
            {
                offset: (before, after)
                for offset, before, after in
                minimal[0xFFFFFC200002C000]
            }[0x31C0],
            (0x0, 0x2),
        )
        self.assertNotIn(
            0x3118,
            {
                offset for offset, _before, _after in
                minimal[0xFFFFFC200002C000]
            },
        )
        self.assertEqual(
            {
                offset: (before, after)
                for offset, before, after in
                minimal[0xFFFFFC200002C000]
                if offset in (0x33C0, 0x33E0)
            },
            {0x33C0: (0, 0x2D), 0x33E0: (0, 0x2D)},
        )
        self.assertEqual(
            minimal[g17g_backend.COMPUTE_JOB_LIST_PAGE],
            (
                (0, 0xFFFFFC20C08A8100, 0),
                (8, 0xFFFFFC20C08A8198, 0xFFFFFC2000000000),
            ),
        )
        self.assertEqual(
            minimal[0xFFFFFC20000DC000],
            ((0x2C40, 0x16, 0), (0x2C48, 0x146, 0)),
        )
        self.assertEqual(
            minimal[0xFFFFFC20015E0000],
            ((0x0, 0x400, 0xFF),),
        )
        self.assertEqual(
            minimal[g17g_postcontrol.ADDRESS_TABLE_PAGE][-4:],
            (
                (0x110, 0x0000000100000050, 0x50),
                (0x128, 0xC00188A600000001, 0x0),
                (0x130, 0x00000000FFFFFC20, 0x0),
                (0x190, 0x1, 0x0),
            ),
        )
        self.assertEqual(
            minimal[g17g_backend.RENDER_POST_FIRST_ALLOCATOR_PAGE][0],
            (0x8, 0x00001E0000000000, 0x00001F3800000138),
        )
        self.assertEqual(
            minimal[g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS][-2],
            (0x20, 0x00001A0000000000, 0x00001F3800000138),
        )
        self.assertEqual(
            minimal[g17g_postcontrol.QUEUE_ADDRESS_70_PAGE][-1],
            (0x28, 0x0, 0x0000000648000001),
        )
        for value in (0x60000, 0x90000, 0xFFFF0000):
            self.assertTrue(
                g17g_backend.is_post_first_render_lifecycle_source_value(
                    0xFFFFFC20C0790000, 0x280, value, 0x60000
                )
            )
        for value in (0x10000, 0x90001, 0x100000000):
            self.assertFalse(
                g17g_backend.is_post_first_render_lifecycle_source_value(
                    0xFFFFFC20C0790000, 0x280, value, 0x60000
                )
            )
        rtkstack = int.from_bytes(b"RTKSTACK", "little")
        for offset in range(0x34A0, 0x34D0, 8):
            self.assertTrue(
                g17g_backend.is_post_first_render_lifecycle_source_value(
                    0xFFFFFC200002C000, offset, rtkstack, 0
                )
            )
        for offset, value in (
            (0x000, 0x000000E6000006F7),
            (0x010, 0x000000E6000006F7),
            (0x000, 0x0000018D00000427),
            (0x010, 0x0000018D00000427),
        ):
            self.assertTrue(
                g17g_backend.is_post_first_render_lifecycle_source_value(
                    g17g_render.FRAGMENT_STATUS, offset, value, 0
                )
            )
        for offset, value in (
            (0x020, 0xAB02000000000000),
            (0x028, 0x000000083F000001),
            (0x020, 0xAD02000000000000),
            (0x028, 0x000000582E000001),
            (0x020, 0xE002000000000000),
            (0x028, 0x0000005AD0000001),
        ):
            self.assertTrue(
                g17g_backend.is_post_first_render_lifecycle_source_value(
                    g17g_postcontrol.QUEUE_ADDRESS_70_PAGE,
                    offset,
                    value,
                    0,
                )
            )
        for value in (0x1, 0x100000000):
            self.assertTrue(
                g17g_backend.is_post_first_render_lifecycle_source_value(
                    g17g_postcontrol.ADDRESS_TABLE_PAGE,
                    0x190,
                    value,
                    0x1,
                )
            )

    def test_active_render_service_counter_pairs_are_structural(self):
        page = bytearray(g17g_backend.PAGE_SIZE)
        struct.pack_into("<QQ", page, 0x390, 0x100000007, 7)
        struct.pack_into("<QQ", page, 0x2160, 0x10000000C, 12)
        # Idle and malformed neighbors are not active records.
        struct.pack_into("<QQ", page, 0x3000, 0x100000000, 0)
        struct.pack_into("<QQ", page, 0x3020, 0x100000008, 7)
        self.assertEqual(
            g17g_backend.find_active_render_service_counter_pairs(page),
            ((0x390, 7), (0x2160, 12)),
        )
        with self.assertRaises(ValueError):
            g17g_backend.find_active_render_service_counter_pairs(page[:-1])

    def test_beta5_render_service_record(self):
        record = g17g.build_service_opcode20_record(
            g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS,
            g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
            sequence=1,
            cursor_delta=0x340,
            count=16,
        )
        self.assertEqual(
            record.hex(),
            "20000000010000003f000000010000000000000000008bc020fcffff"
            "00804000720000004083400072000000100000000000000001000000"
            "0000000000000000",
        )

    def test_beta5_render_service_lifecycles_match_native_boundaries(self):
        first = g17g_backend.build_first_render_service_records()
        self.assertEqual(
            tuple(hashlib.sha256(record).hexdigest() for record in first),
            (
                "061e0434dca7e63d2ad660480c9205f0f127e41ed54036938dbc7dbf49576392",
                "061e0434dca7e63d2ad660480c9205f0f127e41ed54036938dbc7dbf49576392",
                "6209b942c92812c6ed62d3040d9e6c185acaf0b179e0ea80567fd40018bcf21b",
            ),
        )
        mixed_clear = g17g_backend.build_first_mixed_clear_service_records()
        self.assertEqual(
            tuple(struct.unpack_from("<I", record)[0] for record in mixed_clear),
            (0x15, 0x15, 0x20),
        )
        self.assertEqual(
            mixed_clear[2].hex(),
            "20000000010000003f000000020000000000000000808bc020fcffff"
            "00804000720000004083400072000000100000000100000001000000"
            "0000000000000000",
        )
        mixed_input = (
            g17g_backend.build_first_mixed_render_service_input_pages()
        )
        mixed_work = (
            g17g_backend.build_first_mixed_render_work_lifecycle_qwords()
        )
        self.assertEqual(tuple(mixed_input), (
            g17g_backend.RENDER_MIXED_SHARED_CONTROL,
        ))
        self.assertEqual(set(mixed_work), {
            g17g_backend.COMPUTE_GLOBAL_SCHEDULER_SLOT,
            0xFFFFFC20015F0000,
            g17g_backend.RENDER_MIXED_SHARED_CONTROL,
            g17g_backend.RENDER_LIVE_ADMISSION_PAGE,
        })
        self.assertEqual(
            mixed_work[g17g_backend.COMPUTE_GLOBAL_SCHEDULER_SLOT],
            ((0x00, 0x0000000100000000, 0x0000000200000000),),
        )
        self.assertEqual(
            mixed_work[0xFFFFFC20015F0000],
            (
                (0x00, 0x00000000E4000000, 0x00000000E4008400),
                (0x08, 0x0000166000000060, 0x0000166000000060),
                (0x10, 0x0008000000001600, 0x0008000000001600),
                (
                    0x20,
                    0x00000000E4000000
                    | (g17g_backend.COMPUTE_MIXED_QUEUE_GENERATION << 8),
                    0x00000000E4000000,
                ),
                (0x28, 0x00001A0000000000, 0x00001E0000000000),
                (0x30, 0x0008000000001A00, 0x0008000000001E00),
            ),
        )
        self.assertEqual(
            mixed_work[g17g_backend.RENDER_MIXED_SHARED_CONTROL][0],
            (0x40, 0x0000000100000000, 0),
        )
        offset, before, after = mixed_work[
            g17g_backend.RENDER_MIXED_SHARED_CONTROL
        ][1]
        self.assertEqual(offset, 0x48)
        self.assertEqual(
            struct.unpack_from("<Q", mixed_input[
                g17g_backend.RENDER_MIXED_SHARED_CONTROL
            ], offset)[0],
            before,
        )
        self.assertEqual(after - before, 0x10)
        self.assertEqual(
            mixed_work[g17g_backend.RENDER_LIVE_ADMISSION_PAGE],
            ((
                g17g_backend.RENDER_LIVE_ADMISSION_QWORD_OFFSET,
                0,
                0x0000002A00001F40,
            ),),
        )
        mixed_transition = (
            g17g_backend.build_mixed_render_compute_service_records()
        )
        self.assertEqual(
            tuple(struct.unpack_from("<III", record) for record in
                  mixed_transition),
            (
                (0x2E, 1, 0),
            ),
        )
        mixed_compute_first = (
            g17g_backend.build_mixed_compute_first_opening_service_records()
        )
        self.assertEqual(
            tuple(struct.unpack_from("<IIII", record) for record in
                  mixed_compute_first),
            (
                (0x15, 0, 0, 0),
                (0x15, 0, 0, 0),
                (0x2E, 1, 0, 0),
            ),
        )
        mixed_repeat_pre = (
            g17g_backend.build_mixed_repeat_pre_render_service_records()
        )
        self.assertEqual(len(mixed_repeat_pre), 1)
        self.assertEqual(
            struct.unpack_from("<Q", mixed_repeat_pre[0], 0x14)[0],
            g17g_backend.RENDER_MIXED_SHARED_CONTROL,
        )
        self.assertEqual(
            struct.unpack_from("<Q", mixed_repeat_pre[0], 0x1C)[0],
            g17g_render.RENDER_OPERAND_TABLE_DVA,
        )
        compute_first_preservice = (
            g17g_backend.
                build_mixed_compute_first_preservice_state_pages()
        )
        self.assertEqual(set(compute_first_preservice), {"before", "after"})
        for phase in ("before", "after"):
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.RENDER_LIVE_ADMISSION_PAGE
                ],
                ((
                    g17g_backend.RENDER_LIVE_ADMISSION_QWORD_OFFSET,
                    struct.pack(
                        "<Q", g17g_backend.RENDER_MIXED_LIVE_ADMISSION
                    ),
                ),),
            )
        self.assertEqual(
            compute_first_preservice["before"][
                g17g_backend.COMPUTE_GLOBAL_SCHEDULER_SLOT
            ],
            ((0x04, b"\0" * 4),),
        )
        self.assertEqual(
            compute_first_preservice["after"][
                g17g_backend.COMPUTE_GLOBAL_SCHEDULER_SLOT
            ],
            ((0x04, struct.pack("<I", 1)),),
        )
        self.assertEqual(
            compute_first_preservice["before"][
                0xFFFFFC20C000C000
            ],
            ((0x10E0, bytes(0x18)),),
        )
        self.assertEqual(
            compute_first_preservice["before"][
                g17g_backend.COMPUTE_ITEM_RING_PAGE
            ],
            ((
                0,
                struct.pack(
                    "<3Q",
                    g17g_backend.COMPUTE_MIXED_OPTIONAL,
                    g17g_backend.COMPUTE_DESCRIPTOR_PAGE,
                    g17g_backend.COMPUTE_EVENT_PAGE,
                ),
            ),),
        )
        for phase in ("before", "after"):
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.COMPUTE_QUEUE_CONTEXT_PAGE
                ],
                ((
                    g17g_compute.compute_queue_context_item_offset(0) + 0x18,
                    struct.pack("<Q", g17g_backend.COMPUTE_QUEUE_PAGE),
                ),),
            )
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.COMPUTE_CHANNEL_RING_PAGE
                ],
                ((
                    g17g_compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET
                    + g17g.RING_SLOT_QUEUE_ADDRESS_OFFSET,
                    struct.pack("<Q", g17g_backend.COMPUTE_QUEUE_PAGE),
                ),),
            )
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.COMPUTE_GLOBAL_DISPATCH_A
                ],
                ((0x04, bytes(8)),),
            )
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.COMPUTE_GLOBAL_SCHEDULER
                    & ~(g17g_backend.PAGE_SIZE - 1)
                ],
                (
                    (0x108, struct.pack("<Q", 1)),
                    (0x120, bytes(8)),
                    (0x1A0, bytes(0x28)),
                ),
            )
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.COMPUTE_GLOBAL_SUPPORT
                ],
                (
                    (0x108, struct.pack("<Q", 0x0000000100000000)),
                    (0x1B8, struct.pack("<Q", 0x00000000010000E5)),
                ),
            )
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.COMPUTE_GLOBAL_ZERO
                ],
                ((0x000, struct.pack("<Q", 1)), (0x010, bytes(8))),
            )
            self.assertEqual(
                compute_first_preservice[phase][
                    g17g_backend.RENDER_MIXED_TILING_STATUS
                ],
                (
                    (0x000, struct.pack("<Q", 0x000000600000082D)),
                    (0x010, struct.pack("<Q", 0x000000600000082D)),
                ),
            )
        queue_idle = dict(compute_first_preservice["before"][
            g17g_backend.COMPUTE_QUEUE_PAGE
        ])
        self.assertEqual(
            struct.unpack("<Q", queue_idle[0x10])[0],
            g17g_backend.COMPUTE_JOB_LIST_PAGE + 0x18,
        )
        self.assertEqual(
            struct.unpack("<Q", queue_idle[0x70])[0],
            g17g_backend.COMPUTE_QUEUE_AUX_PAGE + 0x40,
        )
        self.assertEqual(
            queue_idle[g17g.QUEUE_RECORD_STRIDE + 0x18], bytes(8)
        )
        self.assertEqual(
            queue_idle[2 * g17g.QUEUE_RECORD_STRIDE + 0x18], bytes(8)
        )
        service_control = (
            g17g_backend.build_mixed_compute_first_service_control()
        )
        self.assertEqual(
            compute_first_preservice["before"][
                g17g_backend.RENDER_MIXED_SHARED_CONTROL
            ],
            ((0, service_control),),
        )
        self.assertEqual(
            tuple(
                struct.unpack_from("<I", service_control, offset)[0]
                for offset in (0x00, 0x08, 0x10, 0x48, 0x54, 0x5C, 0x60)
            ),
            (1, 0, 2, 0x58, 1, 1, 2),
        )
        self.assertEqual(
            struct.unpack_from("<Q", service_control, 0x20)[0],
            0x0000166000000060,
        )
        for scratch in (
            g17g_backend.RENDER_MIXED_TILING_FIRMWARE_SCRATCH,
            g17g_backend.RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH,
        ):
            self.assertEqual(
                compute_first_preservice["before"][scratch],
                ((0, bytes(g17g_backend.PAGE_SIZE)),),
            )
        self.assertEqual(
            compute_first_preservice["before"][
                0xFFFFFC2000024000
            ],
            (
                (0x0DE8, bytes(8)),
                (0x0E10, bytes(8)),
                (0x0E20, bytes(8)),
                (0x0E40, struct.pack("<Q", 1)),
                (0x0E58, bytes(0x10)),
            ),
        )
        self.assertEqual(
            compute_first_preservice["after"][
                g17g_backend.RENDER_OPTIONAL_PAGE
            ][0][1][0x36:0x3E],
            struct.pack("<Q", g17g_backend.COMPUTE_MIXED_SHARED_SUPPORT),
        )
        fragment_admission = compute_first_preservice["after"][
            g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE
        ][0][1]
        self.assertEqual(
            tuple(fragment_admission[offset] for offset in (
                0, 0x0C, 0x21D6, 0x21D9, 0x21E7, 0x21EE,
            )),
            (1, 1, 1, 0x77, 2, 4),
        )
        mixed_repeat_post = (
            g17g_backend.build_mixed_repeat_post_render_service_records()
        )
        self.assertEqual(
            hashlib.sha256(b"".join(mixed_repeat_post)).hexdigest(),
            "9e494c7b1bc7393f22d40fc04b622ed7"
            "5cb80c106a9440a123b718f63a151023",
        )
        self.assertEqual(
            g17g_backend.build_first_direct_render_service_records(),
            first[:2],
        )
        second = g17g_backend.build_second_render_service_records()
        self.assertEqual(
            tuple(hashlib.sha256(record).hexdigest() for record in second),
            (
                "5501ff31d57f4b9e8ce7c3cd35f90023531629091a8f38a5dddf2f862104c698",
                "48e1218d0f288fa294fb551faad907ca7b0261cf7d422716b852edd465a5d8b7",
                "a655e23ed3e84384e37a3d9335af618b85b49f55bc15bb9355bbbff100e656d5",
                "dfa1faa79d673a5152ec542f6924211e13b0aabd89c1b62f284943e6d1154b59",
                "9b4acc046bdd94667d1f5975bb781940463fcc78e93cd68fd0db40342cdcc49b",
                "43590b8ce88afc7c6c05f9b42c0a66299e5731151299dd46cbc7e161770de8dc",
                "a39027f07e83d83f25a5fd7ecc8bb8c9c3fe220a3070d85e7be8096617bfcfbf",
                "d3666d3af4094a323a7a0ccca7a7ce6efb6c181cc70a07a8f0e5705877607017",
            ),
        )
        self.assertEqual(
            tuple(struct.unpack_from("<I", record)[0] for record in second),
            (0x2E, 0x2E, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A),
        )
        direct_second = (
            g17g_backend.build_second_direct_render_service_records()
        )
        self.assertEqual(direct_second, (second[0], *second[2:]))
        self.assertEqual(
            tuple(struct.unpack_from("<I", record)[0]
                  for record in direct_second),
            (0x2E, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A),
        )
        compute_to_partial = (
            g17g_backend.build_compute_to_partial_render_service_records()
        )
        self.assertEqual(
            tuple(struct.unpack_from("<I", record)[0]
                  for record in compute_to_partial),
            (0x1A, 0x1A, 0x1A, 0x2E, 0x1A, 0x1A, 0x1A),
        )
        self.assertEqual(
            tuple(hashlib.sha256(record).hexdigest()
                  for record in compute_to_partial),
            (
                "a655e23ed3e84384e37a3d9335af618b85b49f55bc15bb9355bbbff100e656d5",
                "dfa1faa79d673a5152ec542f6924211e13b0aabd89c1b62f284943e6d1154b59",
                "9b4acc046bdd94667d1f5975bb781940463fcc78e93cd68fd0db40342cdcc49b",
                "5501ff31d57f4b9e8ce7c3cd35f90023531629091a8f38a5dddf2f862104c698",
                "43590b8ce88afc7c6c05f9b42c0a66299e5731151299dd46cbc7e161770de8dc",
                "a39027f07e83d83f25a5fd7ecc8bb8c9c3fe220a3070d85e7be8096617bfcfbf",
                "d3666d3af4094a323a7a0ccca7a7ce6efb6c181cc70a07a8f0e5705877607017",
            ),
        )
        first_pages = g17g_backend.build_first_render_service_input_pages()
        self.assertEqual(
            {
                address: hashlib.sha256(body).hexdigest()
                for address, body in first_pages.items()
            },
            {
                0xFFFFFC20C08B0000:
                    "bf6fdf217a08ff1e58e2f2530b80e1ae501ac37e57f14a922dc13c3aaa986de3",
            },
        )
        first_object = first_pages[0xFFFFFC20C08B0000]
        self.assertEqual(struct.unpack_from("<I", first_object, 0x10)[0], 2)
        self.assertEqual(struct.unpack_from("<I", first_object, 0x48)[0], 0x68)
        self.assertEqual(struct.unpack_from("<I", first_object, 0x54)[0], 0)
        self.assertEqual(struct.unpack_from("<I", first_object, 0x60)[0], 3)

    def test_beta5_second_render_service_topology_is_source_built(self):
        pages = g17g_backend.build_second_render_service_pages()
        self.assertEqual(
            {
                address: hashlib.sha256(body).hexdigest()
                for address, body in pages.items()
            },
            {
                0xFFFFFC2001638000:
                    "716ad7538f92bb3cb749146290fa25419ab65b4dfe2cffc980566194d825e0a3",
                0xFFFFFC20C08F0000:
                    "6796fc583c47e181689d6639325c3b50b4d05dd6bbccd9d123b87c4fc0346d1d",
            },
        )
        dvas = g17g_backend.expand_second_render_context1_dvas()
        self.assertEqual(len(dvas), 288)
        retired_dvas = (
            g17g_backend.expand_second_render_retired_context1_dvas()
        )
        self.assertEqual(len(retired_dvas), len(dvas))
        self.assertFalse(set(retired_dvas) & set(dvas))
        context_pages = g17g_backend.second_render_context1_page_images()
        self.assertEqual(
            tuple(
                (address, hashlib.sha256(body).hexdigest())
                for address, body in context_pages.items()
            ),
            (
                (0x7202298000, "3973833467713602606e1e40245b6f9104492bb3ad5320a7c50abcb7ae38c988"),
                (0x720229C000, "b33fb5efea81bb657e989bded36b213abfd7fcc5e1b8b82db87df8179fdfd442"),
                (0x72022A0000, "283e520b9f6eef2976f649a59a734a8560a51b8c8dd60876c96cb2688061ebb1"),
                (0x72022A4000, "44cc69a64014d7885f0d41db7efa47bd8d379733684033a50372a3ceb466b68c"),
                (0x72026A0000, "2c3dde5e1a2d90ab7b595544347411dd1db1fbe943883a6c59c4bc108c4eef79"),
            ),
        )

        direct_dvas = (
            g17g_backend.expand_second_direct_render_context1_dvas()
        )
        self.assertEqual(len(direct_dvas), 294)
        self.assertEqual(
            len(g17g_backend.expand_second_direct_render_high_dvas()),
            12,
        )
        direct_pages = (
            g17g_backend.second_direct_render_context1_page_images()
        )
        self.assertEqual(
            tuple(
                (address, hashlib.sha256(body).hexdigest())
                for address, body in direct_pages.items()
            ),
            (
                (0x72028B0000, "3973833467713602606e1e40245b6f9104492bb3ad5320a7c50abcb7ae38c988"),
                (0x72028B4000, "b33fb5efea81bb657e989bded36b213abfd7fcc5e1b8b82db87df8179fdfd442"),
                (0x72028B8000, "283e520b9f6eef2976f649a59a734a8560a51b8c8dd60876c96cb2688061ebb1"),
                (0x72028BC000, "bb375a21ca7d060ea39c2312c6150e783b53a60cb9d0cf32601ec8083436279b"),
                (0x72028C0000, "ff8acd727ee4ef326e9cd09574b7e8e60613a94868a227ab67af493ec3143ca2"),
                (0x7202CB8000, "8aec68246fe407f83722caacfe697821f83d3b793d0b1bc18e9feed95faa05e0"),
            ),
        )
        direct_service = (
            g17g_backend.build_second_direct_render_service_pages(
                bytes(g17g_backend.PAGE_SIZE)
            )
        )
        self.assertEqual(
            hashlib.sha256(
                direct_service[g17g_backend.RENDER_SECOND_SERVICE_OBJECT]
            ).hexdigest(),
            "4785da5ea2d5c196d5bb2f4b169b1857f765e6ac1457b5b1fc549e8c5b40f5f5",
        )

    def test_controlled_clear_render_products_match_both_native_captures(self):
        cases = (
            (
                g17g_render.G17GClearRenderParameters(
                    target_dva=0x10000018000,
                    clear_state_page=0x10000110000,
                    clear_rgba=(0x11, 0x22, 0x33, 0x44),
                    store_pipeline=0x10000130400,
                    load_pipeline=0x10000130200,
                    auxiliary_object=0x10000248000,
                    tiling_lifecycle=0xC6010000EB,
                ),
                "e2686ae885cbd747c6dfd57462e5147762512845dd92aab59895c8f8518778c8",
                "3dd9a46d6a19c48caed90273064b7c6e41fe23e8a5b9ccff93ccf50550a78bc1",
                "45e4a6ec89d521179ddebc9c4b23f3aad0c2e98bea10dc4aea98070963bbf1aa",
                "3a16e5fffdb95f0deb1218094d15a4445bd3253b980c533e43e87bd42032d97f",
                "3a9653e11132e153649ba8454a60be2b22d795654a337bad1b68341c1ee68298",
            ),
            (
                g17g_render.G17GClearRenderParameters(
                    target_dva=0x10000020000,
                    clear_state_page=0x10000118000,
                    clear_rgba=(0x55, 0x66, 0x77, 0x88),
                    store_pipeline=0x10000138400,
                    load_pipeline=0x10000138200,
                    auxiliary_object=0x10000250000,
                    tiling_lifecycle=0xC7010000EC,
                ),
                "70a2c23365a19b01eceaba747bea9f57ae7601a68989f729d49d6f455d6164dd",
                "03c3149f18e474c738849bed433ff4581780f323c237d17b75600aecfe5197aa",
                "386604d0cf8922eaef48826dd23926232213d0fe4087f7c15af0fa7e69e16a5b",
                "093e86546f2ff3a2fecd9c65d2becb522ce0ccdf49bd51159a52422aec44e019",
                "a8516a1ec0266a66b4763f4e69a7da3554922f51aca228968953f41005685060",
            ),
        )
        for (
            params, page_sha, tiling_sha, fragment_sha,
            tiling_descriptor_sha, fragment_descriptor_sha,
        ) in cases:
            page = g17g_render.build_clear_state_page(params)
            tiling = g17g_render.build_register_array(
                g17g_render.build_tiling_registers(params)
            )
            fragment = g17g_render.build_register_array(
                g17g_render.build_fragment_registers(params)
            )
            tiling_descriptor = g17g_render.build_tiling_descriptor(params)
            fragment_descriptor = g17g_render.build_fragment_descriptor(params)
            self.assertEqual(len(page), 0x4000)
            self.assertEqual(len(tiling), 73 * 12)
            self.assertEqual(len(fragment), 89 * 12)
            self.assertEqual(hashlib.sha256(page).hexdigest(), page_sha)
            self.assertEqual(hashlib.sha256(tiling).hexdigest(), tiling_sha)
            self.assertEqual(hashlib.sha256(fragment).hexdigest(), fragment_sha)
            self.assertEqual(
                hashlib.sha256(tiling_descriptor).hexdigest(),
                tiling_descriptor_sha,
            )
            self.assertEqual(
                hashlib.sha256(fragment_descriptor).hexdigest(),
                fragment_descriptor_sha,
            )

        first = cases[0][0]
        page = g17g_render.build_clear_state_page(first)
        self.assertEqual(struct.unpack_from("<Q", page, 0)[0], 0x10000110020)
        self.assertEqual(
            struct.unpack_from("<Q", page, 0x28)[0],
            0x0003C01000001800,
        )
        self.assertEqual(
            page[0x170:0x180],
            struct.pack(
                "<4f", *(value / 255.0 for value in (0x11, 0x22, 0x33, 0x44))
            ),
        )

    def test_clear_render_builder_rejects_unestablished_geometry(self):
        params = g17g_render.G17GClearRenderParameters(
            target_dva=0x10000018000,
            clear_state_page=0x10000110000,
            clear_rgba=(0x11, 0x22, 0x33, 0x44),
            store_pipeline=0x10000130400,
            load_pipeline=0x10000130200,
            auxiliary_object=0x10000248000,
            tiling_lifecycle=0xC6010000EB,
            width=65,
        )
        with self.assertRaisesRegex(ValueError, "one-page BGRA row stride"):
            g17g_render.build_clear_state_page(params)

    def test_clear_render_derives_subpage_geometry(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        params = dataclasses.replace(baseline, width=32, height=64)
        products = g17g_backend.build_clear_render_products(params)
        tiling = dict(g17g_render.build_tiling_registers(params))
        fragment = dict(g17g_render.build_fragment_registers(params))
        self.assertEqual(tiling[0x10129], 0x003F001F)
        self.assertEqual(tiling[0x101B9], 0x1000)
        self.assertEqual(tiling[0x1CA50], 0x1000)
        self.assertEqual(fragment[0x15131], 0x3D5DB3D9)
        self.assertEqual(fragment[0x15139], 0x3CDDB3D9)
        self.assertEqual(fragment[0x16471], 0x1000)
        self.assertEqual(fragment[0x15211], 0x4000000020)
        self.assertEqual(fragment[0x16068], 0x001002A00003717F)
        self.assertEqual(
            products["context1_writes"][params.resolved_scissor_array()][:16],
            struct.pack("<IIIf", 32, 64, 0, 1.0),
        )

    def test_clear_render_uses_caller_selected_merge_bounds(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        params = dataclasses.replace(
            baseline,
            merge_upper_x_bits=0x3D5DB3D9,
            merge_upper_y_bits=0x3DDDB3D9,
        )
        fragment = dict(g17g_render.build_fragment_registers(params))
        self.assertEqual(fragment[0x15131], 0x3D5DB3D9)
        self.assertEqual(fragment[0x15139], 0x3DDDB3D9)
        self.assertEqual(params.resolved_merge_upper_x_bits(), 0x3D5DB3D9)
        self.assertEqual(params.resolved_merge_upper_y_bits(), 0x3DDDB3D9)

        with self.assertRaisesRegex(ValueError, "merge_upper_x_bits"):
            dataclasses.replace(
                baseline, merge_upper_x_bits=1 << 32
            ).validate()

    def test_clear_render_relocates_caller_program_page(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        program_base = 0x100003A0000
        params = dataclasses.replace(
            baseline,
            load_pipeline=program_base + 0x200,
            store_pipeline=program_base + 0x400,
        )
        products = g17g_backend.build_clear_render_products(params)
        fragment = dict(g17g_render.build_fragment_registers(params))
        self.assertEqual(fragment[0x15371], program_base + 0x200)
        self.assertEqual(fragment[0x15381], program_base + 0x400)
        self.assertEqual(fragment[0x153B9], program_base + 0x400)
        self.assertEqual(
            products["context1_writes"][program_base],
            g17g_render.build_clear_pipeline_page(program_base),
        )
        self.assertEqual(
            g17g_render.build_clear_pipeline_page(program_base),
            g17g_render.build_clear_pipeline_page(),
        )

        with self.assertRaisesRegex(ValueError, "page aligned"):
            g17g_render.build_clear_pipeline_page(program_base + 4)

    def test_partial_render_relocates_all_caller_programs(self):
        native = g17g_backend.build_partial_render_products()
        baseline = native["parameters"]
        program_base = 0x10000420000
        params = dataclasses.replace(
            baseline,
            load_pipeline=program_base + 0x200,
            store_pipeline=program_base + 0x400,
            partial_load_pipeline=program_base,
            partial_store_pipeline=program_base + 0x400,
            scissor_array=baseline.resolved_scissor_array(),
            depth_bias_array=baseline.resolved_depth_bias_array(),
        )
        moved = g17g_backend.build_partial_render_products(
            params,
            direct_draw=g17g_encoder.G17GDirectDraw(
                vertex_pipeline=program_base + 0x700
            ),
        )
        self.assertEqual(moved["program_pages"], (program_base,))
        self.assertEqual(
            moved["context1_writes"][program_base],
            native["context1_writes"][0x100001E8000],
        )
        self.assertEqual(
            moved["context1_writes"][program_base + g17g_backend.PAGE_SIZE],
            bytes(g17g_backend.PAGE_SIZE),
        )
        self.assertNotIn(0x100001E8000, moved["context1_writes"])
        fragment = moved["items"]["fragment_descriptor"]
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x1E80)[0],
            program_base + 0x200,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x1EB0)[0],
            program_base,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x1F7C)[0],
            program_base + 0x400,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x1F9C)[0],
            program_base + 0x400,
        )

        split = g17g_backend.build_partial_render_products(
            dataclasses.replace(
                baseline,
                partial_load_pipeline=program_base,
            )
        )
        self.assertEqual(
            split["program_pages"], (0x100001E8000, program_base)
        )
        self.assertEqual(
            split["context1_writes"][program_base],
            split["context1_writes"][0x100001E8000],
        )

    def test_clear_render_uses_caller_selected_scissor_and_depth_bias_arrays(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        scissor = 0x10000390000
        depth_bias = 0x10000394000
        params = dataclasses.replace(
            baseline,
            scissor_array=scissor,
            depth_bias_array=depth_bias,
        )
        products = g17g_backend.build_clear_render_products(params)
        descriptor = products["items"]["fragment_descriptor"]
        self.assertEqual(
            struct.unpack_from("<Q", descriptor, 0x1D20)[0], depth_bias
        )
        self.assertEqual(
            struct.unpack_from("<Q", descriptor, 0x1D30)[0], scissor
        )
        self.assertEqual(
            products["context1_writes"][scissor],
            g17g_render.build_render_scissor_page(),
        )
        self.assertEqual(
            products["context1_writes"][depth_bias], bytes(0x4000)
        )
        self.assertNotIn(
            baseline.resolved_scissor_array(), products["context1_writes"]
        )
        self.assertNotIn(
            baseline.resolved_depth_bias_array(), products["context1_writes"]
        )

    def test_clear_render_builds_caller_timestamp_outputs(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        base = g17g_render.TIMESTAMP_APERTURE_BASE
        params = dataclasses.replace(
            baseline,
            tiling_user_timestamp_start=base + 0x08,
            tiling_user_timestamp_end=base + 0x10,
            fragment_user_timestamp_start=base + 0x18,
            fragment_user_timestamp_end=base + 0x20,
        )
        products = g17g_backend.build_clear_render_products(params)
        tiling = products["items"]["tiling_descriptor"]
        fragment = products["items"]["fragment_descriptor"]
        self.assertEqual(
            struct.unpack_from("<2Q", tiling, 0x90E),
            (base + 0x08, base + 0x10),
        )
        self.assertEqual(
            struct.unpack_from("<2Q", fragment, 0x21A8),
            (base + 0x18, base + 0x20),
        )
        self.assertEqual(products["fresh_global_pages"][base], bytes(0x4000))
        self.assertEqual(
            tuple(item["name"] for item in products["timestamp_outputs"]),
            ("tiling_start", "tiling_end", "fragment_start", "fragment_end"),
        )

    def test_clear_render_process_empty_tiles_controls_both_descriptor_fields(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        params = dataclasses.replace(baseline, process_empty_tiles=False)
        products = g17g_backend.build_clear_render_products(params)
        fragment = products["items"]["fragment_descriptor"]
        registers = dict(g17g_render.build_fragment_registers(params))
        self.assertEqual(registers[0x10039], 0x280)
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x1F58)[0], 0x280)
        self.assertEqual(fragment[0x2100], 1)
        self.assertEqual(fragment[0x2124], 0)
        self.assertTrue(products["expected_no_target_write"])

        enabled = g17g_backend.build_clear_render_products()
        enabled_fragment = enabled["items"]["fragment_descriptor"]
        self.assertEqual(enabled_fragment[0x2100], 0)
        self.assertEqual(enabled_fragment[0x2124], 1)
        self.assertFalse(enabled["expected_no_target_write"])

    def test_render_no_fallback_builds_only_native_partial_programs(self):
        baseline = g17g_backend.build_partial_render_products()["parameters"]
        enabled = dataclasses.replace(baseline, request_tvb_growth=True)
        disabled = dataclasses.replace(enabled, partial_render_fallback=False)
        before = g17g_render.build_fragment_descriptor(enabled)
        after = g17g_render.build_fragment_descriptor(disabled)
        expected = bytearray(before)
        for start, count in ((0x7C0, 17), (0xEE0, 24), (0x1600, 12)):
            expected[start:start + count * 12] = bytes(count * 12)
            struct.pack_into("<IQ", expected, start, 0x16068, 0x40000)
        for offset in (0xEC8, 0x15E8, 0x1D08):
            struct.pack_into("<I", expected, offset, 1)
        self.assertEqual(after, bytes(expected))
        self.assertEqual(g17g_render.build_tiling_descriptor(enabled),
                         g17g_render.build_tiling_descriptor(disabled))
        with self.assertRaises(ValueError):
            dataclasses.replace(baseline, partial_render_fallback=False).validate()
        with self.assertRaises(ValueError):
            dataclasses.replace(enabled, partial_render_fallback=0).validate()

    def test_fragment_growth_is_independent_of_empty_tiles(self):
        baseline = g17g_backend.build_partial_render_products()["parameters"]
        before = g17g_render.build_fragment_descriptor(baseline)
        after = g17g_render.build_fragment_descriptor(
            dataclasses.replace(baseline, fragment_sync_grow=True))
        expected = bytearray(before)
        expected[0x2100] = 1
        self.assertEqual(after, bytes(expected))
        self.assertEqual(after[0x2124], 1)
        with self.assertRaises(ValueError):
            dataclasses.replace(baseline, fragment_sync_grow=1).validate()

    def test_clear_render_builds_caller_sampler_heap_in_both_descriptors(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        sampler = 0x10000398000
        params = dataclasses.replace(
            baseline, sampler_array=sampler, sampler_count=1
        )
        products = g17g_backend.build_clear_render_products(params)
        tiling = products["items"]["tiling_descriptor"]
        fragment = products["items"]["fragment_descriptor"]
        self.assertEqual(
            struct.unpack_from("<QII", tiling, 0x87A),
            (sampler, 1, 2),
        )
        self.assertEqual(
            struct.unpack_from("<QII", fragment, 0x2114),
            (sampler, 1, 2),
        )
        self.assertEqual(products["context1_writes"][sampler], bytes(0x4000))

        with self.assertRaisesRegex(ValueError, "both be zero or nonzero"):
            dataclasses.replace(baseline, sampler_count=1).validate()

    def test_clear_render_builds_caller_occlusion_query_page(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        query = 0x10000398000
        params = dataclasses.replace(baseline, occlusion_query_base=query)
        products = g17g_backend.build_clear_render_products(params)
        fragment = products["items"]["fragment_descriptor"]
        registers = dict(g17g_render.build_fragment_registers(params))
        self.assertEqual(registers[0x15311], query)
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x1D40)[0], query)
        self.assertEqual(
            products["context1_writes"][query], bytes((0xA5,)) * 0x4000
        )
        self.assertEqual(products["preserved_pages"][0]["base"], query)

    def test_clear_render_builds_uncompressed_depth_stencil_state(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        depth_bits = struct.unpack("<I", struct.pack("<f", 0.25))[0]
        flags = (
            g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL
        )
        params = dataclasses.replace(
            baseline,
            depth_buffer=g17g_backend.RENDER_ZLS_DEPTH_DVA,
            stencil_buffer=g17g_backend.RENDER_ZLS_STENCIL_DVA,
            depth_clear_value_bits=depth_bits,
            stencil_clear_value=0x5A,
            depth_flags=flags,
            depth_dimensions=g17g_render.encode_zls_dimensions(64, 64),
        )
        products = g17g_backend.build_clear_render_products(params)
        registers = dict(g17g_render.build_fragment_registers(params))
        self.assertEqual(registers[0x15321], 0x3F003F)
        self.assertEqual(registers[0x15301], depth_bits)
        self.assertEqual(registers[0x15309], 0x35A)
        self.assertEqual(registers[0x15319], flags)
        self.assertEqual(
            registers[0x15329], g17g_backend.RENDER_ZLS_DEPTH_DVA
        )
        self.assertEqual(
            registers[0x15339], g17g_backend.RENDER_ZLS_STENCIL_DVA
        )
        fragment = products["items"]["fragment_descriptor"]
        self.assertEqual(struct.unpack_from("<I", fragment, 0x1FA8)[0], depth_bits)
        self.assertEqual(struct.unpack_from("<I", fragment, 0x1FAC)[0], 0x35A)
        self.assertEqual(len(products["zls_outputs"]), 2)
        self.assertEqual(
            {item["name"] for item in products["zls_outputs"]},
            {"depth", "stencil"},
        )
        dvas = g17g_backend.render_context1_dvas(products)
        self.assertIn(g17g_backend.RENDER_ZLS_DEPTH_DVA, dvas)
        self.assertIn(g17g_backend.RENDER_ZLS_STENCIL_DVA, dvas)
        expected_depth = struct.pack("<f", 0.25) * (64 * 64)
        expected_stencil = bytes((0x5A,)) * (64 * 64) + bytes(0x3000)
        expected_hashes = {
            "depth": hashlib.sha256(expected_depth).hexdigest(),
            "stencil": hashlib.sha256(expected_stencil).hexdigest(),
        }
        self.assertEqual(
            {
                item["name"]: item["expected_sha256"]
                for item in products["zls_outputs"]
            },
            expected_hashes,
        )

    def test_clear_render_builds_layered_and_multisampled_zls_geometry(self):
        baseline = g17g_backend.build_clear_render_products()["parameters"]
        depth_bits = struct.unpack("<I", struct.pack("<f", 0.25))[0]
        flags = (
            g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL
        )
        cases = (
            {
                "layers": 3, "samples": 1,
                "utile_width": 32, "utile_height": 32,
                "multisample_control": 0x88,
                "depth_stride": 1, "stencil_stride": 1,
                "utile_config": 0xA000, "tib_blocks": 4,
            },
            {
                "layers": 1, "samples": 2,
                "utile_width": 32, "utile_height": 32,
                "multisample_control": 0x44CC,
                "depth_stride": 0, "stencil_stride": 0,
                "utile_config": 0xA001, "tib_blocks": 8,
            },
            {
                "layers": 1, "samples": 4,
                "utile_width": 32, "utile_height": 16,
                "multisample_control": 0xEAA26E26,
                "depth_stride": 0, "stencil_stride": 0,
                "utile_config": 0x6002, "tib_blocks": 8,
            },
        )
        for case in cases:
            with self.subTest(layers=case["layers"], samples=case["samples"]):
                params = dataclasses.replace(
                    baseline,
                    **{
                        name: value for name, value in case.items()
                        if name not in ("utile_config", "tib_blocks")
                    },
                    sample_size=8,
                    depth_buffer=g17g_backend.RENDER_ZLS_DEPTH_DVA,
                    stencil_buffer=(
                        g17g_backend.RENDER_ZLS_STENCIL_ARRAY_DVA
                    ),
                    depth_clear_value_bits=depth_bits,
                    stencil_clear_value=0x5A,
                    depth_flags=flags,
                    depth_dimensions=g17g_render.encode_zls_dimensions(64, 64),
                )
                products = g17g_backend.build_clear_render_products(params)
                tiling = dict(g17g_render.build_tiling_registers(params))
                fragment = dict(g17g_render.build_fragment_registers(params))
                self.assertEqual(
                    params.resolved_utile_config(), case["utile_config"]
                )
                self.assertEqual(
                    params.resolved_tib_blocks(), case["tib_blocks"]
                )
                self.assertEqual(tiling[0x10149], case["utile_config"])
                self.assertEqual(
                    tiling[0x10139], case["multisample_control"]
                )
                self.assertEqual(
                    fragment[0x10019], case["multisample_control"]
                )
                self.assertEqual(fragment[0x10051], case["tib_blocks"])
                self.assertEqual(
                    tiling[0x10169],
                    0xE000 | (case["layers"] - 1)
                    if case["layers"] > 1 else 0x8000,
                )
                self.assertEqual(
                    fragment[0x10039],
                    0x10281 if case["layers"] > 1 else 0x10280,
                )

                planes = max(case["layers"], case["samples"])
                expected_size = planes * 0x4000
                records = {
                    item["name"]: item for item in products["zls_outputs"]
                }
                self.assertEqual(records["depth"]["size"], expected_size)
                self.assertEqual(records["stencil"]["size"], expected_size)
                depth = struct.pack("<I", depth_bits) * (64 * 64 * planes)
                if case["layers"] > 1:
                    stencil = (
                        bytes((0x5A,)) * (64 * 64) + bytes(0x3000)
                    ) * case["layers"]
                else:
                    stencil = (
                        bytes((0x5A,))
                        * (64 * 64 * case["samples"])
                    )
                    stencil += bytes(expected_size - len(stencil))
                self.assertEqual(
                    records["depth"]["expected_sha256"],
                    hashlib.sha256(depth).hexdigest(),
                )
                self.assertEqual(
                    records["stencil"]["expected_sha256"],
                    hashlib.sha256(stencil).hexdigest(),
                )
                for base in (
                    params.depth_buffer, params.stencil_buffer,
                ):
                    for offset in range(0, expected_size, 0x4000):
                        self.assertIn(base + offset, products["context1_writes"])

    def test_clear_render_builds_compressed_zls_roundtrip(self):
        products = (
            g17g_backend.build_prequeued_compressed_zls_roundtrip_products()
        )
        first = products["parameters"]
        second = products["final_parameters"]
        self.assertEqual(products["prequeued_group_count"], 2)
        self.assertEqual(products["prequeued_item_limit"], 6)
        self.assertEqual(
            first.depth_flags,
            g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL
            | g17g_render.ZLS_STORE_DEPTH_COMPRESSED
            | g17g_render.ZLS_STORE_STENCIL_COMPRESSED,
        )
        self.assertEqual(
            second.depth_flags,
            g17g_render.ZLS_LOAD_DEPTH
            | g17g_render.ZLS_LOAD_STENCIL
            | g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL
            | g17g_render.ZLS_LOAD_DEPTH_COMPRESSED
            | g17g_render.ZLS_LOAD_STENCIL_COMPRESSED,
        )
        self.assertEqual(second.depth_clear_value_bits, 0x3F600000)
        self.assertEqual(second.stencil_clear_value, 0xE1)
        self.assertEqual(
            {item["name"] for item in products["zls_outputs"]},
            {"depth", "stencil", "depth_aux", "stencil_aux"},
        )
        outputs = {
            item["name"]: item for item in products["zls_outputs"]
        }
        self.assertIsNone(outputs["depth_aux"]["expected_sha256"])
        self.assertIsNone(outputs["stencil_aux"]["expected_sha256"])
        self.assertTrue(outputs["depth_aux"]["require_changed"])
        self.assertTrue(outputs["stencil_aux"]["require_changed"])
        dvas = set(g17g_backend.render_context1_dvas(products))
        self.assertTrue({
            g17g_backend.RENDER_ZLS_DEPTH_DVA,
            g17g_backend.RENDER_ZLS_STENCIL_DVA,
            g17g_backend.RENDER_ZLS_DEPTH_AUX_DVA,
            g17g_backend.RENDER_ZLS_STENCIL_AUX_DVA,
        } <= dvas)

        sequential = (
            g17g_backend.build_sequential_compressed_zls_roundtrip_products()
        )
        self.assertNotIn("prequeued_group_count", sequential)
        self.assertEqual(
            sequential["parameters"].depth_flags,
            products["parameters"].depth_flags,
        )
        self.assertEqual(
            sequential["repeat_parameters"].depth_flags,
            products["final_parameters"].depth_flags,
        )
        self.assertEqual(
            sequential["repeat_parameters"].clear_state_page,
            sequential["parameters"].clear_state_page,
        )
        self.assertEqual(
            sequential["context1_writes"][
                sequential["repeat_parameters"].clear_state_page
            ],
            g17g_render.build_clear_state_page(sequential["parameters"]),
        )

    def test_clear_render_builds_single_component_compressed_stores(self):
        for component, store, compressed_store in (
            (
                "depth", g17g_render.ZLS_STORE_DEPTH,
                g17g_render.ZLS_STORE_DEPTH_COMPRESSED,
            ),
            (
                "stencil", g17g_render.ZLS_STORE_STENCIL,
                g17g_render.ZLS_STORE_STENCIL_COMPRESSED,
            ),
        ):
            with self.subTest(component=component):
                products = g17g_backend.build_compressed_zls_store_products(
                    component
                )
                self.assertEqual(
                    products["parameters"].depth_flags,
                    store | compressed_store,
                )
                self.assertEqual(
                    {item["name"] for item in products["zls_outputs"]},
                    {component, component + "_aux"},
                )
                self.assertTrue(all(
                    item["expected_sha256"] is None
                    and item["require_changed"]
                    for item in products["zls_outputs"]
                ))
        both = g17g_backend.build_compressed_zls_store_products("both")
        self.assertEqual(
            both["parameters"].depth_flags,
            g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL
            | g17g_render.ZLS_STORE_DEPTH_COMPRESSED
            | g17g_render.ZLS_STORE_STENCIL_COMPRESSED,
        )
        self.assertEqual(
            {item["name"] for item in both["zls_outputs"]},
            {"depth", "depth_aux", "stencil", "stencil_aux"},
        )

    def test_clear_render_builds_compressed_zls_load_replay(self):
        images = {
            name: bytes((index,)) * g17g_render.PAGE_SIZE
            for index, name in enumerate(
                ("depth", "stencil", "depth_aux", "stencil_aux"),
                start=1,
            )
        }
        products = g17g_backend.build_compressed_zls_load_replay_products(
            images
        )
        self.assertEqual(
            {item["name"] for item in products["zls_outputs"]},
            {"depth", "stencil"},
        )
        self.assertEqual(
            products["context1_writes"][
                g17g_backend.RENDER_ZLS_DEPTH_AUX_DVA
            ],
            images["depth_aux"],
        )
        self.assertEqual(
            products["context1_writes"][
                g17g_backend.RENDER_ZLS_STENCIL_AUX_DVA
            ],
            images["stencil_aux"],
        )
        self.assertEqual(
            products["diagnostic_captured_input"]["kind"],
            "same-device-earliest-compressed-store-pages",
        )

    def test_clear_render_builds_uncompressed_zls_repeat_control(self):
        products = (
            g17g_backend.build_sequential_uncompressed_zls_repeat_products()
        )
        first = products["parameters"]
        second = products["repeat_parameters"]
        self.assertEqual(
            first.depth_flags,
            g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL,
        )
        self.assertEqual(second.depth_flags, 0)
        self.assertEqual(second.depth_buffer, 0)
        self.assertEqual(second.stencil_buffer, 0)
        self.assertEqual(second.depth_dimensions, 0)
        self.assertEqual(second.clear_rgba, (0x55, 0x66, 0x77, 0x88))
        self.assertEqual(
            products["context1_writes"][second.clear_state_page],
            g17g_render.build_clear_state_page(first),
        )
        self.assertTrue(products["snapshot_zls_before_repeat"])

    def test_partial_render_scissor_is_independent_of_aux_flag_bit_zero(self):
        params = g17g_backend.build_partial_render_products()["parameters"]
        flagged = dataclasses.replace(
            params,
            aux_fb_flags=(
                params.aux_fb_flags | g17g_render.FRAGMENT_AUX_FLAG_BIT0
            ),
        )
        scissored = dataclasses.replace(
            params,
            scissor_width=64,
            scissor_height=64,
        )

        disabled_registers = dict(
            g17g_render.build_fragment_registers(params)
        )
        flagged_registers = dict(
            g17g_render.build_fragment_registers(flagged)
        )
        self.assertEqual(
            disabled_registers[0x15021],
            g17g_render.FRAGMENT_AUX_FLAGS_BASE,
        )
        self.assertEqual(
            flagged_registers[0x15021],
            g17g_render.FRAGMENT_AUX_FLAGS_BASE
            | g17g_render.FRAGMENT_AUX_FLAG_BIT0,
        )
        self.assertEqual(
            {
                number
                for number in disabled_registers
                if disabled_registers[number] != flagged_registers[number]
            },
            {0x15021},
        )

        products = g17g_backend.build_partial_render_products(
            scissored,
            direct_draw=g17g_encoder.G17GDirectDraw(vertex_count=3),
        )
        bound_state = products["context1_writes"][0x1000068000]
        self.assertEqual(
            struct.unpack_from("<I", bound_state, 0x9C4)[0],
            0x80000001,
        )
        self.assertEqual(
            struct.unpack_from("<I", bound_state, 0x9C8)[0],
            1,
        )
        self.assertEqual(
            products["context1_writes"][scissored.resolved_scissor_array()],
            bytes(g17g_render.PAGE_SIZE),
        )
        self.assertEqual(products["attachment_expectation"], "exact-direct")
        self.assertEqual(
            tuple(
                item["expected_sha256"]
                for item in products["attachments"]
            ),
            g17g_backend
            .PARTIAL_RENDER_SCISSOR_64X64_THREE_VERTEX_ATTACHMENT_SHA256,
        )

        x64 = dataclasses.replace(
            params,
            scissor_x=64,
            scissor_y=0,
            scissor_width=64,
            scissor_height=128,
        )
        products = g17g_backend.build_partial_render_products(
            x64,
            direct_draw=g17g_encoder.G17GDirectDraw(vertex_count=3),
        )
        bound_state = products["context1_writes"][0x1000068000]
        self.assertEqual(
            struct.unpack_from("<I", bound_state, 0x9C4)[0],
            0x80020003,
        )
        self.assertEqual(
            struct.unpack_from("<I", bound_state, 0x9C8)[0],
            3,
        )
        self.assertEqual(products["attachment_expectation"], "exact-direct")
        self.assertEqual(
            tuple(
                item["expected_sha256"]
                for item in products["attachments"]
            ),
            g17g_backend.PARTIAL_RENDER_SCISSOR_X64_THREE_VERTEX_ATTACHMENT_SHA256,
        )

        disabled_descriptor = g17g_render.build_fragment_descriptor(params)
        flagged_descriptor = g17g_render.build_fragment_descriptor(flagged)
        self.assertEqual(
            struct.unpack_from("<Q", disabled_descriptor, 0x1F40)[0],
            g17g_render.FRAGMENT_AUX_FLAGS_BASE,
        )
        self.assertEqual(
            struct.unpack_from("<Q", flagged_descriptor, 0x1F40)[0],
            g17g_render.FRAGMENT_AUX_FLAGS_BASE
            | g17g_render.FRAGMENT_AUX_FLAG_BIT0,
        )
        self.assertEqual(
            {
                offset
                for offset, (before, after) in enumerate(zip(
                    disabled_descriptor, flagged_descriptor
                ))
                if before != after
            },
            {0x194, 0x1F40},
        )

    def test_render_integer_depth_bias_routes_to_both_firmware_fields(self):
        params = g17g_backend.build_clear_render_products()["parameters"]
        integer = dataclasses.replace(params, depth_bias_is_integer=True)
        registers = dict(g17g_render.build_fragment_registers(integer))
        descriptor = g17g_render.build_fragment_descriptor(integer)
        expected = (
            params.aux_fb_flags
            | g17g_render.FRAGMENT_AUX_FLAG_DBIAS_IS_INT
        )
        self.assertEqual(integer.resolved_aux_fb_flags(), expected)
        self.assertEqual(registers[0x15021], expected)
        self.assertEqual(
            struct.unpack_from("<Q", descriptor, 0x1F40)[0], expected
        )
        with self.assertRaisesRegex(ValueError, "must be boolean"):
            dataclasses.replace(
                params, depth_bias_is_integer=1
            ).validate()

    def test_partial_render_items_match_earliest_native_witness(self):
        params = g17g_render.G17GClearRenderParameters(
            target_dva=0x10000058000,
            clear_state_page=0x100001B8000,
            clear_rgba=(0, 0, 0, 0),
            store_pipeline=0x100001E8400,
            load_pipeline=0x100001E8200,
            auxiliary_object=0x10000300000,
            tiling_lifecycle=0xCE010000F3,
            width=128,
            height=128,
            partial_load_pipeline=0x100001E8000,
            partial_store_pipeline=0x100001E8400,
            tib_bytes=32,
            aux_fb_flags=0x10C000,
            partial_mode=True,
        )
        items = g17g_render.build_clear_work_items(params, 0x103)
        self.assertEqual(
            {
                name: hashlib.sha256(body).hexdigest()
                for name, body in items.items()
            },
            {
                "tiling_optional":
                    "d3b979e48ac9d4eeabe95bf884cd4ed2b9408ffdd61b88de9dafc11c2467251e",
                "tiling_descriptor":
                    "a0f4edab42499c38091bc2124d10f5f13c9bb014e4b90ac1260c441900095f0a",
                "tiling_event":
                    "2a93ff98ebbdf0d322f3f7a2efa43382379e3a389ca89e8f9afe27bfa8199ce5",
                "fragment_optional":
                    "6f70377f3c9782331aef706514f3298695e439dc4246daee9b29d6603673fd15",
                "fragment_descriptor":
                    "6de0d14620f3ab2934a1d5dc92ac90dcac32e0b446b4faf2f7cfbd40f4faf7d1",
                "fragment_event":
                    "bcfd6489d1225b79908e7e7c1f6897df5648782d3448534e2249e4ce0e3e9c5e",
            },
        )
        fragment = items["fragment_descriptor"]
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x1EB0)[0],
                         0x100001E8000)
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x1F9C)[0],
                         0x100001E8400)
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x1FAC)[0],
                         0x2000000300)
        self.assertEqual(fragment[0x1FB0], 32)
        address_lists = g17g_render.build_render_address_list_pages(
            operand_count=(
                g17g_render.PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT
            )
        )
        self.assertEqual(
            tuple(hashlib.sha256(body).hexdigest()
                  for body in address_lists.values()),
            g17g_render.PARTIAL_RENDER_ADDRESS_LIST_PAGE_SHA256,
        )
        operand_table = g17g_render.build_render_operand_table(
            operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT
        )
        self.assertEqual(
            hashlib.sha256(operand_table).hexdigest(),
            g17g_render.PARTIAL_RENDER_OPERAND_TABLE_SHA256,
        )

    def test_clear_work_items_select_alternate_shared_control(self):
        base_params = g17g_render.G17GClearRenderParameters(
            target_dva=0x10000058000,
            clear_state_page=0x100001B8000,
            clear_rgba=(0, 0, 0, 0),
            store_pipeline=0x100001E8400,
            load_pipeline=0x100001E8200,
            auxiliary_object=0x10000300000,
            tiling_lifecycle=0xD401000140,
            width=128,
            height=128,
            partial_load_pipeline=0x100001E8000,
            partial_store_pipeline=0x100001E8400,
            tib_bytes=32,
            aux_fb_flags=0x10C000,
            partial_mode=True,
        )
        for ordinal, lifecycle in (
            (4, 0xD401000140),
            (5, 0xD601000159),
        ):
            shared_control = g17g_backend.direct_render_service_object(ordinal)
            items = g17g_render.build_clear_work_items(
                dataclasses.replace(
                    base_params, tiling_lifecycle=lifecycle
                ),
                0x103,
                submission_ordinal=ordinal,
                event_group=ordinal,
                shared_control=shared_control,
            )
            self.assertEqual(
                struct.unpack_from("<Q", items["tiling_optional"], 0x36)[0],
                shared_control,
            )
            self.assertEqual(
                struct.unpack_from("<Q", items["fragment_optional"], 0x36)[0],
                shared_control,
            )
            self.assertEqual(
                struct.unpack_from(
                    "<Q", items["tiling_descriptor"], 0x934
                )[0],
                shared_control,
            )
            self.assertEqual(
                struct.unpack_from(
                    "<Q", items["fragment_descriptor"], 0x21CE
                )[0],
                shared_control,
            )
    def test_render_optional_and_event_products_match_both_captures(self):
        expected = {
            0x146: (
                "b0b665dc8fb450509fe45c1d5b6f278d1769252bec2f1f429ebee71caf53f023",
                "8b3d0740fac60b87216feb422e92ae685406c86e6adee06e20ad81d626b22a90",
            ),
            0x150: (
                "327cb666ef7de64fee5396c98d7d2f4e2a9cc71c8cadc8661e07298947098290",
                "f1fd72767f364d78a512386040166260b2b064a38041c89a90751d99fdff89a1",
            ),
        }
        for token, (tiling_sha, fragment_sha) in expected.items():
            tiling = g17g_render.build_optional_item(
                "tiling",
                0x7200438000,
                0xFFFFFC20001D8000,
                0xFFFFFC20C08B0000,
                0xFFFFFC20C07C0000,
                token,
                0xFFFFFC20C08E8000,
            )
            fragment = g17g_render.build_optional_item(
                "fragment",
                0x7200460000,
                0xFFFFFC2000200000,
                0xFFFFFC20C08B0000,
                0xFFFFFC20C07C0000,
                token,
            )
            self.assertEqual(hashlib.sha256(tiling).hexdigest(), tiling_sha)
            self.assertEqual(hashlib.sha256(fragment).hexdigest(), fragment_sha)

        self.assertEqual(
            hashlib.sha256(g17g_render.build_event_item("tiling")).hexdigest(),
            "2a93ff98ebbdf0d322f3f7a2efa43382379e3a389ca89e8f9afe27bfa8199ce5",
        )
        self.assertEqual(
            hashlib.sha256(g17g_render.build_event_item("fragment")).hexdigest(),
            "bcfd6489d1225b79908e7e7c1f6897df5648782d3448534e2249e4ce0e3e9c5e",
        )

    def test_second_render_optional_token_matches_early_native_work_two(self):
        items = g17g_render.build_clear_work_items(
            g17g_render.G17GClearRenderParameters(
                target_dva=0x10000018000,
                clear_state_page=0x10000110000,
                clear_rgba=(0x55, 0x66, 0x77, 0x88),
                store_pipeline=0x100001301C0,
                load_pipeline=0x10000130100,
                auxiliary_object=0x10000248000,
                tiling_lifecycle=0xC8010000FF,
            ),
            g17g_backend.RENDER_SECOND_TOKEN,
            submission_ordinal=2,
            event_group=2,
        )
        self.assertEqual(
            struct.unpack_from("<H", items["tiling_optional"], 0x5A)[0],
            0xEE,
        )
        self.assertEqual(
            struct.unpack_from("<H", items["fragment_optional"], 0x5A)[0],
            0xEE,
        )

    def test_complete_clear_work_group_matches_both_captures(self):
        cases = (
            (
                g17g_render.G17GClearRenderParameters(
                    0x10000018000, 0x10000110000,
                    (0x11, 0x22, 0x33, 0x44),
                    0x10000130400, 0x10000130200,
                    0x10000248000, 0xC6010000EB,
                ),
                0x146,
                "e7c9fa824c2cbcda74ad1d95301956e878bef7ffa25954246baf81243f6927e9",
            ),
            (
                g17g_render.G17GClearRenderParameters(
                    0x10000020000, 0x10000118000,
                    (0x55, 0x66, 0x77, 0x88),
                    0x10000138400, 0x10000138200,
                    0x10000250000, 0xC7010000EC,
                ),
                0x150,
                "7f36736da7c3e67a117fa25ad0776a97bed2589aac390561c3261d26e39b5418",
            ),
        )
        for params, token, expected_sha in cases:
            items = g17g_render.build_clear_work_items(params, token)
            self.assertEqual(tuple(items), g17g_render.CLEAR_RENDER_ITEM_ORDER)
            self.assertEqual(
                [struct.unpack_from("<I", item)[0] for item in items.values()],
                [15, 0, 14, 15, 1, 14],
            )
            self.assertEqual(sum(map(len, items.values())), 0x2E00)
            self.assertEqual(
                hashlib.sha256(b"".join(items.values())).hexdigest(),
                expected_sha,
            )

    def test_second_clear_group_advances_numeric_item_headers(self):
        params = g17g_render.G17GClearRenderParameters(
            target_dva=0x10000018000,
            clear_state_page=0x10000110000,
            clear_rgba=(0x55, 0x66, 0x77, 0x88),
            store_pipeline=0x100001301C0,
            load_pipeline=0x10000130100,
            auxiliary_object=0x10000248000,
            tiling_lifecycle=0xC8010000FF,
        )
        items = g17g_render.build_clear_work_items(
            params,
            0xEE,
            submission_ordinal=2,
            event_group=2,
        )
        self.assertEqual(
            {
                name: hashlib.sha256(body).hexdigest()
                for name, body in items.items()
            },
            {
                "tiling_optional":
                    "74ff34ea55289ba958239979dfd74533e56d37bd834ba45c6058bf2066016a69",
                "tiling_descriptor":
                    "1d3d2afed293aed20a82eabb2403a5d656e4048bc145795ddbc57359469992da",
                "tiling_event":
                    "05b12074f4d645f49385044240679276ea91913a9a26648da07b756efc1b8b17",
                "fragment_optional":
                    "770c63dbc4274c6d551f185ea609df323c9b8671a3bf71e7d9c3360db81c5a2a",
                "fragment_descriptor":
                    "a0688ab64a530da215bc1db4d5bdcf65b52a8c8294d01b5875d7449b38b15da0",
                "fragment_event":
                    "ba25d2d98d9b41efcae5535bcbf8f14c6d0747c76a1f6effec7367610ca7a786",
            },
        )
        self.assertEqual(
            struct.unpack_from("<IQI", items["tiling_descriptor"], 0),
            (0, 3, 1),
        )

        self.assertEqual(
            struct.unpack_from("<IQI", items["fragment_descriptor"], 0),
            (1, 2, 1),
        )
        for offset in (0xEC, 0xF14, 0x1604, 0x1E78, 0x1EA8):
            self.assertEqual(items["fragment_descriptor"][offset], 0x40)
        self.assertEqual(
            struct.unpack_from("<I", items["tiling_event"], 0x08)[0],
            0x202,
        )
        self.assertEqual(
            struct.unpack_from("<I", items["fragment_event"], 0x08)[0],
            0x202,
        )
        self.assertEqual(
            struct.unpack_from("<Q", items["tiling_descriptor"], 0x760)[0],
            g17g_render.TILING_LOW_ALIAS
            + g17g_render.TILING_DESCRIPTOR_SIZE + 0x60,
        )
        tiling = items["tiling_descriptor"]
        self.assertEqual(
            struct.unpack_from("<Q", tiling, 0x28)[0],
            g17g_render.DESCRIPTOR_OBJECTS[2] + 0x80,
        )
        self.assertEqual(struct.unpack_from("<I", tiling, 0x7A0)[0], 0x200)
        self.assertEqual(struct.unpack_from("<I", tiling, 0x7A8)[0], 2)
        self.assertEqual(struct.unpack_from("<I", tiling, 0x7B0)[0], 0x202)
        self.assertEqual(tiling[0x8B7], 2)
        self.assertEqual(tiling[0x8C6], 2)
        self.assertEqual(tiling[0x8CB], 2)
        self.assertEqual(tiling[0x8D6], 1)
        self.assertEqual(
            struct.unpack_from("<Q", tiling, 0x8FE)[0],
            g17g_render.STATUS_A,
        )
        self.assertEqual(
            struct.unpack_from("<Q", tiling, 0x945)[0],
            g17g_render.TILING_STATUS + 0x40,
        )
        fragment = items["fragment_descriptor"]
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x30)[0],
            g17g_render.DESCRIPTOR_OBJECTS[2] + 0x80,
        )
        self.assertEqual(struct.unpack_from("<Q", fragment, 0x90)[0], 2)
        for offset, target in (
            (0x7A0, 0x0A0),
            (0xEC0, 0x7C0),
            (0x15E0, 0xEE0),
            (0x1D00, 0x1600),
        ):
            self.assertEqual(
                struct.unpack_from(
                    "<Q", items["fragment_descriptor"], offset
                )[0],
                g17g_render.FRAGMENT_LOW_ALIAS
                + g17g_render.FRAGMENT_DESCRIPTOR_SIZE + target,
            )
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2150)[0], 0x200)
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2160)[0], 2)
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2164)[0], 0x200)
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2170)[0], 1)
        self.assertEqual(struct.unpack_from("<I", fragment, 0x2174)[0], 0)
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x2198)[0],
            g17g_render.STATUS_A,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x21A0)[0],
            g17g_render.STATUS_B,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment, 0x21DF)[0],
            g17g_render.FRAGMENT_STATUS + 0x40,
        )
        completed = g17g_render.apply_retained_completion_endpoints(
            items,
            (0x123456789A, 0x12345678FE),
            (0x23456789AB, 0x2345678AFF),
        )
        for offset, value in zip(
            (0x87A, 0x882, 0x95D, 0x965),
            (0x123456789A, 0x12345678FE) * 2,
        ):
            self.assertEqual(
                struct.unpack_from(
                    "<Q", completed["tiling_descriptor"], offset
                )[0],
                value,
            )
        for offset, value in zip(
            (0x2114, 0x211C, 0x21F7, 0x21FF),
            (0x23456789AB, 0x2345678AFF) * 2,
        ):
            self.assertEqual(
                struct.unpack_from(
                    "<Q", completed["fragment_descriptor"], offset
                )[0],
                value,
            )
        for kind in ("tiling_optional", "fragment_optional"):
            optional = items[kind]
            self.assertEqual(struct.unpack_from("<H", optional, 0x1A)[0], 0)
            self.assertEqual(struct.unpack_from("<H", optional, 0x2A)[0], 1)
            self.assertEqual(struct.unpack_from("<H", optional, 0x2E)[0], 0x100)
            self.assertEqual(
                struct.unpack_from("<Q", optional, 0x36)[0],
                g17g_render.SHARED_CONTROL,
            )
            self.assertEqual(struct.unpack_from("<H", optional, 0x3E)[0], 2)
            self.assertEqual(optional[0x40:0x4A], bytes(10))
            self.assertEqual(struct.unpack_from("<H", optional, 0x52)[0], 0)
            self.assertEqual(struct.unpack_from("<H", optional, 0x62)[0], 0)
        self.assertEqual(
            struct.unpack_from("<H", items["tiling_optional"], 0x76)[0],
            1,
        )

    def test_third_partial_group_matches_earliest_native_generation(self):
        products = g17g_backend.build_partial_render_products()
        first = products["parameters"]
        params = g17g_render.build_partial_generation_parameters(
            first, 3
        )
        items = g17g_render.build_clear_work_items(
            params,
            products["token"],
            submission_ordinal=3,
            event_group=3,
        )
        self.assertEqual(params.tiling_lifecycle, 0xD20100010D)
        self.assertEqual(params.store_pipeline, 0x100001E8540)
        self.assertEqual(
            params.resolved_partial_store_pipeline(), 0x100001E8540
        )
        self.assertEqual(params.load_pipeline_bind, 0xFFFF800000000120)
        self.assertEqual(
            params.partial_load_pipeline_bind, 0xFFFF800000000000
        )
        self.assertEqual(
            struct.unpack_from("<H", items["tiling_optional"], 0x3E)[0],
            3,
        )
        self.assertEqual(
            struct.unpack_from("<H", items["fragment_optional"], 0x3E)[0],
            3,
        )
        for name in ("tiling_optional", "fragment_optional"):
            self.assertEqual(
                struct.unpack_from("<H", items[name], 0x2A)[0], 2
            )
            self.assertEqual(
                struct.unpack_from("<H", items[name], 0x2E)[0], 0x200
            )
        self.assertEqual(
            struct.unpack_from("<H", items["tiling_optional"], 0x76)[0], 2
        )
        self.assertEqual(
            {
                name: hashlib.sha256(body).hexdigest()
                for name, body in items.items()
            },
            {
                "tiling_optional":
                    "b34578c15ba772c981236600a090b5a3cf294855c938cadea204e6a2c9ea37f6",
                "tiling_descriptor":
                    "7bd1b37927952e17136c9a41bb3cbf3392273e5973ee2f0c87954580d37bd56c",
                "tiling_event":
                    "c9269e16684bf749469fd146fc2aa64d943b04026b1aefe8cfaea6bf9dc9d46d",
                "fragment_optional":
                    "3cad394ad7c8201b2fbfed4d337f846004784e2e43182e3818c9f7fa0ef259f5",
                "fragment_descriptor":
                    "ef4cd3a6b1bae800dfff5946d560e2cf2b0ea8b96fe3144df3cd0ce47636add0",
                "fragment_event":
                    "e76750e12e58a5781310430f2e41e3512ea0cee55dafe09e7decb9c66f364047",
            },
        )
        self.assertEqual(
            struct.unpack_from("<IQI", items["tiling_descriptor"], 0),
            (0, 5, 1),
        )
        self.assertEqual(
            struct.unpack_from("<IQI", items["fragment_descriptor"], 0),
            (1, 4, 1),
        )
        tiling_registers = dict(
            g17g_render.build_tiling_registers(params, descriptor_index=2)
        )
        fragment_registers = dict(
            g17g_render.build_fragment_registers(params, descriptor_index=2)
        )
        self.assertEqual(tiling_registers[0x1C039], 0x262400)
        self.assertEqual(tiling_registers[0x1CA30], 0x2200C0)
        self.assertEqual(fragment_registers[0x16429], 0x1000262400)
        self.assertEqual(fragment_registers[0x10211], 0x102)

    def test_native_render_allocator_and_scheduler_boundaries(self):
        self.assertEqual(
            [
                g17g_render.render_descriptor_work_index(ordinal)
                for ordinal in (1, 63, 64, 126, 127, 189, 190, 252, 253, 257)
            ],
            [0, 62, 64, 126, 128, 190, 192, 254, 256, 260],
        )
        self.assertEqual(
            [
                g17g_render.render_tiling_allocation_index(ordinal)
                for ordinal in (1, 242, 243, 257)
            ],
            [0, 241, 0, 14],
        )
        self.assertEqual(
            [
                g17g_render.render_fragment_allocation_index(ordinal)
                for ordinal in (1, 241, 242, 257)
            ],
            [0, 240, 0, 15],
        )
        self.assertEqual(
            g17g_render.render_pool_a_allocation(1),
            (1, g17g_render.RENDER_POOL_A_RING_BASE + 0x100),
        )
        self.assertEqual(
            g17g_render.render_pool_a_allocation(36),
            (0, g17g_render.RENDER_POOL_A_RING_BASE),
        )
        self.assertEqual(
            g17g_render.render_pool_a_allocation(257),
            (5, g17g_render.RENDER_POOL_A_RING_BASE + 5 * 0x100),
        )
        self.assertEqual(
            g17g_render.render_pool_b_allocation(80),
            (0, g17g_render.RENDER_POOL_B_RING_BASE),
        )
        self.assertEqual(
            g17g_render.render_pool_b_allocation(257),
            (17, g17g_render.RENDER_POOL_B_RING_BASE + 17 * 0x80),
        )
        self.assertEqual(
            dict(g17g_render.render_pool_a_retired_qwords(1)),
            {
                0x08: 0x200000000,
                0x10: 0x50,
                0x20: 0x100000000,
                0xA0: 0xFFFFFC2000000000,
                0xA8: 0x1000000F3,
                0xB0: 0x1000000F2,
                0xC0: 1,
            },
        )
        retired_221 = dict(g17g_render.render_pool_a_retired_qwords(221))
        self.assertEqual(retired_221[0x08], 0x2000000DF)
        self.assertEqual(retired_221[0xA8], 0x10000039C)
        self.assertEqual(retired_221[0xB0], 0x10000039B)
        retired_257 = dict(g17g_render.render_pool_a_retired_qwords(257))
        self.assertEqual(retired_257[0x08], 0x200000104)
        self.assertEqual(retired_257[0xA8], 0x100000428)
        self.assertEqual(retired_257[0xB0], 0x100000427)
        self.assertEqual(
            g17g_render.render_pool_b_retired_qwords(177),
            ((0x48, 0x100000000),),
        )
        for allocator in (
            g17g_render.render_descriptor_work_index,
            g17g_render.render_tiling_allocation_index,
            g17g_render.render_fragment_allocation_index,
            g17g_render.render_pool_a_allocation,
            g17g_render.render_pool_b_allocation,
        ):
            with self.assertRaisesRegex(ValueError, "ordinal is out of range"):
                allocator(0)

    def test_partial_group_uses_final_identity_before_32_slot_wrap(self):
        products = g17g_backend.build_partial_render_products()
        params = g17g_render.build_partial_generation_parameters(
            products["parameters"], 32
        )
        items = g17g_render.build_clear_work_items(
            params,
            products["token"],
            submission_ordinal=32,
            event_group=32,
            descriptor_index=31,
        )
        self.assertEqual(
            struct.unpack_from("<IQI", items["tiling_descriptor"], 0),
            (0, 63, 1),
        )
        self.assertEqual(
            struct.unpack_from("<IQI", items["fragment_descriptor"], 0),
            (1, 62, 1),
        )
        self.assertEqual(
            struct.unpack_from("<I", items["tiling_descriptor"], 0x7A8)[0],
            32,
        )
        self.assertEqual(
            struct.unpack_from("<I", items["fragment_descriptor"], 0x2170)[0],
            31,
        )
        self.assertEqual(
            struct.unpack_from("<I", items["tiling_event"], 0x08)[0],
            0x2002,
        )
        self.assertEqual(
            struct.unpack_from("<H", items["tiling_optional"], 0x2A)[0],
            31,
        )

        extended = g17g_backend.build_partial_render_products(
            submission_count=64
        )
        self.assertEqual(extended["submission_count"], 64)
        self.assertEqual(
            set(extended["fresh_global_pages"]),
            {
                g17g_render.TILING_FIRMWARE_SCRATCH + 0x4000,
                g17g_render.TILING_FIRMWARE_SCRATCH + 0x8000,
            },
        )
        self.assertEqual(
            len(g17g_render.build_render_queue_context_item(
                "tiling", 0xFFFFFC20C0040000, item_index=31
            )),
            g17g_render.RENDER_QUEUE_CONTEXT_ITEM_SIZE,
        )
        wrapped_context = g17g_render.build_render_queue_context_item(
            "tiling", 0xFFFFFC20C0018000, item_index=32
        )
        self.assertEqual(
            struct.unpack_from("<Q", wrapped_context, 0)[0],
            0x1000000000000084,
        )
        context1_ranges = (
            g17g_render.build_render_recycled_parameter_ranges(0)
        )
        self.assertIn((0x1000260000, 0x1200), context1_ranges)
        context1_ranges = (
            g17g_render.build_render_recycled_parameter_ranges(31)
        )
        self.assertIn((0x1000282E00, 0x1200), context1_ranges)

        wrapped = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 33
            ),
            products["token"],
            submission_ordinal=33,
            event_group=33,
            descriptor_index=32,
            parameter_index=0,
        )
        self.assertEqual(
            struct.unpack_from("<Q", wrapped["tiling_descriptor"], 0x48)[0],
            32,
        )
        self.assertEqual(
            struct.unpack_from("<IQ", wrapped["tiling_descriptor"], 0x3CC),
            (0x10209, 0x120),
        )
        self.assertEqual(wrapped["tiling_descriptor"][0x8D6], 32)
        self.assertEqual(
            struct.unpack_from("<Q", wrapped["tiling_descriptor"], 0x945)[0],
            g17g_render.TILING_STATUS + 32 * 0x40,
        )
        self.assertEqual(
            struct.unpack_from("<Q", wrapped["tiling_descriptor"], 0x10)[0],
            g17g_render.DESCRIPTOR_OBJECTS[0] + 32 * 0x100,
        )
        self.assertEqual(
            struct.unpack_from("<I", wrapped["fragment_descriptor"], 0x2170)[0],
            32,
        )
        self.assertEqual(
            struct.unpack_from("<Q", wrapped["fragment_descriptor"], 0x21DF)[0],
            g17g_render.FRAGMENT_STATUS + 32 * 0x40,
        )
        fragment_registers = dict(g17g_render.build_fragment_registers(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 33
            ),
            descriptor_index=0,
            submission_index=32,
        ))
        self.assertEqual(fragment_registers[0x10211], 0x120)
        self.assertEqual(fragment_registers[0x14080], 0x1000258801)

        generation_36 = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 36
            ),
            products["token"],
            submission_ordinal=36,
            event_group=36,
            descriptor_index=35,
            parameter_index=3,
            pool_a_index=0,
            pool_b_index=35,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_36["tiling_descriptor"], 0x10
            )[0],
            g17g_render.DESCRIPTOR_OBJECTS[0],
        )

        generation_64 = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 64
            ),
            products["token"],
            submission_ordinal=64,
            event_group=64,
            descriptor_index=63,
            parameter_index=31,
            pool_a_index=28,
            pool_b_index=63,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_64["tiling_descriptor"], 0x10
            )[0],
            g17g_render.DESCRIPTOR_OBJECTS[0] + 28 * 0x100,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_64["tiling_descriptor"], 0x28
            )[0],
            g17g_render.DESCRIPTOR_OBJECTS[2] + 63 * 0x80,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_64["fragment_descriptor"], 0x40
            )[0],
            0x1000282E00,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_64["fragment_descriptor"], 0x21DF
            )[0],
            g17g_render.FRAGMENT_STATUS + 63 * 0x40,
        )
        self.assertEqual(g17g_render.RENDER_POOL_A_SLOT_COUNT, 35)
        self.assertEqual(g17g_render.RENDER_POOL_B_SLOT_COUNT, 79)
        self.assertEqual(
            g17g_backend.PARTIAL_RENDER_EXPECTED_PROBE_SHA256,
            "4006e9c271746d5c15d877cc21c4a8b8788e58d36855a1930043dcda5bad5ccb",
        )
        self.assertEqual(g17g_backend.PARTIAL_RENDER_PROBE_PAGE_INDEX, 1)
        self.assertEqual(g17g_backend.PARTIAL_RENDER_PROBE_OFFSET, 0x3E80)
        self.assertEqual(g17g_backend.PARTIAL_RENDER_PROBE_SIZE, 0x80)

        wrapped_storage = g17g_backend.build_partial_render_products(
            submission_count=65
        )
        self.assertEqual(wrapped_storage["submission_count"], 65)
        generation_65 = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 65
            ),
            products["token"],
            submission_ordinal=65,
            event_group=65,
            descriptor_index=64,
            parameter_index=0,
            pool_a_index=29,
            pool_b_index=64,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_65["tiling_descriptor"], 0x760
            )[0],
            (
                g17g_render.TILING_LOW_ALIAS
                + 64 * g17g_render.TILING_DESCRIPTOR_SIZE
                + 0x60
            ),
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_65["fragment_descriptor"], 0x21DF
            )[0],
            g17g_render.FRAGMENT_STATUS + 64 * 0x40,
        )
        self.assertEqual(g17g_render.RENDER_TILING_DESCRIPTOR_COUNT, 256)
        self.assertEqual(g17g_render.RENDER_FRAGMENT_DESCRIPTOR_COUNT, 256)
        for builder in (
            g17g_render.build_tiling_descriptor,
            g17g_render.build_fragment_descriptor,
        ):
            builder(
                products["parameters"], descriptor_index=255,
                submission_index=0, parameter_index=0,
                pool_a_index=0, pool_b_index=0,
            )
            with self.assertRaisesRegex(ValueError, "outside its arena"):
                builder(
                    products["parameters"], descriptor_index=256,
                    submission_index=0, parameter_index=0,
                    pool_a_index=0, pool_b_index=0,
                )
        self.assertEqual(g17g_render.RENDER_SUBMISSION_COUNTER_COUNT, 256)
        self.assertEqual(g17g_render.RENDER_QUEUE_CONTEXT_ITEM_COUNT, 256)
        self.assertEqual(g17g_backend.RENDER_INNER_RING_ITEM_COUNT, 0x500)
        self.assertEqual(
            g17g_backend.RENDER_UNWRAPPED_STREAM_SUBMISSION_LIMIT, 426
        )
        self.assertEqual(
            g17g_backend.RENDER_STREAM_SUBMISSION_LIMIT, 65535
        )
        self.assertEqual(
            g17g_backend.render_inner_ring_group_bounds(426, 1),
            (1275, 1278),
        )
        self.assertFalse(
            g17g_backend.render_inner_ring_needs_recreation(426, 1)
        )
        self.assertTrue(
            g17g_backend.render_inner_ring_needs_recreation(427, 1)
        )
        self.assertEqual(
            g17g_backend.render_inner_ring_group_bounds(3, 3, 0x4FB),
            (1275, 1278),
        )
        self.assertTrue(
            g17g_backend.render_inner_ring_needs_recreation(4, 3, 0x4FB)
        )
        self.assertEqual(
            g17g_render.render_queue_context_item_offset(0), 0x200
        )
        self.assertEqual(
            g17g_render.render_queue_context_item_offset(254), 0x1FE00
        )
        self.assertEqual(
            g17g_render.render_queue_context_item_offset(255), 0
        )
        self.assertEqual(
            g17g.parse_ring_slot(
                g17g_backend.build_render_stream_ring_slot(0, 9)
            )["word_14"],
            0x01000009,
        )
        self.assertEqual(
            g17g.parse_ring_slot(
                g17g_backend.build_render_stream_ring_slot(
                    1, 9, first_submit=False
                )
            )["word_14"],
            0x00010009,
        )
        generation_256 = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 256
            ),
            products["token"],
            submission_ordinal=256,
            event_group=256,
            tiling_descriptor_index=13,
            fragment_descriptor_index=14,
            submission_index=255,
            parameter_index=31,
            pool_a_index=10,
            pool_b_index=18,
        )
        self.assertEqual(generation_256["tiling_descriptor"][0x8B7], 0)
        self.assertEqual(generation_256["tiling_descriptor"][0x8C6], 0)
        self.assertEqual(generation_256["tiling_descriptor"][0x8CB], 0)
        self.assertEqual(generation_256["tiling_descriptor"][0x8D6], 255)
        self.assertEqual(
            struct.unpack_from(
                "<H", generation_256["tiling_optional"], 0x2A
            )[0],
            255,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H", generation_256["tiling_optional"], 0x2E
            )[0],
            0xFF00,
        )

        generation_257 = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 257
            ),
            products["token"],
            submission_ordinal=257,
            event_group=257,
            tiling_descriptor_index=14,
            fragment_descriptor_index=15,
            submission_index=0,
            status_index=0,
            register_status_index=0,
            queue_context_index=256,
            parameter_index=0,
            pool_a_index=5,
            pool_b_index=17,
            pool_a_address=g17g_render.RENDER_POOL_A_RING_BASE + 5 * 0x100,
            pool_b_address=g17g_render.RENDER_POOL_B_RING_BASE + 17 * 0x80,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H", generation_257["tiling_optional"], 0x3E
            )[0],
            257,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H", generation_257["tiling_optional"], 0x2A
            )[0],
            256,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H", generation_257["tiling_optional"], 0x2E
            )[0],
            0,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_257["tiling_descriptor"], 0x48
            )[0],
            260,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", generation_257["tiling_descriptor"], 0x7A8
            )[0],
            257,
        )
        self.assertEqual(generation_257["tiling_descriptor"][0x8D6], 0)
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_257["tiling_descriptor"], 0x945
            )[0],
            g17g_render.TILING_STATUS,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_257["fragment_descriptor"], 0x90
            )[0],
            1,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", generation_257["fragment_descriptor"], 0x2160
            )[0],
            257,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", generation_257["fragment_descriptor"], 0x2170
            )[0],
            256,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", generation_257["tiling_descriptor"], 0x7B0
            )[0],
            0x101,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", generation_257["fragment_descriptor"], 0x2164
            )[0],
            0x100,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_257["tiling_descriptor"], 0x10
            )[0],
            g17g_render.RENDER_POOL_A_RING_BASE + 5 * 0x100,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_257["fragment_descriptor"], 0x30
            )[0],
            g17g_render.RENDER_POOL_B_RING_BASE + 17 * 0x80,
        )
        self.assertEqual(
            struct.unpack_from(
                "<IQ", generation_257["tiling_descriptor"], 0x3CC
            ),
            (0x10209, 0x104),
        )
        fragment_primary = dict(
            struct.unpack_from(
                "<IQ",
                generation_257["fragment_descriptor"],
                0xA0 + index * 12,
            )
            for index in range(g17g_render.FRAGMENT_REGISTER_COUNT)
        )
        self.assertEqual(fragment_primary[0x10211], 0x104)
        self.assertEqual(fragment_primary[0x10420], 0x104)
        generation_257_monotonic_status = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 257
            ),
            products["token"],
            submission_ordinal=257,
            event_group=257,
            descriptor_index=0,
            submission_index=0,
            status_index=256,
            register_status_index=256,
            queue_context_index=0,
            parameter_index=0,
            pool_a_index=11,
            pool_b_index=19,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q",
                generation_257_monotonic_status["tiling_descriptor"],
                0x945,
            )[0],
            g17g_render.TILING_STATUS + g17g_render.PAGE_SIZE,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q",
                generation_257_monotonic_status["fragment_descriptor"],
                0x21DF,
            )[0],
            g17g_render.FRAGMENT_STATUS + g17g_render.PAGE_SIZE,
        )
        generation_257_monotonic_queue_context = (
            g17g_render.build_clear_work_items(
                g17g_render.build_partial_generation_parameters(
                    products["parameters"], 257
                ),
                products["token"],
                submission_ordinal=257,
                event_group=257,
                descriptor_index=0,
                submission_index=0,
                status_index=0,
                register_status_index=0,
                queue_context_index=256,
                parameter_index=0,
                pool_a_index=11,
                pool_b_index=19,
            )
        )
        self.assertEqual(
            struct.unpack_from(
                "<H",
                generation_257_monotonic_queue_context["tiling_optional"],
                0x2A,
            )[0],
            256,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H",
                generation_257_monotonic_queue_context["tiling_optional"],
                0x2E,
            )[0],
            0,
        )
        generation_257_wrapped_stamps = g17g_render.build_clear_work_items(
            g17g_render.build_partial_generation_parameters(
                products["parameters"], 257
            ),
            products["token"],
            submission_ordinal=257,
            event_group=257,
            descriptor_index=0,
            submission_index=0,
            status_index=0,
            register_status_index=0,
            work_stamp_index=0,
            queue_context_index=0,
            parameter_index=0,
            pool_a_index=11,
            pool_b_index=19,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", generation_257_wrapped_stamps["tiling_descriptor"],
                0x48,
            )[0],
            260,
        )
        self.assertEqual(
            struct.unpack_from(
                "<IQ", generation_257_wrapped_stamps["tiling_descriptor"],
                0x3CC,
            ),
            (0x10209, 0x100),
        )
        fragment_primary = dict(
            struct.unpack_from(
                "<IQ",
                generation_257_wrapped_stamps["fragment_descriptor"],
                0xA0 + index * 12,
            )
            for index in range(g17g_render.FRAGMENT_REGISTER_COUNT)
        )
        self.assertEqual(fragment_primary[0x10211], 0x100)
        self.assertEqual(fragment_primary[0x10420], 0x100)
        queue_context_257 = g17g_render.build_render_queue_context_item(
            "tiling",
            g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE,
            item_index=256,
            descriptor_index=0,
        )
        self.assertEqual(
            struct.unpack_from("<Q", queue_context_257, 0x00)[0],
            0x1000000000000404,
        )
        self.assertEqual(
            struct.unpack_from("<Q", queue_context_257, 0x28)[0], 256
        )
        tiling_context_extension = (
            g17g_render.TILING_FIRMWARE_SCRATCH
            + 8 * g17g_render.PAGE_SIZE
        )
        fragment_context_extension = (
            g17g_render.FRAGMENT_FIRMWARE_SCRATCH
            + 8 * g17g_render.PAGE_SIZE
        )
        products_255 = g17g_backend.build_partial_render_products(
            submission_count=255
        )
        self.assertNotIn(
            fragment_context_extension, products_255["fresh_global_pages"]
        )
        products_257 = g17g_backend.build_partial_render_products(
            submission_count=257
        )
        self.assertEqual(products_257["submission_count"], 257)
        self.assertIn(
            g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_PAGE,
            products_257["fresh_global_pages"],
        )
        self.assertNotIn(
            tiling_context_extension,
            products_257["fresh_global_pages"],
        )
        self.assertNotIn(
            fragment_context_extension,
            products_257["fresh_global_pages"],
        )
        self.assertIn(
            g17g_render.TILING_STATUS + g17g_render.PAGE_SIZE,
            products_257["fresh_global_pages"],
        )
        self.assertIn(
            g17g_render.FRAGMENT_STATUS + g17g_render.PAGE_SIZE,
            products_257["fresh_global_pages"],
        )
        self.assertIn(
            g17g_render.TILING_REGISTER_STATUS + g17g_render.PAGE_SIZE,
            products_257["context1_writes"],
        )
        self.assertIn(
            g17g_render.FRAGMENT_REGISTER_STATUS + g17g_render.PAGE_SIZE,
            products_257["context1_writes"],
        )
        products_max = g17g_backend.build_partial_render_products(
            submission_count=g17g_backend.RENDER_STREAM_SUBMISSION_LIMIT
        )
        self.assertEqual(products_max["submission_count"], 65535)
        self.assertEqual(
            set(products_max["fresh_global_pages"]),
            set(products_257["fresh_global_pages"]),
        )
        self.assertEqual(
            set(products_max["context1_writes"]),
            set(products_257["context1_writes"]),
        )
        self.assertEqual(
            products_257["descriptor_alias_extensions"],
            {
                g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_LOW_ALIAS:
                    g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_PAGE,
                g17g_backend.RENDER_TILING_DESCRIPTOR_EXTENSION_LOW_ALIAS:
                    g17g_backend.RENDER_TILING_DESCRIPTOR_EXTENSION_PAGE,
            },
        )

    def test_render_operand_tables_match_native_first_clear(self):
        table = g17g_render.build_render_operand_table()
        self.assertEqual(
            hashlib.sha256(table).hexdigest(),
            "24dcb79592fa08a16c3b3ae891584b0a8d94b84643db5456ce368f5f2c649930",
        )
        for index in range(g17g_render.RENDER_OPERAND_COUNT):
            self.assertEqual(
                struct.unpack_from("<Q", table, index * 0x40)[0],
                g17g_render.RENDER_OPERAND_FLAG
                + g17g_render.RENDER_OPERAND_BASE
                + index * g17g_render.RENDER_OPERAND_STRIDE,
            )
        pages = g17g_render.build_render_address_list_pages()
        self.assertEqual(tuple(pages), g17g_render.RENDER_ADDRESS_LIST_PAGE_DVAS)
        self.assertEqual(
            tuple(hashlib.sha256(page).hexdigest() for page in pages.values()),
            g17g_render.RENDER_ADDRESS_LIST_PAGE_SHA256,
        )
        service_input = g17g_render.build_render_address_list_pages(
            operand_count=g17g_render.RENDER_SERVICE_INPUT_OPERAND_COUNT,
        )
        self.assertEqual(
            tuple(
                hashlib.sha256(page).hexdigest()
                for page in service_input.values()
            ),
            g17g_render.RENDER_SERVICE_INPUT_ADDRESS_LIST_PAGE_SHA256,
        )
        self.assertEqual(
            service_input[g17g_render.RENDER_ADDRESS_LIST_PAGE_DVAS[-1]][
                0x1000:
            ],
            bytes(0x3000),
        )
        entries = b"".join(pages.values())
        self.assertEqual(
            struct.unpack_from("<Q", entries, 0)[0],
            g17g_render.RENDER_OPERAND_BASE,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", entries,
                (g17g_render.RENDER_OPERAND_COUNT * 512 - 1) * 8,
            )[0],
            g17g_render.RENDER_OPERAND_BASE
            + (g17g_render.RENDER_OPERAND_COUNT - 1)
            * g17g_render.RENDER_OPERAND_STRIDE
            + g17g_render.RENDER_OPERAND_SIZE - 0x1000,
        )
        self.assertEqual(
            hashlib.sha256(
                g17g_render.build_render_base10_support_page()
            ).hexdigest(),
            "5a60b7f2e7fa473d96676e42fca6cddef0bf1dd22f442601d8a46e4313774a19",
        )
        self.assertEqual(
            hashlib.sha256(g17g_render.build_render_scissor_page()).hexdigest(),
            "e9d9fead6415e57ff85007d22cb95c5a87e82479b54cdc4085b142cbdc16cf3c",
        )
        self.assertEqual(
            hashlib.sha256(g17g_render.build_clear_pipeline_page()).hexdigest(),
            "02a724e4695d2308389f7d4dcd768478df3d5fc299ffac2cac77acce06cbc873",
        )
        self.assertEqual(
            hashlib.sha256(g17g_render.build_clear_pipeline_page(
                g17g_render.CLEAR_PIPELINE_DIFFERENTIAL_BASE
            )).hexdigest(),
            "fc046bc303299933bf63cfab64b810e6864a8c807f971bbbd4d9012f382fcda1",
        )
        self.assertEqual(
            hashlib.sha256(g17g_render.build_clear_pipeline_page(
                g17g_render.CLEAR_PIPELINE_MIXED_BASE
            )).hexdigest(),
            "bbbbae536612fbb5387f210b5d954903b29b079b031499a3d94ee5f2da0ceb46",
        )
        self.assertEqual(
            hashlib.sha256(g17g_render.build_clear_pipeline_page(
                g17g_render.CLEAR_PIPELINE_MIXED_BASE, 1
            )).hexdigest(),
            "b03dc9b62b0b158d137880582085a8d2935d6dc7043fcf72cea76d3648ff25cc",
        )

    def test_host_clear_products_match_native_first_clear_pages(self):
        products = g17g_backend.build_clear_render_products()
        self.assertEqual(
            products["format"],
            "m1n1-t8142-g17g-host-clear-products-v1",
        )
        self.assertTrue(products["submission_ready"])
        self.assertFalse(products["execution_validated"])
        self.assertIsNone(products["captured_input"])
        self.assertEqual(products["channels"], (6, 7))
        expected = {
            "queue": "a04d6bf9b9a6dec0b68f6d1d0e6344c7ca877a0544ff544eb413a8591d517af6",
            "pointers": "6829cadf3e269b55ecc52283db3a7a34ac6ca61b30a349fed99f414988d50792",
            "item_ring": "de4f4ffe8926cf839cb53da3312ef997551c64e25b1c3444d47fcfb42f6c7dcf",
            "optional": "4849f31c5ec3ce11ea9cc190ae93de3496c0933b6d6cf71c74257177429737e8",
            "event": "b5353e23d8c8dfd5fdb29b3dcb7a77ca21aff96a98d58905755e5d1202691f5d",
            "tiling_descriptor": "c08c50a27ad7612d9feba9cc6b51e0e24a554c568d33a033fcef267da38e64a4",
            "fragment_descriptor": "fdd5468e9147f6efcf06d6e5da991e601ef66ff2e45c780d2fb937207507a3ca",
        }
        self.assertEqual(
            {
                name: hashlib.sha256(body).hexdigest()
                for name, body in products["firmware_pages"].items()
            },
            expected,
        )
        self.assertTrue(all(
            len(body) == g17g_backend.PAGE_SIZE
            for body in products["firmware_pages"].values()
        ))
        self.assertEqual(products["missing_dependencies"], {})
        compiler_pages = g17g_render_compiler.build_clear_compiler_pages()
        self.assertEqual(
            {
                dva: hashlib.sha256(body).hexdigest()
                for dva, body in compiler_pages.items()
            },
            g17g_render_compiler.CLEAR_COMPILER_PAGE_SHA256,
        )
        self.assertEqual(
            {
                dva: products["context1_writes"][dva]
                for dva in compiler_pages
            },
            compiler_pages,
        )
        self.assertIn(0x10000018000, products["context1_writes"])
        self.assertEqual(
            products["context1_writes"][0x10000018000],
            bytes(g17g_backend.PAGE_SIZE),
        )
        self.assertEqual(len(products["source_global_pages"]), 13)
        self.assertEqual(
            len(g17g_render.expand_render_context1_dvas()), 2491
        )
        self.assertEqual(
            len(g17g_render.expand_render_context1_read_only_dvas()), 108
        )
        self.assertEqual(len(g17g_backend.render_context1_mapping_runs()), 52)
        self.assertEqual(
            len(g17g_backend.RENDER_SOURCE_RETIRED_GLOBAL_PAGES), 10
        )
        self.assertEqual(
            len(g17g_backend.RENDER_SOURCE_NEW_ZERO_GLOBAL_PAGES), 10
        )
        self.assertEqual(
            set(g17g_backend.RENDER_SOURCE_NEW_ZERO_GLOBAL_PAGES),
            set(g17g_backend.RENDER_PRE_SERVICE_NEW_ZERO_GLOBAL_PAGES)
            | set(g17g_backend.RENDER_POST_SERVICE_NEW_ZERO_GLOBAL_PAGES),
        )
        self.assertEqual(
            len(g17g_backend.RENDER_PRE_SERVICE_RETIRED_GLOBAL_PAGES), 4
        )
        self.assertEqual(
            len(g17g_backend.RENDER_PRE_SERVICE_NEW_ZERO_GLOBAL_PAGES), 4
        )
        self.assertEqual(
            len(g17g_backend.RENDER_POST_SERVICE_NEW_ZERO_GLOBAL_PAGES), 6
        )
        self.assertFalse(
            set(g17g_backend.RENDER_PRE_SERVICE_NEW_ZERO_GLOBAL_PAGES)
            & set(g17g_backend.RENDER_POST_SERVICE_NEW_ZERO_GLOBAL_PAGES)
        )
        self.assertFalse(
            set(g17g_backend.RENDER_PRE_SERVICE_RETIRED_GLOBAL_PAGES)
            & set(g17g_backend.RENDER_SOURCE_NEW_ZERO_GLOBAL_PAGES)
        )
        self.assertFalse(
            set(g17g_backend.RENDER_SOURCE_RETIRED_GLOBAL_PAGES)
            & set(g17g_backend.RENDER_SOURCE_NEW_ZERO_GLOBAL_PAGES)
        )
        known_pages = g17g_backend.render_context1_page_images(products)
        self.assertEqual(len(known_pages), 23)
        self.assertFalse(
            set(known_pages) & set(g17g_context1.POSTCONTROL_ALIASES)
        )
        self.assertEqual(
            hashlib.sha256(known_pages[0x10000000000]).hexdigest(),
            "2feff6090c157480c9a73f07d3ff5b229093359166799c97e147838cb2c66996",
        )
        self.assertTrue(all(
            len(body) == g17g_backend.PAGE_SIZE
            for body in known_pages.values()
        ))

    def test_host_partial_products_are_capture_independent(self):
        products = g17g_backend.build_partial_render_products()
        self.assertEqual(
            products["format"],
            "m1n1-t8142-g17g-host-partial-render-products-v1",
        )
        self.assertTrue(products["submission_ready"])
        self.assertTrue(products["partial_render"])
        self.assertIsNone(products["captured_input"])
        self.assertEqual(products["token"], 0x103)
        self.assertEqual(len(products["attachments"]), 8)
        self.assertEqual(len(products["attachment_pages"]), 32)
        pages = g17g_backend.render_context1_page_images(products)
        self.assertTrue(all(
            not any(pages[address])
            for address in products["attachment_pages"]
        ))
        self.assertTrue(
            set(pages) <= set(g17g_backend.render_context1_dvas(products))
        )
        self.assertNotIn(
            g17g_backend.PARTIAL_RENDER_POSTCONTROL_ALIAS_DVA, pages
        )
        self.assertEqual(
            tuple(
                attachment["expected_sha256"]
                for attachment in products["attachments"]
            ),
            g17g_backend.PARTIAL_RENDER_EXPECTED_ATTACHMENT_SHA256,
        )
        self.assertEqual(
            len(g17g_backend.render_context1_dvas(products)),
            g17g_render.PARTIAL_RENDER_CONTEXT1_PAGE_COUNT,
        )
        self.assertGreater(
            len(g17g_backend.render_context1_mapping_runs(products)),
            len(g17g_backend.render_context1_mapping_runs()),
        )

        permission_changes = (
            g17g_backend.render_context1_permission_changes(
                g17g_compute.expand_compute_context1_dvas(),
                g17g_compute.expand_compute_context1_read_only_dvas(),
                products,
            )
        )
        self.assertEqual(len(permission_changes["to_read_only"]), 7)
        self.assertEqual(
            permission_changes["to_writable"],
            (
                0x10000018000, 0x1000001C000,
                0x10000020000, 0x10000024000,
                0x100000B8000, 0x100000BC000,
                0x100000D8000, 0x100000DC000,
                0x100000E8000, 0x100000EC000,
                0x10000108000, 0x1000010C000,
                0x10000128000, 0x1000012C000,
            ),
        )

    def test_host_partial_products_accept_bounded_operand_prefix(self):
        products = g17g_backend.build_partial_render_products(
            operand_count=1
        )
        self.assertEqual(products["operand_count"], 1)
        table = products["context1_writes"][
            g17g_render.RENDER_OPERAND_TABLE_DVA
        ]
        self.assertNotEqual(struct.unpack_from("<Q", table, 0)[0], 0)
        self.assertFalse(any(table[0x40:]))
        address_pages = g17g_render.build_render_address_list_pages(
            operand_count=1
        )
        self.assertEqual(
            sum(
                struct.unpack_from("<Q", body, offset)[0] != 0
                for body in address_pages.values()
                for offset in range(0, len(body), 8)
            ),
            g17g_render.RENDER_ADDRESS_ENTRIES_PER_OPERAND,
        )
        for operand_count in (-1, 19):
            with self.assertRaises(ValueError):
                g17g_backend.build_partial_render_products(
                    operand_count=operand_count
                )

    def test_host_partial_products_can_isolate_first_address_list_page(self):
        products = g17g_backend.build_partial_render_products(
            address_list_hole=True
        )
        first = g17g_render.RENDER_ADDRESS_LIST_PAGE_DVAS[0]
        full = g17g_render.build_render_address_list_pages(
            operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT
        )
        self.assertEqual(products["operand_count"], 18)
        self.assertEqual(products["address_list_hole"], first)
        self.assertEqual(products["context1_writes"][first], bytes(0x4000))
        for address in g17g_render.RENDER_ADDRESS_LIST_PAGE_DVAS[1:]:
            self.assertEqual(
                products["context1_writes"][address], full[address]
            )
        self.assertEqual(
            products["context1_writes"][
                g17g_render.RENDER_OPERAND_TABLE_DVA
            ],
            g17g_render.build_render_operand_table(
                operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT
            ),
        )
        with self.assertRaises(ValueError):
            g17g_backend.build_partial_render_products(
                operand_count=1, address_list_hole=True
            )

    def test_partial_operand_growth_preserves_firmware_live_bytes(self):
        old = bytearray(0x4000)
        grown = bytearray(old)
        grown[0:4] = b"grow"
        live = bytearray(old)
        live[0x100:0x104] = b"firm"
        live[1] = 0xFF
        merged = g17g_render.merge_render_operand_growth_page(
            live, old, grown
        )
        self.assertEqual(merged[:4], b"grow")
        self.assertEqual(merged[0x100:0x104], b"firm")
        self.assertFalse(any(merged[4:0x100]))
        with self.assertRaises(ValueError):
            g17g_render.merge_render_operand_growth_page(
                bytes(0x100), old, grown
            )

    def test_partial_growth_service_reuses_observed_slot_three_record(self):
        growth = g17g_backend.build_partial_render_growth_service_records()
        self.assertEqual(
            growth,
            (g17g_backend.build_first_render_service_records()[2],),
        )
        self.assertEqual(struct.unpack_from("<I", growth[0], 0)[0], 0x20)
        self.assertEqual(struct.unpack_from("<I", growth[0], 0x0C)[0], 1)
        self.assertEqual(struct.unpack_from("<I", growth[0], 0x2C)[0], 16)

    def test_host_partial_products_accept_caller_direct_draw(self):
        products = g17g_backend.build_partial_render_products(
            direct_draw=g17g_encoder.G17GDirectDraw(vertex_count=3)
        )
        self.assertEqual(products["attachment_expectation"], "exact-direct")
        self.assertEqual(products["direct_draw"]["vertex_count"], 3)
        self.assertEqual(
            tuple(
                item["expected_sha256"] for item in products["attachments"]
            ),
            g17g_backend.PARTIAL_RENDER_THREE_VERTEX_ATTACHMENT_SHA256,
        )
        self.assertEqual(
            len(
                g17g_backend
                .PARTIAL_RENDER_ONE_TRIANGLE_ATTACHMENT_SHA256
            ),
            g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT,
        )
        command = products["context1_writes"][
            g17g_encoder.VDM_STREAM_DVA
        ]
        self.assertEqual(struct.unpack_from("<I", command, 0x90)[0], 3)
        self.assertNotEqual(
            hashlib.sha256(command).hexdigest(),
            g17g_encoder.NATIVE_PARTIAL_PAGE_SHA256,
        )
        repeated = g17g_backend.build_partial_render_products(
            submission_count=2,
            direct_draw=g17g_encoder.G17GDirectDraw(vertex_count=3),
        )
        self.assertEqual(repeated["submission_count"], 2)
        self.assertEqual(repeated["attachment_expectation"], "exact-direct")
        self.assertEqual(
            tuple(
                item["expected_sha256"]
                for item in repeated["attachments"]
            ),
            g17g_backend.PARTIAL_RENDER_THREE_VERTEX_ATTACHMENT_SHA256,
        )
        unknown = g17g_backend.build_partial_render_products(
            direct_draw=g17g_encoder.G17GDirectDraw(vertex_count=9)
        )
        self.assertEqual(unknown["attachment_expectation"], "changed")
        self.assertTrue(all(
            item["expected_sha256"] is None for item in unknown["attachments"]
        ))
        for draw in (
            g17g_encoder.G17GDirectDraw(vertex_count=6),
            g17g_encoder.G17GDirectDraw(vertex_count=3, instance_count=2),
        ):
            six = g17g_backend.build_partial_render_products(direct_draw=draw)
            self.assertEqual(six["attachment_expectation"], "exact-direct")
            self.assertEqual(
                tuple(item["expected_sha256"] for item in six["attachments"]),
                g17g_backend.PARTIAL_RENDER_SIX_VERTEX_ATTACHMENT_SHA256,
            )

    def test_partial_growth_fixture_requires_exact_full_attachment_outputs(self):
        draw = g17g_encoder.G17GDirectDraw(vertex_count=1500000)
        products = g17g_backend.build_partial_render_products(direct_draw=draw)
        self.assertEqual(products["attachment_expectation"], "exact-direct")
        expected = g17g_backend.PARTIAL_RENDER_500K_TRIANGLE_ATTACHMENT_SHA256
        self.assertEqual(tuple(a["expected_sha256"] for a in products["attachments"]), expected)
        growth = g17g_backend.build_partial_render_products(
            params=dataclasses.replace(products["parameters"], request_tvb_growth=True),
            direct_draw=draw, submission_count=2)
        self.assertEqual(tuple(a["expected_sha256"] for a in growth["attachments"]), expected)
        different = g17g_backend.build_partial_render_products(
            direct_draw=dataclasses.replace(draw, instance_count=2))
        self.assertEqual(different["attachment_expectation"], "changed")

    def test_host_partial_products_build_caller_vdm_viewport(self):
        products = g17g_backend.build_partial_render_products(
            direct_draw=g17g_encoder.G17GDirectDraw(
                vertex_count=3, viewport_width=64, viewport_height=96,
            )
        )
        page = products["context1_writes"][0x1000068000]
        self.assertEqual(products["attachment_expectation"], "changed")
        self.assertEqual(struct.unpack_from("<I", page, 0x9C4)[0], 0x80000003)
        self.assertEqual(struct.unpack_from("<I", page, 0x9C8)[0], 3)
        self.assertEqual(struct.unpack_from("<f", page, 0x9D0)[0], 32.0)
        self.assertEqual(struct.unpack_from("<f", page, 0x9D4)[0], 32.0)
        self.assertEqual(struct.unpack_from("<f", page, 0x9D8)[0], 48.0)
        self.assertEqual(struct.unpack_from("<f", page, 0x9DC)[0], -48.0)

        exact = g17g_backend.build_partial_render_products(
            direct_draw=g17g_encoder.G17GDirectDraw(
                vertex_count=3, viewport_width=130, viewport_height=128,
            )
        )
        self.assertEqual(exact["attachment_expectation"], "exact-direct")
        self.assertEqual(
            tuple(item["expected_sha256"] for item in exact["attachments"]),
            g17g_backend.PARTIAL_RENDER_VIEWPORT_130X128_ATTACHMENT_SHA256,
        )

    def test_host_partial_products_build_two_direct_records(self):
        draw = g17g_encoder.G17GDirectDraw(vertex_count=3)
        products = g17g_backend.build_partial_render_products(
            direct_draws=(draw, draw)
        )
        self.assertEqual(products["attachment_expectation"], "exact-direct")
        self.assertEqual(len(products["direct_draws"]), 2)
        self.assertEqual(
            tuple(item["expected_sha256"] for item in products["attachments"]),
            g17g_backend.PARTIAL_RENDER_SIX_VERTEX_ATTACHMENT_SHA256,
        )
        stream = products["context1_writes"][g17g_encoder.VDM_STREAM_DVA]
        self.assertEqual(struct.unpack_from("<I", stream, 0x90)[0], 3)
        self.assertEqual(struct.unpack_from("<I", stream, 0xA4)[0], 3)
        self.assertEqual(struct.unpack_from("<I", stream, 0xB4)[0], 0xC0000000)

        many = g17g_backend.build_partial_render_products(
            direct_draws=(draw,) * 64
        )
        self.assertEqual(many["attachment_expectation"], "exact-direct")
        self.assertEqual(len(many["direct_draws"]), 64)
        self.assertEqual(
            tuple(item["expected_sha256"] for item in many["attachments"]),
            g17g_backend.PARTIAL_RENDER_64_DIRECT_ATTACHMENT_SHA256,
        )
        self.assertEqual(
            g17g_encoder.direct_vdm_stream_size(64), 0x590
        )

    def test_render_parameters_route_caller_vdm_stream(self):
        baseline = g17g_backend.build_partial_render_products()["parameters"]
        moved = dataclasses.replace(
            baseline,
            vdm_ctrl_stream_base=g17g_render.VDM_CTRL_STREAM_BASE + 0x4000,
        )
        registers = dict(g17g_render.build_tiling_registers(moved))
        self.assertEqual(registers[0x1C880], 0x1C000)
        products = g17g_backend.build_partial_render_products(
            moved,
            direct_draw=g17g_encoder.G17GDirectDraw(vertex_count=3),
        )
        self.assertNotIn(
            g17g_encoder.VDM_STREAM_DVA, products["context1_writes"]
        )
        self.assertEqual(
            products["vdm_stream_pages"],
            (g17g_encoder.VDM_STREAM_DVA + 0x4000,),
        )
        relocated = products["context1_writes"][
            g17g_encoder.VDM_STREAM_DVA + 0x4000
        ]
        self.assertEqual(
            relocated[:g17g_encoder.VDM_STREAM_SIZE],
            g17g_encoder.build_direct_vdm_page(
                g17g_encoder.G17GDirectDraw(vertex_count=3)
            )[:g17g_encoder.VDM_STREAM_SIZE],
        )
        with self.assertRaisesRegex(ValueError, "render-resource window"):
            dataclasses.replace(
                baseline,
                vdm_ctrl_stream_base=g17g_render.VDM_RESOURCE_BASE - 4,
            ).validate()

    def test_shim_backend_builds_and_validates_compute(self):
        seen = []

        def submit(graph):
            seen.append(graph)
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
            }

        backend = G17GShimBackend(submit)
        result = backend.submit_add((1.0,) * 64, (2.0,) * 64)
        self.assertIs(result, backend.last_compute)
        self.assertEqual(seen[0]["expected_values"], (3.0,) * 64)
        backend.submit_add()
        self.assertEqual(seen[0]["logical_queue_sequence"], 0)
        self.assertEqual(seen[1]["logical_queue_sequence"], 1)
        queue_id = backend.create_compute_queue()
        backend.submit_add(queue_id=queue_id)
        self.assertEqual(seen[2]["logical_queue_id"], queue_id)
        self.assertEqual(seen[2]["logical_queue_sequence"], 0)
        self.assertEqual(
            backend.compute_queue_state(queue_id)["submission_count"], 1
        )
        tombstone = backend.destroy_compute_queue(queue_id)
        self.assertEqual(tombstone, {
            "queue_id": queue_id,
            "submission_count": 1,
            "priority": 1,
            "firmware_priority": 2,
            "firmware_transport": "shared-compute",
            "quiescent": True,
        })
        self.assertEqual(backend.destroy_compute_queue(queue_id), tombstone)
        with self.assertRaisesRegex(G17GUnsupported, "destroyed"):
            backend.submit_add(queue_id=queue_id)

    def test_shim_backend_batches_compute_across_logical_queues(self):
        seen = []

        def submit(graph):
            seen.append(graph)
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
                "batch": {
                    "all_outputs_exact": True,
                    "exact_output_count": 7,
                },
            }

        backend = G17GShimBackend(submit)
        queues = [0] + [backend.create_compute_queue() for _index in range(3)]
        schedule = tuple(queues[index % 4] for index in range(8))
        result = backend.submit_add_batch(schedule)
        self.assertIs(result, backend.last_compute)
        self.assertEqual(seen[0]["submission_count"], 8)
        self.assertEqual(
            [item["logical_queue_id"]
             for item in seen[0]["logical_queue_schedule"]],
            list(schedule),
        )
        self.assertEqual(
            [backend.compute_queue_state(queue)["submission_count"]
             for queue in queues],
            [2, 2, 2, 2],
        )
        self.assertEqual(len(backend.compute_submissions), 8)
        tombstones = [
            backend.destroy_compute_queue(queue_id) for queue_id in queues[1:]
        ]
        self.assertEqual(
            [entry["submission_count"] for entry in tombstones], [2, 2, 2]
        )
        with self.assertRaisesRegex(G17GUnsupported, "destroyed"):
            backend.submit_add_batch((queues[1],))

        with self.assertRaisesRegex(G17GUnsupported, "16-bit"):
            backend.submit_add_batch(
                (0,) * (g17g_backend.COMPUTE_STREAM_SUBMISSION_LIMIT + 1)
            )

    def test_shim_backend_retargets_complete_queue_priority_profiles(self):
        compute_seen = []
        render_seen = []

        def submit_compute(graph):
            compute_seen.append(graph)
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
            }

        def submit_render(products):
            render_seen.append(products)
            return {
                "captured_input": None,
                "execution_claim": "partial-render",
                "changed": True,
                "exact_partial_attachments": True,
                "attachments": [
                    {"changed": True, "exact_native_output": True}
                    for _index in range(
                        g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT
                    )
                ],
            }

        backend = G17GShimBackend(submit_compute, submit_render)
        compute_source = g17g_backend.build_add_compute_graph()
        compute_queue = backend.create_compute_queue(priority=1)
        render_queue = backend.create_render_queue(priority=0)
        backend.submit_add(queue_id=compute_queue)
        backend.submit_partial_render(queue_id=render_queue)

        self.assertEqual(
            compute_seen[0]["firmware_objects"]["queue_context"],
            compute_source["firmware_objects"]["queue_context"],
        )
        self.assertEqual(
            compute_seen[0]["firmware_objects"]["queue_aux"],
            compute_source["firmware_objects"]["queue_aux"],
        )
        self.assertEqual(
            compute_seen[0]["firmware_priority_record_count"], 1
        )

        compute_page = compute_seen[0]["firmware_objects"]["queue"]
        self.assertEqual(
            g17g.parse_queue_priority(
                compute_page[:g17g.QUEUE_RECORD_SIZE]
            )["priority"],
            2,
        )
        self.assertEqual(compute_seen[0]["priority"], 1)
        self.assertEqual(compute_seen[0]["firmware_priority"], 2)
        render_page = render_seen[0]["firmware_pages"]["queue"]
        populated = []
        for offset in range(0, len(render_page), g17g.QUEUE_RECORD_STRIDE):
            record = render_page[offset:offset + g17g.QUEUE_RECORD_SIZE]
            if len(record) < g17g.QUEUE_RECORD_SIZE or not any(record[:0x18]):
                continue
            populated.append(g17g.parse_queue_priority(record)["priority"])
        self.assertEqual(populated, [3, 3])
        self.assertEqual(render_seen[0]["priority"], 0)
        self.assertEqual(render_seen[0]["firmware_priority"], 3)

        low_queue = backend.create_compute_queue(priority=0)
        with self.assertRaisesRegex(G17GUnsupported, "mixed-priority"):
            backend.submit_add_batch((compute_queue, low_queue))
        with self.assertRaisesRegex(G17GUnsupported, "LOW.*MEDIUM"):
            backend.create_compute_queue(priority=2)
        with self.assertRaisesRegex(G17GUnsupported, "LOW.*MEDIUM"):
            backend.create_render_queue(priority=3)

    def test_shim_backend_batches_with_runtime_compute_graph_variant(self):
        seen = []

        def submit(graph):
            seen.append(graph)
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
                "batch": {
                    "all_outputs_exact": True,
                    "exact_output_count": 1,
                },
            }

        backend = G17GShimBackend(
            submit_compute=submit,
            compute_graph_builder=(
                lambda values_a=None, values_b=None:
                g17g_backend.build_add_compute_graph(
                    values_a, values_b, mixed_after_render=True
                )
            ),
        )
        backend.submit_add_batch((0, 0))
        self.assertEqual(
            seen[0]["format"],
            "m1n1-t8142-g17g-host-mixed-compute-graph-v1",
        )
        self.assertEqual(seen[0]["submission_count"], 2)
        self.assertEqual(seen[0]["queue_index"], 0)

        with self.assertRaisesRegex(TypeError, "graph builder"):
            G17GShimBackend(submit_compute=submit, compute_graph_builder=1)

    def test_shim_backend_tracks_compute_execution_contexts(self):
        seen = []

        def submit(graph):
            seen.append(graph)
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
                "batch": {
                    "all_outputs_exact": True,
                    "exact_output_count": 2,
                },
            }

        backend = G17GShimBackend(submit)
        context_b = backend.create_execution_context()
        result = backend.submit_add_batch(
            (0, 0, 0), context_ids=(0, context_b, 0)
        )
        self.assertIs(result, backend.last_compute)
        self.assertEqual(
            [item["logical_context_id"]
             for item in seen[0]["logical_queue_schedule"]],
            [0, context_b, 0],
        )
        self.assertTrue(all(
            item["firmware_context_id"] == 1
            for item in seen[0]["logical_queue_schedule"]
        ))
        self.assertEqual(
            backend.execution_context_state(0)["compute_submission_count"],
            2,
        )
        tombstone = backend.destroy_execution_context(context_b)
        self.assertEqual(tombstone, {
            "context_id": context_b,
            "compute_submission_count": 1,
            "render_submission_count": 0,
            "firmware_context_id": 1,
            "quiescent": True,
        })
        self.assertEqual(
            backend.destroy_execution_context(context_b), tombstone
        )
        with self.assertRaisesRegex(G17GUnsupported, "destroyed"):
            backend.submit_add(context_id=context_b)
        with self.assertRaisesRegex(G17GUnsupported, "destroyed"):
            backend.submit_add_batch((0,), context_ids=(context_b,))

    def test_shim_backend_tracks_render_execution_contexts(self):
        seen = []

        def submit(products):
            seen.append(products)
            return {
                "captured_input": None,
                "execution_claim": "partial-render-repeat",
                "changed": True,
                "exact_partial_attachments": True,
                "attachments": [
                    {
                        "changed": True,
                        "exact_native_output": True,
                    }
                    for _index in range(
                        g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT
                    )
                ],
            }

        backend = G17GShimBackend(submit_render=submit)
        context_b = backend.create_execution_context()
        result = backend.submit_partial_render_batch(
            (0, 0, 0), context_ids=(0, context_b, 0)
        )
        self.assertIs(result, backend.last_render)
        self.assertEqual(
            [item["logical_context_id"]
             for item in seen[0]["logical_queue_schedule"]],
            [0, context_b, 0],
        )
        self.assertTrue(all(
            item["firmware_context_id"] == 1
            for item in seen[0]["logical_queue_schedule"]
        ))
        self.assertEqual(
            backend.execution_context_state(0)["render_submission_count"],
            2,
        )
        tombstone = backend.destroy_execution_context(context_b)
        self.assertEqual(tombstone, {
            "context_id": context_b,
            "compute_submission_count": 0,
            "render_submission_count": 1,
            "firmware_context_id": 1,
            "quiescent": True,
        })
        self.assertEqual(
            backend.destroy_execution_context(context_b), tombstone
        )
        with self.assertRaisesRegex(G17GUnsupported, "destroyed"):
            backend.submit_partial_render(context_id=context_b)
        with self.assertRaisesRegex(G17GUnsupported, "destroyed"):
            backend.submit_partial_render_batch(
                (0,), context_ids=(context_b,)
            )

    def test_shim_backend_serializes_mixed_binary_and_timeline_sync(self):
        order = []

        def submit_compute(graph):
            order.append(("compute", graph["logical_global_sequence"]))
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
                "after_sha256": "compute-%d" % len(order),
            }

        def submit_render(products):
            order.append(("render", products["logical_global_sequence"]))
            return {
                "captured_input": None,
                "execution_claim": "partial-render",
                "changed": True,
                "exact_partial_attachments": True,
                "after_sha256": "render-%d" % len(order),
                "attachments": [
                    {"changed": True, "exact_native_output": True}
                    for _index in range(
                        g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT
                    )
                ],
            }

        backend = G17GShimBackend(submit_compute, submit_render)
        timeline = g17g_sync.G17GSyncObject(timeline=True)
        binary = g17g_sync.G17GSyncObject()

        _compute1, compute1_fence = backend.submit_add_synced(
            out_syncs=((timeline, 1),)
        )
        _render, render_fence = backend.submit_partial_render_synced(
            in_syncs=((timeline, 1),), out_syncs=((binary, 0),)
        )
        _compute2, compute2_fence = backend.submit_add_synced(
            in_syncs=((binary, 0),), out_syncs=((timeline, 2),)
        )

        self.assertEqual(order, [
            ("compute", 0), ("render", 0), ("compute", 1)
        ])
        self.assertTrue(compute1_fence.signaled())
        self.assertTrue(render_fence.signaled())
        self.assertTrue(compute2_fence.signaled())
        self.assertEqual(len(compute1_fence.fences), 1)
        self.assertEqual(len(render_fence.fences), 2)
        self.assertEqual(timeline.query(), 2)
        self.assertTrue(binary.signaled())
        self.assertEqual(
            [fence.metadata["completion_id"]
             for fence in backend.submission_fences],
            [0, 1, 2],
        )
        self.assertEqual(
            render_fence.metadata["completion_source"],
            "exact-output-plus-ta-and-fragment-retirement",
        )

        submissions_before = len(order)
        with self.assertRaisesRegex(ValueError, "already bound"):
            backend.submit_add_synced(out_syncs=((timeline, 2),))
        self.assertEqual(len(order), submissions_before)

    def test_sync_validation_is_transactional_before_publication(self):
        missing = g17g_sync.G17GSyncObject(timeline=True)
        output = g17g_sync.G17GSyncObject()
        publications = []
        plan = g17g_sync.G17GSubmissionSyncPlan(
            in_syncs=((missing, 7),), out_syncs=((output, 0),)
        )
        with self.assertRaisesRegex(ValueError, "has no fence"):
            plan.publish(lambda: publications.append(True))
        self.assertEqual(publications, [])
        self.assertIsNone(output.point())

        failed_input = g17g_sync.G17GSyncObject()
        failed_input.bind(
            g17g_sync.G17GSubmissionFence((
                g17g_sync.G17GSoftwareFence(signaled=True, error=-5),
            ))
        )
        plan = g17g_sync.G17GSubmissionSyncPlan(
            in_syncs=((failed_input, 0),), out_syncs=((output, 0),)
        )
        with self.assertRaises(OSError):
            plan.publish(lambda: publications.append(True))
        self.assertEqual(publications, [])
        self.assertIsNone(output.point())

        ready = g17g_sync.G17GSyncObject()
        ready.bind(g17g_sync.G17GSubmissionFence((
            g17g_sync.G17GSoftwareFence(signaled=True),
        )))
        plan = g17g_sync.G17GSubmissionSyncPlan(
            in_syncs=((ready, 0),), out_syncs=((output, 0),)
        )
        with self.assertRaisesRegex(RuntimeError, "build failed"):
            plan.publish(
                lambda: (_ for _ in ()).throw(RuntimeError("build failed"))
            )
        self.assertIsNone(output.point())

    def test_render_submission_fence_requires_both_engine_completions(self):
        ta = g17g_sync.G17GSoftwareFence()
        fragment = g17g_sync.G17GSoftwareFence()
        fence = g17g_sync.G17GSubmissionFence((ta, fragment))
        self.assertEqual(fence.state, g17g_sync.G17GWorkState.PENDING)
        ta.signal()
        self.assertFalse(fence.signaled())
        fragment.signal()
        self.assertTrue(fence.signaled())
        self.assertEqual(fence.state, g17g_sync.G17GWorkState.COMPLETED)

    def test_memory_limit_error_fence_is_owned_and_queue_can_continue(self):
        from m1n1.drm_shim.g17g_growth import build_growth_limit_followup
        # Construct the exact observed tail independently of padding words.
        report = struct.pack("<6I4Q4I", 7, 0, 1, 1, 0x100, 0,
            0xfffffc20c0000080, 0xfffffc20c08e8000, 0xfffffc0000108000,
            0xfffffc20c00b0000, 0, 0, 1, 0)
        owner = dict(queue_dva=0xfffffc20c0000080, pool_dva=0xfffffc20c08e8000,
                     fragment_dva=0xfffffc20c00b0000, event_slot=1, event_value=0x100)
        followup = build_growth_limit_followup(report, **owner)
        terminal = struct.pack("<4I", 1, 3, 0, 0) + bytes(56)
        fault = g17g_sync.G17GPublishedFault.memory_limit_terminated(report, followup, terminal, **owner)
        self.assertTrue(fault.recoverable)
        self.assertFalse(fault.fatal)
        self.assertEqual(fault.error, -12)
        for bad_followup, bad_terminal in ((bytes(64), terminal), (followup, bytes(72))):
            with self.assertRaises(ValueError):
                g17g_sync.G17GPublishedFault.memory_limit_terminated(
                    report, bad_followup, bad_terminal, **owner)
        calls = []
        def submit(products):
            calls.append(products)
            if len(calls) == 1:
                raise fault
            return dict(captured_input=None, execution_claim="partial-render", changed=True,
                exact_partial_attachments=True, after_sha256="test-only",
                attachments=[dict(changed=True, exact_native_output=True) for _ in range(8)])
        backend = G17GShimBackend(submit_render=submit)
        context = backend.create_execution_context()
        queue = backend.create_render_queue()
        timeline = g17g_sync.G17GSyncObject(timeline=True)
        binary = g17g_sync.G17GSyncObject()
        result, fence = backend.submit_partial_render_synced(queue_id=queue, context_id=context,
            out_syncs=((timeline, 1), (binary, 0)))
        self.assertIsNone(result["changed"])
        self.assertEqual(fence.error, -12)
        self.assertEqual(len(fence.fences), 2)
        self.assertTrue(fence.signaled())
        # The aggregate error terminates the submission; do not invent
        # successful TA/fragment hardware completions underneath it.
        self.assertEqual(fence.state, g17g_sync.G17GWorkState.FAILED)
        self.assertEqual(fence.metadata["logical_queue_id"], queue)
        self.assertEqual(fence.metadata["logical_context_id"], context)
        self.assertEqual(timeline.point(1).error, -12)
        self.assertIs(binary.point().fence, fence)
        self.assertEqual(binary.point().error, -12)
        with self.assertRaises(OSError):
            backend.submit_partial_render_synced(queue_id=queue, context_id=context, in_syncs=((timeline, 1),))
        self.assertEqual(len(calls), 1)
        _, recovered = backend.submit_partial_render_synced(queue_id=queue, context_id=context,
            out_syncs=((timeline, 2),))
        self.assertTrue(recovered.signaled())
        self.assertIsNone(recovered.error)
        self.assertFalse(backend.fault_state()["device_lost"])

    def test_mock_recoverable_fault_is_attributed_and_queue_continues(self):
        calls = []

        def submit(graph):
            calls.append(graph)
            if len(calls) == 1:
                # Exercise host fence policy, not an invented hardware error:
                # shader-store soft faults are successful UAPI completions.
                raise g17g_sync.G17GPublishedFault(
                    "mock-recoverable-channel", g17g_sync.G17GWorkError.CHANNEL,
                    recoverable=True, metadata={"fault_address": 0x12340000},
                )
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
                "after_sha256": "recovered",
            }

        backend = G17GShimBackend(submit_compute=submit)
        context_id = backend.create_execution_context()
        queue_id = backend.create_compute_queue()
        timeline = g17g_sync.G17GSyncObject(timeline=True)
        result, fence = backend.submit_add_synced(
            queue_id=queue_id,
            context_id=context_id,
            out_syncs=((timeline, 7),),
        )
        self.assertEqual(result["execution_claim"], "failed")
        self.assertEqual(fence.state, g17g_sync.G17GWorkState.FAILED)
        self.assertEqual(fence.error, -5)
        self.assertEqual(fence.terminal_reason, "mock-recoverable-channel")
        self.assertIs(timeline.point(7).fence, fence)
        self.assertEqual(timeline.point(7).error, -5)
        self.assertEqual(fence.metadata["logical_queue_id"], queue_id)
        self.assertEqual(fence.metadata["logical_context_id"], context_id)
        self.assertEqual(
            fence.metadata["metadata"]["fault_address"], 0x12340000
        )
        self.assertEqual(
            backend.compute_queue_state(queue_id)["submission_count"], 1
        )
        self.assertEqual(
            backend.execution_context_state(context_id)[
                "compute_submission_count"
            ],
            1,
        )
        self.assertFalse(backend.fault_state()["device_lost"])

        recovered, recovered_fence = backend.submit_add_synced(
            queue_id=queue_id, context_id=context_id
        )
        self.assertEqual(recovered["execution_claim"], "compute")
        self.assertEqual(
            recovered_fence.state, g17g_sync.G17GWorkState.COMPLETED
        )
        self.assertEqual(
            backend.compute_queue_state(queue_id)["submission_count"], 2
        )

        publications = len(calls)
        with self.assertRaises(OSError):
            backend.submit_add_synced(in_syncs=((timeline, 7),))
        self.assertEqual(len(calls), publications)

    def test_command_fetch_mmu_fault_is_device_lost(self):
        def submit(_graph):
            raise g17g_sync.G17GPublishedFault.command_fetch_mmu(
                fault_address=0x100000C8000,
                context_id=1,
                unit=0xD0,
            )

        backend = G17GShimBackend(submit_compute=submit)
        pending = backend.fence_tracker.track((
            g17g_sync.G17GSoftwareFence(),
        ), name="already pending")
        output = g17g_sync.G17GSyncObject()
        result, fence = backend.submit_add_synced(
            out_syncs=((output, 0),)
        )
        self.assertEqual(result["fault"]["kind"], "command-fetch-uat")
        self.assertEqual(result["fault"]["error"], -19)
        self.assertTrue(result["fault"]["fatal"])
        self.assertFalse(result["fault"]["recoverable"])
        self.assertEqual(
            result["fault"]["metadata"]["fault_address"],
            0x100000C8000,
        )
        self.assertEqual(fence.state, g17g_sync.G17GWorkState.FAILED)
        self.assertEqual(fence.error, -19)
        self.assertEqual(fence.terminal_reason, "command-fetch-uat")
        self.assertIs(output.point().fence, fence)
        self.assertEqual(pending.error, -19)
        self.assertEqual(pending.terminal_reason, "device-lost")
        self.assertTrue(backend.fault_state()["device_lost"])
        with self.assertRaisesRegex(G17GUnsupported, "device was lost"):
            backend.submit_add_synced()

    def test_fatal_published_fault_fails_fence_and_loses_device(self):
        def submit(_products):
            raise g17g_sync.G17GPublishedFault(
                "firmware-crash",
                g17g_sync.G17GWorkError.DEVICE_LOST,
                fatal=True,
                metadata={"crash_artifact": "crash.bin"},
            )

        backend = G17GShimBackend(submit_render=submit)
        output = g17g_sync.G17GSyncObject()
        result, fence = backend.submit_partial_render_synced(
            out_syncs=((output, 0),)
        )
        self.assertEqual(result["fault"]["kind"], "firmware-crash")
        self.assertEqual(fence.error, -19)
        self.assertTrue(fence.signaled())
        self.assertEqual(len(fence.fences), 2)
        self.assertIs(output.point().fence, fence)
        state = backend.fault_state()
        self.assertTrue(state["device_lost"])
        self.assertEqual(state["fault_count"], 1)
        self.assertEqual(
            state["last_fault"]["metadata"]["crash_artifact"],
            "crash.bin",
        )
        with self.assertRaisesRegex(G17GUnsupported, "device was lost"):
            backend.submit_partial_render_synced()

    def test_nonrecoverable_fault_quarantines_only_attributed_queue(self):
        calls = 0

        def submit(_graph):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise g17g_sync.G17GPublishedFault(
                    "channel",
                    g17g_sync.G17GWorkError.CHANNEL,
                    recoverable=False,
                )
            return {
                "captured_input": None,
                "execution_claim": "compute",
                "changed": True,
                "exact_first_64_floats": True,
            }

        backend = G17GShimBackend(submit_compute=submit)
        faulted_queue = backend.create_compute_queue()
        _result, fence = backend.submit_add_synced(queue_id=faulted_queue)
        self.assertEqual(fence.error, -5)
        with self.assertRaisesRegex(G17GUnsupported, "faulted.*queue"):
            backend.submit_add_synced(queue_id=faulted_queue)
        result, healthy_fence = backend.submit_add_synced(queue_id=0)
        self.assertEqual(result["execution_claim"], "compute")
        self.assertEqual(
            healthy_fence.state, g17g_sync.G17GWorkState.COMPLETED
        )

    def test_backend_builds_earliest_two_partial_groups(self):
        products = (
            g17g_backend.build_prequeued_two_partial_render_products()
        )
        self.assertEqual(
            products["format"],
            "m1n1-t8142-g17g-host-two-partial-render-products-v1",
        )
        self.assertTrue(products["prequeued_partial_negative_then_positive"])
        self.assertEqual(products["prequeued_group_count"], 2)
        self.assertEqual(products["prequeued_item_limit"], 6)
        self.assertEqual(
            products["parameters"].resolved_partial_load_pipeline(),
            0x100001E8200,
        )
        self.assertEqual(
            products["final_parameters"].resolved_partial_load_pipeline(),
            0x100001E8000,
        )
        pointers = products["firmware_pages"]["pointers"]
        for block_offset in (0, 0x2870):
            self.assertEqual(
                struct.unpack_from(
                    "<I", pointers,
                    block_offset + g17g.POINTER_FIELD_40,
                )[0],
                6,
            )
        for _offset, body in products["firmware_patches"]["state"]:
            self.assertEqual(
                struct.unpack("<I12xI12xI", body), (0, 0, 2)
            )

    def test_backend_builds_two_prequeued_first_generation_clears(self):
        products = g17g_backend.build_prequeued_two_clear_render_products()
        self.assertEqual(
            products["format"],
            "m1n1-t8142-g17g-host-two-clear-products-v1",
        )
        self.assertEqual(products["prequeued_group_count"], 2)
        self.assertEqual(products["prequeued_item_limit"], 6)
        self.assertEqual(products["token"], g17g_backend.RENDER_DEFAULT_TOKEN)
        self.assertEqual(
            products["final_parameters"].clear_rgba,
            (0x55, 0x66, 0x77, 0x88),
        )
        self.assertEqual(
            products["final_parameters"].target_dva,
            products["parameters"].target_dva,
        )
        self.assertEqual(
            products["final_parameters"].clear_state_page,
            products["parameters"].clear_state_page + g17g_backend.PAGE_SIZE,
        )

        for index, name in enumerate(("channel_ring_6", "channel_ring_7")):
            slots = products["firmware_patches"][name]
            self.assertEqual(len(slots), 2)
            self.assertEqual(
                g17g.parse_ring_slot(slots[0][1])["limit"], 3
            )
            second = g17g.parse_ring_slot(slots[1][1])
            self.assertEqual(second["limit"], 6)
            self.assertEqual(second["queue_index"], index)
        for _offset, body in products["firmware_patches"]["state"]:
            self.assertEqual(
                struct.unpack("<I12xI12xI", body), (0, 0, 2)
            )

        pointers = products["firmware_pages"]["pointers"]
        for block_offset in (0, 0x2870):
            self.assertEqual(
                struct.unpack_from(
                    "<I", pointers,
                    block_offset + g17g.POINTER_FIELD_40,
                )[0],
                6,
            )

    def test_backend_can_stage_group_two_behind_first_release(self):
        products = g17g_backend.build_staged_two_clear_render_products()
        self.assertEqual(
            products["format"],
            "m1n1-t8142-g17g-host-staged-two-clear-products-v1",
        )
        self.assertEqual(products["staged_group_count"], 2)
        self.assertNotIn("prequeued_group_count", products)
        self.assertEqual(
            products["staged_parameters"].clear_rgba,
            (0x55, 0x66, 0x77, 0x88),
        )
        for _offset, body in products["firmware_patches"]["state"]:
            self.assertEqual(
                struct.unpack("<I12xI12xI", body), (0, 0, 1)
            )
        pointers = products["firmware_pages"]["pointers"]
        for block_offset in (0, 0x2870):
            self.assertEqual(
                struct.unpack_from(
                    "<I", pointers,
                    block_offset + g17g.POINTER_FIELD_40,
                )[0],
                3,
            )
        for name in ("channel_ring_6", "channel_ring_7"):
            self.assertEqual(len(products["firmware_patches"][name]), 2)
        item_ring = products["firmware_pages"]["item_ring"]
        self.assertEqual(
            struct.unpack_from("<3Q", item_ring, 3 * 8),
            (
                g17g_backend.RENDER_OPTIONAL_PAGE + 0x240,
                g17g_backend.RENDER_TILING_DESCRIPTOR_PAGE
                + g17g_render.TILING_DESCRIPTOR_SIZE,
                g17g_backend.RENDER_EVENT_PAGE + 0xC0,
            ),
        )
        self.assertEqual(
            struct.unpack_from("<3Q", item_ring, 0x2870 + 3 * 8),
            (
                g17g_backend.RENDER_OPTIONAL_PAGE + 0x180,
                g17g_backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE
                + g17g_render.FRAGMENT_DESCRIPTOR_SIZE,
                g17g_backend.RENDER_EVENT_PAGE + 0x80,
            ),
        )
        known_pages = g17g_backend.render_context1_page_images(products)
        self.assertEqual(len(known_pages), 24)
        self.assertEqual(
            known_pages[products["staged_parameters"].clear_state_page],
            g17g_render.build_clear_state_page(products["staged_parameters"]),
        )

    def test_shim_backend_builds_and_validates_render(self):
        seen = []

        def submit(products):
            seen.append(products)
            return {
                "captured_input": None,
                "execution_claim": "render",
                "changed": True,
                "exact_clear_page": True,
            }

        backend = G17GShimBackend(submit_render=submit)
        result = backend.submit_clear()
        self.assertIs(result, backend.last_render)
        self.assertEqual(
            seen[0]["format"],
            "m1n1-t8142-g17g-host-clear-products-v1",
        )
        self.assertEqual(seen[0]["logical_queue_id"], 0)
        self.assertEqual(seen[0]["logical_queue_sequence"], 0)
        backend.submit_clear()
        self.assertEqual(seen[1]["logical_queue_sequence"], 1)
        with self.assertRaisesRegex(G17GUnsupported, "compute adapter"):
            backend.submit_add()

    def test_shim_backend_builds_and_validates_partial_render(self):
        seen = []

        def submit(products):
            seen.append(products)
            return {
                "captured_input": None,
                "execution_claim": "partial-render",
                "changed": True,
                "exact_partial_attachments": True,
                "attachments": [
                    {
                        "changed": True,
                        "exact_native_output": True,
                    }
                    for _index in range(
                        g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT
                    )
                ],
            }

        backend = G17GShimBackend(submit_render=submit)
        result = backend.submit_partial_render()
        self.assertIs(result, backend.last_render)
        self.assertEqual(
            seen[0]["format"],
            "m1n1-t8142-g17g-host-partial-render-products-v1",
        )
        self.assertEqual(backend.render_queue_state(0)["submission_count"], 1)

    def test_shim_multiplexes_arbitrary_logical_render_queues(self):
        seen = []

        def submit(products):
            seen.append(products)
            return {
                "captured_input": None,
                "execution_claim": (
                    "partial-render"
                    if products["logical_global_sequence"] == 0 else
                    "partial-render-repeat"
                ),
                "changed": True,
                "exact_partial_attachments": True,
                "attachments": [
                    {
                        "changed": True,
                        "exact_native_output": True,
                    }
                    for _index in range(
                        g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT
                    )
                ],
            }

        backend = G17GShimBackend(submit_render=submit)
        queues = [0] + [backend.create_render_queue() for _index in range(63)]
        for queue_id in queues:
            backend.submit_partial_render(queue_id=queue_id)

        self.assertEqual(len(seen), 64)
        self.assertEqual(
            [item["logical_queue_id"] for item in seen], queues
        )
        self.assertEqual(
            [item["logical_global_sequence"] for item in seen],
            list(range(64)),
        )
        self.assertTrue(all(
            item["logical_queue_sequence"] == 0 for item in seen
        ))
        self.assertTrue(all(
            item["firmware_transport"] == "shared-paired-render"
            for item in seen
        ))
        self.assertTrue(all(
            item["firmware_pages"] == seen[0]["firmware_pages"]
            and item["context1_writes"] == seen[0]["context1_writes"]
            for item in seen[1:]
        ))

        retired = queues[-1]
        tombstone = backend.destroy_render_queue(retired)
        self.assertEqual(tombstone, {
            "queue_id": retired,
            "submission_count": 1,
            "priority": 1,
            "firmware_priority": 2,
            "firmware_transport": "shared-paired-render",
            "quiescent": True,
        })
        self.assertEqual(backend.destroy_render_queue(retired), tombstone)
        with self.assertRaisesRegex(G17GUnsupported, "destroyed"):
            backend.submit_partial_render(queue_id=retired)

    def test_shim_batches_repeated_interleaved_logical_queues(self):
        seen = []

        def submit(products):
            seen.append(products)
            return {
                "captured_input": None,
                "execution_claim": "partial-render-repeat",
                "changed": True,
                "exact_partial_attachments": True,
                "attachments": [
                    {
                        "changed": True,
                        "exact_native_output": True,
                    }
                    for _index in range(
                        g17g_backend.PARTIAL_RENDER_ATTACHMENT_COUNT
                    )
                ],
            }

        backend = G17GShimBackend(submit_render=submit)
        queues = [0] + [backend.create_render_queue() for _index in range(63)]
        schedule = queues * 3
        direct_draw = g17g_encoder.G17GDirectDraw(vertex_count=3)
        backend.submit_partial_render_batch(
            schedule, direct_draws=(direct_draw,)
        )

        self.assertEqual(len(seen), 1)
        submission = seen[0]
        self.assertEqual(submission["submission_count"], 192)
        self.assertEqual(
            submission["direct_draws"], (dataclasses.asdict(direct_draw),)
        )
        self.assertEqual(
            [item["logical_queue_id"]
             for item in submission["logical_queue_schedule"]],
            schedule,
        )
        self.assertEqual(
            [item["logical_global_sequence"]
             for item in submission["logical_queue_schedule"]],
            list(range(192)),
        )
        self.assertEqual(
            [item["logical_queue_sequence"]
             for item in submission["logical_queue_schedule"]],
            [sequence for sequence in range(3) for _queue in queues],
        )
        self.assertTrue(all(
            backend.render_queue_state(queue_id)["submission_count"] == 3
            for queue_id in queues
        ))

    def test_host_multi_dispatch_compute_backend_graph(self):
        graph = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=((
                tuple(2000.0 + index for index in range(64)),
                (1.25,) * 64,
            ),),
        )
        self.assertEqual(
            graph["format"],
            "m1n1-t8142-g17g-host-mixed-compute-graph-v2",
        )
        self.assertEqual(graph["direct_dispatch_count"], 2)
        self.assertEqual(graph["cdm_size"], 0x5C)
        second = graph["dispatch_outputs"][1]
        self.assertEqual(second["buffer_a"], 0x10010000000)
        self.assertEqual(second["buffer_b"], 0x10010004000)
        self.assertEqual(second["output"], 0x10010008000)
        self.assertEqual(
            second["expected_values"],
            tuple(2001.25 + index for index in range(64)),
        )
        self.assertTrue(
            {second["buffer_a"], second["buffer_b"], second["output"]}
            <= set(graph["context1_dvas"])
        )
        shader = graph["context1_writes"][
            g17g_backend.COMPUTE_MIXED_SHADER
        ]
        self.assertEqual(shader[:3], bytes.fromhex("2ca002"))
        self.assertEqual(shader[0xC0:0xC3], bytes.fromhex("2cc002"))
        resources = graph["context1_writes"][
            g17g_backend.COMPUTE_MIXED_RESOURCE
        ]
        self.assertEqual(
            struct.unpack_from("<3Q", resources, 0x14C0),
            (second["buffer_a"], second["buffer_b"], second["output"]),
        )

        relocated_base = g17g_backend.COMPUTE_DIRECT_BUFFER_BASE + 0x4000
        relocated = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(((0.0,) * 64, (0.0,) * 64),),
            direct_buffer_base=relocated_base,
        )
        self.assertEqual(relocated["direct_buffer_base"], relocated_base)
        self.assertEqual(
            tuple(relocated["dispatch_outputs"][1][name]
                  for name in ("buffer_a", "buffer_b", "output")),
            (relocated_base, relocated_base + 0x4000,
             relocated_base + 0x8000),
        )
        compute_then_render = g17g_backend.build_add_compute_graph(
            first_dispatch_buffers=(
                g17g_backend.COMPUTE_TO_RENDER_BUFFERS
            ),
        )
        self.assertEqual(
            tuple(
                compute_then_render["dispatch_outputs"][0][name]
                for name in ("buffer_a", "buffer_b", "output")
            ),
            g17g_backend.COMPUTE_TO_RENDER_BUFFERS,
        )
        self.assertTrue(
            set(g17g_backend.COMPUTE_TO_RENDER_BUFFERS)
            <= set(compute_then_render["context1_dvas"])
        )
        self.assertEqual(
            compute_then_render["direct_buffer_topology_overlap"], ()
        )
        relocated_callers = {
            "shader": 0x10000168000,
            "cdm": 0x10000188000,
            "resource": 0x100001B8000,
            "robustness": 0x1000078000,
        }
        native_compute = g17g_backend.build_add_compute_graph(
            first_dispatch_buffers=(
                0x10000058000,
                0x10000060000,
                0x10000068000,
            ),
            caller_shader_address=relocated_callers["shader"],
            caller_cdm_address=relocated_callers["cdm"],
            caller_resource_address=relocated_callers["resource"],
            caller_robustness_address=relocated_callers["robustness"],
        )
        self.assertTrue(
            {
                relocated_callers["shader"],
                relocated_callers["cdm"],
                relocated_callers["resource"],
            }
            <= set(native_compute["context1_writes"])
        )
        self.assertEqual(
            native_compute["robustness_address"],
            relocated_callers["robustness"],
        )
        self.assertNotIn(
            g17g_backend.COMPUTE_SHADER,
            native_compute["context1_writes"],
        )
        self.assertEqual(
            tuple(
                native_compute["dispatch_outputs"][0][name]
                for name in ("buffer_a", "buffer_b", "output")
            ),
            (0x10000058000, 0x10000060000, 0x10000068000),
        )
        predecessor_compute = (
            g17g_backend.build_compute_predecessor_partial_compute_graph()
        )
        self.assertEqual(
            predecessor_compute["first_dispatch_buffers"],
            g17g_backend
            .COMPUTE_PREDECESSOR_PARTIAL_FIRST_DISPATCH_BUFFERS,
        )
        self.assertEqual(
            len(predecessor_compute["context1_dvas"]),
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_PAGE_COUNT,
        )
        self.assertEqual(
            len(predecessor_compute["context1_read_only_dvas"]),
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_PAGE_COUNT,
        )
        self.assertEqual(
            hashlib.sha256(b"".join(
                struct.pack("<Q", address)
                for address in predecessor_compute["context1_dvas"]
            )).hexdigest(),
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_DVA_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(b"".join(
                struct.pack("<Q", address)
                for address in predecessor_compute[
                    "context1_read_only_dvas"
                ]
            )).hexdigest(),
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_DVA_SHA256,
        )
        predecessor_images = g17g_backend.context1_page_images(
            predecessor_compute
        )
        self.assertEqual(len(predecessor_images), 21)
        self.assertLessEqual(
            set(predecessor_images),
            set(predecessor_compute["context1_dvas"]),
        )
        self.assertIn(
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_CDM,
            predecessor_images,
        )
        self.assertIn(
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_RESOURCE,
            predecessor_images,
        )
        self.assertEqual(
            hashlib.sha256(
                predecessor_images[0x10000000000]
            ).hexdigest(),
            "1571c550e14085ea7eb7d12b76938f86dc825be82c32109486f615fed9ea2c8b",
        )
        self.assertEqual(
            hashlib.sha256(
                predecessor_images[
                    g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_SHADER
                ]
            ).hexdigest(),
            "ca94ffbadcee5e575b6a0438de634c07978673bbfce5920ecad41a99d9dd2f65",
        )
        self.assertTrue(
            predecessor_compute[
                "compute_predecessor_partial_context1_assets"
            ]["included"]
        )
        predecessor_render = (
            g17g_backend.build_earliest_mixed_partial_render_products(
                compute_predecessor=True
            )
        )
        predecessor_compute_dvas = set(predecessor_compute["context1_dvas"])
        predecessor_render_dvas = set(
            g17g_backend.render_context1_dvas(predecessor_render)
        )
        self.assertEqual(
            len(predecessor_render_dvas - predecessor_compute_dvas),
            2895,
        )
        self.assertEqual(
            len(predecessor_render_dvas | predecessor_compute_dvas),
            4619,
        )
        multi_predecessor_compute = (
            g17g_backend.build_compute_predecessor_partial_compute_graph(
                additional_dispatch_values=(((2.0,) * 64, (3.0,) * 64),),
                include_first_admission_assets=False,
            )
        )
        self.assertFalse(
            multi_predecessor_compute[
                "compute_predecessor_partial_context1_topology"
            ]["standard_graph"]
        )
        self.assertLessEqual(
            {
                multi_predecessor_compute["dispatch_outputs"][1][name]
                for name in ("buffer_a", "buffer_b", "output")
            },
            set(multi_predecessor_compute["context1_dvas"]),
        )
        source_multi_predecessor_compute = (
            g17g_backend.build_compute_predecessor_partial_compute_graph(
                additional_dispatch_values=(((2.0,) * 64, (3.0,) * 64),),
            )
        )
        self.assertEqual(
            source_multi_predecessor_compute["direct_dispatch_count"], 2
        )
        self.assertEqual(
            source_multi_predecessor_compute["compute_descriptor_count"], 1
        )
        self.assertTrue(
            source_multi_predecessor_compute[
                "compute_predecessor_partial_context1_assets"
            ]["included"]
        )
        self.assertEqual(
            source_multi_predecessor_compute[
                "compute_predecessor_partial_context1_topology"
            ]["preexisting_added_mapping_count"],
            0,
        )
        source_multi_images = g17g_backend.context1_page_images(
            source_multi_predecessor_compute
        )
        multi_shader = source_multi_images[
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_SHADER
        ]
        single_shader = predecessor_images[
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_SHADER
        ]
        companion_start = 0xC0
        companion_end = 0x237
        self.assertEqual(
            multi_shader[:companion_end], single_shader[:companion_end]
        )
        self.assertTrue(any(
            multi_shader[
                g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_ADDITIONAL_SHADER_OFFSET:
                g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_ADDITIONAL_SHADER_OFFSET
                + g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
            ]
        ))
        self.assertEqual(
            multi_shader[companion_start:companion_end],
            single_shader[companion_start:companion_end],
        )
        second_cdm_record = source_multi_images[
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_CDM
        ][g17g_compute.CDM_RECORD_SIZE:2 * g17g_compute.CDM_RECORD_SIZE]
        self.assertEqual(
            struct.unpack_from("<Q", second_cdm_record, 8)[0],
            g17g_compute.encode_shader_pointer(
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_SHADER
                + g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_ADDITIONAL_SHADER_OFFSET
            ),
        )
        with self.assertRaisesRegex(ValueError, "requires one compute descriptor"):
            g17g_backend.build_compute_predecessor_partial_compute_graph(
                additional_dispatch_values=(((2.0,) * 64, (3.0,) * 64),),
                direct_dispatch_group_capacity=1,
            )
        eleven_predecessor_compute = (
            g17g_backend.build_compute_predecessor_partial_compute_graph(
                additional_dispatch_values=tuple(
                    (((float(index),) * 64), ((0.5,) * 64))
                    for index in range(2, 12)
                ),
            )
        )
        self.assertEqual(eleven_predecessor_compute["direct_dispatch_count"], 11)
        self.assertEqual(eleven_predecessor_compute["compute_descriptor_count"], 1)
        self.assertEqual(eleven_predecessor_compute["cdm_group_sizes"], (0x1E8,))
        eleven_shader = g17g_backend.context1_page_images(
            eleven_predecessor_compute
        )[g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_SHADER]
        self.assertEqual(
            eleven_shader[companion_start:companion_end],
            single_shader[companion_start:companion_end],
        )
        final_shader_start = (
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_ADDITIONAL_SHADER_OFFSET
            + 9 * g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
        )
        self.assertTrue(any(
            eleven_shader[
                final_shader_start:
                final_shader_start + g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
            ]
        ))
        two_publication_predecessor = (
            g17g_backend.build_compute_predecessor_partial_compute_graph(
                mixed_after_render=True,
                additional_dispatch_values=tuple(
                    (((float(index),) * 64), ((0.5,) * 64))
                    for index in range(2, 5)
                ),
                direct_dispatch_group_capacity=2,
                fresh_queue_per_group=True,
                native_two_publication_layout=True,
            )
        )
        self.assertEqual(two_publication_predecessor["direct_dispatch_count"], 4)
        self.assertEqual(two_publication_predecessor["compute_descriptor_count"], 2)
        self.assertEqual(
            two_publication_predecessor[
                "compute_predecessor_partial_context1_topology"
            ]["native_two_publication_layout"],
            True,
        )
        self.assertEqual(
            len(two_publication_predecessor["context1_dvas"]), 2543
        )
        self.assertEqual(
            len(two_publication_predecessor["context1_read_only_dvas"]), 114
        )
        self.assertEqual(
            len(g17g_backend.context1_page_images(two_publication_predecessor)),
            47,
        )
        admission_zero = (
            g17g_backend.RENDER_MIXED_COMPUTE_ADMISSION_ZERO_DVA
        )
        self.assertIn(admission_zero, two_publication_predecessor["context1_dvas"])
        self.assertNotIn(
            admission_zero,
            two_publication_predecessor["context1_read_only_dvas"],
        )
        self.assertEqual(
            two_publication_predecessor["context1_writes"][admission_zero],
            bytes(g17g_backend.PAGE_SIZE),
        )
        self.assertEqual(
            set(two_publication_predecessor[
                "compute_predecessor_partial_context1_assets"
            ]["merged_caller_pages"]),
            {0x10000000000, 0x10000030000},
        )
        first_work_globals = two_publication_predecessor[
            "compute_predecessor_partial_first_work_globals"
        ]
        self.assertTrue(first_work_globals["included"])
        self.assertEqual(first_work_globals["page_count"], 7)
        self.assertEqual(
            set(first_work_globals["pages"]),
            set(g17g_backend.COMPUTE_MIXED_TWO_FIRST_WORK_GLOBAL_PAGES),
        )
        job_list = two_publication_predecessor["source_global_pages"][
            g17g_backend.COMPUTE_JOB_LIST_PAGE
        ]
        self.assertEqual(
            struct.unpack_from("<QQQ", job_list, 0x18),
            (0, g17g_backend.COMPUTE_MIXED_JOB_LIST, 0),
        )
        queue_aux = two_publication_predecessor["source_global_pages"][
            g17g_backend.COMPUTE_QUEUE_AUX_PAGE
        ]
        self.assertEqual(
            struct.unpack_from("<Q", queue_aux, 0x40)[0],
            0x1000000FFFF,
        )
        with self.assertRaisesRegex(ValueError, "fixes caller placement"):
            g17g_backend.build_compute_predecessor_partial_compute_graph(
                caller_shader_address=g17g_backend.COMPUTE_SHADER
            )
        with self.assertRaisesRegex(ValueError, "distinct and aligned"):
            g17g_backend.build_add_compute_graph(
                first_dispatch_buffers=(0x1000, 0x2000, 0x2000)
            )
        with self.assertRaisesRegex(ValueError, "caller shader"):
            g17g_backend.build_add_compute_graph(caller_shader_address=1)
        with self.assertRaisesRegex(ValueError, "not page aligned"):
            g17g_backend.build_add_compute_graph(direct_buffer_base=1)
        native_stride = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(((0.0,) * 64, (0.0,) * 64),),
            direct_buffer_page_stride=0x8000,
        )
        native_stride_second = native_stride["dispatch_outputs"][1]
        self.assertEqual(
            tuple(native_stride_second[name]
                  for name in ("buffer_a", "buffer_b", "output")),
            (
                g17g_backend.COMPUTE_DIRECT_BUFFER_BASE,
                g17g_backend.COMPUTE_DIRECT_BUFFER_BASE + 0x8000,
                g17g_backend.COMPUTE_DIRECT_BUFFER_BASE + 0x10000,
            ),
        )
        self.assertEqual(native_stride["direct_buffer_page_stride"], 0x8000)
        with self.assertRaisesRegex(ValueError, "positive page multiple"):
            g17g_backend.build_add_compute_graph(
                direct_buffer_page_stride=0x8000 - 1,
            )
        native_placed = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(((0.0,) * 64, (0.0,) * 64),),
            direct_buffer_base=0x10000110000,
            direct_buffer_page_stride=0x8000,
            allow_direct_buffer_topology_overlap=True,
        )
        self.assertEqual(
            tuple(native_placed["dispatch_outputs"][1][name]
                  for name in ("buffer_a", "buffer_b", "output")),
            (0x10000110000, 0x10000118000, 0x10000120000),
        )
        self.assertEqual(
            native_placed["direct_buffer_topology_overlap"],
            (0x10000110000, 0x10000120000),
        )
        with self.assertRaisesRegex(ValueError, "overlap base topology"):
            g17g_backend.build_add_compute_graph(
                mixed_after_render=True,
                additional_dispatch_values=(((0.0,) * 64, (0.0,) * 64),),
                direct_buffer_base=0x10000110000,
                direct_buffer_page_stride=0x8000,
            )
        aliased = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(
                (((2.0,) * 64), ((3.0,) * 64)),
                (((4.0,) * 64), ((5.0,) * 64)),
            ),
            alias_final_dispatch_buffers=True,
        )
        self.assertEqual(
            tuple(aliased["dispatch_outputs"][1][name]
                  for name in ("buffer_a", "buffer_b", "output")),
            tuple(aliased["dispatch_outputs"][2][name]
                  for name in ("buffer_a", "buffer_b", "output")),
        )
        self.assertEqual(
            aliased["dispatch_outputs"][1]["expected_values"],
            aliased["dispatch_outputs"][2]["expected_values"],
        )
        self.assertTrue(aliased["aliased_final_dispatch_buffers"])
        with self.assertRaisesRegex(ValueError, "requires two dispatches"):
            g17g_backend.build_add_compute_graph(
                alias_final_dispatch_buffers=True,
            )
        aliased_record = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(
                (((2.0,) * 64), ((3.0,) * 64)),
                (((4.0,) * 64), ((5.0,) * 64)),
            ),
            alias_final_dispatch_buffers=True,
            alias_final_dispatch_shader=True,
        )
        cdm = aliased_record["context1_writes"][
            g17g_backend.COMPUTE_MIXED_CDM
        ]
        self.assertEqual(
            cdm[g17g_compute.CDM_RECORD_SIZE + 8:
                g17g_compute.CDM_RECORD_SIZE + 16],
            cdm[2 * g17g_compute.CDM_RECORD_SIZE + 8:
                2 * g17g_compute.CDM_RECORD_SIZE + 16],
        )
        self.assertTrue(aliased_record["aliased_final_dispatch_shader"])
        truncated = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(
                (((2.0,) * 64), ((3.0,) * 64)),
                (((4.0,) * 64), ((5.0,) * 64)),
            ),
            truncate_final_dispatch_extent=True,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", truncated["firmware_objects"]["descriptor"], 0xEE0
            )[0],
            g17g_backend.COMPUTE_MIXED_CDM
            + 2 * g17g_compute.CDM_RECORD_SIZE,
        )
        self.assertTrue(truncated["truncated_final_dispatch_extent"])
        exact_identity = 0xC7010000FD
        exact = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(((0.0,) * 64, (0.0,) * 64),),
            dispatch_identity=exact_identity,
        )
        self.assertEqual(exact["dispatch_identity"], exact_identity)
        self.assertEqual(
            struct.unpack_from(
                "<Q", exact["firmware_objects"]["descriptor"],
                g17g_compute.COMPUTE_REGISTER_START + 23 * 12 + 4,
            )[0],
            exact_identity,
        )
        exact_generation = 0x17
        generated = g17g_backend.build_add_compute_graph(
            queue_generation=exact_generation,
        )
        self.assertEqual(generated["queue_generation"], exact_generation)
        self.assertEqual(
            g17g.parse_queue_record(
                generated["firmware_objects"]["queue"][
                    :g17g.QUEUE_RECORD_SIZE
                ]
            )["word_40"],
            (exact_generation << 32) | 0xFFFFFFFF,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H", generated["firmware_objects"]["optional"], 0x5A
            )[0],
            exact_generation,
        )
        with self.assertRaisesRegex(ValueError, "does not fit in u32"):
            g17g_backend.build_add_compute_graph(
                queue_generation=1 << 32,
            )
        padded = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(((0.0,) * 64, (0.0,) * 64),),
            trailing_zero_page_count=3,
        )
        self.assertEqual(padded["trailing_zero_page_count"], 3)
        self.assertEqual(
            set(padded["context1_dvas"]) - set(graph["context1_dvas"]),
            {
                g17g_backend.COMPUTE_DIRECT_BUFFER_BASE + 0xC000,
                g17g_backend.COMPUTE_DIRECT_BUFFER_BASE + 0x10000,
                g17g_backend.COMPUTE_DIRECT_BUFFER_BASE + 0x14000,
            },
        )
        split_trailing_base = 0x10011000000
        split_padded = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=(((0.0,) * 64, (0.0,) * 64),),
            trailing_zero_page_count=3,
            trailing_zero_page_base=split_trailing_base,
        )
        self.assertEqual(
            split_padded["trailing_zero_page_base"], split_trailing_base
        )
        self.assertEqual(
            set(split_padded["context1_dvas"])
            - set(graph["context1_dvas"]),
            {
                split_trailing_base,
                split_trailing_base + 0x4000,
                split_trailing_base + 0x8000,
            },
        )
        with self.assertRaisesRegex(ValueError, "not page aligned"):
            g17g_backend.build_add_compute_graph(
                trailing_zero_page_count=1,
                trailing_zero_page_base=1,
            )
    def test_host_four_dispatch_single_descriptor_compute_backend_graph(self):
        graph = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=tuple(
                (
                    tuple(float(ordinal * 1000 + index)
                          for index in range(64)),
                    (float(ordinal) - 0.75,) * 64,
                )
                for ordinal in range(2, 5)
            ),
        )
        self.assertEqual(graph["direct_dispatch_count"], 4)
        self.assertEqual(graph["compute_descriptor_count"], 1)
        self.assertEqual(graph["cdm_group_sizes"], (0xB4,))
        self.assertEqual(graph["cdm_size"], 0xB4)
        fourth = graph["dispatch_outputs"][3]
        resource = graph["context1_writes"][
            g17g_backend.COMPUTE_MIXED_RESOURCE
        ]
        self.assertEqual(
            struct.unpack_from("<3Q", resource, 0x1500),
            (fourth["buffer_a"], fourth["buffer_b"], fourth["output"]),
        )
        self.assertEqual(
            struct.unpack(
                "<3Q", graph["firmware_objects"]["item_ring"]
            ),
            (
                graph["addresses"]["optional"],
                graph["addresses"]["descriptor"],
                graph["addresses"]["event"],
            ),
        )
        self.assertEqual(
            graph["context1_writes"][g17g_backend.COMPUTE_MIXED_SHADER][
                3 * g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE:
                3 * g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE + 6
            ],
            bytes.fromhex("2c8002001408"),
        )
        self.assertEqual(
            len(graph["firmware_patches"]["channel_ring"]), 1
        )
        self.assertEqual(
            g17g.parse_ring_slot(
                graph["firmware_patches"]["channel_ring"][0][1]
            )["word_14"],
            0x01000003,
        )

        nine = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=tuple(
                (
                    tuple(float(ordinal * 1000 + index)
                          for index in range(64)),
                    (float(ordinal) - 0.75,) * 64,
                )
                for ordinal in range(2, 10)
            ),
        )
        self.assertEqual(nine["direct_dispatch_count"], 9)
        self.assertEqual(
            nine["dispatch_identity"],
            g17g_backend.COMPUTE_MIXED_DISPATCH_IDENTITY + 3,
        )
        descriptor = nine["firmware_objects"]["descriptor"]
        for register_index in (23, 24, 25):
            register, value = struct.unpack_from(
                "<IQ",
                descriptor,
                g17g_compute.COMPUTE_REGISTER_START
                + register_index * g17g_compute.COMPUTE_REGISTER_SIZE,
            )
            self.assertIn(register, (0x1A540, 0x014A9, 0x0A351))
            self.assertEqual(value, 0x000000CB010000F4)

        ten = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=tuple(
                ((0.0,) * 64, (0.0,) * 64) for _index in range(9)
            ),
        )
        self.assertEqual(ten["direct_dispatch_count"], 10)
        self.assertEqual(
            ten["dispatch_identity"],
            nine["dispatch_identity"],
        )

        twelve = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=tuple(
                ((0.0,) * 64, (0.0,) * 64) for _index in range(11)
            ),
        )
        self.assertEqual(
            twelve["dispatch_identity"],
            nine["dispatch_identity"],
        )
        self.assertEqual(twelve["compute_descriptor_count"], 1)

        split_twelve = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=tuple(
                ((0.0,) * 64, (0.0,) * 64) for _index in range(11)
            ),
            direct_dispatch_group_capacity=11,
        )
        self.assertEqual(split_twelve["compute_descriptor_count"], 2)
        self.assertEqual(split_twelve["cdm_group_sizes"], (0x1E8, 0x30))
        self.assertEqual(
            split_twelve["direct_dispatch_group_capacity"], 11
        )
        self.assertEqual(
            struct.unpack(
                "<6Q", split_twelve["firmware_objects"]["item_ring"]
            ),
            (
                split_twelve["addresses"]["optional"],
                split_twelve["addresses"]["descriptor"],
                split_twelve["addresses"]["event"],
                split_twelve["addresses"]["optional_1"],
                split_twelve["addresses"]["descriptor_1"],
                split_twelve["addresses"]["event_1"],
            ),
        )
        self.assertEqual(
            len(split_twelve["firmware_patches"]["channel_ring"]), 2
        )
        self.assertEqual(
            tuple(
                g17g.parse_ring_slot(body)["word_14"]
                for _offset, body in
                split_twelve["firmware_patches"]["channel_ring"]
            ),
            (0x01000003, 0x00000006),
        )
        self.assertEqual(
            struct.unpack(
                "<I12xI12xI",
                split_twelve["firmware_patches"]["state"][0][1],
            ),
            (0, 0, 2),
        )
        grouped_sixty_four = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=tuple(
                ((0.0,) * 64, (0.0,) * 64) for _index in range(63)
            ),
            direct_dispatch_group_capacity=12,
        )
        self.assertEqual(grouped_sixty_four["compute_descriptor_count"], 6)
        self.assertEqual(
            grouped_sixty_four["cdm_group_sizes"],
            (0x214, 0x214, 0x214, 0x214, 0x214, 0xB4),
        )
        for group_index in range(1, 6):
            resource_page = (
                g17g_backend.COMPUTE_MIXED_RESOURCE
                + group_index * g17g_backend.PAGE_SIZE
            )
            self.assertIn(resource_page, grouped_sixty_four["context1_dvas"])
            self.assertIn(
                resource_page,
                grouped_sixty_four["context1_read_only_dvas"],
            )
        self.assertIn(
            g17g_backend.COMPUTE_MIXED_RESOURCE + 5 * g17g_backend.PAGE_SIZE,
            g17g_backend.context1_page_images(grouped_sixty_four),
        )
        with self.assertRaisesRegex(ValueError, "group capacity"):
            g17g_backend.build_add_compute_graph(
                direct_dispatch_group_capacity=0,
            )

    def test_host_compute_backend_graph(self):
        graph = g17g_backend.build_add_compute_graph()
        self.assertEqual(
            graph["format"],
            "m1n1-t8142-g17g-host-compute-graph-v1",
        )
        self.assertEqual(graph["channel"], 8)
        self.assertEqual(graph["grid_index"], 10)
        self.assertEqual(graph["cdm_size"], 0x30)
        self.assertEqual(
            graph["expected_values"],
            tuple(1000.5 + index for index in range(64)),
        )
        self.assertEqual(
            graph["context1_writes"][
                g17g_compute.COMPUTE_PIPELINE_SUPPORT_DVA
            ],
            g17g_compute.build_compute_pipeline_support(),
        )
        self.assertEqual(
            struct.unpack(
                "<64f",
                graph["context1_writes"][
                    g17g_backend.COMPUTE_BUFFER_A
                ],
            ),
            tuple(1000.0 + index for index in range(64)),
        )
        self.assertEqual(
            tuple(graph["firmware_objects"]),
            (
                "class2_state", "class2_support", "queue_context",
                "optional", "event", "descriptor", "job_list",
                "queue_aux", "pointers", "item_ring", "queue",
            ),
        )
        self.assertEqual(
            set(graph["firmware_patches"]), {"channel_ring", "state"}
        )
        self.assertEqual(len(graph["source_global_pages"]), 17)
        self.assertEqual(
            set(graph["source_global_pages"]),
            {
                0xFFFFFC2000000000,
                0xFFFFFC2000010000,
                0xFFFFFC2000024000,
                0xFFFFFC20001C8000,
                0xFFFFFC2001600000,
                0xFFFFFC2001608000,
                0xFFFFFC2001610000,
                0xFFFFFC20C0000000,
                0xFFFFFC20C0008000,
                0xFFFFFC20C07C0000,
                0xFFFFFC20C07D8000,
                0xFFFFFC20C07F0000,
                0xFFFFFC20C07F4000,
                0xFFFFFC20C0878000,
                0xFFFFFC20C087C000,
                0xFFFFFC20C08A8000,
                0xFFFFFC20C08B0000,
            },
        )
        self.assertTrue(all(
            not any(graph["source_global_pages"][address])
            for address in g17g_backend.COMPUTE_SOURCE_NEW_ZERO_GLOBAL_PAGES
        ))
        status_page = g17g_backend.build_compute_status_global_page()
        self.assertEqual(
            hashlib.sha256(status_page).hexdigest(),
            "6a432f5f738835af200a17b38622b04fffc74908f19e754cf930426274fc3b40",
        )
        self.assertEqual(
            graph["source_global_pages"][0xFFFFFC2000024000],
            status_page,
        )
        self.assertEqual(struct.unpack_from("<Q", status_page, 0xE48)[0], 0)
        self.assertEqual(struct.unpack_from("<Q", status_page, 0xE50)[0], 0)
        self.assertEqual(
            len(g17g_backend.COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES), 25
        )
        self.assertEqual(
            len(set(g17g_backend.COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES)), 25
        )
        self.assertTrue(all(
            not address & (g17g_backend.PAGE_SIZE - 1)
            for address in g17g_backend.COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES
        ))
        self.assertFalse(
            set(g17g_backend.COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES)
            & set(g17g_backend.COMPUTE_SOURCE_NEW_ZERO_GLOBAL_PAGES)
        )
        context1_pages = g17g_backend.context1_page_images(graph)
        self.assertEqual(len(context1_pages), 15)
        self.assertEqual(
            set(context1_pages),
            set(graph["context1_writes"])
            | {g17g_backend.COMPUTE_PAGE_LIST + 0x4000,
               g17g_backend.COMPUTE_PAGE_LIST + 0x8000},
        )
        self.assertTrue(all(
            len(body) == g17g_backend.PAGE_SIZE
            for body in context1_pages.values()
        ))
        self.assertEqual(
            struct.unpack_from(
                "<64f", context1_pages[g17g_backend.COMPUTE_BUFFER_A]
            ),
            tuple(1000.0 + index for index in range(64)),
        )
        self.assertFalse(any(
            context1_pages[g17g_backend.COMPUTE_BUFFER_A][64 * 4:]
        ))
        firmware_pages = g17g_backend.firmware_page_images(graph)
        self.assertEqual(len(firmware_pages), 11)
        self.assertTrue(all(
            len(body) == g17g_backend.PAGE_SIZE
            for body in firmware_pages.values()
        ))
        optional = firmware_pages[graph["addresses"]["optional"]]
        self.assertEqual(
            optional[:len(graph["firmware_objects"]["optional"])],
            graph["firmware_objects"]["optional"],
        )
        self.assertFalse(any(
            optional[len(graph["firmware_objects"]["optional"]):]
        ))
        runs = g17g_backend.context1_mapping_runs()
        self.assertEqual(
            sum(page_count for _address, page_count, _executable in runs),
            g17g_compute.COMPUTE_CONTEXT1_PAGE_COUNT,
        )
        self.assertTrue(any(executable for _address, _count, executable in runs))
        self.assertTrue(any(
            not executable for _address, _count, executable in runs
        ))

    def test_host_mixed_render_compute_graph_uses_channel_local_queue_zero(self):
        predecessor = (
            g17g_backend.build_earliest_mixed_clear_render_products()
        )
        params = predecessor["parameters"]
        self.assertEqual(
            predecessor["format"],
            "m1n1-t8142-g17g-host-earliest-mixed-clear-products-v1",
        )
        self.assertEqual(
            predecessor["token"],
            g17g_backend.EARLIEST_MIXED_RENDER_TOKEN,
        )
        self.assertEqual(params.target_dva, 0x10000098000)
        self.assertEqual(params.clear_state_page, 0x10000128000)
        self.assertEqual(params.store_pipeline, 0x10000148400)
        self.assertEqual(params.load_pipeline, 0x10000148200)
        self.assertEqual(params.auxiliary_object, 0x10000260000)
        self.assertEqual(
            predecessor["context1_writes"][0x10000088000],
            bytes(g17g_backend.PAGE_SIZE),
        )
        admission_zero = (
            g17g_backend.RENDER_MIXED_COMPUTE_ADMISSION_ZERO_DVA
        )
        self.assertEqual(
            predecessor["context1_writes"][admission_zero],
            bytes(g17g_backend.PAGE_SIZE),
        )
        self.assertIn(
            admission_zero,
            g17g_backend.render_context1_dvas(predecessor),
        )
        executable = {
            address + index * g17g_backend.PAGE_SIZE
            for address, count, read_only in
            g17g_backend.render_context1_mapping_runs(predecessor)
            if read_only
            for index in range(count)
        }
        self.assertNotIn(admission_zero, executable)
        self.assertNotIn(0x100000F8000, executable)
        mixed_callers = (
            g17g_backend.build_earliest_mixed_render_caller_pages(1)
        )
        expected_mixed_callers = {
            0x10000000000:
                "a31aaa0f07737fa94ed91ebd4a445abb96e4475c8772bd87e2c5487f7a8a6118",
            0x10000018000:
                "cb6d460eab398bcaeaddd46f78231f46c052b6a43e081eb79398a514441ad819",
        }
        for target, source in (
            (0x100000A0000, 0x10000140000),
            (0x10000104000, 0x100001A4000),
        ):
            expected_mixed_callers[target] = (
                g17g_partial_assets.PARTIAL_CONTEXT_PAGE_SHA256[source]
            )
        self.assertEqual(
            {
                dva: hashlib.sha256(body).hexdigest()
                for dva, body in mixed_callers.items()
            },
            expected_mixed_callers,
        )
        self.assertEqual(
            {dva: predecessor["context1_writes"][dva] for dva in mixed_callers},
            mixed_callers,
        )
        two_publication_callers = (
            g17g_backend.build_earliest_mixed_render_caller_pages(2)
        )
        two_publication_predecessor = (
            g17g_backend.build_earliest_mixed_clear_render_products(
                compute_publication_count=2
            )
        )
        two_publication_executable = {
            address + index * g17g_backend.PAGE_SIZE
            for address, count, read_only in
            g17g_backend.render_context1_mapping_runs(
                two_publication_predecessor
            )
            if read_only
            for index in range(count)
        }
        self.assertIn(0x100000F8000, two_publication_executable)
        self.assertEqual(
            hashlib.sha256(
                two_publication_callers[0x10000000000]
            ).hexdigest(),
            "b3f401d29ba6d12ddee1045df5670b20614971b22e41996770afb6267d8a6579",
        )
        self.assertEqual(
            hashlib.sha256(
                two_publication_callers[0x10000018000]
            ).hexdigest(),
            "3350bd87f4d0a00444e16f8c0cbd6a034ff0bd5d6e5f6469e7bf1d7e8067f667",
        )
        self.assertEqual(
            {
                dva: two_publication_predecessor["context1_writes"][dva]
                for dva in two_publication_callers
            },
            two_publication_callers,
        )
        self.assertIsNone(predecessor["captured_input"])
        self.assertEqual(
            g17g_mixed_render_assets.SOURCE_MANIFEST_SHA256,
            "04bc8a5adc8bbeb5c08011fd3fe716a2861bb3a7a317fcf80d283a29a1c47f9b",
        )
        self.assertEqual(
            g17g_mixed_render_assets.BASE_MANIFEST_SHA256,
            "c1a3c35054bf743540ace0b51d16e5c698049af0d6c2d600ca1cebedd1c51c6f",
        )
        self.assertEqual(
            params.tiling_lifecycle,
            g17g_backend.EARLIEST_MIXED_RENDER_LIFECYCLE,
        )
        self.assertEqual(
            g17g_backend.build_earliest_mixed_clear_render_products(
                compute_dispatch_count=12
            )["parameters"].tiling_lifecycle,
            g17g_backend.EARLIEST_MIXED_RENDER_LIFECYCLE + 9,
        )
        self.assertEqual(
            g17g_backend.build_earliest_mixed_clear_render_products(
                compute_dispatch_count=12,
                tiling_lifecycle=0xC901000155,
            )["parameters"].tiling_lifecycle,
            0xC901000155,
        )
        render_items = predecessor["items"]
        self.assertEqual(
            struct.unpack_from(
                "<H", render_items["tiling_optional"], 0x18
            )[0],
            1,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H", render_items["fragment_optional"], 0x18
            )[0],
            2,
        )
        self.assertEqual(
            struct.unpack_from(
                "<H", render_items["tiling_optional"], 0x3E
            )[0],
            2,
        )
        self.assertEqual(render_items["tiling_optional"][0x46], 1)
        self.assertEqual(render_items["fragment_optional"][0x56], 1)
        self.assertEqual(
            struct.unpack_from(
                "<I", render_items["tiling_event"], 0x04
            )[0],
            0x10001,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", render_items["fragment_event"], 0x04
            )[0],
            0x10002,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", render_items["tiling_descriptor"], 0x8A6
            )[0],
            g17g_render.DISPATCH_A + 4,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", render_items["fragment_descriptor"], 0x2140
            )[0],
            g17g_render.DISPATCH_A + 8,
        )
        late = predecessor["late_global_pages"]
        tiling_qctx = late[
            g17g_backend.RENDER_MIXED_TILING_FIRMWARE_SCRATCH
        ]
        fragment_qctx = late[
            g17g_backend.RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH
        ]
        self.assertEqual(
            struct.unpack_from("<Q", tiling_qctx, 0x200)[0],
            0x1000040000000004,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment_qctx, 0x200)[0],
            0x1000080000000004,
        )
        self.assertEqual(
            struct.unpack_from("<Q", tiling_qctx, 0x220)[0],
            0xFFFF0C0100000001,
        )
        self.assertEqual(
            struct.unpack_from("<Q", fragment_qctx, 0x220)[0],
            0xFFFF180100000003,
        )
        self.assertEqual(
            predecessor["firmware_alias_extensions"],
            {
                0x7200488000 + index * g17g_backend.PAGE_SIZE:
                    0xFFFFFC2000228000
                    + index * g17g_backend.PAGE_SIZE
                for index in range(8)
            },
        )

        two_publication = (
            g17g_backend.build_earliest_mixed_clear_render_products(
                compute_dispatch_count=2,
                compute_publication_count=2,
            )
        )
        two_control = two_publication["source_global_pages"][
            g17g_backend.RENDER_MIXED_TWO_SHARED_CONTROL
        ]
        self.assertEqual(
            hashlib.sha256(two_publication["source_global_pages"][
                g17g_backend.RENDER_MIXED_SHARED_CONTROL
            ]).hexdigest(),
            "a109c09caac83bd7d09778b962d2cab0"
            "e466bed929b318834138ff681ccaae20",
        )
        self.assertEqual(
            hashlib.sha256(two_control).hexdigest(),
            "8d5de5950d6a4376cbf4b7131acd1124"
            "0e834844422cfc708569d042476beab1",
        )
        self.assertEqual(struct.unpack_from("<I", two_control, 0)[0], 2)
        self.assertEqual(
            struct.unpack_from("<Q", two_control, 0x30)[0],
            0x7201EA8000,
        )
        two_service = (
            g17g_backend.build_first_mixed_clear_service_records(2)[2]
        )
        self.assertEqual(
            hashlib.sha256(two_service).hexdigest(),
            "725206cdd0e372513d74c375a81bdd29"
            "97ba40722ef866c2e46677e79454e79d",
        )
        self.assertEqual(
            struct.unpack_from("<Q", two_service, 0x14)[0],
            g17g_backend.RENDER_MIXED_TWO_SHARED_CONTROL,
        )
        self.assertEqual(
            struct.unpack_from("<Q", two_service, 0x1C)[0],
            g17g_backend.RENDER_MIXED_TWO_TAGGED_ADDRESS,
        )
        self.assertEqual(
            struct.unpack_from("<Q", two_control, 0x4C)[0],
            g17g_backend.COMPUTE_MIXED_SHARED_STATE,
        )
        self.assertEqual(
            hashlib.sha256(two_publication["source_global_pages"][
                0xFFFFFC20C08C8000
            ]).hexdigest(),
            "b5d3b70c821af1257b641c52108ed9fd"
            "94edbaf1c62bde6ff16a66c3e2c0ce33",
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q",
                predecessor["source_global_pages"][
                    g17g_postcontrol.QUEUE_ADDRESS_10_PAGE
                ],
                0x20,
            )[0],
            g17g_backend.COMPUTE_MIXED_JOB_LIST,
        )
        render_queue = predecessor["firmware_pages"]["queue"]
        stride = g17g.QUEUE_RECORD_STRIDE
        self.assertFalse(any(render_queue[0:stride]))
        self.assertTrue(any(render_queue[stride:2 * stride]))
        self.assertTrue(any(render_queue[2 * stride:3 * stride]))
        ta_slot = g17g.parse_ring_slot(
            predecessor["firmware_patches"]["channel_ring_6"][0][1]
        )
        fragment_slot = g17g.parse_ring_slot(
            predecessor["firmware_patches"]["channel_ring_7"][0][1]
        )
        self.assertEqual(
            (ta_slot["queue_address"], ta_slot["queue_index"],
             ta_slot["word_14"]),
            (
                g17g_postcontrol.QUEUE_PAGE + g17g.QUEUE_RECORD_STRIDE,
                1,
                0x01010003,
            ),
        )
        self.assertEqual(
            (fragment_slot["word_10"], fragment_slot["queue_index"],
             fragment_slot["word_14"]),
            (1, 2, 0x01020003),
        )

        graph = g17g_backend.build_add_compute_graph(
            mixed_after_render=True
        )
        addresses = graph["addresses"]
        objects = graph["firmware_objects"]
        self.assertEqual(
            graph["format"],
            "m1n1-t8142-g17g-host-mixed-compute-graph-v1",
        )
        self.assertEqual(graph["queue_index"], 0)
        self.assertEqual(graph["queue_generation"], 0x10E)
        self.assertEqual(addresses["queue"], 0xFFFFFC20C0000000)
        self.assertEqual(addresses["pointers"], 0xFFFFFC2000010000)
        self.assertEqual(addresses["item_ring"], 0xFFFFFC20C0008000)
        self.assertEqual(addresses["optional"], 0xFFFFFC20C0600000)
        self.assertEqual(addresses["event"], 0xFFFFFC20C05E8000)
        self.assertEqual(addresses["queue_context"], 0xFFFFFC20001D8000)
        self.assertEqual(addresses["shared_support"], 0xFFFFFC20C08C0000)
        self.assertEqual(addresses["shared_state"], 0xFFFFFC2001620000)
        self.assertEqual(
            len(g17g_backend.COMPUTE_MIXED_FIRST_TYPE84_BEFORE_GLOBAL_PAGES),
            10,
        )
        self.assertEqual(
            len(g17g_backend.COMPUTE_MIXED_FIRST_TYPE84_AFTER_GLOBAL_PAGES),
            23,
        )
        self.assertFalse(
            set(g17g_backend.COMPUTE_MIXED_FIRST_TYPE84_BEFORE_GLOBAL_PAGES)
            & set(g17g_backend.COMPUTE_MIXED_FIRST_TYPE84_AFTER_GLOBAL_PAGES)
        )
        history = bytearray(g17g_backend.PAGE_SIZE)
        struct.pack_into(
            "<8Q", history, 0x40,
            0x0101000000000033, 0x20,
            0x100, 0x110, 0x120, 0x140,
            g17g_backend.COMPUTE_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000080,
        )
        relocated = (
            g17g_backend.build_mixed_compute_first_type84_service_history(
                history
            )
        )
        self.assertEqual(
            set(relocated),
            {
                g17g_backend.RENDER_FIRST_SERVICE_HISTORY_PAGE,
                g17g_backend.RENDER_SECOND_SERVICE_HISTORY_PAGE,
            },
        )
        self.assertFalse(any(relocated[
            g17g_backend.RENDER_FIRST_SERVICE_HISTORY_PAGE
        ]))
        self.assertEqual(
            struct.unpack_from(
                "<8Q",
                relocated[g17g_backend.RENDER_SECOND_SERVICE_HISTORY_PAGE],
            ),
            (
                0x0001000000000033, 0x20,
                0x100, 0x110, 0x120, 0x140,
                g17g_backend.COMPUTE_DESCRIPTOR_PAGE,
                0xFFFFFC20C0000000,
            ),
        )
        struct.pack_into(
            "<Q", history, 0x40 + 7 * 8,
            0xFFFFFC20C0000000,
        )
        current_relocated = (
            g17g_backend.build_mixed_compute_first_type84_service_history(
                history
            )
        )
        self.assertEqual(current_relocated, relocated)
        standalone_history = bytearray(g17g_backend.PAGE_SIZE)
        struct.pack_into(
            "<8Q", standalone_history, 0,
            0x0001000000000033, 0x20,
            0x200, 0x210, 0x220, 0x250,
            g17g_backend.COMPUTE_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000000,
        )
        dependent_history = (
            g17g_backend.build_compute_to_render_service_history(
                standalone_history
            )
        )
        self.assertFalse(any(dependent_history[
            g17g_backend.RENDER_FIRST_SERVICE_HISTORY_PAGE
        ]))
        self.assertEqual(
            dependent_history[
                g17g_backend.RENDER_SECOND_SERVICE_HISTORY_PAGE
            ][:g17g_backend.RENDER_SERVICE_HISTORY_RECORD_SIZE],
            standalone_history[
                :g17g_backend.RENDER_SERVICE_HISTORY_RECORD_SIZE
            ],
        )
        self.assertFalse(any(dependent_history[
            g17g_backend.RENDER_SECOND_SERVICE_HISTORY_PAGE
        ][g17g_backend.RENDER_SERVICE_HISTORY_RECORD_SIZE:]))
        with self.assertRaisesRegex(ValueError, "header changed"):
            bad_history = bytearray(standalone_history)
            bad_history[0] ^= 1
            g17g_backend.build_compute_to_render_service_history(bad_history)
        self.assertEqual(
            g17g_backend.COMPUTE_TO_RENDER_HISTORY_CONTEXT_LOW,
            0x7201848000,
        )
        self.assertEqual(addresses["zero_page"], 0xFFFFFC2001628000)
        self.assertEqual(graph["source_global_pages"], {})
        self.assertEqual(
            hashlib.sha256(
                graph["context1_writes"][0x10000000000]
            ).hexdigest(),
            "a31aaa0f07737fa94ed91ebd4a445abb96e4475c8772bd87e2c5487f7a8a6118",
        )
        self.assertNotIn("class2_state", objects)
        self.assertNotIn("class2_support", objects)
        self.assertEqual(
            graph["fresh_firmware_page_flags"],
            {
                0xFFFFFC20001D8000: "shared",
                0xFFFFFC20001DC000: "shared",
                0xFFFFFC20001E0000: "shared",
                0xFFFFFC20001E4000: "shared",
                0xFFFFFC20001E8000: "shared",
                0xFFFFFC20001EC000: "shared",
                0xFFFFFC20001F0000: "shared",
                0xFFFFFC20001F4000: "shared",
                0xFFFFFC2001620000: "shared",
                0xFFFFFC20C08C0000: "normal",
                0xFFFFFC2001628000: "shared",
            },
        )
        self.assertEqual(
            g17g_backend.COMPUTE_MIXED_RETIRED_GLOBAL_PAGES,
            (0xFFFFFC20C0890000, 0xFFFFFC20C0894000),
        )
        self.assertEqual(
            len(g17g_backend.COMPUTE_MIXED_QUEUE_CONTEXT_TAIL_PAGES), 7
        )
        render_dvas = set(g17g_backend.render_context1_dvas(
            g17g_backend.build_clear_render_products()
        ))
        mixed_dvas = set(graph["context1_dvas"])
        retained_union = (
            render_dvas
            - set(g17g_backend.COMPUTE_MIXED_CONTEXT1_RETIRED_DVAS)
        ) | mixed_dvas
        self.assertEqual(len(retained_union), 2529)
        self.assertEqual(retained_union, mixed_dvas)

        optional = objects["optional"]
        self.assertEqual(struct.unpack_from("<H", optional, 0x18)[0], 0)
        self.assertEqual(struct.unpack_from("<H", optional, 0x1A)[0], 1)
        self.assertEqual(struct.unpack_from("<H", optional, 0x3E)[0], 1)
        self.assertEqual(optional[0x46], 0)
        self.assertEqual(struct.unpack_from("<H", optional, 0x5A)[0], 0x10E)
        self.assertEqual(struct.unpack_from("<H", optional, 0x62)[0], 1)
        self.assertEqual(
            struct.unpack_from("<Q", optional, 0x08)[0],
            g17g_backend.COMPUTE_QUEUE_CONTEXT_LOW,
        )
        self.assertEqual(
            struct.unpack_from("<I", objects["event"], 0x04)[0],
            0x10000,
        )
        slot = g17g.parse_ring_slot(
            graph["firmware_patches"]["channel_ring"][0][1]
        )
        self.assertEqual(slot["queue_address"], addresses["queue"])
        self.assertEqual(slot["queue_index"], 0)
        self.assertEqual(slot["word_14"], 0x01000003)

        queue_context = objects["queue_context"]
        self.assertEqual(
            struct.unpack_from("<Q", queue_context, 0x200)[0],
            0x1000000000000004,
        )
        self.assertEqual(
            struct.unpack_from("<Q", queue_context, 0x228)[0],
            0,
        )
        descriptor = objects["descriptor"]
        self.assertEqual(struct.unpack_from("<Q", descriptor, 0x04)[0], 0)
        self.assertEqual(struct.unpack_from("<I", descriptor, 0xF50)[0], 0x100)
        self.assertEqual(struct.unpack_from("<I", descriptor, 0xF54)[0], 0)
        self.assertEqual(struct.unpack_from("<I", descriptor, 0xF60)[0], 1)
        self.assertEqual(
            struct.unpack_from("<Q", descriptor, 0xF70)[0], 0
        )
        self.assertEqual(
            struct.unpack_from("<Q", descriptor, 0xF40)[0],
            addresses["dispatch_a"],
        )
        self.assertEqual(
            struct.unpack_from("<Q", descriptor, 0xF48)[0],
            addresses["dispatch_b"],
        )

        support = objects["shared_support"]
        self.assertEqual(struct.unpack_from("<I", support, 0x00)[0], 2)
        self.assertEqual(struct.unpack_from("<I", support, 0x08)[0], 0)
        self.assertEqual(struct.unpack_from("<I", support, 0x10)[0], 2)
        self.assertEqual(support[0x25], 0x16)
        self.assertEqual(support[0x2D], 0x16)
        self.assertEqual(struct.unpack_from("<I", support, 0x5C)[0], 1)
        self.assertEqual(struct.unpack_from("<I", support, 0x60)[0], 2)
        self.assertEqual(
            struct.unpack_from("<I", support, 0x14)[0], 0x00420000
        )
        self.assertEqual(
            struct.unpack_from("<Q", support, 0x30)[0], 0x7200828000
        )
        self.assertIn(0x7200420000, graph["context1_dvas"])
        self.assertIn(0x7200840000, graph["context1_dvas"])
        self.assertIn(0x7200828000, graph["context1_writes"])
        self.assertNotIn(
            g17g_backend.COMPUTE_CLIENT_STATE, graph["context1_writes"]
        )
        self.assertEqual(
            graph["context1_writes"][g17g_backend.COMPUTE_MIXED_SCRATCH],
            bytes(8 * g17g_backend.PAGE_SIZE),
        )
        self.assertIn(
            g17g_backend.COMPUTE_MIXED_SHADER, graph["context1_writes"]
        )
        self.assertIn(
            g17g_backend.COMPUTE_MIXED_CDM, graph["context1_writes"]
        )
        self.assertIn(
            g17g_backend.COMPUTE_MIXED_RESOURCE,
            graph["context1_writes"],
        )
        relocated_caller_pages = (
            g17g_backend.build_mixed_compute_relocated_caller_pages()
        )
        self.assertEqual(
            {
                address: graph["context1_writes"][address]
                for address in relocated_caller_pages
            },
            relocated_caller_pages,
        )
        self.assertEqual(
            hashlib.sha256(
                relocated_caller_pages[0x100000FC000]
            ).hexdigest(),
            "0fa41d5bab4fb10165159d9e77055e81916ee2ca85436fb1a44bbee93e880b1c",
        )
        self.assertEqual(
            hashlib.sha256(
                relocated_caller_pages[0x1000010C000]
            ).hexdigest(),
            "46d45e3cf7376b8d2143e5d3524b8712544b064dd8c3fafe20946f3f6f251007",
        )
        self.assertNotIn(
            g17g_backend.COMPUTE_SHADER, graph["context1_writes"]
        )
        pipeline_support = graph["context1_writes"][
            g17g_compute.COMPUTE_PIPELINE_SUPPORT_DVA
        ]
        self.assertEqual(struct.unpack_from("<H", pipeline_support)[0], 0x340)
        self.assertEqual(
            pipeline_support[0x2A0:0x2C0],
            g17g_compute.COMPUTE_PIPELINE_RECORD * 2,
        )
        self.assertEqual(
            pipeline_support[
                g17g_compute.COMPUTE_PIPELINE_AUX_RECORD_OFFSET:
                g17g_compute.COMPUTE_PIPELINE_AUX_RECORD_OFFSET
                + len(g17g_compute.COMPUTE_PIPELINE_AUX_RECORD)
            ],
            g17g_compute.COMPUTE_PIPELINE_AUX_RECORD,
        )
        self.assertEqual(len(graph["context1_dvas"]), 2529)
        self.assertEqual(len(graph["context1_retired_dvas"]), 0)
        self.assertEqual(len(graph["context1_repermission_dvas"]), 0)
        self.assertEqual(
            sum(
                page_count for _address, page_count, _executable
                in g17g_backend.context1_mapping_runs(graph)
            ),
            2529,
        )
        with self.assertRaisesRegex(ValueError, "not page aligned"):
            g17g_backend.firmware_page_images(graph)

    def test_host_mixed_partial_render_uses_coherent_transport(self):
        ordinary_partial = g17g_backend.build_partial_render_products()
        for publication_count, token, lifecycle in (
            (1, g17g_backend.EARLIEST_MIXED_RENDER_TOKEN,
             g17g_backend.EARLIEST_MIXED_RENDER_LIFECYCLE),
            (2, g17g_backend.RENDER_MIXED_TWO_TOKEN,
             g17g_backend.RENDER_MIXED_TWO_LIFECYCLE),
        ):
            products = (
                g17g_backend.build_earliest_mixed_partial_render_products(
                    compute_publication_count=publication_count
                )
            )
            self.assertEqual(
                products["format"],
                "m1n1-t8142-g17g-host-earliest-mixed-partial-products-v1",
            )
            self.assertTrue(products["partial_render"])
            self.assertTrue(products["mixed_compute_pending"])
            self.assertIsNone(products["captured_input"])
            self.assertEqual(products["compute_publication_count"], publication_count)
            self.assertEqual(products["token"], token)
            self.assertEqual(products["parameters"].tiling_lifecycle, lifecycle)
            self.assertEqual(len(products["attachments"]), 8)
            self.assertEqual(
                products["parameters"].target_dva,
                g17g_backend.MIXED_PARTIAL_RENDER_ATTACHMENT_BASE,
            )
            self.assertEqual(
                products["attachment_relocation"]["pointer_rewrite_count"],
                1,
            )
            self.assertEqual(
                tuple(item["base"] for item in products["attachments"]),
                tuple(
                    g17g_backend.MIXED_PARTIAL_RENDER_ATTACHMENT_BASE
                    + index * g17g_backend.PARTIAL_RENDER_ATTACHMENT_STRIDE
                    for index in range(8)
                ),
            )
            self.assertNotIn(
                g17g_backend.PARTIAL_RENDER_ATTACHMENT_BASE,
                products["attachment_pages"],
            )
            self.assertEqual(
                products["context1_writes"][0x10000000000],
                ordinary_partial["context1_writes"][0x10000000000],
            )
            self.assertEqual(
                products["context1_writes"][0x10000018000],
                ordinary_partial["context1_writes"][0x10000018000],
            )
            mixed_callers = (
                g17g_backend.build_earliest_mixed_render_caller_pages(
                    publication_count
                )
            )
            for address, body in mixed_callers.items():
                if address not in (0x10000000000, 0x10000018000):
                    self.assertEqual(products["context1_writes"][address], body)
            transport = g17g_backend.build_clear_render_products(
                params=products["parameters"],
                token=token,
                mixed_compute_pending=True,
                compute_publication_count=publication_count,
            )
            for key in (
                "items", "firmware_addresses", "firmware_pages",
                "firmware_patches", "source_global_pages", "late_global_pages",
                "fresh_global_pages", "fresh_global_page_flags",
                "firmware_alias_extensions",
            ):
                self.assertEqual(products[key], transport[key])
            mixed_context = (
                g17g_backend.build_earliest_mixed_partial_render_products(
                    compute_publication_count=publication_count,
                    mixed_context_page_mask=3,
                )
            )
            self.assertEqual(mixed_context["mixed_context_page_mask"], 3)
            for address in (0x10000000000, 0x10000018000):
                self.assertEqual(
                    mixed_context["context1_writes"][address],
                    mixed_callers[address],
                )

        with self.assertRaisesRegex(ValueError, "mask"):
            g17g_backend.build_earliest_mixed_partial_render_products(
                mixed_context_page_mask=4
            )

        sequential = (
            g17g_backend.build_earliest_mixed_partial_render_products(
                compute_predecessor=True
            )
        )
        simultaneous = (
            g17g_backend.build_earliest_mixed_partial_render_products()
        )
        self.assertTrue(sequential["compute_predecessor"])
        self.assertFalse(simultaneous["compute_predecessor"])
        self.assertTrue(sequential["compute_predecessor_family"])
        self.assertFalse(simultaneous["compute_predecessor_family"])
        self.assertEqual(
            sequential["token"],
            g17g_backend.COMPUTE_PREDECESSOR_RENDER_TOKEN,
        )
        self.assertEqual(
            sequential["parameters"].tiling_lifecycle,
            g17g_backend.COMPUTE_PREDECESSOR_RENDER_LIFECYCLE,
        )
        sequential_two_compute = (
            g17g_backend.build_earliest_mixed_partial_render_products(
                compute_publication_count=2,
                compute_predecessor=True,
            )
        )
        self.assertEqual(
            sequential_two_compute["token"],
            g17g_backend.COMPUTE_PREDECESSOR_RENDER_TOKEN,
        )
        self.assertEqual(
            sequential_two_compute["parameters"].tiling_lifecycle,
            g17g_backend.COMPUTE_PREDECESSOR_RENDER_LIFECYCLE,
        )
        self.assertEqual(
            sequential_two_compute["compute_publication_count"], 2
        )
        self.assertEqual(
            set(sequential_two_compute["firmware_pages"]),
            {
                "queue", "pointers", "pointers_tail", "item_ring",
                "item_ring_tail", "optional", "event",
                "tiling_descriptor", "fragment_descriptor",
            },
        )
        self.assertEqual(
            sequential_two_compute["firmware_live_preserve_ranges"],
            sequential["firmware_live_preserve_ranges"],
        )
        self.assertEqual(
            sequential_two_compute["fresh_global_pages"],
            sequential["fresh_global_pages"],
        )
        self.assertEqual(
            sequential["parameters"].target_dva,
            0x10000070000,
        )
        self.assertEqual(
            sequential["context1_aliases"],
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_CONTEXT1_ALIASES,
        )
        self.assertEqual(len(sequential["context1_aliases"]), 4)
        self.assertLessEqual(
            set(sequential["context1_aliases"]),
            set(g17g_backend.render_context1_dvas(sequential)),
        )
        self.assertLessEqual(
            set(sequential["context1_aliases"].values()),
            set(sequential["fresh_global_pages"]),
        )
        self.assertEqual(
            sequential["parameters"].store_pipeline,
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_STORE_PIPELINE,
        )
        self.assertEqual(
            sequential["parameters"].load_pipeline,
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_LOAD_PIPELINE,
        )
        self.assertEqual(
            sequential["parameters"].resolved_partial_load_pipeline(),
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_RELOAD_PIPELINE,
        )
        self.assertEqual(
            sequential["parameters"].auxiliary_object,
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_AUXILIARY_OBJECT,
        )
        self.assertEqual(
            sequential["parameters"].resolved_scissor_array(),
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_SCISSOR_ARRAY,
        )
        self.assertEqual(
            sequential["parameters"].resolved_depth_bias_array(),
            g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_DEPTH_BIAS_ARRAY,
        )
        self.assertEqual(
            set(sequential["precompute_context1_writes"]),
            {g17g_render.RENDER_BASE10_SUPPORT_DVA, 0x10000018000},
        )
        self.assertEqual(
            sequential["precompute_context1_writes"][
                g17g_render.RENDER_BASE10_SUPPORT_DVA
            ],
            sequential["context1_writes"][
                g17g_render.RENDER_BASE10_SUPPORT_DVA
            ],
        )
        self.assertEqual(
            hashlib.sha256(
                sequential["precompute_context1_writes"][0x10000018000]
            ).hexdigest(),
            "ae46fdaefc78cd2a0df30f7fd622f94669372681bbe6a3290bd6526a4c18b9b4",
        )
        self.assertEqual(simultaneous["precompute_context1_writes"], {})
        for address, body in (
                g17g_mixed_partial_assets
                .build_mixed_partial_context_pages().items()):
            self.assertEqual(sequential["context1_writes"][address], body)
        for index in range(
                g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_COMPILER_PAGE_COUNT):
            source = (
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_COMPILER_SOURCE_BASE
                + index * g17g_backend.PAGE_SIZE
            )
            target = (
                source
                + g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_COMPILER_RELOCATION
            )
            self.assertNotIn(source, sequential["context1_writes"])
            self.assertEqual(
                sequential["context1_writes"][target],
                ordinary_partial["context1_writes"][source],
            )
        for address in (
                g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_ZERO_COMPILER_PAGES):
            self.assertEqual(
                sequential["context1_writes"][address],
                bytes(g17g_backend.PAGE_SIZE),
            )
        self.assertNotIn(0x1000240000, sequential["context1_writes"])
        allocation_index = sequential["fresh_global_pages"][
            0xFFFFFC20C08D0000
        ]
        self.assertEqual(
            struct.unpack_from("<48I", allocation_index),
            tuple(
                value
                for start in (0x12, 0x23, 0x34)
                for value in range(start, start + 0x10)
            ),
        )
        self.assertEqual(allocation_index[0xC0:], bytes(0x4000 - 0xC0))
        self.assertEqual(
            hashlib.sha256(allocation_index).hexdigest(),
            g17g_backend
            .COMPUTE_PREDECESSOR_PARTIAL_ALLOCATION_INDEX_SHA256,
        )
        self.assertEqual(sequential["source_global_pages"], {})
        self.assertEqual(
            set(sequential["fresh_global_pages"]),
            set(g17g_backend.COMPUTE_TO_PARTIAL_RENDER_NEW_GLOBAL_PAGES),
        )
        self.assertEqual(len(sequential["fresh_global_pages"]), 36)
        self.assertEqual(
            sequential["fresh_global_page_flags"][
                g17g_backend.COMPUTE_PREDECESSOR_RENDER_TILING_STATUS
            ],
            "shared_executable",
        )
        self.assertEqual(
            sequential["fresh_global_page_flags"][
                g17g_backend.COMPUTE_PREDECESSOR_RENDER_FRAGMENT_STATUS
            ],
            "shared_executable",
        )
        relocated_lists = g17g_render.build_render_address_list_pages(
            buffer_base=(
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE
            ),
            address_list_base=(
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_ADDRESS_LIST_BASE
            ),
            operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT,
        )
        self.assertEqual(len(relocated_lists), 5)
        for address, body in relocated_lists.items():
            self.assertEqual(sequential["context1_writes"][address], body)
        self.assertEqual(
            sequential["context1_writes"][
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_TABLE
            ],
            g17g_render.build_render_operand_table(
                buffer_base=(
                    g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE
                ),
                operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT,
            ),
        )
        for address in g17g_render.build_render_address_list_pages(
                operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT):
            self.assertNotIn(address, sequential["context1_writes"])
        self.assertNotIn(
            g17g_render.RENDER_OPERAND_TABLE_DVA,
            sequential["context1_writes"],
        )
        self.assertEqual(
            sequential["context1_extra_runs"],
            (
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_RUNS
                + g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_ZERO_RESERVATION_RUNS
                + g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_RETAINED_CONTEXT1_RUNS
            ),
        )
        sequential_dvas = set(g17g_backend.render_context1_dvas(sequential))
        for base, page_count, read_only in (
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_RUNS):
            self.assertFalse(read_only)
            self.assertLessEqual(
                {
                    base + index * g17g_backend.PAGE_SIZE
                    for index in range(page_count)
                },
                sequential_dvas,
            )
        zero_reservation_dvas = {
            base + index * g17g_backend.PAGE_SIZE
            for base, page_count, _read_only in (
                g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_ZERO_RESERVATION_RUNS
            )
            for index in range(page_count)
        }
        self.assertEqual(len(zero_reservation_dvas), 69)
        self.assertLessEqual(zero_reservation_dvas, sequential_dvas)
        self.assertFalse(
            zero_reservation_dvas
            & set(g17g_backend.render_context1_page_images(sequential))
        )
        excluded_dvas = set(sequential["context1_excluded_dvas"])
        self.assertEqual(len(excluded_dvas), 94)
        self.assertFalse(excluded_dvas & sequential_dvas)
        self.assertEqual(
            excluded_dvas,
            {
                base + index * g17g_backend.PAGE_SIZE
                for base, page_count in (
                    g17g_backend
                    .COMPUTE_PREDECESSOR_PARTIAL_RETIRED_CONTEXT1_RUNS
                )
                for index in range(page_count)
            },
        )
        mapped_permissions = {}
        for base, page_count, read_only in (
                g17g_backend.render_context1_mapping_runs(sequential)):
            mapped_permissions.update({
                base + index * g17g_backend.PAGE_SIZE: read_only
                for index in range(page_count)
            })
        for base, page_count, _read_only in (
                g17g_backend.COMPUTE_PREDECESSOR_PARTIAL_OPERAND_RUNS):
            self.assertTrue(all(
                not mapped_permissions[base + index * g17g_backend.PAGE_SIZE]
                for index in range(page_count)
            ))
        for base, page_count, read_only in (
                g17g_backend
                .COMPUTE_PREDECESSOR_PARTIAL_ZERO_RESERVATION_RUNS):
            self.assertTrue(all(
                mapped_permissions[base + index * g17g_backend.PAGE_SIZE]
                == read_only
                for index in range(page_count)
            ))
        permission_overrides = sequential[
            "context1_read_only_overrides"
        ]
        self.assertEqual(len(permission_overrides), 94)
        self.assertEqual(
            permission_overrides,
            {
                base + index * g17g_backend.PAGE_SIZE: read_only
                for base, page_count, read_only in (
                    g17g_backend
                    .COMPUTE_PREDECESSOR_PARTIAL_PERMISSION_RUNS
                )
                for index in range(page_count)
            },
        )
        for address, read_only in permission_overrides.items():
            self.assertEqual(mapped_permissions[address], read_only)
        self.assertEqual(
            sequential["firmware_live_preserve_ranges"],
            {
                "queue": ((0, g17g.QUEUE_RECORD_STRIDE),),
                "pointers": ((0, 0x2870),),
                "item_ring": ((0, 0x2870),),
                "optional": ((0, 0xC0),),
                "event": ((0, 0x40),),
            },
        )
        for name, expected_qword in (
            ("tiling_descriptor", 0x0000000200000000),
            ("fragment_descriptor", 0x0000000100000001),
        ):
            sequential_body = sequential["firmware_pages"][name]
            self.assertEqual(
                struct.unpack_from("<Q", sequential_body)[0],
                expected_qword,
            )
        shared = sequential["fresh_global_pages"][
            g17g_backend.COMPUTE_PREDECESSOR_RENDER_SHARED_CONTROL
        ]
        self.assertEqual(struct.unpack_from("<Q", shared, 0x00)[0], 2)
        self.assertEqual(
            struct.unpack_from("<Q", shared, 0x48)[0],
            0x0161800000000090,
        )
        self.assertEqual(
            struct.unpack_from("<Q", shared, 0x20)[0],
            0x0000240000000000,
        )
        target_records = sequential["fresh_global_pages"][
            0xFFFFFC20C08C0000
        ]
        self.assertEqual(
            struct.unpack_from("<Q", target_records, 0x00)[0],
            0x1000088000,
        )
        self.assertEqual(
            struct.unpack_from("<Q", target_records, 0x08)[0],
            0xFFFFFC2001630000,
        )
        self.assertEqual(
            struct.unpack_from("<Q", target_records, 0x40)[0],
            0xFFFFFC2001628040,
        )
        trailing = sequential["fresh_global_pages"][
            g17g_backend.COMPUTE_PREDECESSOR_RENDER_DESCRIPTOR_OBJECTS[1]
        ]
        for offset, value in (
            (0x20, 0xFFFFFC20C08D0000),
            (0x28, 0x1000240000),
            (0x44, 0xFFFFFC20C08C8000),
            (0x4C, 0xFFFFFC2001628000),
            (0x64, 0xFFFFFC2001638000),
        ):
            self.assertEqual(struct.unpack_from("<Q", trailing, offset)[0], value)

    def test_host_mixed_compute_fresh_publication_topology(self):
        graph = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=((
                tuple(2000.0 + index for index in range(64)),
                (1.25,) * 64,
            ),),
            direct_dispatch_group_capacity=1,
            fresh_queue_per_group=True,
        )
        addresses = graph["addresses"]
        objects = graph["firmware_objects"]
        self.assertTrue(graph["fresh_queue_per_group"])
        self.assertEqual(graph["compute_descriptor_count"], 2)
        self.assertEqual(
            (addresses["queue"], addresses["queue_1"]),
            (0xFFFFFC20C0000000, 0xFFFFFC20C0000180),
        )
        self.assertEqual(
            (addresses["pointers"], addresses["pointers_1"]),
            (0xFFFFFC2000010000, 0xFFFFFC2000017950),
        )
        self.assertEqual(
            (addresses["item_ring"], addresses["item_ring_1"]),
            (0xFFFFFC20C0008000, 0xFFFFFC20C000F950),
        )
        self.assertEqual(
            (addresses["queue_context"], addresses["queue_context_1"]),
            (0xFFFFFC20001D8000, 0xFFFFFC2000250000),
        )
        slots = tuple(
            g17g.parse_ring_slot(body)
            for _offset, body in graph["firmware_patches"]["channel_ring"]
        )
        self.assertEqual(
            tuple((slot["queue_address"], slot["queue_index"], slot["limit"])
                  for slot in slots),
            ((addresses["queue"], 0, 3), (addresses["queue_1"], 1, 3)),
        )
        for index, suffix in enumerate(("", "_1")):
            pointer = g17g.parse_pointer_block(objects["pointers" + suffix])
            self.assertEqual(pointer["field_40"], 3)
            self.assertEqual(
                struct.unpack("<3Q", objects["item_ring" + suffix]),
                (
                    addresses["optional" + suffix],
                    addresses["descriptor" + suffix],
                    addresses["event" + suffix],
                ),
            )
            descriptor = objects["descriptor" + suffix]
            self.assertEqual(
                struct.unpack_from("<I", descriptor, 0xF54)[0], index
            )
            self.assertEqual(
                struct.unpack_from("<I", descriptor, 0xF58)[0], index
            )
            optional = objects["optional" + suffix]
            self.assertEqual(
                struct.unpack_from("<H", optional, 0x18)[0], index
            )
            self.assertEqual(
                struct.unpack_from("<H", optional, 0x1A)[0], 1
            )
            self.assertEqual(
                struct.unpack_from("<H", optional, 0x3E)[0], 1
            )
            self.assertEqual(
                struct.unpack_from("<I", descriptor, 0xF50)[0], 0x100
            )
            self.assertEqual(
                struct.unpack_from("<I", descriptor, 0xF60)[0], 1
            )
            self.assertEqual(
                struct.unpack_from("<I", objects["event" + suffix], 0x08)[0],
                0x102,
            )
        self.assertEqual(
            struct.unpack_from("<Q", objects["descriptor_1"], 0xF7C)[0],
            0xFFFFFC2000024E68,
        )
        self.assertEqual(
            struct.unpack_from("<Q", objects["descriptor_1"], 0xFCB)[0],
            g17g_backend.COMPUTE_MIXED_FRESH_ZERO_BASE,
        )
        self.assertEqual(
            graph["context1_writes"][0x72004B0000], bytes(0x4000)
        )
        self.assertEqual(
            graph["context1_writes"][
                g17g_backend.COMPUTE_MIXED_FRESH_SCRATCH_BASE
            ],
            bytes(8 * 0x4000),
        )
        self.assertEqual(
            struct.unpack_from("<Q", objects["shared_state"])[0], 1
        )
        self.assertEqual(
            struct.unpack_from("<I", objects["shared_support"], 0x5C)[0], 1
        )

    def test_host_native_two_publication_mixed_topology(self):
        graph = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=((
                tuple(2000.0 + index for index in range(64)),
                (1.25,) * 64,
            ),),
            direct_dispatch_group_capacity=1,
            fresh_queue_per_group=True,
            native_two_publication_layout=True,
        )
        self.assertTrue(graph["native_two_publication_layout"])
        self.assertFalse(graph["deferred_fresh_shared_activation"])
        self.assertEqual(graph["queue_generation"], 0x107)
        self.assertEqual(
            {
                name: graph["addresses"][name]
                for name in (
                    "queue", "queue_1", "pointers", "pointers_1",
                    "item_ring", "item_ring_1", "optional", "optional_1",
                    "event", "event_1", "descriptor", "descriptor_1",
                    "queue_context", "queue_context_1",
                )
            },
            {
                "queue": 0xFFFFFC20C0000000,
                "queue_1": 0xFFFFFC20C0000100,
                "pointers": 0xFFFFFC2000010000,
                "pointers_1": 0xFFFFFC20000150E0,
                "item_ring": 0xFFFFFC20C0008000,
                "item_ring_1": 0xFFFFFC20C000D0E0,
                "optional": 0xFFFFFC20C0600000,
                "optional_1": 0xFFFFFC20C06000C0,
                "event": 0xFFFFFC20C05E8000,
                "event_1": 0xFFFFFC20C05E8040,
                "descriptor": 0xFFFFFC20C0358000,
                "descriptor_1": 0xFFFFFC20C0359040,
                "queue_context": 0xFFFFFC20001D8000,
                "queue_context_1": 0xFFFFFC2000200000,
            },
        )
        expected_hashes = {
            "descriptor":
                "54b4042116113684a0141b8ebaf2aaf7394b2ce3bd07b60c1a4abf83f6488e3e",
            "descriptor_1":
                "537034d6da3d171e4a780ea04cc133c95d87d7c8574108ae79071cafc412aace",
            "optional":
                "4ec04e798c53b964a7f500a7fe942b85386341e71714f8e03b3a4278951c5357",
            "optional_1":
                "6eb489185ea41eed1873e583eeed25c8f292ca82560f5772db599f2b06d72118",
            "event":
                "8fdb2b49819b4c59d4b76da24144c41b7892b641d0cee16c91a8ab11b638fa47",
            "event_1":
                "5371c71dd92b3a6fd413b7e7d6d4dd76a4ba903893686d1531ebecafa38feca9",
            "scheduler":
                "f79a298be24af60cbf41d5da25c6721490e36a1fa283ee298ed3aa1700645f1a",
            "scheduler_1":
                "9a6d3d713c9b700257253cd23e86330ff59f41df655799bee7aab40b8028ae26",
            "item_ring":
                "4a69c37d3c168431a8f40aeb727b0640b385fd1d1f7b7dc2e6fdfe3ab635a113",
            "item_ring_1":
                "c1c1626c2e083fcc140d05bedf0cb67faa38ef57e19b8c80011accbd12284c9f",
            "queue":
                "e85358b2269b4958119af73677213cb088373b7c3ee8907143768fa6f031b6cd",
            "queue_1":
                "bbccdbe3279104610cf61088d4e0625f83cc573ef145a5f175ab17f1ffa59bd0",
            "shared_support":
                "a7e59ea59d8f7a7a2bd1a041d97dde8fe51873e0785047a9270b1db6f545a503",
            "shared_state":
                "716ad7538f92bb3cb749146290fa25419ab65b4dfe2cffc980566194d825e0a3",
        }
        self.assertEqual(
            {
                name: hashlib.sha256(
                    graph["firmware_objects"][name]
                ).hexdigest()
                for name in expected_hashes
            },
            expected_hashes,
        )
        context_pages = g17g_backend.context1_page_images(graph)
        self.assertEqual(len(context_pages), 34)
        self.assertEqual(
            hashlib.sha256(context_pages[0x10000000000]).hexdigest(),
            "b3f401d29ba6d12ddee1045df5670b20614971b22e41996770afb6267d8a6579",
        )
        self.assertIn(0x7200438000, context_pages)
        self.assertIn(0x7200460000, context_pages)
        self.assertIn(0x7201EDC000, context_pages)
        self.assertEqual(
            hashlib.sha256(
                context_pages[
                    g17g_backend.COMPUTE_MIXED_TWO_RETAINED_CALLER_PAGE
                ]
            ).hexdigest(),
            "46d45e3cf7376b8d2143e5d3524b8712544b064dd8c3fafe20946f3f6f251007",
        )

        render = g17g_backend.build_earliest_mixed_clear_render_products(
            compute_publication_count=2
        )
        self.assertEqual(render["token"], 0x107)
        self.assertEqual(render["parameters"].tiling_lifecycle, 0xC901000120)
        self.assertEqual(
            {
                name: hashlib.sha256(body).hexdigest()
                for name, body in render["items"].items()
            },
            {
                "tiling_optional":
                    "330f7c52c4cc242320ea851913f087bf2c49fb08c1cca70af1d0f9c81eb014f9",
                "tiling_descriptor":
                    "25d8ba97f02f97b06017313284d6763454a4c43c7929859b12cd74d3e891e1fb",
                "tiling_event":
                    "bddcd0acc63ff152c5cc51efec7e625c2135a00ccffd00636ec51b4592ca9b34",
                "fragment_optional":
                    "17e2af121ad8772793199c66066f24de5accd163cf82fc38161f895c60f2abc1",
                "fragment_descriptor":
                    "086786d272a1ea03e78876d7043f6424f70a9a948d73aa842fc906bd6cdd054f",
                "fragment_event":
                    "833630e6aab0a92c066ed4f8c78d66e74bc93ac11c32fa01a78bd4d55deb2ba3",
            },
        )
        self.assertEqual(
            render["firmware_addresses"]["fragment_pointers"],
            0xFFFFFC2001658000,
        )
        self.assertEqual(
            render["firmware_addresses"]["fragment_item_ring"],
            0xFFFFFC20C0900000,
        )

        values = tuple(
            (
                tuple(float(ordinal * 1000 + index) for index in range(64)),
                (float(ordinal),) * 64,
            )
            for ordinal in range(1, 4)
        )
        multi = g17g_backend.build_add_compute_graph(
            mixed_after_render=True,
            additional_dispatch_values=values,
            direct_dispatch_group_capacity=2,
            fresh_queue_per_group=True,
            native_two_publication_layout=True,
        )
        self.assertEqual(multi["direct_dispatch_count"], 4)
        self.assertEqual(multi["compute_descriptor_count"], 2)
        self.assertEqual(multi["cdm_group_sizes"], (92, 92))
        self.assertEqual(
            [item["output"] for item in multi["dispatch_outputs"]],
            [
                0x10000040000,
                0x10010014000,
                0x10000440000,
                0x1001002C000,
            ],
        )

    def test_native_compute_group_builders(self):
        registers = g17g_compute.build_compute_registers(
            resource=0x100000F8000,
            cdm=0x100000C8000,
            robustness=0x1000018000,
            scratch=0x7200420000,
            dispatch_identity=0xC8010000D1,
        )
        self.assertEqual(len(registers), 40)
        self.assertEqual(registers[7], (0x0D4A1, 0x54B))
        self.assertEqual(registers[21], (0x1A141, 0))
        self.assertEqual(registers[37], (0x0A731, 0))
        second_registers = g17g_compute.build_compute_registers(
            resource=0x100000F8000,
            cdm=0x100000C8000,
            robustness=0x1000018000,
            scratch=0x7200420000,
            dispatch_identity=0xC8010000D1,
            work_ordinal=1,
        )
        self.assertEqual(second_registers[27], (0x10201, 0x101))
        self.assertEqual(second_registers[28], (0x10428, 0x101))

        descriptor = g17g_compute.build_compute_descriptor(
            registers=registers,
            scheduler_record=0xFFFFFC20C08A8100,
            low_alias=0x7200340000,
            cdm_terminator=0x100000C802C,
            dispatch_identity=0xC8010000D1,
            dispatch_a=0xFFFFFC20001C8000,
            dispatch_b=0xFFFFFC20C07D8000,
            status_a=0xFFFFFC2000024E48,
            status_b=0xFFFFFC2000024E50,
            shared_control=0xFFFFFC20C08B0000,
            zero_page=0xFFFFFC2001610000,
        )
        self.assertEqual(len(descriptor), g17g_compute.PAGE_SIZE)
        self.assertEqual(
            hashlib.sha256(descriptor).hexdigest(),
            "ae38991792e822ed175a48e1d36fb719"
            "e51b0c48b819fb4954ca187a0046d0a7",
        )
        self.assertEqual(struct.unpack_from("<4H", descriptor, 0x18),
                         (0x25, 0x27, 0x27, 0x28))
        self.assertEqual(struct.unpack_from("<I", descriptor, 0x748)[0], 40)
        self.assertEqual(
            struct.unpack_from("<I", descriptor, 0xF58)[0],
            0,
        )
        second_publication_descriptor = (
            g17g_compute.build_compute_descriptor(
                registers=registers,
                scheduler_record=0xFFFFFC20C08A8100,
                low_alias=0x7200340000,
                cdm_terminator=0x100000C802C,
                dispatch_identity=0xC8010000D1,
                dispatch_a=0xFFFFFC20001C8000,
                dispatch_b=0xFFFFFC20C07D8000,
                status_a=0xFFFFFC2000024E48,
                status_b=0xFFFFFC2000024E50,
                shared_control=0xFFFFFC20C08B0000,
                zero_page=0xFFFFFC2001610000,
                submit_sequence=1,
            )
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", second_publication_descriptor, 0xF58
            )[0],
            1,
        )
        split_identity_descriptor = g17g_compute.build_compute_descriptor(
            registers=registers,
            scheduler_record=0xFFFFFC20C08A8100,
            low_alias=0x7200340000,
            cdm_terminator=0x100000C802C,
            dispatch_identity=0xC8010000D1,
            dispatch_a=0xFFFFFC20001C8000,
            dispatch_b=0xFFFFFC20C07D8000,
            status_a=0xFFFFFC2000024E48,
            status_b=0xFFFFFC2000024E50,
            shared_control=0xFFFFFC20C08B0000,
            zero_page=0xFFFFFC2001610000,
            lifecycle_ordinal=256,
            queue_submission=2,
        )
        self.assertEqual(
            struct.unpack_from("<I", split_identity_descriptor, 0xF50)[0],
            0x200,
        )
        self.assertEqual(
            struct.unpack_from("<I", split_identity_descriptor, 0xF60)[0],
            256,
        )

        optional = g17g_compute.build_compute_optional(
            context_low=0x7200438000,
            context_high=0xFFFFFC20001D8000,
            shared_control=0xFFFFFC20C08B0000,
            channel_control=0xFFFFFC20C07C0000,
        )
        self.assertEqual(
            hashlib.sha256(optional).hexdigest(),
            "0561ccdff8229e7a3a7e5af3e3615978"
            "8c9f764277a0cab667e130eed176db7d",
        )
        second_queue_optional = g17g_compute.build_compute_optional(
            context_low=0x7200438000,
            context_high=0xFFFFFC20001D8000,
            shared_control=0xFFFFFC20C0000000,
            channel_control=0xFFFFFC20C07C0040,
            submission_ordinal=2,
            token=0x13E,
            first_queue=False,
        )
        self.assertEqual(
            hashlib.sha256(second_queue_optional).hexdigest(),
            "983c7d0362884a9606afc54a4429c8e6"
            "ed6a7285b5191096901e3f32175d2844",
        )
        mixed_repeat_optional = g17g_compute.build_compute_optional(
            context_low=0x7200438000,
            context_high=0xFFFFFC20001D8000,
            shared_control=0xFFFFFC20C08C0000,
            channel_control=0xFFFFFC20C07C0040,
            submission_ordinal=3,
            token=0x11E,
            first_queue=False,
        )
        self.assertEqual(
            hashlib.sha256(mixed_repeat_optional).hexdigest(),
            "1e82bc40ea25d9e48f2ff4c350afa065"
            "737658c18958bc461a56e8335714bfb5",
        )
        self.assertEqual(
            g17g_backend.COMPUTE_MIXED_DISPATCH_IDENTITY
            + g17g_backend.COMPUTE_MIXED_REPEAT_DISPATCH_IDENTITY_STRIDE,
            0x000000CD0100012A,
        )
        mixed_repeat_scheduler = (
            g17g_compute.build_compute_scheduler_record(
                0xFFFFFC2001608000, slot_index=2, work_id=2
            )
        )
        self.assertEqual(
            hashlib.sha256(mixed_repeat_scheduler).hexdigest(),
            "9a6d3d713c9b700257253cd23e86330f"
            "f59f41df655799bee7aab40b8028ae26",
        )
        second_queue_support = g17g_compute.build_compute_shared_support(
            0x7200408000,
            0xFFFFFC2000010000,
            active=2,
        )
        self.assertEqual(
            hashlib.sha256(second_queue_support).hexdigest(),
            "053316b16c0f88a6551027338b52fa81"
            "45df1d89c685afb0e8d805606e2b475d",
        )
        event = g17g_compute.build_compute_event()
        self.assertEqual(
            hashlib.sha256(event).hexdigest(),
            "8fdb2b49819b4c59d4b76da24144c41b"
            "7892b641d0cee16c91a8ab11b638fa47",
        )

        queue = g17g_compute.build_compute_queue_record(
            0xFFFFFC2000010000,
            0xFFFFFC20C0008000,
            0xFFFFFC2000000000,
            0xFFFFFC20C07C0000,
        )
        self.assertEqual(
            hashlib.sha256(queue).hexdigest(),
            "778c7e37db6b18d4fe132c35e544d3f6"
            "1272919400351272eb912952bdb7fbaf",
        )
        self.assertEqual(
            g17g.parse_queue_record(queue)["word_40"],
            0x119FFFFFFFF,
        )
        self.assertEqual(
            g17g_compute.build_compute_channel_slot(0xFFFFFC20C0000000),
            bytes.fromhex(
                "0000000000000000000000c020fcffff"
                "0200000003000001"
            ),
        )
        self.assertEqual(
            g17g_compute.build_compute_repeat_channel_slot(
                0xFFFFFC20C0000000
            ),
            bytes.fromhex(
                "0000000000000000000000c020fcffff"
                "0200000005000000"
            ),
        )
        self.assertEqual(
            g17g_compute.build_compute_full_group_channel_slot(
                0xFFFFFC20C0000080, item_limit=6
            ),
            bytes.fromhex(
                "0000000000000000800000c020fcffff"
                "0200000006000000"
            ),
        )
        with self.assertRaisesRegex(ValueError, "multiple of 3"):
            g17g_compute.build_compute_full_group_channel_slot(
                0xFFFFFC20C0000080, item_limit=5
            )

    def test_native_compute_caller_objects(self):
        compute_dvas = g17g_compute.expand_compute_context1_dvas()
        self.assertEqual(
            len(compute_dvas), g17g_compute.COMPUTE_CONTEXT1_PAGE_COUNT
        )
        self.assertEqual(compute_dvas[0], 0x1000000000)
        self.assertEqual(compute_dvas[-1], 0x2FFFFFF8000)
        read_only_dvas = g17g_compute.expand_compute_context1_read_only_dvas()
        self.assertEqual(len(read_only_dvas), 32)
        self.assertEqual(read_only_dvas[0], 0x1000000000)
        self.assertEqual(read_only_dvas[-1], 0x1000015C000)
        self.assertTrue(set(read_only_dvas) <= set(compute_dvas))

        address_lists = g17g_compute.build_compute_address_list_pages(
            0x7200448000
        )
        self.assertEqual(
            tuple(address_lists), g17g_compute.COMPUTE_ADDRESS_LIST_PAGE_DVAS
        )
        self.assertEqual(
            tuple(
                hashlib.sha256(address_lists[dva]).hexdigest()
                for dva in g17g_compute.COMPUTE_ADDRESS_LIST_PAGE_DVAS
            ),
            g17g_compute.COMPUTE_ADDRESS_LIST_PAGE_SHA256,
        )
        self.assertEqual(
            struct.unpack_from("<Q", address_lists[0x7200000000], 0)[0],
            0x7200448000,
        )
        self.assertEqual(address_lists[0x720000C000], bytes(0x4000))

        dispatch = g17g_compute.build_direct_dispatch(
            0x100000A8000, (64, 1, 1), (32, 1, 1)
        )
        cdm = g17g_compute.build_cdm_stream((dispatch,))
        self.assertEqual(len(cdm), 0x30)
        self.assertEqual(
            hashlib.sha256(cdm).hexdigest(),
            "0eca9d8b05ad0b4c6f2b4cb26c0a462d"
            "c24ed4905ede7d8ecaea16b5d355ee0c",
        )
        resources = g17g_compute.build_buffer_resource_table((
            0x10000030000,
            0x10000038000,
            0x10000040000,
        ))
        self.assertEqual(
            hashlib.sha256(resources).hexdigest(),
            "09b63c7fea5c1c5d7061e072bba411ac"
            "5ca9b7fb41c10513e5d4421d277eab43",
        )
        shader_page = (
            g17g_compute.G17G_ADD_SHADER
            + bytes(g17g_compute.PAGE_SIZE - len(g17g_compute.G17G_ADD_SHADER))
        )
        self.assertEqual(
            hashlib.sha256(shader_page).hexdigest(),
            "52584c2b62c89070fad0e0722c3670d5"
            "327e220b9978b7b35664d8e7eecaa5d6",
        )
        dual_shader = g17g_compute.build_add_shader_program(
            0x100000A8000, 0x100000B0000, dispatch_count=2
        )
        self.assertEqual(
            dual_shader[:8], bytes.fromhex("2ca0020012088000")
        )
        self.assertEqual(
            dual_shader[0xC0:0xC8], bytes.fromhex("2cc0020012088000")
        )
        second_shader = bytearray(
            dual_shader[:len(g17g_compute.G17G_ADD_SHADER)]
        )
        second_shader[1] = 0xC0
        self.assertEqual(
            dual_shader[0xC0:0xC0 + len(second_shader)], bytes(second_shader)
        )
        dual_resources = g17g_compute.build_buffer_resource_tables((
            (0x10000030000, 0x10000038000, 0x10000040000),
            (0x10000110000, 0x10000118000, 0x10000120000),
        ))
        self.assertEqual(
            struct.unpack_from("<3Q", dual_resources, 0x14A0),
            (0x10000030000, 0x10000038000, 0x10000040000),
        )
        self.assertEqual(
            struct.unpack_from("<3Q", dual_resources, 0x14C0),
            (0x10000110000, 0x10000118000, 0x10000120000),
        )
        four_shader = g17g_compute.build_add_shader_program(
            0x100000A8000, 0x100000B0000, dispatch_count=4
        )
        self.assertEqual(
            four_shader[0x240:0x248],
            bytes.fromhex("2c80020014088000"),
        )
        second_addresses = g17g_backend.compute_submission_addresses(2)
        self.assertEqual(second_addresses["shader"], 0x10000118000)
        self.assertEqual(second_addresses["resource"], 0x10000168000)
        self.assertEqual(second_addresses["cdm"], 0x10000138000)
        self.assertEqual(second_addresses["descriptor"], 0xFFFFFC20C0359040)
        self.assertEqual(g17g_backend.compute_scheduler_slot_index(64), 64)
        self.assertEqual(g17g_backend.compute_scheduler_slot_index(65), 1)
        self.assertEqual(
            g17g_compute.compute_queue_context_item_offset(254), 0x1FE00
        )
        self.assertEqual(
            g17g_compute.compute_queue_context_item_offset(255), 0
        )
        self.assertEqual(
            g17g_compute.compute_queue_context_item_offset(256), 0x200
        )
        self.assertEqual(
            g17g_backend.compute_dispatch_identity(2),
            0x000000CA010000F0,
        )
        self.assertEqual(
            g17g_backend.compute_dispatch_identity(2, queue_epoch=1),
            0x000000CA010000E6,
        )
        self.assertEqual(g17g_backend.compute_queue_generation(0), 0x119)
        self.assertEqual(g17g_backend.compute_queue_generation(1), 0x13E)
        self.assertEqual(g17g_backend.compute_queue_epoch(127), 0)
        self.assertEqual(g17g_backend.compute_queue_epoch(128), 1)
        self.assertEqual(g17g_backend.compute_queue_epoch(147), 1)
        self.assertEqual(g17g_backend.compute_queue_epoch(254), 1)
        self.assertEqual(g17g_backend.compute_queue_epoch(255), 2)
        self.assertEqual(g17g_backend.compute_queue_start_ordinal(2), 255)
        self.assertEqual(g17g_backend.compute_queue_command_capacity(0), 127)
        self.assertEqual(g17g_backend.compute_queue_command_capacity(1), 127)
        self.assertEqual(
            g17g_backend.COMPUTE_RECREATED_SCHEDULER_RECORD_COUNT, 20
        )
        self.assertEqual(
            g17g_backend.compute_submission_addresses(65)["scheduler"],
            g17g_backend.COMPUTE_GLOBAL_SCHEDULER,
        )
        self.assertEqual(
            g17g_backend.compute_client_submission_addresses(65),
            {
                key: g17g_backend.compute_submission_addresses(1)[key]
                for key in ("shader", "resource", "cdm")
            },
        )
        descriptor_189 = g17g_backend.compute_submission_addresses(189)
        self.assertLessEqual(
            descriptor_189["descriptor_low"]
            + g17g_compute.COMPUTE_DESCRIPTOR_OBJECT_SIZE,
            0x7200400000,
        )
        self.assertEqual(
            g17g_backend.compute_submission_addresses(190)["descriptor_low"],
            g17g_backend.COMPUTE_DESCRIPTOR_LOW_RELOCATED_BASE,
        )
        self.assertEqual(
            g17g_backend.compute_submission_addresses(210)["descriptor_low"],
            g17g_backend.COMPUTE_DESCRIPTOR_LOW_RELOCATED_BASE
            + 20 * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE,
        )
        descriptor_241 = g17g_backend.compute_submission_addresses(241)
        self.assertLess(
            descriptor_241["descriptor"],
            g17g_backend.COMPUTE_DESCRIPTOR_PAGE
            + 61 * g17g_compute.PAGE_SIZE,
        )
        self.assertEqual(
            g17g_backend.compute_submission_addresses(242)["descriptor"],
            g17g_backend.COMPUTE_DESCRIPTOR_PAGE,
        )
        recreated_queue = g17g_backend.compute_recreated_queue_addresses()
        self.assertEqual(recreated_queue["queue"], 0xFFFFFC20C1000000)
        self.assertEqual(recreated_queue["queue_aux"], 0xFFFFFC20C100C000)
        self.assertEqual(recreated_queue["scheduler"], 0xFFFFFC20C1010000)
        self.assertEqual(
            recreated_queue["queue_support"], 0xFFFFFC20C1018000
        )
        self.assertEqual(recreated_queue["pointers"], 0xFFFFFC2001800000)
        self.assertEqual(recreated_queue["job_list"], 0xFFFFFC2001804000)
        self.assertEqual(
            recreated_queue["scheduler_slot"], 0xFFFFFC2001808000
        )
        self.assertEqual(len(set(recreated_queue.values())), 9)
        self.assertEqual(
            g17g_backend.compute_recreated_queue_addresses(6),
            recreated_queue,
        )
        self.assertEqual(
            g17g_backend.compute_recreated_queue_addresses(7)["queue"],
            0xFFFFFC20C1020000,
        )
        self.assertEqual(
            g17g_backend.compute_batch_buffer_addresses(2),
            {
                "a": 0x11000000000,
                "b": 0x11000004000,
                "out": 0x11000008000,
            },
        )
        self.assertEqual(
            g17g_backend.compute_batch_buffer_addresses(30)["out"],
            0x110001C8000,
        )
        second_shader = g17g_compute.relocate_add_shader(
            g17g_backend.COMPUTE_SHADER, second_addresses["shader"]
        )
        self.assertEqual(second_shader[:8].hex(), "2ca002001208b400")
        self.assertEqual(
            hashlib.sha256(
                second_shader
                + bytes(g17g_compute.PAGE_SIZE - len(second_shader))
            ).hexdigest(),
            "b562982e898812ad0e527da8aa3a6271"
            "9dfb8f33a6745f865821606af436a7d3",
        )
        second_cdm = g17g_compute.build_cdm_stream((
            g17g_compute.build_direct_dispatch(
                second_addresses["shader"], (64, 1, 1), (32, 1, 1)
            ),
        ))
        self.assertEqual(
            hashlib.sha256(second_cdm).hexdigest(),
            "719faad18ae2d7405151f445ac654466"
            "1d66515df24dcdba2960ea843e00e3dc",
        )

        second_queue_context = (
            g17g_compute.build_compute_queue_context_item(
                0xFFFFFC20C0359040,
                0xFFFFFC20C0000000,
                item_index=1,
            )
        )
        self.assertEqual(len(second_queue_context), 0x200)
        self.assertEqual(
            struct.unpack_from("<4Q", second_queue_context, 0x00),
            (
                0x1000000000000008,
                0,
                0xFFFFFC20C0359040,
                0xFFFFFC20C0000000,
            ),
        )
        self.assertEqual(
            struct.unpack_from("<Q", second_queue_context, 0x28)[0], 1
        )
        self.assertEqual(
            struct.unpack_from("<Q", second_queue_context, 0x150)[0],
            0x000128039001A084,
        )
        self.assertEqual(
            struct.unpack_from("<Q", second_queue_context, 0x158)[0],
            0x000020039001A0BD,
        )
        context_item_64 = g17g_compute.build_compute_queue_context_item(
            0xFFFFFC20C0397FC0,
            0xFFFFFC20C0000000,
            item_index=63,
        )
        self.assertEqual(
            struct.unpack_from("<Q", context_item_64, 0)[0],
            0x1000000000000100,
        )
        self.assertEqual(
            struct.unpack_from("<Q", context_item_64, 0x28)[0], 63
        )
        recreated_context_item = (
            g17g_compute.build_compute_queue_context_item(
                0xFFFFFC20C03D8FC0,
                0xFFFFFC20C0000000,
                item_index=0,
            )
        )
        self.assertEqual(
            struct.unpack_from("<Q", recreated_context_item, 0)[0],
            0x1000000000000004,
        )
        self.assertEqual(
            struct.unpack_from("<Q", recreated_context_item, 0x150)[0],
            0x000128039001E080,
        )
        self.assertEqual(
            len(g17g_compute.build_compute_scheduler_record(
                0xFFFFFC2001600000, slot_index=64, work_id=63
            )),
            0x100,
        )
        pipeline_support = g17g_compute.build_compute_pipeline_support()
        self.assertEqual(len(pipeline_support), g17g_compute.PAGE_SIZE)
        self.assertEqual(
            pipeline_support[
                g17g_compute.COMPUTE_PIPELINE_RECORD_OFFSET:
                g17g_compute.COMPUTE_PIPELINE_RECORD_OFFSET
                + len(g17g_compute.COMPUTE_PIPELINE_RECORD)
            ],
            g17g_compute.COMPUTE_PIPELINE_RECORD,
        )
        self.assertEqual(
            pipeline_support[
                g17g_compute.COMPUTE_PIPELINE_AUX_RECORD_OFFSET:
                g17g_compute.COMPUTE_PIPELINE_AUX_RECORD_OFFSET
                + len(g17g_compute.COMPUTE_PIPELINE_AUX_RECORD)
            ],
            g17g_compute.COMPUTE_PIPELINE_AUX_RECORD,
        )
        expected_pipeline_support = bytearray(g17g_compute.PAGE_SIZE)
        expected_pipeline_support[0x2A0:0x2B0] = bytes.fromhex(
            "0700100f0000270004002000a50a0600"
        )
        expected_pipeline_support[0x3C0:0x3F0] = bytes.fromhex(
            "1ca010060f000302182210402f040302"
            "180210c04100800000002900041a2220"
            "a002040812000f080302010610400e00"
        )
        self.assertEqual(pipeline_support, bytes(expected_pipeline_support))

        exact_objects = (
            (
                g17g_compute.build_compute_queue_context(
                    0xFFFFFC20C0358000, 0xFFFFFC20C0000000
                ),
                "c6079bf9631c07a1be043791058dcc600"
                "0a7fe3fbd4f8531c817095838af5e35",
            ),
            (
                g17g_compute.build_compute_scheduler_record(
                    0xFFFFFC2001600000
                ),
                "b640836c4591fa92a83aea588f95ba632"
                "6b149a10d788fd75d479f5515d180a2",
            ),
            (
                g17g_compute.build_compute_scheduler_slot(),
                "2ae57ae4d3a88a7a369784c9737061cc"
                "026c03bd96e1acef865b29063267ed45",
            ),
            (
                g17g_compute.build_compute_shared_support(
                    0x7200408000, 0xFFFFFC2001608000
                ),
                "897f86e16ba95f89c8a41c14d396cf3"
                "3b57b1330de5afe452788403ce45e21f3",
            ),
            (
                g17g_compute.build_compute_shared_state(),
                "dfc53015b39cdf85a8eec8608cd741333"
                "0a8e260e8954bc315aedd85bd8954a0",
            ),
            (
                g17g_compute.build_compute_operand_table(0x7200448000),
                "3f6a8ce17830a27981a804d274d18c5e"
                "b53902643a77a9f7609131e243c2412a",
            ),
            (
                g17g_compute.build_compute_operand_page_lists(),
                "2aae7dc846aaf25f1cadf55f166686204"
                "6c6db9d65d84bdc07fa039dac405606",
            ),
        )
        for body, expected in exact_objects:
            with self.subTest(expected=expected):
                self.assertEqual(hashlib.sha256(body).hexdigest(), expected)

    def test_context1_numeric_topology(self):
        dvas = g17g_context1.expand_context1_dvas()
        self.assertEqual(len(g17g_context1.CONTEXT1_RUNS), 53)
        self.assertEqual(len(dvas), g17g_context1.EXPECTED_PAGE_COUNT)
        self.assertEqual(dvas[0], 0x1000000000)
        self.assertEqual(dvas[-1], 0x2FFFFFF8000)
        encoded = b"".join(struct.pack("<Q", va) for va in dvas)
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            g17g_context1.EXPECTED_DVA_SHA256,
        )
        aliases = g17g_context1.validate_postcontrol_aliases(
            g17g_postcontrol.POSTCONTROL_PAGE_DVAS
        )
        self.assertEqual(len(aliases), 9)
        self.assertEqual(
            aliases[0x1000238000], 0xFFFFFC20C08C8000
        )
        self.assertEqual(
            aliases[0x1000258000], 0xFFFFFC2001630000
        )

        tagged = g17g_context1.build_tagged_address_page()
        self.assertEqual(len(tagged), g17g_context1.PAGE_SIZE)
        self.assertEqual(
            hashlib.sha256(tagged).hexdigest(),
            g17g_context1.TAGGED_ADDRESS_PAGE_SHA256,
        )
        self.assertEqual(
            struct.unpack_from("<Q", tagged, 0)[0],
            0x2000007200420000,
        )
        self.assertEqual(
            struct.unpack_from(
                "<Q", tagged,
                (g17g_context1.TAGGED_ADDRESS_COUNT - 1)
                * g17g_context1.TAGGED_ADDRESS_STRIDE,
            )[0],
            0x2000007201E88000,
        )
        self.assertEqual(
            sum(bool(value) for value in tagged), 57
        )

        address_lists = g17g_context1.build_address_list_pages()
        self.assertEqual(
            tuple(address_lists), g17g_context1.ADDRESS_LIST_PAGE_DVAS
        )
        self.assertEqual(
            tuple(
                hashlib.sha256(address_lists[va]).hexdigest()
                for va in g17g_context1.ADDRESS_LIST_PAGE_DVAS
            ),
            g17g_context1.ADDRESS_LIST_PAGE_SHA256,
        )
        combined = b"".join(address_lists.values())
        self.assertEqual(struct.unpack_from("<Q", combined, 0)[0],
                         0x7200420000)
        self.assertEqual(
            struct.unpack_from("<Q", combined, 13 * 512 * 8 - 8)[0],
            0x7201E7F000,
        )
        self.assertEqual(
            combined[13 * 512 * 8:14 * 512 * 8], bytes(512 * 8)
        )

        completed_lists = g17g_context1.build_address_list_pages(
            completed=True
        )
        self.assertEqual(
            tuple(
                hashlib.sha256(completed_lists[va]).hexdigest()
                for va in g17g_context1.ADDRESS_LIST_PAGE_DVAS
            ),
            g17g_context1.ADDRESS_LIST_COMPLETED_PAGE_SHA256,
        )
        completed = b"".join(completed_lists.values())
        self.assertEqual(
            struct.unpack_from("<Q", completed, 13 * 512 * 8)[0],
            0x7201E88000,
        )
        self.assertEqual(
            struct.unpack_from("<Q", completed, 14 * 512 * 8 - 8)[0],
            0x7202087000,
        )

    def test_postcontrol_source_package_matches_native_snapshots(self):
        expected = {
            0xB4: (
                "8349c14baf45ee1c0f668ea1bea711406"
                "e1e0c31e0c6f3299fa0e32718ac088e"
            ),
            0xB3: (
                "7c0d0eb64938c95f4a34c5429510175a"
                "7edcfda5c215ac189378a289c6626db4"
            ),
        }
        for generation, expected_hash in expected.items():
            with self.subTest(generation=generation):
                pages = g17g_postcontrol.build_postcontrol_pages(generation)
                self.assertEqual(
                    tuple(pages), g17g_postcontrol.POSTCONTROL_PAGE_DVAS
                )
                self.assertEqual(len(pages), 43)
                self.assertEqual(sum(any(page) for page in pages.values()), 14)
                self.assertEqual(sum(
                    g17g_postcontrol.flag_class_for_address(va)
                    == g17g_postcontrol.FLAG_CLASS_SHARED_UXN
                    for va in pages
                ), 26)
                self.assertEqual(sum(
                    g17g_postcontrol.flag_class_for_address(va)
                    == g17g_postcontrol.FLAG_CLASS_SHARED_EXECUTABLE
                    for va in pages
                ), 1)
                self.assertEqual(sum(
                    g17g_postcontrol.flag_class_for_address(va)
                    == g17g_postcontrol.FLAG_CLASS_NORMAL_UXN
                    for va in pages
                ), 16)
                self.assertEqual(
                    g17g_postcontrol.flag_class_for_address(
                        0xFFFFFC2001610000
                    ),
                    g17g_postcontrol.FLAG_CLASS_SHARED_EXECUTABLE,
                )
                self.assertTrue(all(
                    len(page) == g17g_postcontrol.PAGE_SIZE
                    for page in pages.values()
                ))
                aggregate = b"".join(
                    pages[va]
                    for va in g17g_postcontrol.POSTCONTROL_PAGE_DVAS
                )
                self.assertEqual(
                    hashlib.sha256(aggregate).hexdigest(), expected_hash
                )
        with self.assertRaisesRegex(ValueError, "absent"):
            g17g_postcontrol.flag_class_for_address(0)

        aliases = g17g_postcontrol.build_context0_aliases()
        self.assertEqual(len(aliases), 16)
        self.assertEqual(
            aliases[0x7200438000], 0xFFFFFC20001D8000
        )
        self.assertEqual(
            aliases[0x7200454000], 0xFFFFFC20001F4000
        )
        self.assertEqual(
            aliases[0x7200460000], 0xFFFFFC2000200000
        )
        self.assertEqual(
            aliases[0x720047C000], 0xFFFFFC200021C000
        )
        self.assertTrue(
            set(aliases.values())
            <= set(g17g_postcontrol.POSTCONTROL_PAGE_DVAS)
        )

        patches = g17g_postcontrol.build_existing_postcontrol_qwords()
        self.assertEqual(len(patches), 4)
        self.assertEqual(sum(map(len, patches.values())), 14)
        self.assertEqual(
            patches[0xFFFFFC2000024000],
            (
                (0x358, 0x00080A0100000000),
                (0x360, 0x3BD),
                (0x5D0, 0x5),
            ),
        )
        self.assertEqual(
            patches[0xFFFFFC20015F0000][2],
            (0x10, 0x8000000001A00),
        )
        self.assertEqual(
            patches[0xFFFFFC20015E8000],
            ((0x0, 0x0000003000023800),),
        )
        mixed_patches = g17g_postcontrol.build_existing_postcontrol_qwords(
            allocation_family=1
        )
        self.assertEqual(
            mixed_patches[0xFFFFFC20015E8000],
            ((0x0, 0x0000003000024000),),
        )
        mixed_resource_patches = (
            g17g_postcontrol.build_existing_postcontrol_qwords(
                allocation_family=1, resource_units=0x16
            )
        )
        self.assertEqual(
            mixed_resource_patches[0xFFFFFC20015F0000],
            (
                (0x0, 0xE4000000),
                (0x8, 0x0000160000000000),
                (0x10, 0x0008000000001600),
            ),
        )
        two_compute_patches = (
            g17g_postcontrol.build_existing_postcontrol_qwords(
                allocation_family=2
            )
        )
        self.assertEqual(
            two_compute_patches[0xFFFFFC20015E8000],
            ((0x0, 0x0000003000024800),),
        )
        with self.assertRaisesRegex(ValueError, "allocation family"):
            g17g_postcontrol.build_existing_postcontrol_qwords(
                allocation_family=3
            )
        with self.assertRaisesRegex(ValueError, "resource units"):
            g17g_postcontrol.build_existing_postcontrol_qwords(
                resource_units=1 << 24
            )
        self.assertEqual(
            patches[0xFFFFFC20C00B0000][-1],
            (0x21E8, 0x4000000000000),
        )

        selector15_hashes = {
            0xB3: (
                "4a762612db5407046e81452b3499d3fca"
                "3fd0cd4ee8053b8c4750ae008c7cb99"
            ),
            0xB4: (
                "bbd049457f2e0f8e5dd254f774e2da4e"
                "da53804be314bb50022818462fc4a6fc"
            ),
        }
        for generation, page_hash in selector15_hashes.items():
            with self.subTest(selector15_generation=generation):
                record = g17g_postcontrol.build_selector15_record(generation)
                self.assertEqual(
                    len(record), g17g.ITEM_RECORD_SIZE[g17g.SELECTOR_15]
                )
                self.assertEqual(struct.unpack_from("<Q", record, 0)[0], 15)
                self.assertEqual(record[0x5A], generation)
                page = record + b"\0" * (
                    g17g_postcontrol.PAGE_SIZE - len(record)
                )
                self.assertEqual(hashlib.sha256(page).hexdigest(), page_hash)
        with self.assertRaisesRegex(ValueError, "u8"):
            g17g_postcontrol.build_selector15_record(0x100)

        entry20 = g17g_postcontrol.build_channel12_entry20()
        self.assertEqual(len(entry20), 0x40)
        self.assertEqual(
            hashlib.sha256(entry20).hexdigest(),
            "f8a8e67bb201977ae64c541d11ab3f228"
            "c5308c0112ca27422f759ca48f525f5",
        )
        self.assertEqual(struct.unpack_from("<III", entry20, 0), (0x20, 1, 0x3F))
        self.assertEqual(
            struct.unpack_from("<QQQ", entry20, 0x14),
            (
                0xFFFFFC20C08B0000,
                0x7200408000,
                0x7200408340,
            ),
        )
        self.assertEqual(struct.unpack_from("<I", entry20, 0x2C)[0], 8)
        self.assertEqual(struct.unpack_from("<I", entry20, 0x34)[0], 1)

        first_object = g17g.build_opcode20_first_object(
            0x7200000000,
            0x7200408000,
            0xFFFFFC2001608000,
        )
        self.assertEqual(len(first_object), 0x4000)
        self.assertEqual(
            hashlib.sha256(first_object).hexdigest(),
            "c2b653b88617d57927c0e5917d6446ca"
            "1dd3a2b6556a54232b1adfff39a58332",
        )
        self.assertEqual(
            first_object,
            g17g_postcontrol.build_postcontrol_pages(0xB4)[
                0xFFFFFC20C08B0000
            ],
        )
        dynamic_entry20 = g17g.build_service_opcode20_record(
            0xFFFFFC2001630000,
            0x7004000000,
        )
        self.assertEqual(
            struct.unpack_from("<III", dynamic_entry20, 0),
            (0x20, 1, 0x3F),
        )
        self.assertEqual(
            struct.unpack_from("<QQQ", dynamic_entry20, 0x14),
            (
                0xFFFFFC2001630000,
                0x7004000000,
                0x7004000340,
            ),
        )
        dynamic_first_object = g17g.build_opcode20_first_object(
            0x7005000000,
            0x7004000000,
            0xFFFFFC2001634000,
        )
        self.assertEqual(
            struct.unpack_from("<I", dynamic_first_object, 0x14)[0],
            0x05000000,
        )
        self.assertEqual(
            struct.unpack_from("<Q", dynamic_first_object, 0x18)[0],
            0x0008000000000070,
        )

    def test_numeric_context0_alias_recipe(self):
        fields = g17g_defaults.canonical_preinit_fields()
        runs = g17g_uat.build_context0_alias_runs(
            fields["hwdata_fields"]["region_records"]
        )
        aliases = g17g_uat.expand_context0_alias_runs(runs)
        self.assertEqual(
            len(aliases), g17g_uat.EXPECTED_CONTEXT0_ALIAS_PAGE_COUNT
        )
        self.assertEqual(
            aliases[0x7200000000]["high_va"], 0xFFFFFC20C0018000
        )
        self.assertEqual(
            aliases[0x7201848000]["high_va"],
            g17g_defaults.CANONICAL_REGION_ADDRESSES[0],
        )
        self.assertEqual(
            aliases[0x72018DC000]["high_va"],
            g17g_defaults.CANONICAL_REGION_ADDRESSES[3] + 7 * 0x4000,
        )
        executable = sum(not item["flags"]["UXN"] for item in aliases.values())
        self.assertEqual(executable, 265)
        self.assertEqual(len(aliases) - executable, 34)

    def test_channel_table_observed_shape(self):
        table = bytearray(
            g17g.CHANNEL_ENTRY_COUNT * g17g.CHANNEL_ENTRY_SIZE
        )
        for index in range(g17g.CHANNEL_POPULATED_COUNT):
            base = index * g17g.CHANNEL_ENTRY_SIZE
            struct.pack_into(
                "<4Q", table, base,
                0x1000 + index * 0x100,
                0x1010 + index * 0x100,
                0x1020 + index * 0x100,
                0x8000 + index * 0x200,
            )
        entries = g17g.parse_channel_table(table)
        self.assertEqual(len(entries), 17)
        self.assertEqual(
            entries[1]["state_addresses"], (0x1100, 0x1110, 0x1120)
        )
        self.assertEqual(entries[1]["ring_address"], 0x8200)
        self.assertTrue(entries[16]["all_zero"])
        encoded = g17g.build_channel_table([
            (
                (0x1000 + index * 0x100,
                 0x1010 + index * 0x100,
                 0x1020 + index * 0x100),
                0x8000 + index * 0x200,
            )
            for index in range(g17g.CHANNEL_POPULATED_COUNT)
        ] + [((0, 0, 0), 0)])
        self.assertEqual(encoded, table)

        table[16 * g17g.CHANNEL_ENTRY_SIZE] = 1
        with self.assertRaisesRegex(ValueError, "entry 16"):
            g17g.parse_channel_table(table)

    def test_native_type84_prefix_records(self):
        records = g17g.build_type84_prefix_records()
        self.assertEqual(len(records), 5)
        self.assertTrue(all(
            len(record) == g17g.SERVICE_RECORD_SIZE for record in records
        ))
        self.assertEqual(
            tuple(struct.unpack_from("<III", record, 0) for record in records),
            tuple(
                (g17g.TYPE84_PREFIX_OPCODE, first, second)
                for first, second in g17g.TYPE84_PREFIX_U32_PAIRS
            ),
        )
        self.assertTrue(all(not any(record[0x0C:]) for record in records))
        self.assertEqual(
            tuple(hashlib.sha256(record).hexdigest() for record in records),
            (
                "dfa1faa79d673a5152ec542f6924211e"
                "13b0aabd89c1b62f284943e6d1154b59",
                "9b4acc046bdd94667d1f5975bb7819404"
                "63fcc78e93cd68fd0db40342cdcc49b",
                "43590b8ce88afc7c6c05f9b42c0a662"
                "99e5731151299dd46cbc7e161770de8dc",
                "a39027f07e83d83f25a5fd7ecc8bb8c"
                "9c3fe220a3070d85e7be8096617bfcfbf",
                "d3666d3af4094a323a7a0ccca7a7ce6"
                "efb6c181cc70a07a8f0e5705877607017",
            ),
        )
        with self.assertRaisesRegex(ValueError, "u32"):
            g17g.build_type84_prefix_record(1 << 32, 0)

        service_records = g17g.build_first_compute_service_records()
        self.assertEqual(len(service_records), 8)
        self.assertEqual(
            tuple(struct.unpack_from("<I", record, 0)[0]
                  for record in service_records),
            (0x15, 0x15, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A, 0x1A),
        )
        self.assertEqual(
            tuple(struct.unpack_from("<II", record, 4)
                  for record in service_records[2:]),
            ((0, 1), *g17g.TYPE84_PREFIX_U32_PAIRS),
        )
        self.assertEqual(
            tuple(hashlib.sha256(record).hexdigest()
                  for record in service_records[:3]),
            (
                "061e0434dca7e63d2ad660480c9205f0"
                "f127e41ed54036938dbc7dbf49576392",
                "061e0434dca7e63d2ad660480c9205f0"
                "f127e41ed54036938dbc7dbf49576392",
                "a655e23ed3e84384e37a3d9335af618"
                "b85b49f55bc15bb9355bbbff100e656d5",
            ),
        )

    def test_ring_slot_and_queue_record(self):
        slot = struct.pack(
            "<QQII", 0, 0xFFFFFC20C0000080, 1, 0x00010006
        )
        decoded = g17g.parse_ring_slot(slot)
        self.assertEqual(decoded["queue_address"], 0xFFFFFC20C0000080)
        self.assertEqual(decoded["word_10"], 1)
        self.assertEqual(decoded["limit"], 6)
        self.assertEqual(decoded["queue_index"], 1)
        self.assertEqual(decoded["unresolved_bits"], 0)
        self.assertEqual(
            g17g.build_ring_slot(
                0xFFFFFC20C0000080, 1, 0x00010006
            ),
            slot,
        )

        queue = g17g.build_queue_record(
            0xFFFFFC2000012870,
            0xFFFFFC20C000A870,
            0xFFFFFC2000000000,
            0xFFFFFC20C07C0000,
            limit_1c=6,
            word_40=0xB4FFFFFFFF,
            accumulator_68=0xB36,
        )
        self.assertEqual(g17g.parse_queue_record(queue), {
            "pointer_block_address": 0xFFFFFC2000012870,
            "item_ring_address": 0xFFFFFC20C000A870,
            "address_10": 0xFFFFFC2000000000,
            "limit_1c": 6,
            "word_20": 0xFFFFFFFF00000000,
            "word_28": 0,
            "word_30": 0xFFFFFFFFFFFF0000,
            "word_38": 0x100000001,
            "word_40": 0xB4FFFFFFFF,
            "accumulator_68": 0xB36,
            "address_70": 0xFFFFFC20C07C0000,
        })
        self.assertEqual(g17g.parse_queue_priority(queue), {
            "priority": 0,
            "fields": (0, 0, 0xFFFFFFFFFFFF0000, 1, 1),
            "coherent": True,
        })
        medium = g17g.apply_queue_priority(queue, 1)
        self.assertEqual(g17g.parse_queue_priority(medium), {
            "priority": 1,
            "fields": (1, 1, 0xFFFFFFFF00000000, 0, 0),
            "coherent": True,
        })
        self.assertEqual(medium[:g17g.QUEUE_PRIORITY_OFFSET],
                         queue[:g17g.QUEUE_PRIORITY_OFFSET])
        self.assertEqual(medium[g17g.QUEUE_WORD_40_OFFSET:],
                         queue[g17g.QUEUE_WORD_40_OFFSET:])
        with self.assertRaisesRegex(ValueError, "priority must be in 0..3"):
            g17g.apply_queue_priority(queue, 4)
        self.assertEqual(g17g.uapi_queue_priority_profile(0), {
            "priority": 3,
            "mirror": 3,
            "mask": 0,
            "mode": 0,
            "selector": 3,
            "uapi_priority": 0,
            "firmware_priority": 3,
        })
        self.assertEqual(g17g.uapi_queue_priority_profile(1), {
            "priority": 2,
            "mirror": 2,
            "mask": 0xFFFF000000000000,
            "mode": 0,
            "selector": 2,
            "uapi_priority": 1,
            "firmware_priority": 2,
        })
        with self.assertRaisesRegex(ValueError, "LOW.*MEDIUM"):
            g17g.uapi_queue_priority_profile(2)

    def test_persistent_render_stream_ring_slots_retain_inner_head(self):
        for queue_index, expected_word in (
            (0, 0x01000006),
            (1, 0x01010006),
        ):
            body = g17g_backend.build_render_stream_ring_slot(
                queue_index, 6
            )
            parsed = g17g.parse_ring_slot(body)
            self.assertEqual(
                parsed["queue_address"],
                g17g_postcontrol.QUEUE_ADDRESSES[queue_index],
            )
            self.assertEqual(parsed["word_10"], queue_index)
            self.assertEqual(parsed["word_14"], expected_word)
            self.assertEqual(parsed["limit"], 6)
            self.assertEqual(parsed["queue_index"], queue_index)
            self.assertEqual(parsed["unresolved_bits"], 0x01000000)
        pair_one = g17g_backend.build_render_stream_ring_slot(2, 3)
        self.assertEqual(
            g17g.parse_ring_slot(pair_one),
            {
                "word_00": 0,
                "queue_address": g17g_postcontrol.QUEUE_PAGE
                + 2 * g17g.QUEUE_RECORD_STRIDE,
                "word_10": 0,
                "word_14": 0x01020003,
                "limit": 3,
                "queue_index": 2,
                "unresolved_bits": 0x01000000,
                "all_zero": False,
            },
        )
        pair_one_fragment = g17g_backend.build_render_stream_ring_slot(3, 3)
        self.assertEqual(
            g17g.parse_ring_slot(pair_one_fragment)["word_10"], 1
        )
        with self.assertRaisesRegex(ValueError, "inner head"):
            g17g_backend.build_render_stream_ring_slot(0, 1 << 16)

    def test_render_generation_service_record_advances(self):
        self.assertEqual(
            g17g_backend.build_render_generation_service_record(2),
            g17g.build_service_opcode2e_record(1),
        )
        self.assertEqual(
            g17g_backend.build_render_generation_service_record(3),
            g17g.build_service_opcode2e_record(2),
        )
        self.assertEqual(
            g17g_backend.build_render_generation_service_record(257),
            g17g.build_service_opcode2e_record(256),
        )
        with self.assertRaisesRegex(ValueError, "at least 2"):
            g17g_backend.build_render_generation_service_record(1)
        self.assertEqual(g17g_backend.render_channel_counter(255), 255)
        self.assertEqual(g17g_backend.render_channel_counter(256), 0)
        self.assertEqual(g17g_backend.render_channel_counter(257), 1)
        self.assertEqual(g17g_backend.render_service_counter(255), 255)
        self.assertEqual(g17g_backend.render_service_counter(256), 0)
        self.assertEqual(g17g_backend.render_service_counter(257), 1)
        self.assertTrue(
            g17g_backend.render_counter_between(255, 0, 0)
        )
        self.assertFalse(
            g17g_backend.render_counter_between(255, 1, 0)
        )

    def test_compute_channel_counter_and_slot_wrap_at_256(self):
        self.assertEqual(g17g_backend.compute_channel_counter(255), 255)
        self.assertEqual(g17g_backend.compute_channel_counter(256), 0)
        self.assertEqual(g17g_backend.compute_channel_counter(257), 1)
        self.assertEqual(g17g_backend.compute_channel_slot_index(255), 254)
        self.assertEqual(g17g_backend.compute_channel_slot_index(256), 255)
        self.assertEqual(g17g_backend.compute_channel_slot_index(257), 0)
        with self.assertRaisesRegex(ValueError, "positive"):
            g17g_backend.compute_channel_slot_index(0)

    def test_render_service_reregisters_before_ring_wrap(self):
        ordinary = g17g_backend.build_render_generation_service_records(
            255, 252
        )
        self.assertEqual(
            ordinary,
            (g17g.build_service_opcode2e_record(254),),
        )
        rollover = g17g_backend.build_render_generation_service_records(
            257, 253
        )
        self.assertEqual(len(rollover), 2)
        self.assertEqual(
            rollover[0],
            g17g.build_service_opcode20_record(
                g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS,
                g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
                sequence=256,
                count=16,
            ),
        )
        self.assertEqual(
            rollover[1], g17g.build_service_opcode2e_record(256)
        )
        self.assertEqual(
            g17g_backend.build_render_generation_service_records(257, 255),
            (g17g.build_service_opcode2e_record(256),),
        )
        self.assertEqual(
            g17g_backend.build_render_generation_service_records(
                246, 253, position_registration=False
            ),
            (g17g.build_service_opcode2e_record(245),),
        )

    def test_render_stream_fences_pool_reuse_and_service_rollover(self):
        fences = [
            ordinal for ordinal in range(3, 258)
            if g17g_stream.render_stream_requires_fence(
                ordinal, 3, g17g_stream.RENDER_STREAM_BATCH_SIZE, 257,
                service_rollover=ordinal in (255, 256),
            )
        ]
        self.assertEqual(
            fences,
            list(range(3, 258)),
        )
        self.assertEqual(
            [
                g17g_stream.render_stream_batch_index(
                    ordinal, 3, g17g_stream.RENDER_STREAM_BATCH_SIZE,
                    forced_fence_ordinals=(255, 256),
                )
                for ordinal in (3, 34, 35, 226, 227, 255, 256, 257)
            ],
            [0, 31, 32, 223, 224, 252, 253, 254],
        )
        with self.assertRaisesRegex(ValueError, "invalid"):
            g17g_stream.render_stream_requires_fence(2, 3, 32, 257)

    def test_render_report_ack_pairs_require_distinct_aligned_words(self):
        pairs = (
            (0x100000, 0x100020),
            (0x100040, 0x100060),
        )
        self.assertEqual(
            g17g_stream.normalize_report_ack_pairs(pairs), pairs
        )
        with self.assertRaisesRegex(ValueError, "invalid"):
            g17g_stream.normalize_report_ack_pairs(((0x100001, 0x100020),))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            g17g_stream.normalize_report_ack_pairs((
                (0x100000, 0x100020),
                (0x100000, 0x100060),
            ))

    def test_empty_report_ack_batch_needs_no_proxy_call(self):
        self.assertEqual(
            g17g_stream.acknowledge_report_pairs(None, None, None, ()),
            {
                "pair_count": 0,
                "changed_count": 0,
                "proxy_call_count": 0,
            },
        )

    def test_pointer_block_numeric_fields(self):
        block = bytearray(g17g.POINTER_BLOCK_OBSERVED_SIZE)
        for offset, value in (
            (0x00, 6), (0x30, 6), (0x40, 6),
            (0x50, 0xFFFFFFFF), (0x60, 0x500),
        ):
            struct.pack_into("<I", block, offset, value)
        self.assertEqual(g17g.parse_pointer_block(block), {
            "field_00": 6,
            "field_30": 6,
            "field_40": 6,
            "field_50": 0xFFFFFFFF,
            "field_60": 0x500,
        })
        self.assertEqual(
            g17g.build_pointer_block(6, 6, 6),
            block,
        )

    def test_mixed_compute_pointer_release_rearms_retired_consumers(self):
        block = g17g_backend.build_mixed_compute_pointer_release(3, 6)
        self.assertEqual(g17g.parse_pointer_block(block), {
            "field_00": 3,
            "field_30": 3,
            "field_40": 6,
            "field_50": 0xFFFFFFFF,
            "field_60": 0x500,
        })
        with self.assertRaisesRegex(ValueError, "invalid"):
            g17g_backend.build_mixed_compute_pointer_release(3, 3)

    def test_repeated_endpoints_and_queue_arithmetic(self):
        cases = (
            (g17g.SELECTOR_0, 0x134C62C01, 0x134C62D7C, 0xE9),
            (g17g.SELECTOR_1, 0x134C62D87, 0x134C63517, 0x3A6),
        )
        for selector, endpoint_a, endpoint_b, accumulator_before in cases:
            with self.subTest(selector=selector):
                item = bytearray(g17g.ITEM_RECORD_SIZE[selector])
                struct.pack_into("<I", item, g17g.ITEM_SELECTOR_OFFSET, selector)
                struct.pack_into(
                    "<Q", item, g17g.ITEM_SEQUENCE_OFFSET, 2 + selector
                )
                struct.pack_into("<I", item, g17g.ITEM_CONTEXT_OFFSET, 1)
                for pair in g17g.ITEM_ENDPOINT_OFFSETS[selector]:
                    write_u40(item, pair[0], endpoint_a)
                    write_u40(item, pair[1], endpoint_b)

                before = bytearray(g17g.QUEUE_RECORD_SIZE)
                after = bytearray(g17g.QUEUE_RECORD_SIZE)
                struct.pack_into("<I", before, g17g.QUEUE_LIMIT_OFFSET, 3)
                struct.pack_into("<I", after, g17g.QUEUE_LIMIT_OFFSET, 6)
                struct.pack_into(
                    "<Q", before, g17g.QUEUE_ACCUMULATOR_OFFSET,
                    accumulator_before,
                )
                struct.pack_into(
                    "<Q", after, g17g.QUEUE_ACCUMULATOR_OFFSET,
                    accumulator_before + endpoint_b - endpoint_a,
                )

                result = g17g.validate_consumption_arithmetic(
                    before, after, item
                )
                self.assertEqual(result["endpoints"]["copies"], (
                    (endpoint_a, endpoint_b), (endpoint_a, endpoint_b)
                ))
                self.assertEqual(
                    result["endpoints"]["difference"], endpoint_b - endpoint_a
                )

                write_u40(
                    item, g17g.ITEM_ENDPOINT_OFFSETS[selector][1][1],
                    endpoint_b + 1,
                )
                with self.assertRaisesRegex(ValueError, "copies disagree"):
                    g17g.parse_item_endpoints(item, require_repeated=True)

                for offset in g17g.ITEM_ENDPOINT_OFFSETS[selector][1]:
                    write_u40(item, offset, 0)
                result = g17g.validate_consumption_arithmetic(
                    before, after, item
                )
                self.assertEqual(result["endpoints"]["copies"][1], (0, 0))

    def test_selector_14_numeric_words(self):
        item = g17g.build_selector_14(1, 2)
        self.assertEqual(g17g.parse_selector_14(item), {
            "selector": 14,
            "word_04": 0x00010001,
            "word_08": 0x200,
            "word_10": 0x100,
        })
        self.assertEqual(len(item), 0x40)
        self.assertFalse(any(item[0x14:]))

        with self.assertRaisesRegex(ValueError, "channel"):
            g17g.build_selector_14(2, 1)
        with self.assertRaisesRegex(ValueError, "group"):
            g17g.build_selector_14(0, 0)

    def test_numeric_item_header_builder(self):
        for selector, sequence in ((0, 5), (1, 4)):
            with self.subTest(selector=selector):
                data = g17g.build_item_header(selector, sequence)
                self.assertEqual(len(data), 0x10)
                self.assertEqual(g17g.parse_item_header(data), {
                    "selector": selector,
                    "sequence": sequence,
                    "context": 1,
                })
        with self.assertRaisesRegex(ValueError, "selector"):
            g17g.build_item_header(14, 1)

    def test_numeric_target_record_builders(self):
        target_40 = g17g.build_target_record_40(0x60000009D6)
        self.assertEqual(g17g.parse_target_record_40(
            target_40, require_observed_shape=True
        ), {
            "word_00": 0x60000009D6,
            "word_10": 0x60000009D6,
            "words_equal": True,
            "other_bytes_all_zero": True,
            "all_zero": False,
        })

        target_80 = g17g.build_target_record_80(
            0x1000080040,
            0xFFFFFC2001620040,
            0x220040,
            0xFFFFFC2001618040,
        )
        self.assertEqual(g17g.parse_target_record_80(target_80), {
            "word_00": 0x1000080040,
            "word_08": 0xFFFFFC2001620040,
            "word_10": 0,
            "word_28": 0x220040,
            "word_40": 0xFFFFFC2001618040,
            "word_48": 1 << 32,
            "other_bytes_all_zero": True,
        })

        updated = g17g.build_target_record_80(
            0x1000080040,
            0xFFFFFC2001620040,
            0x220040,
            0xFFFFFC2001618040,
            word_48=(1 << 32) | 3,
            word_10=3,
        )
        parsed = g17g.parse_target_record_80(updated)
        self.assertEqual(parsed["word_10"], 3)
        self.assertEqual(parsed["word_48"], (1 << 32) | 3)

    def test_numeric_initdata_root_builder(self):
        root = g17g_initdata.build_root(
            0xFFFFFC20001B8000,
            0xFFFFFC20C07A6E00,
            0xFFFFFC20001A0000,
            0xFFFFFC200002F180,
            0xFFFFFC2000020340,
        )
        self.assertEqual(len(root), 0xB8)
        fields = g17g_initdata.root_from_bytes(root)
        self.assertEqual(fields["version"], (0x4C0, 0x83A0, 0x4339, 0xC8B))
        self.assertEqual(fields["instance_index"], 0)
        self.assertEqual(g17g_initdata.build_root(**fields), root)

    def test_numeric_initdata_main_builder(self):
        channels = [((0, 0, 0), 0)] * g17g.CHANNEL_ENTRY_COUNT
        channels[12] = ((0x1000, 0x1010, 0x1020), 0x2000)
        main = g17g_initdata.build_main_config(
            0xFFFFFC20C0788000,
            0xFFFFFC20C0794D40,
            channels,
            region_triples=(
                (0, 0x1838000, 0x72),
                (0, 0x1840000, 0x72),
                (0, 0, 0),
            ),
            word_300=0xC,
            secondary_address_481=0xFFFFFC20C078D340,
            word_4c0=0x2A,
        )
        parsed = g17g_initdata.parse_main_config(main)
        self.assertEqual(parsed["channels"][12], channels[12])
        self.assertEqual(parsed["word_300"], 0xC)
        self.assertEqual(parsed["secondary_address_481"], 0xFFFFFC20C078D340)
        self.assertEqual(g17g_initdata.rebuild_main_config(main), main)
        self.assertEqual(
            g17g_initdata.build_status_record(),
            b"\0" * 4 + b"\1\0\0\0" + b"\0" * 0x78,
        )
        region = g17g_initdata.build_region_20()
        self.assertEqual(len(region), 0x1000)
        self.assertEqual(struct.unpack_from("<I", region, 0x24)[0], 0xBB8)
        self.assertEqual(struct.unpack_from("<I", region, 0x40)[0], 0x78)
        self.assertEqual(
            struct.unpack_from("<Q", region, 0x80)[0],
            0x0000000100000001,
        )
        self.assertEqual(
            struct.unpack_from("<Q", region, 0xA0)[0],
            0x310000023200000D,
        )
        self.assertEqual(struct.unpack_from("<I", region, 0xE5C)[0], 0x300)
        self.assertEqual(
            struct.unpack_from("<Q", region, 0xE70)[0],
            0x0000010000000000,
        )

    def test_numeric_hwdata_record_builders(self):
        register = g17g_initdata.build_register_record(
            field_00=0x381014000,
            field_08=0xFFFFFC2180000000,
            word_10=0x4000,
            word_14=0x4000,
            word_20=2,
        )
        self.assertEqual(
            g17g_initdata.build_register_record(
                **g17g_initdata.parse_register_record(register)
            ),
            register,
        )
        region = g17g_initdata.build_region_record(
            0x100, 0x1848000, 0x72, 0xFFFFFC20C07F8000
        )
        parsed = g17g_initdata.parse_region_record(region)
        self.assertEqual(parsed["word_08"], 0x72)
        self.assertEqual(parsed["address_0c"], 0xFFFFFC20C07F8000)
        self.assertEqual(
            g17g_initdata.build_region_record(**parsed), region
        )

    def test_numeric_preinit_auxiliary_pages(self):
        dynamic = 0x936917BA
        pages = g17g_initdata.build_preinit_auxiliary_pages(dynamic)
        self.assertEqual(
            set(pages), set(g17g_initdata.PREINIT_AUXILIARY_PAGE_DVAS)
        )
        repeated = pages[g17g_initdata.AUXILIARY_REPEATED_7FFF_PAGE]
        start = g17g_initdata.AUXILIARY_REPEATED_7FFF_OFFSET
        size = g17g_initdata.AUXILIARY_REPEATED_7FFF_COUNT * 2
        self.assertEqual(repeated[start:start + size], b"\xff\x7f" * 512)
        variable = pages[g17g_initdata.AUXILIARY_DYNAMIC_U32_PAGE]
        self.assertEqual(
            struct.unpack_from(
                "<I", variable, g17g_initdata.AUXILIARY_DYNAMIC_U32_OFFSET
            )[0],
            dynamic,
        )
        with self.assertRaisesRegex(ValueError, "u32"):
            g17g_initdata.build_preinit_auxiliary_pages(1 << 32)

    def test_numeric_firmware_root_ram_recipe(self):
        region_records = [
            {"address_0c": address}
            for address in (
                0xFFFFFC20C07F8000,
                0xFFFFFC20C0820000,
                0xFFFFFC20C0848000,
                0xFFFFFC20C0880000,
            )
        ]
        runs = g17g_uat.build_ram_runs(region_records)
        self.assertEqual(
            sum(run["page_count"] for run in runs),
            g17g_uat.EXPECTED_RAM_PAGE_COUNT,
        )
        pages = {
            run["va"] + index * g17g_uat.PAGE_SIZE
            for run in runs for index in range(run["page_count"])
        }
        for address in region_records[:3]:
            for index in range(g17g_uat.DYNAMIC_REGION_PAGE_COUNT):
                self.assertIn(
                    address["address_0c"] + index * g17g_uat.PAGE_SIZE,
                    pages,
                )

    def test_canonical_source_package(self):
        fields = g17g_defaults.canonical_preinit_fields()
        self.assertEqual(len(fields["primary_main_fields"]["channels"]), 17)
        self.assertEqual(len(fields["secondary_main_fields"]["channels"]), 17)
        self.assertEqual(
            len(fields["hwdata_fields"]["register_records"]), 60
        )
        self.assertEqual(
            tuple(
                item["address_0c"]
                for item in fields["hwdata_fields"]["region_records"]
            ),
            g17g_defaults.CANONICAL_REGION_ADDRESSES,
        )
        pages = g17g_defaults.build_canonical_seed_pages(0x12345678)
        self.assertEqual(len(pages), 29)
        self.assertEqual(
            struct.unpack_from(
                "<I", pages[0xFFFFFC200002C000], 0x33E0
            )[0],
            8,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", pages[0xFFFFFC20000D4000], 0x1C40
            )[0],
            5,
        )
        recipe = g17g_uat.build_firmware_root_recipe(
            fields["hwdata_fields"]
        )
        expanded = g17g_uat.expand_firmware_root_recipe(recipe)
        self.assertEqual(len(expanded), 666)
        self.assertEqual(
            sum(
                item["content_class"] == "captured-ram"
                for item in expanded.values()
            ),
            608,
        )
        plan = g17g_uat.build_backing_plan(recipe, 0x10000000000)
        self.assertEqual(plan["backing_size"], 608 * 0x4000)
        self.assertEqual(len(plan["ram_pages"]), 608)
        explicit_pages = dict(plan["ram_pages"])
        first, second = sorted(explicit_pages)[:2]
        explicit_pages[first], explicit_pages[second] = (
            explicit_pages[second], explicit_pages[first]
        )
        explicit = g17g_uat.build_backing_plan_for_pages(
            recipe, explicit_pages
        )
        self.assertIsNone(explicit["backing_pa"])
        self.assertEqual(explicit["ram_pages"], explicit_pages)
        self.assertEqual(len(explicit["physical_runs"]), 1)
        self.assertEqual(
            set(pages),
            set(g17g_initdata.PREINIT_CLOSURE_PAGE_DVAS)
            | set(g17g_initdata.PREINIT_AUXILIARY_PAGE_DVAS),
        )



if __name__ == "__main__":
    unittest.main()
