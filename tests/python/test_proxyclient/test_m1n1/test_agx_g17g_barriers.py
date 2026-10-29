# SPDX-License-Identifier: GPL-2.0-only
import struct
from types import SimpleNamespace
import unittest

from m1n1.drm_shim import g17g_backend as backend, g17g_compute as compute
from m1n1.drm_shim.g17g_barriers import with_dependencies, context_dependencies, bound_record, apply_submission_barriers
from m1n1.drm_shim.g17g_compute_queue import compute_wave
from m1n1.drm_shim.g17g_mixed_submit import mixed_compute_graph, mixed_partial_graph, continued_mixed_partial_graph
from m1n1.drm_shim.g17g_uapi import DRM_ASAHI_BARRIER_NONE as NONE, DRM_ASAHI_CMD_COMPUTE as C, DRM_ASAHI_CMD_RENDER as R


def command(index, kind, *, vdm=NONE, cdm=NONE):
    return SimpleNamespace(index=index, header=SimpleNamespace(cmd_type=kind, vdm_barrier=vdm, cdm_barrier=cdm))


class TestGpuBarriers(unittest.TestCase):
    def test_native_two_predecessor_encoding(self):
        original = compute.build_compute_queue_context_item(0xfffffc20c0359040, 0xfffffc20c0000180, queue_index=3)
        actual = with_dependencies(original, ((2, 1), (1, 1)))
        # Independently observed native CRC fence record: two predecessors,
        # then self. Descriptor pointers and all other fields stay opaque.
        expected = bytearray(original)
        struct.pack_into('<I', expected, 0x20, 7)
        struct.pack_into('<3Q', expected, 0x28, 0x10000000001, 0x20000000001, 0x30000000000)
        struct.pack_into('<Q', expected, 0x180, 0x15)
        self.assertEqual(actual, bytes(expected))
        with self.assertRaises(ValueError):
            with_dependencies(original, ((3, 1),))

    def test_mixed_uapi_indices_select_actual_predecessors(self):
        first = mixed_compute_graph(0x1801000000, 0x1801000040)
        params = backend.build_clear_render_products()['parameters']
        render1 = mixed_partial_graph(params)
        compute2 = compute_wave(((0x1801000080, 0x18010000c0),), 1, first['addresses'])
        render2 = continued_mixed_partial_graph(params, 2, private_dvas=render1['private_dvas'])
        commands = (command(1, C), command(3, R, cdm=1), command(4, C, vdm=1, cdm=1),
                    command(6, R, vdm=1, cdm=2))
        apply_submission_barriers(commands, first, (render1, compute2, render2))
        def decoded(graph, stage=0):
            return context_dependencies(bound_record(graph, graph['dependency_jobs'][0][stage]))
        self.assertEqual(decoded(render1), (((0, 1),), (1, 0)))
        self.assertEqual(decoded(render1, 1), (((1, 1),), (2, 0)))
        self.assertEqual(decoded(compute2), (((2, 1),), (0, 1)))
        self.assertEqual(decoded(render2), (((0, 2), (2, 1)), (1, 1)))
        self.assertEqual(decoded(render2, 1), (((1, 2),), (2, 1)))

    def test_retired_queue_lifetime_does_not_create_impossible_wait(self):
        initial = mixed_compute_graph(0x1801000000, 0x1801000040, empty=False)
        old = compute_wave(((0x1801000000, 0x1801000040),), 126, initial['addresses'])
        new = compute_wave(((0x1801000080, 0x18010000c0),), 127, old['addresses'])
        render = mixed_partial_graph(backend.build_clear_render_products()['parameters'])
        apply_submission_barriers((command(1, C), command(2, C), command(3, R, cdm=1)),
                                  old, (old, new, render))
        waits, _ = context_dependencies(bound_record(render, render['dependency_jobs'][0][0]))
        self.assertEqual(waits, ())


if __name__ == '__main__':
    unittest.main()
