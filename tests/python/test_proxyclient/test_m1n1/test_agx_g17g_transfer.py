# SPDX-License-Identifier: GPL-2.0-only
from contextlib import nullcontext
import random
import struct
import unittest
from unittest.mock import Mock

from m1n1.drm_shim.g17g_transfer import zero_runs, write_publications, read_ranges, compare_publications


class TestZeroRunTransfer(unittest.TestCase):
    def test_compare_covers_every_byte_and_reports_first_failed_zero_run(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        util.heap.guarded_malloc.return_value = nullcontext(0x100000)
        util.exec.return_value = 2
        result = compare_publications(util, proxy, iface, ((0x8000, b"A" * 64 + bytes(65)),))
        self.assertEqual(result, dict(exact=False, bytes=129, unequal_run=dict(pa=0x8040, size=65)))
        staging, wire = iface.writemem.call_args.args
        self.assertEqual(struct.unpack_from("<6Q", wire), (0x8000, staging + 48, 64, 0x8040, 0, 65))
        self.assertEqual(wire[48:], b"A" * 64)
        util.exec.return_value = 0
        self.assertTrue(compare_publications(util, proxy, iface, ((0x8000, bytes(65)),))["exact"])
        util.exec.return_value = 2
        with self.assertRaisesRegex(RuntimeError, "invalid comparison"):
            compare_publications(util, proxy, iface, ((0x8000, bytes(65)),))

    def test_read_gathers_only_exact_owned_ranges_in_order(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        util.heap.guarded_malloc.return_value = nullcontext(0x100000)
        iface.readmem.return_value = b"abcdeXYZ"
        result = read_ranges(util, proxy, iface, ((0x800001, 5), (0x920013, 3)))
        self.assertEqual(result, (b"abcde", b"XYZ"))
        self.assertEqual(iface.writemem.call_args.args, (0x100000,
            struct.pack("<6Q", 0x100030, 0x800001, 5, 0x100035, 0x920013, 3)))
        iface.readmem.assert_called_once_with(0x100030, 8)

    def test_gather_rejects_unbounded_ranges_and_short_reads(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        for ranges in (((0x8000, 1), (1 << 42, 8)), ((0x8000, 0),), ((0x8000, 0x100001),)):
            with self.assertRaises(ValueError):
                read_ranges(util, proxy, iface, ranges)
        self.assertFalse(util.mock_calls + proxy.mock_calls + iface.mock_calls)
        util.heap.guarded_malloc.return_value = nullcontext(0x100000)
        iface.readmem.return_value = b"X"
        with self.assertRaisesRegex(RuntimeError, "short"):
            read_ranges(util, proxy, iface, ((0x8000, 8),))

    def test_random_dense_sparse_zero_and_overlapping_writes_are_exact(self):
        randomizer = random.Random(2718)
        writes = [(0x8000, randomizer.randbytes(4096))]
        for _ in range(40):
            size = randomizer.randint(1, 150)
            body = bytes(size) if randomizer.randrange(2) else randomizer.randbytes(size)
            writes.append((0x8000 + randomizer.randrange(4096 - size), body))
        expected, actual = bytearray(4096), bytearray(4096)
        for pa, body in writes:
            expected[pa - 0x8000:pa - 0x8000 + len(body)] = body
        for pa, size, body in zero_runs(writes):
            actual[pa - 0x8000:pa - 0x8000 + size] = bytes(size) if body is None else body
        self.assertEqual(actual, expected)

    def test_wire_image_omits_zero_data_but_keeps_every_destination_byte(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        util.heap.guarded_malloc.return_value = nullcontext(0x100000)
        data = bytes(0x10000) + b"A" * 64 + bytes(127)
        self.assertEqual(write_publications(util, proxy, iface, ((0x800000, data),)), 1)
        staging, wire = iface.writemem.call_args.args
        count = util.exec.call_args.args[2]
        self.assertEqual(count, 3)
        self.assertLess(len(wire), 256)
        restored = bytearray()
        for offset in range(0, count * 24, 24):
            pa, source, length = struct.unpack_from("<3Q", wire, offset)
            self.assertEqual(pa, 0x800000 + len(restored))
            restored.extend(bytes(length) if not source else wire[source - staging:source - staging + length])
        self.assertEqual(restored, data)

    def test_validate_entire_list_before_first_proxy_access(self):
        util, proxy, iface = Mock(), Mock(), Mock()
        with self.assertRaises(ValueError):
            write_publications(util, proxy, iface, ((0x8000, b"X"), (1 << 42, b"Y")))
        self.assertEqual(util.mock_calls + proxy.mock_calls + iface.mock_calls, [])
