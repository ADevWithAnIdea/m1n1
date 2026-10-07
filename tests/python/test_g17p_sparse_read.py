# SPDX-License-Identifier: MIT
import struct
import unittest
from pathlib import Path
import sys
from contextlib import contextmanager
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient"))

from m1n1.agx.g17p_sparse_read import unpack_lines, validate_vector, SparseRead


class SparseReadTests(unittest.TestCase):
    def test_exact_patterns(self):
        patterns = [bytes(4096), bytes(range(256)) * 16,
                    b"".join(bytes(i) + b"\x80" + bytes(63 - i)
                             for i in range(64))]
        for source in patterns:
            packed = b"".join(struct.pack("<Q", i // 64) + source[i:i + 64]
                              for i in range(0, len(source), 64)
                              if any(source[i:i + 64]))
            self.assertEqual(unpack_lines(packed, len(source)), source)

    def test_sparse_gaps(self):
        packed = struct.pack("<Q", 1) + b"x" * 64 + struct.pack("<Q", 3) + b"y" * 64
        self.assertEqual(unpack_lines(packed, 320),
                         bytes(64) + b"x" * 64 + bytes(64) + b"y" * 64 + bytes(64))

    def test_reject_malformed(self):
        record = lambda index: struct.pack("<Q", index) + bytes(64)
        for packed, size in [(b"", 0), (b"", 65), (b"x", 64),
                             (record(1), 64), (record(0) * 2, 128),
                             (record(1) + record(0), 128),
                             (record(2**64 - 1), 64)]:
            with self.assertRaises(ValueError):
                unpack_lines(packed, size)

    def test_vector_bounds_exclude_mmio_unaligned_and_unbounded_transfers(self):
        base = 0x10000000000
        for ranges in ([], [(0x348000000, 64)], [(base + 8, 64)],
                       [(base, 65)], [(base, 0)], [(base, -64)],
                       [(base, 0x400040)], [(base, 64)] * 1025,
                       [(0x100ffffffc0, 128)]):
            with self.assertRaises(ValueError):
                validate_vector(ranges)
        ranges = ((base + 0x4000, 128), (base, 64), (base + 0x4040, 64))
        # Aliases and out-of-order explicit spans are valid; each is returned
        # independently in the caller's order, not sorted or deduplicated.
        self.assertEqual(validate_vector(ranges), (ranges, 256))

    def vector_reader(self, fault=None):
        memory, allocations = {}, []
        def write(address, body):
            memory.update((address + i, value) for i, value in enumerate(body))
        def read(address, size):
            body = bytes(memory.get(address + i, 0) for i in range(size))
            return body[:-1] if fault == "short" else body
        @contextmanager
        def allocate(size):
            address = 0x10020000000 + len(allocations) * 0x100000
            allocations.append((address, size))
            yield address
        def execute(_code, vector, output, count):
            source = b""
            for item in range(count):
                address, lines = struct.unpack("<QQ", bytes(
                    memory.get(vector + item * 16 + i, 0) for i in range(16)))
                source += bytes(memory.get(address + i, 0) for i in range(lines * 64))
            packed = b"".join(struct.pack("<Q", i // 64) + source[i:i + 64]
                              for i in range(0, len(source), 64) if any(source[i:i + 64]))
            write(output, packed)
            return 1 if fault == "length" else len(packed)
        iface = SimpleNamespace(readmem=read, writemem=write)
        util = SimpleNamespace(heap=SimpleNamespace(guarded_malloc=allocate), exec=execute)
        return SparseRead(util, iface), write

    def test_vector_reconstruction_returns_all_spans_in_order(self):
        reader, write = self.vector_reader()
        base = 0x10010000000
        source = bytes(range(256)) + bytes(256) + bytes([129]) * 256
        write(base, source)
        ranges = ((base + 512, 256), (base + 256, 256), (base, 256), (base + 64, 64))
        self.assertEqual(reader.read_many(ranges),
                         [source[address - base:address - base + size] for address, size in ranges])
        self.assertEqual((reader.source_bytes, reader.wire_bytes, reader.calls), (832, 648, 1))

    def test_vector_bad_target_length_and_short_transfer_fail_closed(self):
        for fault in ("length", "short"):
            reader, write = self.vector_reader(fault)
            write(0x10010000000, b"x" * 64)
            with self.assertRaises(RuntimeError):
                reader.read_many([(0x10010000000, 64)])
            self.assertEqual(reader.calls, 0)


if __name__ == "__main__":
    unittest.main()
