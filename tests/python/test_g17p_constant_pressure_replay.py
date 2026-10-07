# SPDX-License-Identifier: MIT
"""Full-image and ownership gates for the self-authored native pressure test."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient" / "experiments"))
from agx_g17p_replay_constant_pressure import validate, PAGE, SIZE


class ConstantPressureReplayTests(unittest.TestCase):
    def make_outputs(self, path, ordinal=2, x_shift=2):
        rows = []
        for index in range(ordinal * 8):
            expected = bytearray(SIZE)
            for offset in (0x7efc + x_shift * 4, 0x7f00 + x_shift * 4):
                struct.pack_into('<f', expected, offset, float((index % 8 + 1) * 16384))
            for offset in range(0, SIZE, PAGE):
                before = '%d_%d_before.bin' % (index, offset)
                after = '%d_%d_after.bin' % (index, offset)
                (path / before).write_bytes(expected[offset:offset + PAGE]
                                           if index < (ordinal - 1) * 8 else bytes(PAGE))
                (path / after).write_bytes(expected[offset:offset + PAGE])
                rows.append(dict(dva=0x10000058000 + index * 0x18000 + offset,
                    pa=0x100000 + len(rows) * PAGE, before_file=before, after_file=after))
        (path / 'render_watch.json').write_text(json.dumps(rows))
        return rows

    def test_independent_exact_images_and_shift(self):
        for shift in (0, 2):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                self.make_outputs(path, x_shift=shift)
                validate(path, 2, shift)

    def test_stray_byte_is_rejected_even_with_exact_covered_pixels(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            rows = self.make_outputs(path)
            target = path / rows[-1]['after_file']
            body = bytearray(target.read_bytes())
            body[1234] = 1
            target.write_bytes(body)
            with self.assertRaisesRegex(RuntimeError, 'full image differs'):
                validate(path, 2, 2)

    def test_aliased_physical_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            rows = self.make_outputs(path)
            rows[-1]['pa'] = rows[0]['pa']
            (path / 'render_watch.json').write_text(json.dumps(rows))
            with self.assertRaisesRegex(RuntimeError, 'aliases output backing'):
                validate(path, 2, 2)

    def test_prior_output_and_fresh_zero_prestate_are_checked(self):
        for index in (1, 33):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                rows = self.make_outputs(path)
                target = path / rows[index]['before_file']
                body = bytearray(target.read_bytes())
                body[42] = 1
                target.write_bytes(body)
                with self.assertRaisesRegex(RuntimeError, 'invalid prior state'):
                    validate(path, 2, 2)
