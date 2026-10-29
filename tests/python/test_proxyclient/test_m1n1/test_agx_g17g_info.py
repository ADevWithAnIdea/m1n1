# SPDX-License-Identifier: GPL-2.0-only
"""Live-ID decoding and generation gates, independently of GPU execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "proxyclient"))
from m1n1.drm_shim.g17g_info import decode_params


class G17GInfoTests(unittest.TestCase):
    def decode(self, **changes):
        args = dict(chip_id=0x8142, version=0x0b022000, counts=0x11010a,
                    masks=(0x3bd, 0, 0), frequencies=(0, 338000000, 1578000000),
                    counter_hz=1000000000)
        args.update(changes)
        return decode_params(**args)

    def test_disabled_cores_are_not_reported_as_present(self):
        params = self.decode()
        self.assertEqual((params.gpu_generation, params.gpu_variant, params.gpu_revision),
                         (17, ord("G"), 0x20))
        self.assertEqual((params.num_dies, params.num_clusters_total,
                          params.num_cores_per_cluster), (1, 1, 10))
        self.assertEqual(params.core_masks[0], 0x3bd)
        self.assertEqual(params.core_masks[0].bit_count(), 8)
        self.assertFalse(any(params.core_masks[1:]))
        self.assertEqual(params.max_frequency_khz, 1578000)
        self.assertEqual(params.command_timestamp_frequency_hz, 1000000000)
        self.assertEqual(params.vm_end, (1 << 42) - 0x8000)

    def test_unknown_generation_geometry_revision_clock_and_bad_mask_reject(self):
        for change in (dict(chip_id=0x8140), dict(version=0x0b012000),
                       dict(version=0x0a022000), dict(version=0x0b020000),
                       dict(counts=0x110108), dict(counts=0x11020a),
                       dict(masks=(0, 0, 0)), dict(masks=(0x7ff, 0, 0)),
                       dict(masks=(0x3bd, 1, 0)), dict(counter_hz=24000000),
                       dict(frequencies=()), dict(frequencies=(0,))):
            with self.subTest(change=change), self.assertRaises(OSError):
                self.decode(**change)
