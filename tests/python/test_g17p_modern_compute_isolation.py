# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
os.environ.setdefault("AGX_GPU", "G17")

from agx_g17p_modern_compute_isolation import expected_output, schedule, PAGE


class ComputeIsolationTests(unittest.TestCase):
    def test_bounded_alternating_jobs_have_distinct_full_oracles(self):
        for pairs in (1, 4, 16):
            jobs = schedule(pairs)
            self.assertEqual(len(jobs), 2 * pairs + 1)
            self.assertEqual([owner for owner, _ in jobs], [0, 1] * pairs + [0])
            outputs = [expected_output(addend) for _, addend in jobs]
            self.assertEqual(len(set(outputs)), len(jobs))
            for index, body in enumerate(outputs):
                self.assertEqual(len(body), PAGE)
                self.assertEqual(struct.unpack_from("<f", body)[0], 2000.25 + index * 4096)
                self.assertFalse(any(body[256:]))
        for pairs in (0, 17):
            with self.assertRaises(ValueError):
                schedule(pairs)
