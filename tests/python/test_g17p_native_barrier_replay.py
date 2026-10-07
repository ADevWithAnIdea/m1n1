# SPDX-License-Identifier: MIT
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient/experiments"))
from agx_g17p_replay_native_barriers import EXPECTED, PAGE, validate_outputs


class NativeBarrierReplayTests(unittest.TestCase):
    def output(self):
        result = bytearray(PAGE)
        for offset, body in EXPECTED.values():
            result[offset:offset + len(body)] = body
        return result

    def test_all_three_complete_outputs(self):
        self.assertTrue(validate_outputs(bytes(PAGE), self.output())["passed"])

    def test_every_output_byte_matters(self):
        for name, (offset, expected) in EXPECTED.items():
            for index in range(len(expected)):
                after = self.output()
                after[offset + index] ^= 1
                result = validate_outputs(bytes(PAGE), after)
                self.assertFalse(result["passed"], (name, index))
                self.assertFalse(result["outputs"][name]["exact"])

    def test_unchanged_or_precomputed_output_cannot_pass(self):
        self.assertFalse(validate_outputs(bytes(PAGE), bytes(PAGE))["passed"])
        self.assertFalse(validate_outputs(self.output(), self.output())["passed"])

    def test_short_read_is_not_a_complete_witness(self):
        with self.assertRaises(ValueError):
            validate_outputs(bytes(PAGE), bytes(PAGE - 1))


if __name__ == "__main__":
    unittest.main()
