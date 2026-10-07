# SPDX-License-Identifier: MIT
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "proxyclient/experiments"))
from agx_g17p_vertex_observation import OBSERVATION_SIZE, validate_vertex_observations


class VertexObservationTests(unittest.TestCase):
    def output(self):
        body = bytearray(OBSERVATION_SIZE)
        for vertex in range(24):
            struct.pack_into("<9f", body, vertex * 36, vertex + 1,
                             *(component / 8 for component in range(1, 9)))
        return body

    def test_all_vertices_and_zero_tail(self):
        result = validate_vertex_observations(bytes(OBSERVATION_SIZE), self.output())
        self.assertTrue(result["exact"])
        self.assertEqual(result["bad_words"], [])
        self.assertEqual(len(result["values"]), 24)

    def test_every_missing_word_is_rejected(self):
        for word in range(24 * 9):
            body = self.output()
            body[word * 4:word * 4 + 4] = bytes(4)
            result = validate_vertex_observations(bytes(OBSERVATION_SIZE), body)
            self.assertFalse(result["exact"])
            self.assertEqual(result["bad_words"], [word])

    def test_stale_truncated_and_outside_data_are_rejected(self):
        self.assertFalse(validate_vertex_observations(self.output(), self.output())["exact"])
        for offset in (864, OBSERVATION_SIZE - 1):
            body = self.output()
            body[offset] = 1
            result = validate_vertex_observations(bytes(OBSERVATION_SIZE), body)
            self.assertFalse(result["exact"])
            self.assertEqual(result["outside_bytes"], 1)
        with self.assertRaisesRegex(ValueError, "complete"):
            validate_vertex_observations(bytes(OBSERVATION_SIZE), bytes(864))

    def test_fragment_records_are_explicit_and_every_word_is_checked(self):
        body = self.output()
        for record in range(16):
            struct.pack_into("<9f", body, 0x400 + record * 36, record // 2 + 1,
                             *(component / 8 for component in range(1, 9)))
        self.assertFalse(validate_vertex_observations(bytes(OBSERVATION_SIZE), body)["exact"])
        self.assertTrue(validate_vertex_observations(bytes(OBSERVATION_SIZE), body,
                                                     fragment_inputs=True)["exact"])
        for word in range(16 * 9):
            changed = bytearray(body)
            changed[0x400 + word * 4:0x404 + word * 4] = bytes(4)
            result = validate_vertex_observations(bytes(OBSERVATION_SIZE), changed,
                                                  fragment_inputs=True)
            self.assertFalse(result["exact"])
            self.assertEqual(result["bad_words"], [])
            self.assertEqual(result["fragment_bad_words"], [word])
        for offset in (864, 0x3ff, 0x640, OBSERVATION_SIZE - 1):
            changed = bytearray(body)
            changed[offset] = 1
            self.assertFalse(validate_vertex_observations(bytes(OBSERVATION_SIZE), changed,
                                                          fragment_inputs=True)["exact"])

    def test_triangle_pattern_checks_every_word_with_preselected_numeric_tolerance(self):
        body = bytearray(OBSERVATION_SIZE)
        for index in range(24):
            struct.pack_into("<9f", body, index * 36, index + 1,
                *((index // 3 + 1) * component / 255 for component in range(1, 9)))
        for index in range(16):
            struct.pack_into("<9f", body, 0x400 + index * 36, index // 2 + 1,
                *((index // 2 + 1) * component / 255 for component in range(1, 9)))
        def validate(data):
            return validate_vertex_observations(bytes(OBSERVATION_SIZE), data,
                fragment_inputs=True, triangle_varyings=True)
        self.assertTrue(validate(body)["exact"])
        self.assertEqual(validate(body)["varying_tolerance"], 1e-7)
        for offset, words in ((0, 24 * 9), (0x400, 16 * 9)):
            for word in range(words):
                changed = bytearray(body)
                changed[offset + word * 4:offset + word * 4 + 4] = bytes(4)
                self.assertFalse(validate(changed)["exact"])
        changed = bytearray(body)
        struct.pack_into("<f", changed, 0x404, float("nan"))
        self.assertFalse(validate(changed)["exact"])
        changed = bytearray(body)
        changed[-1] = 1
        self.assertFalse(validate(changed)["exact"])


if __name__ == "__main__":
    unittest.main()
