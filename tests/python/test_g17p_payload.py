# SPDX-License-Identifier: MIT

import unittest

from m1n1.agx.g17p_payload import PAGE_SIZE, parse_page_selector


class G17PPayloadTests(unittest.TestCase):
    def setUp(self):
        self.allowed = {
            0x100000,
            0x100000 + PAGE_SIZE,
            0x100000 + 2 * PAGE_SIZE,
        }

    def test_empty_selector(self):
        self.assertEqual(parse_page_selector("", self.allowed), set())

    def test_pages_and_half_open_ranges(self):
        self.assertEqual(
            parse_page_selector(
                "0x100000:0x108000, 0x108000", self.allowed),
            self.allowed,
        )

    def test_rejects_page_outside_inventory(self):
        with self.assertRaisesRegex(ValueError, "outside the payload"):
            parse_page_selector("0x10c000", self.allowed)

    def test_rejects_unaligned_and_empty_ranges(self):
        with self.assertRaisesRegex(ValueError, "unaligned"):
            parse_page_selector("0x100001", self.allowed)
        with self.assertRaisesRegex(ValueError, "empty G17P page range"):
            parse_page_selector("0x104000:0x104000", self.allowed)


if __name__ == "__main__":
    unittest.main()
