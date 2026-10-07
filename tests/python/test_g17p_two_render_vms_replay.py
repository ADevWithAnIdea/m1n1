# SPDX-License-Identifier: MIT
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / 'proxyclient/experiments'))
from agx_g17p_replay_two_render_vms import BASES, CONTEXTS, PAGE, SIZE, expected_image, validate_outputs


class TwoRenderVMReplayTests(unittest.TestCase):
    def setUp(self):
        self.records, self.files = [], {}
        for context in CONTEXTS:
            for attachment, base in enumerate(BASES):
                expected = expected_image(attachment)
                for offset in range(0, SIZE, PAGE):
                    stem = '%d_%x' % (context, base + offset)
                    row = dict(context=context, dva=base + offset,
                               pa=(len(self.records) + 1) * PAGE,
                               before_file=stem + '_before', after_file=stem + '_after')
                    self.records.append(row)
                    self.files[row['before_file']] = bytes(PAGE)
                    self.files[row['after_file']] = expected[offset:offset + PAGE]

    def test_full_independent_outputs(self):
        self.assertEqual(validate_outputs(self.records, self.files.__getitem__)['complete_outputs'], 16)

    def test_second_owner_missing_does_not_pass_first_owner_output(self):
        with self.assertRaises(ValueError):
            validate_outputs(self.records[:32], self.files.__getitem__)

    def test_guards_and_prior_output_are_checked(self):
        for field, offset in (('before_file', 0), ('after_file', PAGE - 1)):
            name = self.records[47][field]
            saved = self.files[name]
            changed = bytearray(saved)
            changed[offset] ^= 1
            self.files[name] = changed
            with self.assertRaises(ValueError):
                validate_outputs(self.records, self.files.__getitem__)
            self.files[name] = saved

    def test_alias_short_read_and_duplicate_owner_rejected(self):
        self.records[32]['pa'] = self.records[0]['pa']
        with self.assertRaises(ValueError):
            validate_outputs(self.records, self.files.__getitem__)
        self.records[32]['pa'] = 33 * PAGE
        self.files[self.records[32]['after_file']] = bytes(PAGE - 1)
        with self.assertRaises(ValueError):
            validate_outputs(self.records, self.files.__getitem__)
        self.records[32]['context'] = 1
        with self.assertRaises(ValueError):
            validate_outputs(self.records, self.files.__getitem__)


if __name__ == '__main__':
    unittest.main()
