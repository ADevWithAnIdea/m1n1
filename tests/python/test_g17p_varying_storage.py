import importlib.util
from pathlib import Path
import unittest

source = Path(__file__).parents[2] / "proxyclient/experiments/agx_g17p_inspect_varying_storage.py"
spec = importlib.util.spec_from_file_location("varying_storage", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VaryingStorageOwnershipTests(unittest.TestCase):
    def test_anchor_is_one_complete_explicit_caller_output(self):
        observer = dict(pa=0x10000100000, size=module.PAGE)
        self.assertEqual(module.caller_anchor(dict(vertex_observation=observer)),
                         (observer["pa"], module.PAGE, "modern_vertex_observation_after.bin"))
        outputs = [dict(pa=0x10000200000 + i * 4 * module.PAGE, size=4 * module.PAGE)
                   for i in range(8)]
        self.assertEqual(module.caller_anchor(dict(outputs=outputs)),
                         (outputs[0]["pa"], 4 * module.PAGE, "modern_partial_output_0.bin"))
        for ownership in (dict(outputs=outputs[:-1]),
                          dict(vertex_observation=dict(observer, size=4)),
                          dict(vertex_observation=dict(observer, pa=1)),
                          dict(vertex_observation=dict(observer, pa=0)),
                          dict(vertex_observation=dict(observer, pa=None))):
            with self.assertRaises(ValueError):
                module.caller_anchor(ownership)

    def test_latest_whole_page_placement_wins(self):
        allocations = [dict(va=0x10000, pa=0x20000, size=0x8000),
                       dict(va=0x14000, pa=0x30000, size=0x4000)]
        self.assertEqual(module.owned_page(allocations, 0x10000), 0x20000)
        self.assertEqual(module.owned_page(allocations, 0x14000), 0x30000)
        with self.assertRaisesRegex(ValueError, "no recorded owner"):
            module.owned_page(allocations, 0x18000)


if __name__ == "__main__":
    unittest.main()
