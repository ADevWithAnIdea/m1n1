# SPDX-License-Identifier: MIT

import unittest

from m1n1.agx.g17p_source_topology import (
    G17PSourceTopology,
    PAGE_SIZE,
    context0_firmware_peers,
    native_firmware_leaf_pages,
    native_table_targets,
)


class G17PSourceTopologyTests(unittest.TestCase):
    def test_established_root_inventory(self):
        topology = G17PSourceTopology()
        self.assertEqual(topology.selected_root, 1)
        self.assertEqual(topology.root_ctx[0], 0)
        self.assertEqual(topology.root_ctx[1], 64)
        self.assertEqual(topology.root_ctx[7], 1)
        self.assertEqual(
            {root: len(pages) for root, pages in topology.by_root.items()},
            {
                0: 299,
                1: 626,
                2: 1,
                3: 1,
                4: 1,
                5: 1,
                6: 1,
                7: 3618,
                8: 1807,
                9: 1807,
                10: 1807,
                11: 1,
            },
        )

    def test_context_zero_aliases_name_firmware_pages(self):
        topology = G17PSourceTopology()
        peers = context0_firmware_peers()
        self.assertEqual(len(peers), 299)
        self.assertEqual(
            peers[0x7000000000], 0xfffffc20c0018000)
        self.assertEqual(
            peers[0x7001870000 + 7 * PAGE_SIZE],
            0xfffffc20c07f8000 + 7 * PAGE_SIZE,
        )
        for low, high in peers.items():
            self.assertIn(low, topology.by_root[0])
            self.assertIn(high, topology.by_root[1])
            self.assertEqual(
                topology.pa_by_root[0][low],
                topology.pa_by_root[1][high],
            )

    def test_content_interface_is_always_blank(self):
        topology = G17PSourceTopology()
        self.assertEqual(topology.page(0), bytes(PAGE_SIZE))
        self.assertEqual(topology.blob(123), bytes(PAGE_SIZE))
        self.assertEqual(topology.bytes_or_zero(0, 37), bytes(37))
        self.assertEqual(topology.bytes(0, 19), bytes(19))

    def test_first_partial_uses_the_three_native_root_slots(self):
        topology = G17PSourceTopology(partial_opening=True)
        self.assertEqual(topology.root_ctx, {0: 0, 1: 64, 2: 1})
        self.assertEqual(
            {root: len(pages) for root, pages in topology.by_root.items()},
            {0: 299, 1: 626, 2: 2241},
        )
        self.assertIn(0x10000350000, topology.by_root[2])
        self.assertNotIn(7, topology.by_root)

    def test_native_physical_topology_is_address_only_and_complete(self):
        leaves = native_firmware_leaf_pages()
        self.assertEqual(len(leaves), 661)
        self.assertEqual(leaves[0xfffffc2000020000], 0x10034b54000)
        self.assertEqual(leaves[0xfffffc20c0860000], 0x100543e4000)
        self.assertEqual(leaves[0xfffffc21800ec000], 0x480e20000)
        self.assertEqual(len(leaves) - len(set(leaves.values())), 1)

        self.assertEqual(
            native_table_targets("context0"),
            {
                (): 0x10034bcc000,
                (7,): 0x10035138000,
                (7, 0): 0x10035134000,
            },
        )
        self.assertEqual(len(native_table_targets("render_low")), 9)
        self.assertEqual(
            native_table_targets("render_low")[()], 0x10057ba0000)
        self.assertEqual(len(native_table_targets("firmware_high")), 5)
        self.assertEqual(
            native_table_targets("firmware_high")[()], 0x10021598000)


if __name__ == "__main__":
    unittest.main()
