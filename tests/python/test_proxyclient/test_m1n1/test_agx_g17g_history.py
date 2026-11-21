# SPDX-License-Identifier: GPL-2.0-only
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from m1n1.drm_shim import g17g_defaults as defaults, g17g_initdata as init, g17g_uat as uat
from m1n1.drm_shim.g17g_history import prepare_mixed_history, PAGE, HISTORY_RELOCATION


class TestMixedHistory(unittest.TestCase):
    def runtime(self):
        fields = defaults.canonical_preinit_fields()
        recipe = uat.expand_firmware_root_recipe(uat.build_firmware_root_recipe(fields['hwdata_fields']))
        pages = {address: 0x1000000 + index * PAGE for index, address in enumerate(sorted(recipe))}
        mapped = {(1, address): pa for address, pa in pages.items()}
        pointers = {init.HWDATA_ADDRESS + init.HWDATA_REGION_RECORDS + index*0x20 + 0xc:
                    struct.pack('<Q', record['address_0c'])
                    for index, record in enumerate(fields['hwdata_fields']['region_records'])}
        r = SimpleNamespace(root=1, pages=pages, evidence={},
            boot=SimpleNamespace(fields=fields, context0_low_root=2), uat=Mock(),
            channel_state=lambda: (0, 0, 1),
            alloc=Mock(side_effect=(0x4000000 + index*PAGE for index in range(10))),
            publish=Mock(side_effect=lambda pages: tuple(pages)), flush_tables=Mock(),
            published=[])
        r.publish_writes = Mock(side_effect=lambda writes: r.published.extend(writes))
        r.uat.iotranslate_root.side_effect = lambda root, address, size: [(mapped.get((root,address)),size)]
        r.uat.iomap_at_root.side_effect = lambda root,address,pa,size,**flags: mapped.update({(root,address):pa})
        r.read_fields = lambda fields: {key:pointers.get(address,bytes(size)) for key,(address,size) in fields.items()}
        return r, mapped, pointers

    def test_both_history_heads_share_backing_and_all_low_aliases_match(self):
        r, mapped, pointers = self.runtime()
        prepare_mixed_history(r)
        evidence = r.evidence['history_admission']
        self.assertEqual(len(evidence['created']),6)
        self.assertEqual(len(evidence['retained_aliases']),6)
        self.assertEqual(len(evidence['low_aliases']),24)
        for old, new in evidence['retained_aliases']:
            self.assertEqual(mapped[1,old],mapped[1,new])
            self.assertEqual(r.pages[old],r.pages[new])
        for low, high in evidence['low_aliases']:
            self.assertEqual(mapped[2,low],mapped[1,high])
        for index,row in enumerate(r.boot.fields['hwdata_fields']['region_records'][:3]):
            self.assertEqual(row['address_0c'],defaults.CANONICAL_REGION_ADDRESSES[index]+HISTORY_RELOCATION)
        self.assertEqual(r.published,[(field,struct.pack('<Q',new))
                                     for field,old,new in evidence['pointers']])
        self.assertEqual(len(r.published),3)
        self.assertTrue(r.evidence['command_publication_started'])
        self.assertEqual([x.args for x in r.flush_tables.call_args_list],[(0,),(0x40,)])

    def test_changed_initialization_pointer_rejects_before_allocating_or_mapping(self):
        r, mapped, pointers = self.runtime()
        pointers[next(iter(pointers))] = bytes(8)
        with self.assertRaisesRegex(RuntimeError,'pointer changed'):
            prepare_mixed_history(r)
        r.alloc.assert_not_called()
        r.uat.iomap_at_root.assert_not_called()
        self.assertNotIn('command_publication_started',r.evidence)

    def test_nonempty_owned_history_rejects_before_replacing_backing(self):
        r, mapped, pointers = self.runtime()
        original = r.read_fields
        def read(fields):
            result = original(fields)
            for key,(address,size) in fields.items():
                if address == defaults.CANONICAL_REGION_ADDRESSES[0] and size == PAGE:
                    result[key] = b'\x01' + bytes(PAGE-1)
            return result
        r.read_fields = read
        with self.assertRaisesRegex(RuntimeError,'not initially empty'):
            prepare_mixed_history(r)
        r.alloc.assert_not_called()
        r.uat.iomap_at_root.assert_not_called()

    def test_foreign_mapping_rejects_before_replacing_any_history(self):
        r, mapped, pointers = self.runtime()
        mapped[1,defaults.CANONICAL_REGION_ADDRESSES[2]] = 0xdead0000
        with self.assertRaisesRegex(RuntimeError,'no owned backing'):
            prepare_mixed_history(r)
        r.alloc.assert_not_called()
        r.uat.iomap_at_root.assert_not_called()
