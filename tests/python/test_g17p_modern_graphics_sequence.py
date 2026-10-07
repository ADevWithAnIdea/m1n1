# SPDX-License-Identifier: MIT
"""Caller-side pressure/ZLS fixture bounds, whole-buffer oracles and UAPI."""
import os
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
os.environ.setdefault("AGX_GPU", "G17")

import agx_g17p_modern_graphics_sequence as graphics


class GraphicsSequenceTests(unittest.TestCase):
    def test_report_encodes_nested_fence_status_bytes_without_dropping_them(self):
        status = b"\x00\x81\x01\xff"
        value = {"fence": {"commands": [{"status": status}]}}
        self.assertEqual(json.loads(graphics.report_json(value)),
                         {"fence": {"commands": [{"status": status.hex()}]}})
        with self.assertRaises(TypeError):
            graphics.report_json({"unexpected": object()})

    def test_zls_oracles_cover_complete_depth_and_stencil_guards(self):
        initial = graphics.zls_images("store", initial=True)
        expected = graphics.zls_images("store")
        self.assertTrue(all(body == bytes(graphics.SIZE) for body in initial.values()))
        self.assertEqual(expected[graphics.DEPTH], struct.pack("<f", 0.25) * 16384)
        self.assertEqual(expected[graphics.STENCIL], b"\x5a" * 16384 + bytes(49152))
        self.assertEqual(graphics.zls_images("load-store", initial=True),
                         graphics.zls_images("load-store"))
        self.assertEqual(graphics.zls_images("none"), {})
        with self.assertRaises(ValueError):
            graphics.zls_images("bad")

    def test_zls_changes_only_typed_caller_fields_not_programs_or_color_hints(self):
        plain, = graphics.uapi.parse_command_buffer(graphics.render_stream(7, "none"))
        for mode in ("store", "load-store"):
            command, = graphics.uapi.parse_command_buffer(graphics.render_stream(7, mode))
            self.assertEqual([a.to_bytes() for a in command.fragment_attachments],
                             [a.to_bytes() for a in plain.fragment_attachments])
            changed = command.payload
            self.assertEqual((changed.depth.base, changed.stencil.base), graphics.ZLS)
            self.assertEqual(changed.zls_ctrl, 0xc0000 if mode == "store" else 0xcc000)
            self.assertEqual(changed.isp_zls_pixels, 127 | 127 << 15)
            for name in ("depth", "stencil", "zls_ctrl", "isp_zls_pixels",
                         "isp_bgobjdepth", "isp_bgobjvals"):
                setattr(changed, name, getattr(plain.payload, name))
            self.assertEqual(changed.to_bytes(), plain.payload.to_bytes())

    def test_independence_checks_full_physical_intervals_not_just_bases(self):
        self.assertTrue(graphics.disjoint_ranges([(0x10000, 0x10000), (0x20000, 0x4000)]))
        self.assertFalse(graphics.disjoint_ranges([(0x10000, 0x10000), (0x18000, 0x4000)]))
        self.assertFalse(graphics.disjoint_ranges([(None, 0x4000)]))


if __name__ == "__main__":
    unittest.main()
