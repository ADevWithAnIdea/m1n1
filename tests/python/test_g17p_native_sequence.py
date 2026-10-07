# SPDX-License-Identifier: MIT
"""Bounded producer ownership for the native partial sequence capture hook."""
import contextlib
import io
import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "proxyclient"))


class NativeSequenceTests(unittest.TestCase):
    def hook(self, first, count):
        memory = {0x4000: first - 1, 0x4040: first - 1}
        proxy = Mock()
        proxy.read32.side_effect = memory.__getitem__
        proxy.write32.side_effect = memory.__setitem__
        hv = SimpleNamespace(adt={"/chosen": SimpleNamespace(chip_id=0x8140)},
            tba=SimpleNamespace(cmdline="-s"), _agx_g17p_init_message=1,
            add_tracer=Mock(), del_tracer=Mock(), pt_update=Mock(),
            _agx_g17p_arm_full_capture=Mock())
        recorder = SimpleNamespace(channels=[
            dict(name=name, producer_pa=address) for name, address in
            (("TA_2", 0x4000), ("3D_2", 0x4040))])
        with patch.dict(os.environ, {
                "G17P_PRODUCER_ARM_ON_VUART_MARKER": "1",
                "AGX_G17P_CAPTURE_SPARSE_RAM": "1", "G17P_SEQUENCE_HOOK_ONLY": "1",
                "G17P_SEQUENCE_FIRST_CAPTURE": str(first),
                "G17P_SEQUENCE_CAPTURE_COUNT": str(count)}), \
             contextlib.redirect_stdout(io.StringIO()):
            scope = runpy.run_path(str(ROOT / "proxyclient/hv/g17p_launch_partial_sequence.py"),
                init_globals=dict(hv=hv, p=proxy, u=Mock(), outer_submission_recorder=recorder))
        return scope, hv, proxy, memory

    def test_second_boundary_waits_for_its_marker_and_holds_both_stores(self):
        scope, hv, proxy, memory = self.hook(2, 1)
        hv.add_tracer.assert_not_called()
        self.assertEqual(hv._agx_g17p_native_sequence_ordinal, 2)
        hv._vuart_marker_handler()
        scope["producer_write"](0x4000, 2, 32)
        hv._agx_g17p_arm_full_capture.assert_not_called()
        scope["producer_write"](0x4040, 2, 32)
        hv._agx_g17p_arm_full_capture.assert_called_once()
        self.assertEqual(memory, {0x4000: 1, 0x4040: 1})
        self.assertEqual(scope["producer_read"](0x4000, 32), 2)
        hv._agx_g17p_initdata_capture = "own-full-checkpoint"
        scope["release_publication"]()
        self.assertEqual(memory, {0x4000: 2, 0x4040: 2})
        self.assertEqual(hv.del_tracer.call_count, 2)
        self.assertEqual(hv._agx_g17p_native_sequence_previous, "own-full-checkpoint")

    def test_wrong_prefix_or_failed_capture_cannot_publish(self):
        scope, hv, proxy, memory = self.hook(2, 1)
        with self.assertRaisesRegex(RuntimeError, "completed native prefix"):
            scope["producer_write"](0x4000, 1, 32)
        with self.assertRaisesRegex(RuntimeError, "publication remains held"):
            scope["release_publication"]()
        proxy.write32.assert_not_called()

    def test_first_capture_keeps_second_boundary_armed(self):
        scope, hv, proxy, memory = self.hook(1, 2)
        hv._vuart_marker_handler()
        for address in memory:
            scope["producer_write"](address, 1, 32)
        hv._agx_g17p_initdata_capture = "own-first-checkpoint"
        scope["release_publication"]()
        hv.del_tracer.assert_not_called()
        self.assertIsNone(hv._agx_g17p_initdata_capture)
        self.assertEqual(hv._agx_g17p_native_sequence_ordinal, 2)
