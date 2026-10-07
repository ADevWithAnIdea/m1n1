"""Host-only guard/transport checks for the opt-in self-authored shader hook."""
import base64
import contextlib
import gzip
import io
import os
from pathlib import Path
import runpy
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HOOK = Path(__file__).resolve().parents[2] / "proxyclient/hv/g17p_native_one_varying.py"


class OneVaryingHookTests(unittest.TestCase):
    def test_second_only_hook_is_armed_after_the_first_completed_output_oracle(self):
        with patch.dict(os.environ, G17P_NATIVE_CONSTANT_PRESSURE="1",
                        G17P_NATIVE_CONSTANT_SUBMISSIONS="2",
                        G17P_NATIVE_FRAGMENT="partial_fragment_constant",
                        G17P_NATIVE_CONSTANT_CAPTURE_AFTER="1"):
            scope, _, _ = self.run_hook(stage=True)
            script = scope["assets"]["run.sh"]
            self.assertIn(b"G17P_CAPTURE_AFTER=1", script)
            self.assertNotIn(b"G17P_ARM_CAPTURE_BEFORE_FIRST_COMMIT", script)
            self.assertIn(b"128 128 accumulate 131072 2", script)
        with patch.dict(os.environ, G17P_NATIVE_CONSTANT_CAPTURE_AFTER="1"), \
             self.assertRaisesRegex(ValueError, "second-only"):
            self.run_hook()

    def test_constant_pressure_staging_selects_only_its_own_bounded_workload(self):
        with patch.dict(os.environ, G17P_NATIVE_CONSTANT_PRESSURE="1",
                        G17P_NATIVE_CONSTANT_SUBMISSIONS="2",
                        G17P_NATIVE_FRAGMENT="partial_fragment_constant"):
            scope, _, _ = self.run_hook(stage=True)
            self.assertEqual(scope["assets"]["g17ppartial"], b"g17ppartial-constant-pressure")
            script = scope["assets"]["run.sh"]
            self.assertIn(b"128 128 accumulate 131072 2", script)
            self.assertIn(b"G17P_CONSTANT_PRESSURE=1", script)
            self.assertIn(b"G17P_COMMAND_QUEUE_COUNT=2", script)
        for value in ("0", "4", "-1"):
            with patch.dict(os.environ, G17P_NATIVE_CONSTANT_PRESSURE="1",
                            G17P_NATIVE_CONSTANT_SUBMISSIONS=value,
                            G17P_NATIVE_FRAGMENT="partial_fragment_constant"), \
                 self.assertRaises(ValueError):
                self.run_hook()

    def run_hook(self, *, stage=False, combined=False, capture_handler=None,
                 chip=0x8140, cmdline="-s serial=3"):
        injected = []
        def inject(command):
            injected.append(command)
            return len(command)
        hv = SimpleNamespace(adt={"/chosen": SimpleNamespace(chip_id=chip)},
                             tba=SimpleNamespace(cmdline=cmdline),
                             _vuart_marker_handler=capture_handler)
        proxy = SimpleNamespace(hv_vuart_inject=inject, hv_vuart_inject_at_prompt=inject)
        with patch.dict(os.environ, {"G17P_ONE_VARYING_STAGE": str(int(stage)),
                                    "G17P_ONE_VARYING_STAGE_AND_LAUNCH": str(int(combined))}), \
             patch.object(Path, "read_bytes", autospec=True,
                          side_effect=lambda path: path.name.encode("ascii")), \
             contextlib.redirect_stdout(io.StringIO()):
            scope = runpy.run_path(str(HOOK), init_globals={"hv": hv, "p": proxy})
            if stage or combined:
                for _ in range(len(scope["commands"])):
                    hv._vuart_marker_handler()
        return scope, injected, hv

    def test_combined_stage_restores_capture_callback_before_launch(self):
        markers = []
        handler = lambda: markers.append("capture")
        scope, injected, hv = self.run_hook(combined=True, capture_handler=handler)
        self.assertEqual(injected[:-1], scope["commands"])
        self.assertEqual(injected[-1], scope["staged_launch_command"])
        self.assertLess(len(injected[-1]), 448)
        self.assertNotIn(b"mount", injected[-1])
        self.assertIs(hv._vuart_marker_handler, handler)
        self.assertEqual(markers, [])
        hv._vuart_marker_handler()
        self.assertEqual(markers, ["capture"])
        with self.assertRaisesRegex(RuntimeError, "capture marker handler"):
            self.run_hook(combined=True)

    def test_stage_is_acknowledged_bounded_and_additive(self):
        scope, injected, hv = self.run_hook(stage=True)
        self.assertEqual(injected, scope["commands"])
        self.assertTrue(all(len(command) < 448 for command in injected))
        self.assertIsNone(hv._vuart_marker_handler)
        self.assertEqual(hv._g17p_one_varying_staged["sha256"], scope["digests"])
        self.assertTrue(all(b"G17P_PARTIAL_ARM_CAPTURE" not in c for c in injected))
        text = b"".join(injected)
        for forbidden in (b"rm ", b"killall", b"pkill", b"/dev/m1n1", b"--rid"):
            self.assertNotIn(forbidden, text)
        self.assertIn(b"if [ ! -e $U/", text)
        self.assertIn(b"test -x $U/", text)
        self.assertEqual(text.count(b"/usr/bin/shasum -a 256 -c"), 3)
        packed = gzip.decompress(base64.b64decode(scope["encoded"]))
        with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
            self.assertEqual(archive.getnames(), [scope["name"] + "/" + filename
                                                 for filename in scope["assets"]])
            for filename, body in scope["assets"].items():
                self.assertEqual(archive.extractfile(scope["name"] + "/" + filename).read(),
                                 body)

    def test_launch_uses_the_same_hashed_own_assets_and_eight_triangles(self):
        stage, _, _ = self.run_hook(stage=True)
        launch, injected, _ = self.run_hook()
        self.assertEqual(stage["guest_dir"], launch["guest_dir"])
        self.assertEqual(len(injected), 1)
        self.assertLess(len(injected[0]), 448)
        self.assertIn(b"/bin/sh $D/run.sh $D partial_fragment_one_varying", injected[0])
        script = launch["assets"]["run.sh"]
        self.assertIn(b"G17P_PARTIAL_FRAGMENT=$fragment", script)
        self.assertIn(b"G17P_PARTIAL_METAL_SOURCE=$D/shader.metal", script)
        self.assertIn(b"G17P_ARM_CAPTURE_BEFORE_FIRST_COMMIT=1", script)
        self.assertIn(b"G17P_SEPARATE_SUBMISSION_TARGETS=1", script)
        self.assertIn(b"launchctl remove io.asahi.g17p.one-varying", script)
        self.assertIn(b"128 128 accumulate 8 1", script)
        self.assertIn(b"G17P_ONE_VARYING_REJECT_MISSING_EXECUTABLE", script)
        self.assertNotIn(b"while [ ! -x", injected[0])

    def test_non_neo_or_non_single_user_guest_is_rejected(self):
        for kwargs in ({"chip": 0x8142}, {"cmdline": "-S serial=3"}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(RuntimeError, "T8140 single-user"):
                self.run_hook(**kwargs)

    def test_constant_fragment_is_explicit_and_unknown_entry_is_rejected(self):
        for fragment in ("partial_fragment_constant", "partial_fragment_biased"):
            with patch.dict(os.environ, {"G17P_NATIVE_FRAGMENT": fragment}):
                _, injected, _ = self.run_hook()
                self.assertIn(("/bin/sh $D/run.sh $D " + fragment).encode(), injected[0])
        with patch.dict(os.environ, {"G17P_NATIVE_FRAGMENT": "unrecognized"}), \
             self.assertRaisesRegex(ValueError, "unsupported own fragment"):
            self.run_hook()

    def test_vertex_observation_is_explicit_and_forwarded_in_both_launches(self):
        with patch.dict(os.environ, {"G17P_NATIVE_FRAGMENT": "partial_fragment_biased",
                                     "G17P_NATIVE_OBSERVE_VERTEX": "1"}):
            scope, injected, _ = self.run_hook()
            self.assertIn(b"partial_fragment_biased 1", injected[0])
            self.assertIn(b"partial_fragment_biased 1", scope["staged_launch_command"])
            self.assertIn(b"G17P_OBSERVE_VERTEX_OUTPUTS=$observe_vertices",
                          scope["assets"]["run.sh"])
        for fragment, selector in (("partial_fragment_one_varying", "1"),
                                   ("partial_fragment_biased", "yes")):
            with patch.dict(os.environ, {"G17P_NATIVE_FRAGMENT": fragment,
                                         "G17P_NATIVE_OBSERVE_VERTEX": selector}), \
                 self.assertRaisesRegex(ValueError, "vertex observation"):
                self.run_hook()

    def test_fragment_observation_requires_both_stage_selectors(self):
        valid = {"G17P_NATIVE_FRAGMENT": "partial_fragment_observed",
                 "G17P_NATIVE_OBSERVE_VERTEX": "1", "G17P_NATIVE_OBSERVE_FRAGMENT": "1"}
        with patch.dict(os.environ, valid):
            scope, injected, _ = self.run_hook()
            self.assertIn(b"partial_fragment_observed 1 1", injected[0])
            self.assertIn(b"partial_fragment_observed 1 1", scope["staged_launch_command"])
            self.assertIn(b"G17P_OBSERVE_FRAGMENT_INPUTS=$observe_fragments",
                          scope["assets"]["run.sh"])
        for override in ({"G17P_NATIVE_OBSERVE_VERTEX": "0"},
                         {"G17P_NATIVE_OBSERVE_FRAGMENT": "0"},
                         {"G17P_NATIVE_FRAGMENT": "partial_fragment_biased"}):
            with patch.dict(os.environ, dict(valid, **override)), \
                 self.assertRaisesRegex(ValueError, "fragment observation"):
                self.run_hook()


if __name__ == "__main__":
    unittest.main()
