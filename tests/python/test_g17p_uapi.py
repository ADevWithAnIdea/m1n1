# SPDX-License-Identifier: MIT

import ctypes
import importlib.util
import pathlib
import unittest


MODULE = (pathlib.Path(__file__).parents[2] / "proxyclient" / "m1n1" /
          "agx" / "g17p_uapi.py")
SPEC = importlib.util.spec_from_file_location("g17p_uapi", MODULE)
UAPI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UAPI)


def header(command_type, payload, vdm=UAPI.DRM_ASAHI_BARRIER_NONE,
           cdm=UAPI.DRM_ASAHI_BARRIER_NONE):
    value = UAPI.drm_asahi_cmd_header(
        command_type, len(payload), vdm, cdm)
    return value.to_bytes() + payload


class G17PModernUAPITests(unittest.TestCase):
    def test_layouts_match_canonical_header(self):
        for structure, expected in UAPI.EXPECTED_STRUCTURE_SIZES.items():
            self.assertEqual(ctypes.sizeof(structure), expected)

    def test_compute_command_and_zero_extension(self):
        payload = UAPI.drm_asahi_cmd_compute()
        payload.cdm_ctrl_stream_base = 0x12340000
        commands = UAPI.parse_command_buffer(header(
            UAPI.DRM_ASAHI_CMD_COMPUTE, payload.to_bytes()[:32]))

        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].payload.cdm_ctrl_stream_base, 0x12340000)
        self.assertEqual(commands[0].payload.helper.binary, 0)

    def test_attachment_state_is_snapshotted_per_command(self):
        attachment = UAPI.drm_asahi_attachment(0x10000, 0x4000, 0, 0)
        compute = UAPI.drm_asahi_cmd_compute().to_bytes()
        raw = (header(UAPI.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS,
                      attachment.to_bytes()) +
               header(UAPI.DRM_ASAHI_CMD_COMPUTE, compute) +
               header(UAPI.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS, b"") +
               header(UAPI.DRM_ASAHI_CMD_COMPUTE, compute, cdm=1))
        commands = UAPI.parse_command_buffer(raw)

        self.assertEqual(len(commands[0].compute_attachments), 1)
        self.assertEqual(commands[0].compute_attachments[0].pointer, 0x10000)
        self.assertEqual(commands[1].compute_attachments, ())

    def test_rejects_future_barrier(self):
        compute = UAPI.drm_asahi_cmd_compute().to_bytes()
        with self.assertRaisesRegex(ValueError, "future"):
            UAPI.parse_command_buffer(header(
                UAPI.DRM_ASAHI_CMD_COMPUTE, compute, cdm=1))

    def test_rejects_nonzero_unknown_tail(self):
        compute = UAPI.drm_asahi_cmd_compute().to_bytes() + b"\x01"
        with self.assertRaisesRegex(ValueError, "unknown"):
            UAPI.parse_command_buffer(header(
                UAPI.DRM_ASAHI_CMD_COMPUTE, compute))

    def test_rejects_malformed_attachment_and_software_barrier(self):
        with self.assertRaisesRegex(ValueError, "whole number"):
            UAPI.parse_command_buffer(
                header(UAPI.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS, b"\0") +
                header(UAPI.DRM_ASAHI_CMD_COMPUTE,
                       UAPI.drm_asahi_cmd_compute().to_bytes()))
        with self.assertRaisesRegex(ValueError, "cannot carry barriers"):
            UAPI.parse_command_buffer(
                header(UAPI.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS, b"", cdm=0) +
                header(UAPI.DRM_ASAHI_CMD_COMPUTE,
                       UAPI.drm_asahi_cmd_compute().to_bytes()))

    def test_requires_hardware_command(self):
        with self.assertRaisesRegex(ValueError, "hardware command"):
            UAPI.parse_command_buffer(header(
                UAPI.DRM_ASAHI_SET_COMPUTE_ATTACHMENTS, b""))


if __name__ == "__main__":
    unittest.main()
