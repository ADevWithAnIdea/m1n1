# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
os.environ.setdefault("AGX_GPU", "G17")

from agx_g17p_modern_compute_reuse import (
    build_reuse_workloads, verify_outputs, track_calls, job_resource,
    command, compute, uapi, PAGE, modern)


class ModernComputeReuseTests(unittest.TestCase):
    def test_retained_outputs_are_independent_and_program_graphs_reused(self):
        bodies, jobs = build_reuse_workloads(264, 32)
        pages = set()
        for address, (body, _writable) in bodies.items():
            span = set(range(address, address + len(body), PAGE))
            self.assertFalse(pages & span)
            self.assertLess(address + len(body), modern.VM_END)
            pages.update(span)
        self.assertEqual(len({job["output"] for job in jobs}), 264)
        for index, job in enumerate(jobs):
            self.assertEqual(job["cdm"], jobs[index % 32]["cdm"])
            self.assertEqual(bodies[job["output"]], (bytes(PAGE), True))
            self.assertEqual(struct.unpack_from("<f", job["expected"])[0],
                             2000.25 + (index % 32) * 129 + (index // 32) * 4096)
            self.assertFalse(any(job["expected"][256:]))

    def test_oracle_catches_previous_corruption_and_premature_future_write(self):
        _bodies, jobs = build_reuse_workloads(7, 3)
        bindings = {job["output"]: SimpleNamespace(bo=SimpleNamespace(token={"map":
            bytearray(job["expected"] if job["index"] < 3 else bytes(PAGE))})) for job in jobs}
        self.assertEqual(verify_outputs(jobs, bindings, 3), [])
        bindings[jobs[0]["output"]].bo.token["map"][-1] = 1
        bindings[jobs[5]["output"]].bo.token["map"][0] = 1
        self.assertEqual(verify_outputs(jobs, bindings, 3), [0, 5])

    def test_rejects_caller_timestamp_capacity_and_bad_batch_shapes(self):
        for count, batch in ((0, 1), (1025, 32), (32, 0), (32, 65)):
            with self.assertRaises(ValueError):
                build_reuse_workloads(count, batch)

    def test_764_jobs_keep_independent_outputs_and_bounded_timestamps(self):
        bodies, jobs = build_reuse_workloads(764, 64)
        self.assertEqual(len({job["output"] for job in jobs}), 764)
        self.assertLessEqual((jobs[-1]["index"] + 1) * 16, PAGE)
        self.assertEqual(jobs[-1]["generation"], 11)
        self.assertEqual(bodies[jobs[-1]["output"]], (bytes(PAGE), True))

    def test_indirect_graphs_are_owned_disjoint_and_reuse_changed_dimensions(self):
        bodies, jobs = build_reuse_workloads(128, 64, "indirect")
        pages = set()
        for address, (body, _writable) in bodies.items():
            size = (len(body) + PAGE - 1) & -PAGE
            span = set(range(address, address + size, PAGE))
            self.assertFalse(pages & span)
            pages.update(span)
        for index, job in enumerate(jobs):
            self.assertTrue(job["indirect"])
            self.assertFalse(bodies[job["helper_binding"]][1])
            self.assertTrue(bodies[job["helper_constant"]][1])
            self.assertEqual(job["elements"], 32 if (index % 64 + index // 64) % 2 else 64)
            self.assertFalse(any(job["expected"][job["elements"] * 4:]))
            stream = bodies[job["cdm"]][0]
            self.assertEqual(len(stream), 0x4C)
            self.assertEqual(struct.unpack_from("<I", stream, len(stream) - 4)[0], compute.CDM_TERMINATOR)
            parsed = tuple(uapi.parse_command_buffer(command(cdm_base=job["cdm"],
                cdm_size=job["cdm_size"], attachments=((job["output"], PAGE),))))
            self.assertEqual(parsed[0].payload.cdm_ctrl_stream_end, job["cdm"] + len(stream))
            resource = job_resource(job, completed=True)
            self.assertEqual(struct.unpack_from("<6I", resource, compute.INDIRECT_GEOMETRY_OFFSET),
                             (job["elements"], 1, 1, 32, 1, 1))
            before = job_resource(job)
            start, end = compute.INDIRECT_GEOMETRY_OFFSET, compute.INDIRECT_GEOMETRY_OFFSET + 24
            self.assertFalse(any(before[start:end]))
            self.assertEqual(resource[:start] + resource[end:], before[:start] + before[end:])
        self.assertEqual(jobs[0]["cdm"], jobs[64]["cdm"])
        self.assertNotEqual(jobs[0]["elements"], jobs[64]["elements"])
        self.assertNotEqual(jobs[0]["output"], jobs[64]["output"])

    def test_mixed_dispatch_keeps_both_caller_stream_shapes(self):
        bodies, jobs = build_reuse_workloads(8, 4, "mixed")
        self.assertEqual([job["indirect"] for job in jobs], [False, True] * 4)
        self.assertEqual([job["cdm_size"] for job in jobs], [0x30, 0x4C] * 4)
        for job in jobs:
            self.assertEqual(len(job_resource(job)), 0xC000)
        with self.assertRaises(ValueError):
            build_reuse_workloads(4, 4, "unknown")

    def test_host_timings_preserve_calls_and_errors(self):
        def operation(value, *, increment=0):
            if value < 0:
                raise ValueError("negative")
            return value + increment
        obj = SimpleNamespace(operation=operation)
        timings = track_calls(obj, ("operation",))
        self.assertEqual(obj.operation(2, increment=3), 5)
        with self.assertRaisesRegex(ValueError, "negative"):
            obj.operation(-1)
        self.assertEqual(timings["operation"]["calls"], 2)
        self.assertGreaterEqual(timings["operation"]["seconds"], 0)


if __name__ == "__main__":
    unittest.main()
