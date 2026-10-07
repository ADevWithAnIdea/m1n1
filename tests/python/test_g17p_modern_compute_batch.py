# SPDX-License-Identifier: MIT
"""Host checks for the real caller batch fixture; no proxy connection."""

import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
os.environ.setdefault("AGX_GPU", "G17")

from agx_g17p_modern_compute_batch import build_workloads, command, PAGE, modern, uapi


class ModernComputeBatchTests(unittest.TestCase):
    def test_64_real_commands_have_independent_caller_ranges_and_oracles(self):
        bodies, jobs = build_workloads(64)
        occupied = set()
        for address, (body, _writable) in bodies.items():
            size = (len(body) + PAGE - 1) & -PAGE
            pages = set(range(address, address + size, PAGE))
            self.assertFalse(occupied & pages)
            self.assertLess(address + size, modern.VM_END)
            occupied.update(pages)
        stream = b"".join(command(
            1, attachments=((job["output"], PAGE),),
            cdm_base=job["cdm"], timestamp_offset=index * 16)
            for index, job in enumerate(jobs))
        parsed = tuple(uapi.parse_command_buffer(stream))
        self.assertEqual(len(parsed), 64)
        self.assertEqual(len({job["output"] for job in jobs}), 64)
        for index, (job, parsed_command) in enumerate(zip(jobs, parsed)):
            self.assertEqual(bodies[job["output"]], (bytes(PAGE), True))
            self.assertEqual(len(job["expected"]), PAGE)
            self.assertEqual(struct.unpack_from("<f", job["expected"])[0],
                             2000.25 + index * 129)
            self.assertFalse(any(job["expected"][256:]))
            self.assertEqual(parsed_command.payload.cdm_ctrl_stream_base, job["cdm"])
            self.assertEqual(parsed_command.payload.ts.end.offset, index * 16 + 8)

    def test_fixture_rejects_unbounded_batches(self):
        for count in (0, 65):
            with self.assertRaises(ValueError):
                build_workloads(count)

    def test_boundary_graph_can_be_tested_without_scheduler_wrap(self):
        all_bodies, all_jobs = build_workloads(64, shader_start=0x1000000)
        bodies, jobs = build_workloads(4, first_graph=34, shader_start=0x1000000)
        self.assertEqual(jobs, all_jobs[34:38])
        for address, body in bodies.items():
            self.assertEqual(body, all_bodies[address])
        for first_graph in (-1, 61):
            with self.assertRaises(ValueError):
                build_workloads(4, first_graph)

    def test_64_graphs_fit_below_qualified_program_relocation_boundary(self):
        bodies, jobs = build_workloads(64, shader_start=0x200000)
        for job in jobs:
            self.assertLess(job["resource"] + len(bodies[job["resource"]][0]),
                            0x10002000000)
        for start in (-PAGE, PAGE + 1):
            with self.assertRaises(ValueError):
                build_workloads(1, shader_start=start)


if __name__ == "__main__":
    unittest.main()
