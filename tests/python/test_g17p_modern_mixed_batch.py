# SPDX-License-Identifier: MIT
"""A mixed batch must express real dependencies without caller rebinding."""
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).parents[2] / "proxyclient"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))
os.environ.setdefault("AGX_GPU", "G17")

import agx_g17p_modern_mixed_batch as batch
from m1n1.agx import g17p_compute
from m1n1.agx.shim import _G17PModernHardwareAdapter


class MixedBatchTests(unittest.TestCase):
    def test_native_dependency_wave_uses_explicit_scheduler_records(self):
        adapter = object.__new__(_G17PModernHardwareAdapter)
        actions = []
        notifications = []
        control_done = []
        ticks = []
        control_bodies = []
        registrations = []
        writes = []
        atomic_releases = []
        atomic_work_releases = []
        dependency_releases = []
        root_switches = []
        topology = {
            "job_list": 0x6000,
            "first": {
                "queue": 0x1000, "pointers": 0x1100,
                "item_ring": 0x1200, "job_list": 0x6000,
                "queue_context": 0x7000, "channel_control": 0x7000,
                "context_low": 0x8000, "context_high": 0x9000,
                "grid": 0,
            },
        }
        topology["final"] = {
            "queue": 0x2000, "pointers": 0x2100,
            "item_ring": 0x2200, "job_list": 0x6030,
            "queue_context": 0x7080, "channel_control": 0x7080,
            "context_low": 0xa000, "context_high": 0xb000,
            "grid": 3,
        }
        backend = types.SimpleNamespace(
            submitter=types.SimpleNamespace(
                deferred_producers=None,
                notify=lambda channel: (
                    notifications.append(channel),
                    actions.append(("work", channel)))),
            control_done=lambda: (
                control_done.append(True), actions.append(("control", None))),
            announce_control_with_outer_producers=lambda producers, channel,
                    notify_work=True: (
                atomic_releases.append((tuple(producers), channel)),
                actions.append(("atomic-control-work", channel))),
            release_dependency_window=lambda *args, **_kwargs: (
                dependency_releases.append(args),
                actions.append(("dependency-window", (args[3], args[4])))),
            publish_outer_with_work=lambda producer, channel: (
                atomic_work_releases.append((producer, channel)),
                actions.append(("atomic-control-work", channel))),
            group_number=0,
            native_shared_inner_sequence=True,
            runtime_current_job_records=True,
            native_dependency_queue_context=False,
            runtime_submission_announced=set(),
            _write_dva=lambda address, body: writes.append((address, body)),
            _ensure_firmware_range=lambda _address, _size: None,
            _read_dva=lambda address, size: (
                struct.pack("<I", 2) + bytes(size - 4)
                if address == 0xfffffc2001620000 else
                struct.pack("<Q", 0x9100) + bytes(size - 8)),
            _clean_dva_range=lambda _address, _size: None,
            _switch_registered_context_root=lambda space:
                root_switches.append(space),
            pair_queue_completed=lambda _submission: True,
            channels=types.SimpleNamespace(
                entries=[None] * 12 + [object()],
                counters=lambda _entry: (99, 99, 99)),
            event_pump=None,
            paired_builder_for=lambda _pair: types.SimpleNamespace(
                tiling=types.SimpleNamespace(array_a=0x9000)),
            space=types.SimpleNamespace(flush=lambda: None),
            u=types.SimpleNamespace(inst=lambda _instruction: None))
        adapter.front = types.SimpleNamespace(
            g17p=backend,
            g17p_runtime={
                "stage_runtime_tick": lambda *args, **kwargs:
                (ticks.append((args, kwargs)) or {"target": 2}),
                "stage_control_body": lambda *args, **kwargs:
                (control_bodies.append((args, kwargs)) or {"target": 2}),
                "register_compute_control": lambda *args, **kwargs:
                (registrations.append((args, kwargs)) or {
                    "sequence": 1,
                    "0x20": {
                        "after": [1, 1, 2], "target": 3,
                        "deferred_producer": (0x7600, struct.pack("<I", 3)),
                    }}),
            })
        adapter._prepare_render_after_compute = lambda: None
        adapter._prepare_dependency_queue_topology = lambda: topology
        adapter._prepare_dependency_render_graph = lambda: None
        adapter._freshen_dependency_scheduler_pages = lambda: None
        adapter._ensure_dependency_compute_state = (
            lambda _vm, _runtime, _commands: None)
        dependency_space = object()
        adapter.compute_runtime = {
            "native": types.SimpleNamespace(),
            "dependency_execution_space": dependency_space,
        }
        adapter.device_lost = False
        publications = []
        completions = []
        render_overrides = []
        render_scheduler_nodes = []
        compute_type = batch.uapi.DRM_ASAHI_CMD_COMPUTE
        render_type = batch.uapi.DRM_ASAHI_CMD_RENDER
        commands = [
            types.SimpleNamespace(header=types.SimpleNamespace(cmd_type=kind),
                                  index=index)
            for index, kind in enumerate((compute_type, render_type, compute_type))
        ]

        def submit_compute(_queue, command, **options):
            publications.append(("compute", command.index, options))
            return {"fence": types.SimpleNamespace(error=None),
                    "command": command,
                    "deferred_producer": (0x7100, struct.pack(
                        "<I", command.index + 1)),
                    "deferred_queue_producer": (0x7200, struct.pack(
                        "<I", command.index + 3)),
                    "deferred_queue_context": (0x7300, struct.pack(
                        "<I", command.index + 5))}

        def submit_render(_queue, command, **options):
            publications.append(("render", command.index, options))
            render_scheduler_nodes.append(backend.forced_scheduler_node)
            render_overrides.append({
                kind: dict(values)
                for kind, values in backend.render_control_overrides.items()
            })
            return {"fence": types.SimpleNamespace(error=None),
                    "command": command,
                    "submission": {
                        "doorbell_channel": 8,
                        "deferred_outer_producers": (
                            (0x7400, struct.pack("<I", 1)),
                            (0x7500, struct.pack("<I", 1))),
                    }}

        adapter._submit_compute = submit_compute
        adapter._submit_render = submit_render
        adapter._finish_compute = lambda work, **_options: (
            completions.append(work["command"].index) or work["fence"])
        adapter._finish_render = lambda work: (
            completions.append(work["command"].index) or work["fence"])
        adapter._pull_render_writable_bindings = lambda _vm: None
        adapter._merge_dependency_render_references = lambda _vm, _runtime: None
        queue = types.SimpleNamespace(vm=object())

        fences = adapter._submit_dependency_wave(queue, commands)

        self.assertEqual(root_switches, [dependency_space])
        self.assertEqual([entry[:2] for entry in publications],
                         [("compute", 0), ("render", 1), ("compute", 2)])
        self.assertNotIn(0x87, notifications)
        first_options = publications[0][2]
        final_options = publications[2][2]
        self.assertEqual(first_options["submit_sequence"], 0)
        self.assertTrue(publications[0][2]["dependency_fresh_queue"])
        self.assertFalse(publications[0][2]["notify"])
        self.assertTrue(first_options["defer_outer_producer"])
        self.assertEqual(first_options["scheduler_record"],
                         0xfffffc20c0820100)
        self.assertTrue(first_options["preserve_scheduler_record"])
        self.assertEqual(first_options["transport_override"], topology["first"])
        self.assertEqual(first_options["event_counter"], 0x102)
        self.assertEqual(first_options["descriptor_context_id"], 1)
        self.assertEqual(first_options["scheduler_context_word"], 0x100)
        self.assertEqual(first_options["logical_grid_index"], 0)
        self.assertEqual(first_options["queue_context_points"], ((0, 0),))
        self.assertEqual(first_options["queue_context_completion_value"], 1)
        self.assertEqual(first_options["descriptor_ordinal"], 0)
        self.assertEqual(first_options["queue_uuid"], 0x16)
        self.assertEqual(first_options["outer_grid_index"], 0)
        self.assertEqual(first_options["descriptor_address"],
                         0xfffffc20c0358000)
        self.assertEqual(first_options["descriptor_low_address"],
                         0x7000340000)
        self.assertEqual(first_options["descriptor_completion_record"],
                         0xfffffc2001618000)
        native_compute_support = bytes.fromhex(
            "01000000000000000000000000000000"
            "02000000000000007000000000000400"
            "00000000001500000000000000150000"
            "00802000700000000000000000000000"
            "0400000000000000a800000000006101"
            "20fcffff000000000000000001000000"
            "02000000" + "00" * (0x4000 - 100))
        self.assertEqual(len(native_compute_support), 0x4000)
        self.assertIn(
            (0xfffffc20c0838000, native_compute_support), writes)
        self.assertIn(
            (0xfffffc2001610000,
             b"\x01\x00\x00\x00" + bytes(0x4000 - 4)), writes)
        self.assertIn(
            (0x7000208000, g17p_compute.build_compute_operand_table(
                0x7000238000,
                entries=g17p_compute.COMPUTE_OPERAND_TABLE_ENTRIES)),
            writes)
        self.assertIn(
            (0xfffffc2001618000, bytes(0x40)),
            writes)
        self.assertIn((0xfffffc20c07d0000, bytes(0x100)), writes)
        self.assertIn((0xfffffc20c07f8000, bytes(0x100)), writes)
        for base in (0xfffffc20c07d0000, 0xfffffc20c07f8000):
            self.assertEqual([(address, body) for address, body in writes
                              if base <= address < base + 0x100],
                             [(base, bytes(0x100))])
        fresh_channel = bytearray(0x40)
        struct.pack_into("<Q", fresh_channel, 0x00,
                         0x000001000000ffff)
        struct.pack_into("<Q", fresh_channel, 0x20,
                         0x0002000000000000)
        struct.pack_into("<Q", fresh_channel, 0x30,
                         0x00000000ff000000)
        self.assertIn(
            (0xfffffc20c07b8000, bytes(fresh_channel)), writes)
        self.assertEqual(
            writes.count((0xfffffc20c07b8000, bytes(fresh_channel))), 2)
        self.assertEqual(first_options["completion_status_addresses"],
                         (0xfffffc2000024c68, 0xfffffc2000024c70))
        self.assertEqual(first_options["queue_context_overrides"], {
            "flags_200": 0x1000000000000004,
            "word_220": 0xffff080000000001,
            "word_338": 2,
        })
        self.assertFalse(first_options["omit_optional"])
        self.assertEqual(publications[1][2]["submit_sequences"],
                         {"fragment": 0, "tiling": 1})
        self.assertEqual(publications[1][2]["firmware_timestamp_pair"],
                         (0xfffffc2000024c78, 0xfffffc2000024c80))
        self.assertEqual(render_overrides, [{
            "tiling": {
                0x0a5a1: 0xa900400020,
                0x1ca30: 0x180020,
                0x16c39: 0x180020,
                0x1c910: 0x88005,
                0x1ca10: 0xc701000114,
                0x014a1: 0xc701000114,
                0x0a349: 0xc701000114,
                0x10209: 0x101,
                0x1c9f0: 0x101,
                0x14320: 0x101,
                0x14308: 1,
                0x14318: 0x1000080001,
            },
            "fragment": {
                0x0a5a9: 0xd900400020,
                0x1ca28: 0x180020,
                0x160e0: 0xc701000113,
                0x01499: 0xc701000113,
                0x0a341: 0xc701000113,
                0x10211: 0x101,
                0x10420: 0x101,
                0x14048: 1,
                0x14080: 0x10001a8001,
            },
        }])
        self.assertEqual(render_scheduler_nodes, [1])
        self.assertNotIn("queue_grid_pair", publications[1][2])
        self.assertFalse(publications[1][2]["notify"])
        self.assertEqual(final_options["submit_sequence"], 0)
        self.assertTrue(publications[2][2]["dependency_fresh_queue"])
        self.assertFalse(
            publications[2][2]["dependency_persistent_startup_queue"])
        self.assertFalse(publications[2][2]["notify"])
        self.assertTrue(final_options["defer_outer_producer"])
        self.assertTrue(final_options["defer_inner_producer"])
        self.assertTrue(final_options["defer_queue_context"])
        self.assertEqual(final_options["scheduler_record"],
                         0xfffffc20c0830100)
        self.assertEqual(final_options["transport_override"], topology["final"])
        self.assertNotEqual(final_options["transport_override"], topology["first"])
        self.assertEqual(final_options["event_counter"], 0x102)
        self.assertEqual(final_options["descriptor_context_id"], 1)
        self.assertEqual(final_options["scheduler_context_word"], 0x102)
        self.assertEqual(final_options["logical_grid_index"], 3)
        self.assertEqual(final_options["queue_context_points"], ((2, 1), (3, 0)))
        self.assertEqual(final_options["queue_context_completion_value"], 1)
        self.assertEqual(final_options["outer_grid_index"], 3)
        self.assertEqual(final_options["queue_uuid"], 0x16)
        self.assertEqual(final_options["descriptor_ordinal"], 0)
        self.assertEqual(final_options["descriptor_address"],
                         0xfffffc20c0359040)
        self.assertEqual(final_options["descriptor_low_address"],
                         0x7000341040)
        self.assertEqual(final_options["descriptor_completion_record"],
                         0xfffffc2001650000)
        self.assertEqual(final_options["dispatch_addresses"],
                         (0xfffffc20001c800c, 0xfffffc20c07c000c))
        self.assertEqual(final_options["completion_status_addresses"],
                         (0xfffffc2000024c88, 0xfffffc2000024c90))
        self.assertEqual(final_options["queue_context_overrides"], {
            "flags_200": 0x10000c0000000004,
            "word_220": 0xffff080200000001,
            "word_338": 2,
        })
        self.assertIn((0xfffffc2001650000, bytes(0x40)), writes)
        self.assertIn((0xfffffc20015f8004, struct.pack("<I", 1)), writes)
        self.assertIn((0xfffffc2001600004, struct.pack("<I", 2)), writes)
        self.assertIn((0xfffffc2001608004, struct.pack("<I", 1)), writes)
        for address, slot, wait_value in (
                (0xfffffc20c0820100, 0xfffffc20015f8004, 0),
                (0xfffffc20c0828100, 0xfffffc2001600004, 1),
                (0xfffffc20c0830100, 0xfffffc2001608004, 2)):
            scheduler_writes = [
                body for write_address, body in writes
                if write_address == address and len(body) == 0x100]
            seed = g17p_compute.build_compute_scheduler_record(
                slot, work_id=wait_value)
            self.assertEqual(scheduler_writes, [seed, seed])
        for address, value in (
                (0xfffffc20015f8004, 1),
                (0xfffffc2001600004, 2),
                (0xfffffc2001608004, 1)):
            scheduler_writes = [
                struct.unpack("<I", body)[0]
                for write_address, body in writes
                if write_address == address]
            self.assertEqual(scheduler_writes, [value, value])
        self.assertIsNone(final_options["descriptor_status_a"])
        self.assertFalse(final_options["omit_optional"])
        self.assertEqual(final_options["optional_address"],
                         0xfffffc20c0600240)
        self.assertEqual(final_options["optional_owner"]["submission_ordinal"],
                         2)
        self.assertEqual(final_options["optional_owner"]["context_low"],
                         topology["final"]["context_low"])
        self.assertEqual(final_options["optional_owner"]["context_high"],
                         topology["final"]["context_high"])
        self.assertTrue(final_options["optional_owner"]["first_submit"])
        self.assertEqual(final_options["optional_owner"]["field_56"], 2)
        self.assertEqual(notifications, [])
        self.assertEqual(actions, [
            ("dependency-window", (0x0a, 8)),
            ("atomic-control-work", 0x0a),
            ("control", None),
            ("control", None),
            ("control", None),
            ("control", None),
        ])
        self.assertEqual(atomic_releases, [])
        self.assertEqual(len(dependency_releases), 1)
        self.assertEqual(dependency_releases[0][0],
                         (0x7100, struct.pack("<I", 1)))
        self.assertEqual(dependency_releases[0][1],
                         (0x7600, struct.pack("<I", 3)))
        self.assertEqual(dependency_releases[0][2], (
            (0x7400, struct.pack("<I", 1)),
            (0x7500, struct.pack("<I", 1))))
        self.assertTrue(dependency_releases[0][5])
        self.assertEqual(atomic_work_releases, [(
            (0x7100, struct.pack("<I", 3)), 0x0a)])
        self.assertFalse(any(
            address == 0xfffffc20c07d0000 and len(body) == 0xc0
            for address, body in writes))
        self.assertEqual(control_done, [True] * 4)
        self.assertEqual([entry[0][0] for entry in ticks], [0, 1, 2])
        self.assertEqual([entry[1]["context_word"] for entry in ticks],
                         [0, 1, 0])
        self.assertTrue(all(entry[1]["update_sequence"] for entry in ticks))
        self.assertEqual(len(control_bodies), 3)
        for entry, identity, address in zip(
                control_bodies,
                (0x04020002, 0x04010002, 0x04000002),
                (0xfffffc20c07b8080, 0xfffffc20c07b8040,
                 0xfffffc20c07b8000)):
            owner = entry[0][0]
            self.assertEqual(struct.unpack_from("<I", owner, 0)[0], 0x14)
            self.assertEqual(struct.unpack_from("<I", owner, 8)[0], identity)
            self.assertEqual(struct.unpack_from("<Q", owner, 0x0c)[0],
                             address)
        self.assertEqual(registrations, [(
            (1, 0xfffffc20c0840000, 0x70019e8000),
            {"slot_offset": 0x580, "context_word": 1, "count": 0x28,
             "require_consumed": False, "defer_tick": True,
             "announce": False, "defer_producer": True},
        )])
        self.assertEqual(backend.runtime_submission_announced, set())
        self.assertTrue(backend.native_shared_inner_sequence)
        self.assertTrue(backend.runtime_current_job_records)
        self.assertFalse(backend.native_dependency_queue_context)
        self.assertEqual(backend.native_scheduler_publication_base, 0)
        self.assertEqual(completions, [2, 1, 0])
        self.assertEqual(len(fences), 3)

    @unittest.skipUnless(batch.partial.CONSTANT_PAYLOAD.exists(), "local own compiler payload absent")
    def test_caller_stages_real_viewport_and_texture_dependencies(self):
        with tempfile.TemporaryFile() as memfd:
            caller = batch.graphics.GraphicsCaller(memfd, "store")
            streams, before, expected, timestamps, writes = batch.stage(caller, pressure=False)
            commands = batch.uapi.parse_command_buffer(b"".join(streams))
            self.assertEqual([c.header.cmd_type for c in commands], [1, 0, 1])
            self.assertEqual(commands[1].header.cdm_barrier, 1)
            self.assertEqual(commands[2].header.vdm_barrier, 1)
            self.assertFalse(caller.front.initialized)
            self.assertEqual(len(timestamps), 3)
            viewport = batch.partial.VIEWPORT
            self.assertTrue(caller.bindings[viewport].flags & batch.uapi.DRM_ASAHI_BIND_WRITE)
            self.assertEqual(struct.unpack_from("<f", before[viewport], 0x910)[0], 64)
            self.assertEqual(struct.unpack_from("<f", expected[viewport], 0x910)[0], 66)
            _, jobs = batch.build_workloads(2, first_graph=8)
            first_args = caller.bindings[jobs[0]["resource"]].bo.token["map"]
            second_args = caller.bindings[jobs[1]["resource"]].bo.token["map"]
            self.assertEqual(struct.unpack_from("<Q", first_args, 0x14b0)[0], viewport + 0x910)
            self.assertEqual(struct.unpack_from("<Q", second_args, 0x14a0)[0],
                             batch.partial.OUTPUTS[0] + 0x7f00)
            self.assertEqual(struct.unpack_from("<4f", expected[jobs[1]["output"]]),
                             (.5, .625, .625, .5))
            self.assertTrue(all(not any(body) for address, body in before.items()
                                if address != viewport))
            spans = sorted((binding.addr, binding.end) for binding in caller.vm.bindings)
            self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))

    def test_attachment_packets_never_receive_barriers(self):
        stream = batch.compute_command(7)
        changed = batch.barriers(stream, render=0, compute=0)
        header = batch.uapi.drm_asahi_cmd_header.from_bytes(changed[:8])
        self.assertEqual(header.vdm_barrier, batch.uapi.DRM_ASAHI_BARRIER_NONE)
        self.assertEqual(header.cdm_barrier, batch.uapi.DRM_ASAHI_BARRIER_NONE)
        command, = batch.uapi.parse_command_buffer(changed)
        self.assertEqual((command.header.vdm_barrier, command.header.cdm_barrier), (0, 0))

    @unittest.skipUnless(batch.partial.CONSTANT_PAYLOAD.exists(), "local own compiler payload absent")
    def test_full_cdm_tail_control_only_adds_caller_barriers(self):
        images = []
        for enabled in (False, True):
            with tempfile.TemporaryFile() as memfd:
                caller = batch.graphics.GraphicsCaller(memfd, "store")
                batch.stage(caller, pressure=False, full_cdm_tail=enabled)
                _, jobs = batch.build_workloads(2, first_graph=8)
                images.append([bytes(caller.bindings[job["cdm"]].bo.token["map"])
                               for job in jobs])
                self.assertFalse(caller.front.initialized)
        for original, changed in zip(*images):
            self.assertEqual(changed[:44], original[:44])
            self.assertEqual(struct.unpack_from("<III", changed, 40),
                             (0x60000160, 0x600fffff, 0x40000000))
            self.assertEqual(original[48:], bytes(len(original) - 48))
            self.assertEqual(changed[52:], bytes(len(changed) - 52))

    def test_compute_code_relocation_is_bounded_and_guarded(self):
        from agx_g17p_native_add3 import NATIVE_ADD3_SHADER
        original = NATIVE_ADD3_SHADER + bytes(batch.PAGE - len(NATIVE_ADD3_SHADER))
        moved = batch.relocate_compute_launch(original)
        marker = bytes.fromhex("7701aa07000000020400")
        offset = original.index(marker) + 3
        self.assertEqual(struct.unpack_from("<I", moved, offset)[0], 0x207)
        self.assertEqual(moved[:offset], original[:offset])
        self.assertEqual(moved[offset + 4:], original[offset + 4:])
        for bad in (bytes(batch.PAGE), original + marker, moved):
            with self.assertRaises(ValueError):
                batch.relocate_compute_launch(bad)

    @unittest.skipUnless(batch.partial.CONSTANT_PAYLOAD.exists(), "local own compiler payload absent")
    def test_default_partial_has_independent_resources_and_all_dependencies(self):
        with tempfile.TemporaryFile() as memfd:
            caller = batch.graphics.GraphicsCaller(memfd, "store")
            streams, before, expected, timestamps, writes = batch.stage(caller)
            commands = batch.uapi.parse_command_buffer(b"".join(streams))
            self.assertEqual([c.header.cmd_type for c in commands], [1, 0, 1, 0])
            last = commands[-1]
            self.assertEqual((last.header.vdm_barrier, last.header.cdm_barrier), (1, 2))
            self.assertEqual(len(before), 22)
            self.assertEqual(len(timestamps), 4)
            self.assertEqual([len(group) for group in writes], [1, 10, 1, 10])
            self.assertEqual(last.payload.vdm_ctrl_stream_base, batch.partial.ENCODER + 0x8000000)
            self.assertEqual(last.payload.depth.base, batch.graphics.DEPTH + batch.PARTIAL_SHIFT)
            self.assertEqual(last.payload.stencil.base, batch.graphics.STENCIL + batch.PARTIAL_SHIFT)
            resource = bytes(caller.bindings[batch.partial.RESOURCE + batch.RESOURCE_SHIFT].bo.token["map"])
            for offset in batch.RESOURCE_POINTER_OFFSETS:
                old = struct.unpack_from("<Q", caller.resource, offset)[0]
                self.assertEqual(struct.unpack_from("<Q", resource, offset)[0],
                                 old + batch.RESOURCE_SHIFT)
            for group in (0x20, 0x320, 0x620):
                for index, address in enumerate(batch.partial.OUTPUTS):
                    lo, hi = struct.unpack_from("<II", resource, group + index * 0x20 + 8)
                    self.assertEqual(((hi & 0xfff) << 32 | lo) << 4, address + batch.PARTIAL_SHIFT)
            pipeline = caller.bindings[batch.partial.USC_BASE + 0x1e8000 + batch.PARTIAL_SHIFT].bo.token["map"]
            for offset in (0, 0x240, 0x480):
                self.assertEqual(struct.unpack_from("<H", pipeline, offset + 6)[0], 0x4e4)
            spans = sorted((binding.addr, binding.end) for binding in caller.vm.bindings)
            self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
            self.assertFalse(caller.front.initialized)
            for address in writes[-1]:
                self.assertFalse(any(before[address]))
                self.assertTrue(any(expected[address]))

    @unittest.skipUnless(batch.partial.CONSTANT_PAYLOAD.exists(), "local own compiler payload absent")
    def test_changed_viewport_and_partial_reload_have_distinct_full_oracles(self):
        results = []
        for x, reload_clear in ((66, False), (68, False), (66, True)):
            with tempfile.TemporaryFile() as memfd:
                caller = batch.graphics.GraphicsCaller(memfd, "store")
                results.append(batch.stage(caller, viewport_x=x, reload_clear=reload_clear))
        normal, shifted, cleared = [result[2] for result in results]
        _, jobs = batch.build_workloads(2, first_graph=8)
        self.assertEqual(struct.unpack_from("<6f", shifted[jobs[1]["output"]]),
                         (.5, .5, .5, .625, .625, .5))
        for index, address in enumerate(batch.partial.OUTPUTS):
            self.assertNotEqual(normal[address], shifted[address])
            self.assertEqual(normal[address], cleared[address])
            changed = bytearray(batch.SIZE)
            for pixel in (0x7f04, 0x7f08):
                struct.pack_into("<f", changed, pixel, 33255 * (index + 1) / 8)
            self.assertEqual(cleared[address + batch.PARTIAL_SHIFT], bytes(changed))
            self.assertNotEqual(normal[address + batch.PARTIAL_SHIFT], bytes(changed))

    def test_unqualified_oracle_combinations_fail_before_binding(self):
        for options in (dict(viewport_x=67), dict(pressure=False, reload_clear=True),
                        dict(viewport_x=68, reload_clear=True)):
            with self.assertRaises(ValueError):
                batch.stage(None, **options)

    def test_timestamps_require_all_intervals_and_zero_guard_bytes(self):
        for index, stamps in ((0, (10, 20)), (1, (10, 20, 15, 30)),
                              (2, (10, 20)), (3, (10, 20, 15, 30))):
            body = struct.pack("<%dQ" % len(stamps), *stamps)
            body += bytes(batch.PAGE - len(body))
            self.assertEqual(batch.timestamp_values(body, index), (stamps, True))
            self.assertFalse(batch.timestamp_values(body[:-1] + b"\x01", index)[1])
            self.assertFalse(batch.timestamp_values(bytes(batch.PAGE), index)[1])
            changed = bytearray(body)
            struct.pack_into("<Q", changed, 8, 10)
            self.assertFalse(batch.timestamp_values(changed, index)[1])


if __name__ == "__main__":
    unittest.main()
