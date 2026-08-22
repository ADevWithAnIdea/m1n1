#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the generated second pair-zero render immediately pre-doorbell."""

import os
import pathlib
import struct
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_STEADY_INITIAL_PAIR"] = "1"
os.environ["G17P_NATIVE_SPLIT_LIFECYCLE_PUBLICATION"] = "1"
os.environ["G17P_NATIVE_STATUS_ALIASES"] = "1"

from m1n1.agx.shim import DRMAsahiShim  # noqa: E402


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_snapshot_pair0_reuse.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        import agx_g17p_compute as compute_probe
        from m1n1.agx import g17p, g17p_submission as submission
        from m1n1.agx.g17p_backend import G17PWorkBuilder

        compute_probe.drain_boot_group(front, backend)

        builder = backend.paired_builders[0]
        native_pool_a = 0xFFFFFC20C0820100
        native_pool_a_slots = 0xFFFFFC20015F8000
        backend._ensure_firmware_range(
            native_pool_a & ~(compute_probe.PAGE - 1), compute_probe.PAGE)
        backend._ensure_firmware_range(native_pool_a_slots, compute_probe.PAGE)

        # Construct the complete native post-first Pool-A state.  The opening
        # record has scheduler output beyond the compact host-owned fields; the
        # generated opening produces a different job-list pointer and omits the
        # other three words, so preserving its bytes is not ABI-equivalent.
        pool = bytearray(submission.build_record_array_a(native_pool_a_slots + 4))
        struct.pack_into("<I", pool, 0x0c, 2)
        struct.pack_into("<I", pool, 0x24, 1)
        struct.pack_into("<Q", pool, 0xa0, 0xfffffc2000000000)
        struct.pack_into("<I", pool, 0xa8, 0x010000eb)
        struct.pack_into("<I", pool, 0xb0, 0x010000ea)
        struct.pack_into("<I", pool, 0xc0, 1)
        slots = bytearray(compute_probe.PAGE)
        struct.pack_into("<I", slots, 4, 2)
        backend._write_dva(native_pool_a, pool)
        backend._write_dva(native_pool_a_slots, slots)
        builder.tiling.use_pools(native_pool_a, builder.tiling.array_b)
        builder.fragment.use_pools(native_pool_a, builder.fragment.array_b)
        builder.leaf_pages["pool_a_slots"] = native_pool_a_slots
        reserved = native_pool_a + submission.ARRAY_A_STRIDE
        backend._write_dva(reserved + 0x08, struct.pack("<I", 1))
        backend._write_dva(reserved + 0x10, struct.pack("<I", 0x50))
        backend.forced_scheduler_node = 2
        backend._clean_dva_range(
            native_pool_a & ~(compute_probe.PAGE - 1), compute_probe.PAGE)
        backend._clean_dva_range(native_pool_a_slots, compute_probe.PAGE)
        backend.space.flush()
        backend.u.inst("dsb sy")
        print(
            "PAIR0 REUSE separated Pool-A records/slots at %#x/%#x and "
            "published reserved/selected scheduler nodes 1/2" %
            (native_pool_a, native_pool_a_slots),
            flush=True,
        )

        registered_support = 0xFFFFFC20C0828000
        registered_inner = 0xFFFFFC2001600000
        prior_support = backend._read_dva(
            registered_support, compute_probe.PAGE)
        support = bytearray(compute_probe.PAGE)
        support[:0x64] = prior_support[:0x64]
        struct.pack_into("<Q", support, 0x20, 0x000016A0000000A0)
        struct.pack_into("<Q", support, 0x28, 0x0000160000000000)
        struct.pack_into("<I", support, 0x54, 2)
        inner = bytearray(compute_probe.PAGE)
        struct.pack_into("<I", inner, 0, 2)
        backend._write_dva(registered_support, support)
        backend._write_dva(registered_inner, inner)
        backend._clean_dva_range(registered_support, compute_probe.PAGE)
        backend._clean_dva_range(registered_inner, compute_probe.PAGE)
        backend.space.flush()
        backend.u.inst("dsb sy")
        print(
            "PAIR0 REUSE reconstructed native post-first compact state",
            flush=True,
        )
        pointer_sets = {
            kind: dict(front.g17p_submission_state["%s_optional" % kind])
            for kind in ("tiling", "fragment")
        }
        backend.muxed_queue_pointer_sets[0] = pointer_sets
        for values in pointer_sets.values():
            values["shared_control"] = registered_support
            # Final 26.6 publishes both stages through queue identity 0xac in
            # execution context 1 and names channel-control record zero.  The
            # beta-derived bootstrap used by the generated opening instead
            # leaves this pair on identity 0xa6/context 0/record one.
            values["channel_control"] = backend.CHANNEL_CONTROL_BASE
            values["context_id"] = 1
            values["uuid"] = 0xac

        # Record zero is fresh immediately before native render one, then has
        # this firmware-produced state at both producer boundaries for render
        # two.  Build the measured state field-wise so this test isolates the
        # lifecycle transition without restoring any captured page bytes.
        channel_record = struct.pack(
            "<8Q",
            0x00c8010f00040000,
            0x001b00005dc00000,
            0x0000000000030000,
            0x0000000000000000,
            0x7702000000000000,
            0x0000005657000008,
            0x0000000000000000,
            0x0000000000000000,
        )
        backend._write_dva(backend.CHANNEL_CONTROL_BASE, channel_record)
        backend._clean_dva_range(
            backend.CHANNEL_CONTROL_BASE, backend.CHANNEL_CONTROL_STRIDE)
        backend.u.inst("dsb sy")
        if backend._read_dva(
                backend.CHANNEL_CONTROL_BASE,
                backend.CHANNEL_CONTROL_STRIDE) != channel_record:
            raise RuntimeError("native post-first channel record did not read back")
        print(
            "PAIR0 REUSE constructed native post-first channel-control record 0",
            flush=True,
        )
        G17PWorkBuilder.TAIL_POINTERS = {
            kind: tuple(
                (offset, registered_support, role)
                if offset in (0x0934, 0x21CE)
                else (offset, value, role)
                for offset, value, role in entries
            )
            for kind, entries in G17PWorkBuilder.TAIL_POINTERS.items()
        }
        print(
            "PAIR0 REUSE combines selected slot publication with registered "
            "support %#x" % registered_support,
            flush=True,
        )

        native_job_list = 0xFFFFFC2000000000
        backend._write_dva(
            native_job_list, g17p.build_job_list(native_job_list))
        queue_pair = backend.muxed_queue_pair(0)
        for _kind, (_entry, queue) in queue_pair.items():
            backend._write_dva(
                queue.address + g17p.QUEUE_JOB_LIST_ADDR,
                struct.pack("<Q", native_job_list),
            )
            queue.job_list_addr = native_job_list
            queue.record["job_list_addr"] = native_job_list
            backend._write_dva(
                queue.address + g17p.QUEUE_UUID,
                struct.pack("<I", 0xac),
            )
            backend._write_dva(
                queue.address + g17p.QUEUE_CONTEXT_ADDR,
                struct.pack("<Q", backend.CHANNEL_CONTROL_BASE),
            )
            queue.record["uuid"] = 0xac
            queue.record["context_addr"] = backend.CHANNEL_CONTROL_BASE
            backend._clean_dva_range(
                queue.address & ~(compute_probe.PAGE - 1), compute_probe.PAGE)
        backend._clean_dva_range(native_job_list, compute_probe.PAGE)
        backend.space.flush()
        backend.u.inst("dsb sy")
        print(
            "PAIR0 REUSE moved both queue records and scheduler head to native "
            "job list %#x, context 1/uuid 0xac/channel-control record 0" %
            native_job_list,
            flush=True,
        )

        native_pool_b = 0xFFFFFC20C0830080
        native_packed = 0xFFFFFC20C0860000
        native_zero = 0xFFFFFC20C0832800
        leaves = {
            "primary_index": 0xFFFFFC20C0848000,
            "secondary_index": 0xFFFFFC20C0838000,
            "pool_a_slots": native_pool_a_slots,
            "pool_b_slots": 0xFFFFFC2001618000,
            "shared_slots": 0xFFFFFC2001610000,
            "flag": 0xFFFFFC2001620000,
        }
        native_status = {
            "tiling": 0xFFFFFC2001608000,
            "fragment": 0xFFFFFC2001628000,
        }
        native_pages = {
            native_pool_b & ~(compute_probe.PAGE - 1),
            native_packed & ~(compute_probe.PAGE - 1),
            *(address & ~(compute_probe.PAGE - 1)
              for address in leaves.values()),
            *native_status.values(),
        }
        for address in native_pages:
            backend._ensure_firmware_range(address, compute_probe.PAGE)

        leaf_bodies = submission.build_submission_leaf_pages(
            pair_index=0,
            index_group_ranges=((0x11, 6), (0x4a, 10)),
            shared_count=16,
        )
        primary_index = bytearray(leaf_bodies["primary_index"])
        # Firmware's post-first allocation order, measured at both producer
        # boundaries before native render two.  Only these first 16 entries
        # differ from the host-built pre-first index page.
        post_first_primary = (
            0x1e, 0x20, 0x21, 0x22,
            0x14, 0x13, 0x17, 0x18,
            0x19, 0x1b, 0x12, 0x11,
            0x1c, 0x1d, 0x16, 0x23,
        )
        for index, value in enumerate(post_first_primary):
            struct.pack_into("<I", primary_index, index * 4, value)
        leaf_bodies["primary_index"] = bytes(primary_index)
        shared_slots = bytearray(leaf_bodies["shared_slots"])
        struct.pack_into("<I", shared_slots, 0x40, 0x0b)
        leaf_bodies["shared_slots"] = bytes(shared_slots)
        for name, body in leaf_bodies.items():
            backend._write_dva(leaves[name], body)

        # Record zero belongs to the completed opening.  Native firmware leaves
        # the same retirement cursor in both of its output words before record
        # one is selected for the second render.
        pool_b_body = bytearray(submission.build_record_array_b(
            leaves["pool_b_slots"] + submission.POOL_B_SLOT_OFFSET,
            leaves["shared_slots"] + submission.SHARED_SLOT_OFFSET,
            pair_index=0,
        ))
        struct.pack_into("<I", pool_b_body, 0x10, 0x0b)
        struct.pack_into("<I", pool_b_body, 0x48, 0x0b)
        pool_b_page = bytearray(compute_probe.PAGE)
        pool_b_page[0x80:0x80 + len(pool_b_body)] = pool_b_body
        # The native all-zero shared object immediately follows Pool B in this
        # same page, so constructing the composite page preserves ownership.
        zero_offset = native_zero - (native_pool_b & ~(compute_probe.PAGE - 1))
        pool_b_page[zero_offset:
                    zero_offset + submission.ZERO_SHARED_OBJECT_SIZE] = (
            submission.build_zero_shared_object())
        backend._write_dva(
            native_pool_b & ~(compute_probe.PAGE - 1), pool_b_page)

        packed_body = bytearray(submission.build_shared_object((
            leaves["primary_index"],
            leaves["secondary_index"],
            leaves["shared_slots"],
            leaves["flag"],
        ), pair_index=0, group_count=16))
        for offset in (0x00, 0x04, 0x08, 0x14):
            struct.pack_into("<I", packed_body, offset, 1)
        packed_page = bytearray(compute_probe.PAGE)
        packed_page[:len(packed_body)] = packed_body
        backend._write_dva(native_packed, packed_page)

        builder.tiling.use_pools(native_pool_a, native_pool_b)
        builder.fragment.use_pools(native_pool_a, native_pool_b)
        builder.leaf_pages = dict(leaves)
        builder.shared = (native_packed, native_zero)

        status_bases = {
            kind: list(addresses)
            for kind, addresses in G17PWorkBuilder.PAIR_STATUS_BASES.items()
        }
        for kind, address in native_status.items():
            status_bases[kind][0] = address
            backend._write_dva(address, bytes(compute_probe.PAGE))
        G17PWorkBuilder.PAIR_STATUS_BASES = {
            kind: tuple(addresses)
            for kind, addresses in status_bases.items()
        }
        backend._map_pair_status_aliases(0)

        for address in native_pages:
            backend._clean_dva_range(address, compute_probe.PAGE)
        backend.space.flush()
        backend.u.inst("dsb sy")
        print(
            "PAIR0 REUSE published complete native final-26.6 graph topology: "
            "Pool-B/zero composite, packed object, six leaves, and status aliases",
            flush=True,
        )
        workload = compute_probe.create_render_cadence_workload(front)

        def snapshot(active_backend, pair):
            compute_probe.snapshot_generated_render_slot(
                active_backend, 1, pair)

        backend.pre_notify_hook = snapshot
        compute_probe.run_render_cadence_submission(
            front, backend, workload, "pair-zero reuse render 2")
        print("PAIR0 REUSE physically executed", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
