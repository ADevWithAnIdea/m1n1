#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove rejected and fatal G17P work attribution with no required options."""

import os
import sys
import tempfile

from agx_g17p_render_uapi_fields import (
    FD,
    OUTPUT_DVA,
    PAGE_SIZE,
    expected_output,
    render_command,
)
from m1n1.agx.g17p_sync import G17PWorkError
from m1n1.agx.g17p_uapi import (
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_WRITE,
    drm_asahi_gem_bind_op,
)
from m1n1.agx.shim import DRMAsahiShim


CONTROL_HANDLE = 0x61
FATAL_HANDLE = 0x62
FATAL_DVA = OUTPUT_DVA + PAGE_SIZE
USC_EXEC_BASE = 0x10000000000


def physical_page(front, bo):
    pa = front.modern.adapter._bo_pa(bo)
    front.g17p.u.proxy.dc_civac(pa, PAGE_SIZE)
    return pa, bytes(front.g17p.u.iface.readmem(pa, PAGE_SIZE))


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_fault_termination.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), 2 * PAGE_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        from agx_g17p_compute import drain_boot_group

        drain_boot_group(front, backend)
        driver = front.modern
        vm = driver.create_vm(FD, 0x7000000000, 0x7800000000)
        control_bo = driver.create_bo(FD, CONTROL_HANDLE, 0, PAGE_SIZE)
        fatal_bo = driver.create_bo(
            FD, FATAL_HANDLE, PAGE_SIZE, PAGE_SIZE)
        rw = DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE
        for bo, address in (
                (control_bo, OUTPUT_DVA), (fatal_bo, FATAL_DVA)):
            driver.bind(FD, vm.vm_id, drm_asahi_gem_bind_op(
                rw, bo.handle, 0, PAGE_SIZE, address))
        control_queue = driver.create_queue(
            FD, vm.vm_id, 0, USC_EXEC_BASE)
        fatal_queue = driver.create_queue(
            FD, vm.vm_id, 1, USC_EXEC_BASE)

        # A completed command is the control for the later device-wide fatal
        # notification.  It must remain successful after pending work fails.
        control_bo.token["map"][:] = bytes(PAGE_SIZE)
        control_fence, _ = driver.submit(
            FD, control_queue.queue_id,
            render_command(0, output_dva=OUTPUT_DVA))
        if (control_fence.error is not None
                or bytes(control_bo.token["map"][:PAGE_SIZE])
                != expected_output()):
            raise RuntimeError("fatal-test control render was not exact")

        # A stale caller mapping is rejected synchronously.  It gets an exact
        # ownership record and no output fence or firmware publication.
        group_before = backend.group_number
        try:
            driver.submit(
                FD, fatal_queue.queue_id,
                render_command(0, output_dva=FATAL_DVA + PAGE_SIZE))
        except ValueError as exc:
            rejected_error = str(exc)
        else:
            raise RuntimeError("unmapped fatal-test command was accepted")
        rejection = driver.rejections[-1].snapshot()
        if (rejection["state"] != "rejected"
                or rejection["fence"] is not None
                or rejection["metadata"]["vm_id"] != vm.vm_id
                or rejection["metadata"]["queue_id"] != fatal_queue.queue_id
                or rejection["metadata"]["command_index"] is None
                or backend.group_number != group_before):
            raise RuntimeError(
                "rejection attribution/publication mismatch: %r" % rejection)

        # Publish one real render producer but deliberately suppress only its
        # work doorbell.  The fence is therefore known-pending when RTKit's
        # documented crash request is sent through endpoint 1.
        fatal_bo.token["map"][:] = bytes(PAGE_SIZE)
        original_notify = backend.submitter.notify
        original_pump = backend.event_pump
        crash_endpoint = front.g17p_asc.epmap[1]
        crash_requested = []

        def suppress_work_doorbell(_channel):
            return None

        def crash_pump():
            if not crash_requested:
                crash_requested.append(True)
                crash_endpoint.crash_hard()
            original_pump()

        backend.submitter.notify = suppress_work_doorbell
        backend.event_pump = crash_pump
        try:
            fatal_fence, _ = driver.submit(
                FD, fatal_queue.queue_id,
                render_command(0, output_dva=FATAL_DVA))
        finally:
            backend.submitter.notify = original_notify
            backend.event_pump = original_pump

        fatal_pa, fatal_output = physical_page(front, fatal_bo)
        fatal_snapshot = fatal_fence.snapshot()
        command_fence = fatal_fence.fences[0]
        command_snapshot = command_fence.snapshot()
        fatal_indices = fatal_snapshot["metadata"]["command_indices"]
        if (len(fatal_indices) != 1
                or fatal_indices[0]
                != rejection["metadata"]["command_index"]):
            raise RuntimeError(
                "equivalent render buffers used different command IDs: %r / %r" % (
                    fatal_indices, rejection))
        fatal_command_index = fatal_indices[0]
        notification = front.modern.adapter.fatal_notification
        if notification is None:
            raise RuntimeError("RTKit crash notification was not routed")
        if (fatal_output != bytes(PAGE_SIZE)
                or fatal_snapshot["state"] != "failed"
                or fatal_snapshot["error"] != G17PWorkError.DEVICE_LOST
                or fatal_snapshot["terminal_reason"] != "device-lost"):
            raise RuntimeError(
                "fatal fence/output mismatch: %#x %r" % (
                    fatal_pa, fatal_snapshot))
        for snapshot in (fatal_snapshot, command_snapshot):
            metadata = snapshot["metadata"]
            if (metadata["vm_id"] != vm.vm_id
                    or metadata["queue_id"] != fatal_queue.queue_id):
                raise RuntimeError(
                    "fatal attribution mismatch: %r" % snapshot)
        if command_snapshot["metadata"]["command_index"] != fatal_command_index:
            raise RuntimeError(
                "aggregate/command fence IDs disagree: %r / %r" % (
                    fatal_snapshot, command_snapshot))
        if (control_fence.snapshot()["state"] != "completed"
                or control_fence.error is not None):
            raise RuntimeError("fatal notification poisoned completed work")

        # Logical teardown sees the failed fence as terminal and releases both
        # queue handles immediately.  The crashed device itself is never reused.
        driver.destroy_queue(FD, fatal_queue.queue_id)
        driver.destroy_queue(FD, control_queue.queue_id)
        if (not fatal_queue.lifetime.released
                or not control_queue.lifetime.released):
            raise RuntimeError("terminal queues did not release logically")

        report = getattr(front.g17p_asc, "g17p_fatal_report", None)
        print(
            "G17P FAULT TERMINATION PASS: rejected=%s attribution=%r; "
            "fatal_pa=%#x fatal=%r command=%r notification=%r report=%s; "
            "completed_control=%r queues_released=1" % (
                rejected_error, rejection["metadata"], fatal_pa,
                fatal_snapshot, command_snapshot, notification, report,
                control_fence.snapshot()),
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
