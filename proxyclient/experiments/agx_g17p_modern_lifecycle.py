#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove modern-UAPI VM, binding, queue, and teardown lifetimes on G17P."""

import os
import sys
import tempfile

from agx_g17p_render_uapi_fields import (
    EXPECTED_PIXEL,
    OUTPUT_DVA,
    PAGE_SIZE,
    render_command,
)
from m1n1.agx.g17p_uapi import (
    DRM_ASAHI_BIND_READ,
    DRM_ASAHI_BIND_SINGLE_PAGE,
    DRM_ASAHI_BIND_UNBIND,
    DRM_ASAHI_BIND_WRITE,
    drm_asahi_gem_bind_op,
)
from m1n1.agx.shim import DRMAsahiShim


FILE_A = 0x51
FILE_B = 0x52
TARGET_DVA = OUTPUT_DVA + PAGE_SIZE
SINGLE_DVA = OUTPUT_DVA + 0x100000
USC_EXEC_BASE = 0x10000000000
KERNEL_START = 0x7000000000
KERNEL_END = 0x7800000000


def expected_output():
    return EXPECTED_PIXEL * (0x1000 // len(EXPECTED_PIXEL)) + bytes(
        PAGE_SIZE - 0x1000)


def bind(driver, fd, vm, bo, address, size, flags, offset=0):
    return driver.bind(fd, vm.vm_id, drm_asahi_gem_bind_op(
        flags, bo.handle, offset, size, address))


def unbind(driver, fd, vm, address, size):
    return driver.bind(fd, vm.vm_id, drm_asahi_gem_bind_op(
        DRM_ASAHI_BIND_UNBIND, 0, 0, size, address))


def physical_page(front, bo, offset=0):
    pa = front.modern.adapter._bo_pa(bo) + int(offset)
    front.g17p.u.proxy.dc_civac(pa, PAGE_SIZE)
    return pa, bytes(front.g17p.u.iface.readmem(pa, PAGE_SIZE))


def submit_exact(front, fd, queue, output_dva, bo, bo_offset=0):
    bo.token["map"][bo_offset:bo_offset + PAGE_SIZE] = bytes(PAGE_SIZE)
    fence, _commands = front.modern.submit(
        fd, queue.queue_id,
        render_command(0, output_dva=output_dva),
    )
    output = bytes(bo.token["map"][bo_offset:bo_offset + PAGE_SIZE])
    if not fence.signaled() or output != expected_output():
        raise RuntimeError(
            "queue %d did not produce its exact output" % queue.queue_id)
    return fence


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_modern_lifecycle.py accepts no arguments")

    with tempfile.TemporaryFile() as memfd:
        os.ftruncate(memfd.fileno(), 7 * PAGE_SIZE)
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")

        from agx_g17p_compute import drain_boot_group

        drain_boot_group(front, backend)
        driver = front.modern
        vm_a = driver.create_vm(FILE_A, KERNEL_START, KERNEL_END)
        vm_b = driver.create_vm(FILE_B, KERNEL_START, KERNEL_END)
        if int(vm_a.token) == int(vm_b.token):
            raise RuntimeError("two modern VMs share a hardware context")

        # A begins as one three-page ordinary mapping.  Rendering the middle
        # page gives the later partial-unbind/rebind a semantic old-PA witness.
        a_old = driver.create_bo(FILE_A, 1, 0, 3 * PAGE_SIZE)
        b_output = driver.create_bo(FILE_B, 1, 3 * PAGE_SIZE, PAGE_SIZE)
        a_new = driver.create_bo(FILE_A, 2, 4 * PAGE_SIZE, PAGE_SIZE)
        a_single = driver.create_bo(FILE_A, 3, 5 * PAGE_SIZE, PAGE_SIZE)
        rw = DRM_ASAHI_BIND_READ | DRM_ASAHI_BIND_WRITE
        bind(driver, FILE_A, vm_a, a_old, OUTPUT_DVA, 3 * PAGE_SIZE, rw)
        bind(driver, FILE_B, vm_b, b_output, TARGET_DVA, PAGE_SIZE, rw)

        queue_a = driver.create_queue(
            FILE_A, vm_a.vm_id, 0, USC_EXEC_BASE)
        queue_b = driver.create_queue(
            FILE_B, vm_b.vm_id, 1, USC_EXEC_BASE)

        submit_exact(
            front, FILE_A, queue_a, TARGET_DVA, a_old, PAGE_SIZE)
        old_pa, old_after_a1 = physical_page(front, a_old, PAGE_SIZE)
        if old_after_a1 != expected_output():
            raise RuntimeError("A1 physical output did not match")

        submit_exact(front, FILE_B, queue_b, TARGET_DVA, b_output)
        _old_pa_check, old_after_b1 = physical_page(front, a_old, PAGE_SIZE)
        if old_after_b1 != old_after_a1:
            raise RuntimeError("VM B changed VM A's same-DVA physical page")

        # B is now fully quiescent.  Remove its queue, BO mapping, and private
        # root while A stays live; stale B submissions and context activation
        # must be rejected.
        driver.destroy_queue(FILE_B, queue_b.queue_id)
        if not queue_b.lifetime.released:
            raise RuntimeError("completed B queue did not release")
        driver.destroy_bo(FILE_B, b_output.handle)
        context_b = int(vm_b.token)
        driver.destroy_vm(FILE_B, vm_b.vm_id)
        try:
            backend.activate_execution_context(context_b)
        except Exception as exc:  # stale context has a specific backend error
            stale_context = str(exc)
        else:
            raise RuntimeError("destroyed VM B remained activatable")

        # Remove only A's middle page.  The driver must split the old mapping,
        # reject a stale render transactionally, then accept fresh backing at
        # the exact same DVA without disturbing either surviving flank.
        unbind(driver, FILE_A, vm_a, TARGET_DVA, PAGE_SIZE)
        survivors = [(item.addr, item.size, item.bo_offset)
                     for item in vm_a.bindings if item.bo is a_old]
        if survivors != [
                (OUTPUT_DVA, PAGE_SIZE, 0),
                (OUTPUT_DVA + 2 * PAGE_SIZE, PAGE_SIZE, 2 * PAGE_SIZE)]:
            raise RuntimeError("partial unbind produced %r" % (survivors,))
        group_before = backend.group_number
        try:
            driver.submit(
                FILE_A, queue_a.queue_id,
                render_command(0, output_dva=TARGET_DVA))
        except ValueError as exc:
            stale_mapping = str(exc)
        else:
            raise RuntimeError("unmapped render target was accepted")
        if backend.group_number != group_before:
            raise RuntimeError("rejected stale target changed publication state")

        bind(driver, FILE_A, vm_a, a_new, TARGET_DVA, PAGE_SIZE, rw)
        submit_exact(front, FILE_A, queue_a, TARGET_DVA, a_new)
        new_pa, new_after_a2 = physical_page(front, a_new)
        _old_pa_check, old_after_a2 = physical_page(front, a_old, PAGE_SIZE)
        if new_pa == old_pa or new_after_a2 != expected_output():
            raise RuntimeError("replacement DVA did not use fresh exact backing")
        if old_after_a2 != old_after_a1:
            raise RuntimeError("replacement render changed the released old PA")

        # One page of BO backing is repeated over a two-page DVA range.  Render
        # through the second alias and require the sole physical page to hold
        # the exact result.
        bind(
            driver, FILE_A, vm_a, a_single, SINGLE_DVA, 2 * PAGE_SIZE,
            rw | DRM_ASAHI_BIND_SINGLE_PAGE)
        submit_exact(
            front, FILE_A, queue_a, SINGLE_DVA + PAGE_SIZE, a_single)
        space_a = backend.execution_contexts[int(vm_a.token)]["space"]
        first_pa = space_a.uat.iotranslate(
            int(vm_a.token), SINGLE_DVA, PAGE_SIZE)[0][0]
        second_pa = space_a.uat.iotranslate(
            int(vm_a.token), SINGLE_DVA + PAGE_SIZE, PAGE_SIZE)[0][0]
        if first_pa != second_pa:
            raise RuntimeError(
                "single-page binding used distinct PAs %#x and %#x" %
                (first_pa, second_pa))

        driver.destroy_queue(FILE_A, queue_a.queue_id)
        if not queue_a.lifetime.released:
            raise RuntimeError("completed A queue did not release")
        for handle in (1, 2, 3):
            driver.destroy_bo(FILE_A, handle)
        driver.destroy_vm(FILE_A, vm_a.vm_id)

        print(
            "MODERN LIFECYCLE PASS: VMs %d/%d same DVA isolated; "
            "B teardown=%s; partial-unbind rejection=%s; DVA PA %#x->%#x; "
            "single-page PA=%#x" % (
                int(vm_a.token), context_b, stale_context, stale_mapping,
                old_pa, new_pa, first_pa),
            flush=True,
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
