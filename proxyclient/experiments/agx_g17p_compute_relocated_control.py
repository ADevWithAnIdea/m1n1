#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run source compute with independent render and compact-control objects."""

import importlib.util
import os
import pathlib
import struct
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "1"
os.environ["G17P_STRUCTURAL_TAIL_FIELDS"] = "1"
os.environ["G17P_NATIVE_LIFECYCLE_FIELDS"] = "1"
os.environ["G17P_NATIVE_ITEM_FIELDS"] = "1"


PAGE = 0x4000
INITIAL_SUPPORT = 0xFFFFFC20C0828000
INITIAL_STATE = 0xFFFFFC2001600000
INITIAL_PAGE_LIST = 0x7000000000
INITIAL_OPERAND = 0x7000208000
INITIAL_BUFFER_BASE = 0x7000220000
INITIAL_BUFFER_COUNT = 22
INITIAL_PAGE_LIST_COUNT = 17
INITIAL_BUFFER_STRIDE = 0x108000

LATE_SUPPORT = INITIAL_SUPPORT
LATE_STATE = INITIAL_STATE
LATE_PAGE_LIST = 0x70017D8000
LATE_OPERAND = 0x70019E0000
SOURCE_SHARED = 0xFFFFFC20C0860000
NATIVE_SHARED = 0xFFFFFC20C0868000

LATE_FIRST_WORK_PAGES = (
    0xFFFFFC20C0008000,  # both bootstrap item-ring records
    0xFFFFFC20C0018000,  # tiling descriptor and its low alias
    0xFFFFFC20C00B0000,  # fragment descriptor and its low alias
    0xFFFFFC20C05E8000,  # paired event records
    0xFFFFFC20C0600000,  # paired optional records
    0xFFFFFC20C0798000,  # TA channel-ring publication
    0xFFFFFC20C079C000,  # 3D channel-ring publication
    0xFFFFFC20001D8000,  # tiling context/queue record
    0xFFFFFC2000200000,  # fragment context/queue record
)


def stage_first_work_lifecycle(module, prepared):
    """Hold source-built first-work bytes until the native publication interval."""
    from m1n1.agx import g17p

    read = prepared["read"]
    write = prepared["write"]
    late_pages = {address: read(address, PAGE)
                  for address in LATE_FIRST_WORK_PAGES}

    # Native leaves these complete records blank before the first primary 0x84.
    for address in LATE_FIRST_WORK_PAGES:
        write(address, bytes(PAGE))

    # The fragment descriptor has eight fixed seed bytes before its remaining
    # host-owned body is published.
    fragment_seed = bytearray(PAGE)
    for offset, value in (
            (0x0000, 0x01), (0x000c, 0x01), (0x2100, 0x01),
            (0x2174, 0x01), (0x21d6, 0x01), (0x21d8, 0xe0),
            (0x21d9, 0xbd), (0x21e7, 0x01)):
        fragment_seed[offset] = value
    write(0xFFFFFC20C00B0000, fragment_seed)

    # The queue records exist early, but their UUID changes with publication.
    for queue in (0xFFFFFC20C0000000, 0xFFFFFC20C00000C0):
        write(queue + g17p.QUEUE_UUID, struct.pack("<I", 0xAA))

    # Queue pointer blocks retain an adjacent class word. Only the write index
    # moves from zero to three when the three-item group is published.
    for pointers in (0xFFFFFC2000010000, 0xFFFFFC2000012870):
        write(pointers + g17p.QUEUE_PTR_WRITE, struct.pack("<I", 0))
        write(pointers + g17p.QUEUE_PTR_BLOCK_SIZE, struct.pack("<Q", 0x500))

    write(0xFFFFFC20015F8000 + 4, struct.pack("<I", 1))
    write(0xFFFFFC2001620000, struct.pack("<I", 0))

    # The scheduler's resource page is stable across this interval. The source
    # had its second scalar off by one bit.
    resource = bytearray(PAGE)
    struct.pack_into("<I", resource, 0x00, 0x00019000)
    struct.pack_into("<I", resource, 0x04, 0x00000040)
    write(0xFFFFFC20015E0000, resource)

    # Initial scheduler dispatch state, before its two publication cursors move.
    dispatch = bytearray(PAGE)
    for offset, value in (
            (0x00, 0xe0000000), (0x04, 0x08000000),
            (0x0c, 0x00002200), (0x10, 0x00001100)):
        struct.pack_into("<I", dispatch, offset, value)
    write(0xFFFFFC20015E8000, dispatch)

    # This speculative current-job page is absent at both native boundaries.
    write(0xFFFFFC20C07D0000, bytes(PAGE))
    module.u.inst("dsb sy")
    print(
        "FIRST WORK staged in native pre-0x84 state; late source bytes held",
        flush=True,
    )

    def publish():
        for address, body in late_pages.items():
            write(address, body)
        for queue in (0xFFFFFC20C0000000, 0xFFFFFC20C00000C0):
            write(queue + g17p.QUEUE_UUID, struct.pack("<I", 0xAE))
        for pointers in (0xFFFFFC2000010000, 0xFFFFFC2000012870):
            write(pointers + g17p.QUEUE_PTR_WRITE, struct.pack("<I", 3))
            write(pointers + g17p.QUEUE_PTR_BLOCK_SIZE,
                  struct.pack("<Q", 0x500))
        write(0xFFFFFC20015F8000 + 4, struct.pack("<I", 2))
        write(0xFFFFFC2001620000, struct.pack("<I", 1))

        dispatch = bytearray(PAGE)
        for offset, value in (
                (0x00, 0xe0000000), (0x04, 0x08000000),
                (0x0c, 0x00002c00), (0x10, 0x00001600)):
            struct.pack_into("<I", dispatch, offset, value)
        write(0xFFFFFC20015E8000, dispatch)

        computed = bytearray(PAGE)
        for offset, value, width in (
                (0x000, 0x0f00, 4), (0x008, 0x0f00, 4),
                (0x400, 1, 4), (0x404, 1, 4), (0x600, 2, 4),
                (0x800, module.CHANNEL_CONTROL_ADDRESS, 8),
                (0xc00, 0x2000, 4), (0xe00, 2, 4),
                (0xe20, 1, 4), (0xe28, 1, 4)):
            computed[offset:offset + width] = int(value).to_bytes(
                width, "little")
        write(0xFFFFFC20015D8000, computed)
        write(0xFFFFFC20C07D0000, bytes(PAGE))
        module.u.inst("dsb sy")
        print(
            "FIRST WORK late source-built graph and scheduler state published",
            flush=True,
        )

    return publish


def write_opening_class1(backend, cursor, state_count, page_list_count):
    from m1n1.agx import g17p_compute as compute
    from agx_g17p_native_compute_lifecycle import _write_low

    support = compute.build_compute_class1_support(
        INITIAL_OPERAND,
        INITIAL_PAGE_LIST,
        INITIAL_STATE,
        active=0,
        resource_class=0x11,
        cursor=cursor,
        final_kind=2,
    )
    state = bytearray(PAGE)
    struct.pack_into("<Q", state, 0, state_count)
    operand = compute.build_compute_operand_table_bases(
        INITIAL_BUFFER_BASE + index * INITIAL_BUFFER_STRIDE
        for index in range(INITIAL_BUFFER_COUNT)
    )
    operand += bytes(0x10000 - len(operand))
    page_list = compute.build_compute_operand_page_lists(
        INITIAL_BUFFER_BASE,
        entries=page_list_count,
        buffer_stride=INITIAL_BUFFER_STRIDE,
    )
    page_list += bytes(0x200000 - len(page_list))

    backend._write_dva(INITIAL_SUPPORT, support + bytes(PAGE - len(support)))
    backend._write_dva(INITIAL_STATE, state)
    _write_low(backend.space, INITIAL_OPERAND, operand)
    _write_low(backend.space, INITIAL_PAGE_LIST, page_list)
    backend._clean_dva_range(INITIAL_SUPPORT, PAGE)
    backend._clean_dva_range(INITIAL_STATE, PAGE)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "OPENING CLASS1 built: cursor=%#x state=%d page-list=%d "
        "operand-tranches=%d" % (
            cursor, state_count, page_list_count, INITIAL_BUFFER_COUNT),
        flush=True,
    )


def install_relocated_boot_module():
    """Preload the module name DRMAsahiShim uses, then relocate four objects."""
    path = HERE / "agx_g17p_boot.py"
    name = "m1n1_g17p_drm_cold_boot"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)

    # Exact bootstrap pair-zero graph from the native pre-first-CL0 snapshot.
    # It has 16 index groups and is distinct from the first created (pair-one)
    # graph at c087/c08a used by earlier failed relocation experiments.
    relocated = {
        "record_pool_a": 0xFFFFFC20C0820100,
        "record_pool_b": 0xFFFFFC20C0830080,
        "descriptor_shared_object": 0xFFFFFC20C0860000,
        "descriptor_zero_object": 0xFFFFFC20C0832800,
    }
    for object_name, address in relocated.items():
        old = module.SUBMISSION_ADDRESSES[object_name]
        module.SUBMISSION_ADDRESSES[object_name] = address
        print(
            "RELOCATE %-26s %#014x -> %#014x" %
            (object_name, old, address),
            flush=True,
        )
    relocated_leaves = {
        "primary_index": 0xFFFFFC20C0848000,
        "secondary_index": 0xFFFFFC20C0838000,
        "pool_a_slots": 0xFFFFFC20015F8000,
        "pool_b_slots": 0xFFFFFC2001618000,
        "shared_slots": 0xFFFFFC2001610000,
        "flag": 0xFFFFFC2001620000,
    }
    for object_name, address in relocated_leaves.items():
        old = module.LEAF_PAGE_ADDRESSES[object_name]
        module.LEAF_PAGE_ADDRESSES[object_name] = address
        print(
            "RELOCATE %-26s %#014x -> %#014x" %
            (object_name, old, address),
            flush=True,
        )
    module.SUBMISSION_INDEX_GROUP_RANGES = ((0x11, 6), (0x4A, 10))
    module.SUBMISSION_SHARED_COUNT = 0x10

    prepared_holder = {}
    original_prepare_work_group = module.prepare_work_group

    def prepare_work_group_with_lifecycle(*args, **kwargs):
        prepared = original_prepare_work_group(*args, **kwargs)
        render_state = args[4] if len(args) > 4 else kwargs["render_state"]
        context_state = args[5] if len(args) > 5 else kwargs["context_state"]
        prepared["render_extent"] = render_state["extent"]["mapped"]
        prepared["render_state"] = render_state
        prepared["context_state"] = context_state
        prepared["bound_submission"] = {
            "pools": [
                module.SUBMISSION_ADDRESSES["record_pool_a"],
                module.SUBMISSION_ADDRESSES["record_pool_b"],
            ],
            "shared": [
                module.SUBMISSION_ADDRESSES["descriptor_shared_object"],
                module.SUBMISSION_ADDRESSES["descriptor_zero_object"],
            ],
            "leaf_pages": dict(module.LEAF_PAGE_ADDRESSES),
        }
        module.RELOCATED_PREPARED = prepared
        read = prepared["read"]
        expected_tail_pointers = (
            ("tiling shared", 0xFFFFFC20C0018000 + 0x934,
             INITIAL_SUPPORT),
            ("tiling status", 0xFFFFFC20C0018000 + 0x945,
             0xFFFFFC2001608000),
            ("fragment shared", 0xFFFFFC20C00B0000 + 0x21CE,
             INITIAL_SUPPORT),
            ("fragment status", 0xFFFFFC20C00B0000 + 0x21DF,
             0xFFFFFC2001628000),
        )
        for label, address, expected in expected_tail_pointers:
            actual = struct.unpack("<Q", read(address, 8))[0]
            if actual != expected:
                raise RuntimeError(
                    "%s pointer is %#x, expected relocated %#x" %
                    (label, actual, expected))
        print(
            "RELOCATED DESCRIPTOR POINTERS: all four final values verified",
            flush=True,
        )
        prepared_holder["prepared"] = prepared
        return prepared

    module.prepare_work_group = prepare_work_group_with_lifecycle

    # Final 26.6 registers c082 and every first-work view names that same
    # object. The older source fixture instead mixed c082 registration with
    # c083 optional/tail references and the second channel-control record.
    module.SHARED_CONTROL_ADDRESS = INITIAL_SUPPORT
    module.SHARED_CONTROL_INNER_ADDRESS = INITIAL_STATE
    module.CHANNEL_CONTROL_ITEM_RECORD = 0
    module.QUEUE_UUID_VALUE = 0xAE
    module.QUEUE_JOB_LIST_VA = 0xFFFFFC2000000000

    native_status = {
        "ta_status": 0xFFFFFC2001608000,
        "fragment_status": 0xFFFFFC2001628000,
    }
    module.RENDER_FIRMWARE_ALIASES = {
        0x1000078000: native_status["ta_status"],
        0x1000080000: relocated_leaves["pool_b_slots"],
        0x1000190000: relocated_leaves["primary_index"],
        0x1000194000: relocated_leaves["primary_index"] + PAGE,
        0x1000198000: relocated_leaves["primary_index"] + 2 * PAGE,
        0x100019C000: relocated_leaves["primary_index"] + 3 * PAGE,
        0x10001A8000: native_status["fragment_status"],
    }
    rewritten_targets = {}
    for address, (role, detail) in module.DESCRIPTOR_TAIL_TARGETS.items():
        if role == "shared":
            address = INITIAL_SUPPORT
        elif role == "status":
            address = native_status[detail]
        rewritten_targets[address] = (role, detail)
    module.DESCRIPTOR_TAIL_TARGETS = rewritten_targets
    for kind, entries in module.DESCRIPTOR_TAIL_POINTERS.items():
        rewritten = []
        for offset, address in entries:
            if address == 0xFFFFFC20C0830000:
                address = INITIAL_SUPPORT
            elif address == 0xFFFFFC2001610000:
                address = native_status["ta_status"]
            elif address == 0xFFFFFC2001630000:
                address = native_status["fragment_status"]
            rewritten.append((offset, address))
        module.DESCRIPTOR_TAIL_POINTERS[kind] = tuple(rewritten)

    # G17PWorkBuilder appends the caller-supplied tail and then writes its own
    # canonical tail pointers over it. Keep those final writes coherent with
    # the relocated pair-zero graph too. Otherwise both descriptors retain
    # c0830000 as their shared-control pointer; that address is Pool B in this
    # layout, and firmware follows the bogus pointer into a null dereference.
    G17PWorkBuilder = module.load_backend_modules().g17p_backend.G17PWorkBuilder

    rewritten_builder_pointers = {}
    for kind, entries in G17PWorkBuilder.TAIL_POINTERS.items():
        rewritten = []
        for offset, address, role in entries:
            if address == 0xFFFFFC20C0830000:
                address = INITIAL_SUPPORT
            rewritten.append((offset, address, role))
        rewritten_builder_pointers[kind] = tuple(rewritten)
    G17PWorkBuilder.TAIL_POINTERS = rewritten_builder_pointers

    rewritten_status_bases = {
        kind: list(addresses)
        for kind, addresses in G17PWorkBuilder.PAIR_STATUS_BASES.items()
    }
    rewritten_status_bases["tiling"][0] = native_status["ta_status"]
    rewritten_status_bases["fragment"][0] = native_status["fragment_status"]
    G17PWorkBuilder.PAIR_STATUS_BASES = {
        kind: tuple(addresses)
        for kind, addresses in rewritten_status_bases.items()
    }

    # The first native post-start 0x20 consumes a compact class-1 object while
    # the render descriptors simultaneously use the same numerical low DVA in
    # context 0. The page-list lives in context 1, so only the high state page
    # had to be freed by the complete pair relocation above.
    original_apply_scalars = module.apply_scalars

    def apply_scalars_with_initial_class1(arena, instances):
        from m1n1.agx.g17p_shim import G17PShimBackend

        original_apply_scalars(arena, instances)
        backend = G17PShimBackend(
            module.u,
            instances[0]["root_va"],
            lambda _channel=0: None,
            context=module.CONTEXT,
            adopt=True,
            firmware_root="high",
        )
        backend.space.use_absent_handoff()
        prepared = prepared_holder.get("prepared")
        if prepared is None:
            raise RuntimeError("first-work graph was not prepared before initdata")
        publish_first_work = stage_first_work_lifecycle(module, prepared)
        write_opening_class1(
            backend, cursor=0x88, state_count=1,
            page_list_count=INITIAL_PAGE_LIST_COUNT)

        def prepare_first_work():
            write_opening_class1(
                backend, cursor=0xB0, state_count=2,
                page_list_count=INITIAL_BUFFER_COUNT)
            publish_first_work()

        module.FINAL_26_6_FIRST_WORK_PREPARE = prepare_first_work

    module.apply_scalars = apply_scalars_with_initial_class1
    return module


def _ensure_low_pages(backend, address, size):
    from m1n1.hw.uat import MemoryAttr

    start = address & ~(PAGE - 1)
    end = (address + size + PAGE - 1) & ~(PAGE - 1)
    for page in range(start, end, PAGE):
        ranges = backend.space.uat.iotranslate_root(
            backend.space.uat.ttbr0_base, page, PAGE)
        if ranges and ranges[0][0] is not None:
            continue
        pa = backend.u.memalign(PAGE, PAGE)
        backend.u.proxy.memset32(pa, 0, PAGE)
        backend.u.proxy.dc_civac(pa, PAGE)
        backend.space.uat.iomap_at(
            backend.space.context,
            page,
            pa,
            PAGE,
            AttrIndex=MemoryAttr.Shared,
            AP=2,
            nG=1,
            UXN=1,
            OS=1,
        )
    backend.space.uat.flush_dirty()
    backend.space.uat.invalidate_cache()


def install_late_control_graph(backend):
    """Construct the exact sequence-22/23 inputs after the first render."""
    from m1n1.agx import g17p_compute as compute
    from agx_g17p_native_compute_lifecycle import (
        RENDER_BUFFER_SEQUENCE,
        TABLE_A,
        _write_low,
    )

    # Sequence 22 sees c0868 before that VA is repurposed as the CL2 scheduler
    # array. At this boundary it is the ordinary blank-table class-1 support
    # object used by native queue creation, paired with c1630 state.
    sequence22_state = 0xFFFFFC2001630000
    sequence22_support = compute.build_compute_class1_support(
        TABLE_A,
        0,
        sequence22_state,
        active=1,
        resource_class=0x11,
        cursor=0x88,
        final_kind=2,
    )
    state = bytearray(PAGE)
    struct.pack_into("<I", state, 0, 1)
    backend._write_dva(
        NATIVE_SHARED,
        sequence22_support + bytes(PAGE - len(sequence22_support)))
    backend._write_dva(sequence22_state, state)

    # Sequence 23 is the compact class-1 object observed at the known-positive
    # pre-CL2 boundary. Its low array is the ordered page inventory for the 21
    # render operand tranches; its operand table is populated by the lifecycle
    # helper immediately before publication.
    support = compute.build_compute_class1_support(
        LATE_OPERAND,
        LATE_PAGE_LIST,
        LATE_STATE,
        active=0,
        resource_class=0x15,
        cursor=0xA8,
        final_kind=2,
        word_20=0x00002B5000001650,
        field_54=0x54,
    )
    state = bytearray(PAGE)
    struct.pack_into("<Q", state, 0, 0x54)
    page_list = b"".join(
        struct.pack("<Q", base + offset)
        for base in RENDER_BUFFER_SEQUENCE
        for offset in range(0, 0x100000, 0x1000)
    )
    if len(page_list) != 0xA800:
        raise RuntimeError("late class-1 page inventory has wrong size")
    _ensure_low_pages(backend, LATE_PAGE_LIST, len(page_list))
    _write_low(backend.space, LATE_PAGE_LIST, page_list)
    backend._write_dva(LATE_SUPPORT, support + bytes(PAGE - len(support)))
    backend._write_dva(LATE_STATE, state)
    backend._clean_dva_range(NATIVE_SHARED, PAGE)
    backend._clean_dva_range(sequence22_state, PAGE)
    backend._clean_dva_range(LATE_SUPPORT, PAGE)
    backend._clean_dva_range(LATE_STATE, PAGE)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "LATE CONTROL built: sequence-22 blank-table class1 and exact "
        "sequence-23 class1/page inventory/state",
        flush=True,
    )


def main():
    if len(sys.argv) != 1:
        raise SystemExit(
            "agx_g17p_compute_relocated_control.py accepts no arguments")
    os.environ["G17P_FINAL_26_6_SECONDARY_TARGET"] = "1"
    install_relocated_boot_module()

    # Import after installing the patched cold-boot module. The workload and
    # physical witness are the same exact field-built add3 path as the baseline.
    from m1n1.agx.shim import DRMAsahiShim
    from agx_g17p_native_add3 import build_client_graph, submit_built
    from agx_g17p_native_compute_lifecycle import (
        advance_native_compute_lifecycle,
    )

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        client = build_client_graph(backend)
        advance_native_compute_lifecycle(
            front, backend, client,
            prepare_late_controls=lambda: install_late_control_graph(backend),
            initial_group_already_completed=True)
        submit_built(front, backend, client)
        print(
            "SOURCE COMPUTE PASS: independent source-render and compact-control "
            "graphs, exact add3 physical output",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
