#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepublish one field-built CL2 job for compact startup consumption."""

import hashlib
import math
import os
import json
import pathlib
import struct
import sys
import time


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

os.environ.setdefault("M1N1DEVICE", "/dev/m1n1-neo")
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"
os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = "0"
os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = "0"
os.environ.setdefault("G17P_FINAL_26_6_SECONDARY_TARGET", "1")

from m1n1.agx import g17p, g17p_compute as compute, g17p_initdata  # noqa: E402
from m1n1.agx.g17p_backend import G17PQueueFence  # noqa: E402
from m1n1.agx.g17p_shim import (  # noqa: E402
    G17PCommandBuffer,
    G17P_RETAINED_TARGET,
    G17PShimBackend,
)
from m1n1.agx.g17p_sync import G17PSyncObject  # noqa: E402
from m1n1.agx.shim import DRMAsahiShim  # noqa: E402
from m1n1.hw.uat import MemoryAttr  # noqa: E402

from agx_g17p_compute_relocated_control import (  # noqa: E402
    install_relocated_boot_module,
)
from agx_g17p_native_add3 import (  # noqa: E402
    CONTEXT,
    DESCRIPTOR,
    EVENT,
    OPTIONAL,
    OPERAND_BUFFER_BASE,
    OPERAND_TABLE,
    OUTER_RING,
    RESOURCE_SIZE,
    SHADER_SIZE,
    SHARED_SUPPORT,
    SUPPORT_STATE,
    WORK_DOORBELL_CHANNEL,
    _work_addresses,
    await_next_workload,
    build_client_graph,
    build_firmware_graph,
    stage_next_workload,
    submit_next_workload,
)


PAGE = 0x4000
PRIMARY_RECORD_B = 0xFFFFFC20015E8000
CONTROL_ENTRY_SIZE = 0x40
CONTROL_COUNT = 67
SOURCE_CONFIG_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "generated_config_pre_cl2_20260812_031439"
)
MODELED_CONFIG_ATTEMPT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "replay_first_work_original_pa_attempt_20260812_121541/attempt.json"
)
POSITIVE_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_add3_full_positive_20260811_230235"
)
NATIVE_FOURTH_CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260813_052428/CL_2"
)
NATIVE_INDIRECT_SECOND_CAPTURE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "live_submission_targeted_20260814_210726/CL_2"
)
NATIVE_CONTEXT2_POPULATED = (
    0x1000000000,
    0x10000000000,
    0x10000004000,
    0x10000018000,
    0x10000048000,
    0x1000004C000,
    0x10000098000,
)


def _registration(control_class, sequence, first_object, operand_table,
                  slot_offset, count, context_word=0):
    body = bytearray(CONTROL_ENTRY_SIZE)
    struct.pack_into(
        "<IIII", body, 0,
        0x20, int(control_class), 0x3F, int(sequence),
    )
    struct.pack_into("<Q", body, 0x14, int(first_object))
    struct.pack_into("<Q", body, 0x1C, int(operand_table))
    struct.pack_into(
        "<Q", body, 0x24, int(operand_table) + int(slot_offset))
    struct.pack_into("<I", body, 0x2C, int(count))
    struct.pack_into("<I", body, 0x30, int(context_word))
    struct.pack_into("<I", body, 0x34, 1)
    return bytes(body)


def _tick(sequence, context_word=0):
    body = bytearray(CONTROL_ENTRY_SIZE)
    struct.pack_into("<II", body, 0, 0x2E, int(sequence))
    struct.pack_into("<I", body, 0x0C, int(context_word))
    return bytes(body)


def seed_completed_control_history(backend):
    """Build the 67 records retained by the output-positive checkpoint."""
    opening = bytearray(CONTROL_ENTRY_SIZE)
    struct.pack_into("<I", opening, 0, 0x16)
    records = [bytes(opening)]
    records.append(_registration(
        1, 0, 0xFFFFFC20C0828000, 0x7000208000, 0x440, 0x28))
    records.extend(_tick(sequence) for sequence in range(22))
    records.append(_registration(
        1, 22, 0xFFFFFC20C0868000, 0x70013A0000, 0x440, 0x20))
    records.append(_tick(22))
    records.append(_registration(
        1, 23, 0xFFFFFC20C0828000, 0x70019E0000, 0x440, 0x20))
    records.extend(_tick(sequence) for sequence in range(23, 63))
    if len(records) != CONTROL_COUNT:
        raise RuntimeError(
            "completed control history has %d records" % len(records))

    control = backend.channels.entries[g17p.CHANNEL_TABLE_WORK_COUNT]
    backend._write_dva(control["ring_addr"], b"".join(records))
    for address in control["state_addrs"]:
        backend._write_dva(address, struct.pack("<I", CONTROL_COUNT))
        backend._clean_dva_range(address, 4)
    backend._clean_dva_range(
        control["ring_addr"], len(records) * CONTROL_ENTRY_SIZE)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "SOURCE COMPUTE INITIAL built exact 67-entry completed control "
        "history at %#x" % control["ring_addr"],
        flush=True,
    )
    return control


def graft_processed_source_config(backend):
    metadata = json.loads(
        (SOURCE_CONFIG_SNAPSHOT / "pages.json").read_text())
    blob = (SOURCE_CONFIG_SNAPSHOT / "pages.bin").read_bytes()
    pages = {
        int(record["dva"]): blob[
            int(record["capture_offset"]):
            int(record["capture_offset"]) + PAGE]
        for record in metadata["pages"]
    }
    attempt = json.loads(MODELED_CONFIG_ATTEMPT.read_text())
    addresses = sorted(
        int(record["dva"])
        for record in attempt["grafted_source_config_pages"]["pages"]
    )
    for address in addresses:
        backend._write_dva(address, pages[address])
        backend._clean_dva_range(address, PAGE)
    backend.space.flush()
    backend.u.inst("dsb sy")
    print(
        "SOURCE COMPUTE INITIAL grafted %d processed source-config pages "
        "(%#x bytes)" % (len(addresses), len(addresses) * PAGE),
        flush=True,
    )
    return addresses


def graft_missing_native_context2(client, addresses=None):
    """Install only native context-2 leaves absent from the source builder."""
    manifest = json.loads((POSITIVE_SNAPSHOT / "manifest.json").read_text())
    ram = (POSITIVE_SNAPSHOT / manifest["ram_file"]).read_bytes()
    groups = [
        group for group in manifest["root_mappings"]
        if int(group["root_ctx_id"]) == 2 and int(group["selector"]) == 0
    ]
    if len(groups) != 1:
        raise RuntimeError(
            "positive snapshot exposes %d context-2 low roots" % len(groups))
    space = client["space"]
    requested = None if addresses is None else set(addresses)
    installed = []
    for mapping in groups[0]["mappings"]:
        address = int(mapping["va"])
        if requested is not None and address not in requested:
            continue
        translated = space.uat.iotranslate_root(
            space.uat.ttbr0_base, address, PAGE)
        if translated and translated[0][0] is not None:
            continue
        blob_index = mapping.get("blob_index")
        if blob_index is None:
            raise RuntimeError(
                "native-only context-2 leaf %#x has no captured body" %
                address)
        body = ram[int(blob_index) * PAGE:(int(blob_index) + 1) * PAGE]
        if len(body) != PAGE:
            raise RuntimeError("short context-2 body at %#x" % address)
        pa = space.u.memalign(PAGE, PAGE)
        space.u.iface.writemem(pa, body)
        space.p.dc_civac(pa, PAGE)
        pte = int(mapping["pte"])
        space.uat.iomap_at(
            space.context, address, pa, PAGE,
            AttrIndex=(pte >> 2) & 0x7,
            AP=(pte >> 6) & 0x3,
            SH=(pte >> 8) & 0x3,
            AF=(pte >> 10) & 0x1,
            nG=(pte >> 11) & 0x1,
            PXN=(pte >> 53) & 0x1,
            UXN=(pte >> 54) & 0x1,
            OS=(pte >> 55) & 0x1,
        )
        installed.append({
            "dva": address,
            "pa": pa,
            "nonzero_bytes": sum(byte != 0 for byte in body),
        })
    if requested is not None:
        missing = requested - {record["dva"] for record in installed}
        if missing:
            raise RuntimeError(
                "requested context-2 leaves were not native-only: %s" %
                ", ".join("%#x" % address for address in sorted(missing)))
    space.uat.flush_dirty()
    space.uat.invalidate_cache()
    space.flush()
    space.u.inst("dsb sy; tlbi aside1os, x0; dsb sy; isb", 2 << 48)
    print(
        "SOURCE COMPUTE INITIAL grafted %d native-only context-2 leaves, "
        "%d nonzero pages and %d nonzero bytes" % (
            len(installed),
            sum(record["nonzero_bytes"] != 0 for record in installed),
            sum(record["nonzero_bytes"] for record in installed),
        ),
        flush=True,
    )
    return installed


def main(graft_source_config=False, distinct_empty_client_high=False,
         distinct_empty_all_client_high=False,
         exact_client_context_table=False,
         alias_context0_queue=False,
         native_shader_attributes=False,
         graft_native_context2_missing=False,
         native_context2_graft_addresses=None,
         repeat_workloads=1,
         prepublish_second=False,
         native_fourth_class1_poststate=False,
         native_fourth_class2_ancestry=False,
         native_fourth_record_b=False,
         fresh_command3_style_fourth=False,
         batch_final_pair=False,
         batch_dependency_pair=False,
         verify_sync_objects=False,
         inter_submit_dependency_pair=False,
         mixed_render_compute_dependency=False,
         native_runtime_tick_context=False,
         no_late_fourth_control=False,
         capture_peer_boundaries=False,
         capture_peer_ordinals=(),
         secondary_opening_only=False,
         pre_runtime_native_gate=False,
         pre_runtime_native_class2_only=False,
         pre_runtime_native_gate_context=0,
         pre_initial_native_gate=False,
         drain_runtime_mailboxes=False,
         drain_runtime_reports=False,
         drain_runtime_report_interval=1,
         sync_region_c_control_shadow=False,
         couple_runtime_ticks=False,
         persistent_runtime_queue=False,
         persistent_startup_queue=False,
         persistent_runtime_optional_once=False,
         persistent_runtime_fresh_descriptors=False,
         persistent_runtime_fresh_events=False,
         persistent_runtime_tick_once=False,
         client_slot_count=None,
         fast_sequential=False,
         persistent_runtime_recycle_interval=None,
         persistent_runtime_context_record_count=None,
         persistent_runtime_alternating_contexts=False,
         persistent_runtime_preserve_context_reuse=False,
         persistent_runtime_optional_skip_ordinals=(),
         shared_outer_ring_page=False,
         device_outer_ring_page=False,
         fresh_outer_ring_at=None,
         native_control_tail=False,
         suppress_runtime_controls=False,
         sparse_runtime_tick_count=0,
         sparse_runtime_tick_span=None,
         post_start_initial=False,
         strict_release_publish=False,
         queue_index_bias=0,
         firmware_item_capacity=None,
         client_workload_capacity=None,
         client_dispatch_grids=None,
         client_threadgroups=None,
         indirect_dispatch=False,
         indirect_layout="native",
         soft_fault_ordinal=None,
         client_setup=None,
         result_verifier=None,
         prestage_return_next=False,
         notify_prestaged_before_return=False,
         return_state=False):
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_compute_source_initial.py accepts no arguments")
    for name, value in DRMAsahiShim.G17P_DEFAULTS.items():
        os.environ.setdefault(name, value)

    # The relocated-control helper defaults to exercising its measured
    # lifecycle when imported.  This experiment starts from a completed native
    # history instead, so keep the helper from publishing another opening.
    os.environ["G17P_FINAL_26_6_CONTROL_LIFECYCLE"] = (
        "1" if mixed_render_compute_dependency else "0")
    os.environ["G17P_SOURCE_NATIVE_CONTROL_LIFECYCLE"] = (
        "1" if mixed_render_compute_dependency else "0")
    os.environ["G17P_FINAL_26_6_SECONDARY_LIFECYCLE"] = (
        "1" if secondary_opening_only else "0")
    if mixed_render_compute_dependency:
        os.environ["G17P_FINAL_26_6_SECONDARY_TARGET"] = "19"
    if prepublish_second and int(repeat_workloads) < 2:
        raise ValueError("prepublishing queue two requires repeat_workloads >= 2")
    if batch_final_pair and int(repeat_workloads) != 4:
        raise ValueError("batching the final pair requires four workloads")
    if batch_dependency_pair and int(repeat_workloads) != 3:
        raise ValueError("batching a dependency pair requires three workloads")
    if verify_sync_objects and not batch_dependency_pair:
        raise ValueError("sync-object verification requires a dependency pair")
    if inter_submit_dependency_pair and int(repeat_workloads) != 3:
        raise ValueError(
            "an inter-submit dependency pair requires three workloads")
    if inter_submit_dependency_pair and batch_dependency_pair:
        raise ValueError("dependency pairs cannot be batched and serialized")
    if mixed_render_compute_dependency and int(repeat_workloads) != 2:
        raise ValueError(
            "a mixed render-to-compute dependency requires two compute workloads")
    if soft_fault_ordinal is not None:
        soft_fault_ordinal = int(soft_fault_ordinal)
        if not 1 <= soft_fault_ordinal < int(repeat_workloads):
            raise ValueError(
                "soft-fault ordinal must name a post-start workload")
        if any((batch_final_pair, batch_dependency_pair,
                inter_submit_dependency_pair)):
            raise ValueError(
                "soft-fault injection requires the ordinary sequential path")

    boot = install_relocated_boot_module()
    original_apply_scalars = boot.apply_scalars
    staged = {}

    def stage_before_initdata(arena, instances):
        original_apply_scalars(arena, instances)
        backend = G17PShimBackend(
            boot.u,
            instances[0]["root_va"],
            lambda _channel=0: None,
            context=boot.CONTEXT,
            adopt=True,
            firmware_root="high",
            secondary_initdata_addr=instances[1]["root_va"],
        )
        backend.space.use_absent_handoff()
        if shared_outer_ring_page and device_outer_ring_page:
            raise ValueError("CL2 outer-ring page cannot be both Shared and Device")
        if shared_outer_ring_page or device_outer_ring_page:
            page = OUTER_RING & ~(PAGE - 1)
            translated = backend.space.uat.iotranslate_root(
                backend.firmware_high_root, page, PAGE)
            if (not translated or translated[0][0] is None
                    or translated[0][1] < PAGE):
                raise RuntimeError(
                    "cannot resolve CL2 outer-ring page %#x" % page)
            page_pa = translated[0][0]
            backend.space.uat.iomap_at_root(
                backend.firmware_high_root,
                page,
                page_pa,
                PAGE,
                ctx=backend.space.context,
                AttrIndex=(
                    MemoryAttr.Device if device_outer_ring_page
                    else MemoryAttr.Shared),
                AP=1,
            )
            backend.space.uat.flush_dirty()
            backend.space.uat.invalidate_cache()
            backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
            print(
                "SOURCE COMPUTE mapped CL2 outer-ring page %#x PA %#x "
                "as %s" % (
                    page, page_pa,
                    "Device" if device_outer_ring_page else "Shared"),
                flush=True,
            )
        grafted_config = []
        if graft_source_config:
            grafted_config = graft_processed_source_config(backend)
        control = (
            backend.channels.entries[g17p.CHANNEL_TABLE_WORK_COUNT]
            if mixed_render_compute_dependency
            else seed_completed_control_history(backend)
        )
        compute_dispatch = g17p_initdata.build_compute_dispatch_record()
        backend._write_dva(
            PRIMARY_RECORD_B + g17p_initdata.COMPUTE_DISPATCH_RECORD_STRIDE,
            compute_dispatch,
        )
        backend._clean_dva_range(
            PRIMARY_RECORD_B + g17p_initdata.COMPUTE_DISPATCH_RECORD_STRIDE,
            len(compute_dispatch),
        )
        print(
            "SOURCE COMPUTE INITIAL built compute dispatch record at %#x" %
            (PRIMARY_RECORD_B +
             g17p_initdata.COMPUTE_DISPATCH_RECORD_STRIDE),
            flush=True,
        )
        workload_capacity = (
            repeat_workloads if client_workload_capacity is None else
            int(client_workload_capacity))
        if workload_capacity < repeat_workloads:
            raise ValueError(
                "client workload capacity cannot be smaller than the "
                "executed workload count")
        client = build_client_graph(
            backend,
            distinct_empty_high=(
                distinct_empty_client_high or distinct_empty_all_client_high
                or exact_client_context_table),
            native_shader_attributes=native_shader_attributes,
            workload_count=workload_capacity,
            client_slot_count=client_slot_count,
            dispatch_grids=client_dispatch_grids,
            threadgroups=client_threadgroups,
            indirect_dispatch=indirect_dispatch,
            indirect_layout=indirect_layout,
        )
        if client_setup is not None:
            client_setup(backend, client)
        context2_graft = (
            graft_missing_native_context2(
                client, native_context2_graft_addresses)
            if graft_native_context2_missing else [])
        empty_client_high_roots = {}
        if distinct_empty_all_client_high or exact_client_context_table:
            for context in ((0,) if mixed_render_compute_dependency else (0, 1)):
                high_root = backend.u.memalign(PAGE, PAGE)
                backend.u.proxy.memset32(high_root, 0, PAGE)
                backend.u.proxy.dc_civac(high_root, PAGE)
                backend.space.uat.set_l0(
                    context, 1, high_root, context)
                empty_client_high_roots[context] = high_root
            backend.space.uat.flush_dirty()
            backend.space.uat.invalidate_cache()
            backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
            print(
                "SOURCE COMPUTE INITIAL installed distinct empty client "
                "high roots: %s" % ", ".join(
                    "context %d=%#x" % item
                    for item in sorted(empty_client_high_roots.items())),
                flush=True,
            )
        if exact_client_context_table:
            live_client_contexts = {0, 1, 2}
            # Native command 1 and every later command use client context 3.
            # Keep that root whenever the caller built capacity for later
            # work, even if this bootstrap executes only command 0 itself.
            if workload_capacity > 1:
                live_client_contexts.add(3)
            for context in range(3, backend.space.uat.NUM_CONTEXTS):
                if context in live_client_contexts:
                    continue
                backend.u.proxy.write64(
                    backend.space.uat.gpu_region + context * 16, 0)
                backend.u.proxy.write64(
                    backend.space.uat.gpu_region + context * 16 + 8, 0)
            backend.u.proxy.dc_civac(
                backend.space.uat.gpu_region,
                backend.space.uat.NUM_CONTEXTS * 16,
            )
            backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
            live_slots = []
            for context in range(backend.space.uat.NUM_CONTEXTS):
                low = int(backend.u.proxy.read64(
                    backend.space.uat.gpu_region + context * 16))
                high = int(backend.u.proxy.read64(
                    backend.space.uat.gpu_region + context * 16 + 8))
                if low or high:
                    live_slots.append((context, low, high))
            if [slot for slot, _low, _high in live_slots] != sorted(
                    live_client_contexts):
                raise RuntimeError(
                    "exact client table retained unexpected slots %r" %
                    live_slots)
            print(
                "SOURCE COMPUTE INITIAL hardware context table contains "
                "only client slots %s" % ", ".join(
                    str(slot) for slot in sorted(live_client_contexts)),
                flush=True,
            )
        queue = build_firmware_graph(
            backend, client["terminator"], client["space"],
            alias_context0_queue=alias_context0_queue,
            item_capacity=(
                repeat_workloads if firmware_item_capacity is None else
                int(firmware_item_capacity)),
            fresh_command3_style=fresh_command3_style_fourth,
            indirect_dispatch=indirect_dispatch,
            resource_base=client["resource_base"],
            cdm_base=client["cdm_base"],
            status_addresses=client.get("status_addresses"),
            user_timestamp_addresses=client.get(
                "user_timestamp_addresses"))

        index_bias = int(queue_index_bias)
        if index_bias:
            if index_bias < 0:
                raise ValueError("compute queue index bias must be nonnegative")
            final_write = index_bias + 3 + 2 * (int(repeat_workloads) - 1)
            if final_write * g17p.ITEM_RING_ENTRY_SIZE > 0x2870:
                raise ValueError(
                    "biased compute queue exceeds its item ring: %#x" %
                    final_write)
            for offset in (
                    g17p.QUEUE_PTR_DONE,
                    g17p.QUEUE_PTR_READ,
                    g17p.QUEUE_PTR_WRITE):
                backend._write_dva(
                    queue.pointers_addr + offset,
                    struct.pack("<I", index_bias))
            backend._write_dva(
                queue.address + g17p.QUEUE_GPU_RPTR2,
                struct.pack("<I", index_bias))
            print(
                "SOURCE COMPUTE initialized consumed queue history at %#x" %
                index_bias,
                flush=True,
            )

        entry = backend.channels.by_name("CL_2")
        if entry is None:
            raise RuntimeError("cold boot exposes no CL_2 channel")
        # The output-positive checkpoint has CL2 visible when fresh firmware
        # starts and consumes it from the startup wake.  Publish the producer
        # now; this experiment deliberately sends no later work doorbell.
        backend.submitter.deferred_producers = (
            [] if post_start_initial else None)
        initial = getattr(queue, "initial_spec", {
            "descriptor": DESCRIPTOR,
            "optional": OPTIONAL,
            "event": EVENT,
        })
        published = backend.submitter.stage(
            entry,
            queue,
            (initial["descriptor"], initial["optional"], initial["event"]),
            group_number=1,
            slot=0,
            first_submit=True,
            kind="compute",
            announce=False,
            event_counter_low=2,
        )
        for address, size in (
            (queue.item_ring, 0x18),
            (queue.pointers_addr, 0x80),
            (queue.address, g17p.QUEUE_RECORD_STRIDE),
            (OUTER_RING, g17p.RING_SLOT_SIZE),
        ):
            backend._clean_dva_range(address, size)
        backend.space.flush()
        backend.u.inst("dsb sy")

        prepublished = None
        if prepublish_second:
            prepublished = stage_next_workload(
                backend,
                client,
                queue,
                1,
                require_previous_retired=False,
                notify=False,
            )
            print(
                "SOURCE COMPUTE INITIAL prepublished workload 1 before "
                "initdata: queue=%r channel=%r publication=%r" % (
                    prepublished["work_queue"].indices(),
                    backend.channels.counters(entry),
                    prepublished["publication"],
                ),
                flush=True,
            )

        backend.u.proxy.dc_ivac(client["output_pa"], 256)
        before = bytes(backend.u.iface.readmem(client["output_pa"], 256))
        if any(before):
            raise RuntimeError("source compute output is nonzero before startup")
        staged.update({
            "backend": backend,
            "client": client,
            "entry": entry,
            "queue": queue,
            "published": published,
            "before": before,
            "control": control,
            "grafted_config": grafted_config,
            "empty_client_high_roots": empty_client_high_roots,
            "context2_graft": context2_graft,
            "prepublished": prepublished,
            "initial_deferred_producers": (
                list(backend.submitter.deferred_producers)
                if post_start_initial else []),
            "region_c": struct.unpack(
                "<Q", backend._read_dva(
                    instances[0]["root_va"] + g17p_initdata.ROOT_REGION_C,
                    8,
                ),
            )[0],
        })

        prepared = getattr(boot, "RELOCATED_PREPARED", None)
        if prepared is None:
            raise RuntimeError("relocated boot exposed no prepared render group")
        deferred = prepared["submitter"].deferred_producers
        if deferred is None or len(deferred) != 2:
            raise RuntimeError(
                "expected two withheld render producers, got %r" % deferred)
        staged["render_prepared"] = prepared
        staged["render_deferred_producers"] = list(deferred)
        target_page = G17P_RETAINED_TARGET & ~(PAGE - 1)
        target_pa = prepared["render_extent"].get(target_page)
        if target_pa is None:
            raise RuntimeError(
                "retained render target %#x is not mapped" % target_page)
        backend.u.proxy.dc_ivac(target_pa, PAGE)
        staged["render_target_pa"] = target_pa
        staged["render_target_before"] = bytes(
            backend.u.iface.readmem(target_pa, PAGE))
        if not mixed_render_compute_dependency:
            # The completed compute checkpoint rewrites dormant TA/3D state,
            # so ordinary compute tests remove the unused render publication.
            deferred.clear()
            prepared["submitter"].deferred_producers = None
        staged["startup_visible"] = True

        if not mixed_render_compute_dependency:
            boot.FINAL_26_6_FIRST_WORK = None
            boot.FINAL_26_6_FIRST_WORK_PREPARE = None
        boot.NO_FIRST_DOORBELL[0] = True
        print(
            "SOURCE COMPUTE INITIAL %s field-built CL2 and %s before "
            "initdata%s: "
            "queue=%r channel=%r output_pa=%#x" % (
                ("staged" if post_start_initial else "published"),
                ("preserved the normal render opening"
                 if mixed_render_compute_dependency
                 else "completed control history"),
                (" with producer withheld" if post_start_initial
                 else ", with no later doorbell"),
                queue.indices(), backend.channels.counters(entry),
                client["output_pa"]),
            flush=True,
        )

    boot.apply_scalars = stage_before_initdata
    state = boot.main(list(DRMAsahiShim.G17P_COLD_BOOT_ARGS), return_state=True)
    if not staged or not staged.get("startup_visible"):
        raise RuntimeError("source compute startup visibility was not preserved")

    backend = staged["backend"]
    client = staged["client"]

    def switch_to_fresh_outer_ring():
        """Move CL2 to untouched backing while preserving its ABI offset."""
        entry = staged["entry"]
        old_ring = int(entry["ring_addr"])
        page_offset = old_ring & (PAGE - 1)
        if page_offset + 256 * g17p.RING_SLOT_SIZE > PAGE:
            raise RuntimeError("CL2 ring does not fit in one firmware page")

        fresh_page = 0xFFFFFC20C0A00000
        while True:
            translated = backend.space.uat.iotranslate_root(
                backend.firmware_high_root, fresh_page, PAGE)
            if not translated or translated[0][0] is None:
                break
            fresh_page += PAGE
        backend._ensure_firmware_range(fresh_page, PAGE)
        fresh_ring = fresh_page + page_offset
        if any(backend._read_dva(fresh_page, PAGE)):
            raise RuntimeError("fresh CL2 outer-ring page is not zero")

        table_pointer = (
            backend.channels.main_config + g17p.CHANNEL_TABLE_OFFSET
            + int(entry["index"]) * g17p.CHANNEL_ENTRY_SIZE
            + g17p.CHANNEL_ENTRY_RING_OFFSET)
        backend._write_dva(table_pointer, struct.pack("<Q", fresh_ring))
        backend._clean_dva_range(table_pointer, 8)
        backend._clean_dva_range(fresh_page, PAGE)
        backend.space.flush()
        backend.u.inst("dsb sy; tlbi vmalle1os; dsb sy; isb")
        if struct.unpack("<Q", backend._read_dva(table_pointer, 8))[0] != fresh_ring:
            raise RuntimeError("CL2 fresh outer-ring pointer did not read back")
        entry["ring_addr"] = fresh_ring
        print(
            "SOURCE COMPUTE moved CL2 outer ring %#x -> %#x at counters %r" % (
                old_ring, fresh_ring, backend.channels.counters(entry)),
            flush=True,
        )

    def pump_events():
        for asc in state["ascs"]:
            if asc.has_messages():
                asc.work()

    def drain_mailboxes(label):
        if not drain_runtime_mailboxes:
            return
        counts = []
        for asc in state["ascs"]:
            count = 0
            while count < 64 and asc.has_messages():
                asc.work()
                count += 1
            if asc.has_messages():
                raise RuntimeError(
                    "%s mailbox did not drain within 64 records" %
                    asc.g17p_name)
            counts.append(count)
        print(
            "SOURCE COMPUTE drained runtime mailboxes %s: primary=%d "
            "secondary=%d" % (label, counts[0], counts[1]),
            flush=True,
        )

    def drain_reports(label, ordinal):
        if not drain_runtime_reports:
            return
        interval = max(1, int(drain_runtime_report_interval))
        if (ordinal + 1) % interval:
            return
        touched = len(backend.acknowledge_report_channels())
        print(
            "SOURCE COMPUTE drained runtime report counters %s: "
            "touched=%d" % (label, touched),
            flush=True,
        )

    def sync_control_shadow(label):
        if not sync_region_c_control_shadow:
            return
        counters = backend.channels.counters(staged["control"])
        value = (int(counters[0]) + 1) & 0xffffffff
        address = staged["region_c"] + 0x80
        backend._write_dva(address, struct.pack("<I", value))
        backend._clean_dva_range(address, 4)
        backend.space.flush()
        backend.u.inst("dsb sy")
        print(
            "SOURCE COMPUTE synced region_c +0x80 %s: %#x "
            "(primary control %r)" % (label, value, counters),
            flush=True,
        )

    def runtime_doorbell(channel=0):
        state["ascs"][0].db.send(state["doorbell_message"](
            TYPE=g17p.MSG_WORK_DOORBELL,
            CHANNEL=int(channel),
        ))

    def runtime_control_done():
        state["ascs"][0].db.send(
            state["control_message"](0x0084000000000011))

    # The backend is created before the live ASC endpoints exist, with a
    # deliberate no-op doorbell for its startup-visible command. Later work
    # uses the primary endpoint returned by boot.main().
    backend.submitter.doorbell = runtime_doorbell
    backend.event_pump = pump_events
    backend.control_done = runtime_control_done
    backend.runtime_pair_register = state.get("register_runtime_pair")
    backend.runtime_submission_announce = state.get(
        "announce_runtime_submission")

    def execute_native_gate(label):
        class1_support = 0xFFFFFC20C08C0000
        class1_state = 0xFFFFFC2001678000
        backend._ensure_firmware_range(class1_support, PAGE)
        backend._ensure_firmware_range(class1_state, PAGE)
        class2 = compute.build_compute_class2_support(
            OPERAND_TABLE,
            0,
            SUPPORT_STATE,
            active=0,
            resource_class=0x17,
            cursor=0xB8,
            final_kind=3,
        )
        class1 = compute.build_compute_class1_support(
            OPERAND_TABLE,
            0,
            class1_state,
            active=1,
            resource_class=0x11,
            cursor=0x88,
            final_kind=2,
        )
        for address, body in (
                (SHARED_SUPPORT, class2),
                (SUPPORT_STATE, compute.build_compute_shared_state(1)),
                (class1_support, class1),
                (class1_state, compute.build_compute_shared_state(1)),
                (OPERAND_TABLE, bytes(PAGE))):
            backend._write_dva(address, body)
            backend._clean_dva_range(address, PAGE)
        backend.space.flush()
        backend.u.inst("dsb sy")

        gate_bodies = (
            _registration(
                2, 63, SHARED_SUPPORT, OPERAND_TABLE,
                0x5C0, 0x28,
                context_word=pre_runtime_native_gate_context),
            _tick(63, context_word=pre_runtime_native_gate_context),
            _registration(
                1, 64, class1_support, OPERAND_TABLE,
                0x440, 0x20, context_word=1),
            _tick(64, context_word=1),
        )
        if pre_runtime_native_class2_only:
            gate_bodies = gate_bodies[:2]
        result = state["announce_control_bodies"](
            gate_bodies, label)
        if result["crashed"] is not None or not result["consumed"]:
            raise RuntimeError("%s did not retire: %r" % (label, result))
        print(
            "SOURCE COMPUTE native gate PASS: controls=%r" %
            (state["read_control_counters"](),),
            flush=True,
        )

    if pre_initial_native_gate:
        if not post_start_initial:
            raise ValueError(
                "pre-initial native gate requires a deferred first producer")
        execute_native_gate("source compute pre-initial native gate")

    if mixed_render_compute_dependency:
        render = staged["render_prepared"]
        startup_submission = {}
        for name, kind in (("TA_0", "tiling"), ("3D_0", "fragment")):
            queue = render["queues"][name]
            published = render["staged"][name]
            indices = queue.indices()
            if indices["write"] != published["write_after"]:
                raise RuntimeError(
                    "render-first mixed dependency lost %s head: %r" % (
                        name, indices))
            entry = render["channels"].by_name(name)
            startup_submission[kind] = {
                "entry": entry,
                "queue": queue,
                "published": published,
            }

        # The relocated seed group is deliberately not an execution witness:
        # it is consumed during startup but does not touch the render target.
        # Retire its scheduler state, adopt its live graph, and publish a fresh
        # render through the final-26.6 runtime path that repeated-render tests
        # have already established as output-positive.
        backend.quiesce_submission(
            startup_submission, semantic_failed=True)
        backend.retained_extent = dict(render["render_extent"])
        backend.bound_submission = dict(render["bound_submission"])
        backend.adopt_completed_staged_group()

        params = render["render_state"]["parameters"]
        runtime_render = G17PCommandBuffer(
            width=params.width,
            height=params.height,
            encoder_ptr=params.encoder,
            store_pipeline=params.store_pipeline,
            store_pipeline_bind=params.store_pipeline_bind,
            load_pipeline=params.load_pipeline,
            load_pipeline_bind=params.load_pipeline_bind,
            scissor_array=params.scissor_array,
            deflake_1=params.deflake_1,
            deflake_2=params.deflake_2,
            deflake_3=params.deflake_3,
            aux_fb=params.aux_fb,
            heapmeta=params.heapmeta,
            utile_config=params.utile_config,
            multisample_control=params.multisample_control,
            ppp_control=params.ppp_control,
            tib_blocks=params.tib_blocks,
            tile_config=params.tile_config,
            shared=None,
            pools=None,
            tiling_optional=dict(
                render["context_state"]["pointers"]["tiling"]),
            fragment_optional=dict(
                render["context_state"]["pointers"]["fragment"]),
        )

        target_pa = staged["render_target_pa"]
        backend.u.proxy.memset32(target_pa, 0, PAGE)
        backend.u.proxy.dc_civac(target_pa, PAGE)
        backend.u.inst("dsb sy")
        staged["render_target_before"] = bytes(
            backend.u.iface.readmem(target_pa, PAGE))
        if any(staged["render_target_before"]):
            raise RuntimeError("runtime render dependency target did not clear")

        render_submission = backend.submit(runtime_render)
        render_fences = {
            kind: G17PQueueFence(
                backend.submitter,
                render_submission[kind]["entry"],
                render_submission[kind]["queue"],
                render_submission[kind]["published"],
                name="runtime render mixed dependency %s" % kind,
            )
            for kind in ("tiling", "fragment")
        }
        for fence in render_fences.values():
            fence.wait(timeout=0.2, event_pump=backend.event_pump)

        backend.u.proxy.dc_ivac(target_pa, PAGE)
        render_after = bytes(backend.u.iface.readmem(target_pa, PAGE))
        if render_after == staged["render_target_before"]:
            raise RuntimeError(
                "runtime render mixed dependency completed without target bytes")
        staged["mixed_render_after"] = render_after

        backend.quiesce_submission(
            render_submission, semantic_complete=True)

        # The compute-only positive checkpoint starts with these records and
        # counters already complete. Install that same field-built checkpoint
        # only after the startup render has physically executed.
        staged["control"] = seed_completed_control_history(backend)
        print(
            "SOURCE MIXED runtime-render PASS: both queue fences signaled "
            "and target PA %#x changed before the compute checkpoint was "
            "installed" % target_pa,
            flush=True,
        )

    if post_start_initial:
        deferred = staged["initial_deferred_producers"]
        if len(deferred) != 1:
            raise RuntimeError(
                "post-start initial compute expected one deferred producer, "
                "got %r" % (deferred,))
        for address, value in deferred:
            backend._write_dva(address, value)
            backend._clean_dva_range(address, len(value))
        backend.submitter.deferred_producers = None
        backend.space.flush()
        backend.u.inst("dsb sy")
        backend.submitter.notify(WORK_DOORBELL_CHANNEL)
        print(
            "SOURCE COMPUTE INITIAL published deferred CL2 producer after "
            "firmware start and rang channel %d" % WORK_DOORBELL_CHANNEL,
            flush=True,
        )

    expected = struct.pack("<64f", *client["expected"])
    after = staged["before"]
    deadline = time.monotonic() + 0.1
    while time.monotonic() < deadline:
        for asc in state["ascs"]:
            if asc.has_messages():
                asc.work()
        backend.u.proxy.dc_ivac(client["output_pa"], len(expected))
        after = bytes(backend.u.iface.readmem(
            client["output_pa"], len(expected)))
        if after == expected:
            break
        time.sleep(0.0001)

    changed = sum(a != b for a, b in zip(staged["before"], after))
    if client.get("indirect_dispatch"):
        resource_pa = client["objects"]["resource"][1]
        geometry_pa = resource_pa + compute.INDIRECT_GEOMETRY_OFFSET
        backend.u.proxy.dc_ivac(
            geometry_pa, compute.INDIRECT_GEOMETRY_WORDS * 4)
        geometry = struct.unpack(
            "<6I", backend.u.iface.readmem(
                geometry_pa, compute.INDIRECT_GEOMETRY_WORDS * 4))
        print(
            "SOURCE COMPUTE INDIRECT geometry=%r at PA %#x" % (
                geometry, geometry_pa),
            flush=True,
        )
    print(
        "SOURCE COMPUTE INITIAL result changed=%d queue=%r channel=%r artifact=%s" % (
            changed,
            staged["queue"].indices(),
            backend.channels.counters(staged["entry"]),
            state["artifact"],
        ),
        flush=True,
    )
    if after != expected:
        raise RuntimeError("source compute initial output did not match add3")
    print(
        "SOURCE COMPUTE INITIAL PASS: exact 64-float add3 output, "
        "grafted_config_pages=%d distinct_empty_client_high=%d "
        "distinct_empty_all_client_high=%d exact_client_context_table=%d "
        "alias_context0_queue=%d native_shader_attributes=%d "
        "native_context2_graft_pages=%d" % (
            len(staged["grafted_config"]), distinct_empty_client_high,
            distinct_empty_all_client_high, exact_client_context_table,
            alias_context0_queue, native_shader_attributes,
            len(staged["context2_graft"])),
        flush=True,
    )
    drain_mailboxes("after initial command")
    drain_reports("after initial command", 0)

    if native_control_tail:
        control_before = state["read_control_counters"]()["primary"]
        if control_before != [67, 67, 67]:
            raise RuntimeError(
                "native control suffix requires 67-entry prefix, got %r" %
                control_before)
        result = state["announce_control_bodies"](
            tuple(_tick(sequence) for sequence in range(0x3F, 0xA7)),
            "source compute native primary control suffix 0x3f..0xa6",
        )
        if result["crashed"] is not None or not result["consumed"]:
            raise RuntimeError(
                "native primary control suffix did not retire: %r" % result)
        control_after = state["read_control_counters"]()["primary"]
        if control_after != [171, 171, 171]:
            raise RuntimeError(
                "native control suffix ended at %r" % control_after)
        print(
            "SOURCE COMPUTE built and retired native primary control "
            "history through sequence 0xa6: %r" % control_after,
            flush=True,
        )

    if pre_runtime_native_gate and not pre_initial_native_gate:
        execute_native_gate(
            "source compute pre-runtime native class-2 gate"
            if pre_runtime_native_class2_only
            else "source compute pre-runtime native gate")

    if mixed_render_compute_dependency:
        target_pa = staged["render_target_pa"]
        render_before = staged["render_target_before"]
        render_after = staged["mixed_render_after"]

        dependency_offset = None
        dependency_values = None
        for offset in range(0, PAGE - 256 + 1, 4):
            body = render_after[offset:offset + 256]
            values = struct.unpack("<64f", body)
            if (body != render_before[offset:offset + 256]
                    and all(math.isfinite(value) for value in values)):
                dependency_offset = offset
                dependency_values = values
                break
        if dependency_offset is None:
            raise RuntimeError(
                "render target has no changed 64-float finite dependency window")

        alias = 0x10008000000
        flags = {
            "AttrIndex": MemoryAttr.Shared,
            "AP": 2,
            "nG": 1,
            "UXN": 1,
            "OS": 1,
        }
        client["space"].uat.iomap_at(
            client["space"].context, alias, target_pa, PAGE, **flags)
        client["space"].uat.flush_dirty()
        client["space"].uat.invalidate_cache()
        backend.u.proxy.dc_civac(target_pa, PAGE)
        backend.u.inst("dsb sy; tlbi aside1os, x0; dsb sy; isb", CONTEXT << 48)

        for _ in range(2):
            state["ascs"][0].db.send(state["doorbell_message"](
                TYPE=g17p.MSG_CONTROL_DONE,
                CHANNEL=g17p.CONTROL_DOORBELL_CHANNEL,
            ))
            pump_events()

        prepared_compute = stage_next_workload(
            backend,
            client,
            staged["queue"],
            1,
            require_previous_retired=True,
            notify=False,
            input_a_dependency={
                "expected": dependency_values,
                "output_dva": alias + dependency_offset,
            },
            persistent_runtime_queue=persistent_runtime_queue,
            persistent_startup_queue=persistent_startup_queue,
            persistent_runtime_optional_once=persistent_runtime_optional_once,
            persistent_runtime_fresh_descriptors=(
                persistent_runtime_fresh_descriptors),
            persistent_runtime_fresh_events=persistent_runtime_fresh_events,
            fast_sequential=fast_sequential,
            strict_release_publish=strict_release_publish,
        )
        backend.submitter.notify(WORK_DOORBELL_CHANNEL)
        computed = await_next_workload(backend, prepared_compute)
        print(
            "SOURCE MIXED RENDER->COMPUTE PASS: TA/3D fences signaled, "
            "startup render target changed, and compute consumed target "
            "PA %#x+%#x "
            "into exact output PA %#x" % (
                target_pa, dependency_offset,
                prepared_compute["workload"]["output_pa"],
            ),
            flush=True,
        )
        del computed
        return 0

    peer_snapshots = {}

    def capture_peer_boundary(kick):
        """Save only pages that changed across native kicks three and four."""
        if not capture_peer_boundaries:
            return
        if (capture_peer_ordinals and
                int(kick) not in {int(value) for value in capture_peer_ordinals}):
            return

        sgx = backend.u.adt["/arm-io/sgx"]
        kern_va_base = (
            int(sgx.rtkit_private_vm_region_base)
            + int(sgx.rtkit_private_vm_region_size)
        )
        private_offsets = {
            "primary": (
                0x01C000, 0x020000, 0x024000, 0x028000,
                0x0D8000, 0x0E0000, 0x0E4000, 0x11C000,
                0x120000, 0x128000, 0x12C000, 0x130000,
            ),
            "secondary": (
                0x00C000, 0x020000, 0x024000, 0x028000, 0x0DC000,
                0x114000, 0x118000, 0x11C000, 0x120000, 0x124000,
            ),
        }
        shared_offsets = (
            0x020000, 0x02C000, 0x030000, 0x0E0000,
            0x18C000, 0x190000, 0x194000, 0x1A0000,
        )
        private_regions = {
            "primary": (int(sgx.gfx_data_base), int(sgx.gfx_data_size)),
            "secondary": (int(sgx.gfx1_data_base), int(sgx.gfx1_data_size)),
        }

        artifact = pathlib.Path(state["artifact"]).parent
        directory = artifact / ("source_peer_kick_%02d" % kick)
        directory.mkdir(exist_ok=False)
        manifest = {
            "format": "m1n1-t8140-g17p-source-compute-peer-boundary-v1",
            "kick": int(kick),
            "kern_va_base": kern_va_base,
            "control": state["read_control_counters"](),
            "pages": [],
        }
        bodies = {}

        def save(name, address, offset, body, address_space):
            body = bytes(body)
            filename = "%s_%06x.bin" % (name, offset)
            (directory / filename).write_bytes(body)
            manifest["pages"].append({
                "name": name,
                "address": int(address),
                "offset": int(offset),
                "address_space": address_space,
                "file": filename,
                "sha256": hashlib.sha256(body).hexdigest(),
                "nonzero_bytes": sum(byte != 0 for byte in body),
            })
            bodies[(name, offset)] = body

        for name, offsets in private_offsets.items():
            base, size = private_regions[name]
            for offset in offsets:
                if offset + PAGE > size:
                    continue
                save(
                    name, base + offset, offset,
                    backend.u.iface.readmem(base + offset, PAGE),
                    "physical-private-data",
                )
        for offset in shared_offsets:
            save(
                "shared", kern_va_base + offset, offset,
                backend._read_dva(kern_va_base + offset, PAGE),
                "firmware-uat",
            )

        if peer_snapshots:
            previous_kick = max(peer_snapshots)
            changed = []
            for key, body in bodies.items():
                previous = peer_snapshots[previous_kick].get(key)
                if previous is None or previous == body:
                    continue
                changed.append({
                    "name": key[0],
                    "offset": key[1],
                    "changed_bytes": sum(
                        left != right
                        for left, right in zip(previous, body)
                    ),
                })
            manifest["delta_from_kick"] = previous_kick
            manifest["changed_pages"] = changed
        peer_snapshots[int(kick)] = bodies
        (directory / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(
            "SOURCE COMPUTE peer boundary kick %d: %d pages -> %s" % (
                kick, len(manifest["pages"]), directory),
            flush=True,
        )

    def capture_fourth_prepublish():
        """Save the compact source state that firmware sees before command four."""
        spec = _work_addresses(3)
        records = []
        raw = bytearray()

        def add(name, address, body, address_space):
            body = bytes(body)
            records.append({
                "name": name,
                "dva": int(address),
                "size": len(body),
                "address_space": address_space,
                "capture_offset": len(raw),
                "nonzero_bytes": sum(byte != 0 for byte in body),
            })
            raw.extend(body)

        def add_firmware(name, address, size):
            add(name, address, backend._read_dva(address, size), "firmware")

        def add_client(name, object_name, size=None):
            address, pa, extent = client["objects"][object_name]
            length = extent if size is None else min(int(size), extent)
            add(name, address, client["space"].read(pa, length), "client")

        add_firmware("descriptor", spec["descriptor"], 0x1000)
        add_firmware("optional", spec["optional"], 0xC0)
        add_firmware("event", spec["event"], 0x40)
        add_firmware("queue", spec["queue"], g17p.QUEUE_RECORD_STRIDE)
        add_firmware("queue_pointers", spec["pointers"], 0x80)
        add_firmware("item_ring_head", spec["item_ring"], 0x18)
        add_firmware(
            "outer_ring_slot",
            OUTER_RING + 3 * g17p.RING_SLOT_SIZE,
            g17p.RING_SLOT_SIZE,
        )
        add_firmware("queue_context_high", spec["context_high"], 0x400)
        add_firmware("scheduler", spec["scheduler"], 0x100)
        add_firmware("scheduler_slot", spec["scheduler_slot"], 4)
        add_firmware("shared_support", spec["shared_support"], 0x100)
        add_firmware("support_state", spec["support_state"], 0x40)
        add_firmware("channel_control", spec["channel_control"], 0x40)
        add_firmware("job_list", spec["job_list"], g17p.JOB_LIST_SIZE)
        add_firmware("dispatch_a", spec["dispatch_a"], 8)
        add_firmware("dispatch_b", spec["dispatch_b"], 8)
        add_firmware("status_a", spec["status_a"], 8)
        add_firmware("status_b", spec["status_b"], 8)
        # This main-config scheduler region is not reachable from the command
        # descriptor closure. Retain its live pre-kick contents so repeated
        # compute tests can distinguish scheduler lifecycle from a command-
        # graph mismatch.
        add_firmware(
            "primary_record_predecessor", 0xFFFFFC20015D8000, PAGE)
        add_firmware("primary_record_sentinel", 0xFFFFFC20C07C8000, PAGE)
        add_firmware("primary_record_a", 0xFFFFFC20015E0000, PAGE)
        add_firmware("primary_record_b", PRIMARY_RECORD_B, PAGE)

        command = "%02d" % 3
        add_client("resource", "resource_" + command, RESOURCE_SIZE)
        add_client("cdm", "cdm_" + command, 0x30)
        add_client("shader", "shader_" + command, SHADER_SIZE)
        add_client("input_a", "input_a_" + command, 0x100)
        add_client("input_b", "input_b_" + command, 0x100)
        add_client("output", "output_" + command, 0x100)

        control = backend.channels.entries[g17p.CHANNEL_TABLE_WORK_COUNT]
        counters = backend.channels.counters(control)
        add_firmware(
            "device_control_ring",
            control["ring_addr"],
            counters[2] * g17p.CONTROL_MESSAGE_SIZE,
        )
        artifact = pathlib.Path(state["artifact"]).parent
        binary = artifact / "source_command4_prepublish.bin"
        manifest = artifact / "source_command4_prepublish.json"
        binary.write_bytes(raw)
        manifest.write_text(json.dumps({
            "format": "m1n1-t8140-g17p-source-command4-prepublish-v1",
            "control_counters": counters,
            "secondary_control_counters": state["read_control_counters"]()[
                "secondary"],
            "objects": records,
            "binary": binary.name,
        }, indent=2, sort_keys=True) + "\n")
        print(
            "SOURCE COMPUTE command 4 prepublish snapshot: %d objects, "
            "%#x bytes -> %s" % (len(records), len(raw), manifest),
            flush=True,
        )

        native_pages = json.loads(
            (NATIVE_FOURTH_CAPTURE / "pages.json").read_text())["pages"]
        closure_raw = bytearray()
        closure_records = []
        skipped_low_pages = []
        unmapped_firmware_pages = []
        for native_page in native_pages:
            address = int(native_page["dva"])
            if address < 0xffff000000000000:
                skipped_low_pages.append({
                    "dva": address,
                    "sources": native_page.get("sources", []),
                })
                continue
            try:
                body = backend._read_dva(address, PAGE)
            except Exception as error:
                unmapped_firmware_pages.append({
                    "dva": address,
                    "error": str(error),
                    "sources": native_page.get("sources", []),
                })
                continue
            closure_records.append({
                "dva": address,
                "capture_offset": len(closure_raw),
                "nonzero_bytes": sum(byte != 0 for byte in body),
                "sources": native_page.get("sources", []),
            })
            closure_raw.extend(body)
        closure_binary = artifact / "source_command4_native_closure.bin"
        closure_manifest = artifact / "source_command4_native_closure.json"
        closure_binary.write_bytes(closure_raw)
        closure_manifest.write_text(json.dumps({
            "format": "m1n1-t8140-g17p-source-command4-native-closure-v1",
            "native_capture": str(NATIVE_FOURTH_CAPTURE),
            "page_size": PAGE,
            "pages": closure_records,
            "skipped_low_pages": skipped_low_pages,
            "unmapped_firmware_pages": unmapped_firmware_pages,
            "binary": closure_binary.name,
        }, indent=2, sort_keys=True) + "\n")
        print(
            "SOURCE COMPUTE command 4 native firmware closure snapshot: "
            "%d pages, %d low pages skipped, %d firmware pages unmapped, "
            "%#x bytes -> %s" % (
                len(closure_records), len(skipped_low_pages),
                len(unmapped_firmware_pages),
                len(closure_raw), closure_manifest),
            flush=True,
        )

    def capture_indirect_second_prepublish():
        """Save source-built command 2 exactly as firmware is about to see it."""
        artifact = pathlib.Path(state["artifact"]).parent
        directory = artifact / "source_indirect_command2_prepublish"
        directory.mkdir(exist_ok=False)
        raw = bytearray()
        records = []

        def add(name, address, body, address_space):
            body = bytes(body)
            records.append({
                "name": name,
                "dva": int(address),
                "size": len(body),
                "address_space": address_space,
                "capture_offset": len(raw),
                "nonzero_bytes": sum(byte != 0 for byte in body),
                "sha256": hashlib.sha256(body).hexdigest(),
            })
            raw.extend(body)

        native_pages = json.loads(
            (NATIVE_INDIRECT_SECOND_CAPTURE / "pages.json").read_text())["pages"]
        for page in native_pages:
            address = int(page["dva"])
            if address < 0xFFFF000000000000:
                continue
            try:
                body = backend._read_dva(address, PAGE)
            except Exception:
                continue
            add("firmware_page_%016x" % address, address, body, "firmware")

        client_names = (
            "resource", "cdm", "shader", "input_a", "input_b", "output",
            "indirect_arguments_00", "indirect_helper_binding_00",
            "indirect_helper_constant",
        )
        for name in client_names:
            if name not in client["objects"]:
                continue
            address, pa, size = client["objects"][name]
            add(name, address, client["space"].read(pa, size), "client")

        binary = directory / "objects.bin"
        manifest = directory / "manifest.json"
        binary.write_bytes(raw)
        manifest.write_text(json.dumps({
            "format": "m1n1-t8140-g17p-source-indirect-command2-v1",
            "native_capture": str(NATIVE_INDIRECT_SECOND_CAPTURE),
            "objects": records,
            "binary": binary.name,
            "control": state["read_control_counters"](),
        }, indent=2, sort_keys=True) + "\n")
        print(
            "SOURCE COMPUTE indirect command 2 prepublish snapshot: "
            "%d objects, %#x bytes -> %s" % (
                len(records), len(raw), manifest),
            flush=True,
        )

    soft_fault = {}

    def await_expected_soft_fault(prepared):
        """Require command retirement while its unmapped output stays zero."""
        record = soft_fault.get(prepared["ordinal"])
        if record is None:
            raise RuntimeError("soft-fault publication has no unmap record")
        deadline = time.monotonic() + 0.1
        while time.monotonic() < deadline and not prepared["fence"].signaled():
            pump_events()
            time.sleep(0.0001)
        backend.u.proxy.dc_ivac(record["pa"], len(prepared["expected"]))
        after = bytes(backend.u.iface.readmem(
            record["pa"], len(prepared["expected"])))
        queue_state = prepared["work_queue"].indices()
        channel_state = backend.channels.counters(prepared["entry"])
        if after != prepared["before"]:
            raise RuntimeError(
                "soft-fault workload %d changed unmapped output PA %#x" % (
                    prepared["ordinal"], record["pa"]))
        if not prepared["fence"].signaled():
            raise RuntimeError(
                "soft-fault workload %d did not signal its queue fence: "
                "queue=%r channel=%r" % (
                    prepared["ordinal"], queue_state, channel_state))
        if queue_state["done"] < prepared["publication"]["write_after"]:
            raise RuntimeError(
                "soft-fault workload %d did not retire its queue: %r" % (
                    prepared["ordinal"], queue_state))
        if not all(g17p.producer_reached(
                start, current, prepared["publication"]["producer"])
                for start, current in zip(
                    prepared["channel_before"][:2], channel_state[:2])):
            raise RuntimeError(
                "soft-fault workload %d did not retire its channel: %r" % (
                    prepared["ordinal"], channel_state))
        print(
            "SOURCE COMPUTE SOFT-FAULT %02d PASS: unmapped output DVA %#x "
            "PA %#x remained exact zero while queue=%r channel=%r and fence "
            "sequence %d signaled" % (
                prepared["ordinal"], record["dva"], record["pa"],
                queue_state, channel_state, prepared["fence"].sequence),
            flush=True,
        )
        return {
            "workload": prepared["workload"],
            "changed": 0,
            "queue": queue_state,
            "channel": channel_state,
            "publication": prepared["publication"],
            "fence_object": prepared["fence"],
            "fence": prepared["fence"].snapshot(),
            "soft_fault": True,
        }

    repeated = []
    first_runtime_ordinal = 1
    if staged["prepublished"] is not None:
        result = await_next_workload(backend, staged["prepublished"])
        drain_mailboxes("after workload 1")
        drain_reports("after workload 1")
        print(
            "SOURCE COMPUTE prepublished workload 1 completed with control "
            "state %r" % (state["read_control_counters"](),),
            flush=True,
        )
        repeated.append(result)
        first_runtime_ordinal = 2
    for ordinal in range(first_runtime_ordinal, int(repeat_workloads)):
        if inter_submit_dependency_pair and ordinal == 1:
            timeline = G17PSyncObject(timeline=True)
            prepared_one = stage_next_workload(
                backend,
                client,
                staged["queue"],
                1,
                require_previous_retired=True,
                notify=False,
                persistent_runtime_queue=persistent_runtime_queue,
                persistent_startup_queue=persistent_startup_queue,
                persistent_runtime_optional_once=(
                    persistent_runtime_optional_once),
                persistent_runtime_fresh_descriptors=(
                    persistent_runtime_fresh_descriptors),
                persistent_runtime_fresh_events=(
                    persistent_runtime_fresh_events),
                fast_sequential=fast_sequential,
                strict_release_publish=strict_release_publish,
            )
            timeline.bind(prepared_one["fence"], 1)
            if timeline.signaled(1):
                raise RuntimeError("inter-submit out-fence signaled early")
            backend.submitter.notify(WORK_DOORBELL_CHANNEL)
            timeline.wait(1, timeout=0.1, event_pump=backend.event_pump)
            result_one = await_next_workload(backend, prepared_one)

            prepared_two = stage_next_workload(
                backend,
                client,
                staged["queue"],
                2,
                require_previous_retired=True,
                notify=False,
                input_a_dependency=prepared_one["workload"],
                persistent_runtime_queue=persistent_runtime_queue,
                persistent_startup_queue=persistent_startup_queue,
                persistent_runtime_optional_once=(
                    persistent_runtime_optional_once),
                persistent_runtime_fresh_descriptors=(
                    persistent_runtime_fresh_descriptors),
                persistent_runtime_fresh_events=(
                    persistent_runtime_fresh_events),
                fast_sequential=fast_sequential,
                strict_release_publish=strict_release_publish,
            )
            timeline.bind(prepared_two["fence"], 2)
            if timeline.signaled(2):
                raise RuntimeError("second inter-submit out-fence signaled early")
            backend.submitter.notify(WORK_DOORBELL_CHANNEL)
            timeline.wait(2, timeout=0.1, event_pump=backend.event_pump)
            result_two = await_next_workload(backend, prepared_two)
            repeated.extend((result_one, result_two))
            print(
                "SOURCE COMPUTE INTER-SUBMIT DEPENDENCY PASS: timeline point "
                "1 gated publication of the point-2 consumer",
                flush=True,
            )
            break
        if batch_dependency_pair and ordinal == 1:
            prepared_one = stage_next_workload(
                backend,
                client,
                staged["queue"],
                1,
                require_previous_retired=True,
                notify=False,
                persistent_runtime_queue=persistent_runtime_queue,
                persistent_startup_queue=persistent_startup_queue,
                persistent_runtime_optional_once=(
                    persistent_runtime_optional_once),
                persistent_runtime_fresh_descriptors=(
                    persistent_runtime_fresh_descriptors),
                persistent_runtime_fresh_events=(
                    persistent_runtime_fresh_events),
                fast_sequential=fast_sequential,
                persistent_runtime_recycle_interval=(
                    persistent_runtime_recycle_interval),
                persistent_runtime_context_record_count=(
                    persistent_runtime_context_record_count),
                persistent_runtime_alternating_contexts=(
                    persistent_runtime_alternating_contexts),
                persistent_runtime_preserve_context_reuse=(
                    persistent_runtime_preserve_context_reuse),
                persistent_runtime_optional_skip_ordinals=(
                    persistent_runtime_optional_skip_ordinals),
                strict_release_publish=strict_release_publish,
            )
            prepared_two = stage_next_workload(
                backend,
                client,
                staged["queue"],
                2,
                require_previous_retired=False,
                notify=not verify_sync_objects,
                input_a_dependency=prepared_one["workload"],
                persistent_runtime_queue=persistent_runtime_queue,
                persistent_startup_queue=persistent_startup_queue,
                persistent_runtime_optional_once=(
                    persistent_runtime_optional_once),
                persistent_runtime_fresh_descriptors=(
                    persistent_runtime_fresh_descriptors),
                persistent_runtime_fresh_events=(
                    persistent_runtime_fresh_events),
                fast_sequential=fast_sequential,
                persistent_runtime_recycle_interval=(
                    persistent_runtime_recycle_interval),
                persistent_runtime_context_record_count=(
                    persistent_runtime_context_record_count),
                persistent_runtime_alternating_contexts=(
                    persistent_runtime_alternating_contexts),
                persistent_runtime_preserve_context_reuse=(
                    persistent_runtime_preserve_context_reuse),
                persistent_runtime_optional_skip_ordinals=(
                    persistent_runtime_optional_skip_ordinals),
                strict_release_publish=strict_release_publish,
            )
            binary_one = binary_two = timeline = None
            if verify_sync_objects:
                binary_one = G17PSyncObject()
                binary_two = G17PSyncObject()
                timeline = G17PSyncObject(timeline=True)
                binary_one.bind(prepared_one["fence"])
                binary_two.bind(prepared_two["fence"])
                timeline.bind(prepared_one["fence"], 1)
                timeline.bind(prepared_two["fence"], 2)
                if (binary_one.signaled() or binary_two.signaled() or
                        timeline.signaled(1)):
                    raise RuntimeError(
                        "compute sync object signaled before its doorbell")
                backend.submitter.notify(WORK_DOORBELL_CHANNEL)
            result_one = await_next_workload(backend, prepared_one)
            result_two = await_next_workload(backend, prepared_two)
            if verify_sync_objects:
                if not (binary_one.signaled() and binary_two.signaled() and
                        timeline.signaled(1) and timeline.signaled(2) and
                        timeline.query() == 2):
                    raise RuntimeError(
                        "compute sync objects did not follow queue fences")
                print(
                    "SOURCE COMPUTE SYNCOBJ PASS: binary fences 6/9 and "
                    "timeline points 1/2 signaled from one doorbell",
                    flush=True,
                )
            repeated.extend((result_one, result_two))
            print(
                "SOURCE COMPUTE DEPENDENCY PASS: workload 2 consumed workload "
                "1 output from one batched queue publication",
                flush=True,
            )
            break
        if batch_final_pair and ordinal == 2:
            def before_batch_publish():
                state["announce_runtime_tick"](
                    63,
                    "source compute pre-workload 2 tick 0x3f",
                    context_word=CONTEXT + 1,
                    update_sequence=True,
                )

            try:
                prepared_two = stage_next_workload(
                    backend,
                    client,
                    staged["queue"],
                    2,
                    before_publish=before_batch_publish,
                    require_previous_retired=True,
                    notify=True,
                )
                admission_deadline = time.monotonic() + 0.1
                admission_state = backend.channels.counters(staged["entry"])
                while time.monotonic() < admission_deadline:
                    admission_state = backend.channels.counters(
                        staged["entry"])
                    if all(g17p.producer_reached(
                            start, current,
                            prepared_two["publication"]["producer"])
                           for start, current in zip(
                               prepared_two["channel_before"][:2],
                               admission_state[:2])):
                        break
                    pump_events()
                    time.sleep(0.0001)
                else:
                    raise RuntimeError(
                        "workload 2 was not admitted before workload 3: %r" %
                        admission_state)
                print(
                    "SOURCE COMPUTE workload 2 admitted before workload 3: "
                    "CL2=%r queue=%r" % (
                        admission_state,
                        prepared_two["work_queue"].indices()),
                    flush=True,
                )
                prepared_three = stage_next_workload(
                    backend,
                    client,
                    staged["queue"],
                    3,
                    require_previous_retired=True,
                    notify=True,
                )
                print(
                    "SOURCE COMPUTE exposed workload 3 after workload 2 "
                    "admission: CL2=%r" % (
                        backend.channels.counters(staged["entry"]),),
                    flush=True,
                )
                result_two = await_next_workload(backend, prepared_two)
                result_three = await_next_workload(backend, prepared_three)
            except Exception:
                print(
                    "SOURCE COMPUTE batched workloads 2/3 failed with "
                    "control state %r" % (
                        state["read_control_counters"](),),
                    flush=True,
                )
                raise
            repeated.extend((result_two, result_three))
            print(
                "SOURCE COMPUTE batched workloads 2/3 completed with "
                "control state %r" % (state["read_control_counters"](),),
                flush=True,
            )
            break
        try:
            before_publish = None
            after_publish = None
            if client.get("indirect_dispatch") and ordinal == 1:
                after_publish = capture_indirect_second_prepublish
            sparse_tick = False
            if sparse_runtime_tick_count:
                sparse_span = int(
                    sparse_runtime_tick_span
                    if sparse_runtime_tick_span is not None
                    else int(repeat_workloads) - 1)
                sparse_count = int(sparse_runtime_tick_count)
                if not 0 < sparse_count <= sparse_span:
                    raise ValueError(
                        "sparse runtime tick count must fit its span")
                sparse_tick = (
                    ordinal <= sparse_span and
                    (ordinal * sparse_count) // sparse_span >
                    ((ordinal - 1) * sparse_count) // sparse_span)
            if sparse_tick:
                tick_index = (
                    (ordinal * sparse_count) // sparse_span) - 1
                sequence = 0x3F + tick_index

                def before_publish(
                        sequence=sequence, ordinal=ordinal):
                    state["stage_runtime_tick"](
                        sequence,
                        "source compute sparse pre-workload %d tick %#x" % (
                            ordinal, sequence),
                        context_word=0,
                        update_sequence=True,
                    )
            elif suppress_runtime_controls:
                if native_control_tail:
                    control_now = state["read_control_counters"]()["primary"]
                    if control_now != [171, 171, 171]:
                        raise RuntimeError(
                            "native control history drifted before workload "
                            "%d: %r" % (ordinal, control_now))
            elif (couple_runtime_ticks and
                    not (persistent_runtime_tick_once and ordinal > 1)):
                sequence = ordinal - 1
                context_word = (
                    CONTEXT if native_runtime_tick_context
                    else (1 if ordinal >= 3 else 0))

                def before_publish(
                        sequence=sequence, ordinal=ordinal,
                        context_word=context_word):
                    state["stage_runtime_tick"](
                        sequence,
                        "source compute pending pre-workload %d tick %#x" % (
                            ordinal, sequence),
                        context_word=context_word,
                        update_sequence=True,
                    )
            elif couple_runtime_ticks and persistent_runtime_tick_once:
                print(
                    "SOURCE COMPUTE workload %d has no repeated runtime "
                    "control tick" % ordinal,
                    flush=True,
                )
            elif ordinal >= 2:
                sequence = 61 + ordinal

                def before_publish(sequence=sequence, ordinal=ordinal):
                    if ordinal == 3:
                        if fresh_command3_style_fourth:
                            print(
                                "SOURCE COMPUTE command-three-style workload "
                                "%d has no preceding control publication" %
                                ordinal,
                                flush=True,
                            )
                            return
                        if no_late_fourth_control:
                            print(
                                "SOURCE COMPUTE workload %d has no late "
                                "control publication, matching the native "
                                "third/fourth interval" % ordinal,
                                flush=True,
                            )
                            return
                        if native_fourth_class1_poststate:
                            pointer_array = bytearray(PAGE)
                            for index in range(36):
                                struct.pack_into(
                                    "<Q", pointer_array, index * 0x100,
                                    0xFFFFFC2001630000 + index * 4,
                                )
                            backend._write_dva(
                                0xFFFFFC20C0868000, pointer_array)
                            backend._write_dva(
                                0xFFFFFC2001630000, bytes(PAGE))
                            backend._clean_dva_range(
                                0xFFFFFC20C0868000, PAGE)
                            backend._clean_dva_range(
                                0xFFFFFC2001630000, PAGE)
                            backend.space.flush()
                            backend.u.inst("dsb sy")
                            print(
                                "SOURCE COMPUTE installed native command-four "
                                "post-class1 pointer array and zero state",
                                flush=True,
                            )
                        if native_fourth_class2_ancestry:
                            scheduler_page = bytearray(PAGE)
                            scheduler_state = bytearray(PAGE)
                            identities = (0x03000217, 0x03000245, 0x03000246)
                            for index in range(36):
                                struct.pack_into(
                                    "<Q", scheduler_page, index * 0x100,
                                    0xFFFFFC2001680000 + index * 4,
                                )
                            for work_id, identity in enumerate(identities):
                                offset = (work_id + 1) * 0x100
                                struct.pack_into(
                                    "<I", scheduler_page, offset + 0x08,
                                    work_id)
                                struct.pack_into(
                                    "<I", scheduler_page, offset + 0x0C, 1)
                                struct.pack_into(
                                    "<I", scheduler_page, offset + 0x10, 0x50)
                                struct.pack_into(
                                    "<I", scheduler_page, offset + 0x24, 3)
                                struct.pack_into(
                                    "<Q", scheduler_page, offset + 0xA0,
                                    0xFFFFFC2000000048)
                                struct.pack_into(
                                    "<I", scheduler_page, offset + 0xB8,
                                    identity)
                                struct.pack_into(
                                    "<I", scheduler_page, offset + 0xC0, 2)
                            for index in range(1, 5):
                                struct.pack_into(
                                    "<I", scheduler_state, index * 4, 1)
                            current = 4 * 0x100
                            struct.pack_into(
                                "<I", scheduler_page, current + 0x08, 3)
                            struct.pack_into(
                                "<I", scheduler_page, current + 0x10, 0x50)
                            backend._write_dva(
                                0xFFFFFC20C08C8000, scheduler_page)
                            backend._write_dva(
                                0xFFFFFC2001680000, scheduler_state)
                            backend._clean_dva_range(
                                0xFFFFFC20C08C8000, PAGE)
                            backend._clean_dva_range(
                                0xFFFFFC2001680000, PAGE)
                            backend.space.flush()
                            backend.u.inst("dsb sy")
                            print(
                                "SOURCE COMPUTE installed native command-four "
                                "class-2 scheduler ancestry",
                                flush=True,
                            )
                        registered = state["register_compute_class2"](
                            SHARED_SUPPORT,
                            OPERAND_TABLE,
                            slot_offset=0x5C0,
                            context_word=1,
                            count=0x28,
                        )
                        state["announce_runtime_tick"](
                            registered["sequence"] + 1,
                            "source compute pre-workload 3 trailing tick",
                            context_word=1,
                            update_sequence=True,
                        )
                        spec = _work_addresses(ordinal)
                        backend._write_dva(
                            spec["support_state"] + 0x08, bytes(8))
                        backend._clean_dva_range(
                            spec["support_state"] + 0x08, 8)
                        backend.space.flush()
                        backend.u.inst("dsb sy")
                        print(
                            "SOURCE COMPUTE restored native command-four "
                            "support-state flags at +0x08/+0x0c",
                            flush=True,
                        )
                        if native_fourth_record_b:
                            record_b = bytearray(PAGE)
                            struct.pack_into(
                                "<5I", record_b, 0x00,
                                0xE0031A00, 0x08000000, 0x00002200,
                                0x00002C20, 0x00001500,
                            )
                            struct.pack_into(
                                "<5I", record_b, 0x20,
                                0xE0000000, 0x08000000, 0x00001B00,
                                0x00002BB0, 0x00001500,
                            )
                            backend._write_dva(PRIMARY_RECORD_B, record_b)
                            backend._clean_dva_range(PRIMARY_RECORD_B, PAGE)
                            backend.space.flush()
                            backend.u.inst("dsb sy")
                            print(
                                "SOURCE COMPUTE installed native command-four "
                                "primary record page B",
                                flush=True,
                            )
                    else:
                        state["announce_runtime_tick"](
                            sequence,
                            "source compute pre-workload %d tick %#x" % (
                                ordinal, sequence),
                            context_word=(
                                (2 if native_runtime_tick_context else
                                 (CONTEXT if ordinal == 0 else CONTEXT + 1))),
                            update_sequence=True,
                        )
                if ordinal == 3:
                    after_publish = capture_fourth_prepublish
            original_before_publish = before_publish

            def before_publish_with_shadow(
                    callback=original_before_publish, ordinal=ordinal):
                if callback is not None:
                    callback()
                if (fresh_outer_ring_at is not None and
                        ordinal == int(fresh_outer_ring_at)):
                    switch_to_fresh_outer_ring()
                sync_control_shadow("before workload %d" % ordinal)
                if ordinal == soft_fault_ordinal:
                    output = client["outputs"][
                        ordinal % len(client["outputs"])]
                    translation = client["space"].uat.iotranslate(
                        CONTEXT, output["dva"], PAGE)
                    if (not translation or
                            any(pa is None for pa, _span in translation)):
                        raise RuntimeError(
                            "soft-fault output DVA %#x was not mapped: %r" % (
                                output["dva"], translation))
                    backend.u.proxy.dc_ivac(output["pa"], 256)
                    before = bytes(backend.u.iface.readmem(output["pa"], 256))
                    if any(before):
                        raise RuntimeError(
                            "soft-fault output PA %#x did not start zero" %
                            output["pa"])
                    client["space"].uat.iounmap(
                        CONTEXT, output["dva"], PAGE)
                    client["space"].uat.flush_dirty()
                    client["space"].uat.invalidate_cache()
                    backend.u.inst(
                        "dsb sy; tlbi aside1os, x0; dsb sy; isb",
                        CONTEXT << 48)
                    if any(pa is not None for pa, _span in
                           client["space"].uat.iotranslate(
                               CONTEXT, output["dva"], PAGE)):
                        raise RuntimeError(
                            "soft-fault output DVA %#x still translates" %
                            output["dva"])
                    soft_fault[ordinal] = {
                        "dva": output["dva"],
                        "pa": output["pa"],
                        "translation": translation,
                    }
                    print(
                        "SOURCE COMPUTE armed soft fault for workload %d: "
                        "unmapped output DVA %#x from PA %#x" % (
                            ordinal, output["dva"], output["pa"]),
                        flush=True,
                    )

            common_after_publish = (
                (lambda ordinal=ordinal, callback=after_publish: (
                    callback() if callback is not None else None,
                    capture_peer_boundary(ordinal + 1),
                ))
                if capture_peer_boundaries else after_publish)
            common_options = dict(
                before_publish=before_publish_with_shadow,
                after_publish=common_after_publish,
                fresh_command3_style=(
                    fresh_command3_style_fourth and ordinal >= 3),
                persistent_runtime_queue=persistent_runtime_queue,
                persistent_startup_queue=persistent_startup_queue,
                persistent_runtime_optional_once=(
                    persistent_runtime_optional_once),
                persistent_runtime_fresh_descriptors=(
                    persistent_runtime_fresh_descriptors),
                persistent_runtime_fresh_events=(
                    persistent_runtime_fresh_events),
                fast_sequential=fast_sequential,
                persistent_runtime_recycle_interval=(
                    persistent_runtime_recycle_interval),
                persistent_runtime_context_record_count=(
                    persistent_runtime_context_record_count),
                persistent_runtime_alternating_contexts=(
                    persistent_runtime_alternating_contexts),
                persistent_runtime_preserve_context_reuse=(
                    persistent_runtime_preserve_context_reuse),
                persistent_runtime_optional_skip_ordinals=(
                    persistent_runtime_optional_skip_ordinals),
                strict_release_publish=strict_release_publish,
            )
            if ordinal == soft_fault_ordinal:
                prepared = stage_next_workload(
                    backend, client, staged["queue"], ordinal,
                    require_previous_retired=True,
                    notify=True,
                    **common_options)
                result = await_expected_soft_fault(prepared)
            else:
                result = submit_next_workload(
                    backend, client, staged["queue"], ordinal,
                    **common_options)
            drain_mailboxes("after workload %d" % ordinal)
            drain_reports("after workload %d" % ordinal, ordinal)
        except Exception:
            print(
                "SOURCE COMPUTE workload %d failed with control state %r" % (
                    ordinal, state["read_control_counters"](),
                ),
                flush=True,
            )
            raise
        if fast_sequential:
            print(
                "SOURCE COMPUTE workload %d completed" % ordinal,
                flush=True,
            )
        else:
            print(
                "SOURCE COMPUTE workload %d completed with control state %r" % (
                    ordinal, state["read_control_counters"]()),
                flush=True,
            )
        repeated.append(result)
    if soft_fault_ordinal is not None:
        if not repeated or not repeated[-1].get("fence", {}).get("signaled"):
            raise RuntimeError("post-soft-fault workload did not complete")
        if repeated[-1].get("soft_fault"):
            raise RuntimeError("soft fault was not followed by a valid workload")
        print(
            "SOURCE COMPUTE SOFT-FAULT RECOVERY PASS: workload %d retired "
            "without output and workload %d then produced its exact output "
            "on the same live execution context" % (
                soft_fault_ordinal, soft_fault_ordinal + 1),
            flush=True,
        )
    elif repeat_workloads > 1:
        print(
            "SOURCE COMPUTE REPEAT PASS: %d/%d distinct workloads produced "
            "their exact 64-float outputs on one live context with "
            "append-only queue lifetimes" %
            (1 + len(repeated), repeat_workloads),
            flush=True,
        )
    if result_verifier is not None:
        result_verifier(backend, client, repeated)
    if return_state:
        prepared_next = None
        if prestage_return_next:
            ordinal = int(repeat_workloads)

            def before_return_prestage():
                sync_control_shadow("before retained workload %d" % ordinal)

            prepared_next = stage_next_workload(
                backend,
                client,
                staged["queue"],
                ordinal,
                before_publish=before_return_prestage,
                require_previous_retired=True,
                notify=False,
                fresh_command3_style=(
                    fresh_command3_style_fourth and ordinal >= 3),
                persistent_runtime_queue=persistent_runtime_queue,
                persistent_startup_queue=persistent_startup_queue,
                persistent_runtime_optional_once=(
                    persistent_runtime_optional_once),
                persistent_runtime_fresh_descriptors=(
                    persistent_runtime_fresh_descriptors),
                persistent_runtime_fresh_events=(
                    persistent_runtime_fresh_events),
                fast_sequential=fast_sequential,
                persistent_runtime_recycle_interval=(
                    persistent_runtime_recycle_interval),
                persistent_runtime_context_record_count=(
                    persistent_runtime_context_record_count),
                persistent_runtime_alternating_contexts=(
                    persistent_runtime_alternating_contexts),
                persistent_runtime_preserve_context_reuse=(
                    persistent_runtime_preserve_context_reuse),
                persistent_runtime_optional_skip_ordinals=(
                    persistent_runtime_optional_skip_ordinals),
                strict_release_publish=strict_release_publish,
            )
            print(
                "SOURCE COMPUTE prestaged retained workload %d without "
                "doorbell" % ordinal,
                flush=True,
            )
            if notify_prestaged_before_return:
                backend.submitter.notify(WORK_DOORBELL_CHANNEL)
                print(
                    "SOURCE COMPUTE rang retained workload %d doorbell "
                    "before return" % ordinal,
                    flush=True,
                )
        state["modern_direct_bootstrap"] = {
            "backend": backend,
            "client": client,
            "queue": staged["queue"],
            "completed_ordinal": 0,
            "staged": staged,
            "prepared_next": prepared_next,
            "prepared_next_notified": bool(
                prestage_return_next and notify_prestaged_before_return),
        }
        return state
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
