# SPDX-License-Identifier: GPL-2.0-only
"""Firmware-only first-compute objects, with caller CDM left entirely opaque.

Unlike build_add_compute_graph, this constructs no test shader, argument table,
input/output data or expected result. Allocation and submission are separate.
The layout module places these source-described private objects inside each
UAPI VM's reserved kernel range before publication.
"""

import struct

from . import g17g, g17g_backend as backend, g17g_compute as compute
from . import g17g_postcontrol

PAGE_SIZE = 0x4000
PREEMPT_BASE = 0x7201b00000


def first_compute_completion(before, after):
    """Qualify the owned first report and real stamps, not transport cursors.

    Clean/fault controls share retired cursors and events. The clean command
    writes stamp0x100, mirrored timestamps and report(1,1,0,0); an unmapped CDM
    leaves stamps zero and posts(4,0,0,0xffffffff). Unknown shapes never succeed.
    Report tail bytes are unused stack-fill, not part of this predicate.
    """
    fields = ("dispatch_a", "dispatch_b", "status_a", "status_b")
    if any(bytes.fromhex(before[name]) != bytes(16) for name in fields):
        raise ValueError("first-compute completion was not initially clear")
    old, new = before["reports"], after["reports"]
    if (old["producer"], old["consumer"]) != (0, 0):
        raise ValueError("first-compute report ring is not initially empty")
    if new["consumer"] != old["consumer"]:
        raise ValueError("first-compute report was consumed by another owner")
    if new["producer"] == old["producer"]:
        return None
    if new["producer"] != (old["producer"] + 1) % 256 or len(new["records"]) != 1:
        raise ValueError("unexpected first-compute report count")
    report = bytes.fromhex(new["records"][0])
    if len(report) != 0x48:
        raise ValueError("wrong first-compute report size")
    words = struct.unpack_from("<4I", report)
    if words == (4, 0, 0, 0xffffffff):
        return "fault"
    if words != (1, 1, 0, 0):
        raise ValueError("unclassified first-compute report")
    stamp = bytes.fromhex(after["dispatch_a"])
    if stamp != struct.pack("<I", 0x100) + bytes(12):
        return None
    start, end = struct.unpack("<QQ", bytes.fromhex(after["status_a"]))
    if not 0 < start <= end:
        return None
    if struct.unpack_from("<Q", bytes.fromhex(after["status_b"]))[0] != end:
        return None
    if struct.unpack_from("<QQ", bytes.fromhex(after["descriptor_tail"]), 0x2c) != (start, end):
        return None
    return "complete"


def continued_compute_completion(before, after, *, max_reports=1, queue_id=0):
    """The ordinary [3,14] continuation has fresh per-command timestamps.

    Its successful second command leaves the first shared dispatch stamp and
    report producer unchanged. Do not turn that one-shot event into a required
    per-command advance. Fault reports still take precedence over timestamps.
    """
    if not 1 <= max_reports <= 64:
        raise ValueError("invalid compute wave report bound")
    if not 0 <= queue_id < 64:
        raise ValueError('invalid compute notification queue')
    mask = 1 << queue_id
    if any(bytes.fromhex(before[name]) != bytes(16) for name in ("status_a", "status_b")):
        raise ValueError("continued compute status was not initially clear")
    if bytes.fromhex(before["descriptor_tail"])[0x2c:0x3c] != bytes.fromhex(
            before.get('sampler_input', bytes(16).hex())):
        raise ValueError("continued descriptor differs from its published sampler input")
    old, new = before["reports"], after["reports"]
    if old["producer"] != old["consumer"] or new["consumer"] != old["consumer"]:
        raise ValueError("continued compute report interval is not owned")
    count = (new["producer"] - old["producer"]) % 256
    if count > max_reports or len(new["records"]) != count:
        raise ValueError("unexpected continued compute report count")
    for body in new["records"]:
        report = bytes.fromhex(body)
        if len(report) != 0x48:
            raise ValueError("wrong continued compute report size")
        words = struct.unpack_from("<4I", report)
        if words == (4, 0, 0, 0xffffffff):
            return "fault"
        if words != (1, mask & 0xffffffff, mask >> 32, 0):
            raise ValueError("unclassified continued compute report")
    start, end = struct.unpack("<QQ", bytes.fromhex(after["status_a"]))
    if not 0 < start <= end:
        return None
    if struct.unpack_from("<Q", bytes.fromhex(after["status_b"]))[0] != end:
        return None
    if struct.unpack_from("<QQ", bytes.fromhex(after["descriptor_tail"]), 0x2c) != (start, end):
        return None
    return "complete"


def first_compute_graph(cdm_base, cdm_end, *, priority=2, preempt_base=PREEMPT_BASE,
                        user_timestamps=(0, 0), robustness=backend.COMPUTE_ROBUSTNESS,
                        empty=False, sampler_heap=0, sampler_count=0):
    if empty and (cdm_base is not None or cdm_end is not None or any(user_timestamps)
                  or sampler_heap or sampler_count):
        raise ValueError('empty compute transport has no caller command')
    if not empty and ((cdm_base | cdm_end) & 3 or not 0 < cdm_base < cdm_end < (1 << 42)):
        raise ValueError("invalid caller CDM bounds")
    if preempt_base % PAGE_SIZE or not 0 < preempt_base < (1 << 42) - 3 * PAGE_SIZE:
        raise ValueError("invalid preemption buffer address")
    if robustness % PAGE_SIZE or not 0 < robustness < (1 << 42) - PAGE_SIZE:
        raise ValueError("invalid private robustness address")
    if priority not in (2, 3):
        raise ValueError("unverified first-compute priority")
    addresses = backend.compute_addresses()
    generation = compute.COMPUTE_QUEUE_GENERATION
    postcontrol = g17g_postcontrol.build_postcontrol_pages(generation)
    registers = None if empty else compute.build_compute_registers(
        resource=preempt_base, cdm=cdm_base,
        robustness=robustness, scratch=backend.COMPUTE_SCRATCH,
        dispatch_identity=backend.COMPUTE_DISPATCH_IDENTITY)
    descriptor = b'' if empty else compute.build_compute_descriptor(
        registers, addresses["scheduler"], backend.COMPUTE_DESCRIPTOR_LOW,
        cdm_end - 4, backend.COMPUTE_DISPATCH_IDENTITY,
        addresses["dispatch_a"], addresses["dispatch_b"],
        addresses["status_a"], addresses["status_b"],
        addresses["shared_support"], addresses["zero_page"],
        user_timestamp_start=user_timestamps[0], user_timestamp_end=user_timestamps[1],
        sampler_heap=sampler_heap, sampler_count=sampler_count)
    context = bytearray(PAGE_SIZE)
    item = b'' if empty else compute.build_compute_queue_context_item(addresses["descriptor"], addresses["queue"])
    offset = compute.compute_queue_context_item_offset(0)
    context[offset:offset + len(item)] = item
    pointer = bytearray(postcontrol[addresses["pointers"]])
    body = g17g.build_pointer_block(field_00=0, field_30=0, field_40=0 if empty else 3)
    pointer[:len(body)] = body
    ring = bytearray(postcontrol[addresses["item_ring"]])
    struct.pack_into("<3Q", ring, 0,
                     addresses["optional"], 0 if empty else addresses["descriptor"], 0 if empty else addresses["event"])
    queue = bytearray(postcontrol[addresses["queue"]])
    body = compute.build_compute_queue_record(
        addresses["pointers"], addresses["item_ring"],
        addresses["job_list"], addresses["queue_aux"], queue_generation=generation)
    queue[:len(body)] = body
    objects = dict(
        class2_state=compute.build_compute_shared_state(),
        class2_support=g17g.build_opcode20_first_object(
            backend.COMPUTE_OPERAND_BASE, backend.COMPUTE_CLIENT_STATE,
            addresses["class2_state"]),
        queue_context=bytes(context),
        optional=compute.build_compute_optional(
            backend.COMPUTE_QUEUE_CONTEXT_LOW, addresses["queue_context"],
            shared_control=addresses["shared_support"], channel_control=addresses["queue_aux"],
            token=generation),
        descriptor=descriptor[:compute.COMPUTE_DESCRIPTOR_OBJECT_SIZE],
        event=compute.build_compute_event(),
        job_list=postcontrol[addresses["job_list"]],
        queue_aux=postcontrol[addresses["queue_aux"]],
        pointers=bytes(pointer), item_ring=bytes(ring), queue=bytes(queue))
    if empty:
        del objects['descriptor'], objects['event']
    writes = {
        backend.COMPUTE_CLIENT_STATE: compute.build_compute_operand_table(backend.COMPUTE_OPERAND_BASE),
        backend.COMPUTE_PAGE_LIST: compute.build_compute_operand_page_lists(),
        preempt_base: bytes(3 * PAGE_SIZE),
    }
    writes.update(compute.build_compute_address_list_pages(
        backend.COMPUTE_OPERAND_BASE, address_list_base=backend.COMPUTE_ADDRESS_LIST))
    private = {base + offset for base, body in writes.items()
               for offset in range(0, len(body), PAGE_SIZE)}
    # Zeroed operand and scratch arenas are owned even though no image exists.
    private.update(dva for dva in compute.expand_compute_context1_dvas()
                   if 0x7200000000 <= dva < 0x7300000000)
    private.add(robustness)
    graph = dict(
        format="m1n1-g17g-first-compute-firmware-v1", captured_input=None,
        channel=8, compute_descriptor_count=0 if empty else 1, empty_transport=empty, direct_dispatch_count=None,
        native_two_publication_layout=False, fresh_firmware_page_flags={},
        addresses=addresses, firmware_objects=objects,
        firmware_patches=dict(
            channel_ring=((compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET,
                           compute.build_compute_channel_slot(addresses["queue"])),),
            state=((compute.COMPUTE_CHANNEL_STATE_OFFSET,
                    struct.pack("<I12xI12xI", 0, 0, 0 if empty else 1)),)),
        source_global_pages=backend.source_global_pages(generation),
        context1_writes=writes,
        context1_dvas=tuple(sorted(set(compute.expand_compute_context1_dvas()) | private)),
        context1_read_only_dvas=compute.expand_compute_context1_read_only_dvas(),
        private_dvas=tuple(sorted(private)), cdm_base=cdm_base, cdm_end=cdm_end,
        sampler_heap=sampler_heap, sampler_count=sampler_count,
    )
    # Reuse the M5-qualified raw priority translation, not the G17P layout.
    from .g17g_barriers import record_binding
    graph['dependency_jobs'] = () if empty else ((record_binding(
        'firmware_objects', 'queue_context', offset),),)
    from .g17g_shim import G17GShimBackend
    return G17GShimBackend._retarget_submission_priority(graph, priority)
