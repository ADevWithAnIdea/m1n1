# SPDX-License-Identifier: GPL-2.0-only
"""T8142 numeric type-6/type-8 TVB-growth transaction payloads.

Derived from the first native memoryless request/reply, not firmware code.
Payload builders are pure; allocate_growth_reply also allocates/maps backing
and publishes list/counts, but never the command-ring producer. The caller
owns ACK publication. The other/proactive request path is not implemented here.
"""
import struct

TVB_BLOCK_SIZE = 0x80000
TVB_ADDRESS_UNIT = 0x8000
TVB_ADDRESS_BASE = 0x1000000000


def build_growth_ack(vm_id, buffer_id, counter):
    """Acknowledge a processed request, not successful allocation.

    Hardware can request again after this ACK with capacity unchanged. The
    counter counts processed requests, not added blocks. Do not use this as
    a terminal OOM reply or allow unbounded allocation-failure retry.
    """
    if any(type(v) is not int or not 0 <= v <= 0xffffffff
           for v in (vm_id, buffer_id, counter)):
        raise ValueError("invalid growth identifiers/counter")
    if not 1 <= vm_id < 64 or buffer_id != 0:
        raise ValueError("growth reply requires an owned VM slot and buffer zero")
    return struct.pack("<5I", 8, 1, buffer_id, vm_id, counter) + bytes(44)


def build_growth_reply(vm_id, buffer_id, counter, old_count, block_dvas):
    command = build_growth_ack(vm_id, buffer_id, counter)
    return dict(build_tvb_backing(old_count, block_dvas), command=command)


def build_growth_failure_ack(vm_id, buffer_id, counter):
    """Reply observed at a native limit, not a proven standalone abort.

    The valid 65M-triangle native memoryless limit uses word +4 = 0, then
    has report type 7 in the final history. Word +4 = 0 alone instead yields
    another request in the small replay, so do not infer causal ordering or
    terminal semantics from that history. Owner placement remains (1,0) only.
    """
    command = bytearray(build_growth_ack(vm_id, buffer_id, counter))
    struct.pack_into("<I", command, 4, 0)
    return bytes(command)


def build_growth_limit_followup(body, *, queue_dva, pool_dva, fragment_dva,
                                event_slot, event_value):
    """Validate owned native memory-limit report data and build type9.

    Only the observed fragment/type7-error0 layout is supported. The word
    labelled event_slot follows the independently available Asahi layout;
    the M5 caller must supply its known value, not infer VM ownership from it.
    The firmware data pointer at +0x28 is opaque and never followed.
    """
    if (len(body) != 0x48 or any(type(v) is not int or not 0 < v < 1 << 64
                               for v in (queue_dva, pool_dva, fragment_dva)) or
            any(type(v) is not int or not 0 <= v <= 0xffffffff
                for v in (event_slot, event_value))):
        raise ValueError("invalid owned memory-limit report parameters")
    words = struct.unpack("<18I", body)
    pointers = tuple(struct.unpack_from("<Q", body, offset)[0] for offset in (24, 32, 48))
    if (words[:5] != (7, 0, 1, event_slot, event_value) or
            words[14:] != (0, 0, 1, 0) or
            pointers != (queue_dva, pool_dva, fragment_dva)):
        raise ValueError("unattributed or unsupported memory-limit report")
    return struct.pack("<IIQI", 9, 1, queue_dva, event_value) + bytes(44)


def build_owned_limit_followup(body, *, fragment_dva, event_slot, event_value):
    """Bind a limit report to owned work and echo its opaque callback cookie.

    Words at +0x18/+0x20 varied from queue/pool addresses to firmware cookies
    in later full-capacity work. They are not stable ownership identifiers.
    Never dereference any of these fields. The caller also requires an owned
    negative reply before invoking this validator, and retirement afterwards.
    """
    if (len(body) != 0x48 or type(fragment_dva) is not int or not 0 < fragment_dva < 1 << 64 or
            any(type(v) is not int or not 0 <= v <= 0xffffffff for v in (event_slot, event_value))):
        raise ValueError('invalid owned memory-limit work identity')
    words = struct.unpack('<18I', body)
    if (words[:5] != (7, 0, 1, event_slot, event_value) or words[14:] != (0, 0, 1, 0) or
            struct.unpack_from('<Q', body, 48)[0] != fragment_dva):
        raise ValueError('unattributed or unsupported memory-limit report')
    cookie = body[24:32]
    if not any(cookie):
        raise ValueError('empty memory-limit callback cookie')
    return struct.pack('<2I', 9, 1) + cookie + struct.pack('<I', event_value) + bytes(44)


def build_tvb_backing(old_count, block_dvas):
    """List/count publication shared by host pre-growth and in-job replies."""
    block_dvas = tuple(block_dvas)
    if (not block_dvas or type(old_count) is not int or old_count < 0 or
            old_count + len(block_dvas) > 0xffffffff):
        raise ValueError("invalid growth counts")
    if len(set(block_dvas)) != len(block_dvas):
        raise ValueError("duplicate growth block")
    for va in block_dvas:
        if (type(va) is not int or va < TVB_ADDRESS_BASE or va % TVB_ADDRESS_UNIT or
            va + TVB_BLOCK_SIZE > 1 << 42 or
            (va - TVB_ADDRESS_BASE) // TVB_ADDRESS_UNIT > 0xffffffff):
            raise ValueError("invalid TVB block address")
    ordered = sorted(block_dvas)
    if any(b < a + TVB_BLOCK_SIZE for a, b in zip(ordered, ordered[1:])):
        raise ValueError("overlapping TVB blocks")
    count = old_count + len(block_dvas)
    return {
        "counts": struct.pack("<2I", count, count),
        "list_offset": old_count * 8,
        "block_ids": struct.pack("<%dQ" % len(block_dvas), *(
            (va - TVB_ADDRESS_BASE) // TVB_ADDRESS_UNIT for va in block_dvas)),
    }



def build_idle_tvb_metadata(block_dvas):
    """Build the idle pool's 32-KiB-unit list and three capacity fields.

    Unlike an active type-6 reply, the native inter-job resize updates these
    fields before submitting the next render. The caller must own a quiescent
    pool and sufficient list storage. Other Info words are live firmware state
    and must not be initialized by this helper.
    """
    block_dvas = tuple(block_dvas)
    payload = build_tvb_backing(0, block_dvas)
    units_per_block = TVB_BLOCK_SIZE // TVB_ADDRESS_UNIT
    count = len(block_dvas) * units_per_block
    if count > 0xffffffff:
        raise ValueError("TVB unit count overflows its descriptor field")
    block_ids = struct.unpack("<%dQ" % len(block_dvas), payload["block_ids"])
    unit_list = b"".join(struct.pack("<%dI" % units_per_block,
                                    *range(base, base + units_per_block))
                          for base in block_ids)
    fields = tuple((offset, struct.pack("<I", value)) for offset, value in (
        (0x34, count), (0x3c, len(block_dvas)), (0x54, count - 1)))
    return dict(unit_list=unit_list, info_fields=fields)


def allocate_growth_reply(util, proxy, iface, read_pa, *, root_pa, state_pa,
                          list_pa, list_capacity, request, block_dvas, expected_counter, uat):
    """Validate one firmware request and prepare backing plus its ACK payload.

    The caller still owns the ACK ring producer. Host-side pre-work growth
    uses allocate_tvb_backing directly and never fabricates a firmware request.
    """
    if len(request) != 0x48:
        raise ValueError("growth request must be one complete report record")
    opcode, vm_id, buffer_id, counter = struct.unpack_from("<4I", request)
    if opcode != 6 or counter != expected_counter:
        raise ValueError("unexpected growth request opcode/counter")
    command = build_growth_ack(vm_id, buffer_id, counter)
    return dict(allocate_tvb_backing(util, proxy, iface, read_pa,
        root_pa=root_pa, state_pa=state_pa, list_pa=list_pa,
        list_capacity=list_capacity, block_dvas=block_dvas, uat=uat), command=command, counter=counter)


def allocate_tvb_backing(util, proxy, iface, read_pa, *, root_pa, state_pa,
                         list_pa, list_capacity, block_dvas, uat):
    """Publish fresh TVB backing through the existing UAT client's API.

    The report protocol and capacity policy belong here. Translation, table
    allocation, mapping and encoding belong to the unchanged UAT implementation.
    Once allocation begins, the caller pins all backing on any later failure.
    The ACK producer is advanced only by the report service after this returns.
    """
    from .g17g_uat import FLAGS_CONTEXT0_UXN

    if type(list_capacity) is not int or not 0 < list_capacity <= 0xffffffff:
        raise ValueError("invalid owned TVB block-list capacity")
    counts = struct.unpack("<2I", read_pa(state_pa, 8))
    if counts[0] != counts[1]:
        raise ValueError("inconsistent live TVB counts")
    if counts[0] > list_capacity:
        raise ValueError("live TVB count exceeds owned block list")
    block_dvas = tuple(block_dvas)
    payload = build_tvb_backing(counts[0], block_dvas)
    if counts[0] + len(block_dvas) > list_capacity:
        raise MemoryError("owned TVB block list is full")
    for address in block_dvas:
        if uat.iotranslate_root(root_pa, address, TVB_BLOCK_SIZE) != [(None, TVB_BLOCK_SIZE)]:
            raise ValueError("growth would overwrite a live UAT mapping")
    before_tables = set(uat.root_table_pages(root_pa))
    size = len(block_dvas) * TVB_BLOCK_SIZE
    physical = int(util.memalign(0x4000, size))
    if physical <= 0 or physical % 0x4000 or physical + size > 1 << 42:
        raise ValueError("invalid owned TVB allocation")
    proxy.memset32(physical, 0, size)
    proxy.dc_civac(physical, size)
    for index, address in enumerate(block_dvas):
        uat.iomap_at_root(root_pa, address, physical + index * TVB_BLOCK_SIZE,
                         TVB_BLOCK_SIZE, **FLAGS_CONTEXT0_UXN)
    table_pages = set(uat.root_table_pages(root_pa))
    uat.flush_dirty()
    for address in sorted(table_pages):
        proxy.dc_civac(address, 0x4000)
    util.inst("dsb sy")
    for address, data in ((list_pa + payload["list_offset"], payload["block_ids"]),
                          (state_pa, payload["counts"])):
        iface.writemem(address, data)
        proxy.dc_civac(address & -0x4000, 0x4000)
    util.inst("dsb sy")
    new_tables = sorted(table_pages - before_tables)
    return dict(old_count=counts[0], new_count=counts[0] + len(block_dvas),
                new_physical=physical, bytes=size, block_dvas=block_dvas,
                uat_table_pages=len(table_pages), new_uat_tables=new_tables,
                allocation_bytes=size + len(new_tables) * 0x4000,
                captured_reply_bytes=0)
