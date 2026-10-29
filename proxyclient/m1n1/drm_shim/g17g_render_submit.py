# SPDX-License-Identifier: GPL-2.0-only
"""Firmware-only first-render products; never construct caller programs/data.

These are standalone opening and bounded continuation graphs, not mixed work.
The parameter container is shared with the reference experiment, but its
target/color/clear-state fields do not contribute any bytes to this graph.
"""
import struct
from dataclasses import replace

from . import g17g, g17g_backend as backend, g17g_context1, g17g_postcontrol
from . import g17g_render as render
from .g17g_render_queue import transport_head

PAGE_SIZE = 0x4000
# One current inner transport owns 0x500 entries, three per render. Its
# recreation boundary is separate from every circular outer/object namespace.
RENDER_TRANSPORT_CAPACITY = backend.RENDER_INNER_RING_ITEM_COUNT // 3
# Pool-A enters state 2 only after the final render pass. Descriptor timestamp
# ends can change during spill, and its overflow count can finish at zero.
PARTIAL_COMPLETION_POOL_OFFSET = 0xc
RENDER_TIMESTAMP_FIELDS = ("tiling_user_timestamp_start", "tiling_user_timestamp_end",
                           "fragment_user_timestamp_start", "fragment_user_timestamp_end")


def partial_timestamp_destinations(params, ordinal):
    """Keep omitted timestamps private and preserve each requested caller word."""
    from .g17g_timestamp import TIMESTAMP_USER_BASE, TIMESTAMP_END
    private = render.TIMESTAMP_APERTURE_BASE + 8 + (ordinal - 1) * 32
    assert private + 32 <= TIMESTAMP_USER_BASE
    supplied = tuple(getattr(params, name) for name in RENDER_TIMESTAMP_FIELDS)
    if any(address and (address % 8 or not TIMESTAMP_USER_BASE <= address <= TIMESTAMP_END - 8)
           for address in supplied):
        raise ValueError("partial caller timestamp overlaps private storage or escapes its aperture")
    addresses = tuple(address or private + index * 8 for index, address in enumerate(supplied))
    return replace(params, **dict(zip(RENDER_TIMESTAMP_FIELDS, addresses))), private, (
        addresses if any(supplied) else None)


def ordinary_completion_target(snapshot):
    """Next retained pool state for one completed ordinary render."""
    value = struct.unpack("<I", bytes.fromhex(snapshot["completion_counter"]))[0]
    if value & 1 or value > 0xfffffffc:
        raise ValueError("ordinary completion counter is not a reusable even value")
    return value + 2


def ordinary_published_fragment_interval(graph):
    """Validate the private mirror actually queued for descriptor replacement."""
    address = graph["firmware_addresses"]["fragment_descriptor"] + 0x21f7
    writes = [(dva, body) for dva, body in graph["high"]
              if dva < address + 16 and address < dva + len(body)]
    if len(writes) != 1:
        raise ValueError("ordinary fragment mirror publication is missing or overlaps")
    dva, body = writes[0]
    interval = body[address - dva:address - dva + 16] if dva <= address else b""
    if interval != bytes(16):
        raise ValueError("ordinary fragment mirror publication was not clear")
    return interval


def render_parameters(state, *, buffer_base=0x1010000000):
    """Translate opaque validated UAPI state, without color/target knowledge.

    Use the complete render transport for both ordinary and spilling work.
    Each command gets geometry-sized private buffers, independent of programs
    and framebuffer addresses.
    """
    from .g17g_uapi import DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES, DRM_ASAHI_RENDER_DBIAS_IS_INT
    if any((state.vertex_helper_binary, state.vertex_helper_cfg, state.vertex_helper_data,
            state.fragment_helper_binary, state.fragment_helper_cfg, state.fragment_helper_data)):
        raise NotImplementedError("render helpers not integrated")
    if state.bgobjvals & ~0x3ff:
        raise NotImplementedError("unintegrated background object flags")
    params = render.G17GClearRenderParameters(
        # Unused by the firmware-only graph. No color/target enters the driver.
        target_dva=0, clear_state_page=0, clear_rgba=(0, 0, 0, 0),
        target_stride_pixels=state.width, width=state.width, height=state.height,
        layers=state.layers, utile_width=state.utile_width, utile_height=state.utile_height,
        samples=state.samples, sample_size=state.sample_size, utile_config=state.utile_config,
        multisample_control=state.multisample_control, ppp_control=state.ppp_control,
        tib_blocks=state.blocks_per_utile, tile_config=state.tile_config,
        merge_upper_x_bits=state.merge_upper_x, merge_upper_y_bits=state.merge_upper_y,
        store_pipeline=state.usc_exec_base + state.eot_usc,
        store_pipeline_bind=state.eot_rsrc_spec,
        load_pipeline=state.usc_exec_base + state.bg_usc,
        load_pipeline_bind=0xffff800000000000 | state.bg_rsrc_spec,
        partial_load_pipeline=state.usc_exec_base + state.partial_bg_usc,
        partial_load_pipeline_bind=0xffff800000000000 | state.partial_bg_rsrc_spec,
        partial_store_pipeline=state.usc_exec_base + state.partial_eot_usc,
        partial_store_pipeline_bind=state.partial_eot_rsrc_spec,
        auxiliary_object=0x10000300000,
        tiling_lifecycle=0xce010000f3,
        partial_mode=True, tib_bytes=32,
        aux_fb_flags=0x10c000,
        scissor_array=state.scissor_base, depth_bias_array=state.dbias_base,
        occlusion_query_base=state.oclqry_base, sampler_array=state.sampler_heap,
        sampler_count=state.sampler_count, depth_buffer=state.depth_base,
        stencil_buffer=state.stencil_base, depth_aux_buffer=state.depth_comp_base,
        stencil_aux_buffer=state.stencil_comp_base, depth_stride=state.depth_stride,
        stencil_stride=state.stencil_stride, depth_aux_stride=state.depth_comp_stride,
        stencil_aux_stride=state.stencil_comp_stride, depth_flags=state.zls_ctrl,
        # UAPI ZLS dimensions may differ from the framebuffer dimensions.
        depth_dimensions=state.zls_pixels,
        depth_clear_value_bits=state.bgobjdepth, stencil_clear_value=state.bgobjvals & 0xff,
        process_empty_tiles=bool(state.flags & DRM_ASAHI_RENDER_PROCESS_EMPTY_TILES),
        depth_bias_is_integer=bool(state.flags & DRM_ASAHI_RENDER_DBIAS_IS_INT),
        vdm_ctrl_stream_base=state.vdm_base)
    from .g17g_render_buffers import render_buffers
    params = replace(params, buffers=render_buffers(params, buffer_base))
    params.validate()
    return params


def first_render_completion(before, after, ordinal=1, *, final_ordinal=None, max_reports=2,
                            retained_interval=None, pending_growth=False,
                            published_partial_state=None, published_fragment_interval=None):
    """Owned render completion, distinct from its prefilled admission stamps.

    Kept independent of shader outputs. Hardware qualification and its fault
    control are required before advertising the integrated render path.
    """
    if not 1 <= ordinal < 0x10000:
        raise ValueError("unqualified render completion ordinal")
    if final_ordinal is None:
        final_ordinal = ordinal
    if not ordinal <= final_ordinal < 0x10000:
        raise ValueError("invalid render completion batch interval")
    if ordinal == 1 and (before["dispatch_a"] != bytes(16).hex() or before["timestamps"] != bytes(16).hex()):
        raise ValueError("first render dispatch stamps were not initially clear")
    old, reports = before["reports"], after["reports"]
    if reports["consumer"] != old["consumer"]:
        raise ValueError("first render reports consumed by another owner")
    old_count = (old["producer"] - old["consumer"]) % 256
    count = (reports["producer"] - old["producer"]) % 256
    if count > max_reports or len(old["records"]) != old_count or len(reports["records"]) != old_count + count:
        raise ValueError("unexpected first-render report count")
    if reports["records"][:old_count] != old["records"]:
        raise ValueError("historical service reports changed")
    if any(struct.unpack_from("<I", bytes.fromhex(body))[0] == 4 for body in old["records"]):
        raise ValueError("render admission was already faulted")
    new = reports["records"][old_count:]
    types = []
    for body in new:
        report = bytes.fromhex(body)
        if len(report) != 0x48:
            raise ValueError("wrong first-render report size")
        types.append(struct.unpack_from("<I", report)[0])
    if 4 in types:
        return "fault"
    if any(kind not in ((1, 6) if pending_growth else (1,)) for kind in types):
        raise ValueError("unclassified first-render report")
    if 6 in types:
        # The owned service must validate, back and ACK the request before
        # this command can finish. Never turn a pending request into success.
        return None
    if "completion_counter" in before:
        expected = ordinary_completion_target(before)
        if struct.unpack("<I", bytes.fromhex(after["completion_counter"]))[0] != expected:
            return None
    if "execution_timestamps" in before:
        initial_stamps = struct.unpack("<4Q", bytes.fromhex(before["execution_timestamps"]))
        destinations = before.get("execution_timestamp_addresses")
        if destinations is None:
            if any(initial_stamps):
                raise ValueError("render completion timestamp slot was not initially clear")
        else:
            from .g17g_timestamp import TIMESTAMP_USER_BASE
            if any(value for address, value in zip(destinations, initial_stamps)
                   if address < TIMESTAMP_USER_BASE):
                raise ValueError("private render completion timestamp slot was not initially clear")
        # A target-sequenced wave resets each reused pool slot immediately
        # before that command's publication. Its pre-wave snapshot can still
        # contain the preceding owner's terminal state; retain that snapshot
        # and use the separately validated publication value in this case.
        initial = (struct.unpack("<I", bytes.fromhex(before["partial_completion"]))[0]
                   if published_partial_state is None else published_partial_state)
        if type(initial) is not int or initial != 0:
            raise ValueError("partial completion word was not initially clear")
        if struct.unpack("<I", bytes.fromhex(after["partial_completion"]))[0] != 2:
            return None
        ta_start, ta_end, fr_start, fr_end = struct.unpack("<4Q", bytes.fromhex(after["execution_timestamps"]))
        if destinations is not None:
            # Caller destinations may alias each other or reuse an old word.
            # Their four reads are not necessarily four distinct intervals.
            # Require fresh writes, with the private pool's 0->2 transition
            # above and the runtime's clean retirement providing finality.
            return "complete" if all(value and value != old for value, old in zip(
                (ta_start, ta_end, fr_start, fr_end), initial_stamps)) else None
        # Partial rendering interleaves engines, so TA end need not precede
        # FR start. Both owned per-engine intervals must be newly written.
        return "complete" if 0 < ta_start < ta_end <= fr_end and 0 < fr_start < fr_end else None
    # Group two's retained lifecycle pre-fills the dispatch stamps and posts
    # its type1 report before the work kick. Neither is a completion witness.
    if not new and ordinal == 1:
        return None
    # Recurrent pool reuse does not maintain this shared dispatch prefix:
    # the exact 64-render run retained 0x2400 after work36 while every later
    # fresh descriptor mirror and independent output completed. It is neither
    # a monotonic job counter nor a required completion edge for later work.
    if ordinal <= 2 and bytes.fromhex(after["dispatch_a"]) != struct.pack("<4I", final_ordinal * 0x100, final_ordinal * 0x100, 0, 0):
        return None
    start, end = struct.unpack("<2Q", bytes.fromhex(after["timestamps"]))
    initial_interval = bytes.fromhex(before["fragment_tail"])[0x7f:0x8f]
    if published_fragment_interval is not None:
        if ordinal < 3 or "completion_counter" not in before:
            raise ValueError("descriptor replacement lacks its recurrent completion counter")
        initial_interval = published_fragment_interval
    if initial_interval != bytes(16):
        raise ValueError("first-render fragment mirror was not initially clear")
    fragment_start, fragment_end = struct.unpack_from("<2Q", bytes.fromhex(after["fragment_tail"]), 0x7f)
    prior_end = struct.unpack("<2Q", bytes.fromhex(before["timestamps"]))[1]
    retained = (ordinal == 2 and retained_interval is not None and
                (fragment_start, fragment_end) == tuple(retained_interval) and
                fragment_end <= prior_end)
    if not (0 < start <= fragment_start <= fragment_end <= end and
            (prior_end < fragment_start or retained)):
        return None
    if ordinal == final_ordinal and fragment_end != end and not retained:
        return None
    return "complete"


def first_render_graph(params, *, priority=2, private_completion=False, external_timestamps=False):
    """Build only the source-owned TA/fragment submission and private arenas.

    Caller VDM, pipeline programs, scissor/depth-bias arrays, color/depth/stencil
    and query data must arrive as BO mappings. No known test payload is built
    and then removed: it is never called in the first place.
    """
    params.validate()
    if priority not in (2, 3):
        raise ValueError("unverified render priority")
    partial = params.partial_mode
    completion_timestamps = None
    completion_timestamp_addresses = None
    if params.request_tvb_growth or private_completion:
        if not partial:
            raise ValueError("private completion requires a partial render")
        if not external_timestamps and any(getattr(params, name) for name in RENDER_TIMESTAMP_FIELDS):
            raise ValueError("driver completion requires an unassigned partial timestamp slot")
        params, completion_timestamps, completion_timestamp_addresses = partial_timestamp_destinations(params, 1)
    token = backend.PARTIAL_RENDER_TOKEN if partial else backend.RENDER_DEFAULT_TOKEN
    transport = backend.build_render_transport(params, token)
    items = transport["items"]
    objects = transport["firmware_pages"]
    addresses = transport["firmware_addresses"]
    patches = transport["firmware_patches"]
    low = {
        render.RENDER_OPERAND_TABLE_DVA: render.build_render_operand_table(
            operand_count=render.PARTIAL_RENDER_OPERAND_COUNT if partial else render.RENDER_OPERAND_COUNT),
        0x100001c000: bytes(PAGE_SIZE),
        0x1000260000: bytes(PAGE_SIZE),
        0x1000288000: bytes(PAGE_SIZE),
        params.auxiliary_object: bytes(PAGE_SIZE),
    }
    if params.buffers is not None:
        low.update((address, bytes(PAGE_SIZE)) for address in params.buffers.pages)
    if not partial:
        low[render.RENDER_BASE10_SUPPORT_DVA] = render.build_render_base10_support_page()
    low.update(render.build_render_address_list_pages(
        operand_count=render.PARTIAL_RENDER_OPERAND_COUNT if partial else render.RENDER_SERVICE_INPUT_OPERAND_COUNT))
    dvas = set(render.expand_partial_render_context1_dvas() if partial
               else render.expand_render_context1_dvas()) | set(low)
    # Source topology below the USC window includes two *caller* leaves:
    # the VDM stream and its compiler-provided robustness/support page. Never
    # reserve or synthesize them as driver data. Remaining lower template
    # leaves contain the native private arenas, operand lists and aliases.
    caller_low = {0x1000018000, 0x1000058000}
    if partial:
        # Direct VDM bindings are caller state, including their root page.
        caller_low.update((0x1000000000, 0x1000048000, 0x1000068000))
    private = {dva for dva in dvas if dva < 0x10000000000 and dva not in caller_low}
    private.update(low)
    if set(low) & set(g17g_context1.POSTCONTROL_ALIASES):
        raise RuntimeError("render source image overwrites a shared firmware alias")
    timestamp_pages = ({render.TIMESTAMP_APERTURE_BASE: bytes(PAGE_SIZE)}
                       if completion_timestamps is not None else {})
    for address in (params.tiling_user_timestamp_start, params.tiling_user_timestamp_end,
                    params.fragment_user_timestamp_start, params.fragment_user_timestamp_end):
        if address:
            if external_timestamps:
                from .g17g_timestamp import TIMESTAMP_END
                if not render.TIMESTAMP_APERTURE_BASE <= address <= TIMESTAMP_END - 8:
                    raise ValueError("external timestamp is outside the firmware aperture")
                # The special-object manager owns and uploads caller backing.
                # Do not synthesize or clear a page at this address.
                continue
            page = address & -PAGE_SIZE
            if page != render.TIMESTAMP_APERTURE_BASE:
                raise ValueError("caller timestamp requires the hardware-data aperture")
            timestamp_pages[page] = bytes(PAGE_SIZE)
    graph = dict(format="m1n1-g17g-first-render-firmware-v1", captured_input=None,
        completion_timestamps=completion_timestamps,
        completion_timestamp_addresses=completion_timestamp_addresses,
        channels=backend.RENDER_CHANNELS, token=token, parameters=params,
        items=items, firmware_pages=objects, firmware_addresses=addresses,
        firmware_patch_addresses=transport["firmware_patch_addresses"],
        firmware_patches=patches, source_global_pages=transport["source_global_pages"],
        late_global_pages=transport["late_global_pages"],
        fresh_global_pages=timestamp_pages, fresh_global_page_flags={},
        context1_writes=low, context1_dvas=tuple(sorted(dvas)),
        context1_read_only_dvas=(render.expand_partial_render_context1_read_only_dvas() if partial
                                else render.expand_render_context1_read_only_dvas()),
        context1_aliases=dict(g17g_context1.POSTCONTROL_ALIASES),
        private_dvas=tuple(sorted(private)),
        service_input_pages=backend.build_first_render_service_input_pages(),
        deferred_control_start=partial,
        service_records=(backend.build_first_direct_render_service_records() if partial
                         else backend.build_first_render_service_records()),
        pre_service_zero_dvas=backend.RENDER_PRE_SERVICE_NEW_ZERO_GLOBAL_PAGES,
        pre_service_retired_dvas=backend.RENDER_PRE_SERVICE_RETIRED_GLOBAL_PAGES,
        work_lifecycle_qwords=backend.build_first_render_work_lifecycle_qwords())
    from .g17g_barriers import record_binding
    graph['dependency_jobs'] = (tuple(record_binding('late_global_pages', address, 0x200, generation=1)
        for address in (render.TILING_FIRMWARE_SCRATCH, render.FRAGMENT_FIRMWARE_SCRATCH)),)
    from .g17g_shim import G17GShimBackend
    return G17GShimBackend._retarget_submission_priority(graph, priority)


def second_render_graph(params, *, private_dvas, priority=2):
    """Firmware-only appended group two on the retained ordinary queue pair."""
    return continued_render_graph(params, 2, private_dvas=private_dvas, priority=priority)


def continued_render_graph(params, ordinal, *, private_dvas, priority=2, retain_partial_slot=True, transport_start=1):
    """One retained work group; caller programs remain opaque.

    The first continuation has a one-time service-stage transition. Subsequent
    ordinary groups use the retained timeline and independent storage rings.
    Partial work two uses its separate private-allocation transition.
    Transport recreation is deliberately not implied by this bounded builder.
    """
    if not 2 <= ordinal < 0x10000:
        raise NotImplementedError("render logical ordinal exceeds its namespace")
    head = transport_head(ordinal, transport_start)
    if params.partial_mode and ordinal > 5 and retain_partial_slot:
        raise NotImplementedError("legacy partial continuation is separate")
    if priority not in (2, 3):
        raise ValueError("unverified render priority")
    if type(retain_partial_slot) is not bool:
        raise ValueError("partial storage selection must be a driver boolean")
    partial = params.partial_mode
    params = replace(params, tiling_lifecycle=(0xce010000f3 if partial else 0xc6010000eb) + (2 << 32) + 0x18
                     + (ordinal - 2) * ((2 << 32) + 3))
    if partial and ordinal >= 3:
        params = replace(params, tiling_lifecycle=backend.direct_render_tiling_lifecycle(ordinal))
    completion_timestamps = None
    completion_timestamp_addresses = None
    if partial:
        params, completion_timestamps, completion_timestamp_addresses = partial_timestamp_destinations(params, ordinal)
    slot = ordinal - 1
    # The legacy compact direct scheduler retains the second execution slot. Its
    # storage lifetime is independent of the logical work/parameter timeline;
    # serialized completion must precede each full descriptor replacement.
    descriptor_ordinal = 2 if partial and ordinal >= 3 and retain_partial_slot else ordinal
    ta = render.render_tiling_allocation_index(descriptor_ordinal)
    fr = render.render_fragment_allocation_index(descriptor_ordinal)
    pool_a, pool_a_address = render.render_pool_a_allocation(ordinal)
    pool_b, pool_b_address = render.render_pool_b_allocation(ordinal)
    items = render.build_clear_work_items(params, backend.PARTIAL_RENDER_TOKEN if partial else backend.RENDER_DEFAULT_TOKEN,
        submission_ordinal=ordinal, event_group=ordinal,
        submission_index=slot % render.RENDER_SUBMISSION_COUNTER_COUNT,
        tiling_descriptor_index=ta, fragment_descriptor_index=fr,
        parameter_index=slot % render.RENDER_PARAMETER_SLOT_COUNT,
        pool_a_index=pool_a, pool_b_index=pool_b,
        pool_a_address=pool_a_address, pool_b_address=pool_b_address,
        queue_context_index=slot, register_resource_index=pool_b,
        shared_control=backend.direct_render_service_object(ordinal) if partial else render.SHARED_CONTROL)
    addresses = dict(
        fragment_optional=backend.RENDER_OPTIONAL_PAGE + 2 * (slot % render.RENDER_OPTIONAL_ITEM_PAIR_COUNT) * render.OPTIONAL_ITEM_SIZE,
        tiling_optional=backend.RENDER_OPTIONAL_PAGE + (2 * (slot % render.RENDER_OPTIONAL_ITEM_PAIR_COUNT) + 1) * render.OPTIONAL_ITEM_SIZE,
        fragment_event=backend.RENDER_EVENT_PAGE + 2 * (slot % render.RENDER_EVENT_ITEM_PAIR_COUNT) * render.EVENT_ITEM_SIZE,
        tiling_event=backend.RENDER_EVENT_PAGE + (2 * (slot % render.RENDER_EVENT_ITEM_PAIR_COUNT) + 1) * render.EVENT_ITEM_SIZE,
        fragment_descriptor=backend.RENDER_FRAGMENT_DESCRIPTOR_PAGE + fr * render.FRAGMENT_DESCRIPTOR_SIZE,
        tiling_descriptor=backend.RENDER_TILING_DESCRIPTOR_PAGE + ta * render.TILING_DESCRIPTOR_SIZE)
    writes = [(addresses[name], body) for name, body in items.items()]
    if completion_timestamps is not None:
        writes.append((completion_timestamps, bytes(32)))
    release = []
    for index, kind in enumerate(("tiling", "fragment")):
        writes.append(g17g.queue_priority_write(
            g17g_postcontrol.QUEUE_PAGE + index * g17g.QUEUE_RECORD_STRIDE, priority))
        writes += [
            (g17g_postcontrol.ITEM_RING_ADDRESSES[index] + (head - 3) * 8,
             struct.pack("<3Q", *(addresses[kind + suffix] for suffix in ("_optional", "_descriptor", "_event")))),
            (g17g_postcontrol.POINTER_BLOCK_ADDRESSES[index] + g17g.POINTER_FIELD_40, struct.pack("<I", head)),
            (backend.RENDER_CHANNEL_RING_PAGES[index] + backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[index]
             + (slot % backend.RENDER_CHANNEL_RING_SLOT_COUNT) * g17g.RING_SLOT_SIZE,
             backend.build_render_stream_ring_slot(index, head, first_submit=False)),
            ((render.TILING_FIRMWARE_SCRATCH, render.FRAGMENT_FIRMWARE_SCRATCH)[index]
             + render.render_queue_context_item_offset(slot % render.RENDER_QUEUE_CONTEXT_ITEM_COUNT),
             render.build_render_queue_context_item(kind, addresses[kind + "_descriptor"], item_index=slot,
                                                    descriptor_index=(ta, fr)[index]))]
        if ordinal > 2:
            writes.append(((render.TILING_STATUS, render.FRAGMENT_STATUS)[index]
                           + (slot % render.RENDER_SUBMISSION_COUNTER_COUNT) * 0x40, bytes(0x40)))
        release.append((backend.RENDER_STATE_PAGE + backend.RENDER_STATE_OFFSETS[index] + 0x20,
                        struct.pack("<I", backend.render_channel_counter(ordinal))))
    low = ()
    if params.buffers is None and slot >= render.RENDER_PARAMETER_SLOT_COUNT:
        low = tuple((dva, bytes(size)) for dva, size in render.build_render_recycled_parameter_ranges(
            slot % render.RENDER_PARAMETER_SLOT_COUNT))
    if partial and not retain_partial_slot:
        writes.extend(((pool_a_address + 8, struct.pack("<2Q", 1, 0x50)),
                       (pool_b_address + 0x48, struct.pack("<Q", 0x100000000))))
    private_dvas = set(private_dvas)
    if params.buffers is not None:
        private_dvas.update(params.buffers.pages)
    from .g17g_barriers import high_record_binding
    jobs = (tuple(high_record_binding(writes, address + render.render_queue_context_item_offset(
        slot % render.RENDER_QUEUE_CONTEXT_ITEM_COUNT), generation=transport_start)
        for address in (render.TILING_FIRMWARE_SCRATCH, render.FRAGMENT_FIRMWARE_SCRATCH)),)
    return dict(format="m1n1-g17g-second-render-firmware-v1", captured_input=None,
        dependency_jobs=jobs,
        partial_transition=partial,
        ordinal=ordinal, transport_start=transport_start, parameters=params, items=items, firmware_addresses=addresses,
        completion_timestamps=completion_timestamps,
        completion_timestamp_addresses=completion_timestamp_addresses,
        high=tuple(writes), low=low, release=tuple(release), private_dvas=tuple(private_dvas),
        firmware_priority=priority)
