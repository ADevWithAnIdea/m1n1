# SPDX-License-Identifier: GPL-2.0-only
"""Firmware-owned direct-render allocation transition after work one.

Only private operand arenas, live service history and firmware references are
handled here. Caller program/resource/attachment contents never enter this
transition. The ordinary runtime handles final work publication/completion.
"""
import struct
import time

from m1n1.fw.asc.base import ASCMessage1
from . import g17g, g17g_backend as backend, g17g_render as render
from .g17g_boot import wait_until
from .g17g_transfer import write_publications

PAGE = 0x4000


def restore_history_mappings(runtime):
    """Retain the full advertised history windows after opening transitions.

    Opening service topology temporarily removes leaves from these windows.
    Long spilling workloads reach those leaves again. Their backing remains
    owned, including the context-zero aliases; restore only missing mappings.
    """
    if (not runtime.partial_mode or runtime.completed < 5 or runtime.state != "complete"
            or runtime.boot.submission_owner is not runtime):
        raise RuntimeError("history restoration requires the completed partial owner")
    if hasattr(runtime, "history_mapping_evidence"):
        return runtime.history_mapping_evidence
    from . import g17g_initdata
    expected = runtime.boot.fields["hwdata_fields"]["region_records"]
    base = runtime.boot.fields["primary_main_fields"]["hwdata_address"]
    live = runtime.read_fields({index: (base + g17g_initdata.HWDATA_REGION_RECORDS + index * 0x20, 0x20)
                               for index in range(len(expected))})
    roots = set(runtime.boot.firmware_roots.values()) | {runtime.root}
    missing, windows = [], []
    for index, record in enumerate(expected):
        actual = g17g_initdata.parse_region_record(live[index])
        if (actual["address_0c"] != record["address_0c"] or
                (actual["word_14"], actual["word_18"]) != (0x800, 0x40)):
            raise RuntimeError("history descriptor differs from its owned window")
        address, size = record["address_0c"], 0x800 * 0x40
        windows.append(dict(address=address, bytes=size))
        for dva in range(address, address + size, PAGE):
            pa = runtime.pages[dva]
            mappings = [runtime.uat.iotranslate_root(root, dva, PAGE) for root in roots]
            if all(mapping == [(None, PAGE)] for mapping in mappings):
                missing.append(dva)
            elif not all(mapping == [(pa, PAGE)] for mapping in mappings):
                raise RuntimeError("history mapping changed ownership")
    runtime.map_globals(missing, fresh=False)
    for dva in missing:
        if any(runtime.uat.iotranslate_root(root, dva, PAGE) != [(runtime.pages[dva], PAGE)]
               for root in roots):
            raise RuntimeError("restored history mapping differs between firmware roots")
    runtime.history_mapping_evidence = dict(windows=windows,
        restored=[dict(dva=dva, pa=runtime.pages[dva]) for dva in missing],
        existing_backing=True, verified=True)
    return runtime.history_mapping_evidence


def reset_operand_payloads(runtime):
    """Initialize reused private operand storage before its next work.

    Old address-list contents otherwise become the new arena's payload. Only
    explicitly owned payload pages are cleared: no tables, caller BOs, padding
    or global aliases. The zero publication is one packed device-side batch.
    """
    if not runtime.partial_mode or not 1 <= runtime.completed < 5:
        raise ValueError("operand reset requires a quiescent partial-layout owner")
    dvas = tuple(backend.RENDER_SECOND_OPERAND_BASE + i * render.RENDER_OPERAND_STRIDE + offset
                 for i in range(render.PARTIAL_RENDER_OPERAND_COUNT)
                 for offset in range(0, render.RENDER_OPERAND_SIZE, PAGE))
    if not set(dvas) <= runtime.private_dvas:
        raise ValueError("operand reset escapes private backing")
    physical = tuple(runtime.context["pages"][dva] for dva in dvas)
    caller_pas = {item.pa for item in runtime.context["caller_mappings"].values()}
    if len(set(physical)) != len(physical) or set(physical) & (caller_pas | set(runtime.pages.values())):
        raise ValueError("operand reset would clear aliased caller/global backing")
    start = time.monotonic()
    write_publications(runtime.u, runtime.p, runtime.iface, ((pa, bytes(PAGE)) for pa in physical))
    runtime.publish(physical)
    runtime.evidence["operand_reset"] = dict(pages=len(dvas), bytes=len(dvas) * PAGE,
        seconds=time.monotonic() - start, first_dva=dvas[0], last_dva=dvas[-1])


def prepare_second_partial(runtime, timeout, *, minimal=True):
    context = runtime.context
    start = getattr(runtime, "service_cursor", 3)
    if not runtime.partial_mode or runtime.completed != 1 or runtime.channel_state() != (start,) * 3:
        raise RuntimeError("partial transition requires its completed first direct work")
    bodies = ((g17g.build_service_opcode2e_record(1),) if minimal
              else backend.build_second_direct_render_service_records())
    target = start + len(bodies)
    if target >= 256:
        raise NotImplementedError("partial service-registration wrap not integrated")
    low_dvas = backend.expand_second_direct_render_context1_dvas()
    high_dvas = ((backend.RENDER_SECOND_SERVICE_STATE, backend.RENDER_SECOND_SERVICE_OBJECT) if minimal
                 else backend.expand_second_direct_render_high_dvas())
    old_low = backend.expand_second_direct_retired_context1_dvas()
    if (set(low_dvas) & set(runtime.context.get("private_labels", runtime.context["pages"])) or
            not set(old_low) <= runtime.private_dvas):
        raise RuntimeError("partial transition does not own disjoint private arenas")
    # Verify every new high leaf is absent before allocating or overwriting
    # the inventory of previously retired physical pages.
    for root in runtime.boot.firmware_roots.values():
        for dva in high_dvas:
            if runtime.uat.iotranslate_root(root, dva, PAGE) != [(None, PAGE)]:
                raise RuntimeError("second partial high leaf is already mapped at %#x" % dva)
    history = bytes(PAGE) if minimal else runtime.read_fields({0: (backend.RENDER_FIRST_SERVICE_HISTORY_PAGE, PAGE)})[0]
    relocated = history if minimal else backend.build_second_direct_render_service_history(history)
    low_images = backend.second_direct_render_context1_page_images()
    high_images = backend.build_second_direct_render_service_pages(relocated)
    if minimal:
        high_images = {va: high_images[va] for va in high_dvas}
    low_pa = runtime.alloc(len(low_dvas) * PAGE)
    runtime.context["allocations"].append((low_pa, len(low_dvas) * PAGE))
    high_pa = runtime.alloc(len(high_dvas) * PAGE)
    for index, dva in enumerate(low_dvas):
        runtime.context["pages"][dva] = low_pa + index * PAGE
    for index, dva in enumerate(high_dvas):
        runtime.pages[dva] = high_pa + index * PAGE
    publications = runtime.physical_writes(tuple(low_images.items()), runtime.context["pages"])
    publications += runtime.physical_writes(tuple(high_images.items()), runtime.pages)
    write_publications(runtime.u, runtime.p, runtime.iface, publications)
    runtime.publish((low_pa + i * PAGE for i in range(len(low_dvas))))
    runtime.publish((high_pa + i * PAGE for i in range(len(high_dvas))))
    for space, root, dvas, pages in (
            ("context1-selector0", runtime.context["root0"], low_dvas, runtime.context["pages"]),
            ("context64-selector1", runtime.root, high_dvas, runtime.pages)):
        for dva in dvas:
            runtime.uat.iomap_at_root(root, dva, pages[dva], PAGE,
                **backend.second_direct_render_leaf_flags(space, dva))
    runtime.context["table_witnesses"].update(low_dvas)
    runtime.private_dvas.update(low_dvas)
    layout = context.get("layout")
    if layout is not None:
        layout.reserve(low_dvas)
        layout.relocate_context(runtime, context, pages=low_dvas)
    runtime.flush_tables(context.get("context_id", runtime.context_id))
    runtime.flush_tables(0x40)
    references = {} if minimal else {
        0xfffffc20c0018000 + 0x12f4: backend.RENDER_SECOND_SERVICE_OBJECT,
        0xfffffc20c0788000 + 0x273c: backend.RENDER_SECOND_SERVICE_HISTORY_PAGE,
        0xfffffc20c0788000 + 0x2750: 0x0187000000000002,
        0xfffffc20c0788000 + 0x275c: 0xfffffc20c0830000,
        0xfffffc20c0788000 + 0x277c: 0xfffffc20c0858000,
    }
    before = runtime.read_fields({dva: (dva, 8) for dva in references}) if references else {}
    if references:
        runtime.publish_writes((dva, struct.pack("<Q", value)) for dva, value in references.items())
    runtime.evidence["partial_allocation"] = dict(low_pages=len(low_dvas), high_pages=len(high_dvas),
        minimal=minimal,
        history_before=history.hex(), history_relocated=relocated.hex(),
        reference_before={hex(dva): body.hex() for dva, body in before.items()})
    states, ring = runtime.boot.fields["primary_main_fields"]["channels"][12]
    entries = tuple((ring + (start + index) * g17g.SERVICE_RECORD_SIZE, body)
                    for index, body in enumerate(bodies))
    before_slots = runtime.read_fields({index: (dva, len(body)) for index, (dva, body) in enumerate(entries)})
    if any(any(body) for body in before_slots.values()):
        raise RuntimeError("second partial service slots were not empty")
    runtime.publish_writes((*entries, (states[2], struct.pack("<I", target))))
    for _ in bodies:
        runtime.asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
    wait_until(runtime.asces, lambda: runtime.channel_state() == (target,) * 3, timeout,
               "second partial service registration")
    runtime.service_cursor = target
    runtime.minimal_partial_continuation = minimal
    runtime.evidence["partial_allocation"]["service_retired"] = target
    if minimal:
        reset_operand_payloads(runtime)


def postservice_preimage_is_owned(runtime, dva, value):
    """The retained-path reset consumes live FW counters, not exemplars.

    The qualified direct recipe replaces these firmware-produced scalar
    preimages after completed work one and its seven-record service interval.
    Their exact values vary with partial resumes and scheduling; imposing the
    tiny draw's values would make valid caller work fail. All other stage
    fields retain their normal checks. History must match the fully validated
    page we just relocated, never arbitrary counters masquerading as records.
    """
    allocation = runtime.evidence.get("partial_allocation", {})
    if (not getattr(runtime, "partial_mode", False) or runtime.completed != 1 or
            runtime.boot.submission_owner is not runtime or
            allocation.get("service_retired") != getattr(runtime, "service_cursor", 10)):
        return False
    if dva in (
            0xfffffc2000024e40, 0xfffffc200002f118, 0xfffffc200002f1e0,
            0xfffffc20015e8008, 0xfffffc20015f0008,
            0xfffffc20c07c0008, 0xfffffc20c07c0020, 0xfffffc20c07c0028):
        return True
    offset = dva - backend.RENDER_SECOND_SERVICE_HISTORY_PAGE
    if offset in (0, 0x30, 0x40, 0x70):
        history = bytes.fromhex(allocation["history_relocated"])
        return value == struct.unpack_from("<Q", history, offset)[0]
    return False


def retire_first_partial(runtime, *, context=None, shared=True):
    """After registration, remove only the source-proven private old leaves."""
    context = runtime.context if context is None else context
    dvas = backend.expand_second_direct_retired_context1_dvas()
    minimal = (runtime.evidence.get("partial_allocation", {}).get("minimal") is True
               if shared else getattr(runtime, "minimal_partial_continuation", False) is True)
    # Retained admission still reaches the first operand's trailing pages at
    # work173. Removing them followed the short native allocation transition,
    # whose replacement lifecycle differs from our persistent arena. Keep
    # their original backing and bytes for the lifetime of this context.
    retained = (0x7200200000, 0x7200204000) if minimal else ()
    retired = tuple(dva for dva in dvas if dva not in retained)
    for dva in dvas:
        if dva not in runtime.private_dvas or (context.get("layout") is None and dva in context["caller_mappings"]):
            raise RuntimeError("partial retirement attempted a caller page")
        pa = context["pages"][dva]
        if runtime.uat.iotranslate_root(context["root1" if context.get("layout") is not None else "root0"], dva, PAGE) != [(pa, PAGE)]:
            raise RuntimeError("retired partial private backing changed")
    for dva in retired:
        if context.get("layout") is None and runtime.uat.iounmap_root(context["root0"], dva, PAGE) != PAGE:
            raise RuntimeError("partial private retirement length differs")
        del context["pages"][dva]
        context.get("private_labels", set()).discard(dva)
    runtime.flush_tables(context.get("context_id", runtime.context_id))
    high = ((0xfffffc2001608000, 0xfffffc20c08b0000)
            if minimal
            else backend.RENDER_SECOND_PRESERVICE_RETIRED_GLOBAL_PAGES)
    if shared:
        runtime.unmap_globals(high)
    context["partial_opening_retired"] = True
    context["partial_pending_service"] = False
    # Retain allocation ownership until root teardown; absence of a leaf is
    # not by itself permission to recycle firmware-reachable backing.
    runtime.evidence["partial_retired"] = dict(low_pages=len(retired), high_pages=len(high) if shared else 0,
        retained_low_pages=[dict(dva=dva, pa=context["pages"][dva]) for dva in retained])


def prepare_partial_context(runtime, context, ordinal):
    """Join the current render lifetime without replaying global service.

    The reference's activate_render_context1 / retire_render_context1_work_one
    switch private roots while the service timeline remains device-owned.
    Caller lifecycle pages must already come from this VM's BOs; this helper
    never copies the reference's compiler/program bundle into caller memory.
    """
    if ordinal <= 2:
        return
    if not context.get("partial_opening_retired"):
        retire_first_partial(runtime, context=context, shared=False)
    # Work two fills holes in the common operand backing as well as creating
    # arena B. A VM which skipped work two still needs those payload leaves.
    payload = set(backend.expand_second_direct_render_context1_dvas()) - set(
        backend.expand_fourth_direct_render_context1_dvas())
    missing = payload - set(context.get("private_labels", context["pages"]))
    images = {}
    if ordinal > 5:
        arena = set(backend.expand_third_direct_render_context1_dvas())
        present = arena & set(context["pages"])
        if present and present != arena:
            raise RuntimeError("partial VM retained arena is incomplete")
        if not present:
            missing.update(arena)
            images = backend.third_direct_render_context1_page_images()
    if missing:
        if context.get("layout") is None and missing & set(context["caller_mappings"]):
            raise ValueError("partial VM allocation overlaps caller backing")
        pa = runtime.alloc(len(missing) * PAGE)
        context["allocations"].append((pa, len(missing) * PAGE))
        for index, dva in enumerate(sorted(missing)):
            context["pages"][dva] = pa + index * PAGE
        writes = runtime.physical_writes(tuple(images.items()), context["pages"])
        write_publications(runtime.u, runtime.p, runtime.iface, writes)
        runtime.publish(context["pages"][dva] for dva in missing)
        for dva in missing:
            flags = (backend.second_direct_render_leaf_flags if dva in payload
                     else backend.third_direct_render_leaf_flags)
            runtime.uat.iomap_at_root(context["root0"], dva, context["pages"][dva], PAGE,
                                     **flags("context1-selector0", dva))
        context["table_witnesses"].update(missing)
        runtime.private_dvas.update(missing)
        layout = context.get("layout")
        if layout is not None:
            layout.reserve(missing)
            layout.relocate_context(runtime, context, pages=missing)
        runtime.flush_tables(context.get("context_id", runtime.context_id))


def warmup_dvas(ordinal):
    if ordinal in (3, 5):
        return backend.expand_third_direct_render_context1_dvas()
    if ordinal == 4:
        return backend.expand_fourth_direct_render_context1_dvas()
    raise ValueError("partial warm-up is limited to work3/4/5")


def prepare_partial_warmup(runtime, ordinal):
    """Reuse the bounded A/B service pair; replace only private operand arena."""
    if not runtime.partial_mode or runtime.completed != ordinal - 1:
        raise RuntimeError("partial warm-up does not follow its completed owner")
    context = runtime.context
    low = warmup_dvas(ordinal)
    odd = ordinal != 4
    low_images = (backend.third_direct_render_context1_page_images() if odd
                  else backend.fourth_direct_render_context1_page_images())
    high_images = (backend.build_third_direct_render_service_pages() if odd
                   else backend.build_fourth_direct_render_service_pages())
    flags = backend.third_direct_render_leaf_flags if odd else backend.fourth_direct_render_leaf_flags
    if set(low) & set(runtime.context.get("private_labels", runtime.context["pages"])):
        raise RuntimeError("partial warm-up private arena is already mapped")
    minimal = getattr(runtime, "minimal_partial_continuation", False) is True
    for dva in high_images:
        for root in runtime.boot.firmware_roots.values():
            expected = None if minimal else runtime.pages[dva]
            if runtime.uat.iotranslate_root(root, dva, PAGE) != [(expected, PAGE)]:
                raise RuntimeError("partial warm-up high service pair lost its owner")
    if minimal:
        for dva in high_images:
            runtime.uat.iomap_at_root(runtime.root, dva, runtime.pages[dva], PAGE,
                                     **flags("context64-selector1", dva))
    pa = runtime.alloc(len(low) * PAGE)
    runtime.context["allocations"].append((pa, len(low) * PAGE))
    for index, dva in enumerate(low):
        runtime.context["pages"][dva] = pa + index * PAGE
    physical = runtime.physical_writes(tuple(low_images.items()), runtime.context["pages"])
    write_publications(runtime.u, runtime.p, runtime.iface, physical)
    runtime.publish(pa + index * PAGE for index in range(len(low)))
    runtime.publish_writes(high_images.items())
    for dva in low:
        runtime.uat.iomap_at_root(runtime.context["root0"], dva, runtime.context["pages"][dva], PAGE,
                                 **flags("context1-selector0", dva))
    runtime.context["table_witnesses"].update(low)
    runtime.private_dvas.update(low)
    layout = context.get("layout")
    if layout is not None:
        layout.reserve(low)
        layout.relocate_context(runtime, context, pages=low)
    runtime.flush_tables(context.get("context_id", runtime.context_id))
    if minimal:
        runtime.flush_tables(0x40)
    runtime.evidence["partial_warmup"] = dict(ordinal=ordinal, slot="A" if odd else "B",
        private_low_pages=len(low), reused_high_pages=len(high_images), minimal=minimal)
    if minimal:
        reset_operand_payloads(runtime)


def retire_partial_warmup(runtime, ordinal):
    # The reference's work-three retirement also unbinds a 28-page compiler
    # allocation. It belongs to the caller, not this private allocation cycle.
    low = (backend.expand_fourth_direct_render_context1_dvas() if ordinal in (3, 5)
           else backend.expand_third_direct_render_context1_dvas() if ordinal == 4 else ())
    if not low or runtime.evidence.get("partial_warmup", {}).get("ordinal") != ordinal:
        raise RuntimeError("partial warm-up retirement lacks its staged owner")
    # Source A/B/A keeps B's arena until A's work-three service consumes it.
    # The preceding arena can belong to an inactive root, not the current VM.
    context = getattr(runtime, "last_render_context", runtime.context)
    for dva in low:
        if dva not in runtime.private_dvas or (context.get("layout") is None and dva in context["caller_mappings"]):
            raise RuntimeError("partial warm-up retirement would touch a caller page")
        if runtime.uat.iotranslate_root(context["root1" if context.get("layout") is not None else "root0"], dva, PAGE) != [(context["pages"][dva], PAGE)]:
            raise RuntimeError("partial warm-up old arena translation changed")
    for dva in low:
        if context.get("layout") is None and runtime.uat.iounmap_root(context["root0"], dva, PAGE) != PAGE:
            raise RuntimeError("partial warm-up old arena unmap length changed")
        del context["pages"][dva]
        context.get("private_labels", set()).discard(dva)
    context["partial_pending_service"] = False
    runtime.flush_tables(context.get("context_id", runtime.context_id))
    minimal = getattr(runtime, "minimal_partial_continuation", False) is True
    if minimal:
        high = (backend.expand_fourth_direct_render_high_dvas() if ordinal in (3, 5)
                else backend.expand_third_direct_render_high_dvas())
        runtime.unmap_globals(high)
    runtime.evidence["partial_warmup"].update(retired_private_pages=len(low),
        retained_high_pairs=1 if minimal else 2, caller_pages_retired=0)
