# SPDX-License-Identifier: GPL-2.0-only
"""Opaque recurrent render batches, with no per-job proxy round trip."""
import math
import struct
import time

from m1n1.fw.asc.base import ASCMessage1
from . import g17g, g17g_backend as backend, g17g_postcontrol, g17g_render as render, g17g_stream
from .g17g_boot import wait_until
from .g17g_compute_queue import write_pages
from .g17g_render_submit import (continued_render_graph, first_render_completion,
    ordinary_published_fragment_interval, RENDER_TRANSPORT_CAPACITY)
from .g17g_sync import G17GPublishedFault

from .g17g_render_queue import transport_head, recreate_transport

PAGE = 0x4000


def render_wave(parameters, completed, *, private_dvas, priority=2, transport_start=1):
    parameters = tuple(parameters)
    partial = any(params.partial_mode for params in parameters)
    if (not 1 <= len(parameters) <= (64 if partial else 32) or
            not 2 <= completed < completed + len(parameters) < 0x10000 or
            not 1 <= transport_start <= completed + 1 or
            completed + len(parameters) - transport_start + 1 > RENDER_TRANSPORT_CAPACITY):
        raise NotImplementedError("render wave exceeds integrated ordinary interval")
    if partial and (completed < 5 or not all(params.partial_mode and not params.request_tvb_growth
                                              for params in parameters)):
        raise NotImplementedError("partial batches require a retained arena and fixed-pool policy")
    records = tuple(continued_render_graph(params, ordinal, private_dvas=private_dvas, priority=priority,
                                          retain_partial_slot=not partial, transport_start=transport_start)
                    for ordinal, params in enumerate(parameters, completed + 1))
    return dict(format="m1n1-g17g-render-wave-v1", captured_input=None,
        completed=completed, final=completed + len(parameters), transport_start=transport_start, records=records, partial=partial,
        private_dvas=tuple(private_dvas), low=tuple(row for record in records for row in record["low"]))


def retirement(ordinal, transport_start=1):
    head = transport_head(ordinal, transport_start)
    return dict(queue=[head] * 2, pointers=[[head] * 3] * 2,
                channels=[[backend.render_channel_counter(ordinal)] * 3] * 2)


def dispatch_mailboxes(runtime, messages):
    for instance, word0, word1 in messages:
        if instance not in (0, 1):
            raise RuntimeError("render sequencer returned an invalid mailbox owner")
        asc = runtime.asces[instance]
        msg1 = ASCMessage1(word1)
        asc._trace("R", word0, msg1)
        endpoint = asc.epmap.get(msg1.EP)
        if endpoint is None or not endpoint.handle_msg(word0, msg1):
            raise RuntimeError("unhandled preserved render mailbox message: %r" % ((instance, word0, word1),))


def execute_render_wave(runtime, wave, caller_pages, *, timeout=5, activate=None):
    if runtime.state != "complete" or runtime.completed != wave["completed"]:
        raise RuntimeError("render wave does not follow its live owner")
    if runtime.boot.submission_owner is not runtime or wave.get("captured_input") is not None:
        raise RuntimeError("render wave does not own source initialization")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("render wave timeout must be positive and finite")
    partial = wave.get("partial", False)
    if partial != getattr(runtime, "partial_mode", False) or (partial and
            (wave["completed"] < 5 or not getattr(runtime, "minimal_partial_continuation", False))):
        raise RuntimeError("render batch changes the live allocation lifecycle")
    transport_start = wave.get("transport_start", 1)
    recreation = None
    if transport_start != getattr(runtime, "transport_start", 1):
        recreation = recreate_transport(runtime, transport_start)
    history = None
    if partial:
        from .g17g_partial_runtime import restore_history_mappings
        history = restore_history_mappings(runtime)
    service_start = runtime.service_cursor
    started = time.monotonic()
    runtime.evidence = dict(captured_input=None, command_publication_started=False,
                            first_ordinal=wave["completed"] + 1, ordinal=wave["final"])
    if recreation is not None:
        runtime.evidence["transport_recreation"] = recreation
    if history is not None:
        runtime.evidence["history_mappings"] = history
    runtime.state = "publishing"
    records = wave["records"]
    published_partial_states = tuple(struct.unpack_from("<I",
        dict(record["high"])[render.render_pool_a_allocation(record["ordinal"])[1] + 8], 4)[0]
        if partial else None for record in records)
    if partial and any(state != 0 for state in published_partial_states):
        raise ValueError("partial batch publication does not reset its pool state")
    runtime.evidence["published_partial_states"] = published_partial_states
    messages = []
    try:
        runtime.evidence["retirement_before"] = runtime.retirement()
        if runtime.evidence["retirement_before"] != retirement(wave["completed"], transport_start):
            raise RuntimeError("render predecessor is not quiescent")
        if runtime.channel_state() != (service_start,) * 3:
            raise RuntimeError("render batch service cursor differs")
        runtime.evidence["report_ack"] = runtime.ack_retired_reports()
        runtime.evidence["command_publication_started"] = True
        if activate is not None:
            activate(runtime)
        from .g17g_render_buffers import ensure_render_buffers
        for record in records:
            ensure_render_buffers(runtime, record["parameters"])
        runtime.evidence["changed_caller_mappings"] = runtime.update_caller_mappings(caller_pages)
        runtime.flush_tables(1)
        missing = set().union(*(write_pages(record["high"]) for record in records)) - set(runtime.pages)
        if missing:
            runtime.map_globals(sorted(missing), fresh=True)
        before = runtime.completions(records)
        runtime.evidence["completion_before_all"] = before
        published_fragment_intervals = tuple(None if partial else ordinary_published_fragment_interval(record)
                                             for record in records)
        runtime.evidence["published_fragment_intervals"] = [None if value is None else value.hex()
                                                           for value in published_fragment_intervals]
        if not partial:
            pool_addresses = [render.render_pool_a_allocation(record["ordinal"])[1] for record in records]
            if len(set(pool_addresses)) != len(pool_addresses):
                raise RuntimeError("ordinary wave reuses a completion counter before retirement")
            for record, address in zip(records, pool_addresses):
                if any(dva <= address + 0xc < dva + len(body) for dva, body in record["high"]):
                    raise RuntimeError("ordinary publication overwrites its retained completion counter")
        states, ring = runtime.boot.fields["primary_main_fields"]["channels"][12]
        service_pas = tuple(runtime.pa(dva) for dva in states)
        pointers = tuple(runtime.pa(dva + 0x40) for dva in g17g_postcontrol.POINTER_BLOCK_ADDRESSES)
        counters = tuple(runtime.pa(backend.RENDER_STATE_PAGE + offset) for offset in backend.RENDER_STATE_OFFSETS)
        queues = tuple(runtime.pa(dva + 0x1c) for dva in g17g_postcontrol.QUEUE_ADDRESSES)
        commands = []
        service_cursor = service_start
        for index, record in enumerate(records):
            ordinal = record["ordinal"]
            service_bodies = backend.build_render_generation_service_records(
                ordinal, service_cursor, position_registration=False)
            # Resolve into immutable host-side scatter buffers. No future
            # live ring, descriptor or parameter bytes are published early.
            high = tuple(row for row in record["high"] if row[0] not in
                         tuple(dva + 0x40 for dva in g17g_postcontrol.POINTER_BLOCK_ADDRESSES))
            outer = tuple(backend.RENDER_CHANNEL_RING_PAGES[i] + backend.RENDER_CHANNEL_RING_SLOT_OFFSETS[i]
                + ((ordinal - 1) % backend.RENDER_CHANNEL_RING_SLOT_COUNT) * g17g.RING_SLOT_SIZE for i in (0, 1))
            publications = []
            for dva, body in high:
                # Recycled live producer slots become visible only after
                # service, with coprocessor maintenance before replacement.
                flags = 3 if ordinal > backend.RENDER_CHANNEL_RING_SLOT_COUNT and dva in outer else 0
                publications.extend((pa, fragment, flags) for pa, fragment in
                                    runtime.physical_writes(((dva, body),), runtime.pages))
            publications.extend((pa, body, 0) for pa, body in
                runtime.physical_writes(record["low"], runtime.context["pages"]))
            for body_index, body in enumerate(service_bodies):
                slot = backend.render_service_counter(service_cursor + body_index)
                publications.extend((pa, fragment, int(ordinal + (2 if partial else 3) >= 256))
                    for pa, fragment in runtime.physical_writes(
                        ((ring + slot * g17g.SERVICE_RECORD_SIZE, body),), runtime.pages))
            service_cursor = backend.render_service_counter(service_cursor + len(service_bodies))
            # Complete each command on target before publishing the next.
            # Do not set DEFER_COMPLETION: a64-command host wave crosses
            # live parameter/pool reuse, unlike a collision-free pipeline.
            fields = (*service_pas, service_cursor, *pointers, transport_head(ordinal, transport_start), *counters,
                backend.render_channel_counter(ordinal - 1), backend.render_channel_counter(ordinal),
                0x0084000000000011, 0x0083000000000008,
                ordinal, 0, 0, *queues, g17g_stream.RENDER_STREAM_SKIP_OUTPUT_CLEAR |
                (g17g_stream.RENDER_STREAM_FINAL_STATE if partial else 0))
            # Only fresh owned fragment completion metadata is observed by
            # the driver. Shader outputs/expected values never enter here.
            # The ordinary counter-only candidate loses occasional 8x4
            # output subtiles in long native C runs. Keep its additional host
            # counter check, but retain the prior target timestamp policy
            # until an immediate ownership edge is independently qualified.
            witness = runtime.pa(render.render_pool_a_allocation(ordinal)[1] + 0xc if partial
                                 else record["firmware_addresses"]["fragment_descriptor"] + 0x21ff)
            expected = 2 if partial else 0
            commands.append((fields, tuple(publications), ((witness, expected),)))
        sequence_error = None
        try:
            runtime.evidence["sequence"] = g17g_stream.run_render_stream_sequence(
                runtime.u, runtime.p, runtime.iface, runtime.asces, commands, mailbox_capture=messages,
                mailbox_capacity=65536 if partial else None)
        except Exception as error:
            sequence_error = error
            runtime.evidence["sequence_error"] = dict(kind=type(error).__name__, message=str(error),
                ordinal=getattr(error, "ordinal", None), phase=getattr(error, "phase", None))
        finally:
            runtime.evidence["preserved_mailboxes"] = messages
            dispatch_mailboxes(runtime, messages)
        outcomes = None
        def complete():
            nonlocal outcomes
            after = runtime.completions(records)
            runtime.evidence["completion_after_all"] = after
            outcomes = tuple(first_render_completion(old, new, record["ordinal"],
                final_ordinal=wave["final"], max_reports=len(records) * 2,
                published_partial_state=initial, published_fragment_interval=interval)
                for old, new, record, initial, interval in zip(before, after, records,
                    published_partial_states, published_fragment_intervals))
            return "fault" in outcomes or all(outcome == "complete" for outcome in outcomes)
        if sequence_error is not None:
            complete()
        else:
            wait_until(runtime.asces, complete, timeout, "render batch completion")
        if "fault" in outcomes:
            fault = runtime.fault_status()
            runtime.evidence["fault_after"] = fault
            if isinstance(sequence_error, g17g_stream.RenderStreamTimeout):
                runtime.evidence["fault_ordinal"] = sequence_error.ordinal
            for record in records:
                vdm = record["parameters"].vdm_ctrl_stream_base
                if fault["faulted"] and vdm <= fault["address_raw"] << 6 < (vdm & -PAGE) + PAGE:
                    raise G17GPublishedFault.command_fetch_mmu(**fault)
            raise G17GPublishedFault("render-batch-report", fatal=True, metadata=fault)
        if sequence_error is not None:
            raise sequence_error
        runtime.evidence["retirement_after"] = runtime.retirement()
        if runtime.evidence["retirement_after"] != retirement(wave["final"], transport_start):
            raise RuntimeError("render batch did not retire")
        runtime.completed = wave["final"]
        runtime.service_cursor = service_cursor
        runtime.state = "complete"
    except Exception as error:
        runtime.state = "failed"
        runtime.evidence["error"] = "%s: %s" % (type(error).__name__, error)
        raise
    finally:
        runtime.evidence.update(state=runtime.state, elapsed=time.monotonic() - started)
    return runtime.evidence
