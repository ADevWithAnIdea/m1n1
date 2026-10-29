# SPDX-License-Identifier: GPL-2.0-only
"""Target-side publication and sequencing for repeated G17G render work.

The host prepares immutable command and scatter tables once.  The target then
publishes each generation just in time, kicks firmware, and waits locally for
the real completion boundary.  Consequently a batch costs one proxy call
instead of one or more calls per generation.
"""

import struct
import time

from ..proxy import UartError


# Queue/channel retirement precedes accelerator completion.  Keep exactly one
# render graph in flight until its fragment descriptor completion timestamp is
# written.  The wait still runs target-side, so this costs no proxy transaction
# per generation and makes every finite scheduler/output resource reusable at
# a proved ownership boundary.
RENDER_STREAM_BATCH_SIZE = 1
RENDER_STREAM_DEFER_COMPLETION = 1 << 0
RENDER_STREAM_SKIP_OUTPUT_CLEAR = 1 << 1
# Exact 32-bit completion state; proceed immediately when it matches.
RENDER_STREAM_FINAL_STATE = 1 << 2
RENDER_STREAM_COMMAND_QWORDS = 29
RENDER_STREAM_COMMAND_SIZE = RENDER_STREAM_COMMAND_QWORDS * 8


_WRITE_CONTROL_RECORD_ASM = r"""
    // x0: owned physical destination, x1: stable host-only source, x2: size.
    // Use the same coprocessor/CPU ordering as split-report acknowledgments.
    and x3, x0, #-128
    add x4, x0, x2
    sub x4, x4, #1
    and x4, x4, #-128
    mov x5, x3
1:
    sys #3, c7, c3, #4, x5
    sys #3, c7, c3, #5, x5
    dsb osh
    isb
    dc ivac, x5
    add x5, x5, #128
    cmp x5, x4
    b.ls 1b
    dsb osh
2:
    ldr w6, [x1], #4
    str w6, [x0], #4
    subs x2, x2, #4
    b.ne 2b
    mov x5, x3
3:
    dc civac, x5
    dsb osh
    sys #3, c7, c3, #4, x5
    sys #3, c7, c3, #5, x5
    add x5, x5, #128
    cmp x5, x4
    b.ls 3b
    dsb osh
    isb
    mov x0, #0
"""


def _validate_control_record(pa, data):
    if (type(pa) is not int or not 0 < pa < (1 << 42) or pa % 4 or
            not isinstance(data, bytes) or not 4 <= len(data) <= 64 or
            len(data) % 4 or pa + len(data) > (1 << 42)):
        raise ValueError("invalid owned control subrange")


def write_control_record(u, p, iface, pa, data):
    """Publish an owned 4..64-byte control subrange without proxy gaps.

    The caller validates ownership and firmware-code exclusions. No neighbor
    bytes are intentionally stored. This is cache maintenance, not a claim
    that the firmware has consumed the record or completed the workload.
    """
    _validate_control_record(pa, data)
    with u.heap.guarded_malloc(len(data)) as source:
        iface.writemem(source, data)
        p.dc_civac(source, len(data))
        result = int(u.exec(_WRITE_CONTROL_RECORD_ASM, pa, source, len(data)))
    if result != 0:
        raise RuntimeError("control subrange publication failed")


_WRITE_CONTROL_RECORDS_ASM = r"""
    // Retain table/count outside the single-record helper's x0..x6.
    mov x7, x0
    mov x8, x1
control_record_next:
    ldp x0, x1, [x7], #16
    ldr x2, [x7], #8
""" + _WRITE_CONTROL_RECORD_ASM + r"""
    subs x8, x8, #1
    b.ne control_record_next
"""


def write_control_records(u, p, iface, writes):
    """Publish 1..16 ordered owned records with one target call.

    Each partial store retains the single-record coherency sequence, including
    its final barrier, so a caller can publish the producer LAST. Validate the
    entire batch before any device write; ownership/code exclusions remain
    the caller's responsibility. No ring-consumption claim is made.
    """
    writes = tuple(writes)
    if not 1 <= len(writes) <= 16:
        raise ValueError("invalid control publication batch length")
    for pa, data in writes:
        _validate_control_record(pa, data)
    table_size = len(writes) * 24
    size = table_size + sum(len(data) for _, data in writes)
    with u.heap.guarded_malloc(size) as source:
        # Cache maintenance on a destination must not invalidate the immutable
        # source/table, even if the heap happens to share a neighboring line.
        for pa, data in writes:
            if (pa & -128) < source + size and source < ((pa + len(data) + 127) & -128):
                raise ValueError("control destination overlaps private source cache lines")
        offset, entries = table_size, []
        for pa, data in writes:
            entries.append(struct.pack("<3Q", pa, source + offset, len(data)))
            offset += len(data)
        body = b"".join(entries) + b"".join(data for _, data in writes)
        iface.writemem(source, body)
        p.dc_civac(source, len(body))
        result = int(u.exec(_WRITE_CONTROL_RECORDS_ASM, source, len(writes)))
    if result != 0:
        raise RuntimeError("control batch publication failed")


def normalize_report_ack_pairs(pairs):
    """Validate physical host/peer words for split report credits."""
    normalized = tuple(
        (int(host_pa), int(peer_pa)) for host_pa, peer_pa in pairs
    )
    hosts = set()
    for host_pa, peer_pa in normalized:
        if (
            not host_pa
            or not peer_pa
            or host_pa & 3
            or peer_pa & 3
            or host_pa == peer_pa
        ):
            raise ValueError("invalid render report acknowledgement pair")
        if host_pa in hosts:
            raise ValueError("duplicate render report acknowledgement host")
        hosts.add(host_pa)
    return normalized


_ACK_REPORT_PAIRS_ASM = r"""
    mov x10, x0
    mov x11, x1
    mov x0, #0
    cbz x11, report_ack_done
report_ack_next:
    ldp x16, x17, [x10], #16
    // Firmware writes the peer through the noncoherent Apple coprocessor
    // path.  Invalidate that path and the CPU cache before sampling it.
    and x18, x16, #-128
    sys #3, c7, c3, #4, x18
    sys #3, c7, c3, #5, x18
    and x18, x17, #-128
    sys #3, c7, c3, #4, x18
    sys #3, c7, c3, #5, x18
    dsb osh
    isb
    dc ivac, x16
    dc ivac, x17
    dsb osh
    ldr w8, [x16]
    ldr w9, [x17]
    cmp w8, w9
    b.eq report_ack_advance
    str w9, [x16]
    dc civac, x16
    dsb osh
    and x18, x16, #-128
    sys #3, c7, c3, #4, x18
    sys #3, c7, c3, #5, x18
    dsb osh
    isb
    add x0, x0, #1
report_ack_advance:
    subs x11, x11, #1
    b.ne report_ack_next
report_ack_done:
"""


def acknowledge_report_pairs(u, p, iface, pairs):
    """Return split firmware report credits in one target-side operation.

    This is intentionally a batch boundary service, not a per-generation host
    poll.  It uses the same coherency sequence as the render stream sequencer
    and returns only the number of host words that actually advanced.
    """
    pairs = normalize_report_ack_pairs(pairs)
    if not pairs:
        return {"pair_count": 0, "changed_count": 0, "proxy_call_count": 0}
    body = b"".join(
        struct.pack("<2Q", host_pa, peer_pa)
        for host_pa, peer_pa in pairs
    )
    with u.heap.guarded_malloc(len(body)) as table_pa:
        iface.writemem(table_pa, body)
        p.dc_civac(table_pa, len(body))
        changed = int(u.exec(
            _ACK_REPORT_PAIRS_ASM, table_pa, len(pairs)
        ))
    if not 0 <= changed <= len(pairs):
        raise RuntimeError(
            "report acknowledgement returned invalid change count %d" %
            changed
        )
    return {
        "pair_count": len(pairs),
        "changed_count": changed,
        "proxy_call_count": 1,
    }


def render_stream_requires_fence(
        ordinal, start_ordinal, pool_size, final_ordinal,
        service_rollover=False):
    """Return whether a staged command closes its collision-free batch."""
    ordinal = int(ordinal)
    start_ordinal = int(start_ordinal)
    pool_size = int(pool_size)
    final_ordinal = int(final_ordinal)
    if pool_size <= 0 or ordinal < start_ordinal or final_ordinal < ordinal:
        raise ValueError("invalid render stream fence interval")
    return (
        ordinal == final_ordinal
        or (ordinal - start_ordinal) % pool_size == pool_size - 1
        or bool(service_rollover)
    )


def render_stream_batch_index(
        ordinal, start_ordinal, batch_size,
        forced_fence_ordinals=()):
    """Return the stable-output batch containing one submission ordinal."""
    ordinal = int(ordinal)
    start_ordinal = int(start_ordinal)
    batch_size = int(batch_size)
    if batch_size <= 0 or ordinal < start_ordinal:
        raise ValueError("invalid render stream batch interval")
    forced_fence_ordinals = tuple(sorted(set(
        map(int, forced_fence_ordinals)
    )))
    if any(fence < start_ordinal for fence in forced_fence_ordinals):
        raise ValueError("forced render stream fence precedes the interval")
    segment_start = start_ordinal
    batch_base = 0
    for fence in forced_fence_ordinals:
        if ordinal <= fence:
            return batch_base + (ordinal - segment_start) // batch_size
        batch_base += (fence - segment_start) // batch_size + 1
        segment_start = fence + 1
    return batch_base + (ordinal - segment_start) // batch_size


class RenderStreamTimeout(RuntimeError):
    """One target-sequenced render generation missed its progress boundary."""

    def __init__(self, phase, ordinal, detail=None):
        self.phase = str(phase)
        self.ordinal = int(ordinal)
        self.detail = detail
        if isinstance(detail, dict):
            suffix = " (%s)" % ", ".join(
                "%s=%r" % (key, value)
                for key, value in detail.items()
            )
        elif detail is not None:
            suffix = " (channel-12 state %r, expected %d)" % (
                detail[:3], detail[3]
            )
        else:
            suffix = ""
        super().__init__(
            "target-side render stream sequencer timed out in %s at "
            "generation %d%s" % (self.phase, self.ordinal, suffix)
        )


_SCATTER_COPY_ASM = r"""
    cbz x1, scatter_done
scatter_next:
    ldp x2, x3, [x0]
    ldr x4, [x0, #16]
    add x0, x0, #24
scatter_qword:
    cmp x4, #8
    b.lo scatter_byte
    ldr x5, [x3], #8
    str x5, [x2], #8
    sub x4, x4, #8
    b scatter_qword
scatter_byte:
    cbz x4, scatter_record_done
    ldrb w5, [x3], #1
    strb w5, [x2], #1
    sub x4, x4, #1
    b scatter_byte
scatter_record_done:
    subs x1, x1, #1
    b.ne scatter_next
scatter_done:
    dsb sy
    mov x0, #0
"""


_KICK_AND_WAIT_FOR_RENDER_OUTPUT_ASM = r"""
    // A nonzero x3 replaces the ordinary host mailbox send.  Commit INBOX0
    // and endpoint 0x21's INBOX1 before entering the same local progress loop,
    // so synchronization adds no proxy transaction to the work kick.
    cbz x3, render_completion_start_timer
    add x6, x1, #0x8000
render_completion_wait_inbox:
    ldr w7, [x6, #0x110]
    tbnz w7, #16, render_completion_wait_inbox
    str x3, [x6, #0x800]
    mov x7, #0x21
    str x7, [x6, #0x808]
    dsb sy
render_completion_wait_inbox_accept:
    ldr w7, [x6, #0x110]
    tbnz w7, #16, render_completion_wait_inbox_accept
render_completion_start_timer:
    mrs x4, cntfrq_el0
    mov x5, #5
    mul x4, x4, x5
    mrs x5, cntpct_el0
    add x4, x4, x5
render_completion_wait:
    cbz x1, render_completion_drain_secondary
    add x6, x1, #0x8000
render_completion_drain_primary_next:
    ldr w7, [x6, #0x114]
    tbnz w7, #17, render_completion_drain_secondary
    ldr x7, [x6, #0x830]
    ldr x7, [x6, #0x838]
    b render_completion_drain_primary_next
render_completion_drain_secondary:
    cbz x2, render_completion_drain_done
    add x6, x2, #0x8000
render_completion_drain_secondary_next:
    ldr w7, [x6, #0x114]
    tbnz w7, #17, render_completion_drain_done
    ldr x7, [x6, #0x830]
    ldr x7, [x6, #0x838]
    b render_completion_drain_secondary_next
render_completion_drain_done:
    and x6, x0, #-128
    sys #3, c7, c3, #4, x6
    sys #3, c7, c3, #5, x6
    dsb osh
    dc ivac, x0
    dsb osh
    ldr x5, [x0]
    cbnz x5, render_completion_done
    mrs x5, cntpct_el0
    cmp x5, x4
    b.hs render_completion_timeout
    // Avoid saturating the shared fabric with cache and mailbox probes while
    // the accelerators run.  Roughly 60 us at the architectural counter rate
    // is still far shorter than a host polling interval.
    mrs x6, cntfrq_el0
    lsr x6, x6, #14
    add x6, x6, x5
render_completion_backoff:
    mrs x5, cntpct_el0
    cmp x5, x6
    b.lo render_completion_backoff
    b render_completion_wait
render_completion_timeout:
    mov x0, #0
    b render_completion_return
render_completion_done:
    mov x0, x5
render_completion_return:
"""


_NOTIFY_AND_WAIT_FOR_RENDER_SERVICE_ASM = r"""
    // The three channel-12 state words are x0 + {0,0x10,0x20}; x1/x2 are
    // the primary and secondary ASC bases. w3 contains the expected modulo-
    // 256 counter plus bit 8 (allow the first consumer to remain work-
    // deferred) and bit 9 (wait only; do not send another notification).
    mov x9, x0
    add x10, x0, #0x10
    add x11, x0, #0x20
    mov x12, x1
    mov x13, x2
    mov w18, w3
    and w14, w3, #0xff
    tbnz w18, #9, render_service_notify_start_timer
    add x6, x12, #0x8000
render_service_notify_wait_inbox:
    ldr w7, [x6, #0x110]
    tbnz w7, #16, render_service_notify_wait_inbox
    mov x7, #0x11
    movk x7, #0x84, lsl #48
    str x7, [x6, #0x800]
    mov x7, #0x21
    str x7, [x6, #0x808]
    dsb sy
render_service_notify_wait_accept:
    ldr w7, [x6, #0x110]
    tbnz w7, #16, render_service_notify_wait_accept
render_service_notify_start_timer:
    mrs x15, cntfrq_el0
    mov x16, #5
    mul x15, x15, x16
    mrs x16, cntpct_el0
    add x15, x15, x16
render_service_notify_wait:
    // Raw-drain both ASCs so a full outbox cannot block service consumption.
    cbz x12, render_service_notify_drain_secondary
    add x6, x12, #0x8000
render_service_notify_drain_primary_next:
    ldr w7, [x6, #0x114]
    tbnz w7, #17, render_service_notify_drain_secondary
    ldr x8, [x6, #0x830]
    ldr x8, [x6, #0x838]
    b render_service_notify_drain_primary_next
render_service_notify_drain_secondary:
    cbz x13, render_service_notify_drain_done
    add x6, x13, #0x8000
render_service_notify_drain_secondary_next:
    ldr w7, [x6, #0x114]
    tbnz w7, #17, render_service_notify_drain_done
    ldr x8, [x6, #0x830]
    ldr x8, [x6, #0x838]
    b render_service_notify_drain_secondary_next
render_service_notify_drain_done:
    // Pull firmware writes through the Apple coprocessor cache and then the
    // CPU cache before testing all three independently owned words.
    and x6, x9, #-128
    sys #3, c7, c3, #4, x6
    sys #3, c7, c3, #5, x6
    and x6, x10, #-128
    sys #3, c7, c3, #4, x6
    sys #3, c7, c3, #5, x6
    and x6, x11, #-128
    sys #3, c7, c3, #4, x6
    sys #3, c7, c3, #5, x6
    dsb osh
    dc ivac, x9
    dc ivac, x10
    dc ivac, x11
    dsb osh
    ldr w0, [x9]
    ldr w1, [x10]
    ldr w2, [x11]
    tbnz w18, #8, render_service_notify_check_second
    cmp w0, w14
    b.ne render_service_notify_again
render_service_notify_check_second:
    cmp w1, w14
    b.ne render_service_notify_again
    cmp w2, w14
    b.eq render_service_notify_success
render_service_notify_again:
    mrs x6, cntpct_el0
    cmp x6, x15
    b.hs render_service_notify_return
    mrs x7, cntfrq_el0
    lsr x7, x7, #14
    add x7, x7, x6
render_service_notify_backoff:
    mrs x6, cntpct_el0
    cmp x6, x7
    b.lo render_service_notify_backoff
    b render_service_notify_wait
render_service_notify_success:
    mov x6, #1
    lsl x6, x6, #63
    orr x0, x0, x6
render_service_notify_return:
    orr x0, x0, x1, lsl #16
    orr x0, x0, x2, lsl #32
"""


_RENDER_STREAM_SEQUENCE_ASM = r"""
    stp x19, x20, [sp, #-32]!
    str x30, [sp, #16]
    mov x12, x0
    mov x13, x1
render_sequence_next:
    // Return any report credits produced before this sequencer began (the
    // source stream already executed generations one and two), then clear the
    // stable physical output extent before exposing this generation.
    bl render_sequence_ack_reports
    ldr x18, [x12, #144]
    tbnz x18, #1, render_sequence_output_zero_done
    ldp x14, x15, [x12, #112]
    cbz x15, render_sequence_output_zero_done
    add x15, x14, x15
    mov x16, x14
render_sequence_output_zero:
    stp xzr, xzr, [x14], #16
    cmp x14, x15
    b.lo render_sequence_output_zero
    dsb ishst
    and x14, x16, #-64
render_sequence_output_clean:
    dc civac, x14
    add x14, x14, #64
    cmp x14, x15
    b.lo render_sequence_output_clean
    dsb osh
    and x14, x16, #-128
render_sequence_output_coprocessor_clean:
    sys #3, c7, c3, #4, x14
    sys #3, c7, c3, #5, x14
    add x14, x14, #128
    cmp x14, x15
    b.lo render_sequence_output_coprocessor_clean
render_sequence_output_zero_done:
    dsb osh
    isb
    // Every generation owns an ordered scatter list.  Bit 1 of a scatter
    // record defers the live outer-ring slot until after service admission;
    // publishing a recycled producer slot while the service handler runs
    // exposes a future work record at the channel's current cursor.
    mov x18, #0
    bl render_sequence_publish_phase
    // Publication may include a new context-1 leaf-table image.  Invalidating
    // here keeps every output rebind target-side and ordered immediately before
    // the owning service/work release.
    mov x19, #1
    lsl x19, x19, #48
    tlbi aside1os, x19
    dsb sy
    ldr x6, [x12, #88]
    cbz x6, render_sequence_publish_work_ring
    // Native channel-12 rollover publishes opcode 0x20 and its matching
    // opcode 0x2e together.  One firmware-owned counter is work-deferred;
    // render_sequence_service_round recognizes the two-slot advance and waits
    // only for the immediate consumer before releasing the associated work.
    ldr x4, [x12, #16]
    ldr w5, [x12, #24]
    bl render_sequence_service_round
render_sequence_service_complete:

render_sequence_publish_work_ring:
    mov x18, #2
    bl render_sequence_publish_phase
    // The deferred phase may contain a new context-1 leaf-table image.  Make
    // it visible before publishing the work producers just as the pre-service
    // phase does for ordinary commands.
    mov x19, #1
    lsl x19, x19, #48
    tlbi aside1os, x19
    dsb sy
render_sequence_no_service:
    // A zero work message makes this a focused device-control command.  It
    // advances after service retirement without touching work-channel state.
    ldr x6, [x12, #96]
    cbz x6, render_sequence_advance
    ldp x4, x5, [x12, #32]
    ldr w6, [x12, #48]
    str w6, [x4]
    str w6, [x5]
    dc civac, x4
    dc civac, x5
    dsb sy

    ldp x4, x5, [x12, #56]
    // The counters occupy distinct qword command fields.  A W-register LDP
    // advances by four bytes, so using it here would load w7 from the upper
    // half of expected_counter instead of the published_counter field.
    ldr w6, [x12, #72]
    ldr w7, [x12, #80]
    str w6, [x5]
    str w6, [x5, #16]
    str w7, [x5, #32]
    dc civac, x5
    dsb sy
    str w6, [x4]
    str w6, [x4, #16]
    str w7, [x4, #32]
    dc civac, x4
    dsb sy

    ldr x6, [x12, #96]
    str x6, [x2]
    mov w8, #0x21
    str x8, [x2, #8]
    dsb sy
render_sequence_work_inbox:
    ldr w8, [x3]
    tbnz w8, #16, render_sequence_work_inbox
    // Collision-free batches expose up to 32 independent work graphs before
    // waiting for execution.  The smallest recycled scheduler pool has 36
    // records, so none of the deferred commands can overwrite live state.
    // A batch-end command waits for the cumulative queue/channel boundary and
    // the one measured output-visibility fence below.
    ldr x8, [x12, #144]
    tbnz x8, #0, render_sequence_advance

    mrs x6, cntfrq_el0
    lsl x6, x6, #1
    mrs x8, cntpct_el0
    add x6, x6, x8
render_sequence_work_wait:
    dc ivac, x4
    dc ivac, x5
    dsb sy
    ldr w8, [x4]
    cmp w8, w7
    b.ne render_sequence_work_again
    ldr w8, [x4, #16]
    cmp w8, w7
    b.ne render_sequence_work_again
    ldr w8, [x5]
    cmp w8, w7
    b.ne render_sequence_work_again
    ldr w8, [x5, #16]
    cmp w8, w7
    b.ne render_sequence_work_again
    ldp x9, x10, [x12, #32]
    ldr w11, [x12, #48]
    dc ivac, x9
    dc ivac, x10
    dsb sy
    ldur w14, [x9, #-64]
    cmp w14, w11
    b.ne render_sequence_work_again
    ldur w14, [x9, #-16]
    cmp w14, w11
    b.ne render_sequence_work_again
    ldr w14, [x9]
    cmp w14, w11
    b.ne render_sequence_work_again
    ldur w14, [x10, #-64]
    cmp w14, w11
    b.ne render_sequence_work_again
    ldur w14, [x10, #-16]
    cmp w14, w11
    b.ne render_sequence_work_again
    ldr w14, [x10]
    cmp w14, w11
    b.ne render_sequence_work_again
    // Queue-record consumption is an independent retirement edge.  Pointer
    // and channel counters can reach the producer while limit_1c still lags;
    // the established host loop waits for both limits before reuse.
    ldp x9, x10, [x12, #128]
    dc ivac, x9
    dc ivac, x10
    dsb sy
    ldr w14, [x9]
    cmp w14, w11
    b.ne render_sequence_work_again
    ldr w14, [x10]
    cmp w14, w11
    b.eq render_sequence_complete
render_sequence_work_again:
    mrs x8, cntpct_el0
    cmp x8, x6
    b.lo render_sequence_work_wait
    b render_sequence_retirement_timeout

render_sequence_complete:
    // A focused new-queue discriminator supplies zero output_extent_size.
    // Its output starts on fresh zero backing, so no target-side memset was
    // needed above.  Repeated streams supply a nonzero extent and one fresh
    // fragment-completion timestamp as their resource-ownership fence.
    // Queue and mailbox retirement precede 3D execution.  Poll the command's
    // fresh completion timestamp on-target until it is nonzero and remains
    // stable for 10 ms.  This is the actual reuse boundary; it adds no proxy
    // transaction and no fixed per-generation delay.
    ldp x14, x15, [x12, #168]
    cbz x15, render_sequence_completion_ready
    mrs x6, cntfrq_el0
    // A 16-work batch can take more than two seconds at cold-boot clocks.
    // Five seconds still keeps a dead discriminator below one minute while
    // accommodating the measured execution latency of a healthy batch.
    mov x8, #5
    mul x6, x6, x8
    mrs x8, cntpct_el0
    add x6, x6, x8
    mov x20, #0
render_sequence_output_wait:
    bl render_sequence_drain_outboxes
    // The drain uses x14..x17 while consuming both ASC FIFOs, so reload the
    // immutable witness table cursor after every drain.
    ldp x14, x15, [x12, #168]
    mov x9, x14
    mov x10, x15
render_sequence_output_check:
    ldp x16, x17, [x9], #16
    dc ivac, x16
    // Firmware timestamp mirrors can be unaligned across a CPU cache line.
    add x18, x16, #7
    dc ivac, x18
    dsb osh
    ldr x18, [x12, #144]
    tbnz x18, #2, render_sequence_output_load_state
    ldr x8, [x16]
    b render_sequence_output_loaded
render_sequence_output_load_state:
    ldr w8, [x16]
render_sequence_output_loaded:
    cbz x17, render_sequence_output_check_nonzero
    cmp x8, x17
    b.ne render_sequence_output_not_ready
    b render_sequence_output_check_next
render_sequence_output_check_nonzero:
    cbz x8, render_sequence_output_not_ready
render_sequence_output_check_next:
    subs x10, x10, #1
    b.ne render_sequence_output_check
    // A qualified per-command final state is sufficient immediately. Legacy
    // timestamp-only witnesses retain their old polling policy.
    ldr x8, [x12, #144]
    tbnz x8, #2, render_sequence_completion_ready
    cbnz x20, render_sequence_output_stable
    mrs x20, cntpct_el0
render_sequence_output_stable:
    mrs x8, cntpct_el0
    sub x8, x8, x20
    mrs x9, cntfrq_el0
    mov x10, #100
    udiv x9, x9, x10
    cmp x8, x9
    b.hs render_sequence_completion_ready
    b render_sequence_output_wait
render_sequence_output_not_ready:
    mov x20, #0
    mrs x8, cntpct_el0
    cmp x8, x6
    b.lo render_sequence_output_wait
    b render_sequence_completion_timeout
render_sequence_completion_ready:
    bl render_sequence_drain_outboxes
    // Opcode 0x20's first firmware-owned counter deliberately lags while the
    // registration/admission pair retires.  Native post-work state has all
    // three counters converged, so require that boundary after the associated
    // work completes and before the following ring publication.
    ldr w5, [x12, #24]
    mrs x6, cntfrq_el0
    lsl x6, x6, #1
    mrs x8, cntpct_el0
    add x6, x6, x8
render_sequence_service_convergence_wait:
    bl render_sequence_drain_outboxes
    ldp x14, x15, [x12]
    ldr x16, [x12, #16]
    dc ivac, x14
    dc ivac, x15
    dc ivac, x16
    dsb sy
    ldr w8, [x14]
    cmp w8, w5
    b.ne render_sequence_service_convergence_again
    ldr w8, [x15]
    cmp w8, w5
    b.ne render_sequence_service_convergence_again
    ldr w8, [x16]
    cmp w8, w5
    b.ne render_sequence_service_convergence_again
    // Completion plus converged service state is the quiescent ownership
    // boundary.  Return all report credits before releasing the next command;
    // this prevents a 256-credit producer from stalling future 3D execution.
    bl render_sequence_ack_reports
    b render_sequence_advance
render_sequence_service_convergence_again:
    mrs x8, cntpct_el0
    cmp x8, x6
    b.lo render_sequence_service_convergence_wait
    b render_sequence_service_convergence_timeout
render_sequence_advance:
    add x12, x12, #232
    subs x13, x13, #1
    b.ne render_sequence_next
render_sequence_done:
    // The host performs one exact eight-attachment check after the complete
    // interval.  Duplicating sparse checks for every command is meaningless
    // for the bounded ping-pong backing pool and only bloats this sequencer.
    mov x0, #0
    b render_sequence_return
render_sequence_retirement_timeout:
    // Preserve every work-retirement predicate in the dead command record.
    // A timeout is terminal, so offsets 112..175 are available as a compact
    // diagnostic block and cost no additional proxy round trip while the
    // experiment is running.
    ldp x4, x5, [x12, #56]
    ldp x9, x10, [x12, #32]
    ldp x14, x15, [x12, #128]
    ldr w17, [x12, #144]
    dc ivac, x4
    dc ivac, x5
    dc ivac, x9
    dc ivac, x10
    dc ivac, x14
    dc ivac, x15
    dsb sy
    ldr w2, [x4]
    ldr w3, [x4, #16]
    ldr w6, [x5]
    ldr w7, [x5, #16]
    stp w2, w3, [x12, #112]
    stp w6, w7, [x12, #120]
    ldur w2, [x9, #-64]
    ldur w3, [x9, #-16]
    ldr w6, [x9]
    stp w2, w3, [x12, #128]
    str w6, [x12, #136]
    ldur w2, [x10, #-64]
    ldur w3, [x10, #-16]
    ldr w6, [x10]
    stp w2, w3, [x12, #140]
    str w6, [x12, #148]
    ldr w2, [x14]
    ldr w3, [x15]
    stp w2, w3, [x12, #152]
    ldr w2, [x12, #72]
    ldr w3, [x12, #80]
    ldr w6, [x12, #48]
    stp w2, w3, [x12, #160]
    stp w6, w17, [x12, #168]
    dc civac, x12
    dsb sy
    ldr x0, [x12, #104]
    b render_sequence_return
render_sequence_service_timeout:
    ldp x14, x15, [x12]
    ldr x16, [x12, #16]
    ldr w2, [x14]
    ldr w3, [x15]
    ldr w4, [x16]
    str w2, [x12, #112]
    str w3, [x12, #116]
    str w4, [x12, #120]
    str w5, [x12, #124]
    dc civac, x12
    dsb sy
    ldr x0, [x12, #104]
    mov x1, #1
    orr x0, x0, x1, lsl #32
    b render_sequence_return
render_sequence_completion_timeout:
    ldr x0, [x12, #104]
    mov x1, #2
    orr x0, x0, x1, lsl #32
    b render_sequence_return
render_sequence_service_convergence_timeout:
    ldp x14, x15, [x12]
    ldr x16, [x12, #16]
    ldr w2, [x14]
    ldr w3, [x15]
    ldr w4, [x16]
    str w2, [x12, #112]
    str w3, [x12, #116]
    str w4, [x12, #120]
    str w5, [x12, #124]
    dc civac, x12
    dsb sy
    ldr x0, [x12, #104]
    mov x1, #3
    orr x0, x0, x1, lsl #32
    b render_sequence_return
// Publish one channel-12 producer and wait for its immediate counters.  A
// two-slot advance is the native opcode-0x20/opcode-0x2e rollover pair, whose
// first firmware-owned counter remains deferred until work completion.
// Preserve our caller's LR across the outbox-drain calls; the top-level
// sequencer restores x19 at exit.
render_sequence_service_round:
    mov x19, x30
    ldr x14, [x12]
    dc ivac, x14
    dsb sy
    ldr w8, [x14]
    add w9, w8, #2
    and w9, w9, #0xff
    cmp w9, w5
    cset w9, eq
    str w5, [x4]
    dc civac, x4
    dsb sy
    ldr x6, [x12, #88]
    str x6, [x2]
    mov w7, #0x21
    str x7, [x2, #8]
    dsb sy
render_sequence_service_inbox:
    ldr w8, [x3]
    tbnz w8, #16, render_sequence_service_inbox
    mrs x6, cntfrq_el0
    lsl x6, x6, #1
    mrs x8, cntpct_el0
    add x6, x6, x8
render_sequence_service_wait:
    bl render_sequence_drain_outboxes
    ldp x14, x15, [x12]
    ldr x16, [x12, #16]
    dc ivac, x14
    dc ivac, x15
    dc ivac, x16
    dsb sy
    cbnz w9, render_sequence_service_check_second
    ldr w8, [x14]
    cmp w8, w5
    b.ne render_sequence_service_again
render_sequence_service_check_second:
    ldr w8, [x15]
    cmp w8, w5
    b.ne render_sequence_service_again
    ldr w8, [x16]
    cmp w8, w5
    b.eq render_sequence_service_round_complete
render_sequence_service_again:
    mrs x8, cntpct_el0
    cmp x8, x6
    b.lo render_sequence_service_wait
    b render_sequence_service_timeout
render_sequence_service_round_complete:
    bl render_sequence_drain_outboxes
    mov x30, x19
    ret
// Channels 13 and 14 are firmware-produced split-credit channels on both
// instances.  Each table entry names the host acknowledgement word followed
// by firmware's peer word.  Pull the peer through the Apple coprocessor cache,
// copy it to the host half, and publish that update without returning to the
// proxy host.  Several pairs can share one 0x80-byte coprocessor cache line;
// completing each write before the next inverse read preserves earlier copies.
render_sequence_ack_reports:
    ldp x14, x15, [x12, #200]
    cbz x15, render_sequence_ack_reports_done
render_sequence_ack_reports_next:
    ldp x16, x17, [x14], #16
    and x18, x16, #-128
    sys #3, c7, c3, #4, x18
    sys #3, c7, c3, #5, x18
    and x18, x17, #-128
    sys #3, c7, c3, #4, x18
    sys #3, c7, c3, #5, x18
    dsb osh
    isb
    dc ivac, x16
    dc ivac, x17
    dsb osh
    ldr w8, [x16]
    ldr w9, [x17]
    cmp w8, w9
    b.eq render_sequence_ack_reports_advance
    str w9, [x16]
    dc civac, x16
    dsb osh
    and x18, x16, #-128
    sys #3, c7, c3, #4, x18
    sys #3, c7, c3, #5, x18
    dsb osh
    isb
render_sequence_ack_reports_advance:
    subs x15, x15, #1
    b.ne render_sequence_ack_reports_next
render_sequence_ack_reports_done:
    ret
// Firmware completion events require no reply, but leaving either ASC's
// outbox full defers scheduler cleanup until after a whole target-side burst.
// Consume both outboxes locally so every generation reaches the same progress
// boundary as the established host loop without a proxy transaction.
render_sequence_drain_outboxes:
    ldp x14, x15, [x12, #184]
    cbz x14, render_sequence_drain_secondary
    add x16, x14, #0x8000
render_sequence_drain_primary_next:
    ldr w17, [x16, #0x114]
    tbnz w17, #17, render_sequence_drain_secondary
    ldr x18, [x12, #216]
    cbz x18, render_sequence_discard_primary
    ldr x14, [x18]
    ldr x17, [x12, #224]
    cmp x14, x17
    b.hs render_sequence_overflow_primary
    str xzr, [x14]
    ldr x17, [x16, #0x830]
    str x17, [x14, #8]
    ldr x17, [x16, #0x838]
    str x17, [x14, #16]
    add x14, x14, #24
    str x14, [x18]
    b render_sequence_drain_primary_next
render_sequence_overflow_primary:
    mov x17, #1
    str x17, [x18, #8]
render_sequence_discard_primary:
    ldr x17, [x16, #0x830]
    ldr x17, [x16, #0x838]
    b render_sequence_drain_primary_next
render_sequence_drain_secondary:
    cbz x15, render_sequence_drain_done
    add x16, x15, #0x8000
render_sequence_drain_secondary_next:
    ldr w17, [x16, #0x114]
    tbnz w17, #17, render_sequence_drain_done
    ldr x18, [x12, #216]
    cbz x18, render_sequence_discard_secondary
    ldr x14, [x18]
    ldr x17, [x12, #224]
    cmp x14, x17
    b.hs render_sequence_overflow_secondary
    mov x17, #1
    str x17, [x14]
    ldr x17, [x16, #0x830]
    str x17, [x14, #8]
    ldr x17, [x16, #0x838]
    str x17, [x14, #16]
    add x14, x14, #24
    str x14, [x18]
    b render_sequence_drain_secondary_next
render_sequence_overflow_secondary:
    mov x17, #1
    str x17, [x18, #8]
render_sequence_discard_secondary:
    ldr x17, [x16, #0x830]
    ldr x17, [x16, #0x838]
    b render_sequence_drain_secondary_next
render_sequence_drain_done:
    ret
// Copy one phase of the command's scatter table.  x18 selects bit 1 of the
// record flags: zero publishes graph/PTE data before service; two publishes
// the outer work-ring records after service and before their producers.
render_sequence_publish_phase:
    ldp x4, x5, [x12, #152]
    cbz x5, render_sequence_publish_phase_done
render_sequence_publish_phase_next:
    ldp x6, x7, [x4]
    ldp x8, x9, [x4, #16]
    add x4, x4, #32
    and x10, x9, #2
    cmp x10, x18
    b.ne render_sequence_publish_phase_record_done
    mov x14, x6
    mov x15, x8
render_sequence_publish_phase_qword:
    cmp x8, #8
    b.lo render_sequence_publish_phase_byte
    ldr x17, [x7], #8
    str x17, [x6], #8
    sub x8, x8, #8
    b render_sequence_publish_phase_qword
render_sequence_publish_phase_byte:
    cbz x8, render_sequence_publish_phase_clean
    ldrb w17, [x7], #1
    strb w17, [x6], #1
    sub x8, x8, #1
    b render_sequence_publish_phase_byte
render_sequence_publish_phase_clean:
    add x16, x14, x15
    and x14, x14, #-64
render_sequence_publish_phase_clean_next:
    dc civac, x14
    add x14, x14, #64
    cmp x14, x16
    b.lo render_sequence_publish_phase_clean_next
    tbz x9, #0, render_sequence_publish_phase_record_done
    ldr x14, [x4, #-32]
    add x16, x14, x15
    and x14, x14, #-128
render_sequence_publish_phase_coprocessor_next:
    sys #3, c7, c3, #4, x14
    sys #3, c7, c3, #5, x14
    add x14, x14, #128
    cmp x14, x16
    b.lo render_sequence_publish_phase_coprocessor_next
render_sequence_publish_phase_record_done:
    dsb sy
    subs x5, x5, #1
    b.ne render_sequence_publish_phase_next
render_sequence_publish_phase_done:
    dsb sy
    ret
render_sequence_return:
    ldr x30, [sp, #16]
    ldp x19, x20, [sp], #32
"""


def run_render_stream_sequence(
        u, p, iface, asces, commands, report_ack_pairs=(), *, mailbox_capture=None, mailbox_capacity=None):
    """Run ordered service/work batches in one proxy call.

    Drivers pass a list as mailbox_capture to retain every message for normal
    endpoint dispatch after the bounded target call. Capture overflow is an
    error, never silently successful retirement. Legacy experiment callers may
    retain their raw drain, but the UAPI path must not lose crash messages.
    """
    asces = tuple(asces)
    if len(asces) != 2:
        raise ValueError("render stream sequence requires both graphics ASCs")
    asc_bases = tuple(int(asc.asc._base) for asc in asces)
    commands = tuple(commands)
    if not commands:
        raise ValueError("render stream sequence is empty")
    report_ack_pairs = normalize_report_ack_pairs(report_ack_pairs)
    normalized = []
    for fields, publications, witnesses in commands:
        fields = tuple(map(int, fields))
        publications = tuple(
            (int(physical_address), bytes(body), int(flags))
            for physical_address, body, flags in publications
            if len(body)
        )
        witnesses = tuple(
            (int(physical_address), int(expected))
            for physical_address, expected in witnesses
        )
        if len(fields) != 19:
            raise ValueError(
                "render stream sequence requires nineteen-qword fields"
            )
        normalized.append((fields, publications, witnesses))
    commands = tuple(normalized)
    command_size = RENDER_STREAM_COMMAND_SIZE
    table_size = sum(
        len(publications) * 32
        for _fields, publications, _witnesses in commands
    )
    witness_size = sum(
        len(witnesses) * 16
        for _fields, _publications, witnesses in commands
    )
    report_ack_size = len(report_ack_pairs) * 16
    payload_size = sum(
        len(body)
        for _fields, publications, _witnesses in commands
        for _physical_address, body, _flags in publications
    )
    if mailbox_capacity is None:
        mailbox_capacity = max(512, len(commands) * 32)
    if type(mailbox_capacity) is not int or not 1 <= mailbox_capacity <= 1048576:
        raise ValueError("render mailbox capacity must be a bounded positive integer")
    mailbox_size = 16 + 24 * mailbox_capacity if mailbox_capture is not None else 0
    allocation_size = (
        len(commands) * command_size
        + table_size + witness_size + report_ack_size + payload_size + mailbox_size
    )
    with u.heap.guarded_malloc(allocation_size) as commands_pa:
        table_pa = int(commands_pa) + len(commands) * command_size
        witness_pa = table_pa + table_size
        report_ack_pa = witness_pa + witness_size
        payload_pa = report_ack_pa + report_ack_size
        mailbox_pa = payload_pa + payload_size if mailbox_size else 0
        command_records = []
        table_records = []
        witness_records = []
        payload = bytearray()
        next_table_pa = table_pa
        next_witness_pa = witness_pa
        for fields, publications, witnesses in commands:
            command_records.append(struct.pack(
                "<29Q",
                *fields,
                next_table_pa,
                len(publications),
                next_witness_pa,
                len(witnesses),
                *asc_bases,
                report_ack_pa,
                len(report_ack_pairs),
                mailbox_pa,
                mailbox_pa + mailbox_size if mailbox_size else 0,
            ))
            for physical_address, body, flags in publications:
                table_records.append(struct.pack(
                    "<4Q",
                    physical_address,
                    payload_pa + len(payload),
                    len(body),
                    flags,
                ))
                payload.extend(body)
            witness_records.extend(
                struct.pack("<2Q", physical_address, expected)
                for physical_address, expected in witnesses
            )
            next_table_pa += len(publications) * 32
            next_witness_pa += len(witnesses) * 16
        encoded = (
            b"".join(command_records + table_records + witness_records)
            + b"".join(
                struct.pack("<2Q", host_pa, peer_pa)
                for host_pa, peer_pa in report_ack_pairs
            )
            + bytes(payload)
            + (struct.pack("<2Q", mailbox_pa + 16, 0) + bytes(mailbox_size - 16)
               if mailbox_size else b"")
        )
        if len(encoded) != allocation_size:
            raise RuntimeError("render stream sequence allocation changed size")
        # This CPU-owned staging image contains large zero descriptor tails,
        # recycled parameter ranges and mailbox scratch. Reconstruct every
        # byte locally; uploading those zeros dominates large host waves.
        # Firmware publication order is still controlled solely by the
        # sequencer below, not by this unmapped staging-buffer transport.
        from .g17g_transfer import write_publications
        write_publications(u, p, iface, ((int(commands_pa), encoded),))
        p.dc_civac(commands_pa, len(encoded))
        inbox0 = asc_bases[0] + 0x8800
        inbox_ctrl = asc_bases[0] + 0x8110
        serial = getattr(iface, "dev", None)
        prior_timeout = getattr(serial, "timeout", None)
        if serial is not None and prior_timeout is not None:
            # Each command can wait 2 s for service admission, 2 s for work
            # retirement, 5 s for its witness and 2 s for service convergence.
            # Let the target return its failure and captured crash messages
            # before another proxy request can consume that pending reply.
            # This is an I/O deadline, not an additional completion delay.
            serial.timeout = max(
                float(prior_timeout), 3.0 + 11.0 * len(commands)
            )
        failure_detail = None
        target_call_started = time.monotonic()
        try:
            failed = int(u.exec(
                _RENDER_STREAM_SEQUENCE_ASM,
                commands_pa,
                len(commands),
                inbox0,
                inbox_ctrl,
            ))
            if mailbox_size:
                p.dc_civac(mailbox_pa, mailbox_size)
                cursor, overflow = struct.unpack("<2Q", iface.readmem(mailbox_pa, 16))
                count_bytes = cursor - mailbox_pa - 16
                if not 0 <= count_bytes <= mailbox_size - 16 or count_bytes % 24:
                    raise RuntimeError("render sequencer mailbox cursor is corrupt")
                raw = iface.readmem(mailbox_pa + 16, count_bytes) if count_bytes else b""
                if len(raw) != count_bytes:
                    raise RuntimeError("short render mailbox transfer")
                mailbox_capture.extend(struct.iter_unpack("<3Q", raw))
                if overflow:
                    raise RuntimeError("render sequencer mailbox capture overflow")
            if failed and (failed >> 32) == 0:
                failed_ordinal = failed & 0xFFFFFFFF
                command_index = failed_ordinal - commands[0][0][13]
                diagnostic_pa = (
                    int(commands_pa) + command_index * command_size + 112
                )
                p.dc_ivac(diagnostic_pa, 64)
                u.inst("dsb sy")
                values = struct.unpack(
                    "<16I", iface.readmem(diagnostic_pa, 64)
                )
                failure_detail = {
                    "state_counters": list(values[0:4]),
                    "pointer_0": list(values[4:7]),
                    "pointer_1": list(values[7:10]),
                    "queue_limits": list(values[10:12]),
                    "expected_counter": values[12],
                    "published_counter": values[13],
                    "expected_inner_head": values[14],
                    "stream_flags": values[15],
                }
            elif failed and (failed >> 32) in (1, 3):
                failed_ordinal = failed & 0xFFFFFFFF
                command_index = failed_ordinal - commands[0][0][13]
                diagnostic_pa = (
                    int(commands_pa) + command_index * command_size + 112
                )
                p.dc_ivac(diagnostic_pa, 16)
                u.inst("dsb sy")
                failure_detail = struct.unpack(
                    "<4I", iface.readmem(diagnostic_pa, 16)
                )
            elif failed and (failed >> 32) == 2:
                failed_ordinal = failed & 0xFFFFFFFF
                command_index = failed_ordinal - commands[0][0][13]
                witnesses = []
                # Completion sampling is deliberately failure-only.  Keep
                # successful batches at one proxy call while preserving the
                # exact address/value mismatch when a fence times out.
                width = 4 if commands[command_index][0][18] & RENDER_STREAM_FINAL_STATE else 8
                for physical_address, expected in commands[command_index][2]:
                    p.dc_ivac(physical_address, width)
                    u.inst("dsb sy")
                    observed = struct.unpack("<I" if width == 4 else "<Q",
                                             iface.readmem(physical_address, width))[0]
                    witnesses.append({
                        "physical_address": physical_address,
                        "width": width,
                        "expected": expected,
                        "observed": observed,
                    })
                failure_detail = {"witnesses": witnesses}
        finally:
            target_call_seconds = time.monotonic() - target_call_started
            if serial is not None and prior_timeout is not None:
                serial.timeout = prior_timeout
    if failed:
        failed_ordinal = failed & 0xFFFFFFFF
        phase = {
            0: "work retirement",
            1: "service retirement",
            2: "output witness",
            3: "post-work service convergence",
        }.get(failed >> 32, "unknown phase %d" % (failed >> 32))
        raise RenderStreamTimeout(
            phase, failed_ordinal, failure_detail
        )
    return {
        "command_count": len(commands),
        "proxy_call_count": 1,
        "publication_count": sum(
            len(publications)
            for _fields, publications, _witnesses in commands
        ),
        "first_ordinal": commands[0][0][13],
        "final_ordinal": commands[-1][0][13],
        "target_call_seconds": target_call_seconds,
        "report_ack_pair_count": len(report_ack_pairs),
    }


def read_output_word(u, physical_address):
    """One bounded coherent read of a caller-owned output word.

    The same address-granular inverse publication as the target output wait,
    without blocking while a host growth response may be needed. No mailbox
    drain or queue-index inference; the caller still validates all output.
    """
    if (type(physical_address) is not int or not 0 < physical_address < (1 << 42)
            or physical_address & 3):
        raise ValueError("invalid output-word physical address")
    return int(u.exec(r"""
        and x1, x0, #-128
        sys #3, c7, c3, #4, x1
        sys #3, c7, c3, #5, x1
        dsb osh
        dc ivac, x0
        dsb osh
        ldr w0, [x0]
    """, physical_address))


def _run_render_output_wait(
        u, iface, physical_address, asces, ordinal, message):
    physical_address = int(physical_address)
    ordinal = int(ordinal)
    message = int(message)
    if not physical_address or physical_address & 7:
        raise ValueError("invalid render output witness physical address")
    asces = tuple(asces)
    if len(asces) != 2:
        raise ValueError("render output wait requires both graphics ASCs")
    asc_bases = tuple(int(asc.asc._base) for asc in asces)
    serial = getattr(iface, "dev", None)
    prior_timeout = getattr(serial, "timeout", None)
    if serial is not None and prior_timeout is not None:
        serial.timeout = max(float(prior_timeout), 6.0)
    started = time.monotonic()
    try:
        observed = int(u.exec(
            _KICK_AND_WAIT_FOR_RENDER_OUTPUT_ASM,
            physical_address,
            asc_bases[0],
            asc_bases[1],
            message,
        ))
    finally:
        elapsed = time.monotonic() - started
        if serial is not None and prior_timeout is not None:
            serial.timeout = prior_timeout
    if not observed:
        raise RenderStreamTimeout(
            "output fence", ordinal,
            {"physical_address": physical_address, "observed": 0},
        )
    result = {
        "ordinal": ordinal,
        "physical_address": physical_address,
        "observed": observed,
        "target_wait_seconds": elapsed,
        "proxy_call_count": 1,
        "host_read_count": 0,
    }
    if message:
        result["kick_message"] = message
        result["kick_endpoint"] = 0x21
    return result


def kick_and_wait_for_render_output(
        u, iface, physical_address, asces, message, ordinal=0):
    """Submit one endpoint-0x21 kick and await a real target write on-target."""
    message = int(message)
    if message <= 0 or message >= 1 << 64:
        raise ValueError("invalid render work kick message")
    return _run_render_output_wait(
        u, iface, physical_address, asces, ordinal, message
    )


def notify_and_wait_for_render_service(
        u, iface, state_physical_addresses, asces, expected, ordinal=0,
        defer_first_consumer=False, send_notification=True):
    """Optionally notify and await a channel-12 boundary on-target."""
    state_physical_addresses = tuple(map(int, state_physical_addresses))
    expected = int(expected)
    ordinal = int(ordinal)
    if (
        len(state_physical_addresses) != 3
        or any(not address or address & 3
               for address in state_physical_addresses)
        or state_physical_addresses[1:] != (
            state_physical_addresses[0] + 0x10,
            state_physical_addresses[0] + 0x20,
        )
    ):
        raise ValueError("invalid render service state physical addresses")
    if not 0 <= expected <= 0xFF:
        raise ValueError("invalid render service expected counter")
    asces = tuple(asces)
    if len(asces) != 2:
        raise ValueError("render service wait requires both graphics ASCs")
    asc_bases = tuple(int(asc.asc._base) for asc in asces)
    serial = getattr(iface, "dev", None)
    prior_timeout = getattr(serial, "timeout", None)
    if serial is not None and prior_timeout is not None:
        serial.timeout = max(float(prior_timeout), 6.0)
    started = time.monotonic()
    try:
        control = (
            expected
            | (int(bool(defer_first_consumer)) << 8)
            | (int(not send_notification) << 9)
        )
        packed = int(u.exec(
            _NOTIFY_AND_WAIT_FOR_RENDER_SERVICE_ASM,
            state_physical_addresses[0],
            *asc_bases,
            control,
        ))
    finally:
        elapsed = time.monotonic() - started
        if serial is not None and prior_timeout is not None:
            serial.timeout = prior_timeout
    success = bool(packed >> 63)
    observed = tuple((packed >> shift) & 0xFFFF for shift in (0, 16, 32))
    converged = (
        observed[1:] == (expected, expected)
        if defer_first_consumer else observed == (expected,) * 3
    )
    if not success or not converged:
        raise RenderStreamTimeout(
            "service convergence", ordinal,
            observed + (expected,),
        )
    return {
        "ordinal": ordinal,
        "state_physical_addresses": list(state_physical_addresses),
        "expected": expected,
        "observed": list(observed),
        "target_wait_seconds": elapsed,
        "proxy_call_count": 1,
        "host_read_count": 0,
        "deferred_first_consumer": bool(defer_first_consumer),
        "notification_message": (
            0x0084000000000011 if send_notification else None
        ),
        "notification_endpoint": 0x21 if send_notification else None,
    }


def wait_for_render_service_convergence(
        u, iface, state_physical_addresses, asces, expected, ordinal=0):
    """Await all channel-12 consumers after associated work completes."""
    return notify_and_wait_for_render_service(
        u,
        iface,
        state_physical_addresses,
        asces,
        expected,
        ordinal=ordinal,
        send_notification=False,
    )


def write_physical_publications(u, p, iface, publications, attempts=3):
    """Apply an ordered physical scatter list in one target-side proxy call."""
    publications = tuple(
        (int(physical_address), bytes(body))
        for physical_address, body in publications
        if len(body)
    )
    if not publications:
        return 0
    table_size = len(publications) * 24
    payload_size = sum(len(body) for _physical_address, body in publications)
    with u.heap.guarded_malloc(table_size + payload_size) as staging_pa:
        payload_pa = int(staging_pa) + table_size
        payload_offset = 0
        entries = []
        payload = bytearray()
        for physical_address, body in publications:
            entries.append(struct.pack(
                "<QQQ",
                physical_address,
                payload_pa + payload_offset,
                len(body),
            ))
            payload.extend(body)
            payload_offset += len(body)
        encoded = b"".join(entries) + bytes(payload)
        for attempt in range(1, int(attempts) + 1):
            try:
                iface.writemem(staging_pa, encoded)
                break
            except UartError as exc:
                if attempt == int(attempts):
                    raise
                print(
                    "Retrying physical scatter upload after %s (%d/%d)"
                    % (type(exc).__name__, attempt, int(attempts))
                )
        p.dc_civac(staging_pa, len(encoded))
        u.exec(_SCATTER_COPY_ASM, staging_pa, len(publications))
    return len(publications)
