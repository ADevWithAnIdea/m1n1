# SPDX-License-Identifier: GPL-2.0-only
"""Diagnostic client-heap exhaustion at one real backing allocation.

Reservations change only the host allocator's bookkeeping. They are never
written to target memory or mapped into a GPU context, and are released even
if the allocator raises. This is not evidence of system-wide physical OOM.
"""


class ExhaustAtAllocation:
    def __init__(self, util):
        self.util = util
        self.evidence = None

    def __getattr__(self, name):
        return getattr(self.util, name)

    def memalign(self, alignment, size):
        if self.evidence is not None:
            raise RuntimeError("heap-pressure diagnostic permits one allocation")
        heap = self.util.heap
        sizes = sorted((count * heap.block for count, used in heap.blocks if not used), reverse=True)
        held = []
        self.evidence = dict(reserved_bytes=sum(sizes), requested_bytes=size,
                             gpu_visible_reservation_bytes=0)
        try:
            for length in sizes:
                held.append(heap.malloc(length))
            if any(not used for _, used in heap.blocks):
                raise RuntimeError("diagnostic did not exhaust the client heap")
            return self.util.memalign(alignment, size)
        except Exception as exc:
            self.evidence["allocator_error"] = "%s: %s" % (type(exc).__name__, exc)
            raise
        finally:
            for address in reversed(held):
                heap.free(address)
            self.evidence["free_bytes_after_release"] = sum(
                count * heap.block for count, used in heap.blocks if not used)
