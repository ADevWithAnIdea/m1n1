# SPDX-License-Identifier: GPL-2.0-only
"""Owned reactive TVB allocation and report consumption for the UAPI runtime.

No caller program, output oracle, capture, or experiment entrypoint is used.
Growth requests and replies are attributed to the submitting resident VM slot.
"""
import struct

from m1n1.fw.asc.base import ASCMessage1
from .g17g_growth import (allocate_growth_reply, build_growth_ack,
    build_growth_failure_ack, build_owned_limit_followup, TVB_BLOCK_SIZE)
from .g17g_growth_service import TVBGrowthService, pump_asces_once

PAGE = 0x4000
STATE = 0xfffffc2001618000
BLOCK_LIST = 0xfffffc20c08c0000
GROWTH_BASE = 0x1000290000
GROWTH_STRIDE = 0x88000


class _OwnedAllocator:
    """Pin the entire extent even if a later publication fails."""
    def __init__(self, runtime):
        self.runtime = runtime

    def __getattr__(self, name):
        return getattr(self.runtime.u, name)

    def memalign(self, alignment, size):
        pa = int(self.runtime.u.memalign(alignment, size))
        allocation = (pa, size)
        self.runtime.allocations.append(allocation)
        self.runtime.context["allocations"].append(allocation)
        return pa


class G17GTVBPool:
    def __init__(self, runtime, *, allow_growth=True, max_blocks=None,
                 state_address=STATE, list_address=BLOCK_LIST, growth_base=GROWTH_BASE,
                 notification_masks=(1, 2), fragment_slot=1, terminal_mask=3,
                 require_first_terminal=True):
        if max_blocks is not None and (type(max_blocks) is not int or not 3 <= max_blocks <= PAGE // 8):
            raise ValueError("invalid owned TVB block limit")
        self.runtime = runtime
        self.allow_growth = allow_growth
        self.max_blocks = max_blocks
        self.state_address, self.list_address = state_address, list_address
        self.growth_base = growth_base
        self.notification_masks = tuple(notification_masks)
        self.fragment_slot, self.terminal_mask = fragment_slot, terminal_mask
        self.require_first_terminal = require_first_terminal
        self.counter = 0
        self.replies = []
        self.service = None

    def read(self, address, size):
        return self.runtime.read_fields({0: (address, size)})[0]

    def prepare_context(self, context):
        """Back the retained pool's GPU addresses privately in a selected VM.

        Growth's published block IDs and service counter belong to the shared
        pool. Completed operand payloads do not cross VM boundaries. Preserve
        an existing VM's pages and allocate zero backing only for missing IDs.
        """
        from . import g17g_uat
        runtime = self.runtime
        if runtime.state != "complete":
            raise RuntimeError("TVB VM handoff requires quiescence")
        counts = struct.unpack("<2I", self.read(self.state_address, 8))
        if counts[0] != counts[1] or not 3 <= counts[0] <= PAGE // 8:
            raise RuntimeError("TVB VM handoff has inconsistent capacity")
        for index in range(counts[0] - 3):
            dva = self.growth_base + index * GROWTH_STRIDE
            pages = set(range(dva, dva + TVB_BLOCK_SIZE, PAGE))
            existing = context.get('private_labels', set(context['pages'])) if context.get('layout') is not None else set(context['pages'])
            present = pages & existing
            if (context.get('layout') is None and pages & set(context["caller_mappings"])) or (present and present != pages):
                raise RuntimeError("TVB VM block overlaps caller or incomplete private backing")
            if present:
                continue
            pa = runtime.alloc(TVB_BLOCK_SIZE)
            context["allocations"].append((pa, TVB_BLOCK_SIZE))
            for offset in range(0, TVB_BLOCK_SIZE, PAGE):
                context["pages"][dva + offset] = pa + offset
            runtime.publish(range(pa, pa + TVB_BLOCK_SIZE, PAGE))
            staged_high = context.get('layout') is not None
            runtime.uat.iomap_at_root(context['root1' if staged_high else 'root0'], dva, pa, TVB_BLOCK_SIZE,
                                     **g17g_uat.FLAGS_CONTEXT0_UXN)
            context.setdefault('high_table_witnesses' if staged_high else 'table_witnesses', set()).update(pages)
            runtime.private_dvas.update(pages)
        layout = context.get('layout')
        if layout is not None:
            layout.reserve(runtime.private_dvas)
            layout.relocate_context(runtime, context)
        runtime.flush_tables(context.get('context_id', runtime.context_id))

    def prepare(self, request, counter):
        if not self.allow_growth:
            raise RuntimeError("unexpected capacity request from a fixed-pool render")
        runtime = self.runtime
        counts = struct.unpack("<2I", self.read(self.state_address, 8))
        if counts[0] != counts[1] or counts[0] < 3:
            raise RuntimeError("inconsistent owned TVB capacity")
        count = 10 if self.max_blocks is None else min(10, self.max_blocks - counts[0])
        if count <= 0:
            if count < 0 or self.service is None or self.service.limit_handler is None:
                raise RuntimeError("TVB limit has no qualified command owner")
            result = dict(command=build_growth_failure_ack(runtime.context_id, 0, counter), counter=counter,
                old_count=counts[0], new_count=counts[0], memory_limit=True,
                bytes=0, allocation_bytes=0, block_dvas=())
            self.counter = counter + 1
            self.replies.append({key: value for key, value in result.items() if key != "command"})
            return result
        dvas = tuple(self.growth_base + (counts[0] - 3 + i) * GROWTH_STRIDE for i in range(count))
        pages = {dva + offset for dva in dvas for offset in range(0, TVB_BLOCK_SIZE, PAGE)}
        occupied = runtime.context.get('private_labels', set(runtime.context['pages'])) if runtime.layout is not None else set(runtime.context['pages'])
        if pages & occupied:
            raise RuntimeError("TVB growth overlaps an existing private or caller mapping")
        allocation_count = len(runtime.allocations)
        try:
            result = allocate_growth_reply(_OwnedAllocator(runtime), runtime.p, runtime.iface, runtime.read,
                root_pa=runtime.context['root1' if runtime.layout is not None else 'root0'], state_pa=runtime.pa(self.state_address),
                list_pa=runtime.pa(self.list_address),
                list_capacity=PAGE // 8, request=request, block_dvas=dvas, expected_counter=counter, uat=runtime.uat)
        except MemoryError as error:
            # Only a pre-allocation failure is retryable here. Once any
            # backing has been acquired, publication may have started and
            # all ownership must stay pinned on the terminal error path.
            if len(runtime.allocations) != allocation_count:
                raise
            result = dict(command=build_growth_ack(runtime.context_id, 0, counter), counter=counter,
                old_count=counts[0], new_count=counts[0], allocation_failed=True,
                error=str(error), bytes=0, allocation_bytes=0, block_dvas=())
            self.counter = counter + 1
            self.replies.append({key: value for key, value in result.items() if key != "command"})
            return result
        for index, dva in enumerate(dvas):
            for offset in range(0, TVB_BLOCK_SIZE, PAGE):
                runtime.context["pages"][dva + offset] = result["new_physical"] + index * TVB_BLOCK_SIZE + offset
        # Source labels staged in TTBR1 are not root0 table witnesses. Their
        # requested primary addresses are recorded by relocate_context below.
        runtime.context.setdefault('high_table_witnesses' if runtime.layout is not None
                                   else 'table_witnesses', set()).update(pages)
        runtime.private_dvas.update(pages)
        # The UAT client has published the owned mappings. Drop cached
        # images before any later runtime mapping or root teardown.
        runtime.uat.invalidate_cache()
        runtime.uat.invalidate_root_walk_cache()
        if runtime.layout is not None:
            runtime.layout.reserve(pages)
            runtime.layout.relocate_context(runtime, runtime.context, pages=pages)
            ids = struct.pack('<%dQ' % len(dvas), *(
                ((dva-0x1000000000)//0x8000) | (1 << 24) for dva in dvas))
            runtime.publish_writes(((self.list_address+counts[0]*8, ids),))
        self.counter = counter + 1
        self.replies.append({key: value for key, value in result.items() if key != "command"})
        return result

    def begin(self, graph=None):
        runtime = self.runtime
        if runtime.channel_state() != (runtime.service_cursor,) * 3:
            raise RuntimeError("TVB service does not own a quiescent command ring")
        channels = runtime.boot.fields["primary_main_fields"]["channels"]
        limit_handler = None
        if self.max_blocks is not None and graph is not None:
            ordinal = graph.get('ordinal', 1)
            addresses = graph['firmware_addresses']
            event = graph['items']['fragment_event']
            queue_word, event_word = struct.unpack_from('<2I', event, 4)
            if (queue_word != 0x10000 | self.fragment_slot or
                    event_word & 0xff != 2 or not event_word >> 8):
                raise ValueError('memory-limit owner differs from the published fragment event')
            # Derive the expected identity from our published work, never
            # from the report itself. Its opaque data pointer is not read.
            def limit_handler(body):
                return dict(command=build_owned_limit_followup(body,
                    fragment_dva=addresses['fragment_descriptor'],
                    event_slot=queue_word & 0xff, event_value=event_word & ~0xff), ordinal=ordinal)
        self.service = TVBGrowthService(self.read, lambda dva, body: runtime.publish_writes(((dva, body),)),
            self.prepare, lambda: runtime.asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21)),
            lambda: pump_asces_once(runtime.asces), channel12=channels[12], channel13=channels[13],
            first_counter=self.counter, publish=runtime.publish_writes, limit_handler=limit_handler,
            terminal_mask=self.terminal_mask,
            context_id=runtime.context_id,
            request_limit=32 if self.max_blocks is None else max(32, (self.max_blocks - 3 + 9) // 10 + 1))
        runtime.evidence["tvb"] = dict(first_counter=self.counter, growth_enabled=self.allow_growth,
                                      max_blocks=self.max_blocks, replies=self.service.replies, consumed_reports=[])

    def limit_outcome(self, after):
        """A negative reply needs an owned type7/type9 and strict terminal.

        This outcome classifies a failed job, never successful execution.
        The runtime must additionally prove both queues and service retired.
        """
        service = self.service
        if not any(row.get("negative_reply") for row in service.replies):
            return None
        opcodes = [struct.unpack_from("<I", bytes.fromhex(body))[0]
                   for body in after["reports"]["records"]]
        if 4 in opcodes:
            return "fault"
        if any(opcode not in (1, 6, 7) for opcode in opcodes):
            raise ValueError("unclassified report during owned memory-limit exchange")
        if service.limit_report is None:
            return "pending"
        if self.require_first_terminal and service.limit_report['ordinal'] == 1 and service.terminal is None:
            return "pending"
        if service.u32(service.producer) != service.cursor:
            return "pending"
        if self.runtime.channel_state() != (self.runtime.service_cursor,) * 3:
            return "pending"
        if service.terminal is not None:
            return "out_of_memory"
        # Later jobs, and shared render-first admission without prior compute,
        # need not emit another terminal after type9. The runtime still
        # requires fresh private completion and both queues retired.
        return "limit_followup_retired"

    def lifecycle_qwords(self, rows):
        """Do not synthesize legacy report state alongside the live consumer.

        The fixed second-opening transition includes an exemplar producer
        and report payload. Reactive growth changes that interval and this
        service owns its consumption; firmware alone writes its producer and
        records. Keep all unrelated lifecycle preimage checks unchanged.
        """
        states, _ring = self.runtime.boot.fields["primary_main_fields"]["channels"][13]
        ranges = ((states[0], states[0] + 0x24), (states[1], states[1] + 256 * 0x48))
        return {page: tuple(row for row in entries
                           if not any(page + row[0] < end and page + row[0] + 8 > start
                                      for start, end in ranges))
                for page, entries in rows.items()}

    def step(self, before):
        """Consume only classified service records; keep faults for the fence.

        Rebase the report comparison *past consumed records only*. A report
        that arrived during the ACK remains new and must still be classified.
        Fresh command timestamp preimages are never rebased or synthesized.
        """
        service, runtime = self.service, self.runtime
        if any(struct.unpack_from("<I", bytes.fromhex(body))[0] == 4
               for body in before["reports"]["records"]):
            # Leave a pre-existing fault visible to the normal completion
            # validator, even if newer service records are already waiting.
            return False
        if service.u32(service.producer) == service.cursor:
            return False
        body = self.read(service.records + service.cursor * 0x48, 0x48)
        if struct.unpack_from("<I", body)[0] not in ((1, 6, 7) if getattr(service, 'limit_handler', None) else (1, 6)):
            return False
        words = struct.unpack_from("<4I", body)
        if words in tuple((1, mask, 0, 0) for mask in self.notification_masks):
            # A paired render can emit separate engine notifications. They
            # are not the growth service's combined (1,3) terminal and are
            # never an execution fence. Consume them so a following real
            # growth request/fault cannot be hidden behind an old event.
            service.last_report = dict(slot=service.cursor, record_hex=body.hex())
            service.cursor = (service.cursor + 1) & 255
            service.write(service.consumer, struct.pack("<I", service.cursor))
        else:
            service.step()
        runtime.evidence["tvb"]["consumed_reports"].append(dict(service.last_report))
        runtime.evidence["tvb"]["counter"] = self.counter
        runtime.evidence["tvb"]["limit_report"] = getattr(service, 'limit_report', None)
        runtime.evidence["tvb"]["terminal"] = getattr(service, 'terminal', None)
        if service.next_command_slot is not None:
            runtime.service_cursor = service.next_command_slot
        before["reports"] = dict(consumer=service.cursor, producer=service.cursor, records=[])
        return True
