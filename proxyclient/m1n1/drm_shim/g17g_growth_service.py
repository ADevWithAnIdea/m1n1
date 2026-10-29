# SPDX-License-Identifier: GPL-2.0-only
"""Owned-ring service for the verified G17G in-job TVB request/reply path.

The injected read/write callbacks provide coherent firmware-DVA access. A
prepared allocation must be visible before this service publishes its ACK.
Terminal reports only bound the wait; the caller must verify output bytes.
"""
import struct
import time


def pump_asces_once(asces):
    """One fair, bounded sweep; proxy latency cannot skip the second ASC.

    A sub-millisecond wall-clock budget checked between devices can starve
    one mailbox when processing the other takes longer than that budget.
    Read at most one message per device, with no drain-until-empty loop.
    """
    for asc in asces:
        if asc.has_messages():
            asc.work()


class TVBGrowthService:
    def __init__(self, read, write, prepare, notify, pump, *, channel12, channel13,
                 first_counter=0, request_limit=32, publish=None, limit_handler=None,
                 terminal_mask=3, context_id=1):
        if type(first_counter) is not int or not 0 <= first_counter <= 0xffffffff:
            raise ValueError("invalid expected first TVB request counter")
        self.first_counter = first_counter
        if type(request_limit) is not int or not 1 <= request_limit <= 512:
            raise ValueError("invalid bounded TVB request budget")
        self.request_limit = request_limit
        self.read, self.write, self.prepare = read, write, prepare
        self.notify, self.pump = notify, pump
        self.publish = publish
        self.limit_handler, self.limit_report = limit_handler, None
        if (not isinstance(terminal_mask, int) or not 0 < terminal_mask < (1 << 32) or
                terminal_mask != 3 << ((terminal_mask & -terminal_mask).bit_length()-1)):
            raise ValueError('unsupported paired-engine terminal mask')
        self.terminal_mask = terminal_mask
        if type(context_id) is not int or not 1 <= context_id < 64:
            raise ValueError('invalid owned TVB context slot')
        self.context_id = context_id
        self.last_report = None
        self.next_command_slot = None
        self.command_states, self.command_ring = channel12
        report_states, self.other_report_ring = channel13
        self.consumer, self.records, _state2 = report_states
        self.producer = self.consumer + 0x20
        # Start at the live pre-kick producer, not at a historical slot-zero
        # status. Initial type-13 records are outside this workload boundary.
        self.cursor = self.u32(self.producer)
        if not 0 <= self.cursor < 256:
            raise ValueError("invalid report-ring cursor")
        self.start_cursor = self.cursor
        self.replies = []
        self.terminal = None

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def command_slot(self):
        if self.command_states[2] == self.command_states[0] + 0x20:
            states = self.read(self.command_states[0], 0x24)
            head, tail = struct.unpack_from("<I", states)[0], struct.unpack_from("<I", states, 0x20)[0]
        else:
            head, tail = self.u32(self.command_states[0]), self.u32(self.command_states[2])
        if not 0 <= head < 256 or not 0 <= tail < 256 or (tail + 1) & 255 == head:
            raise RuntimeError("TVB reply command ring invalid or full")
        return tail

    def publish_command(self, command, tail, next_cursor):
        writes = ((self.command_ring + tail * 0x40, command),
                  (self.consumer, struct.pack("<I", next_cursor)),
                  (self.command_states[2], struct.pack("<I", (tail + 1) & 255)))
        if self.publish is not None:
            self.publish(writes)
        else:
            for address, data in writes:
                self.write(address, data)
        self.notify()
        self.next_command_slot = (tail + 1) & 255

    def step(self):
        producer = self.u32(self.producer)
        if not 0 <= producer < 256:
            raise ValueError("invalid firmware report producer")
        if producer == self.cursor:
            return False
        body = self.read(self.records + self.cursor * 0x48, 0x48)
        self.last_report = dict(slot=self.cursor, record_hex=body.hex())
        opcode, word1, word2, counter = struct.unpack_from("<4I", body)
        next_cursor = (self.cursor + 1) & 255
        if opcode == 7 and self.limit_handler is not None:
            if self.limit_report is not None or not self.replies or not self.replies[-1].get("negative_reply"):
                raise ValueError("memory-limit report is not after an owned negative reply")
            tail = self.command_slot()
            # The caller validates the complete report against its owned
            # queue/pool/descriptor/event before returning any command.
            result = dict(self.limit_handler(body))
            command = result.pop("command")
            if (len(command) != 0x40 or struct.unpack_from("<2I", command) != (9, 1) or
                    command[8:16] != body[24:32] or command[16:20] != body[16:20] or any(command[20:])):
                raise ValueError("invalid native memory-limit follow-up")
            self.publish_command(command, tail, next_cursor)
            self.limit_report = dict(result, record_hex=body.hex(), command_hex=command.hex(),
                                     report_slot=self.cursor, reply_slot=tail)
            self.cursor = next_cursor
            return False
        if (opcode, word1, word2, counter) == (1, self.terminal_mask, 0, 0):
            if self.limit_report is not None and body != struct.pack("<4I", 1, self.terminal_mask, 0, 0) + bytes(56):
                raise ValueError("memory-limit terminal report differs from native")
            self.terminal = dict(slot=self.cursor, record_hex=body.hex())
            # No target or fence success is inferred from this record.
            self.cursor = next_cursor
            self.write(self.consumer, struct.pack("<I", self.cursor))
            return True
        if (opcode, word1, word2, counter) != (6, self.context_id, 0, self.first_counter + len(self.replies)):
            raise ValueError("unattributed or unexpected TVB report: " + body.hex())
        if len(self.replies) >= self.request_limit:
            raise RuntimeError("%d-request TVB service limit" % self.request_limit)
        tail = self.command_slot()
        reply = self.prepare(body, counter)
        command = reply.pop("command")
        allowed = {(8, 1, 0, self.context_id, counter)}
        if self.limit_handler is not None:
            allowed.add((8, 0, 0, self.context_id, counter))
        if len(command) != 0x40 or struct.unpack_from("<5I", command) not in allowed or any(command[20:]):
            raise ValueError("allocation produced an invalid TVB reply")
        # Both callbacks preserve ordered coherent partial stores. The optional
        # batch removes proxy gaps without changing producer-last publication.
        self.publish_command(command, tail, next_cursor)
        self.replies.append(dict(reply, report_slot=self.cursor, reply_slot=tail,
                                 request_hex=body.hex(), negative_reply=command[4] == 0))
        self.cursor = next_cursor
        return False

    def run(self, timeout=10, finished=None):
        """Service until a report boundary or explicit caller witness.

        A later source draw can finish without emitting (1,3,0,0). Queue read
        heads can advance while growth is still pending and are NOT a suitable
        finish predicate. The caller uses a real output/fence witness and
        still validates the complete output after this bounded service loop.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            terminal = self.step()
            if terminal or (finished is not None and finished()):
                return dict(start_cursor=self.start_cursor, cursor=self.cursor,
                            replies=self.replies, terminal=self.terminal,
                            limit_report=self.limit_report,
                            next_command_slot=self.next_command_slot,
                            stopped_by="report" if terminal else "caller-witness",
                            execution_claim="none; output verification required")
        raise TimeoutError("TVB request/reply service timeout")
