# SPDX-License-Identifier: MIT
"""Diagnostic full native growth-reply replay; never imported by the shim."""
import json
import os
from pathlib import Path
import struct

from g17p_growth_capture import load_capture, PAGE


def coalesce(pages):
    runs = []
    for pa, body in sorted(pages.items()):
        if runs and runs[-1][0] + len(runs[-1][1]) == pa and len(runs[-1][1]) < 0x100000:
            runs[-1][1].extend(body)
        else:
            runs.append((pa, bytearray(body)))
    return runs


def require_no_heap_overlap(util, pages):
    cursor, live = int(util.heap.offset), []
    for blocks, used in util.heap.blocks:
        end = cursor + int(blocks) * int(util.heap.block)
        if used:
            live.append((cursor, end))
        cursor = end
    for pa, body in pages.items():
        if any(pa < end and start < pa + len(body) for start, end in live):
            raise RuntimeError("captured reply overlaps live host allocation at %#x" % pa)


class NativeGrowthReplay:
    def __init__(self, directory, namespace, primary):
        selected_pool = os.environ.get('G17P_GROWTH_REPLAY_POOL')
        self.native, self.snapshots, self.ctx, self.target, self.before, self.expected = load_capture(
            directory, pool_id=None if selected_pool is None else int(selected_pool, 0))
        self.first = self.snapshots["first_work"]
        header = struct.unpack_from("<4I", bytes.fromhex(self.native["first_request"]["record_hex"]))
        if header[:2] != (6, 1) or header[2] not in (0, 1) or header[3] != 0:
            raise ValueError("unqualified captured growth owner")
        self.pool_id = header[2]
        self.u, self.p, self.iface = (namespace[key] for key in ("u", "p", "iface"))
        self.primary = primary
        self.ASCMessage1 = namespace["ASCMessage1"]
        self.output = Path(namespace["attempt_dir"])
        self.channels = {int(k): tuple(v) for k, v in self.native["channels"].items()}
        self.fwctx = int(self.first.manifest["selected_root"]["ctx_id"])
        self.cursor = self.u32(self.channels[13][0] + 0x20)
        self.replies = 0
        self.terminal = False
        self.copy_mode = os.environ.get("G17P_GROWTH_REPLY_COPY", "all")
        if self.copy_mode not in ("all", "host-pages", "source"):
            raise ValueError("unknown growth reply copy mode")
        self.report = dict(execution_path="full captured native host-graph reply replay",
            source_only=False, replies=[], terminal=False,
            coprocessor_private_data_restored=False, reply_copy=self.copy_mode)
        work = next(i for i, row in enumerate(self.native["events"])
                    if row["endpoint"] == 0x21 and row["message"] >> 48 == 0x83)
        notifications = {row["message"] for row in self.native["events"][work + 1:]
                         if row["endpoint"] == 0x21 and row["message"] >> 48 == 0x84}
        if len(notifications) != 1:
            raise ValueError("capture lacks an unambiguous reply doorbell")
        self.notification = notifications.pop()
        self.publications = [row for row in self.native["publications"]
            if struct.unpack_from("<I", bytes.fromhex(row["record_hex"]))[0] == 8]
        pool = self.first.pool(self.fwctx, self.pool_id)
        self.pool_state, self.pool_list = pool["state"], pool["blocks"]
        self.report["owned_pool"] = pool
        self.grow_blocks = int(os.environ.get("G17P_GROWTH_BLOCKS", "10"))
        self.grow_base = int(os.environ.get("G17P_GROWTH_BASE", "0x1002000000"), 0)
        if not 1 <= self.grow_blocks <= 10:
            raise ValueError("invalid bounded source growth increment")
        self.save()

    def save(self):
        (self.output / "native_growth_replay.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def read_pa(self, pa, size):
        self.p.dc_ivac(pa, size)
        return bytes(self.iface.readmem(pa, size))

    def read(self, va, size):
        # Channel states/records stay within one owned page for these reads.
        pa = self.first.pa(self.fwctx, va)
        if va % PAGE + size > PAGE:
            raise ValueError("unbounded ring read")
        return self.read_pa(pa, size)

    def u32(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]

    def write32(self, va, value):
        pa = self.first.pa(self.fwctx, va)
        self.iface.writemem(pa, struct.pack("<I", value))
        self.p.dc_civac(pa, 4)

    def target_bytes(self):
        return b"".join(self.read_pa(self.first.pa(self.ctx, va), PAGE)
            for va in range(self.target, self.target + 0x10000, PAGE))

    def source_reply(self, request):
        # This historical replay deliberately avoids the legacy AGX package
        # initializer, whose Construct version matrix predates Neo.
        import importlib.util
        path = Path(__file__).resolve().parents[1] / 'm1n1/agx/g17p_growth.py'
        spec = importlib.util.spec_from_file_location('neo_source_growth', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        allocate_growth_reply = module.allocate_growth_reply
        if self.replies >= 32:
            raise RuntimeError("bounded Neo source growth request budget")
        # These are the owned initial fixture's data objects, not pointers
        # supplied by an untrusted report or a pending-reply snapshot.
        state_pa = self.first.pa(self.fwctx, self.pool_state)
        list_pa = self.first.pa(self.fwctx, self.pool_list)
        old = struct.unpack('<I', self.read_pa(state_pa, 4))[0]
        roots = {r['root_pa'] for r in self.first.manifest['root_mappings']
                 if r['root_ctx_id'] == self.ctx and r['selector'] == 0}
        if len(roots) != 1 or old != 8 + self.replies * self.grow_blocks:
            raise ValueError('source fixture pool/root attribution differs')
        producer = self.u32(self.channels[12][2])
        head = self.u32(self.channels[12][0])
        if not 0 <= producer < 256 or (producer + 1) % 256 == head:
            raise RuntimeError('source reply ring invalid/full')
        record = allocate_growth_reply(self.u, self.p, self.iface, self.read_pa,
            root_pa=roots.pop(), state_pa=state_pa, list_pa=list_pa, list_capacity=PAGE // 8,
            request=request, expected_counter=self.replies,
            pool_id=self.pool_id,
            block_dvas=tuple(self.grow_base + (old - 8 + i) * 0x28000
                             for i in range(self.grow_blocks)))
        command = record.pop('command')
        if self.target_bytes() != self.before:
            raise RuntimeError('source allocation unexpectedly changed target')
        command_pa = self.first.pa(self.fwctx, self.channels[12][3] + producer * 0x40)
        self.iface.writemem(command_pa, command)
        self.p.dc_civac(command_pa, len(command))
        self.write32(self.channels[13][0], (self.cursor + 1) % 256)
        self.u.inst('dsb sy')
        self.write32(self.channels[12][2], (producer + 1) % 256)
        self.u.inst('dsb sy')
        self.primary.send(self.notification, self.ASCMessage1(EP=0x21))
        self.report['replies'].append(dict(record, request_hex=request.hex(),
            command_hex=command.hex(), target_unchanged=True))
        self.replies += 1
        self.cursor = (self.cursor + 1) % 256
        self.save()
        print('Source Neo growth:', record, flush=True)

    def step(self):
        if self.terminal:
            return
        tail = self.u32(self.channels[13][0] + 0x20)
        if not 0 <= tail < 256 or not 0 <= self.cursor < 256:
            raise RuntimeError("invalid live report interval")
        if tail == self.cursor:
            return
        request = self.read(self.channels[13][1] + self.cursor * 0x48, 0x48)
        header = struct.unpack_from("<4I", request)
        terminal_mask = 0xc if self.pool_id == 1 else 3
        if header == (1, terminal_mask, 0, 0):
            self.terminal = True
            self.report.update(terminal=True, terminal_hex=request.hex())
            self.cursor = (self.cursor + 1) % 256
            self.write32(self.channels[13][0], self.cursor)
            self.save()
            return
        if header != (6, 1, self.pool_id, self.replies):
            raise RuntimeError("unexpected replay report: " + request.hex())
        if self.copy_mode == 'source':
            self.source_reply(request)
            return
        snapshot = self.snapshots["reply_%d" % self.replies]
        publication = self.publications[self.replies]
        producer_va = self.channels[12][2]
        if self.u32(producer_va) != publication["before"]:
            raise RuntimeError("replay reply slot differs from native publication")
        current = self.target_bytes()
        if current != self.before or snapshot.read(self.ctx, self.target, 0x10000) != self.before:
            raise RuntimeError("reply replay would introduce a target result")
        pages = snapshot.pages()
        if self.copy_mode == "host-pages":
            # Diagnostic page bisection of the captured native host response.
            # The full initial graph remains replayed. Do not rewind the GPU's
            # live old TVB payload, vertex scratch or other working pages.
            before_pages = self.first.pages()
            selected = {snapshot.pa(self.fwctx, va) & -PAGE for va in (
                self.channels[13][0], self.channels[12][3] + publication["before"] * 0x40,
                self.pool_state, self.pool_list)}
            pages = {pa: body for pa, body in pages.items()
                     if before_pages.get(pa) != body and
                     (pa not in before_pages or pa in snapshot.tables or pa in selected)}
        require_no_heap_overlap(self.u, pages)
        # Deliberately restore ALL permitted captured pages before reducing
        # dependencies. The original native producer remains unpublished.
        for pa, body in coalesce(pages):
            # Firmware may update its live data while it is being restored.
            # Validate decompression into private scratch, then copy the exact
            # bytes; a CRC over a free-running destination is not stable.
            with self.u.heap.guarded_malloc(len(body)) as scratch:
                if any(start < scratch + len(body) and scratch < start + len(part)
                       for start, part in pages.items()):
                    raise RuntimeError("reply transfer scratch overlaps capture")
                self.u.compressed_writemem(scratch, body)
                self.p.memcpy8(pa, scratch, len(body))
            self.p.dc_civac(pa, len(body))
        self.u.inst("dsb sy")
        if self.target_bytes() != self.before or self.u32(producer_va) != publication["before"]:
            raise RuntimeError("full reply restore changed output/publication boundary")
        command = self.read(self.channels[12][3] + publication["before"] * 0x40, 0x40)
        if command.hex() != publication["record_hex"]:
            raise RuntimeError("restored native reply differs")
        self.write32(producer_va, publication["after"])
        self.u.inst("dsb sy")
        self.primary.send(self.notification, self.ASCMessage1(EP=0x21))
        self.report["replies"].append(dict(counter=self.replies, request_hex=request.hex(),
            command_hex=command.hex(), restored_pages=len(pages), target_unchanged=True))
        self.replies += 1
        self.cursor = (self.cursor + 1) % 256
        self.save()
        print("Full native growth reply replayed:", self.replies, len(pages), flush=True)

    def verify(self):
        actual = self.target_bytes()
        (self.output / "growth_before.bin").write_bytes(self.before)
        (self.output / "growth_after.bin").write_bytes(actual)
        self.report.update(exact=actual == self.expected, reply_count=self.replies,
                           expected_reply_count=len(self.publications))
        self.save()
        count_ok = self.replies >= 1 if self.copy_mode == 'source' else self.replies == len(self.publications)
        if actual != self.expected or not count_ok:
            raise RuntimeError("full native growth replay output/transaction mismatch")
