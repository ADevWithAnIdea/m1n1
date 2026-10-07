# SPDX-License-Identifier: MIT
"""Hash-checked, data-only reader for native Neo growth snapshots."""
import hashlib
import json
from pathlib import Path
import re
import struct

PAGE = 0x4000
HOST_FIXED = {"gpu-region", "gfx-shared-region", "gfx-shared-l2-region", "gfx-handoff"}

class Snapshot:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.manifest = json.loads((self.directory / "manifest.json").read_text())
        m = self.manifest
        if m["format"] != "m1n1-agx-g17p-initdata-v2" or m["chip_id"] != 0x8140:
            raise ValueError("not a Neo data snapshot")
        self.ram, self.tables, self.fixed, self.mappings = {}, {}, {}, {}
        self.host_fixed = {}
        for filename, key, dest in (("ram.bin", "blob_pages", self.ram),
                                    ("tables.bin", "table_page_records", self.tables)):
            # Capture format names are intentionally checked, never guessed
            # from arbitrary pointers in firmware data.
            rows = m[key]
            body = (self.directory / filename).read_bytes()
            if (len(body) != len(rows) * PAGE or
                    sorted(row["index"] for row in rows) != list(range(len(rows)))):
                raise ValueError("incomplete snapshot " + filename)
            for row in rows:
                part = body[row["index"] * PAGE:(row["index"] + 1) * PAGE]
                if hashlib.sha256(part).hexdigest() != row["sha256"]:
                    raise ValueError("snapshot page digest mismatch")
                dest[row["original_pa"]] = part
        for row in m["fixed_regions"]:
            if "code" in row["name"]:
                raise ValueError("code region is not a data snapshot")
            body = (self.directory / row["file"]).read_bytes()
            if len(body) != row["size"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
                raise ValueError("fixed data region digest mismatch")
            if row["pa"] % PAGE or len(body) % PAGE:
                raise ValueError("unaligned fixed data")
            for offset in range(0, len(body), PAGE):
                self.fixed[row["pa"] + offset] = body[offset:offset + PAGE]
                if row["name"] in HOST_FIXED:
                    self.host_fixed[row["pa"] + offset] = body[offset:offset + PAGE]
        for group in m["root_mappings"]:
            ctx = group["root_ctx_id"]
            for mapping in group["mappings"]:
                key = (ctx, mapping["va"])
                old = self.mappings.setdefault(key, mapping["pa"])
                if old != mapping["pa"]:
                    self.mappings[key] = None

    def pages(self, *, include_coprocessor_data=False):
        result = {}
        # Restore the complete host-visible graph. Coprocessor-private data
        # cannot be checkpointed independently of its running CPU registers;
        # the normal Neo and M5 replay paths leave those regions live.
        fixed = self.fixed if include_coprocessor_data else self.host_fixed
        for group in (fixed, self.ram, self.tables):
            for pa, body in group.items():
                if pa in result and result[pa] != body:
                    raise ValueError("overlapping snapshot data differs")
                result[pa] = body
        return result

    def pa(self, ctx, va):
        page = self.mappings[(ctx, va & -PAGE)]
        if page is None:
            raise ValueError("ambiguous snapshot context/address")
        return page + va % PAGE

    def physical(self, pa, size):
        result = bytearray()
        while size:
            base, offset = pa & -PAGE, pa % PAGE
            body = self.ram.get(base, self.tables.get(base, self.fixed.get(base)))
            if body is None:
                raise ValueError("read outside captured data")
            count = min(size, PAGE - offset)
            result += body[offset:offset + count]
            pa, size = pa + count, size - count
        return bytes(result)

    def read(self, ctx, va, size):
        result = bytearray()
        while size:
            count = min(size, PAGE - va % PAGE)
            result += self.physical(self.pa(ctx, va), count)
            va, size = va + count, size - count
        return bytes(result)

    def pool(self, ctx, owner):
        """Locate the initial eight-block pool by decoded DATA fields only.

        Index allocation size/scalars vary between native queue incarnations.
        Derive the two known pointer fields from the unique initial owner;
        never substitute an address from another capture or a report payload.
        """
        matches = []
        for (context, va), pa in self.mappings.items():
            if context != ctx or va < 0xfffffc0000000000 or pa not in self.ram:
                continue
            body = self.ram[pa]
            for offset in range(0, PAGE - 0x88, 8):
                if (struct.unpack_from('<I', body, offset + 0xc)[0] != owner or
                        struct.unpack_from('<I', body, offset + 0x34)[0] != 32 or
                        struct.unpack_from('<II', body, offset + 0x3c) != (8, 0) or
                        struct.unpack_from('<II', body, offset + 0x54) != (31, 0x20000)):
                    continue
                blocks, state = struct.unpack_from('<QQ', body, offset + 0x44)
                if ((blocks | state) & (PAGE - 1) or
                        self.read(ctx, state, 8) != struct.pack('<II', 8, 8)):
                    continue
                self.read(ctx, blocks, 0x8000)  # Complete owned block-list extent.
                matches.append(dict(shared=va + offset, state=state, blocks=blocks))
        if len(matches) != 1:
            raise ValueError("capture lacks one unambiguous initial growth pool")
        return matches[0]

def load_capture(directory, pool_id=None):
    directory = Path(directory).resolve()
    report = json.loads((directory / "manifest.json").read_text())
    if (report.get("format") != "neo-native-growth-observation-v1" or report.get("error")
            or not report.get("completion_marker") or not report.get("full_capture")):
        raise ValueError("not a completed full native growth capture")
    owners = report.get("staged_assets", {}).get("owners", False)
    both = report.get('staged_assets', {}).get('both', False)
    pool_id = (1 if owners else 0) if pool_id is None else pool_id
    if type(pool_id) is not int or pool_id not in ((0, 1) if owners else (0,)):
        raise ValueError('capture does not contain the selected pool')
    completed_label, first_label = (("completed_%d" % pool_id, "first_work_%d" % pool_id) if owners else
                                     ("completed", "first_work"))
    completed = [s for s in report["samples"] if s["label"] == completed_label]
    first = [s for s in report["samples"] if s["label"] == first_label]
    if len(completed) != 1 or len(first) != 1 or completed[0].get("exact_output") is not True:
        raise ValueError("capture lacks independent complete output witnesses")
    snapshot_rows = report['snapshots']
    if owners:
        warmup = [s for s in report["samples"] if s["label"] == "completed_0"]
        last = [s for s in report['samples'] if s['label'] == 'completed_1']
        retained = last[0].get("earlier_outputs", []) if len(last) == 1 else []
        if (len(warmup) != 1 or warmup[0].get("exact_output") is not True or
                len(last) != 1 or last[0].get('exact_output') is not True or
                len(retained) != 1 or retained[0].get("owner") != 0 or
                retained[0].get("exact") is not True):
            raise ValueError("two-owner capture lacks retained first output proof")
        previous = (directory / warmup[0]["target"]["file"]).read_bytes()
        previous_count = int(report.get('targets', {}).get('0', {}).get('triangles', 1))
        if (not 1 <= previous_count <= 4000000 or
                previous != struct.pack("<I", 28 * previous_count) + bytes(0xfffc) or
                (directory / retained[0]["file"]).read_bytes() != previous):
            raise ValueError("retained first output changed")
    if both:
        # Counter zero is local to EACH pool, so labels alone are not keys.
        # Pair chronological reply snapshots with the corresponding typed
        # control publications before selecting an owner's transaction.
        all_replies = [row for row in report['publications']
                       if struct.unpack_from('<I', bytes.fromhex(row['record_hex']))[0] == 8]
        reply_snapshots = [row for row in snapshot_rows if row['label'].startswith('reply_')]
        if len(reply_snapshots) != len(all_replies):
            raise ValueError('multi-pool capture lacks one snapshot per reply')
        selected_replies, selected_snapshots = [], []
        for publication, snapshot in zip(all_replies, reply_snapshots):
            words = struct.unpack_from('<5I', bytes.fromhex(publication['record_hex']))
            if snapshot['label'] != 'reply_%d' % words[4]:
                raise ValueError('reply snapshot disagrees with local counter')
            if words[2] == pool_id:
                selected_replies.append(publication)
                selected_snapshots.append(snapshot)
        requests = [row for row in report.get('report_publications', ())
                    if struct.unpack_from('<4I', bytes.fromhex(row['record_hex'])) == (6, 1, pool_id, 0)]
        if len(requests) != 1:
            raise ValueError('multi-pool capture lacks a unique initial owned request')
        report = dict(report, first_request=requests[0], publications=selected_replies,
                      all_pool_publications=report['publications'], selected_pool_id=pool_id)
        snapshot_rows = [row for row in snapshot_rows if not row['label'].startswith('reply_')]
        snapshot_rows += selected_snapshots
    snapshots = {row['label']: Snapshot(row['path']) for row in snapshot_rows}
    if len(snapshots) != len(snapshot_rows):
        raise ValueError('ambiguous snapshot labels for selected pool')
    if owners:
        snapshots['first_work'] = snapshots.pop(first_label)
    replies = [row for row in report["publications"]
               if struct.unpack_from("<I", bytes.fromhex(row["record_hex"]))[0] == 8]
    labels = {"first_work"} | {"reply_%d" % i for i in range(len(replies))}
    ignored = {"pre_init", "request"} | ({"first_work_%d" % (1 - pool_id)} if owners else set())
    if not replies or not report.get("first_request") or set(snapshots) - ignored != labels:
        raise ValueError("incomplete captured request/reply sequence")
    target = first[0]["target"]["dva"]
    ctx = first[0]["target"]["root"]["context"]
    before = (directory / first[0]["target"]["file"]).read_bytes()
    after = (directory / completed[0]["target"]["file"]).read_bytes()
    if before != b"\xa5" * 0x10000 or len(after) != 0x10000:
        raise ValueError("invalid full native output buffers")
    if snapshots["first_work"].read(ctx, target, 0x10000) != before:
        raise ValueError("full capture disagrees with pre-kick witness")
    counts = ([int(report["targets"][str(pool_id)]["triangles"])] if owners else
              [int(match[1]) for line in report["markers"]
               if (match := re.search(r"NEO_GROWTH_CONFIG triangles=(\d+) ", line))])
    if len(counts) != 1 or not 1 <= counts[0] <= 4000000:
        raise ValueError("missing unique bounded own workload configuration")
    if after != struct.pack("<I", counts[0] * 28) + bytes(0x10000 - 4):
        raise ValueError("native result fails independent full-buffer integer oracle")
    return report, snapshots, ctx, target, before, after
