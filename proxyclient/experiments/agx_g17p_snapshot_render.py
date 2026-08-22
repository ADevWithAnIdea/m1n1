#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract the latest render group from a saved G17P guest snapshot.

The snapshot contains hardware-visible shared memory only.  This follows the
channel table, latest outer slot, queue record, item ring, and work descriptor,
then reports the render registers and hashes the selected pipeline pages.
"""

import argparse
import hashlib
import json
import pathlib
import struct


PAGE = 0x4000
WORK_SLOT_STRIDE = 0x18


def channels_for_pair(pair):
    if pair < 0 or pair > 3:
        raise ValueError("channel pair must be within 0..3")
    base = pair * 3
    return ((base, "TA_%d" % pair, "tiling", 0x60),
            (base + 1, "3D_%d" % pair, "fragment", 0xa0))
KEY_REGISTERS = {
    "tiling": {
        0x14318: "status",
        0x1c039: "tilemap_offset",
        0x1c880: "encoder_offset",
    },
    "fragment": {
        0x14080: "status",
        0x15101: "depth_bias",
        0x15109: "scissor",
        0x15211: "dimensions",
        0x15369: "load_pipeline_bind",
        0x15371: "load_pipeline",
        0x15379: "store_pipeline_bind",
        0x15381: "store_pipeline",
        0x16060: "heapmeta",
        0x16429: "tilemap",
        0x16461: "aux_fb",
    },
}


def canonicalize(value, shift):
    value &= (1 << (shift + 1)) - 1
    if value & (1 << shift):
        value |= ((1 << 64) - 1) ^ ((1 << (shift + 1)) - 1)
    return value


class Snapshot:
    def __init__(self, directory):
        self.directory = directory.resolve()
        self.manifest = json.loads((self.directory / "manifest.json").read_text())
        self.shift = int(self.manifest["vaddr_shift"])
        self.ram = (self.directory / self.manifest["ram_file"]).read_bytes()
        if hashlib.sha256(self.ram).hexdigest() != self.manifest["ram_sha256"]:
            raise ValueError("RAM image checksum mismatch")
        self.pages = {}
        for root in self.manifest["root_mappings"]:
            identity = (int(root["root_index"]), int(root["root_ctx_id"]),
                        int(root["selector"]))
            table = self.pages.setdefault(identity, {})
            for mapping in root["mappings"]:
                blob_index = mapping.get("blob_index")
                if blob_index is None:
                    continue
                address = canonicalize(int(mapping["va"]), self.shift)
                table[address & ~(PAGE - 1)] = int(blob_index)

    def normalize(self, address):
        return canonicalize(int(address), self.shift)

    def identities(self, ctx_id=None):
        identities = list(self.pages)
        if ctx_id is not None:
            identities = [item for item in identities if item[1] == ctx_id]
        return identities

    def read(self, address, size, ctx_id=None):
        address = self.normalize(address)
        for identity in self.identities(ctx_id):
            table = self.pages[identity]
            cursor = address
            remaining = size
            output = bytearray()
            while remaining:
                index = table.get(cursor & ~(PAGE - 1))
                if index is None:
                    break
                offset = cursor & (PAGE - 1)
                count = min(remaining, PAGE - offset)
                start = index * PAGE + offset
                output += self.ram[start:start + count]
                cursor += count
                remaining -= count
            if not remaining:
                return bytes(output), identity
        raise ValueError("DVA %#x (%#x bytes) is absent from ctx %r" %
                         (address, size, ctx_id))

    def u32(self, address, ctx_id=None):
        return struct.unpack("<I", self.read(address, 4, ctx_id)[0])[0]

    def u64(self, address, ctx_id=None):
        return struct.unpack("<Q", self.read(address, 8, ctx_id)[0])[0]


def parse_registers(body, offset):
    registers = []
    empty = 0
    while offset + 12 <= len(body):
        number, value = struct.unpack_from("<IQ", body, offset)
        offset += 12
        if number == 0 and value == 0:
            empty += 1
            if empty == 3:
                break
            continue
        empty = 0
        registers.append((number, value))
    return registers


def keyed_registers(kind, registers):
    wanted = KEY_REGISTERS[kind]
    result = {}
    for number, value in registers:
        name = wanted.get(number)
        if name is not None and name not in result:
            result[name] = value
    return result


def pipeline_record(snapshot, address, output_dir, label, render_context):
    if not address:
        return None
    page_address = address & ~(PAGE - 1)
    data, identity = snapshot.read(
        page_address, PAGE, ctx_id=render_context)
    record = {
        "address": address,
        "page_address": page_address,
        "page_offset": address - page_address,
        "root": list(identity),
        "sha256": hashlib.sha256(data).hexdigest(),
        "nonzero_bytes": sum(value != 0 for value in data),
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = "%s_%012x.bin" % (label, page_address)
        (output_dir / filename).write_bytes(data)
        record["file"] = filename
    return record


def extract(snapshot, output_dir, pair=0, render_context=1):
    init_message = int(snapshot.manifest["init_message"])
    init_address = snapshot.normalize(init_message & ((1 << 44) - 1))
    region_b = snapshot.u64(init_address + 0x18, ctx_id=64)
    result = {
        "format": "m1n1-agx-g17p-snapshot-render-v1",
        "snapshot": str(snapshot.directory),
        "init_address": init_address,
        "region_b": region_b,
        "channel_pair": pair,
        "render_context": render_context,
        "channels": [],
    }
    for index, name, kind, register_offset in channels_for_pair(pair):
        channel_address = region_b + 0x20 + index * 0x20
        state_addresses = [snapshot.u64(channel_address + offset, ctx_id=64)
                           for offset in (0, 8, 0x10)]
        counters = [snapshot.u32(address, ctx_id=64)
                    for address in state_addresses]
        producer = counters[2]
        if producer == 0:
            raise ValueError("%s has no published outer slot" % name)
        ring = snapshot.u64(channel_address + 0x18, ctx_id=64)
        slot_index = producer - 1
        slot_address = ring + slot_index * WORK_SLOT_STRIDE
        slot = snapshot.read(slot_address, WORK_SLOT_STRIDE, ctx_id=64)[0]
        queue = struct.unpack_from("<Q", slot, 8)[0]
        outer_head = struct.unpack_from("<I", slot, 0x14)[0] & 0xffff
        pointer_state = snapshot.u64(queue, ctx_id=64)
        item_ring = snapshot.u64(queue + 8, ctx_id=64)
        write_head = snapshot.u32(pointer_state + 0x40, ctx_id=64)
        head = outer_head or write_head
        if head < 3:
            raise ValueError("%s latest head is %d, cannot hold a group" %
                             (name, head))
        item_addresses = [snapshot.u64(item_ring + offset * 8, ctx_id=64)
                          for offset in range(head - 3, head)]
        descriptor = item_addresses[0]
        descriptor_body = snapshot.read(descriptor, 0x2400, ctx_id=64)[0]
        registers = parse_registers(descriptor_body, register_offset)
        key = keyed_registers(kind, registers)
        channel = {
            "index": index,
            "name": name,
            "kind": kind,
            "state_addresses": state_addresses,
            "counters": counters,
            "ring": ring,
            "slot_index": slot_index,
            "slot_address": slot_address,
            "slot_hex": slot.hex(),
            "queue": queue,
            "pointer_state": pointer_state,
            "item_ring": item_ring,
            "outer_head": outer_head,
            "write_head": write_head,
            "item_addresses": item_addresses,
            "descriptor": descriptor,
            "register_count": len(registers),
            "key_registers": key,
        }
        if kind == "fragment":
            channel["pipelines"] = {
                which: pipeline_record(snapshot, key.get(which, 0), output_dir,
                                       "%s_%s" % (name, which),
                                       render_context)
                for which in ("load_pipeline", "store_pipeline")
            }
            dimensions = key.get("dimensions")
            if dimensions is not None:
                channel["width"] = dimensions & 0xffffffff
                channel["height"] = dimensions >> 32
        result["channels"].append(channel)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--dump-pipelines", type=pathlib.Path)
    parser.add_argument(
        "--pair", type=int, default=0,
        help="TA/3D channel pair to extract (default: 0)")
    parser.add_argument(
        "--render-context", type=int, default=1,
        help="UAT context containing render objects and pipelines (default: 1)")
    args = parser.parse_args()

    result = extract(
        Snapshot(args.snapshot), args.dump_pipelines,
        pair=args.pair, render_context=args.render_context)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
