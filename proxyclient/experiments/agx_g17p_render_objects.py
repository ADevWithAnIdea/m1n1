#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Enumerate the render-context objects a G17P register program names, and say what is in them.

The firmware-context side of a work group is now built from a model. What is still copied is the
other side: the objects in the render context that the register arrays point at. A driver has to
allocate and fill those itself, so the first question is which carry structure worth modelling and
which are scratch that a fresh zero page would satisfy.

This reads the all-roots snapshot the replay harness uses, parses the two work descriptors' ordered
register arrays out of it, resolves every address those arrays name, and reports the extent and
leading words of each. Addresses the snapshot does not cover are named as such rather than dropped,
because a list that quietly omits what it could not see would overstate how much is understood.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

PAGE_SIZE = 0x4000
REGISTER_ENTRY_SIZE = 0xc

# Where each descriptor's pointer block and register array begin, established on hardware.
DESCRIPTOR_LAYOUT = {
    "tiling": {"registers": 0x60},
    "fragment": {"registers": 0xa0},
}

DEFAULT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "initdata_pre_submit_all_uat_roots_v2_20260724_150935"
)


def canonicalize(value, shift):
    if value & (1 << (shift - 1)):
        value |= ~((1 << shift) - 1)
    return value & 0xffffffffffffffff


def load_snapshot(path):
    manifest = json.loads((path / "manifest.json").read_bytes())
    if manifest.get("format") != "m1n1-agx-g17p-initdata-v2":
        raise SystemExit("snapshot is not the all-roots v2 format")
    ram = (path / manifest["ram_file"]).read_bytes()
    if hashlib.sha256(ram).hexdigest() != manifest["ram_sha256"]:
        raise SystemExit("RAM blob checksum mismatch")
    return manifest, ram


class Roots:
    """Every captured page, grouped by the UAT root it was reachable through."""

    def __init__(self, manifest, ram):
        self.by_root = {}
        shift = int(manifest["vaddr_shift"])
        for mapping_set in manifest["root_mappings"]:
            identity = (
                int(mapping_set["root_index"]),
                int(mapping_set["root_ctx_id"]),
                int(mapping_set["selector"]),
            )
            pages = self.by_root.setdefault(identity, {})
            for mapping in mapping_set["mappings"]:
                blob_index = mapping.get("blob_index")
                if blob_index is None:
                    continue
                dva = canonicalize(int(mapping["va"]) & ((1 << 44) - 1), shift)
                pages[dva] = ram[int(blob_index) * PAGE_SIZE:
                                 (int(blob_index) + 1) * PAGE_SIZE]

    def read(self, dva, length, root=None):
        """Bytes at a device address, from a named root or from whichever root has them."""
        roots = [root] if root is not None else list(self.by_root)
        for identity in roots:
            pages = self.by_root.get(identity, {})
            base = dva & ~(PAGE_SIZE - 1)
            if base not in pages:
                continue
            out = bytearray()
            cursor = dva
            remaining = length
            while remaining > 0:
                page = pages.get(cursor & ~(PAGE_SIZE - 1))
                if page is None:
                    break
                start = cursor & (PAGE_SIZE - 1)
                take = min(remaining, PAGE_SIZE - start)
                out += page[start:start + take]
                cursor += take
                remaining -= take
            if out:
                return bytes(out), identity
        return None, None

    def render_roots(self):
        """Roots that are not the firmware half, in descending page count."""
        candidates = [(len(pages), identity)
                      for identity, pages in self.by_root.items()]
        return [identity for _, identity in sorted(candidates, reverse=True)]


def parse_registers(page_bytes, kind):
    """The ordered (number, value) program stored in a work descriptor."""
    registers = []
    cursor = DESCRIPTOR_LAYOUT[kind]["registers"]
    empties = 0
    while cursor + REGISTER_ENTRY_SIZE <= len(page_bytes):
        number = struct.unpack_from("<I", page_bytes, cursor)[0]
        data = struct.unpack_from("<Q", page_bytes, cursor + 4)[0]
        if number == 0 and data == 0:
            empties += 1
            if empties >= 3:
                break
        else:
            empties = 0
            registers.append((number, data))
        cursor += REGISTER_ENTRY_SIZE
    return registers


def register_value(registers, number, occurrence=0):
    matches = [value for candidate, value in registers if candidate == number]
    if occurrence >= len(matches):
        return None
    return matches[occurrence]


def capture_pages(capture):
    """Every page a targeted capture holds, keyed by device address, across both channels."""
    pages = {}
    directories = sorted(
        child for child in capture.iterdir()
        if child.is_dir() and child.name.startswith(("TA_", "3D_"))
        and (child / "pages.json").exists()
    )
    for directory in directories:
        if not (directory / "pages.json").exists():
            continue
        index = json.loads((directory / "pages.json").read_bytes())
        blob = (directory / "pages.bin").read_bytes()
        for page in index["pages"]:
            dva = page["dva"] & 0xffffffffffffffff
            offset = page["capture_offset"]
            pages[dva] = blob[offset:offset + index["page_size"]]
    return pages


def read_pages(pages, dva, length):
    out = bytearray()
    while length:
        page = pages.get(dva & ~(PAGE_SIZE - 1))
        if page is None:
            return None
        offset = dva & (PAGE_SIZE - 1)
        take = min(length, PAGE_SIZE - offset)
        out += page[offset:offset + take]
        dva += take
        length -= take
    return bytes(out)


def find_descriptors(capture, pages):
    """Read the exact work descriptors named by the captured queue entries."""
    found = {}
    for directory in sorted(capture.iterdir()):
        if directory.name.startswith("TA_"):
            kind = "tiling"
        elif directory.name.startswith("3D_"):
            kind = "fragment"
        else:
            continue
        target_path = directory / "target.json"
        if not target_path.exists():
            continue
        target = json.loads(target_path.read_bytes())
        queues = target.get("queues") or []
        if len(queues) != 1 or len(queues[0].get("inner_entries") or []) != 1:
            raise SystemExit("%s does not describe exactly one queue item" % directory.name)
        dva = int(queues[0]["inner_entries"][0][0])
        body = read_pages(pages, dva, 0x2240)
        if body is None:
            raise SystemExit("descriptor %#x is incomplete in %s" % (dva, directory.name))
        registers = parse_registers(body, kind)
        if len(registers) < 40:
            raise SystemExit("descriptor %#x has only %d registers" % (dva, len(registers)))
        found[kind] = (dva, registers)
    return found


def summarize(name, dva, roots, current_pages, length=PAGE_SIZE):
    if dva is None:
        return "register absent"
    if dva == 0:
        return "null"
    extent = min(length, PAGE_SIZE - (dva & (PAGE_SIZE - 1)))
    data = read_pages(current_pages, dva, extent)
    identity = "targeted capture"
    if data is None:
        data, identity = roots.read(dva, extent)
    if data is None:
        return "not in snapshot"
    last = 0
    for index, byte in enumerate(data):
        if byte:
            last = index + 1
    if last == 0:
        return "zero, root %s" % (identity,)
    words = struct.unpack_from("<%dQ" % (min(last, 32) // 8 or 1),
                               data.ljust(8, b"\0"), 0)
    return "%d bytes, root %s: %s" % (
        last, identity, " ".join("%016x" % word for word in words[:4]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "capture", type=pathlib.Path,
        help="a targeted capture, which holds the two work descriptors")
    parser.add_argument(
        "--snapshot", type=pathlib.Path, default=DEFAULT_SNAPSHOT,
        help="the all-roots snapshot, which holds the render-context pages")
    parser.add_argument(
        "--dump", default=None,
        help="hex dump one named object, or 'all' for every non-empty one")
    args = parser.parse_args()

    manifest, ram = load_snapshot(args.snapshot.resolve())
    roots = Roots(manifest, ram)
    print("snapshot %s" % args.snapshot.name)
    print("%d roots, %d pages" % (
        len(roots.by_root), sum(len(p) for p in roots.by_root.values())))

    pages = capture_pages(args.capture.resolve())
    print("capture %s: %d pages" % (args.capture.name, len(pages)))
    found = find_descriptors(args.capture.resolve(), pages)
    if "tiling" not in found or "fragment" not in found:
        raise SystemExit("could not locate both work descriptors; found %s"
                         % sorted(found))

    ta_dva, ta_registers = found["tiling"]
    fragment_dva, fragment_registers = found["fragment"]
    print("tiling   descriptor %#014x, %d registers" % (ta_dva, len(ta_registers)))
    print("fragment descriptor %#014x, %d registers" % (fragment_dva, len(fragment_registers)))

    dimensions = register_value(fragment_registers, 0x15211)
    tilemap = register_value(fragment_registers, 0x16429)
    tiling_tilemap = register_value(ta_registers, 0x1c039)
    if dimensions is None or tilemap is None or tiling_tilemap is None:
        raise SystemExit("descriptor is missing the dimension or tilemap registers")
    context_base = tilemap - tiling_tilemap
    print("render context base %#x, %d x %d"
          % (context_base, dimensions & 0xffffffff, dimensions >> 32))
    print()

    # TA object addresses are context offsets; fragment ones are full device addresses.
    def ta_object(number, mask=None, occurrence=0):
        value = register_value(ta_registers, number, occurrence)
        if value is None:
            return None
        if mask is not None:
            value &= mask
        return context_base + value

    objects = [
        ("tiling", "tilemap", tilemap),
        ("tiling", "tile parameter cache", ta_object(0x1c0a1)),
        ("tiling", "heap meta", register_value(fragment_registers, 0x16060)),
        ("tiling", "deflake 1", ta_object(0x10111)),
        ("tiling", "deflake 2", ta_object(0x10119)),
        ("tiling", "deflake 3", ta_object(0x1c950, ~0x0004000000000000)),
        ("tiling", "encoder", ta_object(0x1c880, occurrence=0)),
        ("tiling", "tiling status", (register_value(ta_registers, 0x14318) or 0) & ~1),
        ("fragment", "store pipeline bind", register_value(fragment_registers, 0x15379)),
        ("fragment", "store pipeline", register_value(fragment_registers, 0x15381)),
        ("fragment", "load pipeline bind", register_value(fragment_registers, 0x15369)),
        ("fragment", "load pipeline", register_value(fragment_registers, 0x15371)),
        ("fragment", "scissor array", register_value(fragment_registers, 0x15109)),
        ("fragment", "depth bias array", register_value(fragment_registers, 0x15101)),
        ("fragment", "aux framebuffer", register_value(fragment_registers, 0x16461)),
        ("fragment", "depth buffer", register_value(fragment_registers, 0x15329)),
        ("fragment", "stencil buffer", register_value(fragment_registers, 0x15339)),
        ("fragment", "fragment status", (register_value(fragment_registers, 0x14080) or 0) & ~1),
    ]

    present = 0
    for side, name, dva in objects:
        state = summarize(name, dva, roots, pages)
        if state not in ("not in snapshot", "register absent", "null"):
            present += 1
        print("  %-8s %-22s %s  %s"
              % (side, name, "%#014x" % dva if dva else "%-14s" % "-", state))

    print()
    print("%d of %d named render objects are present and non-null in this snapshot"
          % (present, len(objects)))

    if args.dump:
        for side, name, dva in objects:
            if args.dump not in ("all", name):
                continue
            if not dva:
                continue
            extent = PAGE_SIZE - (dva & (PAGE_SIZE - 1))
            data = read_pages(pages, dva, extent)
            identity = "targeted capture"
            if data is None:
                data, identity = roots.read(dva, extent)
            if data is None:
                continue
            last = 0
            for index, byte in enumerate(data):
                if byte:
                    last = index + 1
            if last == 0:
                continue
            print()
            print("%s %s at %#014x, %d bytes" % (side, name, dva, last))
            hexdump(data[:last])
    return 0


def hexdump(data, per_line=32):
    """Sixteen-byte-word rows, since every structure here is little-endian and word-aligned."""
    for offset in range(0, len(data), per_line):
        chunk = data[offset:offset + per_line]
        words = " ".join(
            "%08x" % struct.unpack_from("<I", chunk.ljust(per_line, b"\0"), index)[0]
            for index in range(0, len(chunk), 4))
        print("  +%04x  %s" % (offset, words))


if __name__ == "__main__":
    raise SystemExit(main())
