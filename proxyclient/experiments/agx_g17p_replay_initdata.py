#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import struct
import sys
import time
import traceback

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from agx_g17p_queue import item_record_size, pending_entry_span


PAGE_SIZE = 0x4000
MAX_TRANSFER_SIZE = 0x400000
M1N1_RAM_BASE = 0x10000000000
TABLE_ADDR_MASK = 0x0000FFFFFFFFC000
# Set once from the command line, as a list so submit_first_work can read it without a new
# parameter threaded through several call sites. Defined here rather than beside its use,
# because parse_args runs at module level before that point in the file is reached.
DIFF_SHARED = [False]
SHARED_REGIONS = []
GRAFT_RESET_CONSUMED = [None]
VERIFY_GRAFTED = [False]
# The render parameters the recipe derived, so the encoder builder can reach the encoder's
# address without deriving it a second way and risking the two disagreeing.
RENDER_PARAMETERS = [None]
# The snapshot's own bytes, which are a valid before-image for every page the replay restored.
SNAPSHOT_RAM = [None]
SCAN_RENDER_PREFIX = [0]
BACKEND_READ_CHANNELS = [False]
# Which ring slot to take a channel's command queue from. A channel carries several queues and slot
# zero names the one its host opened first, so a world captured mid-stream needs a later slot.
QUEUE_SLOT = [0]
# Queue addresses unit 0 was given at initialization, kept so a publication onto a virgin channel pair
# can place its created queue in the same array. A virgin channel's slot names no queue at all.
TEMPLATE_QUEUE = {}
# Exact host inputs captured before each native device-control publication. Kept in a holder so
# submit_first_work can apply them without extending its already long call chain.
CONTROL_TIMELINE_REPLAY = [None]
CHANNEL_CONTROL_DVA = 0xFFFFFC20C07B8000
CHANNEL_CONTROL_BYTES = 0x100
CONTROL_ENTRY_SIZE = 0x40
CONTROL_ENTRY_COUNT = 0x100
CONTROL_RESOURCE_BYTES = 0x100000

# Caller-owned add3 program from the minimal native workload. This is the same
# clean-room program already used by the source-built compute experiment, with
# the one hardware-observed binding byte for this three-buffer allocation.
NATIVE_ADD3_SHADER = bytes.fromhex(
    "2ca0020012087c003c80020004000000"
    "8ca0420000000c009c80420004000000"
    "6700542c020000005900024026006700"
    "54240200000057000040260067005430"
    "1800000059040040260077002a410000"
    "00007701aa07000000020400f7002a00"
    "0000000000001c800200000000001481"
    "1106000000000c800200040000009f11"
    "5400020008a810051c80020004000000"
    "0f1254004c004b2c09445b2e09040b24"
    "09041b2609042b2809043b2a09046b30"
    "09047b32090403000700020000006000"
    "0e000000"
)


def queue_slot_base(ring_addr):
    """The ring slot this run reads a channel's command queue out of."""
    return ring_addr + QUEUE_SLOT[0] * WORK_RING_ENTRY_STRIDE
BACKEND_BUILT = [None]
# First-work redirects that must wait for the post-control overlay. On the world whose control
# channel stays live, the captured entry array is not in memory when these normally run, and the
# overlay carries that array, so a redirect applied before it would be overwritten anyway.
DEFERRED_REDIRECTS = []
# A render-context scan baseline taken before firmware starts, so that work already pending when it
# comes up is inside the measured window rather than before it.
INITIAL_SCAN_BASELINE = [None]
# The device-control operand page and the table inside it that a 0x20 entry names a slot of. Each
# populated entry is a mapped buffer's address with bit 60 set.
OPERAND_PAGE = 0x7000208000
OPERAND_TABLE_BASE = 0x400
OPERAND_TABLE_STRIDE = 0x40
# The buffers the table names lie this far apart, measured across the six populated slots of a
# first-submission world and the nine of a mid-stream one. It is a megabyte of buffer plus two
# pages, and firmware reads each buffer at that address rather than wherever one was allocated.
OPERAND_BUFFER_STRIDE = 0x108000
# The mechanical per-submission set of a geometry item: offset, stride and width. Every one of these
# advances by its own fixed step between one submission and the next on a live host, and a generated
# second submission that leaves them at the first's values is wrong in a way the first cannot reveal.
# Only 0x28 is a real address; the rest are plain offsets or counters.
PER_SUBMISSION_STRIDES = (
    (0x28, 0x80, 8),
    (0x310, 0x20, 4),
    (0x31c, 0x20, 4),
    (0x328, 0x4, 4),
    (0x3a0, 0x40, 4),
    (0x7a0, 0x100, 4),
    (0x7a8, 0x1, 4),
    (0x7b0, 0x101, 4),
    (0x8b4, 0x1000000, 4),
    (0x8c4, 0x10000, 4),
    (0x8c8, 0x1000000, 4),
    (0x944, 0x4000, 4),
)
# What each --backend-encoder-field override replaced, so the attempt record says which value the
# run departed from rather than only which one it used.
ENCODER_FIELD_BEFORE = [None]
# The context identifier the shim uses for its own work.
SHIM_CONTEXT_ID = 1
# (device address, bytes) for exactly what a graft wrote, so a run can ask afterwards which of it
# firmware changed. Slices rather than whole pages where the graft wrote slices.
GRAFTED_CONTENT = []
# Render-context addresses do not resolve through the firmware root used by CapturedAddressSpace.
# Keep their known physical mappings so verification can still read the exact live pages.
GRAFTED_PHYSICAL_CONTENT = []
RENDER_MAPPING_OVERRIDES = {}
GRAFT_REUSE_ACTIVE_QUEUE = [False]
BACKEND_FIRMWARE_GRAFTS = []
# A convergence graft which must land after replayed device control and
# immediately before first work.  Kept as a callback so the existing replay
# function does not acquire another experiment-only parameter.
PRE_FIRST_WORK_GRAFT = [None]

REPLAY_FIXED_REGIONS = {
    "gpu-region",
    "gfx-shared-region",
    "gfx-shared-l2-region",
    "gfx-handoff",
}
COPROCESSOR_DATA_REGIONS = {"gfx-data", "gfx1-data"}
# A work ring entry, from the scheduler's own fault registers: it indexes the second
# entry at ring + 0x18 and carries 0x18 as its stride. These rings are 0x6000 apart,
# so they hold 0x400 entries rather than the 0x100 once assumed.
WORK_RING_ENTRY_STRIDE = 0x18

WORK_CHANNEL_NAMES = (
    "TA_0", "3D_0", "CL_0",
    "TA_1", "3D_1", "CL_1",
    "TA_2", "3D_2", "CL_2",
    "TA_3", "3D_3", "CL_3",
)
FIRST_WORK_DIRECT_POINTER_OFFSETS = {
    "TA_0": (0x10, 0x20, 0x28, 0x30),
    "3D_0": (0x20, 0x28, 0x30, 0x38),
}
DEFAULT_SNAPSHOT = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "initdata_pre_submit_all_uat_roots_v2_20260724_150935"
)
DEFAULT_OUTPUT = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")


def selected_first_work_name(channel_name):
    """Map the builder's canonical TA_0/3D_0 names onto one channel pair."""
    unit = int(getattr(args, "first_work_channel_pair", 0))
    if channel_name == "TA_0":
        return "TA_%d" % unit
    if channel_name == "3D_0":
        return "3D_%d" % unit
    return channel_name


def selected_first_work_index(pair_index):
    """Return the channel-table index for pair-relative TA=0 or 3D=1."""
    unit = int(getattr(args, "first_work_channel_pair", 0))
    return unit * 3 + int(pair_index)


def parse_dva_span(value):
    """Parse DVA=LENGTH for a read-only dump at an arbitrary device address."""
    dva, _, raw = value.partition("=")
    if not raw:
        raise argparse.ArgumentTypeError("expected DVA=LENGTH, got %r" % value)
    return int(dva, 0), int(raw, 0)


def parse_dva_value(value):
    """Parse DVA=VALUE for a u32 write at an arbitrary device address."""
    dva, _, raw = value.partition("=")
    if not raw:
        raise argparse.ArgumentTypeError("expected DVA=VALUE, got %r" % value)
    return int(dva, 0), int(raw, 0)


def parse_dva_offset_length(value):
    """Parse page-aligned DVA+OFFSET=LENGTH for a firmware-page graft."""
    location, separator, raw_length = value.partition("=")
    raw_dva, offset_separator, raw_offset = location.partition("+")
    if not separator or not offset_separator or not raw_offset or not raw_length:
        raise argparse.ArgumentTypeError(
            "expected DVA+OFFSET=LENGTH, got %r" % value)
    try:
        dva = int(raw_dva, 0)
        offset = int(raw_offset, 0)
        length = int(raw_length, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "invalid DVA+OFFSET=LENGTH %r: %s" % (value, error)) from error
    if dva & (PAGE_SIZE - 1):
        raise argparse.ArgumentTypeError(
            "firmware graft DVA must be page aligned, got %#x" % dva)
    if offset < 0 or length <= 0 or offset + length > PAGE_SIZE:
        raise argparse.ArgumentTypeError(
            "firmware graft span %#x+%#x exceeds one %#x-byte page" %
            (offset, length, PAGE_SIZE))
    return dva, offset, length


def parse_dva_copy_length(value):
    """Parse SOURCE_DVA:DESTINATION_DVA=LENGTH for an explicit graft copy."""
    locations, separator, raw_length = value.partition("=")
    raw_source, destination_separator, raw_destination = locations.partition(":")
    if (not separator or not destination_separator
            or not raw_destination or not raw_length):
        raise argparse.ArgumentTypeError(
            "expected SOURCE_DVA:DESTINATION_DVA=LENGTH, got %r" % value)
    try:
        source = int(raw_source, 0)
        destination = int(raw_destination, 0)
        length = int(raw_length, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "invalid SOURCE_DVA:DESTINATION_DVA=LENGTH %r: %s" %
            (value, error)) from error
    if length <= 0:
        raise argparse.ArgumentTypeError(
            "firmware object-copy length must be positive")
    return source, destination, length


def parse_dva_path(value):
    """Parse DESTINATION_DVA=FILE for an explicit post-lifecycle object copy."""
    raw_destination, separator, raw_path = value.partition("=")
    if not separator or not raw_path:
        raise argparse.ArgumentTypeError(
            "expected DESTINATION_DVA=FILE, got %r" % value)
    try:
        destination = int(raw_destination, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "invalid destination DVA in %r: %s" % (value, error)) from error
    return destination, pathlib.Path(raw_path)


def backend_bound_object_pointer_offsets(submission, length):
    """Embedded address fields to retain during a scalar-only object graft."""
    if length == submission.ARRAY_A_RECORDS * submission.ARRAY_A_STRIDE:
        return tuple(
            index * submission.ARRAY_A_STRIDE
            for index in range(submission.ARRAY_A_RECORDS)
        )
    if length == submission.ARRAY_B_RECORDS * submission.ARRAY_B_STRIDE:
        return tuple(
            offset
            for index in range(submission.ARRAY_B_RECORDS)
            for offset in (
                index * submission.ARRAY_B_STRIDE
                + submission.ARRAY_B_SLOT_OFFSET,
                index * submission.ARRAY_B_STRIDE
                + submission.ARRAY_B_SHARED_OFFSET,
            )
        )
    if length == submission.SHARED_OBJECT_SIZE:
        return tuple(submission.SHARED_OBJECT_POINTER_OFFSETS)
    return ()


def preserve_backend_bound_object_pointers(
        address_space, backend, firmware_copies, file_copies):
    """Save replay-world pointer identity before explicit object transplants."""
    plans = [
        (raw_destination, length, "firmware object")
        for _raw_source, raw_destination, length in firmware_copies
    ]
    for raw_destination, path in file_copies:
        try:
            length = path.stat().st_size
        except OSError as error:
            raise RuntimeError(
                "cannot stat source object file %s: %s" % (path, error)
            ) from error
        plans.append((raw_destination, length, str(path)))

    preserved = []
    seen = set()
    for raw_destination, length, source in plans:
        destination = address_space.normalize(raw_destination)
        offsets = backend_bound_object_pointer_offsets(
            backend.submission, length
        )
        if not offsets:
            print(
                "  pointer-preserving graft has no layout for %#x-byte "
                "object at %#x (%s)" % (length, destination, source)
            )
        for offset in offsets:
            address = destination + offset
            if address in seen:
                raise RuntimeError(
                    "overlapping preserved object pointer at %#x" % address
                )
            seen.add(address)
            preserved.append({
                "address": address,
                "object_dva": destination,
                "offset": offset,
                "value": address_space.read(address, 8),
            })
    print(
        "Preserved %d replay-world embedded pointer(s) across %d object(s)"
        % (len(preserved), len(plans))
    )
    return preserved


def restore_backend_bound_object_pointers(address_space, preserved):
    """Restore pointer identity after source scalar bytes have been installed."""
    for record in preserved:
        address_space.write(record["address"], record["value"])
    if preserved:
        u.inst("dsb sy")
    result = {
        "preserved_object_pointers": [
            {
                "address": record["address"],
                "object_dva": record["object_dva"],
                "offset": record["offset"],
                "value": struct.unpack("<Q", record["value"])[0],
            }
            for record in preserved
        ]
    }
    BACKEND_FIRMWARE_GRAFTS.append(result)
    print(
        "Restored %d replay-world embedded pointer(s) after object graft"
        % len(preserved)
    )
    return result


def copy_backend_object_files(address_space, copies):
    """Install explicit source-object artifacts after lifecycle preparation."""
    if not copies:
        return None
    records = []
    for raw_destination, path in copies:
        destination = address_space.normalize(raw_destination)
        body = path.read_bytes()
        if not body:
            raise RuntimeError("source object file %s is empty" % path)
        before = address_space.read(destination, len(body))
        address_space.write(destination, body)
        records.append({
            "file": str(path),
            "destination_dva": destination,
            "length": len(body),
            "different_bytes": sum(a != b for a, b in zip(before, body)),
        })
    u.inst("dsb sy")
    result = {"object_files": records}
    BACKEND_FIRMWARE_GRAFTS.append(result)
    print(
        "Backend copied %d explicit source object file(s), %d bytes "
        "different" % (
            len(records),
            sum(record["different_bytes"] for record in records),
        )
    )
    for record in records:
        print(
            "  %s -> %#x, %#x bytes, %d differing" % (
                record["file"], record["destination_dva"],
                record["length"], record["different_bytes"],
            )
        )
    return result


def copy_backend_source_firmware_objects(
        address_space, directory, copies):
    """Copy explicit source-world object ranges after lifecycle preparation."""
    if not copies:
        return None
    directory = pathlib.Path(directory)
    metadata = json.loads((directory / "manifest.json").read_text())
    if metadata.get("format") != \
            "m1n1-t8140-g17p-live-source-firmware-pages-v1":
        raise RuntimeError(
            "unsupported source firmware-page format %r" %
            metadata.get("format"))
    page_size = int(metadata["page_size"])
    if page_size != PAGE_SIZE:
        raise RuntimeError(
            "source firmware pages are %#x bytes, expected %#x" %
            (page_size, PAGE_SIZE))
    raw = (directory / metadata.get("binary", "pages.bin")).read_bytes()
    pages = {
        address_space.normalize(int(record["dva"])): record
        for record in metadata["pages"]
    }

    def source_bytes(address, length):
        result = bytearray()
        cursor = address_space.normalize(address)
        remaining = length
        while remaining:
            page = cursor & ~(PAGE_SIZE - 1)
            record = pages.get(page)
            if record is None:
                raise RuntimeError(
                    "source firmware object copy needs absent page %#x" % page)
            within = cursor - page
            take = min(remaining, PAGE_SIZE - within)
            capture_offset = int(record["capture_offset"]) + within
            result.extend(raw[capture_offset:capture_offset + take])
            cursor += take
            remaining -= take
        if len(result) != length:
            raise RuntimeError("truncated source firmware object copy")
        return bytes(result)

    records = []
    for raw_source, raw_destination, length in copies:
        source = address_space.normalize(raw_source)
        destination = address_space.normalize(raw_destination)
        body = source_bytes(source, length)
        before = address_space.read(destination, length)
        address_space.write(destination, body)
        records.append({
            "source_dva": source,
            "destination_dva": destination,
            "length": length,
            "different_bytes": sum(a != b for a, b in zip(before, body)),
        })
    u.inst("dsb sy")
    result = {
        "source": str(directory),
        "object_copies": records,
    }
    BACKEND_FIRMWARE_GRAFTS.append(result)
    print(
        "Backend copied %d explicit source firmware object(s), %d bytes "
        "different" % (
            len(records),
            sum(record["different_bytes"] for record in records),
        )
    )
    for record in records:
        print(
            "  %#x -> %#x, %#x bytes, %d differing" % (
                record["source_dva"], record["destination_dva"],
                record["length"], record["different_bytes"],
            )
        )
    return result


def graft_backend_source_firmware(
        address_space, manifest, directory, page_slice,
        protected_addresses=(), byte_spans=()):
    """Replace a bounded DVA slice with one live source world's page bytes."""
    directory = pathlib.Path(directory)
    metadata = json.loads((directory / "manifest.json").read_text())
    if metadata.get("format") != \
            "m1n1-t8140-g17p-live-source-firmware-pages-v1":
        raise RuntimeError(
            "unsupported source firmware-page format %r" %
            metadata.get("format"))
    page_size = int(metadata["page_size"])
    if page_size != PAGE_SIZE:
        raise RuntimeError(
            "source firmware pages are %#x bytes, expected %#x" %
            (page_size, PAGE_SIZE))
    raw = (directory / metadata.get("binary", "pages.bin")).read_bytes()
    available = sorted(metadata["pages"], key=lambda item: int(item["dva"]))

    protected = set()
    protected_reasons = {}

    def protect(address, label):
        page = address_space.normalize(int(address)) & ~(PAGE_SIZE - 1)
        protected.add(page)
        protected_reasons.setdefault(page, []).append(label)

    built = BACKEND_BUILT[0]
    if built is not None:
        allocator = built.get("allocator_object")
        if allocator is not None:
            for record in allocator.pages:
                protect(record[0], "backend allocator")

        # Fixed native-array placement means these records need not come from
        # the backend allocator.  They are still source-built command state,
        # and replacing a whole page containing one with the other world's
        # unused/zero page destroys the experiment before firmware sees it.
        # Preserve every generated descriptor/optional/event page; the graft
        # is intended to vary the surrounding replay lifecycle state.
        pairs = [built.get("pair"), built.get("publish_pair")]
        pairs.extend(built.get("publish_pairs") or [])
        for pair_index, pair in enumerate(pairs):
            if not pair:
                continue
            for kind in ("tiling", "fragment"):
                for item_index, address in enumerate(pair.get(kind) or ()):
                    protect(
                        address,
                        "generated pair %d %s item %d" %
                        (pair_index, kind, item_index),
                    )
        for address in built.get("bound_addresses") or ():
            protect(address, "bound render object")
        for context_index, context in enumerate(
                built.get("fresh_queue_contexts") or ()):
            for kind in ("tiling", "fragment"):
                metadata = context.get(kind) or {}
                if metadata.get("scratch"):
                    protect(
                        metadata["scratch"],
                        "queue-context scratch %d %s" %
                        (context_index, kind),
                    )
    for address, label in protected_addresses:
        if address:
            protect(address, label)

    candidates = []
    skipped_unmapped = []
    for record in available:
        dva = address_space.normalize(int(record["dva"])) & ~(PAGE_SIZE - 1)
        if dva in protected:
            continue
        try:
            address_space.read(dva, PAGE_SIZE)
        except RuntimeError:
            skipped_unmapped.append(dva)
            continue
        offset = int(record["capture_offset"])
        body = raw[offset:offset + PAGE_SIZE]
        if len(body) != PAGE_SIZE:
            raise RuntimeError(
                "truncated source firmware page at DVA %#x" % dva)
        captured = read_snapshot_dva_bytes(
            manifest, SNAPSHOT_RAM[0], dva, PAGE_SIZE)
        if body == captured:
            continue
        candidates.append((dva, body, int(record["nonzero_bytes"])))

    first, last = page_slice
    if last is None:
        last = len(candidates)
    if first < 0 or first > last or last > len(candidates):
        raise RuntimeError(
            "backend firmware graft slice %d:%d exceeds %d candidates" %
            (first, last, len(candidates)))
    selected = candidates[first:last]
    spans_by_page = {}
    for raw_dva, offset, length in byte_spans:
        dva = address_space.normalize(raw_dva)
        spans_by_page.setdefault(dva, []).append((offset, length))
    selected_dvas = {dva for dva, _body, _nonzero in selected}
    missing_span_pages = sorted(set(spans_by_page) - selected_dvas)
    if missing_span_pages:
        raise RuntimeError(
            "backend firmware graft span page(s) are not in selected candidate "
            "slice %d:%d: %s" % (
                first, last,
                ", ".join("%#x" % dva for dva in missing_span_pages)))

    changed = []
    for dva, body, nonzero in selected:
        before = address_space.read(dva, PAGE_SIZE)
        after = bytearray(before)
        if byte_spans:
            spans = spans_by_page.get(dva, [])
        else:
            spans = [(0, PAGE_SIZE)]
        if not byte_spans:
            after[:] = body
        else:
            for offset, length in spans:
                after[offset:offset + length] = body[offset:offset + length]
        address_space.write(dva, bytes(after))
        changed.append({
            "dva": dva,
            "nonzero_bytes": nonzero,
            "different_bytes": sum(a != b for a, b in zip(before, after)),
            "spans": [[offset, length] for offset, length in spans],
        })
    u.inst("dsb sy")
    result = {
        "source": str(directory),
        "candidate_pages": len(candidates),
        "protected_pages": len(protected),
        "protected": {
            "%#x" % page: reasons
            for page, reasons in sorted(protected_reasons.items())
        },
        "unmapped_pages": skipped_unmapped,
        "slice": [first, last],
        "byte_spans": [
            {"dva": address_space.normalize(dva),
             "offset": offset, "length": length}
            for dva, offset, length in byte_spans
        ],
        "pages": changed,
    }
    BACKEND_FIRMWARE_GRAFTS.append(result)
    print(
        "Backend grafted source firmware page slice %d:%d: %d/%d pages, "
        "%d protected, %d absent" % (
            first, last, len(selected), len(candidates), len(protected),
            len(skipped_unmapped)))
    if selected:
        print(
            "  source firmware DVA range %#x..%#x, %d differing bytes" % (
                selected[0][0], selected[-1][0],
                sum(item["different_bytes"] for item in changed)))
    return result


def load_backend_package():
    """Load the DRM backend's modules without importing the m1n1.agx package.

    That package's __init__ pulls in version-dependent construct definitions which raise when no
    version key is set, and this harness sets none. The backend and the two modules it uses are
    dependency-free, but they use relative imports, so a synthetic package is needed rather than
    loading each file on its own.
    """
    import importlib.util
    import types

    directory = pathlib.Path(__file__).resolve().parents[1] / "m1n1" / "agx"
    package = types.ModuleType("g17pbackend")
    package.__path__ = [str(directory)]
    sys.modules["g17pbackend"] = package
    for name in ("g17p", "g17p_submission", "g17p_render", "g17p_encoder",
                 "g17p_compute", "g17p_backend", "g17p_shim"):
        spec = importlib.util.spec_from_file_location(
            "g17pbackend." + name, directory / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules["g17pbackend." + name] = module
        setattr(package, name, module)
        spec.loader.exec_module(module)
    return sys.modules["g17pbackend.g17p_backend"]


class BackendRenderContext:
    """The little the front end's translation needs from a context: an allocator and a base.

    The shim's own context owns a UAT and a heap this harness does not have, and the translation
    only ever asks it for objects and for the render context's base address, so this supplies
    exactly that rather than standing up the real thing.
    """

    class _Objects:
        def __init__(self, allocator):
            self.allocator = allocator

        def new(self, size, name="object"):
            address = self.allocator.alloc(size, name)
            self.allocator.write(address, bytes(size))
            return type("Allocated", (), {"_addr": address,
                                          "push": lambda s, data, a=address,
                                          alloc=self.allocator: alloc.write(a, data)})()

    def __init__(self, allocator, pipeline_base):
        self.gobj = self._Objects(allocator)
        self.pipeline_base = pipeline_base


def read_snapshot_bytes(manifest, ram, dva, length):
    """Bytes at a device address in the snapshot, for objects the harness only reads."""
    out = bytearray()
    cursor = int(dva)
    remaining = int(length)
    while remaining > 0:
        page = cursor & ~(PAGE_SIZE - 1)
        mapping = render_context_mapping(manifest, page)
        blob_index = int(mapping["blob_index"])
        data = ram[blob_index * PAGE_SIZE:(blob_index + 1) * PAGE_SIZE]
        start = cursor & (PAGE_SIZE - 1)
        take = min(remaining, PAGE_SIZE - start)
        out += data[start:start + take]
        cursor += take
        remaining -= take
    return bytes(out)


class BackendAllocator:
    """A bump allocator over fresh firmware-context pages, for the backend to build into.

    The backend asks for small objects; the harness can only install whole pages, and only before
    firmware starts, because the leaves go into the table images that the restore writes out. So
    pages are taken as needed and carved up, and every write goes straight to physical memory rather
    than through an address space that is not live yet.
    """

    def __init__(self, manifest, table_pages, source_dva, relocations,
                 direct_space=None, fixed_allocations=None):
        self.manifest = manifest
        self.table_pages = table_pages
        self.source_dva = source_dva
        self.relocations = relocations
        self.pages = []
        self.reserved = []
        self.cursor = 0
        self.limit = 0
        self.base = 0
        self.direct_space = direct_space
        self.fixed_allocations = {
            str(name): list(addresses)
            for name, addresses in (fixed_allocations or {}).items()
        }
        self.fixed_used = []

    def reserve(self, count):
        """Map spare heap pages while the world is still being built.

        A page mapped once firmware is running never reaches the UAT, because the leaves go into the
        table images the restore writes out. So anything a publication allocates later has to come
        out of pages reserved before that point, which is what per-submission allocation needs.
        """
        for _ in range(int(count)):
            mapping = map_built_page(
                self.manifest, self.table_pages, self.source_dva,
                b"\0" * PAGE_SIZE, "backend-reserve-%d" % len(self.reserved))
            self.relocations.append(mapping)
            self.reserved.append(
                (int(mapping["dva"]), int(mapping["relocated_pa"])))

    def _new_page(self):
        if self.reserved:
            dva, pa = self.reserved.pop(0)
            self.pages.append((dva, pa))
            self.base = dva
            self.cursor = 0
            self.limit = PAGE_SIZE
            return {"dva": dva, "relocated_pa": pa}
        mapping = map_built_page(
            self.manifest, self.table_pages, self.source_dva,
            b"\0" * PAGE_SIZE, "backend-heap-%d" % len(self.pages))
        self.relocations.append(mapping)
        self.pages.append((int(mapping["dva"]), int(mapping["relocated_pa"])))
        self.base = int(mapping["dva"])
        self.cursor = 0
        self.limit = PAGE_SIZE
        return mapping

    def alloc(self, size, name="object"):
        size = int(size)
        fixed = self.fixed_allocations.get(str(name))
        if fixed:
            address = fixed.pop(0)
            if address is not None:
                address = int(address)
                self.fixed_used.append(
                    {"name": str(name), "dva": address, "size": size})
                return address
        if size > PAGE_SIZE:
            raise RuntimeError("backend asked for %d bytes, larger than a page" % size)
        aligned = (self.cursor + 0x3f) & ~0x3f
        if not self.pages or aligned + size > self.limit:
            self._new_page()
            aligned = 0
        self.cursor = aligned + size
        return self.base + aligned

    def write(self, dva, data):
        """Write through the physical alias, since these pages are not live yet."""
        for page_dva, page_pa in self.pages:
            if page_dva <= dva < page_dva + PAGE_SIZE:
                iface.writemem(page_pa + (dva - page_dva), bytes(data))
                p.dc_civac(page_pa, PAGE_SIZE)
                return
        if self.direct_space is not None:
            self.direct_space.write(dva, bytes(data))
            return
        raise RuntimeError("write to %#x is outside the backend's own pages" % dva)

    def summary(self):
        return {"pages": [{"dva": dva, "pa": pa} for dva, pa in self.pages],
                "fixed": list(self.fixed_used),
                "bytes_used": (len(self.pages) - 1) * PAGE_SIZE + self.cursor
                if self.pages else 0}


class BackendRenderAllocator:
    """Allocate whole pages in the context-1 render address space.

    Work descriptors and their support records live in the firmware context, but
    the register programs name render-context objects. The first backend command
    buffer test used :class:`BackendAllocator` for both and therefore put the
    generated render objects behind the wrong UAT root. Keep the two heaps
    separate so hardware can actually follow the generated register values.
    """

    def __init__(
        self,
        manifest,
        table_pages,
        source_dva,
        relocations,
        fixed_dvas=None,
        source_dvas=None,
        alias_source_names=None,
    ):
        self.manifest = manifest
        self.table_pages = table_pages
        self.source_dva = int(source_dva)
        self.relocations = relocations
        self.fixed_dvas = dict(fixed_dvas or {})
        self.source_dvas = dict(source_dvas or {})
        self.alias_source_names = set(alias_source_names or ())
        self.pages = []
        self.object_dvas = {}
        self.object_sizes = {}

    def alloc(self, size, name="object"):
        size = int(size)
        target_dva = self.fixed_dvas.pop(name, None)
        source_dva = int(self.source_dvas.get(name, self.source_dva))
        object_offset = (
            int(target_dva) if target_dva is not None else source_dva
        ) & (PAGE_SIZE - 1)
        page_count = (object_offset + size + PAGE_SIZE - 1) // PAGE_SIZE
        object_dva = None
        first_page_dva = None
        remaining = size

        if target_dva is None:
            mappings = map_built_context_pages(
                self.manifest,
                self.table_pages,
                source_dva,
                page_count,
                "backend-render-" + name,
                1,
                0,
                alias_source_pages=name in self.alias_source_names,
            )
        else:
            mappings = []
            for page_index in range(page_count):
                suffix = "" if page_index == 0 else "-%d" % page_index
                mappings.append(replace_context_page(
                    self.manifest,
                    self.table_pages,
                    int(target_dva) + page_index * PAGE_SIZE,
                    bytes(PAGE_SIZE),
                    "backend-render-fixed-" + name + suffix,
                    1,
                    0,
                ))

        for page_index, mapping in enumerate(mappings):
            page_dva = int(mapping["dva"]) & ~(PAGE_SIZE - 1)
            if object_dva is None:
                object_dva = page_dva + object_offset
                first_page_dva = page_dva
            elif page_dva != first_page_dva + page_index * PAGE_SIZE:
                raise RuntimeError(
                    "render backend could not allocate contiguous leaves for %s"
                    % name
                )

            mapping["object_dva"] = object_dva
            mapping["dva"] = page_dva
            self.relocations.append(mapping)
            pa = int(mapping["relocated_pa"])
            page_capacity = PAGE_SIZE - object_offset if page_index == 0 else PAGE_SIZE
            segment_size = min(remaining, page_capacity)
            remaining -= segment_size
            self.pages.append((page_dva, pa, name, segment_size))
            RENDER_MAPPING_OVERRIDES[page_dva] = pa

        self.object_dvas[name] = object_dva
        self.object_sizes[name] = size
        return object_dva

    def write(self, dva, data):
        current = int(dva)
        remaining = memoryview(bytes(data))
        while remaining:
            for page_dva, page_pa, _name, _size in self.pages:
                if not page_dva <= current < page_dva + PAGE_SIZE:
                    continue
                offset = current - page_dva
                count = min(len(remaining), PAGE_SIZE - offset)
                iface.writemem(page_pa + offset, bytes(remaining[:count]))
                p.dc_civac(page_pa, PAGE_SIZE)
                current += count
                remaining = remaining[count:]
                break
            else:
                raise RuntimeError(
                    "render write to %#x is outside the backend's render pages"
                    % current
                )

    def page_named(self, name):
        for dva, pa, candidate, _segment_size in self.pages:
            if candidate == name:
                return {
                    "dva": self.object_dvas[candidate],
                    "page_dva": dva,
                    "pa": pa,
                    "size": self.object_sizes[candidate],
                }
        raise RuntimeError("render allocator has no object named %s" % name)

    def summary(self):
        return {
            "pages": [
                {
                    "dva": self.object_dvas[name],
                    "page_dva": dva,
                    "pa": pa,
                    "name": name,
                    "size": size,
                }
                for dva, pa, name, size in self.pages
            ],
            "bytes_used": sum(self.object_sizes.values()),
        }


def report_model_against_capture(label, body, captured, model_bytes):
    """Say where the model's descriptor differs from the one the snapshot holds.

    Every gate in this project checks the model against a first submission's descriptors. A world
    captured later has its own, and the model reproducing one says nothing about the other. Where
    they differ is where the model has fixed something a host varies.
    """
    limit = min(model_bytes, len(captured))
    diffs = [offset for offset in range(0, limit, 4)
             if bytes(body[offset:offset + 4]) != captured[offset:offset + 4]]
    if not diffs:
        print("  %s model matches the captured descriptor over %#x bytes"
              % (label, limit))
        return
    print("  %s model differs from the captured descriptor at %d of %d words"
          % (label, len(diffs), limit // 4))
    for offset in diffs[:24]:
        print("    +%#05x  model %08x  captured %08x"
              % (offset, struct.unpack_from("<I", bytes(body), offset)[0],
                 struct.unpack_from("<I", captured, offset)[0]))
    if len(diffs) > 24:
        print("    ... and %d more" % (len(diffs) - 24))


def copy_captured_words(label, body, captured, model_bytes):
    """Take named words from the captured descriptor into the built one.

    The model leaves some words zero that a host populates once it has been running. Copying one is
    a way to ask whether it matters, without claiming to know what it means.
    """
    for kind, offset in args.build_descriptor_copy_word:
        if kind != label or offset + 4 > min(model_bytes, len(captured)):
            continue
        before = struct.unpack_from("<I", bytes(body), offset)[0]
        value = struct.unpack_from("<I", captured, offset)[0]
        struct.pack_into("<I", body, offset, value)
        print("  %s descriptor +%#05x taken from the capture: %08x -> %08x"
              % (label, offset, before, value))


def deferred_redirect(fn, *fn_args, **fn_kwargs):
    """Apply a first-work redirect now, or after the post-control overlay when there is one."""
    if args.post_control_overlay:
        DEFERRED_REDIRECTS.append((fn, fn_args, fn_kwargs))
        return {"deferred_until_after_overlay": True}
    return fn(*fn_args, **fn_kwargs)


def apply_deferred_redirects():
    """Run the redirects the overlay had to come first for."""
    if not DEFERRED_REDIRECTS:
        return []
    applied = []
    for fn, fn_args, fn_kwargs in DEFERRED_REDIRECTS:
        applied.append(fn(*fn_args, **fn_kwargs))
    print("Applied %d first-work redirects after the post-control overlay"
          % len(applied))
    DEFERRED_REDIRECTS.clear()
    return applied


def control_channel_tick(asces, address_space, manifest, init_message, count, start):
    """Publish opcode-0x2e device-control entries and report whether firmware takes them.

    A booted host publishes these continuously while it submits work. Whether a replayed firmware
    consumes them is a property of the control channel alone, so this needs no queued work and can
    be run on a world that performed control itself as well as on one that resumed a completed one.
    """
    backend = load_backend_package()
    initdata_dva = canonicalize(
        int(init_message) & ((1 << 44) - 1), int(manifest["vaddr_shift"]))
    channels = backend.G17PChannels(
        lambda addr, size: address_space.read(addr, size), initdata_dva)
    control = channels.entries[12]
    print("Device-control channel ring %#x" % control["ring_addr"])
    # What this world's own opening sequence holds, so it can be compared against a guest's.
    for index in range(7):
        entry = address_space.read(control["ring_addr"] + index * 0x40, 0x40)
        print("  control entry %d: %s" % (index, entry.hex(" ", 8)))
    custom = (bytes.fromhex(args.backend_control_entry_hex.replace(" ", ""))
              if args.backend_control_entry_hex else None)
    if custom is not None and len(custom) != 0x40:
        raise SystemExit("a device-control entry is 0x40 bytes, got %#x" % len(custom))
    # A guest's ring has exactly one 0x2e between its two 0x20 entries, so a custom entry is
    # published after the ticks rather than instead of them. Publishing a 0x20 straight after a
    # 0x20 is an order no host uses.
    if args.backend_control_opcode_scan:
        # Firmware states that the bound parameter-buffer state must be unbound before a different
        # one is bound, so an unbind exists. It is not 0x16, 0x20 or 0x2e, which are the opening and
        # the two this record knows. Opcodes are cheap to try one at a time: an accepted one is a
        # candidate, and a crash ends the run and is itself a fact about that opcode.
        first, _, last = args.backend_control_opcode_scan.partition(":")
        opcodes = range(int(first, 0), int(last or first, 0) + 1)
        results = []
        for opcode in opcodes:
            counters = channels.counters(control)
            producer = counters[2]
            body = bytearray(0x40)
            struct.pack_into("<II", body, 0, opcode, start + len(results))
            address_space.write(control["ring_addr"] + producer * 0x40, bytes(body))
            address_space.write(control["state_addrs"][2],
                                struct.pack("<I", producer + 1))
            asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
            after = counters
            for _ in range(20):
                after = channels.counters(control)
                if after[0] > counters[0]:
                    break
            taken = after[0] > counters[0]
            results.append((opcode, taken))
            print("  control opcode %#04x at index %d: %s -> %s  %s"
                  % (opcode, producer, counters, after,
                     "CONSUMED" if taken else "not consumed"))
        return channels.counters(control)

    plan = [None] * count + ([custom] if custom is not None else [])
    for tick, body_override in enumerate(plan):
        counters = channels.counters(control)
        producer = counters[2]
        if body_override is not None:
            body = bytearray(body_override)
        else:
            body = bytearray(0x40)
            struct.pack_into("<II", body, 0, 0x2e, start + tick)
        address_space.write(control["ring_addr"] + producer * 0x40, bytes(body))
        address_space.write(control["state_addrs"][2],
                            struct.pack("<I", producer + 1))
        asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
        for _ in range(20):
            after = channels.counters(control)
            if after[0] > counters[0]:
                break
        print("  control tick %d at index %d: counters %s -> %s%s"
              % (start + tick, producer, counters, after,
                 "  CONSUMED" if after[0] > counters[0] else "  not consumed"))
    return channels.counters(control)


def dump_backend_pre_notify(
    address_space,
    backend,
    pair,
    queue_records,
    queue_context,
    staged,
    fresh_index,
    published_group,
):
    """Save the generated work and transport closure immediately before its kick.

    This deliberately follows pointers out of the work that will actually be
    published.  A fixed-address dump silently compares different array slots
    when one side is a native/source submission and the other is a replay-built
    fresh item; named objects plus their DVAs let the offline comparison account
    for that relocation.
    """
    requested = args.backend_dump_pre_notify
    if requested is None:
        return None
    outdir = pathlib.Path(requested)
    if int(args.backend_fresh_item_count) > 1:
        outdir = outdir / ("item_%04d" % (fresh_index + 1))
    outdir.mkdir(parents=True, exist_ok=False)

    ranges = []

    def save(name, address, size):
        address = int(address or 0)
        size = int(size)
        record = {"name": name, "dva": address, "size": size}
        if not address:
            record["error"] = "null address"
        else:
            try:
                body = address_space.read(address, size)
                filename = "%s_%016x.bin" % (name, address)
                (outdir / filename).write_bytes(body)
                record["file"] = filename
                record["sha256"] = hashlib.sha256(body).hexdigest()
            except Exception as exc:  # noqa: BLE001
                record["error"] = str(exc)
        ranges.append(record)

    submission = backend.submission
    for kind in ("tiling", "fragment"):
        descriptor, optional, event = pair[kind]
        save(
            "%s_descriptor" % kind,
            descriptor,
            backend.G17PWorkBuilder.BODY_STRIDE[kind],
        )
        save("%s_optional" % kind, optional, submission.OPTIONAL_ITEM_SIZE)
        save("%s_event" % kind, event, submission.EVENT_RECORD_SIZE)

        optional_body = address_space.read(
            optional, submission.OPTIONAL_ITEM_SIZE
        )
        for role, offset in submission.OPTIONAL_ITEM_POINTER_OFFSETS.items():
            pointer = struct.unpack_from("<Q", optional_body, offset)[0]
            if not pointer:
                continue
            # These support pointers all name compact objects living in a
            # firmware page.  Saving the page preserves neighboring lifecycle
            # fields without pretending we know the compact object's extent.
            save(
                "%s_%s_page" % (kind, role),
                pointer & ~(PAGE_SIZE - 1),
                PAGE_SIZE,
            )
            if role == "shared_control":
                support = address_space.read(pointer, 0x80)
                inner = struct.unpack_from("<Q", support, 0x4c)[0]
                if inner:
                    save(
                        "%s_shared_control_inner_page" % kind,
                        inner & ~(PAGE_SIZE - 1),
                        PAGE_SIZE,
                    )

        queue_name = "TA_0" if kind == "tiling" else "3D_0"
        queue = queue_records[queue_name]["queue"]
        save("%s_queue" % kind, queue.address, backend.g17p.QUEUE_RECORD_STRIDE)
        save(
            "%s_queue_pointers" % kind,
            queue.pointers_addr,
            backend.g17p.QUEUE_PTR_BLOCK_SIZE,
        )
        save("%s_item_ring" % kind, queue.item_ring, 0x100)
        save(
            "%s_job_list" % kind,
            queue.job_list_addr,
            backend.g17p.JOB_LIST_SIZE,
        )
        entry = queue_records[queue_name]["entry"]
        save("%s_channel_ring" % kind, entry["ring_addr"], 0x100)

        if queue_context:
            metadata = queue_context[kind]
            target = (
                int(metadata["scratch"])
                + submission.QUEUE_CONTEXT_ITEM_BASE
                + int(metadata["item_index"])
                * submission.QUEUE_CONTEXT_ITEM_STRIDE
            )
            save(
                "%s_queue_context_item_page" % kind,
                target & ~(PAGE_SIZE - 1),
                PAGE_SIZE,
            )

    # Both descriptor halves name the same parameter-buffer graph.  Following
    # the tiling pointer block is enough and avoids duplicate closure files.
    descriptor = pair["tiling"][0]
    layout = submission.DESCRIPTOR_LAYOUT["tiling"]
    cursor = layout["pointers"]
    objects = [struct.unpack("<Q", address_space.read(descriptor + cursor, 8))[0]]
    cursor += 8 + layout["pointer_gap"]
    for _index in range(3):
        objects.append(
            struct.unpack("<Q", address_space.read(descriptor + cursor, 8))[0]
        )
        cursor += 8
    record_a, packed_shared, record_b, zero_shared = objects
    save("bound_record_a", record_a, submission.ARRAY_A_STRIDE)
    save("bound_packed_shared", packed_shared, submission.SHARED_OBJECT_SIZE)
    save("bound_record_b", record_b, submission.ARRAY_B_STRIDE)
    save("bound_zero_shared", zero_shared, submission.ZERO_SHARED_OBJECT_SIZE)

    packed = address_space.read(packed_shared, submission.SHARED_OBJECT_SIZE)
    leaf_addresses = {
        name: struct.unpack_from("<Q", packed, offset)[0]
        for name, offset in zip(
            ("primary_index", "secondary_index", "shared_slots", "flag"),
            submission.SHARED_OBJECT_POINTER_OFFSETS,
        )
    }
    leaf_addresses["pool_a_slots"] = struct.unpack(
        "<Q", address_space.read(record_a, 8)
    )[0]
    leaf_addresses["pool_b_slots"] = struct.unpack(
        "<Q",
        address_space.read(record_b + submission.ARRAY_B_SLOT_OFFSET, 8),
    )[0]
    for name, address in leaf_addresses.items():
        save("bound_leaf_%s" % name, address & ~(PAGE_SIZE - 1), PAGE_SIZE)

    save("channel_control", CHANNEL_CONTROL_DVA, PAGE_SIZE)
    save("current_jobs", 0xFFFFFC20C07D0000, 0x80)
    manifest = {
        "format": "g17p-backend-replay-pre-notify-v1",
        "fresh_index": int(fresh_index),
        "published_group": int(published_group),
        "pair": {
            kind: [int(value) for value in pair[kind]]
            for kind in ("tiling", "fragment")
        },
        "staged": staged,
        "ranges": ranges,
    }
    (outdir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print("Saved backend pre-notify closure -> %s" % outdir)
    return outdir


def backend_publish(
    asces,
    address_space,
    manifest,
    init_message,
    timeout,
    group_number,
    notify=True,
    fresh_index=0,
):
    """Publish one group through the DRM backend's own code, on live firmware.

    Everything the backend does here is its own: it reads the channel table out of the live
    descriptor, finds the queues, and runs its publication sequence. The harness supplies only the
    read, write and doorbell primitives. This is the first time that code has driven hardware, and
    the point is to find out whether the path the backend implements behaves as the replay's
    hand-written one does.
    """
    backend = load_backend_package()
    initdata_dva = canonicalize(
        int(init_message) & ((1 << 44) - 1), int(manifest["vaddr_shift"]))

    def read(addr, size):
        return address_space.read(addr, size)

    def write(addr, data):
        address_space.write(addr, data)

    def doorbell():
        asces[0].send(0x0083000000000000, ASCMessage1(EP=0x21))

    channels = backend.G17PChannels(read, initdata_dva)
    named = [entry for entry in channels.entries if entry["name"]]
    print("Backend read the channel table: %d entries, %d named work channels"
          % (len(channels.entries), len(named)))

    # Report credits are split counter objects, not ordinary channel triples.
    # Each state pointer is the AP-owned acknowledgement and its +0x20 peer is
    # firmware's producer.  Both accelerator instances contribute credits and
    # the shared admission generation eventually wraps, so service both roots
    # before every publication even though an unchanged counter is a no-op.
    acknowledged_reports = []
    for instance, root in (
        ("primary", initdata_dva),
        ("secondary", canonicalize(
            initdata_dva + 0x8000, int(manifest["vaddr_shift"])
        )),
    ):
        report_channels = backend.G17PChannels(read, root)
        for report_index in backend.g17p.REPORT_CHANNEL_INDICES:
            report = report_channels.entries[report_index]
            for state_index in backend.g17p.REPORT_STATE_INDICES:
                host = int(report["state_addrs"][state_index])
                if not host:
                    continue
                peer = host + backend.g17p.REPORT_PEER_OFFSET
                before = read_dva_u32(address_space, host)
                produced = read_dva_u32(address_space, peer)
                if before == produced:
                    continue
                write_dva_u32(address_space, host, produced)
                acknowledged_reports.append(
                    (instance, report_index, state_index, before, produced)
                )
    print("Backend returned %d changed report credit(s): %s"
          % (len(acknowledged_reports), acknowledged_reports))

    if args.backend_channel_pair:
        # Only the first work on a channel has ever been seen to execute, and the pairs past unit 0
        # are untouched in every capture: their counters read zero. Publishing onto one makes this
        # host's group that channel's first work rather than unit 0's second. The entries are renamed
        # so the whole publish path, which names TA_0 and 3D_0 throughout, drives the chosen pair.
        unit = int(args.backend_channel_pair)
        # A virgin channel's ring is empty, so its slot names no queue and the discovery below has
        # nothing to read. Take the queue addresses unit 0 was given at init as the template, so a
        # created queue can be placed in the same array.
        for template_name in ("TA_0", "3D_0"):
            template_entry = channels.by_name(template_name)
            template_slot = read(template_entry["ring_addr"],
                                 backend.g17p.RING_SLOT_SIZE)
            TEMPLATE_QUEUE[template_name] = struct.unpack_from(
                "<Q", template_slot, backend.g17p.RING_SLOT_QUEUE_PTR)[0]
        print("Template queues from unit 0: %s"
              % {k: "%#x" % v for k, v in TEMPLATE_QUEUE.items()})
        renames = {"TA_0": "TA_%d" % unit, "3D_0": "3D_%d" % unit,
                   "TA_%d" % unit: "TA_0", "3D_%d" % unit: "3D_0"}
        for entry in channels.entries:
            if entry["name"] in renames:
                entry["name"] = renames[entry["name"]]
        print("Publishing on work channel pair %d, whose counters are %s"
              % (unit, channels.counters(channels.by_name("TA_0"))))

    def dump_requested_spans(label):
        for dump_addr, dump_length in args.dump_dva:
            try:
                body = read(dump_addr, dump_length)
            except Exception as error:  # noqa: BLE001
                print("  dump %#x %s unreadable: %s" % (dump_addr, label, error))
                continue
            print("  dump %#x %s (%d bytes):" % (dump_addr, label, dump_length))
            for offset in range(0, len(body), 0x20):
                print("    +%#05x  %s"
                      % (offset, body[offset:offset + 0x20].hex(" ", 8)))

    # A plain read of any device address, for looking at a structure whose shape is still open.
    for dump_addr, dump_length in args.dump_dva:
        try:
            body = read(dump_addr, dump_length)
        except Exception as error:  # noqa: BLE001
            print("  dump %#x unreadable: %s" % (dump_addr, error))
            continue
        print("  dump %#x (%d bytes):" % (dump_addr, dump_length))
        for offset in range(0, len(body), 0x20):
            print("    +%#05x  %s"
                  % (offset, body[offset:offset + 0x20].hex(" ", 8)))

    # A published job is linked into the scheduler's list and never runs, so what else firmware is
    # talking to matters. The entries past the twelve work channels have no established role, and
    # their counters say which of them are live at all.
    if args.backend_dump_channels:
        for index, entry in enumerate(channels.entries):
            try:
                counters = [read_dva_u32(address_space, addr)
                            for addr in entry["state_addrs"]]
            except Exception as error:  # noqa: BLE001
                counters = "unreadable: %s" % error
            # The counters are read two ways in this harness, once from these three addresses and
            # once from a 0x40-aligned block at offsets 0, 0x10 and 0x20. Those agree only when the
            # three are 0x10 apart, so print them and let the channel say whether they are.
            print("  channel %2d %-6s ring %#014x counters %s state %s"
                  % (index, entry["name"] or "-", entry["ring_addr"], counters,
                     ["%#x" % addr for addr in entry["state_addrs"]]))
        # The entries past the work channels have counters that do not look like a host producing
        # work, so read what is actually in their rings. A firmware-to-host channel carrying
        # undrained messages is a firmware asking for something nobody answered.
        for index in args.backend_dump_channel_ring:
            entry = channels.entries[index]
            if not entry["ring_addr"]:
                print("  channel %d has no ring" % index)
                continue
            body = read(entry["ring_addr"], 0x180)
            print("  channel %d ring %#x:" % (index, entry["ring_addr"]))
            for offset in range(0, len(body), 0x20):
                chunk = body[offset:offset + 0x20]
                if any(chunk):
                    print("    +%#05x  %s" % (offset, chunk.hex(" ", 8)))

    submitter = backend.G17PSubmitter(read, write, doorbell, channels)
    results = {}
    for name in ("TA_0", "3D_0"):
        channel_name = selected_first_work_name(name)
        entry = channels.by_name(channel_name)
        if entry is None:
            raise RuntimeError(
                "the backend did not find channel %s" % channel_name)
        # The queue's address lives in the ring slot, which is how the shim reaches it too. Slot zero
        # names the queue a host opened first, and a channel carries several: in captured worlds the
        # host's later work goes to a second queue announced from a later slot. Reading slot zero
        # unconditionally is right only in a world captured before any submission.
        queue_slot = args.backend_queue_slot
        slot = read(entry["ring_addr"] + queue_slot * backend.g17p.RING_SLOT_SIZE,
                    backend.g17p.RING_SLOT_SIZE)
        queue_addr = struct.unpack_from(
            "<Q", slot, backend.g17p.RING_SLOT_QUEUE_PTR)[0]
        if not queue_addr and name in TEMPLATE_QUEUE:
            # A virgin channel names no queue. Stand in the queue unit 0 was given, which the
            # create-queue step below then replaces with one of its own in the same array.
            queue_addr = TEMPLATE_QUEUE[name]
            print("  %s names no queue; using unit 0's %#x as the template"
                  % (name, queue_addr))
        # The slot also carries the queue's index on the queue grid. This was hardcoded to zero
        # for both channels, which is right for whichever queue sits at grid index zero and wrong
        # for any other, and a slot naming the wrong grid index points firmware at another
        # channel's queue.
        flags = backend.g17p.decode_slot_flags(
            struct.unpack_from("<I", slot, backend.g17p.RING_SLOT_FLAGS_HEAD)[0])
        queue = backend.G17PQueue(read, queue_addr, flags["queue_index"])
        indices = queue.indices()
        results[name] = {"entry": entry, "queue": queue, "indices": dict(indices)}
        print("  %s ring %#x queue %#x grid index %d head %d first_submit %s indices %s"
              % (channel_name, entry["ring_addr"], queue.address, flags["queue_index"],
                 flags["head"], flags["first_submit"], dict(indices)))

    if (args.backend_graft_firmware_pages is not None
            and fresh_index == 0 and not BACKEND_FIRMWARE_GRAFTS):
        transport_protected = []
        for name in ("TA_0", "3D_0"):
            record = results[name]
            entry = record["entry"]
            queue = record["queue"]
            transport_protected.append(
                (entry["ring_addr"], "%s channel ring" % name)
            )
            transport_protected.extend(
                (address, "%s channel counter" % name)
                for address in entry["state_addrs"]
            )
            for address, label in (
                (queue.address, "queue record"),
                (queue.pointers_addr, "queue pointer block"),
                (queue.item_ring, "queue item ring"),
                (queue.job_list_addr, "paired queue job list"),
            ):
                transport_protected.append(
                    (address, "%s %s" % (name, label))
                )
            context = struct.unpack(
                "<Q",
                read(
                    queue.address + backend.g17p.QUEUE_CONTEXT_ADDR,
                    8,
                ),
            )[0]
            transport_protected.append(
                (context, "%s queue context" % name)
            )
        graft_backend_source_firmware(
            address_space,
            manifest,
            args.backend_graft_firmware_pages,
            args.backend_graft_firmware_page_slice,
            transport_protected,
            args.backend_graft_firmware_byte_span,
        )

    if args.backend_doorbell_only:
        # Whether the publication's writes are what stop firmware servicing anything, or its doorbell
        # on its own does. Rings the work doorbell with nothing staged and leaves the control tick to
        # report whether firmware is still alive to anything but the work ring.
        print("Ringing the work doorbell with nothing staged")
        submitter.notify()
        if args.backend_control_tick:
            control_channel_tick(
                asces, address_space, manifest, init_message,
                args.backend_control_tick, args.backend_control_tick_start)
        return {"backend": backend, "channels": channels, "submitter": submitter,
                "queues": results, "initdata_dva": initdata_dva}

    if BACKEND_BUILT[0] is not None:
        publish_pairs = BACKEND_BUILT[0].get("publish_pairs") or []
        queue_contexts = BACKEND_BUILT[0].get("fresh_queue_contexts") or []
        if publish_pairs:
            if fresh_index < 0 or fresh_index >= len(publish_pairs):
                raise RuntimeError(
                    "fresh publication index %d is outside %d built items"
                    % (fresh_index, len(publish_pairs))
                )
            pair = publish_pairs[fresh_index]
            queue_context = queue_contexts[fresh_index]
            print(
                "Publishing fresh item %d of %d"
                % (fresh_index + 1, len(publish_pairs))
            )
            deferred_items = BACKEND_BUILT[0].get(
                "deferred_item_payloads"
            ) or []
            if fresh_index < len(deferred_items):
                materialization = deferred_items[fresh_index]
                if materialization:
                    for address, payload in materialization:
                        write(address, payload)
                    print(
                        "  materialized %d completion-gated item span(s)"
                        % len(materialization)
                    )
            if args.backend_recycle_submission_graph and fresh_index > 0:
                generation_builder = BACKEND_BUILT[0].get("builder_object")
                if generation_builder is None:
                    raise RuntimeError(
                        "submission-graph recycling has no live builder"
                    )
                # The preceding call returned only after every cleared
                # attachment was physically repopulated.  At that point both
                # queues are complete, but firmware can leave their shared
                # intrusive scheduler head linked to the retired Pool-A
                # record.  Rebuilding that record while it is still linked
                # makes the scheduler follow stale linkage.  Physical output
                # is the semantic fence that makes resetting the list safe.
                reset_job_lists = set()
                for name in ("TA_0", "3D_0"):
                    job_list = int(results[name]["queue"].job_list_addr)
                    if not job_list or job_list in reset_job_lists:
                        continue
                    write(job_list, backend.g17p.build_job_list(job_list))
                    reset_job_lists.add(job_list)
                generation_pair = int(
                    queue_context["tiling"]["pair"]
                )
                generation_builder.queue_pair = generation_pair
                generation_builder.tiling.queue_pair = generation_pair
                generation_builder.fragment.queue_pair = generation_pair
                rebuilt = generation_builder.rebuild_submission_graph()
                for kind, work_builder in (
                    ("tiling", generation_builder.tiling),
                    ("fragment", generation_builder.fragment),
                ):
                    status_base = work_builder.status_base
                    if status_base is None:
                        status_base = (
                            backend.G17PWorkBuilder.PAIR_STATUS_BASES[kind][
                                generation_pair
                            ]
                        )
                    write(status_base, bytes(0x40))
                print(
                    "  reset %d semantically completed scheduler list(s), "
                    "rebuilt quiesced graph generation in place at pools "
                    "%#x/%#x as pair %d, and reset local status"
                    % (
                        len(reset_job_lists),
                        rebuilt["pools"][0],
                        rebuilt["pools"][1],
                        generation_pair,
                    )
                )
        else:
            pair = BACKEND_BUILT[0].get("publish_pair") or BACKEND_BUILT[0]["pair"]
            queue_context = BACKEND_BUILT[0].get("fresh_queue_context")
            if BACKEND_BUILT[0].get("publish_pair"):
                print("Publishing the second item, not the one that became the first work")
        if queue_context:
            for name, kind in (("TA_0", "tiling"), ("3D_0", "fragment")):
                metadata = queue_context[kind]
                queue = results[name]["queue"]
                item_index = int(metadata["item_index"])
                body = backend.submission.build_queue_context_item(
                    kind,
                    descriptor=metadata["descriptor"],
                    queue=queue.address,
                    pair=metadata["pair"],
                    item_index=item_index,
                    context_id=metadata["context_id"],
                    grid_index=queue.grid_index,
                )
                target = (
                    int(metadata["scratch"])
                    + backend.submission.QUEUE_CONTEXT_ITEM_BASE
                    + item_index
                    * backend.submission.QUEUE_CONTEXT_ITEM_STRIDE
                )
                write(target, body)
                print(
                    "  wrote fresh %s queue-context item %d at %#x "
                    "for descriptor %#x, queue %#x"
                    % (
                        kind,
                        item_index,
                        target,
                        metadata["descriptor"],
                        queue.address,
                    )
                )
            # Reproduce the host-owned final pre-doorbell lifecycle state for
            # pair 2's next native array slot.  The captured first item has its
            # selected scheduler slot at 2, Pool-B's publication marker at 1,
            # the shared inner sequence at 2, and the leaf flag at 1.  A second
            # item advances those same resources to 2/1/4/2 respectively.
            tiling_descriptor = pair["tiling"][0]
            record_a = struct.unpack(
                "<Q", read(tiling_descriptor + 0x10, 8)
            )[0]
            record_b = struct.unpack(
                "<Q", read(tiling_descriptor + 0x28, 8)
            )[0]
            scheduler_slot = struct.unpack("<Q", read(record_a, 8))[0]
            work_ordinal = backend.submission.descriptor_work_ordinal(item_index)
            write(record_a + 0x08, struct.pack("<I", work_ordinal))
            write(record_a + 0x10, struct.pack("<I", 0x50))
            write(scheduler_slot, struct.pack("<I", 2))
            write(record_b + 0x4c, struct.pack("<I", 1))

            packed_shared = struct.unpack(
                "<Q", read(tiling_descriptor + 0x20, 8)
            )[0]
            shared_slots = struct.unpack(
                "<Q", read(packed_shared + 0x4c, 8)
            )[0]
            leaf_flag = struct.unpack(
                "<Q", read(packed_shared + 0x64, 8)
            )[0]
            shared_count = struct.unpack("<I", read(shared_slots, 4))[0]
            write(shared_slots + 0x04, struct.pack("<I", shared_count))
            if item_index >= 2:
                # The native runtime marks the shared leaf bundle retired
                # after the preceding generated group.  The mark persists for
                # later groups on the same graph.  Item 2 is the first place
                # this transition can matter, and is the observed boundary.
                write(shared_slots + 0x40, struct.pack("<I", 0x13))
            write(shared_slots + 0x60, struct.pack("<I", 1))
            write(leaf_flag, struct.pack("<I", item_index + 1))

            shared_control = struct.unpack(
                "<Q", read(pair["tiling"][1] + 0x36, 8)
            )[0]
            inner_sequence = struct.unpack(
                "<Q", read(shared_control + 0x4c, 8)
            )[0]
            inner_target = 2 * (item_index + 1)
            write(inner_sequence, struct.pack("<I", inner_target))
            print(
                "  prepared native scheduler record %#x/slot %#x, "
                "Pool-B %#x, shared sequence %#x=%d, leaf flag %#x=%d"
                % (
                    record_a,
                    scheduler_slot,
                    record_b,
                    inner_sequence,
                    inner_target,
                    leaf_flag,
                    item_index + 1,
                )
            )
        preserved_object_pointers = []
        if (args.backend_graft_preserve_object_pointers
                and fresh_index == 0):
            preserved_object_pointers = preserve_backend_bound_object_pointers(
                address_space,
                backend,
                args.backend_graft_firmware_object,
                args.backend_graft_object_file,
            )
        if (args.backend_graft_firmware_object
                and fresh_index == 0):
            if args.backend_graft_firmware_pages is None:
                raise RuntimeError(
                    "explicit firmware object copies require "
                    "--backend-graft-firmware-pages")
            copy_backend_source_firmware_objects(
                address_space,
                args.backend_graft_firmware_pages,
                args.backend_graft_firmware_object,
            )
        if args.backend_graft_object_file and fresh_index == 0:
            copy_backend_object_files(
                address_space,
                args.backend_graft_object_file,
            )
        if (args.backend_graft_preserve_object_pointers
                and fresh_index == 0):
            restore_backend_bound_object_pointers(
                address_space, preserved_object_pointers
            )
        if args.backend_publish_captured_items:
            # The items the captured world already has on its queue are work firmware executed as
            # part of a host's own stream. Publishing those rather than anything this host built
            # separates a submission that is wrong from a publication that cannot rasterise.
            pair = {}
            for name, kind in (("TA_0", "tiling"), ("3D_0", "fragment")):
                queue = results[name]["queue"]
                write_index = queue.indices()["write"]
                first = write_index - 3
                if first < 0:
                    raise RuntimeError(
                        "%s has no complete captured group to republish" % name)
                addresses = list(struct.unpack(
                    "<3Q", read(queue.item_ring
                                + first * backend.g17p.ITEM_RING_ENTRY_SIZE, 24)))
                pair[kind] = addresses
                print("  republishing %s captured group at entries %d..%d: %s"
                      % (name, first, first + 2,
                         ["%#x" % value for value in addresses]))
        # Firmware binds parameter-buffer state before any work runs and refuses a
        # different one, and the snapshot does not hold the pages that state lives in.
        # A live sweep of the queue records and the pages around the bound objects is
        # the way to find what names it.
        bound = BACKEND_BUILT[0].get("bound_addresses") or []
        if bound:
            print("Looking for what names the bound parameter-buffer state")
            wanted = {int(value) for value in bound}
            pages = sorted({value & ~(PAGE_SIZE - 1) for value in wanted})
            searched = 0
            for name in ("TA_0", "3D_0"):
                queue = results[name]["queue"]
                for label, addr in (("queue record", queue.address),
                                    ("pointer block", queue.pointers_addr),
                                    ("job list", queue.job_list_addr)):
                    if not addr:
                        continue
                    try:
                        blob = read(addr & ~(PAGE_SIZE - 1), PAGE_SIZE)
                    except Exception as error:
                        print("  %s %s unreadable: %s" % (name, label, error))
                        continue
                    searched += 1
                    hits = [offset for offset in range(0, PAGE_SIZE - 8, 4)
                            if struct.unpack_from("<Q", blob, offset)[0] in wanted]
                    if hits:
                        print("  %s %s page %#x references it at %s"
                              % (name, label, addr & ~(PAGE_SIZE - 1),
                                 ["+%#x" % offset for offset in hits[:8]]))
            # The remaining candidates after the config objects, the queue structures and
            # the work descriptors: the initialization descriptor's own data region and the
            # channel state blocks, both of which this host still restores from a capture.
            root = read(initdata_dva, 0x100)
            candidates = [("initdata root", initdata_dva)]
            for label, offset in (("data region", 0x20),
                                  ("channel state a", 0xa8),
                                  ("channel state b", 0xb0),
                                  ("main config", 0x18)):
                value = struct.unpack_from("<Q", root, offset)[0]
                if value:
                    candidates.append(("%s (root +%#x)" % (label, offset), value))
            for label, addr in candidates:
                try:
                    blob = read(addr & ~(PAGE_SIZE - 1), PAGE_SIZE)
                except Exception as error:
                    print("  %s at %#x unreadable: %s" % (label, addr, error))
                    continue
                searched += 1
                hits = [offset for offset in range(0, PAGE_SIZE - 8, 4)
                        if struct.unpack_from("<Q", blob, offset)[0] in wanted]
                print("  %-28s %#014x  %s"
                      % (label, addr,
                         "references it at %s" % ["+%#x" % o for o in hits[:8]]
                         if hits else "no reference"))

            for page in pages:
                try:
                    blob = read(page, PAGE_SIZE)
                except Exception:
                    continue
                searched += 1
                nonzero = sum(1 for byte in blob if byte)
                print("  bound page %#014x holds %d non-zero bytes" % (page, nonzero))
            print("  searched %d pages" % searched)
        # A published item carrying the same register programs as the first work would rewrite
        # identical bytes, so "nothing changed" cannot distinguish an inert publication from a
        # successful re-execution. Clearing an output page first removes that ambiguity: only a
        # publication that actually executes can put the pattern back.
        # The job list is the one queue structure a publication never touches, and this record
        # already notes a queue whose job-list length matched its outstanding work. If firmware
        # schedules from the list rather than from the ring, a publication that leaves it empty
        # would be drained without executing, which is exactly what is observed.
        for name in ("TA_0", "3D_0"):
            queue = results[name]["queue"]
            if not queue.job_list_addr:
                print("  %s has no job list" % name)
                continue
            body = read(queue.job_list_addr, backend.g17p.JOB_LIST_SIZE)
            parsed = backend.g17p.parse_job_list(body, queue.job_list_addr)
            print("  %s job list %#x before publishing: first %#x last %#x empty %s  raw %s"
                  % (name, queue.job_list_addr, parsed["first"], parsed["last"],
                     parsed["empty"], body.hex(" ", 8)))

        # Firmware produces on channels 13 and 14 as it executes. On a host the first counter tracks
        # that producer; here it stays where the snapshot left it while the producer advances, so
        # nothing acknowledges what firmware wrote. A channel nobody drains is a plausible reason for
        # a scheduler to stop after one submission.
        for index in args.backend_ack_firmware_channel:
            entry = channels.entries[index]
            if not entry["state_addrs"][0]:
                continue
            counters = channels.counters(entry)
            write(entry["state_addrs"][0], struct.pack("<I", counters[2]))
            print("  acknowledged channel %d: %s -> first counter %d"
                  % (index, counters, counters[2]))

        cleared_pages = []
        if (args.backend_clear_render_before_publish
                or args.backend_patch_render_u16_before_publish):
            # Render-context pages are not in the firmware address space this backend writes
            # through, so resolve them the way the render watch does.
            render_pages = dict(render_context_pages(manifest))
            render_pages.update(RENDER_MAPPING_OVERRIDES)
            for dva in args.backend_clear_render_before_publish:
                page = int(dva) & ~(PAGE_SIZE - 1)
                pa = render_pages.get(page)
                if pa is None:
                    try:
                        pa = int(render_context_mapping(manifest, page)["pa"])
                    except RuntimeError as error:
                        raise RuntimeError(
                            "render page %#x is not mapped, so it cannot be cleared"
                            % page
                        ) from error
                iface.writemem(pa, bytes(PAGE_SIZE))
                p.dc_civac(pa, PAGE_SIZE)
                cleared_pages.append((page, pa))
                print("Cleared render page %#x (PA %#x) before publishing" % (page, pa))

            for dva, value in args.backend_patch_render_u16_before_publish:
                page = int(dva) & ~(PAGE_SIZE - 1)
                pa = render_pages.get(page)
                if pa is None:
                    try:
                        pa = int(render_context_mapping(manifest, page)["pa"])
                    except RuntimeError as error:
                        raise RuntimeError(
                            "render page %#x is not mapped, so it cannot be patched"
                            % page
                        ) from error
                target = pa + (int(dva) - page)
                before = struct.unpack("<H", iface.readmem(target, 2))[0]
                iface.writemem(target, struct.pack("<H", int(value) & 0xffff))
                p.dc_civac(pa, PAGE_SIZE)
                print("Patched render %#x (PA %#x) half-word %#06x -> %#06x before publishing"
                      % (int(dva), target, before, int(value) & 0xffff))

        # Bracket the publication, since this doorbell is the host's own and a baseline
        # taken here therefore contains whatever the submission does.
        baseline = (scan_render_baseline(manifest, SCAN_RENDER_PREFIX[0])
                    if SCAN_RENDER_PREFIX[0] else None)
        # A live host varies three descriptor fields per submission that this model does not carry:
        # tiling +0x48, fragment +0x40 and fragment +0x90. A generated second submission leaves
        # them at the first submission's values, which the first submission could never reveal.
        PER_SUBMISSION = {"tiling": (0x04, 0x48), "fragment": (0x04, 0x40, 0x90)}
        for kind in ("tiling", "fragment"):
            descriptor = pair[kind][0]
            values = {"+%#04x" % offset:
                      "%08x" % struct.unpack("<I", read(descriptor + offset, 4))[0]
                      for offset in PER_SUBMISSION[kind]}
            print("  published %s descriptor %#x per-submission fields %s"
                  % (kind, descriptor, values))
        # A live host advances a family of register values every submission, most visibly a group
        # that steps by a constant and looks like a bump cursor. Reaching them by register number
        # rather than by descriptor offset keeps this independent of where the array happens to sit.
        REGISTERS_AT = {"tiling": 0x60, "fragment": 0xa0}
        REGISTER_STRIDE = 0xc
        REGISTER_COUNT = {"tiling": 73, "fragment": 89}
        for kind, number, delta in args.backend_publish_register_delta:
            descriptor = pair[kind][0]
            array = read(descriptor + REGISTERS_AT[kind],
                         REGISTER_COUNT[kind] * REGISTER_STRIDE)
            for index in range(REGISTER_COUNT[kind]):
                at = index * REGISTER_STRIDE
                if struct.unpack_from("<I", array, at)[0] != number:
                    continue
                before = struct.unpack_from("<Q", array, at + 4)[0]
                after = (before + delta) & 0xffffffffffffffff
                write(descriptor + REGISTERS_AT[kind] + at + 4,
                      struct.pack("<Q", after))
                print("  %s register %#07x %#018x -> %#018x (%+#x)"
                      % (kind, number, before, after, delta))
                break
            else:
                raise RuntimeError(
                    "the %s program has no register %#x" % (kind, number))

        for kind, offset, value in args.backend_publish_descriptor_u32:
            if kind not in pair:
                raise RuntimeError("kind must be tiling or fragment, got %r" % kind)
            descriptor = pair[kind][0]
            before = struct.unpack("<I", read(descriptor + offset, 4))[0]
            write(descriptor + offset, struct.pack("<I", value & 0xffffffff))
            print("  patched %s descriptor +%#04x %08x -> %08x"
                  % (kind, offset, before, value & 0xffffffff))

        # Every pool A record a live host has in use carries these words; the captured array carries
        # them only on record zero, because only record zero had been used when it was taken. So a
        # host writes them when it takes a record for a submission, and this host never did. This
        # has to happen before staging, since firmware reads the record when it links the job.
        if args.backend_fill_job_record:
            for kind, pointer_at in (("tiling", 0x10), ("fragment", 0x20)):
                record = struct.unpack(
                    "<Q", read(pair[kind][0] + pointer_at, 8))[0]
                for offset, value in ((0x0c, args.backend_job_record_0c),
                                      (0x10, 0x50), (0x24, 1), (0xc0, 1)):
                    write(record + offset, struct.pack("<I", value))
                print("  filled %s job record %#x before staging"
                      % (kind, record))

        if args.backend_restore_item_pages:
            # The executed fragment item carries values near the end of its record that a freshly
            # built one has as zero. Those may be firmware's own writes as it retired the work, in
            # which case republishing that item presents work already marked done and firmware is
            # right to retire it without executing. Restoring the item pages to their captured,
            # pre-execution contents tests that directly.
            restored = set()
            for kind in ("tiling", "fragment"):
                for address in pair[kind]:
                    page = int(address) & ~(PAGE_SIZE - 1)
                    if page in restored:
                        continue
                    restored.add(page)
                    try:
                        mapping = selected_mapping_at(manifest, page)
                        blob_index = mapping.get("blob_index")
                        if blob_index is None:
                            raise RuntimeError("not a captured RAM page")
                        start = int(blob_index) * PAGE_SIZE
                        original = SNAPSHOT_RAM[0][start:start + PAGE_SIZE]
                    except Exception as error:  # noqa: BLE001
                        print("  item page %#x not restorable: %s" % (page, error))
                        continue
                    live = read(page, PAGE_SIZE)
                    write(page, original)
                    differing = sum(1 for a, b in zip(live, original) if a != b)
                    print("  restored item page %#x: %d of %d bytes put back"
                          % (page, differing, PAGE_SIZE))

        if args.backend_zero_fragment_tail:
            # The item firmware executed carries values near the end of its record that a fresh one
            # has as zero. If those are firmware's marks from retiring the work, an item still
            # carrying them is work already done, and zeroing them before republishing should let it
            # run again.
            target = pair["fragment"][0]
            start, end = 0x2180, 0x2240
            before = read(target + start, end - start)
            nonzero = sum(1 for i in range(0, len(before), 4)
                          if before[i:i + 4] != b"\0\0\0\0")
            write(target + start, bytes(end - start))
            print("  zeroed fragment tail %#x..%#x at %#x, %d non-zero words cleared"
                  % (start, end, target, nonzero))

        if args.backend_copy_fragment_tail:
            # The executed fragment item carries pointers and counters across the end of its record
            # that the published one has as zero, because the first work's descriptor is built with
            # the captured tail and the backend's is not. Copy that region over so the two groups
            # differ in nothing this comparison can see.
            fragment_queue = results["3D_0"]["queue"]
            served_fragment = struct.unpack(
                "<Q", read(fragment_queue.item_ring, 8))[0]
            published_fragment = pair["fragment"][0]
            start, end = 0x2180, 0x2240
            body = read(served_fragment + start, end - start)
            write(published_fragment + start, body)
            nonzero = sum(1 for i in range(0, len(body), 4)
                          if body[i:i + 4] != b"\0\0\0\0")
            print("  copied fragment tail %#x..%#x from %#x to %#x, %d non-zero words"
                  % (start, end, served_fragment, published_fragment, nonzero))

        if args.backend_restore_bound_objects:
            # This record's own reading of the refusal is that the parameter buffer is bound, filled
            # by the work that binds it, and then refuses to be rebound, so a second submission into
            # an exhausted binding has nothing to draw into. That predicts something cheap: put the
            # bound objects' contents back as they were before any work ran, keeping the addresses so
            # nothing is rebound, and the group that follows should draw.
            bound_now = [int(v, 0) if isinstance(v, str) else int(v)
                         for v in (BACKEND_BUILT[0].get("bound_addresses") or [])]
            if not bound_now:
                raise RuntimeError(
                    "restoring the bound objects needs --backend-reuse-pools, which is what "
                    "records which addresses firmware has bound")
            for address in bound_now:
                page = int(address) & ~(PAGE_SIZE - 1)
                try:
                    mapping = selected_mapping_at(manifest, page)
                    blob_index = mapping.get("blob_index")
                    if blob_index is None:
                        raise RuntimeError("page %#x is not a captured RAM page" % page)
                    start = int(blob_index) * PAGE_SIZE
                    original = SNAPSHOT_RAM[0][start:start + PAGE_SIZE]
                except Exception as error:  # noqa: BLE001
                    print("  bound page %#x not restorable: %s" % (page, error))
                    continue
                live = read(page, PAGE_SIZE)
                write(page, original)
                differing = sum(1 for a, b in zip(live, original) if a != b)
                print("  restored bound page %#x: %d of %d bytes put back"
                      % (page, differing, PAGE_SIZE))

        if args.backend_unbind_opcode is not None:
            # Firmware requires the bound parameter-buffer state to be unbound before a different one
            # is bound, and four opcodes below the opening's are consumed after it. Publish one, then
            # let the publication that follows say whether the binding moved: with the backend's own
            # pools it either still refuses or it does not.
            control = channels.entries[12]
            before = channels.counters(control)
            producer = before[2]
            body = bytearray(0x40)
            struct.pack_into("<II", body, 0, args.backend_unbind_opcode, producer)
            write(control["ring_addr"] + producer * 0x40, bytes(body))
            write(control["state_addrs"][2], struct.pack("<I", producer + 1))
            asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
            after = before
            for _ in range(8):
                after = channels.counters(control)
                if after[0] > before[0]:
                    break
            print("  unbind opcode %#04x at index %d: %s -> %s  %s"
                  % (args.backend_unbind_opcode, producer, before, after,
                     "CONSUMED" if after[0] > before[0] else "not consumed"))

        if args.backend_advance_per_submission:
            # A completed group that draws nothing is one whose body still describes the submission
            # before it. These are the fields a live host advances between successive submissions.
            steps = int(args.backend_advance_per_submission)
            descriptor = pair["tiling"][0]
            for offset, stride, width in PER_SUBMISSION_STRIDES:
                fmt = "<Q" if width == 8 else "<I"
                mask = (1 << (width * 8)) - 1
                before = struct.unpack(fmt, read(descriptor + offset, width))[0]
                after = (before + stride * steps) & mask
                write(descriptor + offset, struct.pack(fmt, after))
                print("  per-submission +%#05x %#x -> %#x" % (offset, before, after))

        for ack_index in (args.backend_ack_firmware_consumer or ()):
            # A firmware-produced channel's first counter is the one that grows with firmware's work,
            # 8 against 202 between a first-submission world and one six submissions in, and its
            # second is world-invariant and far behind. That is the shape of a producer and a consumer
            # the host is meant to advance. The existing acknowledgement writes the first counter to
            # its own value, which is a no-op if that counter is the producer.
            # A live host's queue-window trace shows this channel's third counter tracking its first,
            # 8 against 8 early and 309 against 345 ten submissions in, so the host drains firmware's
            # reports continuously. In a replayed world the third counter is zero against a producer of
            # eight: nothing has ever been consumed. Which counter to move is selectable because an
            # earlier version of this moved the second, which is world-invariant and not a consumer.
            ack_entry = channels.entries[ack_index]
            slot = int(args.backend_ack_firmware_index)
            produced = read_dva_u32(address_space, ack_entry["state_addrs"][0])
            before = read_dva_u32(address_space, ack_entry["state_addrs"][slot])
            write_dva_u32(address_space, ack_entry["state_addrs"][slot], produced)
            print("  channel %d counter %d: %d -> %d (producer %d)"
                  % (ack_index, slot, before, produced, produced))

        if args.backend_create_queue is not None:
            # A host's second submission goes to a queue it creates, at the next free grid index,
            # announced as that queue's first. This host has only ever reused the queue firmware was
            # given at init. A queue record is the array entry plus two pieces of memory it owns, so
            # creating one is copying the template and pointing it at a fresh pointer block and ring.
            allocator = BACKEND_BUILT[0].get("allocator_object")
            if allocator is None:
                raise RuntimeError("creating a queue needs the backend's own allocator")
            base_grid = (
                int(args.backend_create_queue)
                + fresh_index * int(args.backend_created_queue_grid_step)
            )
            recycled = (
                BACKEND_BUILT[0].get("recycled_created_queue")
                if args.backend_recycle_created_queue
                else None
            )
            if recycled is not None:
                if int(recycled["base_grid"]) != base_grid:
                    raise RuntimeError(
                        "recycled queue grid %d does not match requested %d"
                        % (recycled["base_grid"], base_grid)
                    )
                if recycled["context"] is not None:
                    write(recycled["context"], recycled["context_prestate"])
                write(
                    recycled["job_list"],
                    struct.pack("<QQQ", 0, recycled["job_list"], 0),
                )
                for queue_name in ("TA_0", "3D_0"):
                    state = recycled["queues"][queue_name]
                    write(state["target"], state["record_prestate"])
                    write(
                        state["pointers"],
                        bytes(backend.g17p.QUEUE_PTR_BLOCK_SIZE),
                    )
                    write(
                        state["pointers"] + backend.g17p.QUEUE_PTR_RING_SIZE,
                        struct.pack("<I", 0xffffffff),
                    )
                    write(state["ring"], bytes(0x200))
                    results[queue_name]["queue"] = backend.G17PQueue(
                        read, state["target"], state["grid"]
                    )
                print(
                    "  recycled completed queue pair grids %d/%d at %#x/%#x"
                    % (
                        base_grid,
                        base_grid + 1,
                        recycled["queues"]["TA_0"]["target"],
                        recycled["queues"]["3D_0"]["target"],
                    )
                )
                recycled = True
            else:
                recycled = False
            # A queue pair shares one context object and different pairs have different ones: the
            # captures carry `...b8040` on grid 0 and 1 and `...b8000` on grid 2 and 3, on the `0x40`
            # context grid. So the created pair gets one of its own, copied from the template's.
            created_context = None
            context_prestate = None
            if not recycled and not args.backend_share_queue_context:
                template_context = struct.unpack(
                    "<Q", read(results["TA_0"]["queue"].address
                               + backend.g17p.QUEUE_CONTEXT_ADDR, 8))[0]
                created_context = allocator.alloc(
                    backend.g17p.QUEUE_CONTEXT_STRIDE, "queue-%d-context" % base_grid)
                context_body = bytearray(
                    read(template_context, backend.g17p.QUEUE_CONTEXT_STRIDE))
                if args.backend_context_index is not None:
                    # The two context objects a host uses differ at byte 1 of the first word, 0 for
                    # the pair bound at init and 1 for the pair it creates later. An earlier run
                    # patched byte 2, which holds 4 in both and is not the field; that test was void.
                    before_byte = context_body[1]
                    context_body[1] = int(args.backend_context_index) & 0xff
                    print("  context object byte 1 %d -> %d (byte 2 is %d, unchanged)"
                          % (before_byte, context_body[1], context_body[2]))
                context_prestate = bytes(context_body)
                allocator.write(created_context, context_prestate)
                print("  created queue context %#x copied from %#x"
                      % (created_context, template_context))
            # Both halves of every captured render queue pair name one shared
            # intrusive job list.  Allocating one list per queue creates two
            # unrelated scheduler graphs even though the TA/3D event records
            # describe one paired command.
            created_job_list = None
            if not recycled and not args.backend_share_job_list:
                created_job_list = allocator.alloc(
                    0x18, "queue-%d-pair-job-list" % base_grid)
                allocator.write(
                    created_job_list,
                    struct.pack("<QQQ", 0, created_job_list, 0),
                )
                print(
                    "  created queue pair job list %#x" % created_job_list
                )
            if not recycled:
                created_queues = {}
                for position, queue_name in enumerate(("TA_0", "3D_0")):
                    source = results[queue_name]["queue"]
                    grid = base_grid + position
                    if args.backend_allocate_queue_record:
                        target = allocator.alloc(
                            backend.g17p.QUEUE_RECORD_STRIDE,
                            "queue-%d-record" % grid,
                        )
                    else:
                        array_base = (
                            source.address
                            - source.grid_index
                            * backend.g17p.QUEUE_RECORD_STRIDE
                        )
                        target = (
                            array_base
                            + grid * backend.g17p.QUEUE_RECORD_STRIDE
                        )
                    record = bytearray(read(source.address,
                                            backend.g17p.QUEUE_DESCRIPTOR_SIZE))
                    pointers = allocator.alloc(backend.g17p.QUEUE_PTR_BLOCK_SIZE,
                                               "queue-%d-pointers" % grid)
                    ring = allocator.alloc(0x200, "queue-%d-ring" % grid)
                    allocator.write(
                        pointers, bytes(backend.g17p.QUEUE_PTR_BLOCK_SIZE)
                    )
                    allocator.write(ring, bytes(0x200))
                    # All ones in every observed queue's pointer block.
                    allocator.write(
                        pointers + backend.g17p.QUEUE_PTR_RING_SIZE,
                        struct.pack("<I", 0xffffffff),
                    )
                    struct.pack_into(
                        "<Q", record, backend.g17p.QUEUE_POINTERS_ADDR, pointers
                    )
                    struct.pack_into(
                        "<Q", record, backend.g17p.QUEUE_RING_ADDR, ring
                    )
                    if created_job_list is not None:
                        struct.pack_into(
                            "<Q", record, backend.g17p.QUEUE_JOB_LIST_ADDR,
                            created_job_list,
                        )
                        print("  queue grid %d job list %#x"
                              % (grid, created_job_list))
                    if created_context is not None:
                        struct.pack_into(
                            "<Q", record, backend.g17p.QUEUE_CONTEXT_ADDR,
                            created_context,
                        )
                    record_prestate = bytes(record)
                    write(target, record_prestate)
                    results[queue_name]["queue"] = backend.G17PQueue(
                        read, target, grid
                    )
                    created_queues[queue_name] = {
                        "grid": grid,
                        "target": target,
                        "pointers": pointers,
                        "ring": ring,
                        "record_prestate": record_prestate,
                    }
                    print("  created queue grid %d at %#x: pointers %#x ring %#x"
                          % (grid, target, pointers, ring))
                if args.backend_recycle_created_queue:
                    if created_job_list is None:
                        raise RuntimeError(
                            "queue recycling requires a private shared job list"
                        )
                    BACKEND_BUILT[0]["recycled_created_queue"] = {
                        "base_grid": base_grid,
                        "context": created_context,
                        "context_prestate": context_prestate,
                        "job_list": created_job_list,
                        "queues": created_queues,
                    }

            # The locator was initially materialized against the queue named
            # by the channel's current outer slot. A native fresh generation
            # keeps the same logical grid but gives the queue record a new
            # address, so rewrite it only after that address exists.
            if queue_context:
                for queue_name, kind in (
                    ("TA_0", "tiling"),
                    ("3D_0", "fragment"),
                ):
                    metadata = queue_context[kind]
                    queue = results[queue_name]["queue"]
                    item_index = int(metadata["item_index"])
                    body = backend.submission.build_queue_context_item(
                        kind,
                        descriptor=metadata["descriptor"],
                        queue=queue.address,
                        pair=metadata["pair"],
                        item_index=item_index,
                        context_id=metadata["context_id"],
                        grid_index=queue.grid_index,
                    )
                    target = (
                        int(metadata["scratch"])
                        + backend.submission.QUEUE_CONTEXT_ITEM_BASE
                        + item_index
                        * backend.submission.QUEUE_CONTEXT_ITEM_STRIDE
                    )
                    write(target, body)
                    print(
                        "  rebound fresh %s queue-context item %d to "
                        "queue record %#x"
                        % (kind, item_index, queue.address)
                    )

        if args.backend_control_tick_before_publish:
            # A host publishes these continuously while it submits work, and this host's only ticks
            # run after staging. Control is provably still consumed at this point, so this asks
            # whether firmware wants them alongside the publication rather than after it.
            control_channel_tick(
                asces, address_space, manifest, init_message,
                args.backend_control_tick_before_publish,
                args.backend_control_tick_start)

        if args.backend_reset_queue_indices:
            # Whether firmware objects to entries three to five, or to a second group after a
            # completed one wherever it sits. Putting the queue's completion, read and write indices
            # back to zero republishes at entry zero, in the configuration the first work had, and
            # changes nothing else about the publication.
            for reset_name in ("TA_0", "3D_0"):
                reset_queue = results[reset_name]["queue"]
                for offset in (backend.g17p.QUEUE_PTR_DONE,
                               backend.g17p.QUEUE_PTR_READ,
                               backend.g17p.QUEUE_PTR_WRITE):
                    write(reset_queue.pointers_addr + offset, struct.pack("<I", 0))
                print("  reset %s queue indices to zero at %#x"
                      % (reset_name, reset_queue.pointers_addr))

        published_group = (
            group_number + 1
            if args.backend_publish_group_number is None
            else args.backend_publish_group_number + fresh_index
        )
        print("Publishing as group number %d" % published_group)
        staged = {}
        for name, kind in (("TA_0", "tiling"), ("3D_0", "fragment")):
            record = results[name]
            staged[name] = submitter.stage(
                record["entry"], record["queue"], pair[kind], published_group,
                slot=args.backend_publish_slot,
                first_submit=args.backend_publish_first_submit,
                kind=kind,
                in_place=args.backend_publish_in_place,
                announce=not args.backend_skip_publish_announce,
                event_subtype=args.backend_event_subtype,
                event_counter_low=int(args.first_work_channel_pair))
            print("  staged %s at slot %s, write index %s -> %s"
                  % (name, staged[name].get("slot"),
                     staged[name].get("write_before"),
                     staged[name].get("write_after")))
        dump_requested_spans("after staging")
        dump_backend_pre_notify(
            address_space,
            backend,
            pair,
            results,
            queue_context,
            staged,
            fresh_index,
            published_group,
        )
        if not notify:
            # Staged before the first work's doorbell, which is about to be rung and covers both
            # groups. Waiting here would wait for a firmware that has not been woken yet.
            print("Backend staged a paired group before the first work's doorbell")
            # The overlay runs between the backend's allocations and this point, so check that
            # every address the staged group names is still readable rather than assuming it.
            for name, kind in (("TA_0", "tiling"), ("3D_0", "fragment")):
                for position, address in enumerate(pair[kind]):
                    try:
                        head = struct.unpack("<I", read(address, 4))[0]
                        note = "selector %#x" % head
                    except Exception as error:  # noqa: BLE001
                        note = "UNREADABLE: %s" % error
                    print("    staged %s item %d at %#x: %s"
                          % (name, position, address, note))
            return {"backend": backend, "channels": channels, "submitter": submitter,
                    "queues": results, "initdata_dva": initdata_dva}
        if args.backend_control_tick_before_doorbell:
            # A host interleaves device control with its work at about one control doorbell per work
            # doorbell, and the control message frequently comes first: 0x84 0x83 0x84 0x84 0x83 in the
            # sixth-world capture. This host has only ever ticked control after ringing the work
            # doorbell, which is the reverse order.
            control_channel_tick(
                asces, address_space, manifest, init_message,
                args.backend_control_tick_before_doorbell,
                args.backend_control_tick_start)

        submitter.notify()
        print("Backend published a paired group and rang the doorbell")

        if args.backend_reinit_after_publish:
            # Everything that executes was on a queue when firmware started, and nothing published
            # afterwards runs. So send the initialization message again with this host's group already
            # queued, which is the only way to put published work on the before-start side of that
            # line without a reboot.
            reinit = int(init_message)
            print("  re-sending the initdata message %#x with the group queued" % reinit)
            asces[0].send(reinit, ASCMessage1(EP=0x20))
            for _ in range(20):
                pass

        for extra in (args.backend_extra_doorbell or ()):
            # Only the work doorbell has ever been rung after a publication. Firmware also takes
            # 0x84, 0x87 and 0x89 during setup, and a scheduler kick this host has never sent would
            # look exactly like work that is accepted and never run.
            message, _, payload = extra.partition(":")
            word = (int(message, 0) << 48) | int(payload or "0", 0)
            asces[0].send(word, ASCMessage1(EP=0x21))
            print("  rang extra doorbell type %s payload %s -> %#018x"
                  % (message, payload or "0", word))

        for name in ("TA_0", "3D_0"):
            entry = results[name]["entry"]
            expected = read_dva_u32(address_space, entry["state_addrs"][2])
            wait_dva_counters(
                asces, address_space, entry["state_addrs"][:2],
                [expected, expected], timeout, "backend " + name)
        if queue_context:
            # Match the normal post-submit host protocol without waiting for
            # an ASC inbox to become empty.  Event 0x42 can remain asserted
            # while useful work continues, so completion service must always
            # be bounded.  A linked scheduler node is diagnostic state here:
            # hardware has already proved that extra control-done messages do
            # not necessarily unlink a completed second submission.
            asces[0].send(0x0084000000000011, ASCMessage1(EP=0x21))
            event_counts = [0] * len(asces)
            empty_rounds = 0
            for _round in range(16):
                moved = False
                for asc in asces:
                    if asc.has_messages():
                        asc.work()
                        event_counts[asces.index(asc)] += 1
                        moved = True
                if moved:
                    empty_rounds = 0
                else:
                    empty_rounds += 1
                if empty_rounds >= 2:
                    break
            print(
                "  sent control-done and serviced bounded completion events %s"
                % event_counts
            )
        # Acceptance and completion are different signals, and separating them says whether
        # firmware merely took the entries off the ring or reported the work finished.
        for name in ("TA_0", "3D_0"):
            record = results[name]
            indices = record["queue"].indices()
            published = staged[name]
            print("  %s queue indices %s; accepted %s, completed %s"
                  % (name, dict(indices),
                     submitter.accepted(record["entry"], record["queue"], published),
                     submitter.completed(record["entry"], record["queue"], published)))

        # The job list names a pool A record, so the record is the job. The serviced submission uses
        # record 0 of the captured pool and a published one uses a later record, which the captured
        # guest may never have filled in. Compare them.
        if args.backend_dump_pool_records:
            base = BACKEND_BUILT[0].get("bound_addresses") or []
            if base:
                pool_a = int(base[0])
                for index in (0, 1, 2, 3):
                    address = pool_a + index * 0x100
                    body = read(address, 0x100)
                    nonzero = sum(1 for byte in body if byte)
                    print("  pool A record %d at %#x: %d of 256 bytes non-zero"
                          % (index, address, nonzero))
                    if nonzero:
                        for offset in range(0, 0x100, 0x20):
                            chunk = body[offset:offset + 0x20]
                            if any(chunk):
                                print("      +%#04x  %s" % (offset, chunk.hex(" ", 8)))

        # A live host's device-control ring does not stop at the opening sequence. After the three
        # 0x16 entries and the 0x20 that follow them, it publishes opcode 0x2e continuously, each
        # entry carrying an incrementing counter and otherwise zero, interleaved with its work. This
        # host has never published one, so send them the way a host does: entry, producer, doorbell.
        if args.backend_control_tick:
            # The same publication and the same polling the control-only path uses, so a result
            # here and one there mean the same thing.
            control_channel_tick(
                asces, address_space, manifest, init_message,
                args.backend_control_tick, args.backend_control_tick_start)
            job = read(results["TA_0"]["queue"].job_list_addr,
                       backend.g17p.JOB_LIST_SIZE)
            parsed = backend.g17p.parse_job_list(
                job, results["TA_0"]["queue"].job_list_addr)
            print("  after control ticks: job list empty %s" % parsed["empty"])

        # A live host's steady-state traffic on this endpoint is not the work doorbell alone. It
        # interleaves device control, at a constant payload, and a third type this project has never
        # sent. Sending those after a publication is the direct test of whether one of them is what
        # starts a linked job.
        for raw in args.backend_message_after_publish:
            asces[0].send(raw, ASCMessage1(EP=0x21))
            body = read(results["TA_0"]["queue"].job_list_addr,
                        backend.g17p.JOB_LIST_SIZE)
            parsed = backend.g17p.parse_job_list(
                body, results["TA_0"]["queue"].job_list_addr)
            print("  sent %#018x after publishing: job list empty %s"
                  % (raw, parsed["empty"]))

        # Both publication doorbells are rung back to back, before firmware has linked the job. If
        # what starts execution is a notification arriving while a job is already linked, a later
        # ring is a different event from either of those, and nothing else has to change to test it.
        for round_number in range(args.backend_doorbell_after_publish):
            doorbell()
            body = read(results["TA_0"]["queue"].job_list_addr,
                        backend.g17p.JOB_LIST_SIZE)
            parsed = backend.g17p.parse_job_list(
                body, results["TA_0"]["queue"].job_list_addr)
            print("  doorbell after publishing, round %d: job list empty %s"
                  % (round_number + 1, parsed["empty"]))
            if parsed["empty"]:
                break

        # Whether the linked job ever drains separates a job the scheduler is holding from one it
        # will run late. Poll rather than sample once, and say which it was.
        deadline = args.backend_job_list_poll
        queue = results["TA_0"]["queue"]
        if queue.job_list_addr:
            drained_at = None
            for attempt in range(max(1, deadline)):
                body = read(queue.job_list_addr, backend.g17p.JOB_LIST_SIZE)
                parsed = backend.g17p.parse_job_list(body, queue.job_list_addr)
                if parsed["empty"]:
                    drained_at = attempt
                    break
                if attempt == 0 or deadline <= 1:
                    print("  job list after publishing: first %#x last %#x empty %s  raw %s"
                          % (parsed["first"], parsed["last"], parsed["empty"],
                             body.hex(" ", 8)))
            if drained_at is not None:
                print("  job list drained after about %d polls" % drained_at)
            elif deadline > 1:
                print("  job list still holds the job after %d polls" % deadline)
            # Firmware links the job after the doorbell, so anything asked for here is read in the
            # state firmware left it, which the dump taken before staging cannot show.
            dump_requested_spans("after publishing")

        # The work firmware executed and the work it retired without executing are both on this
        # queue, at entries 0..2 and 3..5. Comparing them is the most direct statement of what a
        # published group carries that a serviced one does not.
        if args.backend_compare_published_items:
            for name in ("TA_0", "3D_0"):
                queue = results[name]["queue"]
                ring = queue.item_ring
                addresses = struct.unpack(
                    "<6Q", read(ring, 6 * backend.g17p.ITEM_RING_ENTRY_SIZE))
                print("  %s item ring: %s"
                      % (name, ["%#x" % value for value in addresses]))
                for position in range(3):
                    served, published = addresses[position], addresses[position + 3]
                    if not served or not published:
                        continue
                    # A fixed 0x40 covers each item's header and none of its body, so it can only
                    # ever say the headers match. Compare the whole record instead, sized by the
                    # selector each item carries.
                    try:
                        selector = struct.unpack("<I", read(served, 4))[0]
                        span = item_record_size(selector)
                    except Exception:  # noqa: BLE001
                        span = 0x40
                    a = read(served, span)
                    b = read(published, span)
                    diffs = [off for off in range(0, span, 4)
                             if a[off:off + 4] != b[off:off + 4]]
                    print("    entry %d vs %d: %d of %d words differ"
                          % (position, position + 3, len(diffs), span // 4))
                    for off in diffs:
                        print("      +%#04x  served %08x  published %08x"
                              % (off, struct.unpack_from("<I", a, off)[0],
                                 struct.unpack_from("<I", b, off)[0]))

        # Firmware's scheduler activity is visible on channel 14, which advanced by thirty-eight
        # while it executed the first work. Whether it moves across this publication says whether
        # the scheduler engaged with the published group at all, rather than only accepting it.
        if args.backend_dump_channels:
            report = []
            for index in range(12, 17):
                entry = channels.entries[index]
                if not entry["state_addrs"][0]:
                    continue
                report.append("ch%d=%s" % (index, channels.counters(entry)))
            print("  non-work channels after publishing: %s" % " ".join(report))
            # Firmware produced ten entries on channel 14 while processing this group. Whatever it
            # wrote there is its own account of what it did, which nothing else in this record has.
            for index in args.backend_dump_channel_ring:
                entry = channels.entries[index]
                if not entry["ring_addr"]:
                    continue
                counters = channels.counters(entry)
                body = read(entry["ring_addr"], 0x400)
                print("  channel %d ring after publishing, producer %d:"
                      % (index, counters[2]))
                for offset in range(0, len(body), 0x20):
                    chunk = body[offset:offset + 0x20]
                    if any(chunk):
                        print("    +%#05x  %s" % (offset, chunk.hex(" ", 8)))

        # The watch images are taken before this function runs, so they cannot say what the
        # publication did to a page cleared inside it. Read those pages here instead: they were
        # zeroed moments ago, so any non-zero byte was written by the published submission.
        cleared_nonzero = []
        for page, pa in cleared_pages:
            p.dc_civac(pa, PAGE_SIZE)
            body = bytes(iface.readmem(pa, PAGE_SIZE))
            nonzero = sum(1 for byte in body if byte)
            cleared_nonzero.append((page, nonzero))
            print("  cleared page %#x after publishing: %d non-zero bytes%s"
                  % (page, nonzero,
                     ("  first 32: " + body[:32].hex()) if nonzero else ""))
        missing_outputs = [page for page, nonzero in cleared_nonzero if not nonzero]
        if missing_outputs:
            raise RuntimeError(
                "fresh publication %d completed without repopulating cleared "
                "output page(s): %s"
                % (
                    fresh_index + 1,
                    ", ".join("%#x" % page for page in missing_outputs),
                )
            )
        if cleared_nonzero:
            print(
                "FRESH PARTIAL OUTPUT PASS %d: all %d cleared attachments "
                "were repopulated"
                % (fresh_index + 1, len(cleared_nonzero))
            )

        # One channel accepts and the other does not, and the ring slot is what firmware reads to
        # find the work, so show what is actually in both channels' slots afterwards.
        for name in ("TA_0", "3D_0"):
            entry = results[name]["entry"]
            for slot_index in (0, 1):
                raw = read(entry["ring_addr"]
                           + slot_index * backend.g17p.RING_SLOT_SIZE,
                           backend.g17p.RING_SLOT_SIZE)
                queue_ptr = struct.unpack_from(
                    "<Q", raw, backend.g17p.RING_SLOT_QUEUE_PTR)[0]
                word = struct.unpack_from(
                    "<I", raw, backend.g17p.RING_SLOT_FLAGS_HEAD)[0]
                flags = backend.g17p.decode_slot_flags(word)
                print("  %s slot %d: queue %#x head %d grid %d first_submit %s  raw %s"
                      % (name, slot_index, queue_ptr, flags["head"],
                         flags["queue_index"], flags["first_submit"], raw.hex(" ", 4)))
            print("  %s channel counters %s"
                  % (name, [read_dva_u32(address_space, addr)
                            for addr in entry["state_addrs"]]))

        # What firmware left in the two queue
        # records is the most direct place the difference can show. Report the words that differ
        # between them rather than the whole record, since most of it is the same by construction.
        try:
            blobs = {name: read(results[name]["queue"].address,
                                backend.g17p.QUEUE_DESCRIPTOR_SIZE)
                     for name in ("TA_0", "3D_0")}
            differing = [
                offset for offset in range(0, len(blobs["TA_0"]), 4)
                if blobs["TA_0"][offset:offset + 4] != blobs["3D_0"][offset:offset + 4]]
            print("  queue records differ in %d of %d words"
                  % (len(differing), len(blobs["TA_0"]) // 4))
            for offset in differing:
                print("    +%#04x  TA %08x  3D %08x"
                      % (offset,
                         struct.unpack_from("<I", blobs["TA_0"], offset)[0],
                         struct.unpack_from("<I", blobs["3D_0"], offset)[0]))
            for name in ("TA_0", "3D_0"):
                pointers = read(results[name]["queue"].pointers_addr,
                                backend.g17p.QUEUE_PTR_BLOCK_SIZE)
                print("  %s pointer block %s" % (name, pointers.hex(" ", 4)))
        except Exception as error:  # noqa: BLE001
            print("  queue record comparison failed: %s" % error)
        if baseline is not None:
            scan_render_writes(manifest, baseline, SCAN_RENDER_PREFIX[0])

    return {"backend": backend, "channels": channels, "submitter": submitter,
            "queues": results, "initdata_dva": initdata_dva}


def parse_render_parameter(value):
    """Parse NAME=VALUE for a render-recipe parameter, which may be a size or an address."""
    name, _, raw = value.partition("=")
    if not raw:
        raise argparse.ArgumentTypeError("expected NAME=VALUE, got %r" % value)
    return name.strip(), int(raw, 0)


def parse_structural_tail_range(value):
    """Parse KIND:START:END for a half-open generated-tail splice."""
    try:
        kind, start, end = value.split(":", 2)
        kind = kind.strip().lower()
        if kind not in ("tiling", "fragment"):
            raise ValueError("kind must be tiling or fragment")
        start = int(start, 0)
        end = int(end, 0)
        if start < 0 or end <= start:
            raise ValueError("range must be non-empty and non-negative")
        return kind, start, end
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected KIND:START:END, got %r" % value
        ) from error


def parse_dva_copy(value):
    """Parse SRC:DST:SIZE for a device-address-space copy."""
    try:
        source, destination, size = value.split(":", 2)
        return int(source, 0), int(destination, 0), int(size, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected SRC:DST:SIZE, got %r" % value
        ) from error


def parse_offset_value(value):
    """Parse OFFSET=VALUE for a u32 patch into a copied outer message."""
    offset, _, raw = value.partition("=")
    if not raw:
        raise argparse.ArgumentTypeError("expected OFFSET=VALUE, got %r" % value)
    return int(offset, 0), int(raw, 0)


def parse_publish_descriptor_patch_kindless(value):
    """Parse KIND:OFFSET for a word taken from a captured descriptor."""
    kind, _, offset = value.partition(":")
    if not offset:
        raise argparse.ArgumentTypeError("expected KIND:OFFSET, got %r" % value)
    return kind, int(offset, 0)


def parse_publish_register_delta(value):
    """Parse KIND:REG=DELTA for a published register advance."""
    kind, _, rest = value.partition(":")
    number, _, raw = rest.partition("=")
    if kind not in ("tiling", "fragment") or not raw:
        raise argparse.ArgumentTypeError(
            "expected tiling:REG=DELTA or fragment:REG=DELTA, got %r" % value)
    return kind, int(number, 0), int(raw, 0)


def parse_publish_descriptor_patch(value):
    """Parse KIND:OFFSET=VALUE for a published work descriptor patch."""
    kind, _, rest = value.partition(":")
    offset, _, raw = rest.partition("=")
    if kind not in ("tiling", "fragment") or not raw:
        raise argparse.ArgumentTypeError(
            "expected tiling:OFFSET=VALUE or fragment:OFFSET=VALUE, got %r" % value)
    return kind, int(offset, 0), int(raw, 0)


def parse_encoder_fields(overrides, encoder):
    """Turn NAME=VALUE overrides into keyword arguments for the encoder model.

    Only scalar fields are reachable. A name the model does not carry, or one holding a list of
    bound objects rather than a number, is refused by name: a silent no-op here would look exactly
    like a field that hardware ignores, which is the thing these runs are trying to measure.
    """
    parsed = {}
    for override in overrides:
        name, _, raw = override.partition("=")
        name = name.strip()
        if not raw:
            raise SystemExit("expected NAME=VALUE, got %r" % override)
        if not hasattr(encoder, name):
            raise SystemExit(
                "the tiler stream model has no field %r; it carries %s"
                % (name, ", ".join(sorted(
                    field for field in vars(encoder)
                    if isinstance(getattr(encoder, field), int)))))
        if not isinstance(getattr(encoder, name), int):
            raise SystemExit(
                "%r is not a scalar field, so it cannot be set this way" % name)
        parsed[name] = int(raw, 0)
    return parsed


def parse_first_work_u32_patch(value):
    try:
        channel, offset, replacement = value.split(":", 2)
        offset = int(offset, 0)
        replacement = int(replacement, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected CHANNEL:OFFSET:VALUE"
        ) from error
    if channel not in WORK_CHANNEL_NAMES[:2]:
        raise argparse.ArgumentTypeError(
            "CHANNEL must be TA_0 or 3D_0"
        )
    if offset < 0 or offset > PAGE_SIZE - 4:
        raise argparse.ArgumentTypeError("OFFSET must select one u32 in a page")
    if replacement < 0 or replacement > 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("VALUE must fit in u32")
    return channel, offset, replacement


def parse_first_work_u64_patch(value):
    try:
        channel, offset, replacement = value.split(":", 2)
        offset = int(offset, 0)
        replacement = int(replacement, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected CHANNEL:OFFSET:VALUE"
        ) from error
    if channel not in WORK_CHANNEL_NAMES[:2]:
        raise argparse.ArgumentTypeError(
            "CHANNEL must be TA_0 or 3D_0"
        )
    if offset < 0 or offset > PAGE_SIZE - 8:
        raise argparse.ArgumentTypeError("OFFSET must select one u64 in a page")
    if replacement < 0 or replacement > 0xFFFFFFFFFFFFFFFF:
        raise argparse.ArgumentTypeError("VALUE must fit in u64")
    return channel, offset, replacement


def parse_page_slice(value):
    if value == "all":
        return 0, None
    try:
        first, last = value.split(":", 1)
        first = int(first, 0)
        last = int(last, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected FIRST:LAST or all"
        ) from error
    if first < 0 or last <= first:
        raise argparse.ArgumentTypeError(
            "page slice must satisfy 0 <= FIRST < LAST"
        )
    return first, last


class Tee:
    def __init__(self, *files):
        self.files = files

    def write(self, data):
        for file in self.files:
            file.write(data)
            file.flush()
        return len(data)

    def flush(self):
        for file in self.files:
            file.flush()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replay a captured T8140/G17P firmware initdata image"
    )
    parser.add_argument("--snapshot", type=pathlib.Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument(
        "--restore-coprocessor-data-regions",
        action="store_true",
        help="also restore the captured gfx-data and gfx1-data regions for an "
        "exact late-state positive-control replay",
    )
    parser.add_argument(
        "--post-control-overlay",
        type=pathlib.Path,
        help="after native device-control setup, apply the selected-root memory delta "
        "from this later snapshot while preserving grafted submission objects",
    )
    parser.add_argument("--output-root", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--init-message", type=lambda value: int(value, 0))
    parser.add_argument("--replay-first-work", action="store_true")
    parser.add_argument(
        "--first-work-channel-pair",
        type=int,
        choices=range(4),
        default=0,
        metavar="UNIT",
        help="apply first-work descriptor builders and patches to TA_UNIT/3D_UNIT "
             "instead of the historical pair 0 (default: 0)",
    )
    parser.add_argument(
        "--first-work-descriptor-pair",
        type=int,
        choices=range(4),
        default=None,
        metavar="PAIR",
        help="build descriptor-local pair/grid fields for PAIR while publishing "
             "through --first-work-channel-pair; default: keep them coupled",
    )
    parser.add_argument(
        "--rebuild-compute-work",
        action="store_true",
        help="destroy and reconstruct the pending CL_2 queue and direct work "
        "objects field by field before firmware starts",
    )
    parser.add_argument(
        "--rebuild-compute-client",
        action="store_true",
        help="destroy and reconstruct the pending add3 shader, CDM stream, "
        "resource table, input buffers, and output/robustness pages",
    )
    parser.add_argument(
        "--rebuild-compute-registration",
        action="store_true",
        help="destroy and reconstruct the pending compute operand table, "
        "page lists, blank state/scratch pages, and registered tranches",
    )
    parser.add_argument(
        "--omit-first-optional-item",
        action="store_true",
        help="publish each native first work group as descriptor,event instead of "
        "descriptor,optional,event, updating the queue write index and ring head",
    )
    parser.add_argument(
        "--build-first-optional-items",
        action="store_true",
        help="construct both native first selector-0x0f records from the model on "
        "a new page and redirect the two queue entry-one pointers",
    )
    parser.add_argument(
        "--build-first-event-items",
        action="store_true",
        help="construct both native first selector-0x0e records from the model on "
        "a new page and redirect the two queue entry-two pointers",
    )
    parser.add_argument(
        "--build-shared-descriptor-objects",
        action="store_true",
        help="construct the packed second and zero fourth objects shared by the "
        "first TA/3D descriptor pair at new firmware addresses",
    )
    parser.add_argument(
        "--build-submission-leaf-pages",
        action="store_true",
        help="construct the six index, slot, and flag pages named by the first "
        "descriptor pair and its record pools at new firmware addresses",
    )
    parser.add_argument(
        "--relocate-optional-scratch-alias",
        action="store_true",
        help="copy the page jointly mapped by the first optional records in "
        "context 0 and firmware context 64, install fresh aliases in both roots, "
        "and update the generated records",
    )
    parser.add_argument(
        "--clear-hardware-context-zero",
        action="store_true",
        help="clear the two raw gpu-region context-0 root descriptors after "
             "restoring an otherwise complete snapshot",
    )
    parser.add_argument(
        "--dump-post-ack",
        metavar="DIR",
        help="save this world's top-level descriptor objects after acknowledgement, so a fresh "
             "firmware's output here can be diffed against a fresh firmware's on the cold path. "
             "Comparing either against the capture compares against macOS's firmware instead",
    )
    parser.add_argument(
        "--no-secondary-initdata",
        action="store_true",
        help="do not hand the second instance a descriptor, to find out whether the render "
             "depends on it. The record describes it as a power instance, and an unclocked "
             "accelerator is what the cold path's symptom looks like",
    )
    parser.add_argument(
        "--pre-initdata-delay",
        type=float,
        default=0.0,
        help="wait this many seconds between starting the coprocessors and sending initdata. "
             "The cold-boot path takes a long time there and this one does not; lengthening it "
             "on the world that renders tests whether firmware degrades over that window",
    )
    parser.add_argument(
        "--graft-firmware-pages",
        metavar="DIR",
        help="overwrite captured firmware pages with the cold boot's own content for the same "
             "address, from a directory of <hex dva>.bin files as --dump-post-ack writes. "
             "Convergence from the rendering side: the subset that stops this world rendering "
             "names a page whose content differs and matters",
    )
    parser.add_argument(
        "--graft-after-boot",
        action="store_true",
        help="apply the graft after the coprocessors have started rather than before, which is when "
        "the cold-boot path's own content comes into existence",
    )
    parser.add_argument(
        "--graft-before-first-work",
        action="store_true",
        help="apply the graft after device control has settled and immediately "
             "before the captured first work is published",
    )
    parser.add_argument(
        "--graft-page-slice",
        metavar="FIRST:LAST",
        help="graft only this half-open slice of the directory's pages in address order, for "
             "bisecting which of them matters",
    )
    parser.add_argument(
        "--graft-different-only",
        action="store_true",
        help="before applying --graft-page-slice, retain only source pages "
             "whose bytes differ from the restored snapshot at the same DVA",
    )
    parser.add_argument(
        "--graft-root-index",
        type=lambda value: int(value, 0),
        default=None,
        help="interpret --graft-firmware-pages through this captured root "
             "index instead of the selected firmware root",
    )
    parser.add_argument(
        "--zero-unreachable-firmware-pages",
        action="store_true",
        help="zero every captured page mapped in the firmware root that the descriptor cannot "
             "reach by following pointers, leaving every other root's pages alone. The cold-boot "
             "path has only the reachable graph, so this asks whether the rest of a restored "
             "firmware context is needed for a submission to execute",
    )
    parser.add_argument(
        "--zero-transitive-extra-firmware-pages",
        type=parse_page_slice,
        metavar="FIRST:LAST|all",
        help="after rebuilding pending compute, zero this DVA-ordered slice of "
             "firmware-root pages found only by the byte-granular transitive "
             "pointer scan. Pages reached through modeled initdata fields and "
             "pages containing rebuilt compute objects are retained",
    )
    parser.add_argument(
        "--source-config-snapshot",
        type=pathlib.Path,
        help="pages.json/pages.bin source-built config snapshot used by "
             "--graft-source-config-page",
    )
    parser.add_argument(
        "--graft-source-config-page",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        metavar="DVA",
        help="after compute reconstruction, replace this firmware-root page "
             "with the same DVA from --source-config-snapshot; repeatable",
    )
    parser.add_argument(
        "--graft-all-modeled-source-config-pages",
        action="store_true",
        help="graft the source-config form of every page reached through a "
             "modeled primary or secondary initdata pointer field",
    )
    parser.add_argument(
        "--zero-unreferenced-init-pages",
        action="store_true",
        help="zero captured RAM pages not reached through known primary or "
             "secondary initdata pointer fields",
    )
    parser.add_argument(
        "--unmap-unreferenced-init-pages",
        type=parse_page_slice,
        metavar="FIRST:LAST|all",
        help="zero all captured pages outside the known initdata closure, then "
             "clear this half-open slice of their selected-root leaves in DVA "
             "order. This isolates blank mappings firmware probes after ACK",
    )
    parser.add_argument(
        "--rebuild-descriptor",
        action="store_true",
        help="overwrite the restored descriptor root and hardware-data object "
             "with ones built from the field model in m1n1/agx/g17p_initdata.py",
    )
    parser.add_argument(
        "--zero-opaque-runs",
        type=lambda v: [tuple(int(x, 0) for x in part.split(":"))
                        for part in v.split(",")],
        help="zero only opaque runs in the index ranges FIRST:LAST[,FIRST:LAST], "
             "for bisecting which runs firmware requires",
    )
    parser.add_argument(
        "--zero-opaque-fields",
        action="store_true",
        help="with --rebuild-descriptor, leave the bytes the builder cannot "
             "derive as zero instead of copying them, to test whether firmware "
             "requires them",
    )
    parser.add_argument(
        "--corrupt-render-page",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="relocate this render-context page and fill it with 0xa5, to test whether "
        "the accelerator reads it; repeatable. Needs a control run corrupting an "
        "unrelated page, since a completed submission proves nothing on its own",
    )
    parser.add_argument(
        "--relocate-render-page",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        help="move this render-context page into host memory, keeping its address; "
        "repeatable. Tests whether the accelerator reads render state from memory the "
        "host owns, which the firmware-context relocations cannot show",
    )
    parser.add_argument(
        "--relocate-initdata-page",
        action="store_true",
        help="copy the primary initdata page to host-allocated RAM and repoint its UAT leaf",
    )
    parser.add_argument(
        "--relocate-secondary-initdata-page",
        action="store_true",
        help="copy the secondary initdata page to host-allocated RAM and repoint its UAT leaf",
    )
    parser.add_argument(
        "--relocate-first-work-descriptor-pages",
        action="store_true",
        help="copy the first TA and 3D work-descriptor pages to host RAM and repoint their UAT leaves",
    )
    parser.add_argument(
        "--relocate-first-work-direct-target-pages",
        action="store_true",
        help="copy pages referenced by first TA/3D descriptor headers and repoint their UAT leaves",
    )
    parser.add_argument(
        "--relocate-first-work-support-item-pages",
        action="store_true",
        help="copy the required first TA/3D queue entries one and two and repoint their UAT leaves",
    )
    parser.add_argument(
        "--graft-submission",
        metavar="CLOSURE_DIR",
        help="overwrite the replayed submission with one captured from a guest later in "
        "a boot, matching by device address. Gives a submission that does dependent "
        "work in a context that can be replayed",
    )
    parser.add_argument(
        "--diff-shared-across-work",
        action="store_true",
        help="snapshot the firmware shared regions either side of the work doorbell and report "
        "what changed. Firmware records its own progress there, so this asks whether a "
        "submission that completes leaves any trace at all",
    )
    parser.add_argument(
        "--verify-grafted-after",
        action="store_true",
        help="after the submission is processed, re-read exactly what the graft wrote and report "
        "which of it firmware changed. A working host writes nineteen of a submission's pages; "
        "this asks how many the replay writes",
    )
    parser.add_argument(
        "--poison-render-dva",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        metavar="DVA",
        help="fill this render-context page with 0xa5 after grafting, creating the mapping if "
        "the replayed world lacks it. For pages a submission references that the capture does "
        "not reach, which the grafted-render poison cannot cover; repeatable",
    )
    parser.add_argument(
        "--poison-grafted-render",
        action="store_true",
        help="after grafting, fill every render page the graft created with 0xa5. A completed "
        "submission whose render pages still hold the marker did not write them",
    )
    parser.add_argument(
        "--graft-reset-consumed",
        type=lambda value: int(value, 0),
        default=None,
        metavar="N",
        help="rewind the grafted queue's consumed pointer to N, so its work items are "
        "outstanding. Without this the queue reports as much consumed as written and firmware "
        "retires the publication without walking any of it",
    )
    parser.add_argument(
        "--watch-render-dva",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        metavar="DVA",
        help="save and diff this render-context page across the work doorbell; repeatable",
    )
    parser.add_argument(
        "--watch-context",
        type=int,
        default=1,
        metavar="ID",
        help="UAT context containing --watch-render-dva pages (default: 1)",
    )
    parser.add_argument(
        "--watch-render-from-start",
        action="store_true",
        help="take --watch-render-dva baselines before firmware startup instead of "
        "immediately before the work doorbell; catches work consumed during initial 0x89",
    )
    parser.add_argument(
        "--require-render-change",
        action="store_true",
        help="fail unless at least one byte changes in a --watch-render-dva page",
    )
    parser.add_argument(
        "--clear-watched-render-before-extra-submissions",
        action="store_true",
        help="after validating the startup work, zero every watched physical page "
        "before --replay-second-outer-message rounds and require those later "
        "submissions to repopulate at least one byte",
    )
    parser.add_argument(
        "--graft-objects-only",
        action="store_true",
        help="write only the submission's own objects rather than every captured page. A "
        "captured page can hold unrelated firmware state, including other channels' queue "
        "descriptors and shared record pools, and overwriting it corrupts the replayed world",
    )
    parser.add_argument(
        "--graft-reuse-active-queues",
        action="store_true",
        help="after a post-control overlay restores native active queues, publish "
        "the grafted descriptors through those queue addresses",
    )
    parser.add_argument(
        "--graft-inner-head",
        type=lambda v: int(v, 0),
        default=None,
        metavar="N",
        help="publish this many entries for a grafted submission instead of the captured "
        "count. Entries are three a work item, so this bounds how many items firmware "
        "processes without altering any grafted content",
    )
    parser.add_argument(
        "--build-ta-pools",
        action="store_true",
        help="with --build-ta-descriptor, also generate the two record pools and point "
        "the built descriptor at them, so the bulk of the item's memory is generated "
        "rather than captured",
    )
    parser.add_argument(
        "--build-ta-descriptor",
        action="store_true",
        help="build the first TA descriptor from the submission model instead of "
        "copying it, map it at a free address and point queue entry zero at it. Tests "
        "whether firmware accepts a descriptor it has never seen; remaining "
        "unmodeled kind-specific scalars are zero",
    )
    parser.add_argument(
        "--build-3d-descriptor",
        action="store_true",
        help="build the first 3D descriptor from the submission model, map it at a "
        "free address and point queue entry zero at it",
    )
    parser.add_argument(
        "--build-render-register-recipe",
        action="store_true",
        help="with built TA and 3D descriptors, generate both ordered register "
        "arrays from the G17P render recipe instead of copying register entries",
    )
    parser.add_argument(
        "--backend-render-recipe-snapshot",
        type=pathlib.Path,
        metavar="DIR",
        help="derive only the workload-facing render recipe from a "
        "g17p-generated-render-pre-notify-v1 snapshot, while retaining the "
        "positive replay's queue, descriptor identity, and runtime-control "
        "lifecycle. Snapshot bytes are not installed as firmware objects",
    )
    parser.add_argument(
        "--backend-graft-firmware-pages",
        type=pathlib.Path,
        help="immediately before the first fresh backend publication, replace "
             "firmware pages with a live source pre-submit snapshot at the "
             "same DVAs; backend allocator pages are always protected",
    )
    parser.add_argument(
        "--backend-graft-firmware-page-slice",
        type=parse_page_slice,
        default=(0, None),
        metavar="FIRST:LAST|all",
        help="DVA-ordered half-open slice selected from "
             "--backend-graft-firmware-pages (default: all)",
    )
    parser.add_argument(
        "--backend-graft-firmware-byte-span",
        type=parse_dva_offset_length,
        action="append",
        default=[],
        metavar="DVA+OFFSET=LENGTH",
        help="within the selected source firmware candidate page(s), copy only "
             "this byte span; repeat for disjoint fields (default: whole pages)",
    )
    parser.add_argument(
        "--backend-graft-firmware-object",
        type=parse_dva_copy_length,
        action="append",
        default=[],
        metavar="SOURCE_DVA:DESTINATION_DVA=LENGTH",
        help="after preparing the fresh submission lifecycle, copy this "
             "explicit object range out of --backend-graft-firmware-pages "
             "to a bound destination; repeat for independent objects",
    )
    parser.add_argument(
        "--backend-graft-object-file",
        type=parse_dva_path,
        action="append",
        default=[],
        metavar="DESTINATION_DVA=FILE",
        help="after preparing the fresh submission lifecycle, copy this "
             "source object artifact into an already-bound destination; "
             "repeat for independent objects",
    )
    parser.add_argument(
        "--backend-graft-preserve-object-pointers",
        action="store_true",
        help="during explicit post-lifecycle Pool-A, Pool-B, or packed-shared "
             "object grafts, retain every embedded destination-world qword "
             "pointer so only scalar contents change",
    )
    parser.add_argument(
        "--allow-register-recipe-differences",
        action="store_true",
        help="run a generated register recipe even when capture-varying lifecycle "
        "entries differ; every difference is printed before hardware startup",
    )
    parser.add_argument(
        "--build-ta-captured-tail",
        action="store_true",
        help="with --build-ta-descriptor, retain captured bytes after the "
        "model-built register array through the selector-0 record end",
    )
    parser.add_argument(
        "--relocate-render-status-pages",
        action="store_true",
        help="with the generated render recipe, copy the TA and fragment status "
        "pages to fresh context-1 DVAs and update their register values",
    )
    parser.add_argument(
        "--redirect-descriptor-backreferences",
        action="store_true",
        help="with built TA and 3D descriptors, update the non-queue descriptor "
        "locators in both context-global pages without breaking their aliases",
    )
    parser.add_argument(
        "--mirror-backend-global-descriptors",
        action="store_true",
        help="keep the captured full descriptors on the context-global path and "
        "mirror every backend-translated register plus the two status aliases "
        "into them, while queue entries use the generated compact descriptors",
    )
    parser.add_argument(
        "--mirror-status-relocation-in-global-descriptors",
        action="store_true",
        help="with relocated status pages, write the two new status values into "
        "the full-size descriptors named by the context-global locators",
    )
    parser.add_argument(
        "--build-3d-captured-header",
        action="store_true",
        help="with --build-3d-descriptor, overlay only the captured bytes before "
        "the register array, preserving the model-built pointer block",
    )
    parser.add_argument(
        "--build-3d-captured-tail",
        action="store_true",
        help="with --build-3d-descriptor, append the captured bytes after the "
        "model-built register array through the selector-1 record end",
    )
    parser.add_argument(
        "--build-structural-tails",
        action="store_true",
        help="replace both captured descriptor tails with the production G17P "
        "backend's generated pointer and structural fields",
    )
    parser.add_argument(
        "--build-ta-structural-tail",
        action="store_true",
        help="replace only the TA captured tail with production-generated fields",
    )
    parser.add_argument(
        "--build-3d-structural-tail",
        action="store_true",
        help="replace only the fragment captured tail with production-generated fields",
    )
    parser.add_argument(
        "--build-structural-tail-range",
        action="append",
        default=[],
        type=parse_structural_tail_range,
        metavar="KIND:START:END",
        help="with a captured tail and the matching structural-tail switch, splice "
        "only this half-open byte range from the production-generated tail; "
        "repeatable and intended for bounded field-block experiments",
    )
    parser.add_argument(
        "--new-first-ta-descriptor-dva",
        action="store_true",
        help="map a copied first TA descriptor at a free selected-root DVA and update queue entry zero",
    )
    parser.add_argument(
        "--new-first-3d-descriptor-dva",
        action="store_true",
        help="map a copied first 3D descriptor at a free selected-root DVA and update queue entry zero",
    )
    parser.add_argument(
        "--new-first-work-support-item-dvas",
        action="store_true",
        help="map copied required support items at free selected-root DVAs and update both queues",
    )
    parser.add_argument(
        "--relocate-ta-descriptor-backreference-page",
        action="store_true",
        help="move and update the observed non-queue pointer to a new first TA descriptor DVA",
    )
    parser.add_argument(
        "--relocate-3d-descriptor-backreference-page",
        action="store_true",
        help="move and update the observed non-queue pointer to a new first 3D descriptor DVA",
    )
    parser.add_argument(
        "--patch-dva-u32",
        action="append",
        default=[],
        type=parse_dva_value,
        metavar="DVA=VALUE",
        help="write a u32 at any device address before firmware starts; repeatable. "
        "Reaches the record arrays a descriptor points at, not only the descriptor",
    )
    parser.add_argument(
        "--patch-dva-u64",
        action="append",
        default=[],
        type=parse_dva_value,
        metavar="DVA=VALUE",
        help="write a u64 at any device address before firmware starts; repeatable",
    )
    parser.add_argument(
        "--backend-reuse-pools",
        action="store_true",
        help="have the backend name the parameter-buffer state firmware already has "
        "bound rather than building its own, which firmware refuses to rebind. It still "
        "builds its own descriptors, optional items and event records",
    )
    parser.add_argument(
        "--backend-publish-slot",
        type=lambda v: int(v, 0),
        default=None,
        help="which ring slot the backend announces its group in. Firmware takes "
        "its startup work from slot zero, and publications have so far gone into "
        "the next free slot instead",
    )
    parser.add_argument(
        "--empty-queues-before-start",
        action="store_true",
        help="move each queue's write pointer back to its done pointer before "
        "firmware starts, so nothing is consumed at startup and a host publication "
        "is the first thing to use the parameter buffer",
    )
    parser.add_argument(
        "--backend-submit-cmdbuf",
        action="store_true",
        help="build the work from a command buffer through the front end's own "
        "translation, instead of handing the builder register programs. The shader-"
        "binding programs are compiled code and come from the captured context",
    )
    parser.add_argument(
        "--backend-reuse-render-dvas",
        action="store_true",
        help="build the command buffer's seven generated render objects on fresh "
        "physical pages at their captured context-1 DVAs. This controls for the "
        "still-undecoded aliases in the captured full-descriptor tails",
    )
    parser.add_argument(
        "--backend-reuse-heapmeta-dva",
        action="store_true",
        help="keep only generated heap metadata at its captured DVA while all "
        "other generated render objects use fresh addresses",
    )
    parser.add_argument(
        "--backend-reuse-encoder-dva",
        action="store_true",
        help="keep only the generated tiler stream at its captured context "
        "offset while all other generated render objects use fresh addresses",
    )
    parser.add_argument(
        "--backend-reuse-context-heapmeta",
        action="store_true",
        help="supply the captured context heap-metadata object to command-buffer "
        "translation instead of allocating per-submission heap metadata",
    )
    parser.add_argument(
        "--build-descriptor-copy-word",
        action="append",
        default=[],
        type=parse_publish_descriptor_patch_kindless,
        metavar="KIND:OFFSET",
        help="take this word from the captured descriptor into the built one, as TA_0:0x38; "
        "repeatable. The model leaves some words zero that a host populates once it has run",
    )
    parser.add_argument(
        "--scan-render-from-start",
        action="store_true",
        help="take the render scan's baseline before firmware starts, so work already pending when "
        "it comes up is inside the measured window rather than before it",
    )
    parser.add_argument(
        "--backend-publish-captured-items",
        action="store_true",
        help="publish the item addresses already on the queue rather than anything this host built. "
        "Those are work firmware executed as part of a host's own stream, so a republication of them "
        "separates a submission that is wrong from a publication that cannot rasterise",
    )
    parser.add_argument(
        "--backend-alias-render-backing",
        action="store_true",
        help="give every generated render object the captured physical page rather than a fresh "
        "one. A world captured mid-stream holds tiler state in those objects, and a blank page "
        "under them is what a world that has not started yet looks like",
    )
    parser.add_argument(
        "--backend-alias-heapmeta-backing",
        action="store_true",
        help="give generated heap metadata a fresh DVA whose leaves alias the "
        "captured native physical pages, distinguishing backing-object state "
        "from virtual-address binding",
    )
    parser.add_argument(
        "--backend-encoder-opcode",
        type=lambda value: int(value, 0),
        default=None,
        help="replace only the opcode in the command buffer's generated tiler "
        "stream. Zero is the established no-render control",
    )
    parser.add_argument(
        "--backend-encoder-index-count",
        type=lambda value: int(value, 0),
        default=None,
        help="replace the generated tiler stream's draw index count",
    )
    parser.add_argument(
        "--backend-fresh-pools",
        action="store_true",
        help="with --backend-reuse-pools, take the two record pools fresh while the shared objects "
        "stay bound. Firmware names the parameter-buffer state without saying which of the item's "
        "four pointer-block objects carries it, and swapping one group at a time separates them",
    )
    parser.add_argument(
        "--backend-fresh-shared",
        action="store_true",
        help="with --backend-reuse-pools, take the two shared objects fresh while the record pools "
        "stay bound. The other half of the same separation",
    )
    parser.add_argument(
        "--backend-fill-job-record",
        action="store_true",
        help="write into the published item's pool A record the words every in-use record of a "
        "live host carries, which the model treats as a marker on the array's first record only",
    )
    parser.add_argument(
        "--backend-job-record-0c",
        type=lambda value: int(value, 0),
        default=2,
        help="the value for the pool A record's +0x0c, which a live host varies between 2 and 4",
    )
    parser.add_argument(
        "--backend-dump-pool-records",
        action="store_true",
        help="dump the first few pool A records, which the job list names, so the record a serviced "
        "submission uses can be compared against the one a published submission uses",
    )
    parser.add_argument(
        "--backend-dump-pre-notify",
        type=pathlib.Path,
        metavar="DIR",
        help="save the generated descriptor, support, parameter-buffer, and queue "
        "transport closure immediately after staging and before the work doorbell. "
        "With multiple fresh items, each item is saved in a numbered subdirectory",
    )
    parser.add_argument(
        "--work-model-snapshot",
        type=pathlib.Path,
        default=None,
        help="read the captured work model from this snapshot while restoring the one named by "
        "--snapshot. The pre-control image is the only world whose control channel stays live and "
        "has no work in it; the later image has the work and the two are structurally identical",
    )
    parser.add_argument(
        "--prestage-control-tick",
        type=int,
        default=0,
        metavar="COUNT",
        help="leave this many opcode-0x2e device-control entries outstanding before firmware "
        "starts. Firmware consumes these, which is what establishes the entry body is well formed, "
        "but it still refuses every entry published after the first work; a "
        "firmware resumed with none pending consumes nothing, and this tests whether that is the "
        "whole difference",
    )
    parser.add_argument(
        "--prestage-control-entry-hex",
        help="leave this 0x40-byte device-control entry outstanding before firmware starts, so a "
        "0x20 is processed while the opening still accepts one",
    )
    parser.add_argument(
        "--prestage-control-copy",
        type=int,
        default=None,
        metavar="INDEX",
        help="prestage copies of this existing device-control ring entry instead of building "
        "0x2e entries. Index 3 is the opening 0x20, the opcode a firmware executes in its own "
        "boot only in the world whose control channel stays live",
    )
    parser.add_argument(
        "--backend-control-tick",
        type=int,
        default=0,
        metavar="COUNT",
        help="publish this many opcode-0x2e device-control entries after the work publication, the "
        "way a live host does: entry, producer, doorbell. A host publishes these continuously "
        "while it submits work and this host has never published one",
    )
    parser.add_argument(
        "--map-operand-slot",
        type=int,
        action="append",
        default=[],
        metavar="SLOT",
        help="allocate and map a buffer, then write its address into this slot of the operand "
        "page's table, which is what a device-control 0x20 entry names. Every populated slot is a "
        "buffer that exists, so an entry cannot be published without one",
    )
    parser.add_argument(
        "--alias-operand-buffer",
        action="store_true",
        help="point a mapped operand buffer at the previous buffer's own physical pages, so it holds "
        "what that buffer holds rather than zeroes. Separates the buffer existing from its contents",
    )
    parser.add_argument(
        "--map-operand-pages",
        type=int,
        default=64,
        help="how many pages the buffer mapped for --map-operand-slot spans; the captured buffers "
        "are sixty-four pages of each 0x108000 step",
    )
    parser.add_argument(
        "--backend-control-entry-hex",
        default=None,
        metavar="HEX",
        help="publish this exact 0x40-byte device-control entry instead of a generated 0x2e. A "
        "guest sends a second opcode-0x20 entry after its first 0x2e, which this host has never "
        "sent, and its payload differs from the opening one",
    )
    parser.add_argument(
        "--backend-control-tick-start",
        type=int,
        default=0,
        help="the counter the first published 0x2e entry carries, which a host increments per entry",
    )
    parser.add_argument(
        "--backend-message-after-publish",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        metavar="PAYLOAD",
        help="send this endpoint 0x21 message after publishing; repeatable. A live host's traffic "
        "interleaves 0x0084000000000011 and 0x0087000000000010 with its work doorbells, and this "
        "host has never sent either during operation",
    )
    parser.add_argument(
        "--backend-publish-in-place",
        action="store_true",
        help="write the published group over the entries already on the queue and leave the write "
        "index alone, which is what a host's submissions after the first do: its write index stops "
        "at six while the producer counter carries every later submission",
    )
    parser.add_argument(
        "--backend-publish-before-doorbell",
        action="store_true",
        help="stage the backend's group before the first work's doorbell rather than after it, so "
        "firmware is woken once with both groups already on the queue. Separates whether a "
        "published group fails because of publication or because it arrives after the wake-up",
    )
    parser.add_argument(
        "--backend-doorbell-after-publish",
        type=int,
        default=0,
        metavar="ROUNDS",
        help="ring the work doorbell this many more times after the publication has been linked, "
        "which is a different event from the two rung back to back during publication",
    )
    parser.add_argument(
        "--backend-job-list-poll",
        type=int,
        default=1,
        metavar="POLLS",
        help="how many times to re-read the job list after publishing, to separate a job the "
        "scheduler is holding from one it runs late",
    )
    parser.add_argument(
        "--backend-dump-channel-ring",
        action="append",
        default=[],
        type=int,
        metavar="INDEX",
        help="dump this channel's ring contents; repeatable. For the entries past the work "
        "channels, whose counters do not look like a host producing work",
    )
    parser.add_argument(
        "--backend-ack-firmware-channel",
        action="append",
        default=[],
        type=int,
        metavar="INDEX",
        help="before publishing, set this channel's first counter to its producer; repeatable. "
        "Firmware produces on channels 13 and 14 as it executes and a host's first counter tracks "
        "that, while this world's stays where the snapshot left it",
    )
    parser.add_argument(
        "--backend-dump-channels",
        action="store_true",
        help="print every channel table entry with its counters, including the entries past the "
        "twelve work channels whose roles are not established",
    )
    parser.add_argument(
        "--backend-compare-published-items",
        action="store_true",
        help="after publishing, compare the three items firmware executed against the three it "
        "retired without executing, which are on the same queue in the same run",
    )
    parser.add_argument(
        "--backend-publish-register-delta",
        action="append",
        default=[],
        type=parse_publish_register_delta,
        metavar="KIND:REG=DELTA",
        help="add a signed delta to a register value in the published work descriptor, as "
        "tiling:0x1c039=0x5200; repeatable. Reaches the values a live host advances between "
        "submissions by register number rather than by descriptor offset",
    )
    parser.add_argument(
        "--backend-publish-descriptor-u32",
        action="append",
        default=[],
        type=parse_publish_descriptor_patch,
        metavar="KIND:OFFSET=VALUE",
        help="set a u32 in the published work descriptor before staging, as tiling:0x48=4 or "
        "fragment:0x90=2; repeatable. Reaches the per-submission fields a live host varies and "
        "this model does not carry",
    )
    parser.add_argument(
        "--backend-clone-shared-packed",
        action="store_true",
        help="publish with a byte-identical copy of the bound packed shared object at a fresh "
        "address. Separates firmware comparing the object's address from firmware comparing what "
        "it holds, which the fresh-object runs cannot, since those change both",
    )
    parser.add_argument(
        "--backend-fresh-shared-packed",
        action="store_true",
        help="take only the packed shared object fresh, which is the one naming the four leaf "
        "pages, to separate it from the zero object beside it",
    )
    parser.add_argument(
        "--backend-fresh-shared-zero",
        action="store_true",
        help="take only the zero shared object fresh, the other half of that separation",
    )
    parser.add_argument(
        "--backend-publish-first-submit",
        action="store_true",
        help="set bit 24 in the published ring slot. Captures show it set only on a queue's first "
        "slot, and a queue's first submission is the only one this part has been seen to execute, "
        "so whether it describes that or causes it is worth separating",
    )
    parser.add_argument(
        "--backend-patch-render-u16-before-publish",
        action="append",
        default=[],
        type=parse_offset_value,
        metavar="DVA=VALUE",
        help="write this half-word into a render-context page immediately before the backend "
        "publishes; repeatable. Lets the first work run with its draw suppressed and the "
        "published work armed, so any render output can only have come from the publication",
    )
    parser.add_argument(
        "--backend-publish-group-number",
        type=lambda value: int(value, 0),
        default=None,
        help="the group number the published event records carry. The model pairs work item n "
        "with group n+1, and the publication path has always used 1 regardless of which item it "
        "publishes, so a second item has been announcing a group number that is already complete",
    )
    parser.add_argument(
        "--backend-clear-render-before-publish",
        action="append",
        default=[],
        type=lambda value: int(value, 0),
        metavar="DVA",
        help="zero this render-context page immediately before the backend publishes; repeatable. "
        "Distinguishes a publication that did nothing from one that re-executed identical work",
    )
    parser.add_argument(
        "--backend-publish-fresh-item",
        action="store_true",
        help="publish a second, distinct work item rather than republishing the descriptors that "
        "became the first work. A republished item is one firmware has already executed and whose "
        "completion records are already written, which would retire without doing anything",
    )
    parser.add_argument(
        "--backend-fresh-item-count",
        type=int,
        default=1,
        metavar="COUNT",
        help="build and serially publish COUNT distinct append-only items after the captured "
        "first work; every item must repopulate every caller-cleared output attachment",
    )
    parser.add_argument(
        "--backend-defer-future-items",
        action="store_true",
        help="keep fresh item 2 and later zero until the preceding item completes, then restore "
        "their already-built bytes immediately before publication; this matches native "
        "completion-gated construction without changing object placement or contents",
    )
    parser.add_argument(
        "--backend-render-pool-cadence",
        action="store_true",
        help="select render Pool-A records as A0,A0,A2,A2,... while Pool-B advances every "
        "item, matching the consecutive native render descriptors retained in the capture",
    )
    parser.add_argument(
        "--backend-encoder-field",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="replace any modeled scalar field of the command buffer's generated "
        "tiler stream, as NAME=VALUE; repeatable. Reaches the fields no dedicated "
        "flag covers, so a field's modeled role can be tested without a new flag",
    )
    parser.add_argument(
        "--backend-first-work",
        action="store_true",
        help="make the backend-built group the first work firmware processes, "
        "instead of publishing it afterwards. The first submission is the only one "
        "this part has been seen to render",
    )
    parser.add_argument(
        "--backend-build-submission",
        action="store_true",
        help="have the DRM backend construct a complete paired work group in pages "
        "of its own, given only the register programs and the context pointers "
        "hardware showed belong to context initialization",
    )
    parser.add_argument(
        "--backend-read-channels",
        action="store_true",
        help="after the first work, have the DRM backend's own code read the live channel "
        "table and locate both work queues. The first time that code touches hardware",
    )
    parser.add_argument(
        "--dump-dva",
        action="append",
        default=[],
        type=parse_dva_span,
        metavar="DVA=LENGTH",
        help="dump LENGTH bytes at a device address once the world is live, read only",
    )
    parser.add_argument(
        "--backend-context-index",
        type=int,
        default=None,
        metavar="INDEX",
        help="set the created queue pair's context object to declare this context index. A host's "
        "second queue pair declares 1 where the pair bound at init declares 0",
    )
    parser.add_argument(
        "--pre-work-interleave",
        type=int,
        default=0,
        metavar="ROUNDS",
        help="send this many rounds of 0x87 and 0x84 before the first work's doorbell, which is how a "
        "booted host drives the coprocessor continuously and this host never has",
    )
    parser.add_argument(
        "--backend-reinit-after-publish",
        action="store_true",
        help="re-send the initialization message after publishing, so the published group is on the "
        "queue when firmware initializes. Everything that executes was queued before firmware started",
    )
    parser.add_argument(
        "--backend-control-tick-before-doorbell",
        type=int,
        default=0,
        metavar="COUNT",
        help="publish this many device-control entries after staging the group and before ringing the "
        "work doorbell, which is the order a host uses",
    )
    parser.add_argument(
        "--backend-event-subtype",
        type=lambda v: int(v, 0),
        default=None,
        metavar="VALUE",
        help="override the published event record's subtype. A native first submission carries "
        "0x00010000 and 0x00010001 on the tiling and fragment halves; a later host publication "
        "carries 0x00010008, which this host has never written",
    )
    parser.add_argument(
        "--backend-extra-doorbell",
        action="append",
        default=[],
        metavar="TYPE[:PAYLOAD]",
        help="after publishing, send this message type on the doorbell endpoint; repeatable. Only "
        "the work doorbell has been rung after a publication, and firmware takes others at setup",
    )
    parser.add_argument(
        "--backend-channel-pair",
        type=int,
        default=0,
        metavar="UNIT",
        help="publish onto the work channel pair of this unit instead of unit 0. The pairs past unit "
        "0 are untouched in every capture, so a group published there is that channel's first work",
    )
    parser.add_argument(
        "--backend-zero-fragment-tail",
        action="store_true",
        help="zero the published fragment item's record tail before staging. If the values an "
        "executed item carries there are firmware's marks from retiring the work, clearing them "
        "should let that item run again",
    )
    parser.add_argument(
        "--backend-restore-item-pages",
        action="store_true",
        help="restore the pages holding the items about to be published to their captured contents "
        "first, so a republished item is presented as it was before firmware executed it rather than "
        "with whatever firmware wrote into it while retiring the work",
    )
    parser.add_argument(
        "--backend-copy-fragment-tail",
        action="store_true",
        help="copy the executed fragment item's record tail into the published one, which the "
        "backend builds as zero where the first work's descriptor receives the captured tail",
    )
    parser.add_argument(
        "--backend-restore-bound-objects",
        action="store_true",
        help="put the pages holding the bound parameter-buffer state back to their captured contents "
        "before publishing, keeping the same addresses so nothing is rebound. Tests whether a second "
        "submission draws nothing because the binding it names has been used up",
    )
    parser.add_argument(
        "--backend-unbind-opcode",
        type=lambda v: int(v, 0),
        default=None,
        metavar="OPCODE",
        help="publish one device-control entry carrying this opcode immediately before the group, to "
        "test whether it unbinds the parameter-buffer state. Meaningful with the backend building its "
        "own pools, where the publication otherwise stops firmware",
    )
    parser.add_argument(
        "--backend-control-opcode-scan",
        metavar="FIRST[:LAST]",
        help="publish device-control entries carrying each opcode in this range and report which "
        "firmware consumes. Firmware requires an unbind before parameter-buffer state can be "
        "rebound, and the opcode for it is not among the three this record knows",
    )
    parser.add_argument(
        "--backend-reserve-pages",
        type=int,
        default=0,
        metavar="COUNT",
        help="map this many spare backend heap pages before the restore, so a publication can "
        "allocate per-submission buffers out of memory that is already in the tables. A page mapped "
        "after firmware starts never reaches the UAT",
    )
    parser.add_argument(
        "--backend-advance-per-submission",
        type=int,
        default=0,
        metavar="STEPS",
        help="advance the geometry item's twelve mechanical per-submission fields by this many "
        "steps of their own strides before publishing, which is what a live host does between one "
        "submission and the next",
    )
    parser.add_argument(
        "--backend-ack-firmware-index",
        type=int,
        default=2,
        metavar="SLOT",
        help="which of a channel's three counters --backend-ack-firmware-consumer advances. The third "
        "is the one a live host keeps up with its producer",
    )
    parser.add_argument(
        "--backend-ack-firmware-consumer",
        action="append",
        default=[],
        type=int,
        metavar="INDEX",
        help="advance this channel's second counter to its first before publishing; repeatable. On a "
        "firmware-produced channel the first counter is what grows with firmware's work and the "
        "second sits far behind it, which is a consumer the host has never moved",
    )
    parser.add_argument(
        "--backend-share-queue-context",
        action="store_true",
        help="give a created queue pair the template's context object instead of its own copy, "
        "which is not what the captures show but separates the context from the rest of it",
    )
    parser.add_argument(
        "--backend-share-job-list",
        action="store_true",
        help="give a created queue the template queue's job list instead of its own, which is not "
        "what the captures show a host doing but separates the job list from the rest of it",
    )
    parser.add_argument(
        "--backend-create-queue",
        type=int,
        default=None,
        metavar="GRID",
        help="create a queue pair at this grid index and publish onto it, the way a host's second "
        "submission goes to a queue it creates rather than to the one firmware was given at init. "
        "The tiling half takes GRID and the fragment half GRID+1",
    )
    parser.add_argument(
        "--backend-created-queue-grid-step",
        type=int,
        default=0,
        metavar="STEP",
        help="advance the created queue's advertised grid by STEP for each "
        "fresh publication. The late native partial generation advances from "
        "grids 4/5 to 9/10 because grid 8 was allocated between them",
    )
    parser.add_argument(
        "--backend-allocate-queue-record",
        action="store_true",
        help="give each created logical queue generation a fresh queue-record "
        "DVA while retaining its advertised GRID. Native partial submissions "
        "reuse grids 4/5 but point their outer slots at different queue records",
    )
    parser.add_argument(
        "--backend-recycle-created-queue",
        action="store_true",
        help="after each completed fresh publication, restore and reuse one "
        "created queue pair's context, shared job list, pointer blocks, and "
        "item rings instead of allocating an unbounded queue generation",
    )
    parser.add_argument(
        "--backend-recycle-submission-graph",
        action="store_true",
        help="after the first generated command completes, regenerate the "
        "quiesced bound PB/submission graph in place and publish each later "
        "command as graph-local item zero. This models a finite graph "
        "generation rather than an unbounded same-graph item stream",
    )
    parser.add_argument(
        "--backend-recycle-descriptor-pair",
        type=int,
        default=None,
        metavar="PAIR",
        help="when recycling the submission graph, encode every generation "
        "after the first with this descriptor/graph pair identity. The exact "
        "late native partial capture advances from pair 2 to pair 4",
    )
    parser.add_argument(
        "--backend-control-tick-before-publish",
        type=int,
        default=0,
        metavar="COUNT",
        help="publish this many opcode-0x2e device-control entries before staging the group, the "
        "way a host publishes them continuously while it submits work",
    )
    parser.add_argument(
        "--backend-reset-queue-indices",
        action="store_true",
        help="zero the queue's completion, read and write indices before publishing, so the group "
        "lands at entry zero as the first work did. Separates firmware objecting to later entries "
        "from firmware objecting to a second group after a completed one",
    )
    parser.add_argument(
        "--backend-doorbell-only",
        action="store_true",
        help="ring the work doorbell without staging anything, to separate the publication's writes "
        "from its doorbell as the thing that stops firmware servicing device control",
    )
    parser.add_argument(
        "--backend-skip-publish-announce",
        action="store_true",
        help="publish without writing the queue record's has-commands field. That field reads zero "
        "on every queue in a world whose work has completed, so a host does not leave it set, and "
        "writing it may be what stops firmware servicing anything after a publication",
    )
    parser.add_argument(
        "--backend-queue-slot",
        type=int,
        default=0,
        help="which work-channel ring slot to take the command queue from. A channel carries "
        "several queues and slot zero names the one a host opened first, so a world captured "
        "mid-stream needs a later slot to reach the queue its host is actually using",
    )
    parser.add_argument(
        "--render-parameter",
        action="append",
        default=[],
        type=parse_render_parameter,
        metavar="NAME=VALUE",
        help="re-derive both register programs with this parameter changed, after the "
        "recipe has been checked against the capture; repeatable. Asks the hardware about "
        "a workload rather than about a replay",
    )
    parser.add_argument(
        "--scan-render-writes",
        nargs="?",
        const=64,
        type=int,
        default=0,
        metavar="BYTES",
        help="after the submission, read the first BYTES of every render-context page the "
        "snapshot maps and report which differ from the snapshot's own contents. Finds "
        "outputs that watching three chosen pages cannot",
    )
    parser.add_argument(
        "--build-encoder",
        action="store_true",
        help="destroy the tiler encoder's page, then write a stream generated from the "
        "model into it. Needs --build-render-register-recipe for the encoder's address. "
        "The generated stream must match the captured one byte for byte or the run aborts",
    )
    parser.add_argument(
        "--patch-render-u32",
        action="append",
        default=[],
        type=parse_dva_value,
        metavar="DVA=VALUE",
        help="write a u32 at a render-context device address before firmware starts; "
        "repeatable. The render context is a different root, so --patch-dva-u32 cannot "
        "reach it. This is how the tiler encoder and the objects it names are perturbed",
    )
    parser.add_argument(
        "--copy-dva-range",
        action="append",
        default=[],
        type=parse_dva_copy,
        metavar="SRC:DST:SIZE",
        help="copy bytes within the device address space after native control setup "
        "and immediately before work publication; repeatable. If both ranges are "
        "mapped by --watch-context, that client context is preferred over the "
        "firmware address space",
    )
    parser.add_argument(
        "--patch-first-work-u32",
        action="append",
        default=[],
        type=parse_first_work_u32_patch,
        metavar="CHANNEL:OFFSET:VALUE",
        help="replace one u32 in first TA_0 or 3D_0 descriptor before firmware startup",
    )
    parser.add_argument(
        "--patch-first-work-u64",
        action="append",
        default=[],
        type=parse_first_work_u64_patch,
        metavar="CHANNEL:OFFSET:VALUE",
        help="replace one u64 in first TA_0 or 3D_0 descriptor before firmware startup",
    )
    parser.add_argument(
        "--control-producer",
        type=int,
        default=4,
        help="publish this many captured device-control entries (at most 256)",
    )
    parser.add_argument(
        "--control-only",
        action="store_true",
        help="stop after device-control processing; do not publish TA/3D work",
    )
    parser.add_argument(
        "--init-only",
        action="store_true",
        help="send both initdata descriptors and observe firmware without any "
             "post-ACK doorbell or control/work publication",
    )
    parser.add_argument(
        "--resume-post-control",
        action="store_true",
        help="preserve captured completed device-control state and publish only queued work",
    )
    parser.add_argument(
        "--reapply-snapshot-after-control",
        action="store_true",
        help="after the opening control message, restore every captured UAT page "
        "again while keeping deferred work producers hidden; requires "
        "--resume-post-control or --prestage-control",
    )
    parser.add_argument(
        "--prestage-control",
        action="store_true",
        help="present all requested device-control entries as pending when initdata is handed "
        "to firmware, instead of publishing entries two through four after the initial 0x89",
    )
    parser.add_argument(
        "--sequence-control-doorbells",
        action="store_true",
        help="after the opening entry, publish each captured device-control record "
        "individually, ring 0x84, and wait for both consumers before the next record",
    )
    parser.add_argument(
        "--control-timeline",
        type=pathlib.Path,
        help="restore exact pre-consumption host inputs from this device-control "
        "timeline before each sequential 0x84 publication",
    )
    parser.add_argument(
        "--disable-work-channel",
        action="append",
        choices=WORK_CHANNEL_NAMES,
        default=[],
        help="with --resume-post-control, suppress this captured pending queue",
    )
    parser.add_argument(
        "--defer-work-channel",
        action="append",
        choices=WORK_CHANNEL_NAMES,
        default=[],
        help="with --resume-post-control, publish this captured queue after the others complete",
    )
    parser.add_argument(
        "--use-captured-work-message",
        action="store_true",
        help="ring first/deferred captured work with the exact type-0x83 mailbox "
        "message that triggered the snapshot instead of the generic zero payload",
    )
    parser.add_argument(
        "--queue-state-40",
        type=int,
        choices=range(1, 4),
        help="override the observed queue-state word at offset 0x40 for pending channels",
    )
    parser.add_argument(
        "--clear-work-item-before-control",
        action="append",
        type=int,
        choices=range(3),
        default=[],
        help="zero this captured work-item pointer before the initial 0x89 control doorbell",
    )
    parser.add_argument(
        "--clear-work-item-after-control",
        action="append",
        type=int,
        choices=range(3),
        default=[],
        help="zero this captured work-item pointer after initial 0x89 control processing",
    )
    parser.add_argument(
        "--replay-second-outer-message",
        action="store_true",
        help="copy each captured TA/3D outer command message into slot one and publish producer two",
    )
    parser.add_argument(
        "--construct-queue",
        action="store_true",
        help="give each further submission a queue, pointer state and entry array "
        "on host pages at host-chosen device addresses, instead of the captured ones",
    )
    parser.add_argument(
        "--extra-submissions",
        type=int,
        default=1,
        help="how many further submissions to publish after the first, each a copy "
        "of the previous entry one stride further along",
    )
    parser.add_argument(
        "--second-outer-patch-u32",
        action="append",
        default=[],
        type=parse_offset_value,
        metavar="OFFSET=VALUE",
        help="set a u32 in the copied outer message before publishing it, as "
        "OFFSET=VALUE; repeatable. +0x04 is zero in the captured first submission "
        "and an external reference names it a submission sequence counter",
    )
    parser.add_argument(
        "--second-outer-clear-first-submit",
        action="store_true",
        help="clear bit 24 of copied outer message word +0x14 before publishing it",
    )
    parser.add_argument(
        "--append-second-inner-batch",
        action="store_true",
        help="duplicate the captured inner batch, advance its head, and publish it in the copied outer message",
    )
    parser.add_argument(
        "--coproc-maint",
        action="store_true",
        help="replay EL2-accessible UAT map-time cache maintenance for control operands",
    )
    parser.add_argument(
        "--dump-pre-control-state",
        action="store_true",
        help="save fresh firmware and opcode-0x20 operand state after 0x89",
    )
    args = parser.parse_args()
    if args.backend_fresh_item_count < 1:
        parser.error("--backend-fresh-item-count must be positive")
    if (
        args.backend_fresh_item_count != 1
        and not args.backend_publish_fresh_item
    ):
        parser.error(
            "--backend-fresh-item-count requires --backend-publish-fresh-item"
        )
    if args.backend_dump_pre_notify is not None and not args.backend_read_channels:
        parser.error(
            "--backend-dump-pre-notify requires --backend-read-channels"
        )
    if (
        args.backend_defer_future_items
        and (
            not args.backend_publish_fresh_item
            or args.backend_fresh_item_count < 2
        )
    ):
        parser.error(
            "--backend-defer-future-items requires at least two fresh items"
        )
    if (
        args.backend_render_pool_cadence
        and not args.backend_publish_fresh_item
    ):
        parser.error(
            "--backend-render-pool-cadence requires fresh item publication"
        )
    if (
        args.backend_created_queue_grid_step
        and args.backend_create_queue is None
    ):
        parser.error(
            "--backend-created-queue-grid-step requires --backend-create-queue"
        )
    if args.backend_recycle_submission_graph and (
        not args.backend_publish_fresh_item
        or args.backend_fresh_item_count < 2
        or not args.backend_reuse_pools
    ):
        parser.error(
            "--backend-recycle-submission-graph requires --backend-reuse-pools "
            "and at least two fresh items"
        )
    if (
        args.backend_recycle_descriptor_pair is not None
        and not args.backend_recycle_submission_graph
    ):
        parser.error(
            "--backend-recycle-descriptor-pair requires "
            "--backend-recycle-submission-graph"
        )
    DIFF_SHARED[0] = bool(args.diff_shared_across_work)
    VERIFY_GRAFTED[0] = bool(args.verify_grafted_after)
    GRAFT_RESET_CONSUMED[0] = args.graft_reset_consumed
    SCAN_RENDER_PREFIX[0] = int(args.scan_render_writes or 0)
    BACKEND_READ_CHANNELS[0] = bool(args.backend_read_channels)
    QUEUE_SLOT[0] = int(args.backend_queue_slot)
    if args.backend_build_submission and not args.build_render_register_recipe:
        raise SystemExit(
            "--backend-build-submission needs --build-render-register-recipe, "
            "which is where the register programs it hands the builder come from")
    if args.backend_submit_cmdbuf and not args.backend_build_submission:
        parser.error(
            "--backend-submit-cmdbuf requires --backend-build-submission"
        )
    if args.backend_reuse_render_dvas and not args.backend_submit_cmdbuf:
        parser.error(
            "--backend-reuse-render-dvas requires --backend-submit-cmdbuf"
        )
    if args.backend_reuse_heapmeta_dva and not args.backend_submit_cmdbuf:
        parser.error(
            "--backend-reuse-heapmeta-dva requires --backend-submit-cmdbuf"
        )
    if args.backend_reuse_encoder_dva and not args.backend_submit_cmdbuf:
        parser.error(
            "--backend-reuse-encoder-dva requires --backend-submit-cmdbuf"
        )
    if args.backend_reuse_context_heapmeta and not args.backend_submit_cmdbuf:
        parser.error(
            "--backend-reuse-context-heapmeta requires --backend-submit-cmdbuf"
        )
    if args.backend_reuse_render_dvas and (
        args.backend_reuse_heapmeta_dva
        or args.backend_reuse_encoder_dva
    ):
        parser.error(
            "--backend-reuse-render-dvas already includes the heap-metadata "
            "and encoder DVAs"
        )
    if args.backend_reuse_context_heapmeta and (
        args.backend_reuse_render_dvas
        or args.backend_reuse_heapmeta_dva
        or args.backend_alias_heapmeta_backing
    ):
        parser.error(
            "--backend-reuse-context-heapmeta does not allocate heap metadata"
        )
    if args.backend_alias_heapmeta_backing and not args.backend_submit_cmdbuf:
        parser.error(
            "--backend-alias-heapmeta-backing requires --backend-submit-cmdbuf"
        )
    if args.backend_encoder_opcode is not None and not args.backend_submit_cmdbuf:
        parser.error(
            "--backend-encoder-opcode requires --backend-submit-cmdbuf"
        )
    if (
        args.backend_encoder_index_count is not None
        and not args.backend_submit_cmdbuf
    ):
        parser.error(
            "--backend-encoder-index-count requires --backend-submit-cmdbuf"
        )
    if args.backend_encoder_field and not args.backend_submit_cmdbuf:
        parser.error(
            "--backend-encoder-field requires --backend-submit-cmdbuf"
        )
    if args.backend_submit_cmdbuf and not (
        args.build_ta_captured_tail
        and args.build_3d_captured_tail
        and (
            args.redirect_descriptor_backreferences
            or args.mirror_backend_global_descriptors
        )
    ):
        parser.error(
            "--backend-submit-cmdbuf requires both captured descriptor tails "
            "and either --redirect-descriptor-backreferences or "
            "--mirror-backend-global-descriptors so both descriptor views "
            "carry the translated state"
        )
    if (
        args.mirror_backend_global_descriptors
        and args.redirect_descriptor_backreferences
    ):
        parser.error(
            "--mirror-backend-global-descriptors and "
            "--redirect-descriptor-backreferences select different global views"
        )
    GRAFT_REUSE_ACTIVE_QUEUE[0] = bool(args.graft_reuse_active_queues)
    if (
        args.relocate_first_work_direct_target_pages
        or args.relocate_first_work_support_item_pages
        or args.new_first_ta_descriptor_dva
        or args.new_first_3d_descriptor_dva
        or args.new_first_work_support_item_dvas
        or args.relocate_ta_descriptor_backreference_page
        or args.relocate_3d_descriptor_backreference_page
        or args.replay_second_outer_message
        or args.build_ta_descriptor
        or args.build_3d_descriptor
        or args.omit_first_optional_item
        or args.build_first_optional_items
        or args.build_first_event_items
        or args.build_shared_descriptor_objects
        or args.build_submission_leaf_pages
        or args.relocate_optional_scratch_alias
        or args.relocate_render_status_pages
        or args.redirect_descriptor_backreferences
        or args.mirror_status_relocation_in_global_descriptors
        or args.rebuild_compute_work
        or args.rebuild_compute_client
        or args.rebuild_compute_registration
    ) and not args.replay_first_work:
        parser.error(
            "first-work descriptor mapping options require --replay-first-work"
        )
    if args.build_ta_pools and not args.build_ta_descriptor:
        parser.error("--build-ta-pools requires --build-ta-descriptor")
    if args.build_ta_captured_tail and not args.build_ta_descriptor:
        parser.error(
            "--build-ta-captured-tail requires --build-ta-descriptor"
        )
    if args.build_render_register_recipe and not (
        args.build_ta_descriptor and args.build_3d_descriptor
    ):
        parser.error(
            "--build-render-register-recipe requires built TA and 3D descriptors"
        )
    if (
        args.allow_register_recipe_differences
        and not args.build_render_register_recipe
    ):
        parser.error(
            "--allow-register-recipe-differences requires "
            "--build-render-register-recipe"
        )
    if (
        args.backend_render_recipe_snapshot is not None
        and not args.build_render_register_recipe
    ):
        parser.error(
            "--backend-render-recipe-snapshot requires "
            "--build-render-register-recipe"
        )
    if (
        args.relocate_render_status_pages
        and not args.build_render_register_recipe
    ):
        parser.error(
            "--relocate-render-status-pages requires "
            "--build-render-register-recipe"
        )
    if args.redirect_descriptor_backreferences and not (
        args.build_ta_descriptor and args.build_3d_descriptor
    ):
        parser.error(
            "--redirect-descriptor-backreferences requires built TA and 3D "
            "descriptors"
        )
    if args.redirect_descriptor_backreferences and (
        args.relocate_ta_descriptor_backreference_page
        or args.relocate_3d_descriptor_backreference_page
    ):
        parser.error(
            "--redirect-descriptor-backreferences cannot be combined with "
            "back-reference page relocation"
        )
    if (
        args.mirror_status_relocation_in_global_descriptors
        and not args.relocate_render_status_pages
    ):
        parser.error(
            "--mirror-status-relocation-in-global-descriptors requires "
            "--relocate-render-status-pages"
        )
    if args.build_shared_descriptor_objects and not (
        args.build_ta_descriptor
        and args.build_3d_descriptor
        and args.build_first_optional_items
    ):
        parser.error(
            "--build-shared-descriptor-objects requires --build-ta-descriptor, "
            "--build-3d-descriptor, and --build-first-optional-items"
        )
    if args.build_submission_leaf_pages and not (
        args.build_shared_descriptor_objects and args.build_ta_pools
    ):
        parser.error(
            "--build-submission-leaf-pages requires "
            "--build-shared-descriptor-objects and --build-ta-pools"
        )
    if (
        args.relocate_optional_scratch_alias
        and not args.build_first_optional_items
    ):
        parser.error(
            "--relocate-optional-scratch-alias requires "
            "--build-first-optional-items"
        )
    if (
        args.build_3d_captured_header or args.build_3d_captured_tail
    ) and not args.build_3d_descriptor:
        parser.error(
            "--build-3d-captured-header/--build-3d-captured-tail require "
            "--build-3d-descriptor"
        )
    if (
        args.build_structural_tails
        or args.build_ta_structural_tail
        or args.build_3d_structural_tail
    ) and not (
        args.build_ta_descriptor
        and args.build_3d_descriptor
        and args.build_render_register_recipe
    ):
        parser.error(
            "--build-structural-tails requires built TA and 3D descriptors "
            "and --build-render-register-recipe"
        )
    if args.build_structural_tail_range:
        selected_kinds = {kind for kind, _start, _end in args.build_structural_tail_range}
        if "tiling" in selected_kinds and not (
            args.build_ta_structural_tail or args.build_structural_tails
        ):
            parser.error(
                "tiling --build-structural-tail-range requires "
                "--build-ta-structural-tail or --build-structural-tails"
            )
        if "fragment" in selected_kinds and not (
            args.build_3d_structural_tail or args.build_structural_tails
        ):
            parser.error(
                "fragment --build-structural-tail-range requires "
                "--build-3d-structural-tail or --build-structural-tails"
            )
        if "tiling" in selected_kinds and not args.build_ta_captured_tail:
            parser.error(
                "tiling --build-structural-tail-range requires "
                "--build-ta-captured-tail"
            )
        if "fragment" in selected_kinds and not args.build_3d_captured_tail:
            parser.error(
                "fragment --build-structural-tail-range requires "
                "--build-3d-captured-tail"
            )
    if args.omit_first_optional_item and args.build_first_optional_items:
        parser.error(
            "--omit-first-optional-item and --build-first-optional-items "
            "are mutually exclusive"
        )
    if (
        args.relocate_ta_descriptor_backreference_page
        and not args.new_first_ta_descriptor_dva
        and not args.build_ta_descriptor
    ):
        parser.error(
            "--relocate-ta-descriptor-backreference-page requires "
            "--new-first-ta-descriptor-dva or --build-ta-descriptor"
        )
    if (
        args.relocate_3d_descriptor_backreference_page
        and not args.new_first_3d_descriptor_dva
    ):
        parser.error(
            "--relocate-3d-descriptor-backreference-page requires --new-first-3d-descriptor-dva"
        )
    if args.second_outer_clear_first_submit and not args.replay_second_outer_message:
        parser.error(
            "--second-outer-clear-first-submit requires --replay-second-outer-message"
        )
    if args.append_second_inner_batch and not args.replay_second_outer_message:
        parser.error(
            "--append-second-inner-batch requires --replay-second-outer-message"
        )
    if args.prestage_control and args.resume_post_control:
        parser.error("--prestage-control and --resume-post-control are mutually exclusive")
    if args.sequence_control_doorbells and (
        args.prestage_control or args.resume_post_control
    ):
        parser.error(
            "--sequence-control-doorbells cannot be combined with "
            "--prestage-control or --resume-post-control"
        )
    if args.control_timeline and not args.sequence_control_doorbells:
        parser.error("--control-timeline requires --sequence-control-doorbells")
    if args.control_timeline and not args.replay_first_work:
        parser.error("--control-timeline requires --replay-first-work")
    if args.require_render_change and not args.watch_render_dva:
        parser.error("--require-render-change requires --watch-render-dva")
    if args.clear_watched_render_before_extra_submissions and not (
        args.replay_second_outer_message
        and args.watch_render_from_start
        and args.watch_render_dva
    ):
        parser.error(
            "--clear-watched-render-before-extra-submissions requires "
            "--replay-second-outer-message, --watch-render-from-start, and "
            "--watch-render-dva"
        )
    if args.post_control_overlay and not args.replay_first_work:
        parser.error("--post-control-overlay requires --replay-first-work")
    if args.control_producer < 1 or args.control_producer > 0x100:
        parser.error("--control-producer must be between 1 and 256")
    if args.reapply_snapshot_after_control and not (
        args.resume_post_control or args.prestage_control
    ):
        parser.error(
            "--reapply-snapshot-after-control requires --resume-post-control "
            "or --prestage-control"
        )
    if args.graft_reuse_active_queues and (
        not args.graft_submission or not args.post_control_overlay
    ):
        parser.error(
            "--graft-reuse-active-queues requires --graft-submission and "
            "--post-control-overlay"
        )
    return args


args = parse_args()
if args.control_timeline is not None:
    args.control_timeline = args.control_timeline.resolve()
stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
attempt_kind = "first_work" if args.replay_first_work else "initdata"
attempt_dir = (
    args.output_root
    / ("replay_%s_original_pa_attempt_%s" % (attempt_kind, stamp))
).resolve()
attempt_dir.mkdir(parents=True, exist_ok=False)
log_file = (attempt_dir / "replay.log").open("w", buffering=1)
sys.stdout = Tee(sys.__stdout__, log_file)
sys.stderr = Tee(sys.__stderr__, log_file)
os.chdir(attempt_dir)

from m1n1.constructutils import Ver
from m1n1.fw.asc import StandardASC
from m1n1.fw.asc.base import ASCBaseEndpoint, ASCMessage1, msg_handler
from m1n1.setup import iface, p, u
from m1n1.utils import Register64

Ver.set_version(u)


class GPUMessage(Register64):
    TYPE = 63, 48


class FirmwareEndpoint(ASCBaseEndpoint):
    BASE_MESSAGE = GPUMessage
    SHORT = "fw"

    def __init__(self, *endpoint_args, **endpoint_kwargs):
        super().__init__(*endpoint_args, **endpoint_kwargs)
        self.init_ack = False
        self.events = 0

    @msg_handler(0x09)
    def init_complete(self, msg):
        self.init_ack = True
        self.log("init ACK %#x" % int(msg))
        return True

    @msg_handler(0x42)
    def event(self, msg):
        self.events += 1
        self.log("event %#x" % int(msg))
        return True


class DoorbellEndpoint(ASCBaseEndpoint):
    BASE_MESSAGE = GPUMessage
    SHORT = "db"


def canonicalize(addr, shift):
    addr &= (1 << (shift + 1)) - 1
    if addr & (1 << shift):
        addr |= ((1 << 64) - 1) ^ ((1 << (shift + 1)) - 1)
    return addr


class CapturedAddressSpace:
    def __init__(
        self, manifest, page_relocations=None, virtual_page_overrides=None
    ):
        self.shift = int(manifest["vaddr_shift"])
        self.pages = {}
        self.context_pages = {}
        page_relocations = page_relocations or {}
        virtual_page_overrides = virtual_page_overrides or {}

        for mapping_set in manifest["root_mappings"]:
            key = (
                int(mapping_set["root_ctx_id"]),
                int(mapping_set["selector"]),
            )
            pages = {
                int(mapping["va"]) & ~(PAGE_SIZE - 1):
                page_relocations.get(
                    int(mapping["pa"]) & ~(PAGE_SIZE - 1),
                    int(mapping["pa"]) & ~(PAGE_SIZE - 1),
                )
                for mapping in mapping_set["mappings"]
            }
            previous = self.context_pages.get(key)
            if previous is None:
                self.context_pages[key] = pages
            elif previous != pages:
                # Some captures expose several unrelated hardware slots under
                # the sentinel context ID. Callers must use an unambiguous ID.
                self.context_pages[key] = False

        selected_index = int(manifest["selected_root"]["index"])
        mapping_sets = [
            item
            for item in manifest["root_mappings"]
            if int(item["root_index"]) == selected_index
        ]
        for mapping_set in mapping_sets:
            for mapping in mapping_set["mappings"]:
                va = int(mapping["va"]) & ~(PAGE_SIZE - 1)
                pa = int(mapping["pa"]) & ~(PAGE_SIZE - 1)
                pa = page_relocations.get(pa, pa)
                previous = self.pages.get(va)
                if previous is not None and previous != pa:
                    raise RuntimeError(
                        "conflicting DVA %#x mappings: %#x and %#x"
                        % (va, previous, pa)
                    )
                self.pages[va] = pa
        for va, pa in virtual_page_overrides.items():
            va = self.normalize(va) & ~(PAGE_SIZE - 1)
            if va in self.pages:
                raise RuntimeError("virtual page override collides at %#x" % va)
            self.pages[va] = int(pa) & ~(PAGE_SIZE - 1)

    def normalize(self, addr):
        return canonicalize(int(addr) & ((1 << 44) - 1), self.shift)

    def translate(self, addr, size):
        addr = self.normalize(addr)
        result = []
        while size:
            page = addr & ~(PAGE_SIZE - 1)
            offset = addr & (PAGE_SIZE - 1)
            length = min(size, PAGE_SIZE - offset)
            pa = self.pages.get(page)
            if pa is None:
                phys_base = min(M1N1_RAM_BASE, int(u.ba.phys_base))
                phys_end = int(u.ba.phys_base) + int(u.ba.mem_size_actual)
                if phys_base <= addr < phys_end:
                    pa = page
            result.append((None if pa is None else pa + offset, length))
            addr += length
            size -= length
        return result

    def translate_context(self, context_id, selector, addr, size):
        key = (int(context_id), int(selector))
        pages = self.context_pages.get(key)
        if pages is False:
            raise RuntimeError(
                "captured context %d selector %d is ambiguous" % key
            )
        if pages is None:
            raise RuntimeError(
                "capture has no context %d selector %d" % key
            )
        addr = self.normalize(addr)
        result = []
        while size:
            page = addr & ~(PAGE_SIZE - 1)
            offset = addr & (PAGE_SIZE - 1)
            length = min(size, PAGE_SIZE - offset)
            pa = pages.get(page)
            result.append((None if pa is None else pa + offset, length))
            addr += length
            size -= length
        return result

    def read_context(self, context_id, selector, addr, size):
        chunks = []
        for pa, length in self.translate_context(
            context_id, selector, addr, size
        ):
            if pa is None:
                raise RuntimeError(
                    "unmapped context-%d/%d DVA %#x" %
                    (context_id, selector, int(addr))
                )
            chunks.append(bytes(iface.readmem(pa, length)))
        return b"".join(chunks)

    def write_context(self, context_id, selector, addr, data):
        offset = 0
        for pa, length in self.translate_context(
            context_id, selector, addr, len(data)
        ):
            if pa is None:
                raise RuntimeError(
                    "unmapped context-%d/%d DVA %#x" %
                    (context_id, selector, int(addr))
                )
            iface.writemem(pa, data[offset:offset + length])
            p.dc_civac(pa, length)
            offset += length

    def read(self, addr, size):
        chunks = []
        for pa, length in self.translate(addr, size):
            if pa is None:
                raise RuntimeError("unmapped firmware DVA %#x" % int(addr))
            chunks.append(bytes(iface.readmem(pa, length)))
        return b"".join(chunks)

    def write(self, addr, data):
        offset = 0
        for pa, length in self.translate(addr, len(data)):
            if pa is None:
                raise RuntimeError("unmapped firmware DVA %#x" % int(addr))
            iface.writemem(pa, data[offset : offset + length])
            p.dc_civac(pa, length)
            offset += length


class ReplayASC(StandardASC):
    ENDPOINTS = {
        0x20: FirmwareEndpoint,
        0x21: DoorbellEndpoint,
    }

    def __init__(self, util, base, name, address_space, mailbox_trace):
        self.replay_name = name
        self.address_space = address_space
        self.mailbox_trace = mailbox_trace
        self.trace_start = time.monotonic_ns()
        super().__init__(util, base)
        self.verbose = 0
        self.mgmt.verbose = 1

    def _trace(self, operation, msg0, msg1):
        endpoint = int(msg1) & 0xff
        elapsed = time.monotonic_ns() - self.trace_start
        self.mailbox_trace.write(
            "%d %s %s ep=0x%02x msg=0x%016x\n"
            % (elapsed, self.replay_name, operation, endpoint, int(msg0))
        )
        self.mailbox_trace.flush()

    def send(self, msg0, msg1):
        self._trace("W", msg0, msg1)
        return super().send(msg0, msg1)

    def recv(self):
        msg0, msg1 = super().recv()
        if msg0 is not None:
            self._trace("R", msg0, msg1)
        return msg0, msg1

    def iotranslate(self, dva, size):
        return self.address_space.translate(dva, size)

    def ioread(self, dva, size):
        return self.address_space.read(dva, size)

    def iowrite(self, dva, data):
        self.address_space.write(dva, data)

    def ioalloc(self, size):
        raise RuntimeError(
            "%s firmware requested an uncaptured host allocation of %#x bytes"
            % (self.replay_name, size)
        )


def load_snapshot(snapshot):
    snapshot = snapshot.resolve()
    manifest_path = snapshot / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("format") != "m1n1-agx-g17p-initdata-v2":
        raise RuntimeError("snapshot is not the all-roots v2 format")
    if manifest.get("unsupported_entries"):
        raise RuntimeError("snapshot has unsupported UAT descriptors")
    ram_path = snapshot / manifest["ram_file"]
    ram = ram_path.read_bytes()
    if hashlib.sha256(ram).hexdigest() != manifest["ram_sha256"]:
        raise RuntimeError("RAM blob checksum mismatch")
    return snapshot, manifest, manifest_bytes, ram


def snapshot_mapping_pages(manifest, ram):
    """Return captured pages keyed by root identity and device address."""
    pages = {}
    for mapping_set in manifest["root_mappings"]:
        identity = (
            int(mapping_set["root_index"]),
            int(mapping_set["root_ctx_id"]),
            int(mapping_set["selector"]),
        )
        for mapping in mapping_set["mappings"]:
            blob_index = mapping.get("blob_index")
            if blob_index is None:
                continue
            dva = canonicalize(
                int(mapping["va"]) & ((1 << 44) - 1),
                int(manifest["vaddr_shift"]),
            )
            index = int(blob_index)
            data = ram[index * PAGE_SIZE:(index + 1) * PAGE_SIZE]
            if len(data) != PAGE_SIZE:
                raise RuntimeError("short RAM page at blob index %d" % index)
            pages[identity + (dva,)] = (int(mapping["pa"]), data)
    return pages


def prepare_post_control_overlay(base_manifest, base_ram, overlay_path):
    """Build only the selected-root page changes between two native boundaries."""
    overlay_path, overlay_manifest, overlay_manifest_bytes, overlay_ram = load_snapshot(
        overlay_path
    )
    if int(base_manifest["init_message"]) != int(overlay_manifest["init_message"]):
        raise RuntimeError("post-control overlay names a different initdata address")
    base_pages = snapshot_mapping_pages(base_manifest, base_ram)
    later_pages = snapshot_mapping_pages(overlay_manifest, overlay_ram)
    if set(base_pages) != set(later_pages):
        raise RuntimeError(
            "post-control overlay root maps differ: base-only=%d overlay-only=%d"
            % (
                len(set(base_pages) - set(later_pages)),
                len(set(later_pages) - set(base_pages)),
            )
        )
    changes = {}
    changed_mappings = 0
    changed_mapping_bytes = 0
    for key in sorted(base_pages):
        base_pa, base_data = base_pages[key]
        _, later_data = later_pages[key]
        if base_data == later_data:
            continue
        changed_mappings += 1
        changed_mapping_bytes += sum(
            left != right for left, right in zip(base_data, later_data)
        )
        page = changes.setdefault(
            base_pa,
            {"pa": base_pa, "data": later_data, "mapping_keys": []},
        )
        if page["data"] != later_data:
            raise RuntimeError(
                "aliases of base PA %#x disagree in post-control overlay" % base_pa
            )
        page["mapping_keys"].append(key)
    return changes, {
        "snapshot": str(overlay_path),
        "manifest_sha256": hashlib.sha256(overlay_manifest_bytes).hexdigest(),
        "ram_sha256": overlay_manifest["ram_sha256"],
        "changed_mapping_records": changed_mappings,
        "changed_mapping_bytes_against_base": changed_mapping_bytes,
        "changed_physical_pages": len(changes),
    }


def fixed_region_data(snapshot, manifest, include_coprocessor_data=False):
    regions = []
    enabled = set(REPLAY_FIXED_REGIONS)
    if include_coprocessor_data:
        enabled.update(COPROCESSOR_DATA_REGIONS)
    for region in manifest["fixed_regions"]:
        if region["name"] not in enabled:
            continue
        data = (snapshot / region["file"]).read_bytes()
        if len(data) != int(region["size"]):
            raise RuntimeError("bad size for %s" % region["name"])
        if hashlib.sha256(data).hexdigest() != region["sha256"]:
            raise RuntimeError("checksum mismatch for %s" % region["name"])
        regions.append((int(region["pa"]), data, region["name"]))
    return regions


def captured_tables(snapshot, manifest):
    records = manifest.get("table_page_records")
    tables_file = manifest.get("tables_file")
    tables_sha256 = manifest.get("tables_sha256")
    if not records or not tables_file or not tables_sha256:
        return None

    data = (snapshot / tables_file).read_bytes()
    if hashlib.sha256(data).hexdigest() != tables_sha256:
        raise RuntimeError("UAT table blob checksum mismatch")
    if len(data) != len(records) * PAGE_SIZE:
        raise RuntimeError("UAT table blob size does not match manifest")

    pages = {}
    for record in records:
        index = int(record["index"])
        page = data[index * PAGE_SIZE : (index + 1) * PAGE_SIZE]
        if hashlib.sha256(page).hexdigest() != record["sha256"]:
            raise RuntimeError("UAT table page checksum mismatch at index %d" % index)
        pages[int(record["original_pa"])] = page
    return pages


def rebuild_tables(manifest):
    shift = int(manifest["vaddr_shift"])
    l1_mask = (1 << max(0, shift - 36)) - 1
    pages = {}

    for mapping_set in manifest["root_mappings"]:
        table_pages = [int(pa) for pa in mapping_set["table_pages"]]
        mappings = mapping_set["mappings"]
        if not table_pages:
            if mappings:
                raise RuntimeError("mappings exist without table pages")
            continue

        tree = {}
        for mapping in mappings:
            raw = int(mapping["va"]) & ((1 << (shift + 1)) - 1)
            l1_index = (raw >> 36) & l1_mask
            l2_index = (raw >> 25) & 0x7ff
            l3_index = (raw >> 14) & 0x7ff
            tree.setdefault(l1_index, {}).setdefault(l2_index, {})[
                l3_index
            ] = int(mapping["pte"])

        expected = 1 + len(tree) + sum(len(l2) for l2 in tree.values())
        if len(table_pages) != expected:
            raise RuntimeError(
                "cannot infer table topology for ctx=%d selector=%d: "
                "have %d pages, expected %d"
                % (
                    mapping_set["root_ctx_id"],
                    mapping_set["selector"],
                    len(table_pages),
                    expected,
                )
            )

        cursor = 1
        root_pa = table_pages[0]
        root = bytearray(PAGE_SIZE)
        pages[root_pa] = root
        for l1_index in sorted(tree):
            l2_pa = table_pages[cursor]
            cursor += 1
            struct.pack_into("<Q", root, l1_index * 8, l2_pa | 3)
            l2_page = bytearray(PAGE_SIZE)
            pages[l2_pa] = l2_page
            for l2_index in sorted(tree[l1_index]):
                l3_pa = table_pages[cursor]
                cursor += 1
                struct.pack_into("<Q", l2_page, l2_index * 8, l3_pa | 3)
                l3_page = bytearray(PAGE_SIZE)
                pages[l3_pa] = l3_page
                for l3_index, pte in sorted(tree[l1_index][l2_index].items()):
                    struct.pack_into("<Q", l3_page, l3_index * 8, pte)

    return {pa: bytes(data) for pa, data in pages.items()}


def validate_fixed_tables(fixed_regions, table_pages):
    for table_pa, table_data in table_pages.items():
        for region_pa, region_data, region_name in fixed_regions:
            if region_pa <= table_pa < region_pa + len(region_data):
                offset = table_pa - region_pa
                captured = region_data[offset : offset + PAGE_SIZE]
                if captured != table_data:
                    raise RuntimeError(
                        "reconstructed table %#x differs from captured %s"
                        % (table_pa, region_name)
                    )


def used_heap_ranges():
    ranges = []
    cursor = int(u.heap.offset)
    for blocks, used in u.heap.blocks:
        size = int(blocks) * int(u.heap.block)
        if used:
            ranges.append((cursor, cursor + size))
        cursor += size
    return ranges


def assert_no_live_heap_overlap(addresses):
    live = used_heap_ranges()
    for start, size, label in addresses:
        end = start + size
        for used_start, used_end in live:
            if start < used_end and used_start < end:
                raise RuntimeError(
                    "%s %#x-%#x overlaps live proxy heap %#x-%#x"
                    % (label, start, end, used_start, used_end)
                )


def merge_ranges(ranges):
    merged = []
    for start, size in sorted(ranges):
        end = start + size
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [(start, end - start) for start, end in merged]


def restore_blob_pages(manifest, ram, page_overrides=None):
    page_overrides = page_overrides or {}
    pages = sorted(
        (int(page["original_pa"]), page) for page in manifest["blob_pages"]
    )
    cursor = 0
    completed = 0
    next_report = 256
    while cursor < len(pages):
        start = pages[cursor][0]
        end = start + PAGE_SIZE
        next_cursor = cursor + 1
        while (
            next_cursor < len(pages)
            and pages[next_cursor][0] == end
            and end - start < MAX_TRANSFER_SIZE
        ):
            end += PAGE_SIZE
            next_cursor += 1

        data = bytearray()
        for _, page in pages[cursor:next_cursor]:
            index = int(page["index"])
            captured = ram[index * PAGE_SIZE : (index + 1) * PAGE_SIZE]
            if hashlib.sha256(captured).hexdigest() != page["sha256"]:
                raise RuntimeError(
                    "page checksum mismatch at blob index %d" % index
                )
            replacement = page_overrides.get(int(page["original_pa"]))
            if replacement is not None:
                if len(replacement) != PAGE_SIZE:
                    raise RuntimeError(
                        "RAM page override at %#x has size %#x"
                        % (int(page["original_pa"]), len(replacement))
                    )
                captured = replacement
            data.extend(captured)
        # These snapshots are mostly zero or repeated structure bytes. m1n1's established
        # compressed upload path reduces this 320 MiB replay image to roughly 11 MiB on the
        # wire and inflates it directly at the captured physical address.
        u.compressed_writemem(start, data)
        completed += next_cursor - cursor
        if completed >= next_report or next_cursor == len(pages):
            print("  restored RAM pages %d/%d" % (completed, len(pages)))
            while next_report <= completed:
                next_report += 256
        cursor = next_cursor


def restore_snapshot(
    snapshot,
    manifest,
    ram,
    include_coprocessor_data=False,
    page_overrides=None,
):
    fixed_regions = fixed_region_data(
        snapshot, manifest, include_coprocessor_data
    )
    # Remember where the firmware shared regions landed, so a submission can be diffed
    # against them without another pass over the manifest.
    del SHARED_REGIONS[:]
    for _region_pa, _region_data, _region_name in fixed_regions:
        SHARED_REGIONS.append((_region_name, int(_region_pa), len(_region_data)))
    table_pages = captured_tables(snapshot, manifest)
    table_source = "captured"
    if table_pages is None:
        table_pages = rebuild_tables(manifest)
        table_source = "reconstructed"
    validate_fixed_tables(fixed_regions, table_pages)

    targets = []
    for page in manifest["blob_pages"]:
        targets.append((int(page["original_pa"]), PAGE_SIZE, "RAM blob page"))
    for pa, data in table_pages.items():
        targets.append((pa, len(data), "UAT table page"))
    assert_no_live_heap_overlap(targets)

    print(
        "Restoring %d RAM pages, %d %s UAT pages, and %d fixed regions"
        % (
            len(manifest["blob_pages"]),
            len(table_pages),
            table_source,
            len(fixed_regions),
        )
    )
    for pa, data, name in fixed_regions:
        print("  fixed %-22s %#x+%#x" % (name, pa, len(data)))
        iface.writemem(pa, data)

    restore_blob_pages(manifest, ram, page_overrides)

    for pa, data in table_pages.items():
        iface.writemem(pa, data)

    cache_ranges = [(pa, len(data)) for pa, data, _ in fixed_regions]
    cache_ranges.extend(
        (int(page["original_pa"]), PAGE_SIZE) for page in manifest["blob_pages"]
    )
    cache_ranges.extend((pa, len(data)) for pa, data in table_pages.items())
    for pa, size in merge_ranges(cache_ranges):
        p.dc_civac(pa, size)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")

    for root in manifest["roots"]:
        if int(root["ctx_id"]) != 0:
            continue
        gpu_region = next(
            item for item in fixed_regions if item[2] == "gpu-region"
        )
        offset = int(root["ctx_id"]) * 16
        expected = struct.unpack_from("<QQ", gpu_region[1], offset)
        actual = (
            int(p.read64(gpu_region[0] + offset)),
            int(p.read64(gpu_region[0] + offset + 8)),
        )
        if actual != expected:
            raise RuntimeError(
                "GPU root readback mismatch: expected %r, got %r"
                % (expected, actual)
            )

    return fixed_regions, table_pages


def snapshot_dva_pa(manifest, dva):
    """Physical address a captured DVA restores to, and the page's blob index."""
    mapping = selected_mapping_at(manifest, dva)
    blob_index = mapping.get("blob_index")
    if blob_index is None:
        raise RuntimeError("DVA %#x is not a captured RAM page" % dva)
    offset = canonicalize(
        int(dva) & ((1 << 44) - 1), int(manifest["vaddr_shift"])
    ) - int(mapping["va"])
    return int(mapping["pa"]) + offset, blob_index, offset


def rebuild_descriptor_objects(manifest, ram, init_message, zero_opaque,
                               zero_runs=None):
    """Overwrite the restored descriptor with one built from the field model.

    Returns a record of what was written. With ``zero_opaque`` the bytes the
    builder cannot derive are left zero instead of being copied, which tests
    whether firmware actually requires them.
    """
    import importlib.util

    agx_dir = pathlib.Path(__file__).resolve().parent.parent / "m1n1" / "agx"

    def load(name, filename):
        spec = importlib.util.spec_from_file_location(
            name, str(agx_dir / filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    g = load("g17p_layout", "g17p.py")
    b = load("g17p_builder", "g17p_initdata.py")

    root_dva = canonicalize(int(init_message) & ((1 << 44) - 1),
                            int(manifest["vaddr_shift"]))
    root_pa, _, _ = snapshot_dva_pa(manifest, root_dva)
    root_ref = bytes(iface.readmem(root_pa, b.ROOT_SIZE))
    root_built = b.rebuild_root(root_ref)

    main_dva = struct.unpack("<Q", root_ref[b.ROOT_MAIN_CONFIG:
                                           b.ROOT_MAIN_CONFIG + 8])[0]
    main_pa, _, _ = snapshot_dva_pa(manifest, main_dva)
    hwdata_dva = struct.unpack("<Q", bytes(iface.readmem(main_pa, 8)))[0]
    hwdata_pa, _, _ = snapshot_dva_pa(manifest, hwdata_dva)
    hw_ref = bytes(iface.readmem(hwdata_pa, b.HWDATA_SIZE))

    entries, flags = {}, {}
    for slot in range(b.REGISTER_SLOT_COUNT):
        base = b.REGISTER_ARRAY_OFFSET + slot * b.REGISTER_ENTRY_SIZE
        phys, va = struct.unpack_from("<QQ", hw_ref, base)
        size = struct.unpack_from("<I", hw_ref, base + 0x10)[0]
        unk = struct.unpack_from("<Q", hw_ref, base + 0x18)[0]
        flag = struct.unpack_from("<I", hw_ref, base + 0x20)[0]
        if g.is_register_va(va):
            entries[slot] = dict(phys=phys, device_va=va, size=size, flag=flag,
                                 unk_18=unk)
        elif flag:
            flags[slot] = flag

    def ladder(offset):
        return list(struct.unpack_from("<%dI" % b.LADDER_ENTRIES, hw_ref, offset))

    def column(offset):
        return [struct.unpack_from("<I", hw_ref,
                                   offset + s * b.STATE_BLOCK_STRIDE)[0]
                for s in range(b.LADDER_ENTRIES)]

    perf = {
        "freq_a": ladder(b.TABLE_GROUP_BASES[0]),
        "freq_b": ladder(b.FREQ_LADDER_B),
        "scale_b": ladder(b.SCALE_LADDER_B),
        "relative_a": ladder(b.RELATIVE_LADDER_A),
        "relative_b": ladder(b.RELATIVE_LADDER_B),
        "index_a": ladder(b.INDEX_MAP_A),
        "index_b": ladder(b.INDEX_MAP_B),
        "core_voltage": column(b.TABLE_GROUP_BASES[0] + b.GROUP_VOLTAGE_DELTA),
        "memory_voltage": column(b.TABLE_GROUP_BASES[0]
                                 + b.GROUP_MEMORY_VOLTAGE_DELTA),
        "voltage_repeat": 16,
    }
    chip_id = struct.unpack_from("<I", hw_ref, b.HWDATA_CHIP_ID)[0]
    records = []
    for index in range(2):
        base = b.REGION_RECORD_OFFSET + index * b.REGION_RECORD_STRIDE
        if struct.unpack_from("<I", hw_ref, base + b.REGION_RECORD_KIND)[0] \
                != b.REGION_RECORD_KIND_VALUE:
            break
        records.append(dict(
            lead=struct.unpack_from("<I", hw_ref, base + b.REGION_RECORD_LEAD)[0],
            value=struct.unpack_from("<I", hw_ref, base + b.REGION_RECORD_VALUE)[0],
            addr=struct.unpack_from("<Q", hw_ref, base + b.REGION_RECORD_ADDR)[0],
            size_a=struct.unpack_from("<I", hw_ref,
                                      base + b.REGION_RECORD_SIZE_A)[0],
            size_b=struct.unpack_from("<I", hw_ref,
                                      base + b.REGION_RECORD_SIZE_B)[0],
            trail=struct.unpack_from("<I", hw_ref,
                                     base + b.REGION_RECORD_TRAIL)[0]))

    derived = b.build_hwdata(entries, flags, perf, [], chip_id=chip_id,
                            region_records=records)
    runs, current = [], None
    for offset in range(len(hw_ref)):
        if hw_ref[offset] != derived[offset]:
            if current and offset <= current[1] + 8:
                current[1] = offset
            else:
                current = [offset, offset]
                runs.append(current)
    # Zero either every opaque run, or only a selected index range of them, so a
    # bisection can find which runs firmware actually requires.
    if zero_runs is not None:
        def selected(index):
            return any(first <= index < last for first, last in zero_runs)
        opaque = [(a, hw_ref[a:b_ + 1])
                  for index, (a, b_) in enumerate(runs)
                  if not selected(index)]
    elif zero_opaque:
        opaque = []
    else:
        # None makes the builder use its own recorded device constants, so the
        # descriptor comes entirely from the module and nothing is copied out of
        # the capture.
        opaque = None
    hw_built = b.build_hwdata(entries, flags, perf, opaque, chip_id=chip_id,
                              region_records=records)

    # The main configuration object, including the channel table, is built from the
    # addresses the host allocated plus named constants, with nothing opaque.
    main_ref = bytes(iface.readmem(main_pa, b.MAIN_SIZE))
    channels = []
    for index in range(b.CHANNEL_TABLE_ENTRIES):
        base = b.MAIN_CHANNEL_TABLE + index * b.CHANNEL_ENTRY_SIZE
        words = struct.unpack_from("<4Q", main_ref, base)
        channels.append((list(words[:3]), words[3]))
    addr_array = [struct.unpack_from("<Q", main_ref, b.MAIN_ADDR_ARRAY + i * 8)[0]
                  for i in range(b.MAIN_ADDR_ARRAY_COUNT)]
    triples = []
    for index in range(b.MAIN_REGION_TRIPLE_COUNT):
        base = b.MAIN_REGION_TRIPLES + index * b.MAIN_REGION_TRIPLE_STRIDE
        value = struct.unpack_from("<I", main_ref, base + 8)[0]
        kind = struct.unpack_from("<I", main_ref, base + 0xc)[0]
        triples.append((struct.unpack_from("<Q", main_ref, base)[0],
                        value if kind == b.MAIN_REGION_TRIPLE_KIND else None))
    main_built = bytearray(b.build_main_config(
        struct.unpack_from("<Q", main_ref, b.MAIN_HWDATA_ADDR)[0],
        struct.unpack_from("<Q", main_ref, b.MAIN_REPEATED_ADDR)[0],
        channels, addr_array, triples))

    # The device-control ring lives inside this object, at `+0x4c0` on the `0x40` entry stride, and
    # the word the builder writes there as a scalar field is really the ring's first entry. So a
    # rebuild overwrites the ring, and in a world resumed from a completed control phase that
    # destroys the resumed entries: the run then fails on entry 3 no longer being the `0x20`.
    # Keep whatever the restored object holds from the ring onwards.
    main_built[b.MAIN_INTERVAL:] = main_ref[b.MAIN_INTERVAL:len(main_built)]
    main_built = bytes(main_built)

    # The data region and the two status blocks the root reaches.
    region_c_dva = struct.unpack_from("<Q", root_ref, b.ROOT_REGION_C)[0]
    region_c_pa, _, _ = snapshot_dva_pa(manifest, region_c_dva)
    region_c_ref = bytes(iface.readmem(region_c_pa, b.REGION_C_SIZE))
    region_c_built = b.build_region_c()

    status_results = []
    for offset in (b.ROOT_STATUS_A, b.ROOT_STATUS_B):
        dva = struct.unpack_from("<Q", root_ref, offset)[0]
        pa, _, _ = snapshot_dva_pa(manifest, dva)
        ref = bytes(iface.readmem(pa, b.STATUS_BLOCK_SIZE))
        built = b.build_status_block()
        iface.writemem(pa, built)
        p.dc_civac(pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
        status_results.append({"offset": offset, "pa": pa,
                               "byte_exact": built == ref})

    iface.writemem(root_pa, root_built)
    iface.writemem(main_pa, main_built)
    iface.writemem(hwdata_pa, hw_built)
    iface.writemem(region_c_pa, region_c_built)
    p.dc_civac(main_pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
    p.dc_civac(region_c_pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
    def _report_diff(label, built, ref):
        # Byte-exactness alone does not say how much is left. A count and the first few differing
        # offsets size the remaining construction work for each object.
        if built == ref:
            return
        diffs = [i for i in range(min(len(built), len(ref))) if built[i] != ref[i]]
        runs = []
        for off in diffs:
            if runs and off == runs[-1][1] + 1:
                runs[-1][1] = off
            else:
                runs.append([off, off])
        print("  %s: %d of %d bytes differ in %d run(s)"
              % (label, len(diffs), len(ref), len(runs)))
        for first, last in runs[:8]:
            print("    +%#06x..+%#06x  built %s  ref %s"
                  % (first, last,
                     built[first:min(first + 8, last + 1)].hex(),
                     ref[first:min(first + 8, last + 1)].hex()))
        if len(runs) > 8:
            print("    ... and %d more run(s)" % (len(runs) - 8))

    _report_diff("data region", region_c_built, region_c_ref)
    _report_diff("main config", main_built, main_ref)
    print("Rebuilt data region at %#x (%d bytes, byte-exact: %s)"
          % (region_c_pa, len(region_c_built), region_c_built == region_c_ref))
    for result in status_results:
        print("Rebuilt status block from root +%#x at %#x (byte-exact: %s)"
              % (result["offset"], result["pa"], result["byte_exact"]))
    print("Rebuilt main config at %#x (%d bytes, byte-exact: %s)"
          % (main_pa, len(main_built), main_built == main_ref))
    p.dc_civac(root_pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
    p.dc_civac(hwdata_pa & ~(PAGE_SIZE - 1), PAGE_SIZE)

    zeroed = [[a, b_] for index, (a, b_) in enumerate(runs)
              if zero_opaque or (zero_runs and any(f <= index < l
                                                   for f, l in zero_runs))]
    opaque_bytes = sum(b_ - a + 1 for a, b_ in zeroed)
    print("Rebuilt descriptor root at %#x (%d bytes, byte-exact: %s)"
          % (root_pa, len(root_built), root_built == root_ref))
    print("Rebuilt hardware-data at %#x (%d bytes, %d of %d opaque bytes zeroed)"
          % (hwdata_pa, len(hw_built), opaque_bytes,
             sum(b_ - a + 1 for a, b_ in runs)))
    print("  hardware-data matches capture: %s" % (hw_built == hw_ref))
    return {
        "root_pa": root_pa,
        "root_dva": root_dva,
        "root_byte_exact": root_built == root_ref,
        "hwdata_pa": hwdata_pa,
        "hwdata_dva": hwdata_dva,
        "hwdata_byte_exact": hw_built == hw_ref,
        "main_pa": main_pa,
        "main_byte_exact": main_built == main_ref,
        "region_c_pa": region_c_pa,
        "region_c_byte_exact": region_c_built == region_c_ref,
        "status_blocks": status_results,
        "opaque_bytes_zeroed": opaque_bytes,
        "opaque_zeroed_all": bool(zero_opaque),
        "opaque_zero_runs": [list(r) for r in zero_runs] if zero_runs else None,
        "opaque_runs": [[a, b_] for a, b_ in runs],
        "opaque_runs_zeroed": zeroed,
        "register_entries": len(entries),
        "flag_only_slots": len(flags),
    }


def root_mapping_at(manifest, dva, root_index):
    dva = canonicalize(
        int(dva) & ((1 << 44) - 1), int(manifest["vaddr_shift"])
    )
    dva &= ~(PAGE_SIZE - 1)
    matches = []
    for mapping_set in manifest["root_mappings"]:
        if int(mapping_set["root_index"]) != int(root_index):
            continue
        for mapping in mapping_set["mappings"]:
            if int(mapping["va"]) == dva:
                matches.append(mapping)
    if len(matches) != 1:
        raise RuntimeError(
            "expected one root-%d mapping for %#x, found %d"
            % (int(root_index), dva, len(matches))
        )
    return matches[0]


def selected_mapping_at(manifest, dva):
    return root_mapping_at(
        manifest, dva, int(manifest["selected_root"]["index"])
    )


def read_snapshot_dva_u64(manifest, ram, dva):
    mapping = selected_mapping_at(manifest, dva)
    blob_index = mapping.get("blob_index")
    if blob_index is None:
        raise RuntimeError("snapshot DVA %#x is not a captured RAM page" % dva)
    offset = canonicalize(
        int(dva) & ((1 << 44) - 1), int(manifest["vaddr_shift"])
    ) - int(mapping["va"])
    if offset < 0 or offset + 8 > PAGE_SIZE:
        raise RuntimeError("snapshot DVA %#x crosses a page boundary" % dva)
    return struct.unpack_from("<Q", ram, int(blob_index) * PAGE_SIZE + offset)[0]


def read_snapshot_dva_bytes(manifest, ram, dva, size):
    """Read a selected-root range, including objects that cross UAT pages."""
    current = canonicalize(
        int(dva) & ((1 << 44) - 1), int(manifest["vaddr_shift"])
    )
    remaining = int(size)
    result = bytearray()
    while remaining:
        mapping = selected_mapping_at(manifest, current)
        blob_index = mapping.get("blob_index")
        if blob_index is None:
            raise RuntimeError(
                "snapshot DVA %#x is not a captured RAM page" % current
            )
        offset = current - int(mapping["va"])
        count = min(remaining, PAGE_SIZE - offset)
        start = int(blob_index) * PAGE_SIZE + offset
        result.extend(ram[start:start + count])
        current += count
        remaining -= count
    if len(result) != int(size):
        raise RuntimeError("short snapshot range at DVA %#x" % int(dva))
    return bytes(result)


def initdata_transitive_firmware_pages(manifest, ram, init_message, depth=16,
                                       step=1):
    """Every captured firmware-context page reachable from the descriptor by pointer.

    The hand-enumerated walk beside this one stops at the channel table, so it misses the queues,
    their pointer blocks, item rings and job list, and every item those rings name. That is why
    zeroing its complement broke a rendering run on a queue pointer that had become zero.

    It also scans at every byte offset by default rather than every eight, because this ABI holds
    pointers unaligned: the optional item's `+0x36` and `+0x4a`, and the descriptor tails' `+0x8a6`
    and `+0x945`. An aligned walk cannot see any of them, nor anything below them, and reaches 47
    pages where a byte-granular one reaches 59.
    """
    low, high = 0xfffffc2000000000, 0xfffffc2200000000
    root = canonicalize(int(init_message) & ((1 << 44) - 1),
                        int(manifest["vaddr_shift"]))
    pages = {}
    visited = set()
    frontier = [(root & ~(PAGE_SIZE - 1), 0),
                ((root + 0x8000) & ~(PAGE_SIZE - 1), 0)]
    while frontier:
        page_dva, level = frontier.pop()
        if page_dva in visited or level > depth:
            continue
        visited.add(page_dva)
        try:
            mapping = selected_mapping_at(manifest, page_dva)
        except RuntimeError:
            continue
        if mapping.get("blob_index") is None:
            continue
        pa = int(mapping["pa"]) & ~(PAGE_SIZE - 1)
        pages.setdefault(pa, page_dva)
        index = int(mapping["blob_index"])
        body = ram[index * PAGE_SIZE:(index + 1) * PAGE_SIZE]
        for offset in range(0, PAGE_SIZE - 8, step):
            value = struct.unpack_from("<Q", body, offset)[0]
            if low <= value < high:
                frontier.append((value & ~(PAGE_SIZE - 1), level + 1))
    return pages


def initdata_reachable_blob_pages(manifest, ram, init_message):
    """Return captured RAM pages reached by known initdata pointer fields."""
    pages = {}
    unresolved = []

    def keep(dva, label):
        if not dva:
            return
        try:
            mapping = selected_mapping_at(manifest, dva)
        except RuntimeError:
            unresolved.append({"label": label, "dva": int(dva)})
            return
        if mapping.get("blob_index") is None:
            return
        pa = int(mapping["pa"]) & ~(PAGE_SIZE - 1)
        pages.setdefault(pa, []).append(label)

    def read(dva):
        return read_snapshot_dva_u64(manifest, ram, dva)

    root = canonicalize(int(init_message) & ((1 << 44) - 1),
                        int(manifest["vaddr_shift"]))
    for instance, root_dva in (("primary", root),
                               ("secondary", root + 0x8000)):
        keep(root_dva, instance + ".root")
        root_targets = {
            "region_a": read(root_dva + 0x08),
            "main": read(root_dva + 0x18),
            "region_c": read(root_dva + 0x20),
            "status_a": read(root_dva + 0xa8),
            "status_b": read(root_dva + 0xb0),
        }
        for name, dva in root_targets.items():
            keep(dva, "%s.%s" % (instance, name))

        main = root_targets["main"]
        if not main:
            continue
        hwdata = read(main)
        keep(hwdata, instance + ".hwdata")
        keep(read(main + 0x08), instance + ".hwdata_repeat")
        keep(read(main + 0x10), instance + ".hwdata_repeat2")

        for channel in range(17):
            base = main + 0x20 + channel * 0x20
            for state in range(3):
                keep(read(base + state * 8),
                     "%s.ch%02d.state%d" % (instance, channel, state))
            keep(read(base + 0x18),
                 "%s.ch%02d.ring" % (instance, channel))

        for index in range(5):
            keep(read(main + 0x254 + index * 8),
                 "%s.addr%d" % (instance, index))
        for index in range(3):
            keep(read(main + 0x2d0 + index * 0x10),
                 "%s.triple%d" % (instance, index))
        if instance == "secondary":
            keep(read(main + 0x471), "secondary.extra")

        if hwdata:
            for index in range(2):
                keep(read(hwdata + 0x2610 + index * 0x40 + 0x0c),
                     "%s.hwregion%d" % (instance, index))

    return pages, unresolved


def modeled_initdata_dvas(manifest, ram, init_message):
    """Return selected-root DVAs backed by the modeled initdata closure."""
    pages, unresolved = initdata_reachable_blob_pages(
        manifest, ram, init_message
    )
    if unresolved:
        raise RuntimeError(
            "modeled initdata closure has unresolved pointers: %r" % unresolved
        )

    selected_index = int(manifest["selected_root"]["index"])
    dvas = set()
    found_pas = set()
    for mapping_set in manifest["root_mappings"]:
        if int(mapping_set["root_index"]) != selected_index:
            continue
        for mapping in mapping_set["mappings"]:
            pa = int(mapping["pa"]) & ~(PAGE_SIZE - 1)
            if pa not in pages or mapping.get("blob_index") is None:
                continue
            dvas.add(int(mapping["va"]) & ~(PAGE_SIZE - 1))
            found_pas.add(pa)
    missing = sorted(set(pages) - found_pas)
    if missing:
        raise RuntimeError(
            "modeled physical pages have no selected-root DVA: %s" %
            ", ".join("%#x" % pa for pa in missing)
        )
    return sorted(dvas)


def zero_transitive_extra_firmware_pages(manifest, ram, init_message,
                                         rebuilt_compute_work, page_slice):
    """Remove unmodeled transitive pages without erasing rebuilt compute.

    The byte-granular closure is deliberately permissive so it does not miss
    unaligned pointers, but it also follows pointer-shaped payload values.  The
    explicit closure follows only fields whose pointer role is modeled.  Their
    difference is therefore the useful next subtraction set.  Run this after
    the pending compute graph has been rebuilt, and protect every physical page
    touched by that builder, so the test changes lifecycle/config state rather
    than the command under test.
    """
    transitive = initdata_transitive_firmware_pages(
        manifest, ram, init_message)
    explicit, unresolved = initdata_reachable_blob_pages(
        manifest, ram, init_message)
    if unresolved:
        raise RuntimeError(
            "modeled initdata closure has unresolved pointers: %r" % unresolved
        )

    protected = set()
    protected_objects = []
    for obj in rebuilt_compute_work.get("objects", ()):
        start = int(obj["dva"]) & ~(PAGE_SIZE - 1)
        end = (
            int(obj["dva"]) + int(obj["size"]) + PAGE_SIZE - 1
        ) & ~(PAGE_SIZE - 1)
        object_pages = []
        for dva in range(start, end, PAGE_SIZE):
            mapping = selected_mapping_at(manifest, dva)
            pa = int(mapping["pa"]) & ~(PAGE_SIZE - 1)
            protected.add(pa)
            object_pages.append({"dva": dva, "pa": pa})
        protected_objects.append({
            "name": obj["name"],
            "dva": int(obj["dva"]),
            "size": int(obj["size"]),
            "pages": object_pages,
        })

    candidates = sorted(
        (
            {"pa": pa, "dva": int(transitive[pa])}
            for pa in set(transitive) - set(explicit) - protected
        ),
        key=lambda item: (item["dva"], item["pa"]),
    )
    first, last = page_slice
    if last is None:
        last = len(candidates)
    if first > last or first < 0 or last > len(candidates):
        raise RuntimeError(
            "transitive-extra slice %d:%d exceeds %d candidates" %
            (first, last, len(candidates))
        )
    selected = candidates[first:last]
    for item in selected:
        p.memset32(item["pa"], 0, PAGE_SIZE)
        p.dc_civac(item["pa"], PAGE_SIZE)
    u.inst("dsb sy")
    print(
        "Transitive firmware closure: %d pages; explicit model: %d; "
        "rebuilt compute protects %d; zeroed extra slice %d:%d (%d/%d pages)"
        % (
            len(transitive), len(explicit), len(protected), first, last,
            len(selected), len(candidates),
        )
    )
    if selected:
        print(
            "  zeroed DVA range %#x..%#x" %
            (selected[0]["dva"], selected[-1]["dva"])
        )
    return {
        "transitive_pages": len(transitive),
        "explicit_pages": len(explicit),
        "protected_pages": len(protected),
        "candidate_pages": len(candidates),
        "slice": [first, last],
        "zeroed": selected,
        "protected_objects": protected_objects,
    }


def graft_source_config_pages(manifest, snapshot, dvas,
                              rebuilt_compute_work, address_space,
                              work_state):
    """Substitute coherent source-built pages into a positive replay world."""
    snapshot = pathlib.Path(snapshot)
    page_manifest = json.loads((snapshot / "pages.json").read_text())
    page_blob = (snapshot / "pages.bin").read_bytes()
    if int(page_manifest["page_size"]) != PAGE_SIZE:
        raise RuntimeError("source config snapshot has an unexpected page size")
    source_pages = {
        int(page["dva"]): page
        for page in page_manifest["pages"]
        if page["translation"] == "firmware-high"
    }

    preserved_compute_objects = []
    for obj in rebuilt_compute_work.get("objects", ()):
        dva = int(obj["dva"])
        size = int(obj["size"])
        preserved_compute_objects.append({
            "name": obj["name"],
            "dva": dva,
            "size": size,
            "body": address_space.read(dva, size),
        })

    preserved_work_state = []
    for channel in work_state["channels"]:
        if not channel.get("captured_producer") or channel.get("disabled"):
            continue
        for index, state_dva in enumerate(channel["state_addrs"]):
            preserved_work_state.append({
                "channel": channel["name"],
                "index": index,
                "dva": int(state_dva),
                "value": read_dva_u32(address_space, state_dva),
            })

    records = []
    for requested in dvas:
        dva = int(requested) & ~(PAGE_SIZE - 1)
        source = source_pages.get(dva)
        if source is None:
            raise RuntimeError(
                "source config snapshot has no firmware-high page %#x" % dva
            )
        offset = int(source["capture_offset"])
        body = page_blob[offset:offset + PAGE_SIZE]
        if len(body) != PAGE_SIZE:
            raise RuntimeError("source config page %#x is truncated" % dva)
        mapping = selected_mapping_at(manifest, dva)
        pa = int(mapping["pa"]) & ~(PAGE_SIZE - 1)
        before = bytes(iface.readmem(pa, PAGE_SIZE))
        p.memset32(pa, 0, PAGE_SIZE)
        iface.writemem(pa, body)
        p.dc_civac(pa, PAGE_SIZE)
        differences = sum(left != right for left, right in zip(before, body))
        records.append({
            "dva": dva,
            "pa": pa,
            "different_bytes": differences,
            "sha256": hashlib.sha256(body).hexdigest(),
        })
        print(
            "Grafted source config DVA %#x at PA %#x (%d differing bytes)"
            % (dva, pa, differences)
        )
    for obj in preserved_compute_objects:
        address_space.write(obj["dva"], obj["body"])
    for state in preserved_work_state:
        write_dva_u32(address_space, state["dva"], state["value"])
    u.inst("dsb sy")
    if preserved_compute_objects:
        print(
            "  restored %d rebuilt compute objects after source graft" %
            len(preserved_compute_objects)
        )
    if preserved_work_state:
        print(
            "  preserved active work state: %s" % ", ".join(
                "%s[%d]=%d" % (
                    state["channel"], state["index"], state["value"])
                for state in preserved_work_state
            )
        )
    return {
        "snapshot": str(snapshot),
        "pages": records,
        "preserved_compute_objects": [
            {
                "name": obj["name"],
                "dva": obj["dva"],
                "size": obj["size"],
            }
            for obj in preserved_compute_objects
        ],
        "preserved_work_state": preserved_work_state,
    }


def first_work_descriptor_mappings(manifest, ram, init_message):
    init_dva = canonicalize(
        int(init_message) & ((1 << 44) - 1), int(manifest["vaddr_shift"])
    )
    region_b = read_snapshot_dva_u64(manifest, ram, init_dva + 0x18)
    descriptors = []
    for pair_index, name in enumerate(("TA_0", "3D_0")):
        channel_index = selected_first_work_index(pair_index)
        channel = region_b + 0x20 + channel_index * 0x20
        ring_dva = read_snapshot_dva_u64(manifest, ram, channel + 0x18)
        queue_dva = read_snapshot_dva_u64(
            manifest, ram, queue_slot_base(ring_dva) + 8
        )
        entry_array_dva = read_snapshot_dva_u64(manifest, ram, queue_dva + 8)
        descriptor_dva = read_snapshot_dva_u64(manifest, ram, entry_array_dva)
        mapping = dict(selected_mapping_at(manifest, descriptor_dva))
        mapping["descriptor_dva"] = descriptor_dva
        descriptors.append(
            (name, mapping)
        )
    return descriptors


def first_work_direct_target_mappings(manifest, ram, init_message):
    targets = {}
    for name, descriptor_mapping in first_work_descriptor_mappings(
        manifest, ram, init_message
    ):
        descriptor_dva = int(
            descriptor_mapping.get("descriptor_dva", descriptor_mapping["va"])
        )
        for offset in FIRST_WORK_DIRECT_POINTER_OFFSETS[name]:
            target_dva = read_snapshot_dva_u64(
                manifest, ram, descriptor_dva + offset
            )
            mapping = selected_mapping_at(manifest, target_dva)
            page_dva = int(mapping["va"])
            target = targets.setdefault(
                page_dva,
                {"mapping": mapping, "sources": []},
            )
            target["sources"].append("%s+%#x" % (name, offset))

    result = []
    for page_dva in sorted(targets):
        target = targets[page_dva]
        result.append(
            (
                "first-work-direct-target-" + "+".join(target["sources"]),
                target["mapping"],
            )
        )
    return result


def first_work_support_item_mappings(manifest, ram, init_message):
    targets = {}
    for channel_index, name in enumerate(("TA_0", "3D_0")):
        entry_array_dva = first_work_entry_array_dva(
            manifest, ram, init_message, channel_index
        )
        for item_index in (1, 2):
            item_dva = read_snapshot_dva_u64(
                manifest, ram, entry_array_dva + item_index * 8
            )
            mapping = selected_mapping_at(manifest, item_dva)
            page_dva = int(mapping["va"])
            target = targets.setdefault(
                page_dva,
                {"mapping": mapping, "sources": []},
            )
            target["sources"].append("%s-entry%d" % (name, item_index))

    return [
        (
            "first-work-support-item-" + "+".join(targets[page]["sources"]),
            targets[page]["mapping"],
        )
        for page in sorted(targets)
    ]


def first_work_entry_array_dva(manifest, ram, init_message, channel_index):
    init_dva = canonicalize(
        int(init_message) & ((1 << 44) - 1), int(manifest["vaddr_shift"])
    )
    region_b = read_snapshot_dva_u64(manifest, ram, init_dva + 0x18)
    channel = (
        region_b
        + 0x20
        + selected_first_work_index(channel_index) * 0x20
    )
    ring_dva = read_snapshot_dva_u64(manifest, ram, channel + 0x18)
    queue_dva = read_snapshot_dva_u64(
        manifest, ram, queue_slot_base(ring_dva) + 8
    )
    return read_snapshot_dva_u64(manifest, ram, queue_dva + 8)


def first_work_descriptor_backreference(
    manifest, ram, init_message, channel_name
):
    channel_indexes = {"TA_0": 0, "3D_0": 1}
    descriptor_mapping = dict(
        first_work_descriptor_mappings(manifest, ram, init_message)
    )[channel_name]
    descriptor_dva = int(
        descriptor_mapping.get("descriptor_dva", descriptor_mapping["va"])
    )
    entry_array_dva = first_work_entry_array_dva(
        manifest, ram, init_message, channel_indexes[channel_name]
    )
    selected_index = int(manifest["selected_root"]["index"])
    matches = []

    for mapping_set in manifest["root_mappings"]:
        if int(mapping_set["root_index"]) != selected_index:
            continue
        for mapping in mapping_set["mappings"]:
            blob_index = mapping.get("blob_index")
            if blob_index is None:
                continue
            page = ram[
                int(blob_index) * PAGE_SIZE : (int(blob_index) + 1) * PAGE_SIZE
            ]
            for offset in range(0, PAGE_SIZE, 8):
                if struct.unpack_from("<Q", page, offset)[0] != descriptor_dva:
                    continue
                source_dva = int(mapping["va"]) + offset
                if source_dva == entry_array_dva:
                    continue
                matches.append((mapping, offset))

    if not matches:
        raise RuntimeError(
            "expected a non-queue %s descriptor back-reference, found none"
            % channel_name
        )
    if len(matches) > 1:
        # A world captured after a host has submitted more than once holds a reference per
        # submission that named this descriptor. They are the same descriptor seen from several
        # places, so any one of them redirects it; take the last, which is the most recent
        # submission's, and say so rather than refusing a world that is merely further along.
        print("  %s descriptor %#x has %d back-references; taking the last"
              % (channel_name, descriptor_dva, len(matches)))
    mapping, offset = matches[-1]
    return {
        "mapping": mapping,
        "offset": offset,
        "source_dva": int(mapping["va"]) + offset,
        "original_descriptor_dva": descriptor_dva,
    }


def first_ta_descriptor_backreference(manifest, ram, init_message):
    return first_work_descriptor_backreference(
        manifest, ram, init_message, "TA_0"
    )


def first_3d_descriptor_backreference(manifest, ram, init_message):
    return first_work_descriptor_backreference(
        manifest, ram, init_message, "3D_0"
    )


def relocate_mapping_page(manifest, ram, table_pages, mapping, label):
    original_pa = int(mapping["pa"]) & ~(PAGE_SIZE - 1)
    blob_index = int(mapping["blob_index"])
    captured = ram[blob_index * PAGE_SIZE : (blob_index + 1) * PAGE_SIZE]
    if len(captured) != PAGE_SIZE:
        raise RuntimeError("captured page is absent from the RAM blob")

    pte = int(mapping["pte"])
    matches = []
    for table_pa, table_data in table_pages.items():
        for offset in range(0, PAGE_SIZE, 8):
            if struct.unpack_from("<Q", table_data, offset)[0] == pte:
                matches.append((table_pa, offset))
    if len(matches) != 1:
        raise RuntimeError(
            "expected one initdata UAT leaf PTE, found %d" % len(matches)
        )

    relocated_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
    iface.writemem(relocated_pa, captured)
    p.dc_civac(relocated_pa, PAGE_SIZE)

    table_pa, table_offset = matches[0]
    relocated_pte = (pte & ~TABLE_ADDR_MASK) | (relocated_pa & TABLE_ADDR_MASK)
    iface.writemem(table_pa + table_offset, struct.pack("<Q", relocated_pte))
    p.dc_civac(table_pa + table_offset, 8)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")

    return {
        "label": label,
        "dva": int(mapping["va"]),
        "original_pa": original_pa,
        "relocated_pa": relocated_pa,
        "table_pa": table_pa,
        "table_offset": table_offset,
        "original_pte": pte,
        "relocated_pte": relocated_pte,
    }


def context_mapping(manifest, dva, context):
    """The captured mapping for a device address in one UAT context."""
    page = int(dva) & ~(PAGE_SIZE - 1)
    for group in manifest["root_mappings"]:
        for mapping in group["mappings"]:
            if mapping.get("root_ctx_id") != int(context):
                continue
            if int(mapping["va"]) != page:
                continue
            if mapping.get("blob_index") is None:
                raise RuntimeError(
                    "context-%d page %#x has no captured contents" %
                    (int(context), int(dva))
                )
            return mapping
    raise RuntimeError(
        "no context-%d mapping covers %#x" % (int(context), int(dva))
    )


def render_context_mapping(manifest, dva):
    """The render context's captured mapping covering this device address.

    Register data carries addresses in a translation context separate from the
    firmware's, and that context's tables are captured and restored like any other, so
    a page of render state can be relocated the same way a firmware object can. This
    finds the mapping by context identifier rather than by scanning every root, because
    several roots cover overlapping ranges.
    """
    return context_mapping(manifest, dva, int(args.watch_context))


def selected_l3_location(manifest, table_pages, dva):
    shift = int(manifest["vaddr_shift"])
    raw = int(dva) & ((1 << (shift + 1)) - 1)
    l1_mask = (1 << max(0, shift - 36)) - 1
    l1_index = (raw >> 36) & l1_mask
    l2_index = (raw >> 25) & 0x7FF
    l3_index = (raw >> 14) & 0x7FF

    root_pa = int(manifest["selected_root"]["root1_pa"])
    if root_pa not in table_pages:
        raise RuntimeError("selected root page %#x is not captured" % root_pa)
    l1_pte = struct.unpack_from("<Q", table_pages[root_pa], l1_index * 8)[0]
    if (l1_pte & 3) != 3:
        raise RuntimeError("selected root has no L2 table for DVA %#x" % dva)
    l2_pa = l1_pte & TABLE_ADDR_MASK
    if l2_pa not in table_pages:
        raise RuntimeError("selected L2 page %#x is not captured" % l2_pa)
    l2_pte = struct.unpack_from("<Q", table_pages[l2_pa], l2_index * 8)[0]
    if (l2_pte & 3) != 3:
        raise RuntimeError("selected root has no L3 table for DVA %#x" % dva)
    l3_pa = l2_pte & TABLE_ADDR_MASK
    if l3_pa not in table_pages:
        raise RuntimeError("selected L3 page %#x is not captured" % l3_pa)
    return raw, l3_pa, l3_index


def context_root_pa(manifest, context, selector):
    for group in manifest["root_mappings"]:
        if (
            int(group.get("root_ctx_id", -1)) == context
            and int(group.get("selector", -1)) == selector
            and group.get("root_pa")
        ):
            return int(group["root_pa"])
    raise RuntimeError(
        "no context-%d selector-%d root in this snapshot"
        % (context, selector)
    )


def root_l3_location(manifest, table_pages, root_pa, dva):
    shift = int(manifest["vaddr_shift"])
    raw = int(dva) & ((1 << (shift + 1)) - 1)
    l1_mask = (1 << max(0, shift - 36)) - 1
    l1_index = (raw >> 36) & l1_mask
    l2_index = (raw >> 25) & 0x7FF
    l3_index = (raw >> 14) & 0x7FF
    if root_pa not in table_pages:
        raise RuntimeError("root page %#x is not captured" % root_pa)
    l1_pte = struct.unpack_from("<Q", table_pages[root_pa], l1_index * 8)[0]
    if (l1_pte & 3) != 3:
        raise RuntimeError("root has no L2 table for DVA %#x" % dva)
    l2_pa = l1_pte & TABLE_ADDR_MASK
    l2_pte = struct.unpack_from("<Q", table_pages[l2_pa], l2_index * 8)[0]
    if (l2_pte & 3) != 3:
        raise RuntimeError("root has no L3 table for DVA %#x" % dva)
    l3_pa = l2_pte & TABLE_ADDR_MASK
    if l3_pa not in table_pages:
        raise RuntimeError("L3 page %#x is not captured" % l3_pa)
    return raw, l3_pa, l3_index


def load_control_timeline(path, final_producer):
    """Load the exact uninterrupted control prefix needed to reach final_producer."""
    rows = [
        json.loads(line)
        for line in pathlib.Path(path).read_text().splitlines()
        if line.strip()
    ]
    if not rows or rows[0].get("initial_counters") != [0, 0, 1]:
        raise RuntimeError(
            "control timeline must start with counters [0, 0, 1]"
        )

    by_index = {}
    for row in rows[1:]:
        absolute_index = row.get("absolute_index")
        if absolute_index is None or absolute_index in by_index:
            continue
        by_index[int(absolute_index)] = row

    records = []
    for absolute_index in range(1, int(final_producer)):
        record = by_index.get(absolute_index)
        if record is None:
            raise RuntimeError(
                "control timeline has no record at absolute index %d"
                % absolute_index
            )
        if (
            int(record.get("producer_before", -1)) != absolute_index
            or int(record.get("producer_after", -1)) != absolute_index + 1
        ):
            raise RuntimeError(
                "control record %d is not a single producer transition: %r -> %r"
                % (
                    absolute_index,
                    record.get("producer_before"),
                    record.get("producer_after"),
                )
            )
        entry = bytes.fromhex(record["entry_hex"])
        if len(entry) != CONTROL_ENTRY_SIZE:
            raise RuntimeError(
                "control record %d has a %#x-byte entry"
                % (absolute_index, len(entry))
            )
        channel_control = bytes.fromhex(record["channel_control_hex"])
        if len(channel_control) != CHANNEL_CONTROL_BYTES:
            raise RuntimeError(
                "control record %d has a %#x-byte channel-control block"
                % (absolute_index, len(channel_control))
            )
        records.append(record)
    return records


class ExactControlTimelineReplay:
    """Map and restore every host-visible input captured before a control record."""

    def __init__(
        self,
        manifest,
        table_pages,
        virtual_page_overrides,
        timeline_path,
        final_producer,
    ):
        self.manifest = manifest
        self.table_pages = table_pages
        self.virtual_page_overrides = virtual_page_overrides
        self.records = load_control_timeline(timeline_path, final_producer)
        self.records_by_index = {
            int(record["absolute_index"]): record for record in self.records
        }
        self.shift = int(manifest["vaddr_shift"])
        self.selected_index = int(manifest["selected_root"]["index"])
        self.selected_root = {
            "context": int(manifest["selected_root"]["ctx_id"]),
            "index": self.selected_index,
            "type": 8,
        }
        self.pages = {}
        self.new_direct_pages = 0
        self.new_table_pages = 0
        self.resource_spans = []
        self.attr_patches = 0
        self._selected_manifest_pages = {
            int(mapping["va"]) & ~(PAGE_SIZE - 1)
            for group in manifest["root_mappings"]
            if int(group["root_index"]) == self.selected_index
            for mapping in group["mappings"]
        }
        self._prepare_pages()

    def _page_dva(self, dva):
        return canonicalize(
            int(dva) & ((1 << (self.shift + 1)) - 1), self.shift
        ) & ~(PAGE_SIZE - 1)

    @staticmethod
    def _selector(root):
        return 1 if int(root.get("type", 4)) == 8 else 0

    def _root_pa(self, root):
        return context_root_pa(
            self.manifest, int(root["context"]), self._selector(root)
        )

    @staticmethod
    def _table_descriptor_attrs(table):
        for offset in range(0, PAGE_SIZE, 8):
            candidate = struct.unpack_from("<Q", table, offset)[0]
            if candidate & 3 == 3:
                return candidate & ~TABLE_ADDR_MASK
        return 3

    def _install_table(self, parent_pa, index):
        parent = bytearray(self.table_pages[parent_pa])
        child_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
        p.memset32(child_pa, 0, PAGE_SIZE)
        p.dc_civac(child_pa, PAGE_SIZE)
        child = bytes(PAGE_SIZE)
        self.table_pages[child_pa] = child
        descriptor = self._table_descriptor_attrs(parent) | child_pa
        struct.pack_into("<Q", parent, index * 8, descriptor)
        body = bytes(parent)
        iface.writemem(parent_pa, body)
        p.dc_civac(parent_pa, PAGE_SIZE)
        self.table_pages[parent_pa] = body
        self.new_table_pages += 1
        return child_pa

    def _leaf(self, root, dva):
        root_pa = self._root_pa(root)
        raw = int(dva) & ((1 << (self.shift + 1)) - 1)
        l1_mask = (1 << max(0, self.shift - 36)) - 1
        l1_index = (raw >> 36) & l1_mask
        l2_index = (raw >> 25) & 0x7FF
        l3_index = (raw >> 14) & 0x7FF

        l1 = self.table_pages[root_pa]
        l1_pte = struct.unpack_from("<Q", l1, l1_index * 8)[0]
        if l1_pte & 3 == 3:
            l2_pa = l1_pte & TABLE_ADDR_MASK
            if l2_pa not in self.table_pages:
                raise RuntimeError("captured L2 table %#x is absent" % l2_pa)
        elif l1_pte & 3:
            raise RuntimeError(
                "unsupported root descriptor %#x for DVA %#x" % (l1_pte, dva)
            )
        else:
            l2_pa = self._install_table(root_pa, l1_index)

        l2 = self.table_pages[l2_pa]
        l2_pte = struct.unpack_from("<Q", l2, l2_index * 8)[0]
        if l2_pte & 3 == 3:
            l3_pa = l2_pte & TABLE_ADDR_MASK
            if l3_pa not in self.table_pages:
                raise RuntimeError("captured L3 table %#x is absent" % l3_pa)
        elif l2_pte & 3:
            raise RuntimeError(
                "unsupported L2 descriptor %#x for DVA %#x" % (l2_pte, dva)
            )
        else:
            l3_pa = self._install_table(l2_pa, l2_index)

        pte = struct.unpack_from(
            "<Q", self.table_pages[l3_pa], l3_index * 8
        )[0]
        return root_pa, l3_pa, l3_index, pte

    def _record_page(self, root, dva, pa, pte):
        page_dva = self._page_dva(dva)
        key = (int(root["index"]), page_dva)
        self.pages[key] = {
            "root": dict(root),
            "dva": page_dva,
            "pa": int(pa) & ~(PAGE_SIZE - 1),
            "pte": int(pte),
        }
        if (
            int(root["index"]) == self.selected_index
            and page_dva not in self._selected_manifest_pages
        ):
            previous = self.virtual_page_overrides.get(page_dva)
            if previous is not None and int(previous) != int(pa):
                raise RuntimeError(
                    "control timeline DVA %#x conflicts with an existing override"
                    % page_dva
                )
            self.virtual_page_overrides[page_dva] = int(pa)
        return self.pages[key]

    def ensure_page(self, root, dva, exact_leaf=None):
        page_dva = self._page_dva(dva)
        key = (int(root["index"]), page_dva)
        page = self.pages.get(key)
        if page is not None:
            return page

        _root_pa, l3_pa, l3_index, current = self._leaf(root, page_dva)
        if current & 3:
            pa = current & TABLE_ADDR_MASK
        else:
            if exact_leaf is None:
                raise RuntimeError(
                    "control timeline page %#x in root %d is absent and has no leaf attributes"
                    % (page_dva, int(root["index"]))
                )
            pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
            p.memset32(pa, 0, PAGE_SIZE)
            p.dc_civac(pa, PAGE_SIZE)
            self.new_direct_pages += 1

        desired = current
        if exact_leaf is not None:
            desired = (int(exact_leaf) & ~TABLE_ADDR_MASK) | pa
        elif not (current & 3):
            raise RuntimeError("cannot synthesize attributes for %#x" % page_dva)

        if desired != current:
            offset = l3_index * 8
            data = bytearray(self.table_pages[l3_pa])
            struct.pack_into("<Q", data, offset, desired)
            body = bytes(data)
            iface.writemem(l3_pa, body)
            p.dc_civac(l3_pa, PAGE_SIZE)
            self.table_pages[l3_pa] = body
            if current & 3:
                self.attr_patches += 1

        return self._record_page(root, page_dva, pa, desired)

    def ensure_zero_span(self, root, start, size, exact_leaf):
        """Map every absent page in one native resource allocation as zero."""
        missing = []
        for offset in range(0, int(size), PAGE_SIZE):
            dva = int(start) + offset
            _root_pa, l3_pa, l3_index, current = self._leaf(root, dva)
            if not (current & 3):
                missing.append((dva, l3_pa, l3_index))
        if not missing:
            return 0

        base = u.memalign(PAGE_SIZE, len(missing) * PAGE_SIZE)
        p.memset32(base, 0, len(missing) * PAGE_SIZE)
        p.dc_civac(base, len(missing) * PAGE_SIZE)
        dirty = {}
        attrs = int(exact_leaf) & ~TABLE_ADDR_MASK
        for page_index, (dva, l3_pa, l3_index) in enumerate(missing):
            pa = base + page_index * PAGE_SIZE
            pte = attrs | pa
            table = dirty.setdefault(
                l3_pa, bytearray(self.table_pages[l3_pa])
            )
            struct.pack_into("<Q", table, l3_index * 8, pte)
            self._record_page(root, dva, pa, pte)
        for l3_pa, table in dirty.items():
            body = bytes(table)
            iface.writemem(l3_pa, body)
            p.dc_civac(l3_pa, PAGE_SIZE)
            self.table_pages[l3_pa] = body
        self.resource_spans.append(
            {
                "root_index": int(root["index"]),
                "dva": int(start),
                "size": int(size),
                "new_pages": len(missing),
            }
        )
        return len(missing)

    def _prepare_pages(self):
        # Later registration tables name new 1 MiB client allocations. The old pre-kick
        # snapshot predates twelve of them, so map their complete ranges before firmware can
        # validate the table. Their contents are initially zero; exact captured target pages are
        # restored over the relevant first pages at publication time.
        target_attrs = {}
        for record in self.records:
            root = record.get("operand_target_root")
            if root is not None:
                target_attrs[int(root["index"])] = int(root["leaf_value"])
        missing_starts = {}
        for record in self.records:
            table_hex = record.get("operand_table_hex")
            root = record.get("operand_table_root")
            if not table_hex or root is None:
                continue
            root_index = int(root["index"])
            exact_leaf = target_attrs.get(root_index)
            if exact_leaf is None:
                continue
            table = bytes.fromhex(table_hex)
            for offset in range(0, len(table), 8):
                value = struct.unpack_from("<Q", table, offset)[0]
                target = value & 0x0FFFFFFFFFFFFFFF
                if (
                    value >> 60 != 1
                    or target & (PAGE_SIZE - 1)
                    or not 0x7000000000 <= target < 0x8000000000
                ):
                    continue
                _root_pa, _l3_pa, _l3_index, current = self._leaf(root, target)
                if not (current & 3):
                    missing_starts[(root_index, target)] = (root, exact_leaf)
        for (_root_index, target), (root, exact_leaf) in sorted(
            missing_starts.items()
        ):
            self.ensure_zero_span(
                root, target, CONTROL_RESOURCE_BYTES, exact_leaf
            )

        # Establish every directly captured object mapping before firmware starts. Existing
        # physical backing is retained, but its leaf attributes are made byte-exact with the
        # native capture. Missing pages receive host-owned backing.
        self.ensure_page(self.selected_root, CHANNEL_CONTROL_DVA)
        fields = (
            ("first_object", "first_object_root"),
            ("first_state", "first_state_root"),
            ("first_low_object", "first_low_object_root"),
            ("operand_table", "operand_table_root"),
            ("operand_target", "operand_target_root"),
        )
        for record in self.records:
            for address_name, root_name in fields:
                address = int(record.get(address_name, 0) or 0)
                root = record.get(root_name)
                if not address or root is None:
                    continue
                self.ensure_page(root, address, int(root["leaf_value"]))

        u.inst("dsb sy")
        u.inst("tlbi vmalle1os")
        u.inst("dsb sy")
        u.inst("isb")

    def write(self, root, dva, body):
        offset = 0
        while offset < len(body):
            address = int(dva) + offset
            page = self.ensure_page(root, address)
            page_offset = address & (PAGE_SIZE - 1)
            length = min(len(body) - offset, PAGE_SIZE - page_offset)
            pa = page["pa"] + page_offset
            iface.writemem(pa, body[offset : offset + length])
            p.dc_civac(pa, length)
            offset += length

    def restore_record(self, address_space, work_state, absolute_index):
        record = self.records_by_index[int(absolute_index)]
        fields = (
            ("first_object", "first_object_hex", "first_object_root"),
            ("first_state", "first_state_hex", "first_state_root"),
            ("first_low_object", "first_low_object_hex", "first_low_object_root"),
            ("operand_table", "operand_table_hex", "operand_table_root"),
            ("operand_target", "operand_target_hex", "operand_target_root"),
            # The slot is part of the operand table. Apply it last so its exact 64-byte
            # pre-publication image wins over the full-page table capture.
            ("operand_slot", "operand_slot_hex", "operand_slot_root"),
        )
        for address_name, body_name, root_name in fields:
            address = int(record.get(address_name, 0) or 0)
            body_hex = record.get(body_name)
            root = record.get(root_name)
            if address and body_hex and root is not None:
                self.write(root, address, bytes.fromhex(body_hex))

        self.write(
            self.selected_root,
            CHANNEL_CONTROL_DVA,
            bytes.fromhex(record["channel_control_hex"]),
        )
        slot = int(absolute_index) % CONTROL_ENTRY_COUNT
        address_space.write(
            int(work_state["control_ring_addr"]) + slot * CONTROL_ENTRY_SIZE,
            bytes.fromhex(record["entry_hex"]),
        )
        u.inst("dsb sy")
        return {
            "absolute_index": int(absolute_index),
            "opcode": struct.unpack_from(
                "<I", bytes.fromhex(record["entry_hex"])
            )[0],
        }

    def summary(self, path):
        report = {
            "format": "m1n1-g17p-exact-control-timeline-replay-v1",
            "timeline": str(path),
            "record_count": len(self.records),
            "first_absolute_index": int(self.records[0]["absolute_index"]),
            "last_absolute_index": int(self.records[-1]["absolute_index"]),
            "new_direct_pages": self.new_direct_pages,
            "new_table_pages": self.new_table_pages,
            "attribute_patches": self.attr_patches,
            "resource_spans": self.resource_spans,
        }
        (attempt_dir / "control_timeline_replay.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        return report


def map_built_context_page(
    manifest,
    table_pages,
    source_dva,
    payload,
    label,
    context,
    selector,
    target_pa=None,
):
    """Install a fresh leaf near ``source_dva`` in a specific UAT root."""
    root_pa = context_root_pa(manifest, context, selector)
    raw, l3_pa, source_index = root_l3_location(
        manifest, table_pages, root_pa, source_dva)
    l3_data = table_pages[l3_pa]
    source_pte = struct.unpack_from("<Q", l3_data, source_index * 8)[0]
    if (source_pte & 3) == 0:
        raise RuntimeError("source DVA %#x is not mapped" % source_dva)

    free_index = None
    for distance in range(1, 0x800):
        index = (source_index + distance) & 0x7ff
        if (struct.unpack_from("<Q", l3_data, index * 8)[0] & 3) == 0:
            free_index = index
            break
    if free_index is None:
        raise RuntimeError("no free context-%d UAT leaf" % context)

    shift = int(manifest["vaddr_shift"])
    target_raw = (raw & ~(0x7ff << 14)) | (free_index << 14)
    target_dva = canonicalize(target_raw, shift)
    if target_pa is None:
        target_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
        iface.writemem(
            target_pa,
            payload[:PAGE_SIZE] + bytes(max(0, PAGE_SIZE - len(payload))),
        )
        p.dc_civac(target_pa, PAGE_SIZE)

    target_pte = (
        source_pte & ~TABLE_ADDR_MASK
    ) | (int(target_pa) & TABLE_ADDR_MASK)
    table_offset = free_index * 8
    iface.writemem(l3_pa + table_offset, struct.pack("<Q", target_pte))
    p.dc_civac(l3_pa + table_offset, 8)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")
    table_pages[l3_pa] = (
        l3_data[:table_offset]
        + struct.pack("<Q", target_pte)
        + l3_data[table_offset + 8:]
    )
    return {
        "label": label,
        "context": context,
        "selector": selector,
        "dva": target_dva,
        "source_dva": int(source_dva),
        "relocated_pa": int(target_pa),
        "table_pa": l3_pa,
        "table_offset": table_offset,
        "relocated_pte": target_pte,
    }


def map_built_context_pages(
    manifest,
    table_pages,
    source_dva,
    page_count,
    label,
    context,
    selector,
    alias_source_pages=False,
    target_dva=None,
):
    """Install a contiguous run of fresh leaves with source-role attributes."""
    page_count = int(page_count)
    if page_count < 1:
        raise ValueError("page_count must be positive")

    root_pa = context_root_pa(manifest, context, selector)
    raw, target_l3_pa, source_index = root_l3_location(
        manifest, table_pages, root_pa, source_dva
    )
    target_l3_data = bytearray(table_pages[target_l3_pa])
    if target_dva is not None:
        # Placing the run at an address the caller chose rather than at the first gap after the
        # source. The operand buffers lie on a fixed stride and firmware reads them there, so a run
        # packed in immediately after its source sits at the wrong address by exactly the gap the
        # stride leaves.
        raw, target_l3_pa, free_index = root_l3_location(
            manifest, table_pages, root_pa, int(target_dva)
        )
        target_l3_data = bytearray(table_pages[target_l3_pa])
        occupied = [
            index for index in range(free_index, free_index + page_count)
            if (struct.unpack_from("<Q", target_l3_data, index * 8)[0] & 3) != 0
        ]
        if occupied:
            raise RuntimeError(
                "context-%d leaf for DVA %#x is already mapped" % (context, target_dva)
            )
    else:
        free_index = None
        for index in range(source_index + 1, 0x800 - page_count + 1):
            if all(
                (struct.unpack_from("<Q", target_l3_data, (index + page) * 8)[0] & 3)
                == 0
                for page in range(page_count)
            ):
                free_index = index
                break
        if free_index is None:
            raise RuntimeError(
                "no run of %d free context-%d UAT leaves" % (page_count, context)
            )

    shift = int(manifest["vaddr_shift"])
    first_target_raw = (raw & ~(0x7ff << 14)) | (free_index << 14)
    mappings = []
    for page_index in range(page_count):
        source_page_dva = int(source_dva) + page_index * PAGE_SIZE
        _source_raw, source_l3_pa, source_leaf = root_l3_location(
            manifest, table_pages, root_pa, source_page_dva
        )
        source_pte = struct.unpack_from(
            "<Q", table_pages[source_l3_pa], source_leaf * 8
        )[0]
        if (source_pte & 3) == 0:
            raise RuntimeError(
                "source DVA %#x is not mapped" % source_page_dva
            )

        if alias_source_pages:
            target_pa = source_pte & TABLE_ADDR_MASK
        else:
            target_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
            iface.writemem(target_pa, bytes(PAGE_SIZE))
            p.dc_civac(target_pa, PAGE_SIZE)
        target_pte = (
            source_pte & ~TABLE_ADDR_MASK
        ) | (int(target_pa) & TABLE_ADDR_MASK)
        target_leaf = free_index + page_index
        table_offset = target_leaf * 8
        struct.pack_into("<Q", target_l3_data, table_offset, target_pte)
        target_dva = canonicalize(
            first_target_raw + page_index * PAGE_SIZE, shift
        )
        mappings.append(
            {
                "label": label if page_index == 0 else label + "-%d" % page_index,
                "context": context,
                "selector": selector,
                "dva": target_dva,
                "source_dva": source_page_dva,
                "relocated_pa": int(target_pa),
                "table_pa": target_l3_pa,
                "table_offset": table_offset,
                "relocated_pte": target_pte,
            }
        )

    iface.writemem(target_l3_pa, bytes(target_l3_data))
    p.dc_civac(target_l3_pa, PAGE_SIZE)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")
    table_pages[target_l3_pa] = bytes(target_l3_data)
    return mappings


def replace_context_page(
    manifest,
    table_pages,
    dva,
    payload,
    label,
    context,
    selector,
    target_pa=None,
):
    """Replace one occupied context leaf with a fresh host-owned page."""
    root_pa = context_root_pa(manifest, context, selector)
    _raw, l3_pa, l3_index = root_l3_location(
        manifest, table_pages, root_pa, dva
    )
    l3_data = table_pages[l3_pa]
    original_pte = struct.unpack_from("<Q", l3_data, l3_index * 8)[0]
    if (original_pte & 3) == 0:
        raise RuntimeError("context leaf for DVA %#x is not mapped" % dva)

    if target_pa is None:
        target_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
        iface.writemem(
            target_pa,
            payload[:PAGE_SIZE] + bytes(max(0, PAGE_SIZE - len(payload))),
        )
        p.dc_civac(target_pa, PAGE_SIZE)

    target_pte = (
        original_pte & ~TABLE_ADDR_MASK
    ) | (int(target_pa) & TABLE_ADDR_MASK)
    table_offset = l3_index * 8
    iface.writemem(l3_pa + table_offset, struct.pack("<Q", target_pte))
    p.dc_civac(l3_pa + table_offset, 8)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")
    table_pages[l3_pa] = (
        l3_data[:table_offset]
        + struct.pack("<Q", target_pte)
        + l3_data[table_offset + 8:]
    )
    return {
        "label": label,
        "context": context,
        "selector": selector,
        "dva": int(dva) & ~(PAGE_SIZE - 1),
        "source_dva": int(dva),
        "original_pa": original_pte & TABLE_ADDR_MASK,
        "relocated_pa": int(target_pa),
        "table_pa": l3_pa,
        "table_offset": table_offset,
        "original_pte": original_pte,
        "relocated_pte": target_pte,
    }


def map_new_selected_dva(manifest, ram, table_pages, mapping, label):
    source_dva = int(mapping["va"])
    raw, l3_pa, source_index = selected_l3_location(
        manifest, table_pages, source_dva
    )
    l3_data = table_pages[l3_pa]
    free_index = None
    for distance in range(1, 0x800):
        index = (source_index + distance) & 0x7FF
        pte = struct.unpack_from("<Q", l3_data, index * 8)[0]
        if (pte & 3) == 0:
            free_index = index
            break
    if free_index is None:
        raise RuntimeError("no free leaf in selected UAT L3 table")

    shift = int(manifest["vaddr_shift"])
    target_raw = (raw & ~((0x7FF) << 14)) | (free_index << 14)
    target_dva = canonicalize(target_raw, shift)
    if target_dva == source_dva:
        raise RuntimeError("selected source leaf is unexpectedly free")

    blob_index = int(mapping["blob_index"])
    source = ram[blob_index * PAGE_SIZE : (blob_index + 1) * PAGE_SIZE]
    target_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
    iface.writemem(target_pa, source)
    p.dc_civac(target_pa, PAGE_SIZE)

    source_pte = int(mapping["pte"])
    target_pte = (source_pte & ~TABLE_ADDR_MASK) | (target_pa & TABLE_ADDR_MASK)
    table_offset = free_index * 8
    iface.writemem(l3_pa + table_offset, struct.pack("<Q", target_pte))
    p.dc_civac(l3_pa + table_offset, 8)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")

    table_pages[l3_pa] = (
        l3_data[:table_offset]
        + struct.pack("<Q", target_pte)
        + l3_data[table_offset + 8 :]
    )

    return {
        "label": label,
        "dva": target_dva,
        "source_dva": source_dva,
        "original_pa": int(mapping["pa"]) & ~(PAGE_SIZE - 1),
        "relocated_pa": target_pa,
        "table_pa": l3_pa,
        "table_offset": table_offset,
        "original_pte": 0,
        "relocated_pte": target_pte,
    }


def map_built_page(
    manifest,
    table_pages,
    source_dva,
    payload,
    label,
    preserve_source_offset=True,
):
    """Map a page of host-built content at a free device address.

    Like ``map_new_selected_dva`` but the content comes from a builder rather than from
    the capture, which is the point: it puts a descriptor firmware has never seen in
    front of it. The permissions and attributes are taken from the source mapping's
    entry so only the contents and the address differ.
    """
    raw, l3_pa, source_index = selected_l3_location(
        manifest, table_pages, source_dva
    )
    l3_data = table_pages[l3_pa]
    free_index = None
    for distance in range(1, 0x800):
        index = (source_index + distance) & 0x7FF
        if (struct.unpack_from("<Q", l3_data, index * 8)[0] & 3) == 0:
            free_index = index
            break
    if free_index is None:
        raise RuntimeError("no free leaf in selected UAT L3 table")

    shift = int(manifest["vaddr_shift"])
    target_dva = canonicalize((raw & ~(0x7FF << 14)) | (free_index << 14), shift)
    source_pte = None
    for mapping in manifest["mappings"]:
        if int(mapping["va"]) == (source_dva & ~(PAGE_SIZE - 1)):
            source_pte = int(mapping["pte"])
            break
    if source_pte is None:
        raise RuntimeError("no captured mapping for %#x" % source_dva)

    # The returned address keeps the source's page offset, because the leaf index is
    # the only part of the address that changes, so the payload has to sit at that same
    # offset within the new page. Writing it at the page base instead leaves the caller
    # pointing that many bytes into it. That bug produced a passing run whose pools were
    # misaligned, which passed only because the submission in use never reads them.
    page_offset = (
        int(source_dva) & (PAGE_SIZE - 1)
        if preserve_source_offset
        else 0
    )
    if not preserve_source_offset:
        target_dva &= ~(PAGE_SIZE - 1)
    if page_offset + len(payload) > PAGE_SIZE:
        raise RuntimeError("payload of %#x at offset %#x does not fit a page"
                           % (len(payload), page_offset))
    target_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
    iface.writemem(target_pa, bytes(page_offset) + payload
                   + bytes(PAGE_SIZE - page_offset - len(payload)))
    p.dc_civac(target_pa, PAGE_SIZE)

    target_pte = (source_pte & ~TABLE_ADDR_MASK) | (target_pa & TABLE_ADDR_MASK)
    table_offset = free_index * 8
    iface.writemem(l3_pa + table_offset, struct.pack("<Q", target_pte))
    p.dc_civac(l3_pa + table_offset, 8)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")
    table_pages[l3_pa] = (l3_data[:table_offset]
                          + struct.pack("<Q", target_pte)
                          + l3_data[table_offset + 8:])
    return {"label": label, "dva": target_dva, "source_dva": int(source_dva),
            "original_pa": 0, "relocated_pa": target_pa,
            "table_pa": l3_pa, "table_offset": table_offset,
            "original_pte": 0, "relocated_pte": target_pte}


def map_new_ta_descriptor_dva(manifest, ram, table_pages, init_message):
    ta_mapping = dict(
        first_work_descriptor_mappings(manifest, ram, init_message)
    )["TA_0"]
    return map_new_selected_dva(
        manifest,
        ram,
        table_pages,
        ta_mapping,
        "TA_0-first-work-descriptor-new-dva",
    )


def map_new_3d_descriptor_dva(manifest, ram, table_pages, init_message):
    three_d_mapping = dict(
        first_work_descriptor_mappings(manifest, ram, init_message)
    )["3D_0"]
    return map_new_selected_dva(
        manifest,
        ram,
        table_pages,
        three_d_mapping,
        "3D_0-first-work-descriptor-new-dva",
    )


def g17p_build_registers():
    """The accelerator register windows, from the device tree rather than a constant."""
    return [int(u.adt["/arm-io/sgx"].get_reg(0)[0])]


def power_on_gpu(mailbox_trace):
    for path in ("/arm-io/gfx-asc", "/arm-io/gfx1-asc", "/arm-io/sgx"):
        print("Powering %s" % path)
        p.pmgr_adt_power_enable(path)

    sgx_base = int(u.adt["/arm-io/sgx"].get_reg(0)[0])
    for offset in (0x1000104, 0x1000108):
        addr = sgx_base + offset
        old = int(p.read32(addr))
        new = old | 1
        p.write32(addr, new)
        mailbox_trace.write(
            "%d sgx RMW4 addr=0x%x old=0x%x new=0x%x\n"
            % (time.monotonic_ns(), addr, old, new)
        )
        print("T8140 AXI2AF transition workaround: %#x %#x -> %#x" % (addr, old, new))


def apply_pre_init_sgx_write(mailbox_trace):
    sgx_base = int(u.adt["/arm-io/sgx"].get_reg(0)[0])
    addr = sgx_base + 0xD06030
    p.write32(addr, 0)
    mailbox_trace.write(
        "%d sgx W4 addr=0x%x value=0x0 # observed pre-init clear\n"
        % (time.monotonic_ns(), addr)
    )
    print("Replayed observed SGX pre-init clear at %#x" % addr)


def wait_init_ack(asces, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for asc in asces:
            asc.work_pending()
        if all(asc.fw.init_ack for asc in asces):
            return True
        time.sleep(0.001)
    return False


CHANNEL_NAMES = WORK_CHANNEL_NAMES


def read_dva_u32(address_space, addr):
    return struct.unpack("<I", address_space.read(addr, 4))[0]


def read_dva_u64(address_space, addr):
    return struct.unpack("<Q", address_space.read(addr, 8))[0]


def write_dva_u32(address_space, addr, value):
    address_space.write(addr, struct.pack("<I", int(value)))
    u.inst("dsb sy")


def write_dva_u64(address_space, addr, value):
    address_space.write(addr, struct.pack("<Q", int(value)))
    u.inst("dsb sy")


def captured_context_page(manifest, context, addr):
    addr = canonicalize(int(addr) & ((1 << 44) - 1), int(manifest["vaddr_shift"]))
    for mapping_set in manifest["root_mappings"]:
        if int(mapping_set["root_ctx_id"]) != context:
            continue
        for mapping in mapping_set["mappings"]:
            start = int(mapping["va"])
            if start <= addr < start + PAGE_SIZE:
                return (int(mapping["pa"]) + addr - start) & ~(PAGE_SIZE - 1)
    raise RuntimeError("no context-%d mapping for DVA %#x" % (context, addr))


def captured_control_entry(address_space, work_state, wanted_opcode):
    """Return the newest captured ring entry carrying wanted_opcode."""
    published = int(work_state["captured_control_counters"][2])
    first = max(0, published - CONTROL_ENTRY_COUNT)
    observed = []
    for absolute_index in range(published - 1, first - 1, -1):
        slot = absolute_index % CONTROL_ENTRY_COUNT
        entry = address_space.read(
            work_state["control_ring_addr"] + slot * CONTROL_ENTRY_SIZE,
            CONTROL_ENTRY_SIZE,
        )
        opcode = struct.unpack_from("<I", entry)[0]
        observed.append((absolute_index, opcode))
        if opcode == wanted_opcode:
            return absolute_index, entry
    raise RuntimeError(
        "no opcode %#x in %d captured device-control entries; newest opcodes %s"
        % (
            wanted_opcode,
            published,
            ", ".join(
                "%d:%#x" % item for item in observed[:8]
            ),
        )
    )


def replay_coproc_maint(manifest, address_space, work_state):
    entry_index, entry = captured_control_entry(
        address_space, work_state, 0x20
    )
    print("Using captured opcode-0x20 device-control entry %d" % entry_index)

    pages = {int(record["original_pa"]) for record in manifest["table_page_records"]}
    # G17P's 64-byte opcode-0x20 entry stores these pointers unaligned.
    for operand_offset in (0x14, 0x1C, 0x24):
        operand = struct.unpack_from("<Q", entry, operand_offset)[0]
        if operand >> 44:
            translated = address_space.translate(operand, 1)[0][0]
            if translated is None:
                raise RuntimeError("unmapped control operand %#x" % operand)
            pages.add(translated & ~(PAGE_SIZE - 1))
        else:
            pages.add(captured_context_page(manifest, 1, operand))

    op = (
        "mov x8, x0; dsb osh; sys #3, c7, c3, #4, x8; "
        "sys #3, c7, c3, #5, x8; dsb osh; isb"
    )
    print("Replaying coprocessor maintenance for %d UAT/control pages" % len(pages))
    for page in sorted(pages):
        u.inst(op, page)


def control_operand_pages(manifest, address_space, work_state):
    entry_index, entry = captured_control_entry(
        address_space, work_state, 0x20
    )
    print("Inspecting captured opcode-0x20 device-control entry %d" % entry_index)

    pages = []
    for offset in (0x14, 0x1C, 0x24):
        dva = struct.unpack_from("<Q", entry, offset)[0]
        try:
            if dva >> 44:
                pa = address_space.translate(dva, 1)[0][0]
            else:
                pa = captured_context_page(manifest, 1, dva)
        except RuntimeError as error:
            print(
                "Skipping unavailable diagnostic opcode-0x20 operand %#x: %s"
                % (dva, error)
            )
            continue
        if pa is None:
            print("Skipping unmapped diagnostic opcode-0x20 operand %#x" % dva)
            continue
        pages.append(("operand_%#x" % dva, int(pa) & ~(PAGE_SIZE - 1)))
    return pages


def snapshot_control_operand_state(manifest, address_space, work_state):
    """Read the distinct pages named by opcode 0x20 through their physical mappings."""
    records = []
    seen = set()
    for name, pa in control_operand_pages(manifest, address_space, work_state):
        if pa in seen:
            continue
        seen.add(pa)
        p.dc_civac(pa, PAGE_SIZE)
        records.append({"name": name, "pa": pa, "data": bytes(iface.readmem(pa, PAGE_SIZE))})
    return records


def report_control_operand_changes(before, label):
    """Persist and summarize opcode-0x20 operand state at a control boundary."""
    if before is None:
        return 0
    report = []
    print("Device-control operand changes at %s:" % label)
    for record in before:
        pa = record["pa"]
        p.dc_civac(pa, PAGE_SIZE)
        after = bytes(iface.readmem(pa, PAGE_SIZE))
        differing = [index for index, (a, b) in enumerate(zip(record["data"], after))
                     if a != b]
        safe_name = record["name"].replace("/", "_")
        before_file = "control_operand_%s_before.bin" % safe_name
        after_file = "control_operand_%s_%s.bin" % (safe_name, label)
        (attempt_dir / before_file).write_bytes(record["data"])
        (attempt_dir / after_file).write_bytes(after)
        print("  %-34s PA %#x: %d of %d bytes changed"
              % (record["name"], pa, len(differing), PAGE_SIZE))
        report.append({
            "name": record["name"],
            "pa": pa,
            "changed_bytes": len(differing),
            "first_changed_offsets": differing[:64],
            "before_file": before_file,
            "after_file": after_file,
            "before_sha256": hashlib.sha256(record["data"]).hexdigest(),
            "after_sha256": hashlib.sha256(after).hexdigest(),
        })
    (attempt_dir / ("control_operands_%s.json" % label)).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return sum(record["changed_bytes"] for record in report)


def dump_pre_control_state(manifest, address_space, work_state, init_message):
    records = []

    def dump(name, pa, size):
        data = bytes(iface.readmem(pa, size))
        filename = name.replace("/", "_") + ".bin"
        (attempt_dir / filename).write_bytes(data)
        records.append(
            {
                "name": name,
                "pa": pa,
                "size": size,
                "file": filename,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    sgx = u.adt["/arm-io/sgx"]
    for prefix in ("gfx-data", "gfx1-data"):
        base = int(sgx._properties.get(prefix + "-base", 0))
        size = int(sgx._properties.get(prefix + "-size", 0))
        if base and size:
            dump(prefix, base, size)

    seen = set()
    pages = control_operand_pages(manifest, address_space, work_state)
    for name, page in pages:
        if page in seen:
            continue
        seen.add(page)
        dump(name, page, PAGE_SIZE)

    for name, dva in (
        ("device_control_ring", work_state["control_ring_addr"]),
        ("device_control_producer", work_state["control_state_addrs"][2]),
        ("device_control_firmware_consumer", work_state["control_state_addrs"][0]),
        ("device_control_driver_consumer", work_state["control_state_addrs"][1]),
    ):
        pa = address_space.translate(dva, 1)[0][0]
        if pa is None:
            raise RuntimeError("unmapped pre-control page %s %#x" % (name, dva))
        page = int(pa) & ~(PAGE_SIZE - 1)
        if page in seen:
            continue
        seen.add(page)
        dump(name, page, PAGE_SIZE)

    report = {
        "format": "m1n1-agx-g17p-pre-control-state-v1",
        "init_message": int(init_message),
        "control_ring_dva": int(work_state["control_ring_addr"]),
        "control_state_dvas": [int(value) for value in work_state["control_state_addrs"]],
        "records": records,
    }
    (attempt_dir / "pre_control_state.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print("Saved fresh pre-control state: %d records" % len(records))


def prepare_first_work(
    address_space,
    init_message,
    require_work=True,
    reset_control=True,
    control_producer_at_init=1,
    reset_work_producers=True,
    disabled_channels=(),
    deferred_channels=(),
    queue_state_40=None,
    cleared_work_items_before_control=(),
):
    init_addr = address_space.normalize(init_message)
    region_b = read_dva_u64(address_space, init_addr + 0x18)
    channels = []
    for index, name in enumerate(CHANNEL_NAMES):
        base = region_b + 0x20 + index * 0x20
        state_addrs = [
            read_dva_u64(address_space, base + offset)
            for offset in (0, 8, 0x10)
        ]
        values = [
            read_dva_u32(address_space, state_addr)
            for state_addr in state_addrs
        ]
        ring_addr = read_dva_u64(address_space, base + 0x18)
        channel = {
            "index": index,
            "name": name,
            "state_addrs": state_addrs,
            "captured_counters": values,
            "ring_addr": ring_addr,
        }
        if values[2] != values[0] or values[2] != values[1]:
            channel["captured_producer"] = values[2]
            if name in disabled_channels and name in deferred_channels:
                raise RuntimeError("cannot both disable and defer %s" % name)
            if name in disabled_channels:
                channel["disabled"] = True
                write_dva_u32(address_space, state_addrs[2], values[0])
            elif name in deferred_channels:
                channel["deferred"] = True
                write_dva_u32(address_space, state_addrs[2], values[0])
            elif reset_work_producers:
                write_dva_u32(address_space, state_addrs[2], 0)
            if (
                (queue_state_40 is not None or cleared_work_items_before_control)
                and not channel.get("disabled")
            ):
                queue_addr = read_dva_u64(address_space, queue_slot_base(ring_addr) + 8)
                queue_state = read_dva_u64(address_space, queue_addr)
                entry_array = read_dva_u64(address_space, queue_addr + 8)
                channel["command_queue_addr"] = queue_addr
                channel["queue_state_addr"] = queue_state
                channel["entry_array_addr"] = entry_array
                if queue_state_40 is not None:
                    write_dva_u32(address_space, queue_state + 0x40, queue_state_40)
                    channel["queue_state_40"] = queue_state_40
                if cleared_work_items_before_control:
                    for work_item in sorted(set(cleared_work_items_before_control)):
                        write_dva_u64(address_space, entry_array + work_item * 8, 0)
                    channel["cleared_work_items_before_control"] = sorted(
                        set(cleared_work_items_before_control)
                    )
        channels.append(channel)

    control_base = region_b + 0x1A0
    control_state_addrs = [
        read_dva_u64(address_space, control_base + offset)
        for offset in (0, 8, 0x10)
    ]
    control_ring_addr = read_dva_u64(address_space, control_base + 0x18)
    control_values = [
        read_dva_u32(address_space, state_addr)
        for state_addr in control_state_addrs
    ]
    # Native first-work captures exist at several control boundaries.  The
    # clean single-user first-application capture has exactly two fully
    # consumed records and no pending suffix.  Later final-26.6 captures have
    # one or three records pending, or four already consumed.  Resetting the
    # visible producer hides a pending suffix until submit_first_work()
    # publishes the requested records in order; --resume-post-control retains
    # the fully consumed [2, 2, 2] boundary unchanged.
    if control_values not in ([2, 2, 2], [4, 4, 4], [1, 1, 2], [1, 1, 4]):
        consumed, driver_consumed, published = control_values
        if not (consumed == driver_consumed == published and published >= 4):
            raise RuntimeError(
                "first-work snapshot has unsupported device-control counters %r"
                % control_values
            )
        print("Device-control counters are %r, a world past its first submission"
              % control_values)
    if reset_control:
        if control_producer_at_init > control_values[2]:
            raise RuntimeError(
                "cannot prestage %d device-control entries from a capture with "
                "producer %d"
                % (control_producer_at_init, control_values[2])
            )
        write_dva_u32(address_space, control_state_addrs[0], 0)
        write_dva_u32(address_space, control_state_addrs[1], 0)
        write_dva_u32(
            address_space, control_state_addrs[2], control_producer_at_init
        )

    active = [
        channel
        for channel in channels
        if (
            "captured_producer" in channel
            and not channel.get("disabled")
            and not channel.get("deferred")
        )
    ]
    deferred = [channel for channel in channels if channel.get("deferred")]
    if require_work and not active and not deferred:
        raise RuntimeError("first-work snapshot has no queued work channels")
    print(
        "Staged first work: regionB=%#x channels=%s"
        % (
            region_b,
            ", ".join(
                "%s:%d" % (channel["name"], channel["captured_producer"])
                for channel in active
            ),
        )
    )
    if deferred:
        print(
            "Deferred first work: %s"
            % ", ".join(channel["name"] for channel in deferred)
        )
    return {
        "init_addr": init_addr,
        "region_b": region_b,
        "channels": channels,
        "control_state_addrs": control_state_addrs,
        "control_ring_addr": control_ring_addr,
        "captured_control_counters": control_values,
    }


def rebuild_pending_compute_work(address_space, work_state):
    """Reconstruct the pending CL_2 queue and direct command graph.

    The checkpoint remains the placement/lifecycle positive control, but none
    of the bytes in these host-owned object ranges survive this function: each
    range is poisoned, then replaced with bytes emitted by the field builders.
    Requiring every generated range to match the pre-kick image first prevents
    an incomplete builder from silently changing several variables at once.
    """
    load_backend_package()
    g17p = sys.modules["g17pbackend.g17p"]
    compute = sys.modules["g17pbackend.g17p_compute"]

    active = [
        channel for channel in work_state["channels"]
        if channel.get("captured_producer") and not channel.get("disabled")
    ]
    compute_channels = [channel for channel in active
                        if channel["name"].startswith("CL_")]
    if len(compute_channels) != 1:
        raise RuntimeError(
            "compute rebuild needs exactly one pending CL channel, got %s" %
            [channel["name"] for channel in compute_channels]
        )
    channel = compute_channels[0]
    if channel["name"] != "CL_2":
        raise RuntimeError(
            "compute rebuild is established for CL_2, got %s" %
            channel["name"]
        )

    queue_dva = read_dva_u64(
        address_space, queue_slot_base(channel["ring_addr"]) + 8)
    queue = address_space.read(queue_dva, g17p.QUEUE_DESCRIPTOR_SIZE)
    pointers_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_POINTERS_ADDR)[0]
    item_ring_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_RING_ADDR)[0]
    job_list_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_JOB_LIST_ADDR)[0]
    channel_record_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_CONTEXT_ADDR)[0]
    pointer_state = address_space.read(pointers_dva, 0x80)
    write_index = struct.unpack_from(
        "<I", pointer_state, g17p.QUEUE_PTR_WRITE)[0]
    if write_index < 3:
        raise RuntimeError(
            "pending compute queue write index %d cannot hold a three-item group"
            % write_index
        )
    item_base = write_index - 3
    item_span_dva = item_ring_dva + item_base * 8
    item_span = address_space.read(item_span_dva, 0x18)
    descriptor_dva, optional_dva, event_dva = struct.unpack("<3Q", item_span)
    selectors = [
        read_dva_u32(address_space, address)
        for address in (descriptor_dva, optional_dva, event_dva)
    ]
    if selectors != [
        compute.COMPUTE_SELECTOR,
        compute.COMPUTE_OPTIONAL_SELECTOR,
        0x0E,
    ]:
        raise RuntimeError(
            "pending CL_2 group is not compute/optional/event: %r" % selectors
        )

    descriptor = address_space.read(
        descriptor_dva, compute.COMPUTE_DESCRIPTOR_SIZE)
    optional = address_space.read(
        optional_dva, compute.COMPUTE_OPTIONAL_SIZE)
    event = address_space.read(event_dva, compute.COMPUTE_EVENT_SIZE)

    def u16(body, offset):
        return struct.unpack_from("<H", body, offset)[0]

    def u32(body, offset):
        return struct.unpack_from("<I", body, offset)[0]

    def u64(body, offset):
        return struct.unpack_from("<Q", body, offset)[0]

    registers = []
    for index in range(compute.COMPUTE_REGISTER_CAPACITY):
        offset = (compute.COMPUTE_REGISTER_START
                  + index * compute.COMPUTE_REGISTER_SIZE)
        number, value = struct.unpack_from("<IQ", descriptor, offset)
        if number == 0 and value == 0:
            break
        registers.append((number, value))

    sentinel_size = 0
    for offset in range(g17p.QUEUE_UNK_38 - 1,
                        g17p.QUEUE_UNK_38 - g17p.QUEUE_SENTINEL_SIZE - 1,
                        -1):
        if queue[offset] != 0xFF:
            break
        sentinel_size += 1
    generated_queue = g17p.build_queue_record(
        pointers_dva,
        item_ring_dva,
        job_list_dva,
        channel_record_dva,
        uuid=u32(queue, g17p.QUEUE_UUID),
        priority=u32(queue, g17p.QUEUE_PRIORITY),
        prio5=u32(queue, g17p.QUEUE_PRIO5),
        unk_2c=u32(queue, g17p.QUEUE_UNK_2C),
        unk_38=u32(queue, g17p.QUEUE_UNK_38),
        unk_94=u32(queue, g17p.QUEUE_UNK_94),
        sentinel_size=sentinel_size,
    )

    generated_pointers = bytearray(0x80)
    generated_pointers[:g17p.QUEUE_PTR_BLOCK_SIZE] = (
        g17p.build_queue_pointers(
            u32(pointer_state, g17p.QUEUE_PTR_RING_SIZE)))
    for offset in (
        g17p.QUEUE_PTR_DONE,
        g17p.QUEUE_PTR_UNK_10,
        g17p.QUEUE_PTR_UNK_20,
        g17p.QUEUE_PTR_READ,
        g17p.QUEUE_PTR_WRITE,
        0x60,
    ):
        struct.pack_into("<I", generated_pointers, offset,
                         u32(pointer_state, offset))

    slot = address_space.read(queue_slot_base(channel["ring_addr"]),
                              g17p.RING_SLOT_SIZE)
    slot_fields = g17p.decode_slot_flags(u32(slot, g17p.RING_SLOT_FLAGS_HEAD))
    generated_slot = g17p.build_ring_slot(
        queue_dva,
        slot_fields["head"],
        slot_fields["queue_index"],
        slot_fields["first_submit"],
        kind="compute",
    )

    generated_descriptor = compute.build_compute_descriptor(
        registers,
        scheduler_record=u64(descriptor, 0x10),
        low_alias=(u64(descriptor, 0x740)
                   - compute.COMPUTE_REGISTER_START),
        cdm_terminator=u64(descriptor, 0xEE0),
        submit_sequence=u64(descriptor, 0x04),
        context_id=u32(descriptor, 0x0C),
        grid_index=u32(descriptor, 0xF54),
        dispatch_a=u64(descriptor, 0xF40),
        dispatch_b=u64(descriptor, 0xF48),
        status_a=u64(descriptor, 0xF7C),
        status_b=u64(descriptor, 0xF84),
        shared_control=u64(descriptor, 0xFB2),
        zero_page=u64(descriptor, 0xFCB),
        protection_index=u32(descriptor, 0xF60),
        support_control=u32(descriptor, 0xFBA),
        support_flags=u32(descriptor, 0xFBE),
    )
    generated_optional = compute.build_compute_optional(
        u64(optional, 0x08),
        u64(optional, 0x10),
        grid_index=u16(optional, 0x18),
        submission_ordinal=u16(optional, 0x3E),
        shared_control=u64(optional, 0x36),
        channel_control=u64(optional, 0x4A),
        uuid=u16(optional, 0x5A),
        field_46=u16(optional, 0x46),
        field_1e=u16(optional, 0x1E),
        field_32=u16(optional, 0x32),
        field_56=u16(optional, 0x56),
        field_5e=u16(optional, 0x5E),
    )
    event_word = u32(event, 0x08)
    generated_event = compute.build_compute_event(
        event_word >> 8,
        u32(event, 0x04) & 0xFFFF,
        counter_low=event_word & 0xFF,
    )

    queue_context_dva = u64(optional, 0x10)
    queue_context = address_space.read(
        queue_context_dva, compute.COMPUTE_QUEUE_CONTEXT_SIZE)
    grid_index = u16(optional, 0x18)
    flags_200 = u64(queue_context, 0x200) & ~(
        (grid_index * 4) << 40 | 4)
    generated_queue_context = compute.build_compute_queue_context(
        descriptor_dva,
        queue_dva,
        grid_index,
        flags_200=flags_200,
        word_220=u64(queue_context, 0x220),
        word_330=u64(queue_context, 0x330),
        word_338=u64(queue_context, 0x338),
        word_350=u64(queue_context, 0x350),
        word_358=u64(queue_context, 0x358),
        word_378=u64(queue_context, 0x378),
    )

    scheduler_dva = u64(descriptor, 0x10)
    scheduler = address_space.read(scheduler_dva, 0x100)
    generated_scheduler = compute.build_compute_scheduler_record(
        u64(scheduler, 0x00),
        work_id=u32(scheduler, 0x08),
        phase=u32(scheduler, 0x0C),
        job_list=u64(scheduler, 0xA0),
        node_id=u64(scheduler, 0xA8) & 0xFFFFFF,
    )
    scheduler_state_dva = u64(scheduler, 0x00)
    scheduler_state_page = scheduler_state_dva & ~(PAGE_SIZE - 1)
    scheduler_page_dva = scheduler_dva & ~(PAGE_SIZE - 1)
    scheduler_index = (scheduler_dva - scheduler_page_dva) // 0x100
    generated_scheduler_page = bytearray(PAGE_SIZE)
    for index in range(36):
        struct.pack_into(
            "<Q", generated_scheduler_page, index * 0x100,
            scheduler_state_page + index * 4,
        )
    generated_scheduler_page[
        scheduler_index * 0x100:(scheduler_index + 1) * 0x100
    ] = generated_scheduler
    scheduler_state = address_space.read(scheduler_state_page, PAGE_SIZE)
    generated_scheduler_state = bytearray(PAGE_SIZE)
    scheduler_state_offset = scheduler_state_dva & (PAGE_SIZE - 1)
    struct.pack_into(
        "<I", generated_scheduler_state, scheduler_state_offset,
        u32(scheduler_state, scheduler_state_offset),
    )

    shared_support_dva = u64(descriptor, 0xFB2)
    shared_support = address_space.read(shared_support_dva, PAGE_SIZE)
    support_state_dva = u64(shared_support, 0x4C)
    support_state = address_space.read(support_state_dva, PAGE_SIZE)
    generated_shared_support = compute.build_compute_shared_support(
        u64(shared_support, 0x30),
        support_state_dva,
        word_08=u64(shared_support, 0x08),
        word_10=u64(shared_support, 0x10),
        header=u64(shared_support, 0x00),
        resource_class=u64(shared_support, 0x20) >> 40,
        cursor=u32(shared_support, 0x48),
        field_5c=u32(shared_support, 0x5C),
        final_kind=u32(shared_support, 0x60),
    )
    generated_support_state = compute.build_compute_shared_state(
        u32(support_state, 0x00))

    generated_channel_record = bytearray(0x40)
    for offset, value in (
        (0x00, 0x000001000000FFFF),
        (0x20, 0x0002000000000000),
        (0x30, 0x00000000FF000000),
    ):
        struct.pack_into("<Q", generated_channel_record, offset, value)

    objects = [
        ("work ring slot", queue_slot_base(channel["ring_addr"]),
         slot, generated_slot),
        ("queue", queue_dva, queue, generated_queue),
        ("queue pointer block", pointers_dva, pointer_state,
         bytes(generated_pointers)),
        ("pending item triplet", item_span_dva, item_span,
         struct.pack("<3Q", descriptor_dva, optional_dva, event_dva)),
        ("compute descriptor", descriptor_dva, descriptor,
         generated_descriptor),
        ("compute optional", optional_dva, optional, generated_optional),
        ("compute event", event_dva, event, generated_event),
        ("queue context", queue_context_dva, queue_context,
         generated_queue_context),
        ("scheduler page", scheduler_page_dva,
         address_space.read(scheduler_page_dva, PAGE_SIZE),
         bytes(generated_scheduler_page)),
        ("scheduler state", scheduler_state_page, scheduler_state,
         bytes(generated_scheduler_state)),
        ("shared support", shared_support_dva, shared_support,
         generated_shared_support),
        ("shared support state", support_state_dva, support_state,
         generated_support_state),
        ("queue job list", job_list_dva,
         address_space.read(job_list_dva, g17p.JOB_LIST_SIZE),
         g17p.build_job_list(job_list_dva)),
        ("channel record", channel_record_dva,
         address_space.read(channel_record_dva, 0x40),
         bytes(generated_channel_record)),
    ]
    for label, offset in (
        ("dispatch A", 0xF40),
        ("dispatch B", 0xF48),
        ("status A", 0xF7C),
        ("status B", 0xF84),
    ):
        dva = u64(descriptor, offset)
        objects.append((label, dva, address_space.read(dva, 8), bytes(8)))
    zero_page_dva = u64(descriptor, 0xFCB)
    objects.append((
        "descriptor zero page",
        zero_page_dva,
        address_space.read(zero_page_dva, PAGE_SIZE),
        bytes(PAGE_SIZE),
    ))

    report = []
    for name, dva, captured, generated in objects:
        if len(captured) != len(generated):
            raise RuntimeError(
                "%s builder length %#x differs from captured length %#x" %
                (name, len(generated), len(captured)))
        differences = [
            index for index, (left, right) in
            enumerate(zip(captured, generated)) if left != right
        ]
        if differences:
            raise RuntimeError(
                "%s builder differs at %s" %
                (name, ["%#x" % index for index in differences[:32]]))
        address_space.write(dva, b"\xA5" * len(generated))
        address_space.write(dva, generated)
        if address_space.read(dva, len(generated)) != generated:
            raise RuntimeError("%s generated readback differs" % name)
        report.append({
            "name": name,
            "dva": int(dva),
            "size": len(generated),
            "sha256": hashlib.sha256(generated).hexdigest(),
        })
        print("Rebuilt compute %-28s DVA %#x size %#x" %
              (name, dva, len(generated)))

    u.inst("dsb sy")
    return {
        "channel": channel["name"],
        "queue": queue_dva,
        "descriptor": descriptor_dva,
        "optional": optional_dva,
        "event": event_dva,
        "objects": report,
    }


def rebuild_pending_compute_client(address_space, work_state):
    """Reconstruct the caller-owned execution closure of minimal add3."""
    load_backend_package()
    g17p = sys.modules["g17pbackend.g17p"]
    compute = sys.modules["g17pbackend.g17p_compute"]

    channels = [
        channel for channel in work_state["channels"]
        if channel.get("captured_producer")
        and not channel.get("disabled")
        and channel["name"] == "CL_2"
    ]
    if len(channels) != 1:
        raise RuntimeError(
            "compute client rebuild needs one pending CL_2 channel, got %d" %
            len(channels)
        )
    channel = channels[0]
    queue_dva = read_dva_u64(
        address_space, queue_slot_base(channel["ring_addr"]) + 8)
    queue = address_space.read(queue_dva, g17p.QUEUE_DESCRIPTOR_SIZE)
    pointers_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_POINTERS_ADDR)[0]
    pointer_state = address_space.read(pointers_dva, 0x80)
    write_index = struct.unpack_from(
        "<I", pointer_state, g17p.QUEUE_PTR_WRITE)[0]
    item_ring_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_RING_ADDR)[0]
    descriptor_dva = read_dva_u64(
        address_space, item_ring_dva + (write_index - 3) * 8)
    descriptor = address_space.read(
        descriptor_dva, compute.COMPUTE_DESCRIPTOR_SIZE)
    context_id = struct.unpack_from("<I", descriptor, 0x0C)[0]

    def client_read(dva, size):
        return address_space.read_context(context_id, 0, dva, size)

    def client_write(dva, body):
        address_space.write_context(context_id, 0, dva, body)

    registers = []
    for index in range(compute.COMPUTE_REGISTER_CAPACITY):
        offset = (compute.COMPUTE_REGISTER_START
                  + index * compute.COMPUTE_REGISTER_SIZE)
        number, value = struct.unpack_from("<IQ", descriptor, offset)
        if number == 0 and value == 0:
            break
        registers.append((number, value))

    def register(number, occurrence=0):
        values = [value for candidate, value in registers
                  if candidate == number]
        if occurrence >= len(values):
            raise RuntimeError(
                "compute client descriptor lacks register %#x occurrence %d" %
                (number, occurrence)
            )
        return values[occurrence]

    resource_dva = register(0x1A510)
    cdm_dva = register(0x1A420)
    robustness_dva = register(0x14070) & ~1
    cdm = client_read(cdm_dva, compute.CDM_RECORD_SIZE + 4)
    config, constant, encoded_shader = struct.unpack_from("<IIQ", cdm, 0)
    grid = struct.unpack_from("<3I", cdm, 0x10)
    threadgroup = struct.unpack_from("<3I", cdm, 0x1C)
    tail = struct.unpack_from("<I", cdm, 0x28)[0]
    terminator = struct.unpack_from("<I", cdm, compute.CDM_RECORD_SIZE)[0]
    shader_control = encoded_shader >> 32
    shader_dva = (
        ((encoded_shader & 0xFFFFFFFF) << 6)
        | ((shader_control & 0x3FFFFFFF) << 40)
    )
    if terminator != compute.CDM_TERMINATOR:
        raise RuntimeError(
            "compute stream terminator is %#x, expected %#x" %
            (terminator, compute.CDM_TERMINATOR)
        )
    if grid != (64, 1, 1) or threadgroup != (32, 1, 1):
        raise RuntimeError(
            "pending add3 dispatch is grid=%r threadgroup=%r" %
            (grid, threadgroup)
        )

    resource = client_read(resource_dva, 0xC000)
    buffers = struct.unpack_from("<3Q", resource, 0x14A0)
    if any(not address for address in buffers):
        raise RuntimeError("add3 resource table has null buffer pointers")
    input_a_dva, input_b_dva, output_dva = buffers

    generated_cdm_stream = compute.build_cdm_stream((
        compute.build_direct_dispatch(
            shader_dva,
            grid,
            threadgroup,
            config=config,
            constant=constant,
            tail=tail,
        ),
    ))
    generated_cdm = generated_cdm_stream + bytes(
        0x8000 - len(generated_cdm_stream))
    generated_shader = NATIVE_ADD3_SHADER + bytes(
        0x8000 - len(NATIVE_ADD3_SHADER))
    generated_resource = compute.build_buffer_resource_table(
        buffers, size=0xC000)
    generated_input_a = struct.pack(
        "<64f", *(1000.0 + index for index in range(64)))
    generated_input_a += bytes(PAGE_SIZE - len(generated_input_a))
    generated_input_b = struct.pack("<64f", *([0.5] * 64))
    generated_input_b += bytes(PAGE_SIZE - len(generated_input_b))

    objects = [
        ("CDM allocation", cdm_dva, generated_cdm),
        ("shader allocation", shader_dva, generated_shader),
        ("resource table", resource_dva, generated_resource),
        ("input A", input_a_dva, generated_input_a),
        ("input B", input_b_dva, generated_input_b),
        ("output", output_dva, bytes(PAGE_SIZE)),
        ("robustness", robustness_dva, bytes(PAGE_SIZE)),
    ]
    report = []
    for name, dva, generated in objects:
        captured = client_read(dva, len(generated))
        differences = [
            index for index, (left, right) in
            enumerate(zip(captured, generated)) if left != right
        ]
        if differences:
            raise RuntimeError(
                "%s builder differs at %s" %
                (name, ["%#x" % index for index in differences[:32]]))
        client_write(dva, b"\xA5" * len(generated))
        client_write(dva, generated)
        if client_read(dva, len(generated)) != generated:
            raise RuntimeError("%s generated readback differs" % name)
        report.append({
            "name": name,
            "dva": int(dva),
            "size": len(generated),
            "sha256": hashlib.sha256(generated).hexdigest(),
        })
        print("Rebuilt add3   %-28s DVA %#x size %#x" %
              (name, dva, len(generated)))

    u.inst("dsb sy")
    return {
        "context_id": context_id,
        "descriptor": descriptor_dva,
        "resource": resource_dva,
        "cdm": cdm_dva,
        "shader": shader_dva,
        "input_a": input_a_dva,
        "input_b": input_b_dva,
        "output": output_dva,
        "objects": report,
    }


def rebuild_pending_compute_registration(address_space, work_state):
    """Reconstruct the context-local operand registration namespace."""
    load_backend_package()
    g17p = sys.modules["g17pbackend.g17p"]
    compute = sys.modules["g17pbackend.g17p_compute"]

    channel = next(
        (
            candidate for candidate in work_state["channels"]
            if candidate.get("captured_producer")
            and not candidate.get("disabled")
            and candidate["name"] == "CL_2"
        ),
        None,
    )
    if channel is None:
        raise RuntimeError("compute registration rebuild has no pending CL_2")
    queue_dva = read_dva_u64(
        address_space, queue_slot_base(channel["ring_addr"]) + 8)
    queue = address_space.read(queue_dva, g17p.QUEUE_DESCRIPTOR_SIZE)
    pointers_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_POINTERS_ADDR)[0]
    pointer_state = address_space.read(pointers_dva, 0x80)
    write_index = struct.unpack_from(
        "<I", pointer_state, g17p.QUEUE_PTR_WRITE)[0]
    item_ring_dva = struct.unpack_from(
        "<Q", queue, g17p.QUEUE_RING_ADDR)[0]
    descriptor_dva = read_dva_u64(
        address_space, item_ring_dva + (write_index - 3) * 8)
    descriptor = address_space.read(
        descriptor_dva, compute.COMPUTE_DESCRIPTOR_SIZE)
    context_id = struct.unpack_from("<I", descriptor, 0x0C)[0]

    def client_read(dva, size):
        return address_space.read_context(context_id, 0, dva, size)

    def client_write(dva, body):
        address_space.write_context(context_id, 0, dva, body)

    def client_memset(dva, value, size):
        for pa, length in address_space.translate_context(
            context_id, 0, dva, size
        ):
            if pa is None:
                raise RuntimeError(
                    "unmapped compute registration DVA %#x" % int(dva)
                )
            p.memset32(pa, value, length)
            p.dc_civac(pa, length)

    shared_support_dva = struct.unpack_from("<Q", descriptor, 0xFB2)[0]
    shared_support = address_space.read(shared_support_dva, PAGE_SIZE)
    operand_table_dva = struct.unpack_from("<Q", shared_support, 0x30)[0]
    operand_table = client_read(operand_table_dva, PAGE_SIZE)
    buffer_bases = []
    for index in range(PAGE_SIZE // compute.COMPUTE_OPERAND_TABLE_STRIDE):
        tagged = struct.unpack_from(
            "<Q", operand_table,
            index * compute.COMPUTE_OPERAND_TABLE_STRIDE,
        )[0]
        if tagged == 0:
            break
        if not tagged & compute.COMPUTE_OPERAND_BUFFER_FLAG:
            raise RuntimeError(
                "operand table entry %d lacks its buffer tag" % index
            )
        buffer_bases.append(
            tagged & ~compute.COMPUTE_OPERAND_BUFFER_FLAG
        )
    if len(buffer_bases) != compute.COMPUTE_OPERAND_TABLE_ENTRIES:
        raise RuntimeError(
            "operand table has %d entries, expected %d" %
            (len(buffer_bases), compute.COMPUTE_OPERAND_TABLE_ENTRIES)
        )

    generated_table = compute.build_compute_operand_table_bases(buffer_bases)
    if operand_table != generated_table:
        raise RuntimeError("operand-table builder differs from checkpoint")
    table_region_size = 0x10000
    table_region = client_read(operand_table_dva, table_region_size)
    generated_table_region = generated_table + bytes(
        table_region_size - len(generated_table)
    )
    if table_region != generated_table_region:
        raise RuntimeError("operand-table region has unexplained bytes")

    page_list_dva = 0x7000000000
    page_list_region_size = 0x200000
    generated_lists = compute.build_compute_operand_page_lists(
        buffer_bases[0], entries=len(buffer_bases)
    )
    generated_list_region = generated_lists + bytes(
        page_list_region_size - len(generated_lists)
    )
    if client_read(page_list_dva, page_list_region_size) != generated_list_region:
        raise RuntimeError("operand page-list region differs from builder")

    pointer_registers = {
        0x10229, 0x140A8, 0x10099, 0x10091, 0x0A5C1, 0x0A5C9,
    }
    pointer_values = []
    for index in range(compute.COMPUTE_REGISTER_CAPACITY):
        number, value = struct.unpack_from(
            "<IQ", descriptor,
            compute.COMPUTE_REGISTER_START
            + index * compute.COMPUTE_REGISTER_SIZE,
        )
        if number == 0 and value == 0:
            break
        if number in pointer_registers:
            pointer_values.append(value & ~1)
    if len(pointer_values) != len(pointer_registers):
        raise RuntimeError(
            "compute descriptor exposes %d/%d state pointers" %
            (len(pointer_values), len(pointer_registers))
        )
    state_start = min(pointer_values) & ~(PAGE_SIZE - 1)
    state_end = (
        max(pointer_values) + PAGE_SIZE
    ) & ~(PAGE_SIZE - 1)
    state_size = state_end - state_start
    if any(client_read(state_start, state_size)):
        raise RuntimeError("compute state/scratch region is not blank")

    tranche_bytes = 0
    for index, base in enumerate(buffer_bases):
        body = client_read(base, compute.COMPUTE_OPERAND_BUFFER_SIZE)
        if any(body):
            raise RuntimeError(
                "operand tranche %d at %#x is not blank" % (index, base)
            )
        client_memset(base, 0xA5A5A5A5,
                      compute.COMPUTE_OPERAND_BUFFER_SIZE)
        client_memset(base, 0, compute.COMPUTE_OPERAND_BUFFER_SIZE)
        tranche_bytes += compute.COMPUTE_OPERAND_BUFFER_SIZE

    for dva, size, generated in (
        (page_list_dva, page_list_region_size, generated_list_region),
        (operand_table_dva, table_region_size, generated_table_region),
        (state_start, state_size, bytes(state_size)),
    ):
        client_memset(dva, 0xA5A5A5A5, size)
        client_memset(dva, 0, size)
        nonzero = [(offset, generated[offset:offset + PAGE_SIZE])
                   for offset in range(0, size, PAGE_SIZE)
                   if any(generated[offset:offset + PAGE_SIZE])]
        for offset, page in nonzero:
            client_write(dva + offset, page)
        if client_read(dva, size) != generated:
            raise RuntimeError(
                "generated registration readback differs at %#x" % dva
            )

    u.inst("dsb sy")
    print(
        "Rebuilt compute registration context %d: %d operand tranches "
        "(%#x bytes), page lists %#x+%#x, table %#x+%#x, state %#x+%#x" %
        (
            context_id, len(buffer_bases), tranche_bytes,
            page_list_dva, page_list_region_size,
            operand_table_dva, table_region_size,
            state_start, state_size,
        )
    )
    return {
        "context_id": context_id,
        "operand_table": operand_table_dva,
        "operand_table_size": table_region_size,
        "page_lists": page_list_dva,
        "page_lists_size": page_list_region_size,
        "state": state_start,
        "state_size": state_size,
        "tranche_count": len(buffer_bases),
        "tranche_bytes": tranche_bytes,
        "operand_table_sha256": hashlib.sha256(
            generated_table_region).hexdigest(),
        "page_lists_sha256": hashlib.sha256(
            generated_list_region).hexdigest(),
    }


def wait_dva_counters(asces, address_space, addrs, expected, timeout, label):
    deadline = time.monotonic() + timeout
    values = []
    # What the counters hold before waiting. A restored snapshot can already satisfy the
    # target, in which case this returns immediately and reports success while nothing has
    # been published; saying so is the difference between a result and a mirage.
    entry = [read_dva_u32(address_space, addr) for addr in addrs]
    if entry == list(expected):
        print("%s counters ALREADY %r at entry: nothing was waited for" % (label, entry))
        return entry
    while time.monotonic() < deadline:
        for asc in asces:
            asc.work_pending()
        values = [read_dva_u32(address_space, addr) for addr in addrs]
        if values == list(expected):
            print("%s counters rose %r -> %r" % (label, entry, values))
            return values
        time.sleep(0.001)
    raise TimeoutError(
        "%s counter timeout: expected %r, got %r"
        % (label, list(expected), values)
    )


def clear_work_items_after_control(address_space, work_state, work_items):
    if not work_items:
        return

    cleared = sorted(set(work_items))
    active = [
        channel
        for channel in work_state["channels"]
        if (
            "captured_producer" in channel
            and not channel.get("disabled")
            and not channel.get("deferred")
        )
    ]
    for channel in active:
        queue_addr = read_dva_u64(address_space, queue_slot_base(channel["ring_addr"]) + 8)
        entry_array = read_dva_u64(address_space, queue_addr + 8)
        channel["command_queue_addr"] = queue_addr
        channel["entry_array_addr"] = entry_array
        for work_item in cleared:
            write_dva_u64(address_space, entry_array + work_item * 8, 0)
        channel["cleared_work_items_after_control"] = cleared
    print(
        "Cleared work items after device-control: %s"
        % ", ".join("%s:%r" % (channel["name"], cleared) for channel in active)
    )


def first_work_descriptor_address(address_space, work_state, channel_name):
    channel_name = selected_first_work_name(channel_name)
    channel_by_name = {
        channel["name"]: channel for channel in work_state["channels"]
    }
    channel = channel_by_name[channel_name]
    queue_addr = read_dva_u64(address_space, queue_slot_base(channel["ring_addr"]) + 8)
    entry_array = read_dva_u64(address_space, queue_addr + 8)
    return read_dva_u64(address_space, entry_array)


def patch_first_work_values(address_space, work_state, patches, size):
    if not patches:
        return []

    if size == 4:
        read = read_dva_u32
        write = write_dva_u32
    elif size == 8:
        read = read_dva_u64
        write = write_dva_u64
    else:
        raise ValueError("unsupported patch size")

    records = []
    for channel_name, offset, replacement in patches:
        descriptor = first_work_descriptor_address(
            address_space, work_state, channel_name
        )
        field_addr = descriptor + offset
        original = read(address_space, field_addr)
        write(address_space, field_addr, replacement)
        record = {
            "channel": channel_name,
            "descriptor_dva": descriptor,
            "offset": offset,
            "size": size,
            "original": original,
            "replacement": replacement,
        }
        records.append(record)
        print(
            "Patched %s first descriptor DVA %#x + %#x (%d-bit): %#x -> %#x"
            % (channel_name, descriptor, offset, size * 8, original, replacement)
        )
    return records


def redirect_first_work_item_at_index(
    address_space, work_state, channel_name, item_index, item_dva
):
    channel_name = selected_first_work_name(channel_name)
    channel_by_name = {
        channel["name"]: channel for channel in work_state["channels"]
    }
    channel = channel_by_name[channel_name]
    queue_addr = read_dva_u64(address_space, queue_slot_base(channel["ring_addr"]) + 8)
    entry_array = read_dva_u64(address_space, queue_addr + 8)
    # The group firmware is about to run is the last one on the queue, not the first. In a world
    # captured at a host's first submission those are the same three entries and the distinction
    # never showed; in one captured later they are not, and redirecting entries zero to two rewrites
    # a group that has already been consumed while the pending one runs untouched.
    pointers_addr = read_dva_u64(address_space, queue_addr)
    write_index = read_dva_u32(address_space, pointers_addr + 0x40)
    base = max(0, write_index - 3)
    entry_index = base + item_index
    entry_dva = entry_array + entry_index * 8
    original = read_dva_u64(address_space, entry_dva)
    write_dva_u64(address_space, entry_dva, item_dva)
    print(
        "Redirected %s queue entry %d (pending group at %d, write index %d): %#x -> %#x"
        % (channel_name, entry_index, base, write_index, original, item_dva)
    )
    return {
        "channel": channel_name,
        "entry_array_dva": entry_array,
        "item_index": item_index,
        "entry_dva": entry_dva,
        "original_item_dva": original,
        "replacement_item_dva": item_dva,
    }


def redirect_first_work_item(address_space, work_state, channel_name, descriptor_dva):
    redirect = redirect_first_work_item_at_index(
        address_space, work_state, channel_name, 0, descriptor_dva
    )
    redirect["original_descriptor_dva"] = redirect.pop("original_item_dva")
    redirect["replacement_descriptor_dva"] = redirect.pop(
        "replacement_item_dva"
    )
    return redirect


def omit_first_optional_item(address_space, work_state, channel_name):
    """Compact the first group from descriptor,optional,event to descriptor,event."""
    channel_name = selected_first_work_name(channel_name)
    channel = next(
        entry for entry in work_state["channels"] if entry["name"] == channel_name
    )
    queue_addr = read_dva_u64(address_space, queue_slot_base(channel["ring_addr"]) + 8)
    pointers_addr = read_dva_u64(address_space, queue_addr)
    entry_array = read_dva_u64(address_space, queue_addr + 8)
    items = [
        read_dva_u64(address_space, entry_array + index * 8)
        for index in range(3)
    ]
    selectors = [
        read_dva_u32(address_space, item) if item else None for item in items
    ]
    if selectors[1:] != [0x0f, 0x0e]:
        raise RuntimeError(
            "%s first group is not descriptor,optional,event: %r"
            % (channel_name, selectors)
        )

    queue_write = read_dva_u32(address_space, pointers_addr + 0x40)
    packed_head = read_dva_u32(address_space, channel["ring_addr"] + 0x14)
    if queue_write != 3 or (packed_head & 0xffff) != 3:
        raise RuntimeError(
            "%s first group has write/head %d/%d, expected 3/3"
            % (channel_name, queue_write, packed_head & 0xffff)
        )

    write_dva_u64(address_space, entry_array + 8, items[2])
    write_dva_u64(address_space, entry_array + 16, 0)
    write_dva_u32(address_space, pointers_addr + 0x40, 2)
    packed_after = (packed_head & ~0xffff) | 2
    write_dva_u32(address_space, channel["ring_addr"] + 0x14, packed_after)
    print(
        "Omitted %s optional item %#x; event %#x moved from entry 2 to 1"
        % (channel_name, items[1], items[2])
    )
    return {
        "channel": channel_name,
        "queue_dva": queue_addr,
        "pointers_dva": pointers_addr,
        "entry_array_dva": entry_array,
        "descriptor_dva": items[0],
        "optional_dva": items[1],
        "event_dva": items[2],
        "queue_write_before": queue_write,
        "queue_write_after": 2,
        "packed_head_before": packed_head,
        "packed_head_after": packed_after,
    }


def snapshot_shared_regions():
    """Read the firmware shared regions as they are right now."""
    out = []
    for name, pa, size in SHARED_REGIONS:
        p.dc_civac(pa, size)
        out.append((name, pa, size, iface.readmem(pa, size)))
    return out


def update_grafted_expected(address, content):
    """Make a deliberate host mutation the baseline for graft verification."""
    patch_start = address
    patch_end = address + len(content)
    for index, (base, expected) in enumerate(GRAFTED_CONTENT):
        overlap_start = max(base, patch_start)
        overlap_end = min(base + len(expected), patch_end)
        if overlap_start >= overlap_end:
            continue
        updated = bytearray(expected)
        updated[overlap_start - base:overlap_end - base] = content[
            overlap_start - patch_start:overlap_end - patch_start
        ]
        GRAFTED_CONTENT[index] = (base, bytes(updated))


def report_grafted_changes(address_space):
    """Re-read exactly what was grafted and report which of it firmware changed."""
    changed = 0
    total = 0
    report = []
    print("Grafted bytes changed by the submission:")
    for addr, content in GRAFTED_CONTENT:
        try:
            now = address_space.read(addr, len(content))
        except Exception as error:
            print("  %#014x  could not be read back: %s" % (addr, error))
            report.append({"dva": addr, "size": len(content), "error": str(error)})
            continue
        total += 1
        offsets = [
            index
            for index, (before, after) in enumerate(zip(content, now))
            if before != after
        ]
        differing = len(offsets)
        if differing:
            changed += 1
            print("  %#014x  %d of %d bytes changed" % (addr, differing, len(content)))
            for offset in offsets[:16]:
                print(
                    "      +%#06x  %02x -> %02x"
                    % (offset, content[offset], now[offset])
                )
        report.append(
            {
                "dva": addr,
                "size": len(content),
                "changed_bytes": differing,
                "changes": [
                    {
                        "offset": offset,
                        "before": content[offset],
                        "after": now[offset],
                    }
                    for offset in offsets[:128]
                ],
            }
        )
    render_changed = 0
    for dva, pa, content in GRAFTED_PHYSICAL_CONTENT:
        p.dc_civac(pa, len(content))
        now = iface.readmem(pa, len(content))
        total += 1
        offsets = [
            index
            for index, (before, after) in enumerate(zip(content, now))
            if before != after
        ]
        differing = len(offsets)
        if differing:
            changed += 1
            render_changed += 1
            print(
                "  %#014x  %d of %d bytes changed (render PA %#x)"
                % (dva, differing, len(content), pa)
            )
        report.append(
            {
                "dva": dva,
                "pa": pa,
                "size": len(content),
                "render_context": True,
                "changed_bytes": differing,
                "changes": [
                    {
                        "offset": offset,
                        "before": content[offset],
                        "after": now[offset],
                    }
                    for offset in offsets[:128]
                ],
            }
        )
    print("  %d of %d render-context pages written by firmware"
          % (render_changed, len(GRAFTED_PHYSICAL_CONTENT)))
    print("  %d of %d grafted regions written by firmware" % (changed, total))
    (attempt_dir / "grafted_changes.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return changed


def snapshot_context_watch_pages(manifest, dvas, context):
    records = []
    seen = set()
    for dva in dvas:
        page_dva = int(dva) & ~(PAGE_SIZE - 1)
        if page_dva in seen:
            continue
        seen.add(page_dva)
        if page_dva in RENDER_MAPPING_OVERRIDES:
            pa = RENDER_MAPPING_OVERRIDES[page_dva]
        else:
            mapping = context_mapping(manifest, page_dva, context)
            pa = int(mapping["pa"])
        p.dc_civac(pa, PAGE_SIZE)
        records.append(
            {
                "dva": page_dva,
                "pa": pa,
                "context": int(context),
                "before": bytes(iface.readmem(pa, PAGE_SIZE)),
            }
        )
    return records


def snapshot_render_watch_pages(manifest, dvas):
    return snapshot_context_watch_pages(manifest, dvas, 1)


def render_context_pages(manifest):
    """Every render-context page the snapshot maps, as (device address, physical address)."""
    pages = {}
    for group in manifest["root_mappings"]:
        for mapping in group["mappings"]:
            if mapping.get("root_ctx_id") != 1:
                continue
            if mapping.get("blob_index") is None:
                continue
            pages.setdefault(int(mapping["va"]), int(mapping["pa"]))
    return sorted(pages.items())


def scan_render_baseline(manifest, prefix_bytes):
    """Read the head of every render-context page, to be compared after the submission.

    An earlier version of this compared against the snapshot instead. That baseline is older than
    device-control initialization, which writes 917 pages by itself, so every result it produced was
    really about initialization. The baseline has to be taken immediately before the doorbell for a
    difference to belong to the work.
    """
    baseline = {}
    for dva, pa in render_context_pages(manifest):
        try:
            p.dc_civac(pa, PAGE_SIZE)
            baseline[dva] = (pa, bytes(iface.readmem(pa, prefix_bytes)))
        except Exception:
            continue
    print("Render-context baseline: %d pages, first %d bytes each"
          % (len(baseline), prefix_bytes))
    return baseline


def scan_render_writes(manifest, baseline, prefix_bytes):
    """Which render-context pages changed since the baseline was taken?

    Only the head of each page is read, so a page written solely beyond that prefix is missed. The
    count of pages not covered is reported rather than left implicit, because a sweep that looks
    complete and is not would be worse than none.
    """
    seen = set()
    changed = []
    unread = 0
    for dva, (pa, expected) in sorted(baseline.items()):
        seen.add(dva)
        try:
            p.dc_civac(pa, PAGE_SIZE)
            actual = bytes(iface.readmem(pa, prefix_bytes))
        except Exception:
            unread += 1
            continue
        if actual != expected:
            differing = sum(1 for left, right in zip(expected, actual) if left != right)
            # What changed matters as much as how much. A page this reports is the only evidence
            # a published submission produces, and reading it afterwards through the watch's
            # mapping gives a different physical page, so the bytes are kept here.
            offsets = [index for index, (left, right)
                       in enumerate(zip(expected, actual)) if left != right]
            first, last = offsets[0], offsets[-1]
            changed.append({
                "dva": dva, "pa": pa, "changed_in_prefix": differing,
                "first_changed": first, "last_changed": last,
                "before": expected[first:last + 1].hex(),
                "after": actual[first:last + 1].hex(),
            })

    print("Render-context write scan: %d of %d pages changed across the submission, "
          "in their first %d bytes" % (len(changed), len(seen), prefix_bytes))
    if unread:
        print("  %d pages could not be read" % unread)
    for record in sorted(changed, key=lambda r: r["dva"])[:40]:
        print("    %#014x  %d bytes" % (record["dva"], record["changed_in_prefix"]))
    if len(changed) > 40:
        print("    ... and %d more" % (len(changed) - 40))
    result = {"pages_scanned": len(seen), "prefix_bytes": prefix_bytes,
              "unreadable": unread, "changed": changed}
    (attempt_dir / "render_write_scan.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def report_render_watch_pages(records, label=None):
    report = []
    prefix = "render_watch" if label is None else "render_watch_%s" % label
    print("Watched render-context pages%s:"
          % ("" if label is None else " (%s)" % label))
    for record in records:
        p.dc_civac(record["pa"], PAGE_SIZE)
        after = bytes(iface.readmem(record["pa"], PAGE_SIZE))
        differing = [
            index
            for index, (left, right) in enumerate(zip(record["before"], after))
            if left != right
        ]
        stem = "%s_%x" % (prefix, record["dva"])
        before_file = stem + "_before.bin"
        after_file = stem + "_after.bin"
        (attempt_dir / before_file).write_bytes(record["before"])
        (attempt_dir / after_file).write_bytes(after)
        print(
            "  DVA %#x PA %#x: %d bytes changed"
            % (record["dva"], record["pa"], len(differing))
        )
        report.append(
            {
                "dva": record["dva"],
                "pa": record["pa"],
                "changed_bytes": len(differing),
                "first_changed_offsets": differing[:128],
                "before_file": before_file,
                "after_file": after_file,
                "before_sha256": hashlib.sha256(record["before"]).hexdigest(),
                "after_sha256": hashlib.sha256(after).hexdigest(),
            }
        )
    (attempt_dir / (prefix + ".json")).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return sum(record["changed_bytes"] for record in report)


def clear_render_watch_pages(records):
    """Zero watched physical pages between the startup work and later publications."""
    zero = bytes(PAGE_SIZE)
    cleared = []
    for record in records:
        iface.writemem(record["pa"], zero)
        p.dc_civac(record["pa"], PAGE_SIZE)
        check = bytes(iface.readmem(record["pa"], PAGE_SIZE))
        if check != zero:
            raise RuntimeError(
                "watched render page %#x at PA %#x did not clear"
                % (record["dva"], record["pa"])
            )
        record["before"] = zero
        cleared.append({"dva": record["dva"], "pa": record["pa"]})
    (attempt_dir / "render_watch_inter_submission_clear.json").write_text(
        json.dumps(cleared, indent=2, sort_keys=True) + "\n"
    )
    print("Cleared and verified %d watched physical pages before extra submissions"
          % len(cleared))
    return cleared


def report_shared_diff(before):
    """Report which parts of the shared regions the submission changed."""
    total = 0
    for name, pa, size, was in before:
        p.dc_civac(pa, size)
        now = iface.readmem(pa, size)
        runs = []
        index = 0
        while index < len(was):
            if was[index] != now[index]:
                start = index
                while index < len(was) and was[index] != now[index]:
                    index += 1
                runs.append((start, index))
            else:
                index += 1
        changed = sum(end - start for start, end in runs)
        total += changed
        print("  shared %-22s %#x+%#x: %d bytes changed in %d runs"
              % (name, pa, size, changed, len(runs)))
        for start, end in runs[:8]:
            print("      +%#08x..+%#08x  %s -> %s"
                  % (start, end, was[start:min(end, start + 8)].hex(),
                     now[start:min(end, start + 8)].hex()))
    print("  TOTAL shared bytes changed by the submission: %d" % total)
    return total


def apply_post_control_overlay(address_space, pages, work_state, init_message):
    """Install native post-control host state without replacing grafted work objects."""
    protected = []

    def protect_dva(dva, size):
        for pa, length in address_space.translate(dva, size):
            if pa is None:
                raise RuntimeError("cannot protect unmapped graft DVA %#x" % dva)
            protected.append((int(pa), int(length)))
            dva += length
            size -= length

    for dva, content in GRAFTED_CONTENT:
        protect_dva(dva, len(content))
    for _dva, pa, content in GRAFTED_PHYSICAL_CONTENT:
        protected.append((int(pa), len(content)))
    for channel in work_state["channels"]:
        if (
            "grafted_producer_after" in channel
            and not GRAFT_REUSE_ACTIVE_QUEUE[0]
        ):
            protect_dva(channel["ring_addr"], WORK_RING_ENTRY_STRIDE)

    report = []
    total_changed = 0
    total_protected = 0
    for pa, page in sorted(pages.items()):
        overlay = page["data"]
        p.dc_civac(pa, PAGE_SIZE)
        current = bytes(iface.readmem(pa, PAGE_SIZE))
        merged = bytearray(overlay)
        protected_bytes = 0
        page_end = pa + PAGE_SIZE
        for start, size in protected:
            end = start + size
            overlap_start = max(pa, start)
            overlap_end = min(page_end, end)
            if overlap_start >= overlap_end:
                continue
            offset = overlap_start - pa
            merged[offset:offset + overlap_end - overlap_start] = current[
                offset:offset + overlap_end - overlap_start
            ]
            protected_bytes += overlap_end - overlap_start
        changed = sum(left != right for left, right in zip(current, merged))
        iface.writemem(pa, merged)
        p.dc_civac(pa, PAGE_SIZE)
        total_changed += changed
        total_protected += protected_bytes
        report.append(
            {
                "pa": pa,
                "changed_bytes_against_live_state": changed,
                "protected_graft_bytes": protected_bytes,
                "mapping_keys": page["mapping_keys"],
                "sha256": hashlib.sha256(merged).hexdigest(),
            }
        )
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")

    if GRAFT_REUSE_ACTIVE_QUEUE[0]:
        rebound_channels = set()
        for channel in work_state["channels"]:
            graft_queue = channel.get("grafted_queue_dva")
            if graft_queue is None:
                continue
            active_channel = channel
            active_queue = read_dva_u64(
                address_space, active_channel["ring_addr"] + 8
            )
            if not active_queue:
                kind = channel["name"].split("_", 1)[0]
                for candidate in work_state["channels"]:
                    if candidate["name"].split("_", 1)[0] != kind:
                        continue
                    if candidate["name"] in rebound_channels:
                        continue
                    candidate_queue = read_dva_u64(
                        address_space, candidate["ring_addr"] + 8
                    )
                    if candidate_queue:
                        active_channel = candidate
                        active_queue = candidate_queue
                        break
            if not active_queue:
                raise RuntimeError(
                    "post-control overlay did not restore an active %s queue family"
                    % channel["name"].split("_", 1)[0]
                )
            rebound_channels.add(active_channel["name"])
            active_context = read_dva_u64(
                address_space, active_queue + 0x9C
            )
            descriptor = bytearray(address_space.read(graft_queue, 0xC0))
            struct.pack_into("<Q", descriptor, 0x9C, active_context)
            address_space.write(active_queue, descriptor)

            outer = bytearray.fromhex(channel["grafted_outer_hex"])
            struct.pack_into("<Q", outer, 8, active_queue)
            address_space.write(active_channel["ring_addr"], outer)
            GRAFTED_CONTENT.append((active_queue, bytes(descriptor)))
            GRAFTED_CONTENT.append(
                (active_channel["ring_addr"], bytes(outer))
            )
            print(
                "Rebound grafted %s queue %#x through active %s queue %#x "
                "(context %#x)"
                % (
                    channel["name"], graft_queue, active_channel["name"],
                    active_queue, active_context,
                )
            )
        u.inst("dsb sy")

    print(
        "Applied post-control overlay: %d pages, %d live bytes changed, "
        "%d graft bytes protected"
        % (len(report), total_changed, total_protected)
    )
    (attempt_dir / "post_control_overlay.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )

    refreshed = prepare_first_work(
        address_space,
        init_message,
        require_work=True,
        reset_control=False,
        reset_work_producers=False,
    )
    work_state.clear()
    work_state.update(refreshed)
    return report


def submit_first_work(
    asces,
    address_space,
    manifest,
    work_state,
    timeout,
    control_producer,
    control_only,
    resume_post_control,
    prestage_control,
    dump_pre_control,
    clear_after_control,
    init_message,
    control_operand_before,
    post_control_overlay,
    watch_render_dvas,
    dva_copies,
    watch_context,
    initial_render_watch,
    replay_snapshot,
    replay_ram,
    reapply_snapshot_after_control,
):
    primary = asces[0]
    control = work_state["control_state_addrs"]
    if resume_post_control:
        initial_control = work_state["captured_control_counters"][:2]
    elif prestage_control:
        initial_control = [control_producer, control_producer]
    else:
        initial_control = [1, 1]
    # Entries left outstanding before firmware started are consumed along with the captured ones,
    # so the counter firmware settles on is that much further along.
    if args.prestage_control_tick:
        initial_control = [value + args.prestage_control_tick
                           for value in initial_control]
    wait_dva_counters(
        asces, address_space, control[:2], initial_control, timeout, "device-control init"
    )
    report_control_operand_changes(control_operand_before, "after-opening")

    if reapply_snapshot_after_control:
        # The late native snapshot is the state immediately before its work
        # doorbell. Fresh firmware mutates that image while consuming initdata
        # and the opening control message. Reapply the complete UAT image now,
        # but patch hidden producers in the image itself so firmware cannot see
        # the pending command partway through the sparse transfer.
        hidden_pages = {}
        hidden_records = []
        for channel in work_state["channels"]:
            if not (channel.get("disabled") or channel.get("deferred")):
                continue
            producer_dva = channel["state_addrs"][2]
            pa, blob_index, offset = snapshot_dva_pa(manifest, producer_dva)
            page_pa = pa - offset
            page = hidden_pages.get(page_pa)
            if page is None:
                start = int(blob_index) * PAGE_SIZE
                page = bytearray(replay_ram[start:start + PAGE_SIZE])
                if len(page) != PAGE_SIZE:
                    raise RuntimeError(
                        "short captured producer page for %s" % channel["name"]
                    )
                hidden_pages[page_pa] = page
            hidden_value = int(channel["captured_counters"][0])
            struct.pack_into("<I", page, offset, hidden_value)
            hidden_records.append(
                {
                    "channel": channel["name"],
                    "producer_dva": int(producer_dva),
                    "producer_pa": int(pa),
                    "hidden_value": hidden_value,
                }
            )
        restore_snapshot(
            replay_snapshot,
            manifest,
            replay_ram,
            page_overrides={pa: bytes(data) for pa, data in hidden_pages.items()},
        )
        for channel in work_state["channels"]:
            if channel.get("disabled") or channel.get("deferred"):
                write_dva_u32(
                    address_space,
                    channel["state_addrs"][2],
                    channel["captured_counters"][0],
                )
        print(
            "Reapplied complete captured UAT state after control with hidden "
            "producers: %s"
            % ", ".join(
                "%s=%d" % (record["channel"], record["hidden_value"])
                for record in hidden_records
            )
        )
        (attempt_dir / "post_control_snapshot_reapply.json").write_text(
            json.dumps(hidden_records, indent=2, sort_keys=True) + "\n"
        )

    if dump_pre_control:
        dump_pre_control_state(manifest, address_space, work_state, init_message)

    clear_work_items_after_control(address_space, work_state, clear_after_control)

    if not resume_post_control and not prestage_control:
        if args.sequence_control_doorbells:
            for producer in range(2, control_producer + 1):
                timeline_replay = CONTROL_TIMELINE_REPLAY[0]
                if timeline_replay is not None:
                    restored = timeline_replay.restore_record(
                        address_space, work_state, producer - 1
                    )
                    print(
                        "Restored native control input %d/%d: opcode %#x"
                        % (
                            restored["absolute_index"],
                            control_producer - 1,
                            restored["opcode"],
                        )
                    )
                write_dva_u32(address_space, control[2], producer)
                primary.send(0x0084000000000011, ASCMessage1(EP=0x21))
                wait_dva_counters(
                    asces,
                    address_space,
                    control[:2],
                    [producer, producer],
                    timeout,
                    "device-control record %d" % (producer - 1),
                )
            print(
                "Sequentially published %d captured device-control records"
                % control_producer
            )
        else:
            write_dva_u32(address_space, control[2], control_producer)
            primary.send(0x0084000000000011, ASCMessage1(EP=0x21))
            wait_dva_counters(
                asces,
                address_space,
                control[:2],
                [control_producer, control_producer],
                timeout,
                "device-control setup",
            )
        report_control_operand_changes(control_operand_before, "after-setup")

    if post_control_overlay:
        apply_post_control_overlay(
            address_space, post_control_overlay, work_state, init_message
        )
        # The overlay carries the captured entry array, so the redirects go on top of it rather
        # than under it, and this is also the first moment that array exists in memory on the
        # world that performs device control itself.
        apply_deferred_redirects()

    copy_report = []
    for source, destination, size in dva_copies:
        try:
            source_context = address_space.translate_context(
                watch_context, 0, source, size
            )
            destination_context = address_space.translate_context(
                watch_context, 0, destination, size
            )
            use_client_context = all(
                pa is not None
                for pa, _length in source_context + destination_context
            )
        except RuntimeError:
            use_client_context = False

        if use_client_context:
            content = address_space.read_context(
                watch_context, 0, source, size
            )
            before = address_space.read_context(
                watch_context, 0, destination, size
            )
            address_space.write_context(
                watch_context, 0, destination, content
            )
            address_space_name = "context-%d" % int(watch_context)
        else:
            content = address_space.read(source, size)
            before = address_space.read(destination, size)
            address_space.write(destination, content)
            update_grafted_expected(destination, content)
            address_space_name = "firmware"
        copy_report.append(
            {
                "source": source,
                "destination": destination,
                "size": size,
                "address_space": address_space_name,
                "changed_bytes": sum(
                    left != right for left, right in zip(before, content)
                ),
                "source_sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    if copy_report:
        print(
            "Copied %d device-address-space ranges after control setup"
            % len(copy_report)
        )
        (attempt_dir / "dva_copies.json").write_text(
            json.dumps(copy_report, indent=2, sort_keys=True) + "\n"
        )

    if control_only:
        # Whether firmware still takes device-control entries after the opening sequence is the
        # question this path can answer on its own, and it needs no queued work to do it. A
        # firmware that performed control itself and one resumed from a captured completed control
        # can be compared directly here.
        if args.backend_control_tick:
            control_channel_tick(
                asces, address_space, manifest, init_message,
                args.backend_control_tick, args.backend_control_tick_start)
        return "passed-device-control-%d" % control_producer

    if PRE_FIRST_WORK_GRAFT[0] is not None:
        graft = PRE_FIRST_WORK_GRAFT[0]
        PRE_FIRST_WORK_GRAFT[0] = None
        print("Grafting at the post-control/pre-first-work boundary")
        graft()

    # Taken here, after initialization and before anything is published, so that a page in
    # the scan below changed because of the submission and not because firmware was starting.
    render_scan_baseline = (
        INITIAL_SCAN_BASELINE[0]
        if INITIAL_SCAN_BASELINE[0] is not None
        else scan_render_baseline(manifest, SCAN_RENDER_PREFIX[0])
        if SCAN_RENDER_PREFIX[0] else None
    )

    render_watch = (
        initial_render_watch
        if initial_render_watch is not None
        else snapshot_context_watch_pages(
            manifest, watch_render_dvas, watch_context
        )
    )

    if (
        not resume_post_control
        and CONTROL_TIMELINE_REPLAY[0] is None
        and control_producer != work_state["captured_control_counters"][2]
    ):
        raise RuntimeError(
            "first work requires all captured device-control entries; "
            "use --control-only with --control-producer < 4"
        )

    active = [
        channel
        for channel in work_state["channels"]
        if (
            "captured_producer" in channel
            and not channel.get("disabled")
            and not channel.get("deferred")
        )
    ]
    for channel in active:
        if not resume_post_control:
            write_dva_u32(
                address_space,
                channel["state_addrs"][2],
                channel["captured_producer"],
            )
    if DIFF_SHARED[0]:
        # A positive control: the pages holding the channel completion counters must change,
        # because the counters advance. If they do not, the diff is not reading live memory and
        # a null result over the shared regions would mean nothing.
        control = []
        for channel in active:
            for label, dva in (("consumer", channel["state_addrs"][0]),
                               ("producer", channel["state_addrs"][2])):
                page = address_space.normalize(int(dva)) & ~(PAGE_SIZE - 1)
                pa = address_space.pages.get(page)
                if pa and not any(entry[1] == pa for entry in SHARED_REGIONS):
                    SHARED_REGIONS.append(
                        ("control:%s/%s" % (channel["name"], label), int(pa), PAGE_SIZE))
        del control
    # Read the counters through the same path wait_dva_counters uses. If they already hold
    # their target before the doorbell, then "counters reached" is reading a value the
    # snapshot restored and the wait never waited for anything.
    counters_before = {}
    if DIFF_SHARED[0]:
        for channel in active:
            counters_before[channel["name"]] = [
                read_dva_u32(address_space, addr) for addr in channel["state_addrs"][:3]
            ]
            print("  before doorbell %s counters %s target %s"
                  % (channel["name"], counters_before[channel["name"]],
                     channel["captured_producer"]))
    # A working firmware writes hundreds of entries to channel 14 over a handful of submissions.
    # Whether this world's move across the first work separates a scheduler that ran once and
    # stopped from one that never ran, with the first work reaching the accelerator another way.
    def _dump_non_work_channels(label):
        if not args.backend_dump_channels:
            return
        try:
            backend_module = load_backend_package()
            initdata_dva = canonicalize(
                int(init_message) & ((1 << 44) - 1), int(manifest["vaddr_shift"]))
            table = backend_module.G17PChannels(
                lambda addr, size: address_space.read(addr, size), initdata_dva)
            report = []
            for index in range(12, 17):
                entry = table.entries[index]
                if not entry["state_addrs"][0]:
                    continue
                report.append("ch%d=%s" % (index, table.counters(entry)))
            print("  non-work channels %s: %s" % (label, " ".join(report)))
        except Exception as error:  # noqa: BLE001
            print("  non-work channels %s unreadable: %s" % (label, error))
        # An external abort is what an access to an unpowered block looks like, and this world
        # aborts on a second device-control 0x20 where a guest does not. The graphics power
        # domains are cheap to read and say whether the block is still on.
        try:
            states = []
            for dev in u.adt["/arm-io/pmgr"].devices:
                name = str(dev.name)
                if not any(key in name.upper() for key in ("GFX", "SGX")):
                    continue
                addr = u.adt.pmgr_dev_get_addr(dev)
                value = p.read32(addr)
                states.append("%s=%#x" % (name, value))
            print("  graphics power %s: %s" % (label, " ".join(states)))
        except Exception as error:  # noqa: BLE001
            print("  graphics power %s unreadable: %s" % (label, error))

    _dump_non_work_channels("before the first work")
    shared_before = snapshot_shared_regions() if DIFF_SHARED[0] else None
    work_message = 0x0083000000000000
    if args.use_captured_work_message:
        work_message = int(manifest.get("trigger_message", 0))
        if ((work_message >> 48) & 0xFF) != 0x83:
            raise RuntimeError(
                "snapshot does not contain a type-0x83 work message: %#x"
                % work_message
            )
        print("Using captured work message %#018x" % work_message)
    # A group published after firmware has been woken is linked and never run. Staging one here,
    # before the first work's doorbell, asks whether that is about publication at all or only about
    # arriving late: firmware is woken once, with both groups already on the queue.
    if args.backend_publish_before_doorbell:
        backend_publish(asces, address_space, manifest, init_message, timeout, 0,
                        notify=False)
    if args.pre_work_interleave:
        # A booted host interleaves 0x87 and 0x84 with its work continuously, from the opening onward.
        # This host sends the opening 0x84 messages and then nothing but the work doorbell, which no
        # host does. Sending them after a publication has no effect; running that way from before the
        # first work is a different condition and is what this drives.
        for round_index in range(int(args.pre_work_interleave)):
            primary.send(0x0087000000000010, ASCMessage1(EP=0x21))
            primary.send(0x0084000000000011, ASCMessage1(EP=0x21))
        print("Interleaved %d rounds of 0x87 and 0x84 before the first work"
              % args.pre_work_interleave)

    if active or args.backend_publish_before_doorbell:
        primary.send(work_message, ASCMessage1(EP=0x21))
        for channel in active:
            producer = channel["captured_producer"]
            # Staging before the doorbell puts a second group on the work channels, so firmware has one
            # more to consume than the capture did. Waiting for the captured count times out on a run
            # that worked, and the timeout aborts before the render scan that the run exists to take.
            if (args.backend_publish_before_doorbell
                    and channel["name"] in ("TA_0", "3D_0")):
                producer += 1
            wait_dva_counters(
                asces,
                address_space,
                channel["state_addrs"][:2],
                [producer, producer],
                timeout,
                channel["name"],
            )

    deferred = [channel for channel in work_state["channels"] if channel.get("deferred")]
    if deferred:
        for channel in deferred:
            write_dva_u32(
                address_space,
                channel["state_addrs"][2],
                channel["captured_producer"],
            )
        primary.send(work_message, ASCMessage1(EP=0x21))
        for channel in deferred:
            producer = channel["captured_producer"]
            wait_dva_counters(
                asces,
                address_space,
                channel["state_addrs"][:2],
                [producer, producer],
                timeout,
                channel["name"] + " deferred",
            )
    if counters_before:
        for channel in active:
            after = [read_dva_u32(address_space, addr) for addr in channel["state_addrs"][:3]]
            print("  after doorbell  %s counters %s (was %s)"
                  % (channel["name"], after, counters_before[channel["name"]]))
    if shared_before is not None:
        print("Shared-region difference across the work doorbell:")
        report_shared_diff(shared_before)
    if VERIFY_GRAFTED[0]:
        report_grafted_changes(address_space)
    _dump_non_work_channels("after the first work")
    if render_watch:
        changed = report_render_watch_pages(render_watch)
        if args.require_render_change and changed == 0:
            raise RuntimeError(
                "work retired without changing any watched output-page byte"
            )
        if args.require_render_change:
            print(
                "PHYSICAL OUTPUT PASS: %d watched output-page bytes changed"
                % changed
            )
    if render_scan_baseline is not None:
        scan_render_writes(manifest, render_scan_baseline, SCAN_RENDER_PREFIX[0])
    if BACKEND_READ_CHANNELS[0]:
        fresh_count = (
            int(args.backend_fresh_item_count)
            if args.backend_publish_fresh_item
            else 1
        )
        for fresh_index in range(fresh_count):
            backend_publish(
                asces,
                address_space,
                manifest,
                init_message,
                timeout,
                fresh_index,
                fresh_index=fresh_index,
            )
            print(
                "Completed fresh backend publication %d of %d"
                % (fresh_index + 1, fresh_count)
            )
    elif args.backend_control_tick:
        # Whether the control channel is still live once work has run is the prerequisite for
        # everything else, and it is worth asking without building a submission first.
        control_channel_tick(
            asces, address_space, manifest, init_message,
            args.backend_control_tick, args.backend_control_tick_start)
    return "passed-first-work"


def mapping_for_dva(manifest, dva):
    """The captured mapping covering this device address."""
    page = int(dva) & ~(PAGE_SIZE - 1)
    for mapping in manifest["mappings"]:
        if int(mapping["va"]) == page:
            return mapping
    raise RuntimeError("no captured mapping covers DVA %#x" % dva)


def construct_queue_objects(manifest, ram, table_pages, address_space, queue_dva,
                            label):
    """Rebuild a queue, its pointer state and its entry array at host addresses.

    The submission chain is ring entry -> queue -> {pointer state, entry array}.
    Everything reached through it has so far been the captured objects at captured
    addresses. This gives each of the three a fresh page of host memory, mapped at a
    device address chosen from a free leaf, and repoints the copies at each other, so
    a submission published against the returned queue address runs entirely through
    containers this host owns.

    The contents are still copied. What is being established here is that the objects
    can live where the host puts them, not yet that their bytes can be authored.
    """
    pointer_state_dva = read_dva_u64(address_space, queue_dva)
    entry_array_dva = read_dva_u64(address_space, queue_dva + 8)

    moved = {}
    for name, dva in (("queue", queue_dva),
                      ("pointer-state", pointer_state_dva),
                      ("entry-array", entry_array_dva)):
        moved[name] = map_new_selected_dva(
            manifest, ram, table_pages, mapping_for_dva(manifest, dva),
            "%s-%s" % (label, name))
        moved[name]["offset"] = int(dva) & (PAGE_SIZE - 1)
        moved[name]["source"] = int(dva)
        # Teach the captured address space about the new leaf, the way the main flow
        # does through its virtual page overrides. Without this a later read through
        # a constructed address reports the DVA as unmapped, because this view of the
        # tables was built before the leaf was written.
        page = address_space.normalize(moved[name]["dva"]) & ~(PAGE_SIZE - 1)
        address_space.pages[page] = moved[name]["relocated_pa"] & ~(PAGE_SIZE - 1)

    def address_of(name):
        return moved[name]["dva"] + moved[name]["offset"]

    # The copied queue still names the captured pointer state and entry array, so
    # point it at the copies instead. Written through the new page's own physical
    # address rather than through the device address space, because firmware is
    # already running and this page is not yet reachable by it.
    queue_pa = moved["queue"]["relocated_pa"] + moved["queue"]["offset"]
    iface.writemem(queue_pa, struct.pack("<QQ", address_of("pointer-state"),
                                         address_of("entry-array")))
    p.dc_civac(queue_pa, 0x10)
    u.inst("dsb sy")

    for name in ("queue", "pointer-state", "entry-array"):
        record = moved[name]
        print("Constructed %s at DVA %#x (was %#x), page %#x"
              % (record["label"], address_of(name), record["source"],
                 record["relocated_pa"]))
    return address_of("queue"), moved


def render_root_pa(manifest):
    """The render context's root table, which is a different root from the firmware's.

    The firmware context is context 64 at selector 1; the render context is context 1 at
    selector 0. Taking the wrong one silently walks the wrong tables.
    """
    for group in manifest["root_mappings"]:
        if group.get("root_ctx_id") == 1 and group.get("selector") == 0:
            if group.get("root_pa"):
                return int(group["root_pa"])
    raise RuntimeError("no render-context root in this snapshot")


def map_at_exact_dva(manifest, table_pages, dva, payload, root_pa=None):
    """Map a host page at a given device address, not at the next free leaf.

    Needed because a later submission references pages an earlier snapshot does not
    map, and grafting one onto the other requires those addresses specifically rather
    than any free address. Checked before writing this: all six such addresses in the
    thirteenth submission resolve to level-three tables that already exist, with free
    leaves, so no intermediate table has to be built and this does not try to build one.

    The entry's attributes are copied from another populated leaf in the same table,
    since leaves in one table cover one region and share their permissions and memory
    type. A wrong attribute here would fault or, worse, silently give firmware a
    mapping with different cacheability.
    """
    shift = int(manifest["vaddr_shift"])
    raw = int(dva) & ((1 << (shift + 1)) - 1)
    l1_mask = (1 << max(0, shift - 36)) - 1
    l1_index = (raw >> 36) & l1_mask
    l2_index = (raw >> 25) & 0x7FF
    l3_index = (raw >> 14) & 0x7FF

    if root_pa is None:
        root_pa = int(manifest["selected_root"]["root1_pa"])
    l1_pte = struct.unpack_from("<Q", table_pages[root_pa], l1_index * 8)[0]
    if (l1_pte & 3) != 3:
        raise RuntimeError("no level-two table for %#x" % dva)
    l2_pa = l1_pte & TABLE_ADDR_MASK
    l2_pte = struct.unpack_from("<Q", table_pages[l2_pa], l2_index * 8)[0]
    if (l2_pte & 3) != 3:
        raise RuntimeError("no level-three table for %#x" % dva)
    l3_pa = l2_pte & TABLE_ADDR_MASK
    l3_data = table_pages[l3_pa]
    if (struct.unpack_from("<Q", l3_data, l3_index * 8)[0] & 3) != 0:
        raise RuntimeError("leaf for %#x is already occupied" % dva)

    template = None
    for index in range(0x800):
        candidate = struct.unpack_from("<Q", l3_data, index * 8)[0]
        if (candidate & 3) != 0:
            template = candidate
            break
    if template is None:
        raise RuntimeError("no populated leaf to take attributes from at %#x" % dva)

    page_offset = int(dva) & (PAGE_SIZE - 1)
    if page_offset:
        raise RuntimeError("expected a page-aligned address, got %#x" % dva)
    target_pa = u.memalign(PAGE_SIZE, PAGE_SIZE)
    iface.writemem(target_pa, payload[:PAGE_SIZE]
                   + bytes(max(0, PAGE_SIZE - len(payload))))
    p.dc_civac(target_pa, PAGE_SIZE)

    pte = (template & ~TABLE_ADDR_MASK) | (target_pa & TABLE_ADDR_MASK)
    offset = l3_index * 8
    iface.writemem(l3_pa + offset, struct.pack("<Q", pte))
    p.dc_civac(l3_pa + offset, 8)
    u.inst("dsb sy")
    u.inst("tlbi vmalle1os")
    u.inst("dsb sy")
    u.inst("isb")
    table_pages[l3_pa] = (l3_data[:offset] + struct.pack("<Q", pte)
                          + l3_data[offset + 8:])
    return {"dva": int(dva), "pa": target_pa, "pte": pte,
            "table_pa": l3_pa, "table_offset": offset}


def graft_submission_closure(address_space, work_state, directory,
                            manifest, table_pages, inner_head=None,
                            objects_only=False):
    """Overwrite a replayed submission with a later one captured from a guest.

    A full replayable snapshot exists only for the first submission after
    initialisation, which does no dependent work, and capturing a later one means
    reading 69 MB over debug USB, past this workflow's wall-clock budget. A closure
    capture of a later submission is small and does exist.

    The two can be combined because the driver reuses addresses: the thirteenth
    submission's descriptor and both pools sit at the same device addresses as the
    first's. So firmware's world comes from the full snapshot and the submission's
    content is written over it by device address, which is consistent even though the
    two captures are from different boots.

    Returns what was grafted. Pages the closure holds that this address space cannot
    resolve are reported rather than skipped silently, since a partial graft would look
    like a working submission and behave like neither.
    """
    pages = json.loads((directory / "pages.json").read_text())
    target = json.loads((directory / "target.json").read_text())
    blob = (directory / "pages.bin").read_bytes()
    page_size = int(pages["page_size"])

    def value(raw):
        return int(raw, 0) if isinstance(raw, str) else int(raw)

    written = []
    created = []
    unresolved = []
    render_pages = []
    skipped_pages = []

    # The ranges this submission owns, as (address, length). Anything else in a page that
    # the snapshot already maps belongs to the replayed world and is left alone.
    queue = (target.get("queues") or [{}])[0]
    # A channel-ring slot is 0x18, a queue descriptor 0xc0, and the queue's fixed
    # state 0x80.
    owned = [(value(target["outer_dva"]), 0x18)]
    if queue.get("queue_dva"):
        owned.append((value(queue["queue_dva"]), 0xc0))
    if queue.get("state_dva"):
        owned.append((value(queue["state_dva"]), 0x80))
    if queue.get("queue_context_dva"):
        owned.append(
            (
                value(queue["queue_context_dva"]),
                value(queue.get("queue_context_size", 0x40)),
            )
        )
    # The capture's own bytes, addressed by device address, so the submission's objects can be
    # located inside it.
    captured_pages = {}
    for record in pages["pages"]:
        captured_pages[value(record["dva"])] = blob[
            value(record["capture_offset"]):value(record["capture_offset"]) + page_size]

    def captured_read(dva, count):
        out = bytearray()
        while count:
            page = captured_pages.get(dva & ~(page_size - 1))
            if page is None:
                return None
            offset = dva & (page_size - 1)
            take = min(count, page_size - offset)
            out += page[offset:offset + take]
            dva += take
            count -= take
        return bytes(out)

    pending_start, pending_end = pending_entry_span(queue)
    pending_records = []
    if not queue.get("inner_dva"):
        raise RuntimeError("%s capture has no item ring" % target["channel"])
    inner_dva = value(queue["inner_dva"])
    entry_count = pending_end - pending_start
    entry_bytes = captured_read(inner_dva + pending_start * 8, entry_count * 8)
    if entry_bytes is None:
        raise RuntimeError(
            "%s capture is missing pending item-ring entries [%d,%d)"
            % (target["channel"], pending_start, pending_end)
        )
    entries = struct.unpack("<%dQ" % entry_count, entry_bytes)
    owned.append((inner_dva + pending_start * 8, entry_count * 8))
    for index, pointer in enumerate(entries, pending_start):
        if not pointer:
            raise RuntimeError(
                "%s pending item-ring entry %d is null"
                % (target["channel"], index)
            )
        header = captured_read(pointer, 4)
        if header is None:
            raise RuntimeError(
                "%s pending item %#x is absent from the capture"
                % (target["channel"], pointer)
            )
        selector = struct.unpack("<I", header)[0]
        length = item_record_size(selector)
        owned.append((pointer, length))
        pending_records.append({
            "index": index,
            "dva": pointer,
            "selector": selector,
            "length": length,
        })

    def owned_slices(page_dva):
        """Byte ranges of this page that belong to the submission."""
        out = []
        for base, length in owned:
            start = max(base, page_dva)
            end = min(base + length, page_dva + page_size)
            if start < end:
                out.append((start, end))
        return out

    for record in pages["pages"]:
        dva = value(record["dva"])
        offset = value(record["capture_offset"])
        content = blob[offset:offset + page_size]
        # A register value names memory in the render context, whose root is not the
        # firmware root, so neither the address-space write nor the default exact
        # mapping can place it. Bit 42 distinguishes the two contexts.
        if not (dva >> 42) & 1:
            try:
                mapping = render_context_mapping(manifest, dva)
                iface.writemem(int(mapping["pa"]), content)
                p.dc_civac(int(mapping["pa"]), page_size)
                render_pages.append({"dva": dva, "pa": int(mapping["pa"]),
                                     "via": "existing render mapping"})
            except RuntimeError:
                try:
                    entry = map_at_exact_dva(manifest, table_pages, dva, content,
                                             root_pa=render_root_pa(manifest))
                    entry["via"] = "created in render context"
                    render_pages.append(entry)
                    created.append(entry)
                except Exception as error:
                    unresolved.append({"dva": dva, "error": str(error)})
                    continue
            written.append(dva)
            GRAFTED_PHYSICAL_CONTENT.append((dva, int(render_pages[-1]["pa"]), content))
            continue
        if objects_only:
            slices = owned_slices(dva)
            try:
                # Read first, so the page can be restored byte for byte. Reading also
                # tells us whether it is mapped, without writing anything to find out.
                existing = address_space.read(dva, page_size)
                mapped = True
            except Exception:
                mapped = False
            if mapped:
                # The page exists in the replayed world, so only the submission's own
                # ranges may be written into it.
                for start, end in slices:
                    address_space.write(
                        start, content[start - dva:end - dva])
                if slices:
                    written.append(dva)
                    for start, end in slices:
                        GRAFTED_CONTENT.append((start, content[start - dva:end - dva]))
                else:
                    skipped_pages.append(dva)
                continue
            # Not mapped at all: nothing of the replayed world lives here, so the whole
            # page is the submission's and is created as before.
        try:
            address_space.write(dva, content)
        except Exception:
            # Not mapped in this snapshot's world, which is expected: the driver
            # allocates more memory as a boot proceeds and a later submission
            # references some of it. Create the mapping and record it, rather than
            # leaving a dangling reference for firmware to fault on.
            try:
                created.append(map_at_exact_dva(manifest, table_pages, dva, content))
                address_space.pages[address_space.normalize(dva)
                                    & ~(PAGE_SIZE - 1)] = created[-1]["pa"]
            except Exception as error:
                unresolved.append({"dva": dva, "error": str(error)})
                continue
        written.append(dva)
        GRAFTED_CONTENT.append((dva, content))

    # The outer record carries the item-ring write index, so the queue's write pointer
    # and the ring slot both have to follow it rather than the replayed submission's.
    outer = bytes.fromhex(target["outer_hex"])
    head = struct.unpack_from("<I", outer, 0x14)[0] & 0xFFFF
    if head != pending_end:
        raise RuntimeError(
            "%s outer head %d does not match captured write index %d"
            % (target["channel"], head, pending_end)
        )
    if inner_head is not None:
        # Publish fewer entries than were captured, leaving every grafted byte in place.
        # The flags in the upper half of this word are preserved; only the count changes.
        flags_head = struct.unpack_from("<I", outer, 0x14)[0]
        head = int(inner_head)
        outer = (outer[:0x14]
                 + struct.pack("<I", (flags_head & ~0xFFFF) | (head & 0xFFFF))
                 + outer[0x18:])
    channel = next(c for c in work_state["channels"]
                   if c["name"] == target["channel"])
    publication_count = value(target["producer_after"]) - value(
        target["producer_before"]
    )
    if publication_count <= 0:
        raise RuntimeError(
            "%s capture has invalid producer transition %d -> %d"
            % (
                target["channel"],
                value(target["producer_before"]),
                value(target["producer_after"]),
            )
        )
    existing_producer = channel.get("captured_producer")
    if existing_producer is not None and existing_producer != publication_count:
        raise RuntimeError(
            "%s graft publishes %d outer entries, snapshot expects %d"
            % (target["channel"], publication_count, existing_producer)
        )
    # A pre-control snapshot has no queued TA/3D work. Teach the later publication
    # path how many ring entries this graft contributes, while leaving the live
    # producer at zero until device control has completed.
    channel["captured_producer"] = publication_count
    channel["grafted_producer_before"] = value(target["producer_before"])
    channel["grafted_producer_after"] = value(target["producer_after"])
    # The queue this submission names, taken from the outer record being grafted rather than
    # from the ring. The ring still holds the replayed submission's record at this point, so
    # reading it here patched the pointer state of the queue being replaced instead of the one
    # about to be published, and the graft's write pointer never reached the grafted queue.
    queue_dva = struct.unpack_from("<Q", outer, 8)[0]
    channel["grafted_queue_dva"] = queue_dva
    channel["grafted_outer_hex"] = outer.hex()
    pointer_state = read_dva_u64(address_space, queue_dva)
    write_dva_u32(address_space, pointer_state + 0x40, head)
    if GRAFT_RESET_CONSUMED[0] is not None:
        # Every word of the pointer state that matches the write pointer is a candidate for
        # the consumed pointer; which one it is has not been established here, so rewind them
        # all and report what was touched.
        rewound = []
        snapshot_words = [read_dva_u32(address_space, pointer_state + off)
                          for off in range(0, 0x80, 4)]
        print("  graft %s queue %#x pointer_state %#x head %d words %s"
              % (target["channel"], queue_dva, pointer_state, head,
                 ["+%#04x=%d" % (i * 4, v) for i, v in enumerate(snapshot_words) if v]))
        # Rewind the words that trail the write pointer, which are the consumed pointers.
        # Matching against the write pointer itself found nothing: at graft time these read
        # 29 against a write pointer of 32, so three entries, one work item, were already
        # outstanding and firmware consumed exactly those. Rewinding to zero is what makes
        # all eleven items outstanding.
        for offset in range(0, 0x80, 4):
            if offset == 0x40:
                continue
            value = read_dva_u32(address_space, pointer_state + offset)
            if value and value <= head and value != GRAFT_RESET_CONSUMED[0]:
                write_dva_u32(address_space, pointer_state + offset,
                              GRAFT_RESET_CONSUMED[0])
                rewound.append(offset)
        u.inst("dsb sy")
        print("  rewound %s pointer-state words %s from %d to %d"
              % (target["channel"], ["+%#04x" % off for off in rewound], head,
                 GRAFT_RESET_CONSUMED[0]))
    address_space.write(channel["ring_addr"], outer)
    u.inst("dsb sy")

    return {"pages_written": len(written), "pages_created": created,
            "render_pages": render_pages,
            "pages_skipped": skipped_pages,
            "unresolved": unresolved,
            "channel": target["channel"], "inner_head": head,
            "pending_span": [pending_start, pending_end],
            "pending_records": pending_records,
            "outer_hex": target["outer_hex"],
            "source": str(directory)}


def read_queue_pointer_state(address_space, channel):
    """The queue's 0x80-byte pointer-state block, as 32 words.

    A ring entry names its queue at +0x08, and the queue's first word points at the pointer
    state, whose write pointer is at +0x40.
    """
    queue_dva = channel.get("constructed_queue_dva")
    if queue_dva is None:
        queue_dva = read_dva_u64(address_space, queue_slot_base(channel["ring_addr"]) + 8)
    pointer_state = read_dva_u64(address_space, queue_dva)
    return [read_dva_u32(address_space, pointer_state + offset)
            for offset in range(0, 0x80, 4)]


def format_pointer_state(words):
    """Only the non-zero words, with the write pointer at +0x40 called out."""
    parts = ["+%#04x=%d" % (index * 4, value)
             for index, value in enumerate(words) if value]
    return "write(+0x40)=%d [%s]" % (words[0x10], " ".join(parts) or "all zero")


def replay_second_outer_message(
    asces,
    address_space,
    work_state,
    timeout,
    clear_first_submit,
    append_inner_batch,
    patch_words=(),
    construct_queue=False,
    manifest=None,
    ram=None,
    table_pages=None,
):
    active = [
        channel
        for channel in work_state["channels"]
        if "captured_producer" in channel and not channel.get("disabled")
    ]
    records = []
    for channel in active:
        try:
            next_channel = work_state["channels"][channel["index"] + 1]
        except IndexError as error:
            raise RuntimeError(
                "no adjacent channel ring to derive %s entry stride"
                % channel["name"]
            ) from error
        span = next_channel["ring_addr"] - channel["ring_addr"]
        if span <= 0 or span % WORK_RING_ENTRY_STRIDE:
            raise RuntimeError(
                "unexpected %s adjacent ring span %#x"
                % (channel["name"], span)
            )
        # The stride was derived as span // 0x100, assuming 256 entries a ring, which
        # gives 0x60 for these rings and put the copied message at ring + 0x60. The
        # scheduler's own fault says otherwise: it takes the second entry from ring +
        # 0x18 and holds 0x18 as its stride, so it read the zeros at +0x18 and
        # dereferenced a null, which is exactly the reported fault address. A work
        # entry is 0x18 bytes, so these rings hold 0x400 of them, and the captured
        # ring agrees: the first entry is a complete structure within 0x18 bytes and
        # everything from 0x18 to 0x30 is zero.
        entry_stride = WORK_RING_ENTRY_STRIDE
        values = [
            read_dva_u32(address_space, state_addr)
            for state_addr in channel["state_addrs"]
        ]
        if values[0] != values[2] or values[1] != values[2]:
            raise RuntimeError(
                "%s outer state is not drained before replay: %r"
                % (channel["name"], values)
            )
        source_index = values[2] - 1
        if source_index < 0:
            raise RuntimeError("%s has no captured outer message" % channel["name"])
        target_index = values[2]
        source_dva = channel["ring_addr"] + source_index * entry_stride
        target_dva = channel["ring_addr"] + target_index * entry_stride
        message = bytearray(address_space.read(source_dva, entry_stride))
        first_submit_before = struct.unpack_from("<I", message, 0x14)[0]
        first_submit_after = first_submit_before
        if clear_first_submit:
            first_submit_after &= ~(1 << 24)
        constructed = None
        if construct_queue:
            # Construct once per channel and reuse it, rather than building a fresh
            # queue every round. Building a fresh one each time copies the original
            # write pointer, so the second arrives claiming no more work than firmware
            # has already consumed and firmware correctly does nothing; that stalled a
            # stream after one submission. One queue per ring with its write pointer
            # advanced is also what a working host does.
            cached = channel.get("constructed_queue_dva")
            if cached is not None:
                new_queue_dva, constructed_records = cached, {}
            else:
                queue_dva = read_dva_u64(address_space, queue_slot_base(channel["ring_addr"]) + 8)
                new_queue_dva, constructed_records = construct_queue_objects(
                    manifest, ram, table_pages, address_space, queue_dva,
                    channel["name"])
                channel["constructed_queue_dva"] = new_queue_dva
            struct.pack_into("<Q", message, 8, new_queue_dva)
            constructed = {
                "queue_before": queue_dva,
                "queue_after": new_queue_dva,
                "objects": {name: {"dva": record["dva"],
                                   "relocated_pa": record["relocated_pa"],
                                   "source": record["source"]}
                            for name, record in constructed_records.items()},
            }
        inner_batch = None
        if append_inner_batch:
            # Append into the queue this submission will actually name. With a
            # constructed queue in play that is the constructed one; appending into the
            # original instead leaves the published queue's array and write pointer
            # untouched, so firmware finds no new work and stalls.
            queue_dva = channel.get("constructed_queue_dva")
            if queue_dva is None:
                queue_dva = read_dva_u64(address_space, queue_slot_base(channel["ring_addr"]) + 8)
            pointer_state_dva = read_dva_u64(address_space, queue_dva)
            entry_array_dva = read_dva_u64(address_space, queue_dva + 8)
            inner_head = read_dva_u32(address_space, pointer_state_dva + 0x40)
            if inner_head != (first_submit_before & 0xFFFF):
                raise RuntimeError(
                    "%s outer head %#x does not match inner CPU write pointer %#x"
                    % (channel["name"], first_submit_before & 0xFFFF, inner_head)
                )
            if inner_head == 0:
                raise RuntimeError("%s has an empty inner batch" % channel["name"])
            inner_data = address_space.read(entry_array_dva, inner_head * 8)
            address_space.write(
                entry_array_dva + inner_head * 8, inner_data
            )
            new_inner_head = inner_head * 2
            write_dva_u32(
                address_space, pointer_state_dva + 0x40, new_inner_head
            )
            first_submit_after = (
                (first_submit_before & ~((1 << 24) | 0xFFFF)) | new_inner_head
            )
            inner_batch = {
                "pointer_state_dva": pointer_state_dva,
                "entry_array_dva": entry_array_dva,
                "head_before": inner_head,
                "head_after": new_inner_head,
                "copied_entry_count": inner_head,
            }
        struct.pack_into("<I", message, 0x14, first_submit_after)
        # Fields other than +0x14 have never been varied in a copied outer message.
        # The one worth varying is +0x04, which is zero in the captured first
        # submission and which an external reference names as a submission sequence
        # counter; a copy that leaves it zero is claiming to be a first submission
        # again. Kept general rather than special-casing that offset, so a sweep of
        # any word costs an argument rather than a code change.
        patched_words = []
        for offset, value in (patch_words or ()):
            before_word = struct.unpack_from("<I", message, offset)[0]
            struct.pack_into("<I", message, offset, value)
            patched_words.append({"offset": offset,
                                  "before": before_word,
                                  "after": value})
        address_space.write(target_dva, message)
        write_dva_u32(address_space, channel["state_addrs"][2], target_index + 1)
        records.append(
            {
                "channel": channel["name"],
                "entry_stride": entry_stride,
                "source_index": source_index,
                "target_index": target_index,
                "source_dva": source_dva,
                "target_dva": target_dva,
                "producer_before": values[2],
                "producer_after": target_index + 1,
                "word_14_before": first_submit_before,
                "word_14_after": first_submit_after,
                "patched_words": patched_words,
                "constructed_queue": constructed,
                "inner_batch": inner_batch,
            }
        )

    u.inst("dsb sy")
    # Immediately before the doorbell, so a counter that is already at its target is
    # distinguishable from one firmware raises in response. The drained-state check above
    # implies this, but implying is what made a vacuous run look like a passing one.
    before = {}
    queue_state = {}
    shared_before = None
    if DIFF_SHARED[0]:
        for channel in active:
            before[channel["name"]] = [
                read_dva_u32(address_space, addr) for addr in channel["state_addrs"][:3]
            ]
            print("  before publish %s counters %s"
                  % (channel["name"], before[channel["name"]]))
            queue_state[channel["name"]] = read_queue_pointer_state(
                address_space, channel)
            print("  before publish %s queue pointer state %s"
                  % (channel["name"], format_pointer_state(queue_state[channel["name"]])))
        shared_before = snapshot_shared_regions()
    # This doorbell is rung by the host, so a baseline taken here genuinely brackets a
    # submission. The same scan taken around the first work cannot, because on the
    # resume path that work has already been consumed before the harness arrives.
    publish_scan_baseline = (
        scan_render_baseline(manifest, SCAN_RENDER_PREFIX[0])
        if SCAN_RENDER_PREFIX[0] and manifest is not None else None
    )
    asces[0].send(0x0083000000000000, ASCMessage1(EP=0x21))
    for channel in active:
        expected = read_dva_u32(address_space, channel["state_addrs"][2])
        wait_dva_counters(
            asces,
            address_space,
            channel["state_addrs"][:2],
            [expected, expected],
            timeout,
            channel["name"] + " second outer message",
        )
    if before:
        for channel in active:
            after = [read_dva_u32(address_space, addr) for addr in channel["state_addrs"][:3]]
            print("  after publish  %s counters %s (was %s)"
                  % (channel["name"], after, before[channel["name"]]))
            now = read_queue_pointer_state(address_space, channel)
            was = queue_state.get(channel["name"])
            print("  after publish  %s queue pointer state %s"
                  % (channel["name"], format_pointer_state(now)))
            if was is not None:
                moved = [(index * 4, a, b)
                         for index, (a, b) in enumerate(zip(was, now)) if a != b]
                print("     queue words changed: %s"
                      % (", ".join("+%#04x %d->%d" % m for m in moved) or "none"))
    if publish_scan_baseline is not None:
        scan_render_writes(manifest, publish_scan_baseline, SCAN_RENDER_PREFIX[0])
    if shared_before is not None:
        print("Shared-region difference across the publishing doorbell:")
        report_shared_diff(shared_before)
    if VERIFY_GRAFTED[0]:
        # After the stream rather than before it. The check inside submit_first_work runs
        # before any extra submission has been published, so it can only ever describe the
        # first one; a streaming sequence that completes repeatedly is the interesting case.
        print("After the publishing doorbell:")
        report_grafted_changes(address_space)
    return records


def dump_state(path, asces, manifest, init_message, work_state=None):
    sgx = u.adt["/arm-io/sgx"]
    handoff = int(sgx.gfx_handoff_base)
    gpu_region = int(sgx.gpu_region_base)
    result = {
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "gpu_region_qwords": [
            int(p.read64(gpu_region + offset)) for offset in range(0, 0x40, 8)
        ],
        "handoff_qwords": [
            int(p.read64(handoff + offset)) for offset in range(0, 0x80, 8)
        ],
        "asces": [],
        "init_message": int(init_message),
    }
    if work_state is not None:
        result["work_replay"] = work_state
    for asc in asces:
        result["asces"].append(
            {
                "name": asc.replay_name,
                "base": int(asc.asc._base),
                "cpu_control": int(asc.asc.CPU_CONTROL.val),
                "cpu_status": int(asc.asc.CPU_STATUS.val),
                "inbox_ctrl": int(asc.asc.INBOX_CTRL.val),
                "outbox_ctrl": int(asc.asc.OUTBOX_CTRL.val),
                "init_ack": bool(asc.fw.init_ack),
                "events": int(asc.fw.events),
            }
        )
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


def run():
    snapshot, manifest, manifest_bytes, ram = load_snapshot(args.snapshot)
    # The world whose control channel stays live is the one captured before device control, and it
    # has no work in it, so every model this harness derives from the snapshot image comes out
    # empty. The later capture has the work. The two images are structurally identical, with the
    # same 663 mappings and 10,007 root mappings in the same order with the same blob indices and
    # the same size, so one image's pages can be restored while the other's are read for the model.
    restore_ram = ram
    if args.work_model_snapshot:
        _, model_manifest, _, model_ram = load_snapshot(args.work_model_snapshot)
        for key in ("init_message", "vaddr_shift"):
            if int(model_manifest[key]) != int(manifest[key]):
                raise SystemExit(
                    "the work-model snapshot disagrees on %s, so it is not the same world" % key)
        if len(model_ram) != len(ram):
            raise SystemExit("the work-model snapshot has a different image size")
        print("Reading the work model from %s while restoring %s"
              % (args.work_model_snapshot, args.snapshot))
        ram = model_ram
    SNAPSHOT_RAM[0] = ram
    post_control_overlay = None
    post_control_overlay_info = None
    if args.post_control_overlay:
        post_control_overlay, post_control_overlay_info = (
            # Against the image actually restored, not the one the work model is read from. With
            # both set to the later capture the delta is empty and the overlay silently does
            # nothing, which is the same as not passing it at all.
            prepare_post_control_overlay(
                manifest, restore_ram, args.post_control_overlay)
        )
    init_message = (
        int(args.init_message)
        if args.init_message is not None
        else int(manifest["init_message"])
    )
    if ((init_message >> 48) & 0xFF) != 0x81:
        raise RuntimeError(
            "init message must have type 0x81; use --init-message for "
            "non-init capture manifests"
        )
    attempt_manifest = {
        "format": "m1n1-agx-g17p-initdata-replay-attempt-v1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snapshot": str(snapshot),
        "snapshot_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "snapshot_ram_sha256": manifest["ram_sha256"],
        "post_control_overlay": post_control_overlay_info,
        "watched_render_dvas": [int(dva) for dva in args.watch_render_dva],
        "watch_render_from_start": bool(args.watch_render_from_start),
        "clear_watched_render_before_extra_submissions": bool(
            args.clear_watched_render_before_extra_submissions
        ),
        "rebuild_compute_work": bool(args.rebuild_compute_work),
        "rebuild_compute_client": bool(args.rebuild_compute_client),
        "rebuild_compute_registration": bool(
            args.rebuild_compute_registration
        ),
        "backend_graft_firmware_pages": (
            str(args.backend_graft_firmware_pages)
            if args.backend_graft_firmware_pages is not None else None
        ),
        "backend_graft_firmware_page_slice": list(
            args.backend_graft_firmware_page_slice
        ),
        "restore_mode": "original-physical-address",
        "timeout_seconds": args.timeout,
        "init_message": init_message,
        "clear_hardware_context_zero": bool(args.clear_hardware_context_zero),
        "zero_transitive_extra_firmware_pages": (
            list(args.zero_transitive_extra_firmware_pages)
            if args.zero_transitive_extra_firmware_pages is not None
            else None
        ),
        "source_config_snapshot": (
            str(args.source_config_snapshot)
            if args.source_config_snapshot is not None else None
        ),
        "graft_source_config_pages": [
            int(dva) for dva in args.graft_source_config_page
        ],
        "graft_all_modeled_source_config_pages": bool(
            args.graft_all_modeled_source_config_pages
        ),
        "zero_unreferenced_init_pages": bool(args.zero_unreferenced_init_pages),
        "unmap_unreferenced_init_pages": (
            list(args.unmap_unreferenced_init_pages)
            if args.unmap_unreferenced_init_pages is not None
            else None
        ),
        "relocate_initdata_page": bool(args.relocate_initdata_page),
        "relocate_secondary_initdata_page": bool(
            args.relocate_secondary_initdata_page
        ),
        "relocate_first_work_descriptor_pages": bool(
            args.relocate_first_work_descriptor_pages
        ),
        "relocate_first_work_direct_target_pages": bool(
            args.relocate_first_work_direct_target_pages
        ),
        "relocate_first_work_support_item_pages": bool(
            args.relocate_first_work_support_item_pages
        ),
        "new_first_ta_descriptor_dva": bool(args.new_first_ta_descriptor_dva),
        "new_first_3d_descriptor_dva": bool(args.new_first_3d_descriptor_dva),
        "build_ta_descriptor": bool(args.build_ta_descriptor),
        "build_ta_captured_tail": bool(args.build_ta_captured_tail),
        "build_3d_descriptor": bool(args.build_3d_descriptor),
        "build_render_register_recipe": bool(
            args.build_render_register_recipe
        ),
        "relocate_render_status_pages": bool(
            args.relocate_render_status_pages
        ),
        "redirect_descriptor_backreferences": bool(
            args.redirect_descriptor_backreferences
        ),
        "mirror_backend_global_descriptors": bool(
            args.mirror_backend_global_descriptors
        ),
        "mirror_status_relocation_in_global_descriptors": bool(
            args.mirror_status_relocation_in_global_descriptors
        ),
        "build_3d_captured_header": bool(args.build_3d_captured_header),
        "build_3d_captured_tail": bool(args.build_3d_captured_tail),
        "build_structural_tails": bool(args.build_structural_tails),
        "build_ta_structural_tail": bool(args.build_ta_structural_tail),
        "build_3d_structural_tail": bool(args.build_3d_structural_tail),
        "build_structural_tail_ranges": [
            {"kind": kind, "start": start, "end": end}
            for kind, start, end in args.build_structural_tail_range
        ],
        "new_first_work_support_item_dvas": bool(
            args.new_first_work_support_item_dvas
        ),
        "relocate_ta_descriptor_backreference_page": bool(
            args.relocate_ta_descriptor_backreference_page
        ),
        "relocate_3d_descriptor_backreference_page": bool(
            args.relocate_3d_descriptor_backreference_page
        ),
        "first_work_u32_patches": [
            {"channel": channel, "offset": offset, "replacement": replacement}
            for channel, offset, replacement in args.patch_first_work_u32
        ],
        "first_work_u64_patches": [
            {"channel": channel, "offset": offset, "replacement": replacement}
            for channel, offset, replacement in args.patch_first_work_u64
        ],
        "first_work_descriptor_pair": (
            None if args.first_work_descriptor_pair is None
            else int(args.first_work_descriptor_pair)
        ),
        "dva_copies": [
            {"source": source, "destination": destination, "size": size}
            for source, destination, size in args.copy_dva_range
        ],
        "restore_coprocessor_data_regions": bool(
            args.restore_coprocessor_data_regions
        ),
        "replay_first_work": bool(args.replay_first_work),
        "control_producer": args.control_producer,
        "control_only": bool(args.control_only),
        "init_only": bool(args.init_only),
        "resume_post_control": bool(args.resume_post_control),
        "reapply_snapshot_after_control": bool(
            args.reapply_snapshot_after_control
        ),
        "prestage_control": bool(args.prestage_control),
        "sequence_control_doorbells": bool(args.sequence_control_doorbells),
        "use_captured_work_message": bool(args.use_captured_work_message),
        "graft_reuse_active_queues": bool(args.graft_reuse_active_queues),
        "disabled_work_channels": list(args.disable_work_channel),
        "deferred_work_channels": list(args.defer_work_channel),
        "queue_state_40": args.queue_state_40,
        "cleared_work_items_before_control": sorted(
            set(args.clear_work_item_before_control)
        ),
        "cleared_work_items_after_control": sorted(
            set(args.clear_work_item_after_control)
        ),
        "replay_second_outer_message": bool(args.replay_second_outer_message),
        "second_outer_clear_first_submit": bool(
            args.second_outer_clear_first_submit
        ),
        "append_second_inner_batch": bool(args.append_second_inner_batch),
        "coproc_maint": bool(args.coproc_maint),
        "dump_pre_control_state": bool(args.dump_pre_control_state),
        "heap_base": int(u.heap_base),
        "heap_top": int(u.heap_top),
        "result": "running",
    }
    attempt_manifest_path = attempt_dir / "attempt.json"
    attempt_manifest_path.write_text(
        json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
    )

    print("Attempt artifacts: %s" % attempt_dir)
    print("Snapshot: %s" % snapshot)
    print("Proxy heap: %#x-%#x" % (u.heap_base, u.heap_top))
    _, table_pages = restore_snapshot(
        snapshot,
        manifest,
        restore_ram,
        include_coprocessor_data=args.restore_coprocessor_data_regions,
    )
    if args.clear_hardware_context_zero:
        gpu_region = int(u.adt["/arm-io/sgx"].gpu_region_base)
        before = [int(p.read64(gpu_region + offset)) for offset in (0, 8)]
        p.write64(gpu_region, 0)
        p.write64(gpu_region + 8, 0)
        p.dc_civac(gpu_region, 0x10)
        u.inst("dsb osh; tlbi vmalle1os; dsb osh; isb")
        after = [int(p.read64(gpu_region + offset)) for offset in (0, 8)]
        attempt_manifest["hardware_context_zero"] = {
            "gpu_region": gpu_region,
            "before": before,
            "after": after,
        }
        attempt_manifest_path.write_text(
            json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
        )
        print("Cleared raw hardware context 0: %s -> %s"
              % (" ".join("%#x" % value for value in before),
                 " ".join("%#x" % value for value in after)))
    if args.zero_unreachable_firmware_pages:
        # Only the firmware root's own pages, and only those the descriptor cannot reach. Every
        # other root, the render context above all, is left exactly as restored.
        reachable = initdata_transitive_firmware_pages(manifest, ram, init_message)
        selected_index = int(manifest["selected_root"]["index"])
        firmware_pages = {
            int(mapping["pa"]) & ~(PAGE_SIZE - 1)
            for group in manifest["root_mappings"]
            if int(group["root_index"]) == selected_index
            for mapping in group["mappings"]
            if mapping.get("blob_index") is not None
        }
        zero_pages = sorted(firmware_pages - set(reachable))
        print("Firmware root has %d captured pages; the descriptor reaches %d; zeroing %d"
              % (len(firmware_pages), len(firmware_pages & set(reachable)),
                 len(zero_pages)))
        for pa in zero_pages:
            iface.writemem(pa, bytes(PAGE_SIZE))
        for pa, size in merge_ranges((page, PAGE_SIZE) for page in zero_pages):
            p.dc_civac(pa, size)
        u.inst("dsb sy")
        u.inst("tlbi vmalle1os")
        u.inst("dsb sy")
        u.inst("isb")
        attempt_manifest["zeroed_unreachable_firmware_pages"] = {
            "firmware_pages": len(firmware_pages),
            "reachable": len(firmware_pages & set(reachable)),
            "zeroed": len(zero_pages),
        }

    if (
        args.zero_unreferenced_init_pages
        or args.unmap_unreferenced_init_pages is not None
    ):
        reachable, unresolved = initdata_reachable_blob_pages(
            manifest, ram, init_message)
        blob_pages = {
            int(page["original_pa"]) & ~(PAGE_SIZE - 1)
            for page in manifest["blob_pages"]
        }
        zero_pages = sorted(blob_pages - set(reachable))
        for completed, pa in enumerate(zero_pages, start=1):
            iface.writemem(pa, bytes(PAGE_SIZE))
            if completed % 64 == 0 or completed == len(zero_pages):
                print("  zeroed unreferenced RAM pages %d/%d"
                      % (completed, len(zero_pages)))
        for pa, size in merge_ranges(
            (page, PAGE_SIZE) for page in zero_pages
        ):
            p.dc_civac(pa, size)
        u.inst("dsb sy")
        u.inst("tlbi vmalle1os")
        u.inst("dsb sy")
        u.inst("isb")
        unmapped = []
        if args.unmap_unreferenced_init_pages is not None:
            selected_index = int(manifest["selected_root"]["index"])
            zero_page_set = set(zero_pages)
            candidates = sorted(
                (
                    mapping
                    for mapping_set in manifest["root_mappings"]
                    if int(mapping_set["root_index"]) == selected_index
                    for mapping in mapping_set["mappings"]
                    if mapping.get("blob_index") is not None
                    and (
                        int(mapping["pa"]) & ~(PAGE_SIZE - 1)
                    ) in zero_page_set
                ),
                key=lambda mapping: int(mapping["va"]),
            )
            first, last = args.unmap_unreferenced_init_pages
            if last is None:
                last = len(candidates)
            if first >= len(candidates) or last > len(candidates):
                raise RuntimeError(
                    "unreferenced mapping slice %d:%d exceeds %d candidates"
                    % (first, last, len(candidates))
                )

            dirty_tables = {}
            for index, mapping in enumerate(candidates[first:last], start=first):
                dva = int(mapping["va"])
                _raw, l3_pa, l3_index = selected_l3_location(
                    manifest, table_pages, dva
                )
                table = dirty_tables.setdefault(
                    l3_pa, bytearray(table_pages[l3_pa])
                )
                offset = l3_index * 8
                before = struct.unpack_from("<Q", table, offset)[0]
                if before != int(mapping["pte"]):
                    raise RuntimeError(
                        "leaf for candidate %d DVA %#x changed: %#x != %#x"
                        % (index, dva, before, int(mapping["pte"]))
                    )
                struct.pack_into("<Q", table, offset, 0)
                unmapped.append(
                    {
                        "index": index,
                        "dva": dva,
                        "pa": int(mapping["pa"]) & ~(PAGE_SIZE - 1),
                        "pte": before,
                    }
                )

            for table_pa, table in dirty_tables.items():
                data = bytes(table)
                iface.writemem(table_pa, data)
                p.dc_civac(table_pa, PAGE_SIZE)
                table_pages[table_pa] = data
            u.inst("dsb sy")
            u.inst("tlbi vmalle1os")
            u.inst("dsb sy")
            u.inst("isb")
            print(
                "Unmapped unreferenced selected-root leaves %d:%d of %d "
                "(DVA %#x..%#x)"
                % (
                    first,
                    last,
                    len(candidates),
                    unmapped[0]["dva"],
                    unmapped[-1]["dva"],
                )
            )
        attempt_manifest["initdata_page_classes"] = {
            "reachable_pages": len(reachable),
            "zeroed_pages": len(zero_pages),
            "reachable": {
                "%#x" % pa: labels for pa, labels in sorted(reachable.items())
            },
            "unresolved_pointers": unresolved,
            "unreferenced_mapping_candidates": (
                len(candidates)
                if args.unmap_unreferenced_init_pages is not None
                else None
            ),
            "unmapped": unmapped,
        }
        attempt_manifest_path.write_text(
            json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
        )
        print("Retained %d known initdata pages; zeroed %d other mapped pages; "
              "%d known pointers were not captured mappings"
              % (len(reachable), len(zero_pages), len(unresolved)))
    def _do_graft():
        # Convergence from the other direction. This world renders; the cold-boot world does not,
        # and every input comparison between them now matches. So take this world's captured
        # firmware pages and overwrite them, a subset at a time, with the cold boot's own content
        # for the same address, and find the subset that stops it rendering. That names a page
        # whose content differs and matters, which no input comparison has been able to do.
        directory = pathlib.Path(args.graft_firmware_pages)
        graft_root_index = (
            int(manifest["selected_root"]["index"])
            if args.graft_root_index is None
            else int(args.graft_root_index)
        )

        def graft_mapping(dva):
            return root_mapping_at(manifest, dva, graft_root_index)

        def captured_page(dva):
            mapping = graft_mapping(dva)
            blob_index = mapping.get("blob_index")
            if blob_index is None:
                raise RuntimeError(
                    "root-%d DVA %#x has no captured RAM page" %
                    (graft_root_index, dva)
                )
            start = int(blob_index) * PAGE_SIZE
            return ram[start:start + PAGE_SIZE]

        source_pages = []
        source_manifest_path = directory / "manifest.json"
        if source_manifest_path.is_file():
            source_manifest = json.loads(source_manifest_path.read_text())
        else:
            source_manifest = {}
        if source_manifest.get("format") == \
                "m1n1-t8140-g17p-live-uat-pages-v1":
            source_raw = (directory / "pages.bin").read_bytes()
            for record in source_manifest["pages"]:
                offset = int(record["capture_offset"])
                body = source_raw[offset:offset + PAGE_SIZE]
                if len(body) != PAGE_SIZE:
                    raise RuntimeError(
                        "truncated source root page at %#x" %
                        int(record["dva"])
                    )
                source_pages.append((int(record["dva"]), body))
        else:
            for path in sorted(directory.glob("*.bin")):
                try:
                    dva = int(path.stem, 16)
                except ValueError:
                    continue
                source_pages.append((dva, path.read_bytes()[:PAGE_SIZE]))

        available = []
        for dva, source_body in source_pages:
            if args.graft_different_only:
                try:
                    captured_body = captured_page(dva)
                except RuntimeError:
                    # A source-only DVA is not graftable into this replay and
                    # therefore is not part of its content bisection.
                    continue
                if source_body == captured_body:
                    continue
            available.append((dva, source_body))
        first, _, last = (args.graft_page_slice or "").partition(":")
        begin = int(first) if first else 0
        end = int(last) if last else len(available)
        chosen = available[begin:end]
        print("Grafting cold-boot content over captured root-%d pages: "
              "%d of %d, slice %d:%d"
              % (graft_root_index, len(chosen), len(available), begin, end))
        grafted = []
        for dva, body in chosen:
            try:
                mapping = graft_mapping(dva)
                pa = int(mapping["pa"])
            except Exception as exc:
                print("  %#x is not a captured root-%d mapping here: %s" %
                      (dva, graft_root_index, exc))
                continue
            iface.writemem(pa, body[:PAGE_SIZE])
            p.dc_civac(pa, PAGE_SIZE)
            grafted.append("%#x" % dva)
            print("  grafted %#x at pa %#x, %d non-zero bytes"
                  % (dva, pa, sum(b != 0 for b in body[:PAGE_SIZE])))
        u.inst("dsb sy")
        attempt_manifest["grafted_firmware_pages"] = grafted

    if args.graft_before_first_work:
        if args.graft_firmware_pages is None:
            parser.error(
                "--graft-before-first-work requires --graft-firmware-pages")
        if args.graft_after_boot:
            parser.error(
                "--graft-before-first-work and --graft-after-boot are "
                "mutually exclusive")
        PRE_FIRST_WORK_GRAFT[0] = _do_graft
    if (args.graft_firmware_pages is not None
            and not args.graft_after_boot
            and not args.graft_before_first_work):
        _do_graft()

    if args.rebuild_descriptor:
        attempt_manifest["rebuilt_descriptor"] = rebuild_descriptor_objects(
            manifest, ram, init_message, args.zero_opaque_fields,
            zero_runs=args.zero_opaque_runs,
        )
        attempt_manifest_path.write_text(
            json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
        )
    page_relocations = {}
    virtual_page_overrides = {}
    initdata_relocations = []
    if args.relocate_initdata_page:
        mapping = selected_mapping_at(manifest, init_message)
        relocation = relocate_mapping_page(
            manifest, ram, table_pages, mapping, "primary-initdata"
        )
        page_relocations[relocation["original_pa"]] = relocation["relocated_pa"]
        initdata_relocations.append(relocation)
        print(
            "Relocated %s DVA %#x: %#x -> %#x"
            % (
                relocation["label"],
                relocation["dva"],
                relocation["original_pa"],
                relocation["relocated_pa"],
            )
        )
    if args.relocate_secondary_initdata_page:
        secondary_dva = (init_message & ~((1 << 44) - 1)) | (
            (init_message + 0x8000) & ((1 << 44) - 1)
        )
        mapping = selected_mapping_at(manifest, secondary_dva)
        relocation = relocate_mapping_page(
            manifest, ram, table_pages, mapping, "secondary-initdata"
        )
        page_relocations[relocation["original_pa"]] = relocation["relocated_pa"]
        initdata_relocations.append(relocation)
        print(
            "Relocated %s DVA %#x: %#x -> %#x"
            % (
                relocation["label"],
                relocation["dva"],
                relocation["original_pa"],
                relocation["relocated_pa"],
            )
        )
    if args.relocate_first_work_descriptor_pages:
        for name, mapping in first_work_descriptor_mappings(
            manifest, ram, init_message
        ):
            relocation = relocate_mapping_page(
                manifest,
                ram,
                table_pages,
                mapping,
                name + "-first-work-descriptor",
            )
            page_relocations[relocation["original_pa"]] = relocation[
                "relocated_pa"
            ]
            initdata_relocations.append(relocation)
            print(
                "Relocated %s DVA %#x: %#x -> %#x"
                % (
                    relocation["label"],
                    relocation["dva"],
                    relocation["original_pa"],
                    relocation["relocated_pa"],
                )
            )
    if args.relocate_first_work_direct_target_pages:
        for name, mapping in first_work_direct_target_mappings(
            manifest, ram, init_message
        ):
            relocation = relocate_mapping_page(
                manifest, ram, table_pages, mapping, name
            )
            page_relocations[relocation["original_pa"]] = relocation[
                "relocated_pa"
            ]
            initdata_relocations.append(relocation)
            print(
                "Relocated %s DVA %#x: %#x -> %#x"
                % (
                    relocation["label"],
                    relocation["dva"],
                    relocation["original_pa"],
                    relocation["relocated_pa"],
                )
            )
    if args.relocate_first_work_support_item_pages:
        for name, mapping in first_work_support_item_mappings(
            manifest, ram, init_message
        ):
            relocation = relocate_mapping_page(
                manifest, ram, table_pages, mapping, name
            )
            page_relocations[relocation["original_pa"]] = relocation[
                "relocated_pa"
            ]
            initdata_relocations.append(relocation)
            print(
                "Relocated %s DVA %#x: %#x -> %#x"
                % (
                    relocation["label"],
                    relocation["dva"],
                    relocation["original_pa"],
                    relocation["relocated_pa"],
                )
            )
    new_ta_descriptor = None
    new_3d_descriptor = None
    built_submission_objects = None
    built_shared_objects = None
    built_leaf_pages = None
    built_optional_scratch = None
    built_optional_items = None
    built_event_items = None
    global_descriptor_status_patches = []
    descriptor_status_aliases = {}
    backend_global_descriptor_patches = []
    new_support_item_dvas = {}
    ta_descriptor_backreference = None
    three_d_descriptor_backreference = None
    if args.redirect_descriptor_backreferences:
        ta_descriptor_backreference = first_ta_descriptor_backreference(
            manifest, ram, init_message
        )
        three_d_descriptor_backreference = first_3d_descriptor_backreference(
            manifest, ram, init_message
        )
    if args.relocate_ta_descriptor_backreference_page:
        ta_descriptor_backreference = first_ta_descriptor_backreference(
            manifest, ram, init_message
        )
        relocation = relocate_mapping_page(
            manifest,
            ram,
            table_pages,
            ta_descriptor_backreference["mapping"],
            "TA_0-descriptor-backreference-page",
        )
        page_relocations[relocation["original_pa"]] = relocation["relocated_pa"]
        initdata_relocations.append(relocation)
        ta_descriptor_backreference["relocation"] = relocation
        print(
            "Relocated TA descriptor back-reference page DVA %#x: %#x -> %#x"
            % (
                relocation["dva"],
                relocation["original_pa"],
                relocation["relocated_pa"],
            )
        )
    if args.relocate_3d_descriptor_backreference_page:
        three_d_descriptor_backreference = first_3d_descriptor_backreference(
            manifest, ram, init_message
        )
        relocation = relocate_mapping_page(
            manifest,
            ram,
            table_pages,
            three_d_descriptor_backreference["mapping"],
            "3D_0-descriptor-backreference-page",
        )
        page_relocations[relocation["original_pa"]] = relocation["relocated_pa"]
        initdata_relocations.append(relocation)
        three_d_descriptor_backreference["relocation"] = relocation
        print(
            "Relocated 3D descriptor back-reference page DVA %#x: %#x -> %#x"
            % (
                relocation["dva"],
                relocation["original_pa"],
                relocation["relocated_pa"],
            )
        )
    for dva in (args.corrupt_render_page or ()):
        # Relocate a render page and then overwrite it, which is the only way to ask
        # whether the accelerator reads it. A relocation on its own answers nothing
        # unless the page is written, and a page that is only read never is. Mappedness
        # is no use either: the render context maps most of its low pages, so an address
        # resolving there distinguishes nothing.
        mapping = render_context_mapping(manifest, dva)
        relocation = relocate_mapping_page(
            manifest, ram, table_pages, mapping, "corrupt-render-%#x" % dva)
        page_relocations[relocation["original_pa"]] = relocation["relocated_pa"]
        initdata_relocations.append(relocation)
        iface.writemem(relocation["relocated_pa"], b"\xa5" * PAGE_SIZE)
        p.dc_civac(relocation["relocated_pa"], PAGE_SIZE)
        u.inst("dsb sy")
        print("Corrupted render page DVA %#x at %#x"
              % (relocation["dva"], relocation["relocated_pa"]))

    for dva in (args.relocate_render_page or ()):
        # Move a page of render state into host memory, keeping its render-context
        # address. This is the render-context counterpart of the firmware-context
        # relocations above, and it tests something they cannot: whether the
        # accelerator will read render state out of memory the host owns. Its address
        # is unchanged, so this separates "host memory" from "host address"; only the
        # first is under test here.
        mapping = render_context_mapping(manifest, dva)
        relocation = relocate_mapping_page(
            manifest, ram, table_pages, mapping, "render-page-%#x" % dva)
        page_relocations[relocation["original_pa"]] = relocation["relocated_pa"]
        initdata_relocations.append(relocation)
        print("Relocated render page DVA %#x: %#x -> %#x"
              % (relocation["dva"], relocation["original_pa"],
                 relocation["relocated_pa"]))

    if (
        args.build_ta_descriptor
        or args.build_3d_descriptor
        or args.build_first_optional_items
        or args.build_first_event_items
        or args.build_shared_descriptor_objects
        or args.build_submission_leaf_pages
        or args.relocate_optional_scratch_alias
        or args.build_render_register_recipe
    ):
        # Loaded by path rather than as m1n1.agx.g17p_submission, because importing
        # that package runs its __init__ and pulls in version-dependent construct
        # definitions which raise when no version key is set, as this harness does not
        # set one. The module itself is deliberately dependency-free for exactly this.
        import importlib.util
        _spec = importlib.util.spec_from_file_location(
            "g17p_submission",
            pathlib.Path(__file__).resolve().parents[1]
            / "m1n1" / "agx" / "g17p_submission.py")
        g17p_build = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(g17p_build)

        _render_spec = importlib.util.spec_from_file_location(
            "g17p_render",
            pathlib.Path(__file__).resolve().parents[1]
            / "m1n1" / "agx" / "g17p_render.py")
        g17p_render = importlib.util.module_from_spec(_render_spec)
        sys.modules[_render_spec.name] = g17p_render
        _render_spec.loader.exec_module(g17p_render)

        _encoder_spec = importlib.util.spec_from_file_location(
            "g17p_encoder",
            pathlib.Path(__file__).resolve().parents[1]
            / "m1n1" / "agx" / "g17p_encoder.py")
        g17p_encoder = importlib.util.module_from_spec(_encoder_spec)
        sys.modules[_encoder_spec.name] = g17p_encoder
        _encoder_spec.loader.exec_module(g17p_encoder)

        descriptor_mappings = dict(
            first_work_descriptor_mappings(manifest, ram, init_message)
        )

        def captured_work_model(channel, kind):
            mapping = descriptor_mappings[channel]
            source = int(mapping.get("descriptor_dva", mapping["va"]))
            selector = 0x00 if kind == "tiling" else 0x01
            captured = read_snapshot_dva_bytes(
                manifest, ram, source, item_record_size(selector)
            )
            layout = g17p_build.DESCRIPTOR_LAYOUT[kind]
            cursor = layout["pointers"]
            objects = [struct.unpack_from("<Q", captured, cursor)[0]]
            cursor += 8 + layout["pointer_gap"]
            for _ in range(3):
                objects.append(struct.unpack_from("<Q", captured, cursor)[0])
                cursor += 8

            registers = []
            cursor = layout["registers"]
            empties = 0
            while cursor + g17p_build.REGISTER_ENTRY_SIZE <= PAGE_SIZE:
                number = struct.unpack_from("<I", captured, cursor)[0]
                data = struct.unpack_from("<Q", captured, cursor + 4)[0]
                if number == 0 and data == 0:
                    empties += 1
                    if empties >= 3:
                        break
                else:
                    empties = 0
                    registers.append((number, data))
                cursor += g17p_build.REGISTER_ENTRY_SIZE
            return source, objects, registers, captured

        def build_backend_structural_record(
            kind, body, captured, model_bytes, registers, parameters
        ):
            """Generate the full-record view with the production backend.

            The four low self aliases are allocation inputs, not copied command
            state; this replay keeps the aliases of the restored render context
            while rebuilding every scalar and other pointer from backend rules.
            """
            backend_module = load_backend_package()
            pair = int(
                args.first_work_channel_pair
                if args.first_work_descriptor_pair is None
                else args.first_work_descriptor_pair
            )
            builder = backend_module.G17PWorkBuilder(
                lambda _size, _name: 0,
                lambda _address, _payload: None,
                kind=kind,
                queue_pair=pair,
            )
            stride = int(builder.BODY_STRIDE[kind])
            if len(body) < stride:
                body.extend(bytes(stride - len(body)))
            original = bytearray(body)
            generated = bytearray(body)
            generated[model_bytes:stride] = bytes(stride - model_bytes)

            for offset, value in builder.BODY_FIELDS.get(kind, ()):
                generated[offset] = value

            for offset, value, role in builder.TAIL_POINTERS[kind]:
                # These are placement inputs of the restored runtime graph,
                # not command state. Preserve its allocation bindings while
                # reconstructing every scalar and workload-dependent field.
                if role in ("self", "status") or offset in (0x0934, 0x21ce):
                    value = struct.unpack_from("<Q", captured, offset)[0]
                elif role == "pair_slot":
                    value += pair * 8
                struct.pack_into("<Q", generated, offset, value)

            pair_offset, kind_index = builder.PAIR_GRID_FIELDS[kind]
            struct.pack_into(
                "<I", generated, pair_offset, pair * 2 + kind_index
            )
            lifecycle_register, high_offset, low_offset = (
                builder.LIFECYCLE_FIELDS[kind]
            )
            lifecycle = dict(registers).get(lifecycle_register, 0)
            struct.pack_into("<Q", generated, high_offset, lifecycle >> 32)
            struct.pack_into(
                "<Q", generated, low_offset, lifecycle & 0xffffffff
            )
            builder._write_item_tail_fields(generated, 0, pair)
            builder._write_structural_tail(generated, parameters, registers)

            ranges = [
                (start, end)
                for range_kind, start, end in args.build_structural_tail_range
                if range_kind == kind
            ]
            if ranges:
                body = original
                for start, end in ranges:
                    if start < model_bytes or end > stride:
                        raise RuntimeError(
                            "%s structural-tail range %#x:%#x is outside "
                            "the tail %#x:%#x"
                            % (kind, start, end, model_bytes, stride)
                        )
                    body[start:end] = generated[start:end]
                    print(
                        "  spliced generated %s tail bytes %#x:%#x"
                        % (kind, start, end)
                    )
            else:
                body = generated
            print(
                "Built %s structural full-record view (%#x bytes)"
                % (kind, stride)
            )
            return body

        built_render_registers = None
        if args.build_render_register_recipe:
            (
                captured_ta_dva,
                _,
                captured_ta_registers,
                captured_ta,
            ) = captured_work_model("TA_0", "tiling")
            (
                captured_fragment_dva,
                _,
                captured_fragment_registers,
                captured_fragment,
            ) = captured_work_model("3D_0", "fragment")

            # Keep the output-positive replay's descriptor identity, status
            # aliases, runtime-control binding, and submission lifecycle.  A
            # source pre-notify snapshot can replace only the workload recipe
            # used to derive the ordered register programs and partial
            # load/store tail.  This cleanly separates command encoding from
            # the captured admission state without installing captured source
            # bytes into the live firmware graph.
            recipe_ta_registers = captured_ta_registers
            recipe_fragment_registers = captured_fragment_registers
            recipe_ta = captured_ta
            recipe_fragment = captured_fragment
            if args.backend_render_recipe_snapshot is not None:
                recipe_dir = args.backend_render_recipe_snapshot
                recipe_manifest = json.loads(
                    (recipe_dir / "manifest.json").read_text()
                )
                if recipe_manifest.get("format") != \
                        "g17p-generated-render-pre-notify-v1":
                    raise RuntimeError(
                        "unsupported render-recipe snapshot format %r" %
                        recipe_manifest.get("format")
                    )
                recipe_ranges = {
                    record["name"]: record
                    for record in recipe_manifest.get("ranges", ())
                }

                def load_recipe_descriptor(kind, expected_size, registers):
                    name = "%s_descriptor" % kind
                    record = recipe_ranges.get(name)
                    if record is None:
                        raise RuntimeError(
                            "render-recipe snapshot has no %s" % name
                        )
                    body = (recipe_dir / record["file"]).read_bytes()
                    if len(body) != expected_size:
                        raise RuntimeError(
                            "%s has %#x bytes, expected %#x" %
                            (name, len(body), expected_size)
                        )
                    start = g17p_build.DESCRIPTOR_LAYOUT[kind]["registers"]
                    decoded = [
                        struct.unpack_from(
                            "<IQ",
                            body,
                            start + index * g17p_build.REGISTER_ENTRY_SIZE,
                        )
                        for index in range(len(registers))
                    ]
                    if [number for number, _value in decoded] != [
                        number for number, _value in registers
                    ]:
                        raise RuntimeError(
                            "%s register order differs from positive replay" %
                            name
                        )
                    return body, decoded

                recipe_ta, recipe_ta_registers = load_recipe_descriptor(
                    "tiling", len(captured_ta), captured_ta_registers
                )
                recipe_fragment, recipe_fragment_registers = \
                    load_recipe_descriptor(
                        "fragment",
                        len(captured_fragment),
                        captured_fragment_registers,
                    )
                print(
                    "Using workload recipe from source snapshot %s; "
                    "the positive replay retains every firmware-facing "
                    "lifecycle and placement identity" % recipe_dir
                )
                attempt_manifest["backend_render_recipe_snapshot"] = {
                    "path": str(recipe_dir),
                    "pair": recipe_manifest.get("pair"),
                    "slot": recipe_manifest.get("slot"),
                    "submission_ordinal": recipe_manifest.get(
                        "submission_ordinal"
                    ),
                }

            def register_value(registers, number, occurrence=0):
                matches = [
                    value for candidate, value in registers
                    if candidate == number
                ]
                if occurrence >= len(matches):
                    raise RuntimeError(
                        "register %#x occurrence %d is absent"
                        % (number, occurrence)
                    )
                return matches[occurrence]

            dimensions = register_value(
                recipe_fragment_registers, 0x15211)
            width = dimensions & 0xffffffff
            height = dimensions >> 32
            tilemap = register_value(
                recipe_fragment_registers, 0x16429)
            context_base = tilemap - register_value(
                recipe_ta_registers, 0x1c039)

            render_parameters = g17p_render.G17PRenderParameters(
                width=width,
                height=height,
                context_base=context_base,
                tilemap=tilemap,
                heapmeta=register_value(
                    recipe_fragment_registers, 0x16060),
                tpc=context_base + register_value(
                    recipe_ta_registers, 0x1c0a1),
                deflake_1=context_base + register_value(
                    recipe_ta_registers, 0x10111),
                deflake_2=context_base + register_value(
                    recipe_ta_registers, 0x10119),
                deflake_3=context_base + (
                    register_value(recipe_ta_registers, 0x1c950)
                    & ~0x0004000000000000
                ),
                encoder=context_base + register_value(
                    recipe_ta_registers, 0x1c880, 0),
                ta_status=register_value(
                    recipe_ta_registers, 0x14318) & ~1,
                store_pipeline_bind=register_value(
                    recipe_fragment_registers, 0x15379),
                store_pipeline=register_value(
                    recipe_fragment_registers, 0x15381),
                load_pipeline_bind=register_value(
                    recipe_fragment_registers, 0x15369),
                load_pipeline=register_value(
                    recipe_fragment_registers, 0x15371),
                partial_load_pipeline_bind=struct.unpack_from(
                    "<Q", recipe_fragment, 0x1ea8
                )[0],
                partial_load_pipeline=struct.unpack_from(
                    "<Q", recipe_fragment, 0x1eb0
                )[0],
                partial_store_pipeline_bind=register_value(
                    recipe_fragment_registers, 0x15379),
                partial_store_pipeline=struct.unpack_from(
                    "<Q", recipe_fragment, 0x1f9c
                )[0],
                scissor_array=register_value(
                    recipe_fragment_registers, 0x15109),
                depth_bias_array=register_value(
                    recipe_fragment_registers, 0x15101),
                aux_fb=register_value(
                    recipe_fragment_registers, 0x16461),
                fragment_status=register_value(
                    recipe_fragment_registers, 0x14080) & ~1,
                depth_buffer=register_value(
                    recipe_fragment_registers, 0x15329),
                stencil_buffer=register_value(
                    recipe_fragment_registers, 0x15339),
                depth_aux_buffer=register_value(
                    recipe_fragment_registers, 0x153c1),
                stencil_aux_buffer=register_value(
                    recipe_fragment_registers, 0x153d1),
                depth_clear_value_bits=register_value(
                    recipe_fragment_registers, 0x15301),
                stencil_clear_value=register_value(
                    recipe_fragment_registers, 0x15309) & ~0x300,
                depth_flags=register_value(
                    recipe_fragment_registers, 0x15319),
                depth_dimensions=register_value(
                    recipe_fragment_registers, 0x15321),
                utile_config=register_value(
                    recipe_fragment_registers, 0x10009),
                multisample_control=register_value(
                    recipe_fragment_registers, 0x10019),
                ppp_control=register_value(
                    recipe_ta_registers, 0x10121),
                tib_blocks=register_value(
                    recipe_fragment_registers, 0x10051),
                tile_config=register_value(
                    recipe_fragment_registers, 0x10039),
                aux_fb_flags=register_value(
                    recipe_fragment_registers, 0x15021),
                aux_fb_page_count=register_value(
                    recipe_fragment_registers, 0x15049),
            )
            RENDER_PARAMETERS[0] = render_parameters
            built_render_registers = {
                "tiling": g17p_render.build_tiling_registers(
                    render_parameters),
                "fragment": g17p_render.build_fragment_registers(
                    render_parameters),
            }
            if built_render_registers["tiling"] != recipe_ta_registers:
                print("Generated TA register recipe differences:")
                for index, (built, captured_entry) in enumerate(zip(
                    built_render_registers["tiling"], recipe_ta_registers
                )):
                    if built != captured_entry:
                        print(
                            "  [%d] built (%#x, %#x), captured (%#x, %#x)"
                            % (index, built[0], built[1],
                               captured_entry[0], captured_entry[1])
                        )
                if not args.allow_register_recipe_differences:
                    raise RuntimeError(
                        "generated TA register recipe differs from capture")
            if (
                built_render_registers["fragment"]
                != recipe_fragment_registers
            ):
                print("Generated fragment register recipe differences:")
                for index, (built, captured_entry) in enumerate(zip(
                    built_render_registers["fragment"],
                    recipe_fragment_registers,
                )):
                    if built != captured_entry:
                        print(
                            "  [%d] built (%#x, %#x), captured (%#x, %#x)"
                            % (index, built[0], built[1],
                               captured_entry[0], captured_entry[1])
                        )
                if not args.allow_register_recipe_differences:
                    raise RuntimeError(
                        "generated fragment register recipe differs from capture")

            # Only after the recipe has been shown to reproduce the capture exactly is it
            # allowed to describe something else. Changing a parameter here re-derives both
            # register programs, which is the only way to ask the hardware a question about
            # a workload rather than about a replay.
            if args.render_parameter:
                values = dict(render_parameters.__dict__)
                changes = {}
                for name, value in args.render_parameter:
                    if name not in values:
                        raise RuntimeError(
                            "no render parameter named %s; known: %s"
                            % (name, ", ".join(sorted(values))))
                    changes[name] = {"before": values[name], "after": value}
                    values[name] = value
                render_parameters = g17p_render.G17PRenderParameters(**values)
                built_render_registers = {
                    "tiling": g17p_render.build_tiling_registers(
                        render_parameters),
                    "fragment": g17p_render.build_fragment_registers(
                        render_parameters),
                }
                differing = sum(
                    1 for kind, captured in (
                        ("tiling", recipe_ta_registers),
                        ("fragment", recipe_fragment_registers))
                    for built, original in zip(built_render_registers[kind], captured)
                    if built != original)
                print("Re-derived the register recipe with %d changed parameter(s); "
                      "%d register entries now differ from the capture"
                      % (len(changes), differing))
                for name, record in sorted(changes.items()):
                    print("  %-22s %s -> %s"
                          % (name, record["before"], record["after"]))
                attempt_manifest["render_parameter_overrides"] = changes
                RENDER_PARAMETERS[0] = render_parameters

            if args.relocate_render_status_pages:
                status_relocations = {}
                replacement_values = {}
                for name, field_name, source_dva in (
                    ("tiling", "ta_status", render_parameters.ta_status),
                    (
                        "fragment",
                        "fragment_status",
                        render_parameters.fragment_status,
                    ),
                ):
                    source_mapping = render_context_mapping(
                        manifest, source_dva)
                    blob_index = int(source_mapping["blob_index"])
                    payload = ram[
                        blob_index * PAGE_SIZE:
                        (blob_index + 1) * PAGE_SIZE
                    ]
                    relocation = map_built_context_page(
                        manifest,
                        table_pages,
                        source_dva,
                        payload,
                        "built-%s-status-page" % name,
                        1,
                        0,
                    )
                    initdata_relocations.append(relocation)
                    target_dva = relocation["dva"]
                    replacement_values[field_name] = target_dva
                    RENDER_MAPPING_OVERRIDES[target_dva] = relocation[
                        "relocated_pa"
                    ]
                    for watch_dva in (source_dva, target_dva):
                        if watch_dva not in args.watch_render_dva:
                            args.watch_render_dva.append(watch_dva)
                    status_relocations[name] = {
                        "source_dva": source_dva,
                        "dva": target_dva,
                        "pa": relocation["relocated_pa"],
                    }

                parameter_values = dict(render_parameters.__dict__)
                parameter_values.update(replacement_values)
                render_parameters = g17p_render.G17PRenderParameters(
                    **parameter_values
                )
                built_render_registers = {
                    "tiling": g17p_render.build_tiling_registers(
                        render_parameters),
                    "fragment": g17p_render.build_fragment_registers(
                        render_parameters),
                }
                if args.mirror_status_relocation_in_global_descriptors:
                    for (
                        kind,
                        descriptor_dva,
                        registers,
                        register_number,
                        replacement,
                    ) in (
                        (
                            "tiling",
                            captured_ta_dva,
                            captured_ta_registers,
                            0x14318,
                            render_parameters.ta_status | 1,
                        ),
                        (
                            "fragment",
                            captured_fragment_dva,
                            captured_fragment_registers,
                            0x14080,
                            render_parameters.fragment_status | 1,
                        ),
                    ):
                        register_index = next(
                            index
                            for index, (number, _value) in enumerate(registers)
                            if number == register_number
                        )
                        value_dva = (
                            descriptor_dva
                            + g17p_build.DESCRIPTOR_LAYOUT[kind]["registers"]
                            + register_index * g17p_build.REGISTER_ENTRY_SIZE
                            + 4
                        )
                        global_descriptor_status_patches.append({
                            "kind": kind,
                            "dva": value_dva,
                            "register": register_number,
                            "replacement": replacement,
                        })
                    attempt_manifest[
                        "global_descriptor_status_patches"
                    ] = list(global_descriptor_status_patches)
                attempt_manifest[
                    "relocated_render_status_pages"
                ] = status_relocations
                attempt_manifest["watched_render_dvas"] = [
                    int(dva) for dva in args.watch_render_dva
                ]
                print(
                    "Relocated render status pages: TA %#x -> %#x, "
                    "fragment %#x -> %#x"
                    % (
                        status_relocations["tiling"]["source_dva"],
                        status_relocations["tiling"]["dva"],
                        status_relocations["fragment"]["source_dva"],
                        status_relocations["fragment"]["dva"],
                    )
                )

            attempt_manifest["built_render_register_recipe"] = {
                "width": width,
                "height": height,
                "context_base": context_base,
                "tiling_register_count": len(
                    built_render_registers["tiling"]),
                "fragment_register_count": len(
                    built_render_registers["fragment"]),
            }
            print(
                "Built ordered render-register recipes: TA %d writes, "
                "fragment %d writes"
                % (
                    len(built_render_registers["tiling"]),
                    len(built_render_registers["fragment"]),
                )
            )

    if args.relocate_optional_scratch_alias:
        entry_array = first_work_entry_array_dva(
            manifest, ram, init_message, 0)
        source_optional = read_snapshot_dva_u64(
            manifest, ram, entry_array + 8)
        context_scratch = read_snapshot_dva_u64(
            manifest,
            ram,
            source_optional
            + g17p_build.OPTIONAL_ITEM_POINTER_OFFSETS["context_scratch"],
        )
        firmware_scratch = read_snapshot_dva_u64(
            manifest,
            ram,
            source_optional
            + g17p_build.OPTIONAL_ITEM_POINTER_OFFSETS["firmware_scratch"],
        )

        firmware_mapping = None
        context_mapping = None
        for group in manifest["root_mappings"]:
            for mapping in group["mappings"]:
                if int(mapping["va"]) == (
                    firmware_scratch & ~(PAGE_SIZE - 1)
                ) and int(group["root_ctx_id"]) == 64:
                    firmware_mapping = mapping
                if int(mapping["va"]) == (
                    context_scratch & ~(PAGE_SIZE - 1)
                ) and int(group["root_ctx_id"]) == 0:
                    context_mapping = mapping
        if firmware_mapping is None or context_mapping is None:
            raise RuntimeError("optional scratch aliases are not captured")
        if int(firmware_mapping["pa"]) != int(context_mapping["pa"]):
            raise RuntimeError(
                "optional scratch pointers do not alias one physical page"
            )
        blob_index = int(firmware_mapping["blob_index"])
        payload = ram[
            blob_index * PAGE_SIZE:(blob_index + 1) * PAGE_SIZE
        ]
        firmware_alias = map_built_context_page(
            manifest,
            table_pages,
            firmware_scratch,
            payload,
            "built-optional-firmware-scratch",
            64,
            1,
        )
        context_alias = map_built_context_page(
            manifest,
            table_pages,
            context_scratch,
            payload,
            "built-optional-context-scratch",
            0,
            0,
            target_pa=firmware_alias["relocated_pa"],
        )
        virtual_page_overrides[
            firmware_alias["dva"] & ~(PAGE_SIZE - 1)
        ] = firmware_alias["relocated_pa"]
        initdata_relocations.extend((firmware_alias, context_alias))
        built_optional_scratch = {
            "context_scratch": context_alias["dva"],
            "firmware_scratch": firmware_alias["dva"],
            "pa": firmware_alias["relocated_pa"],
        }
        print(
            "Relocated optional scratch alias to context-0 DVA %#x and "
            "firmware DVA %#x at shared PA %#x"
            % (
                context_alias["dva"],
                firmware_alias["dva"],
                firmware_alias["relocated_pa"],
            )
        )
        attempt_manifest["built_optional_scratch_alias"] = {
            "source_context_dva": context_scratch,
            "source_firmware_dva": firmware_scratch,
            **built_optional_scratch,
        }

    if args.build_submission_leaf_pages:
        _, objects, _, _ = captured_work_model("TA_0", "tiling")
        source_shared = objects[1]
        nested = [
            read_snapshot_dva_u64(manifest, ram, source_shared + offset)
            for offset in g17p_build.SHARED_OBJECT_POINTER_OFFSETS
        ]
        record_a_slot = read_snapshot_dva_u64(manifest, ram, objects[0])
        record_b_slot = read_snapshot_dva_u64(
            manifest, ram, objects[2] + g17p_build.ARRAY_B_SLOT_OFFSET)
        record_b_shared = read_snapshot_dva_u64(
            manifest, ram, objects[2] + g17p_build.ARRAY_B_SHARED_OFFSET)
        source_pages = {
            "primary_index": nested[0] & ~(PAGE_SIZE - 1),
            "secondary_index": nested[1] & ~(PAGE_SIZE - 1),
            "pool_a_slots": record_a_slot & ~(PAGE_SIZE - 1),
            "pool_b_slots": record_b_slot & ~(PAGE_SIZE - 1),
            "shared_slots": nested[2] & ~(PAGE_SIZE - 1),
            "flag": nested[3] & ~(PAGE_SIZE - 1),
        }
        if (record_b_shared & ~(PAGE_SIZE - 1)) != source_pages["shared_slots"]:
            raise RuntimeError(
                "pool B shared address and packed object do not share a page"
            )

        built_leaf_pages = {}
        leaf_manifest = {}
        for name, body in g17p_build.build_submission_leaf_pages().items():
            mapping = map_built_page(
                manifest,
                table_pages,
                source_pages[name],
                body,
                "built-submission-%s" % name,
            )
            virtual_page_overrides[mapping["dva"]] = mapping["relocated_pa"]
            initdata_relocations.append(mapping)
            built_leaf_pages[name] = mapping["dva"]
            leaf_manifest[name] = {
                "dva": mapping["dva"],
                "pa": mapping["relocated_pa"],
                "bytes": len(body),
                "source_dva": source_pages[name],
            }
        print(
            "Built six submission leaf pages: %s"
            % ", ".join(
                "%s=%#x" % item for item in built_leaf_pages.items()
            )
        )
        attempt_manifest["built_submission_leaf_pages"] = leaf_manifest

    if args.build_shared_descriptor_objects:
        _, objects, _, _ = captured_work_model("TA_0", "tiling")
        source_shared = objects[1]
        source_zero = objects[3]
        nested = [
            read_snapshot_dva_u64(manifest, ram, source_shared + offset)
            for offset in g17p_build.SHARED_OBJECT_POINTER_OFFSETS
        ]
        if built_leaf_pages is not None:
            nested = [
                built_leaf_pages["primary_index"],
                built_leaf_pages["secondary_index"],
                built_leaf_pages["shared_slots"],
                built_leaf_pages["flag"],
            ]
        shared_body = g17p_build.build_shared_object(nested)
        zero_body = g17p_build.build_zero_shared_object()
        built_shared = map_built_page(
            manifest,
            table_pages,
            source_shared,
            shared_body,
            "built-shared-descriptor-object",
        )
        built_zero = map_built_page(
            manifest,
            table_pages,
            source_zero,
            zero_body,
            "built-zero-descriptor-object",
        )
        for mapping in (built_shared, built_zero):
            virtual_page_overrides[mapping["dva"]] = mapping["relocated_pa"]
            initdata_relocations.append(mapping)
        built_shared_objects = (built_shared["dva"], built_zero["dva"])
        print(
            "Built shared descriptor objects at DVA %#x (%#x bytes) and "
            "%#x (%#x zero bytes)"
            % (
                built_shared["dva"],
                len(shared_body),
                built_zero["dva"],
                len(zero_body),
            )
        )
        attempt_manifest["built_shared_descriptor_objects"] = {
            "packed_dva": built_shared["dva"],
            "packed_bytes": len(shared_body),
            "zero_dva": built_zero["dva"],
            "zero_bytes": len(zero_body),
            "nested_addresses": nested,
        }

    if args.build_first_optional_items:
        source_items = {}
        for channel_index, (channel_name, kind) in enumerate(
            (("TA_0", "tiling"), ("3D_0", "fragment"))
        ):
            entry_array = first_work_entry_array_dva(
                manifest, ram, init_message, channel_index)
            source_items[kind] = read_snapshot_dva_u64(
                manifest, ram, entry_array + 8)

        source_pages = {
            address & ~(PAGE_SIZE - 1) for address in source_items.values()
        }
        if len(source_pages) != 1:
            raise RuntimeError(
                "first optional items do not share one page: %r"
                % sorted(source_pages)
            )
        source_page = source_pages.pop()
        payload_size = max(
            (address - source_page) + g17p_build.OPTIONAL_ITEM_SIZE
            for address in source_items.values()
        )
        payload = bytearray(payload_size)
        for kind, source in source_items.items():
            source_body = read_snapshot_dva_bytes(
                manifest, ram, source, g17p_build.OPTIONAL_ITEM_SIZE
            )
            pointer_args = {
                name: read_snapshot_dva_u64(
                    manifest, ram, source + offset)
                for name, offset in
                g17p_build.OPTIONAL_ITEM_POINTER_OFFSETS.items()
                if name != "tiling_shared_object"
            }
            if kind == "tiling":
                pointer_args["tiling_shared_object"] = read_snapshot_dva_u64(
                    manifest,
                    ram,
                    source + g17p_build.OPTIONAL_ITEM_POINTER_OFFSETS[
                        "tiling_shared_object"
                    ],
                )
                if built_shared_objects is not None:
                    pointer_args["tiling_shared_object"] = (
                        built_shared_objects[0]
                    )
            if built_optional_scratch is not None:
                pointer_args["context_scratch"] = (
                    built_optional_scratch["context_scratch"]
                )
                pointer_args["firmware_scratch"] = (
                    built_optional_scratch["firmware_scratch"]
                )
            pointer_args.update(
                grid_index=struct.unpack_from("<H", source_body, 0x18)[0],
                submission_ordinal=struct.unpack_from(
                    "<H", source_body, 0x3e
                )[0],
                context_id=struct.unpack_from("<H", source_body, 0x32)[0],
                uuid=struct.unpack_from("<H", source_body, 0x5a)[0],
                scheduler_class=struct.unpack_from(
                    "<H", source_body, 0x5e
                )[0],
                queue_context_index=struct.unpack_from(
                    "<H", source_body, 0x2a
                )[0],
                queue_context_phase=struct.unpack_from(
                    "<H", source_body, 0x2e
                )[0],
                first_record=any(
                    struct.unpack_from("<H", source_body, offset)[0]
                    for offset in (0x1a, 0x52, 0x62)
                ),
                lifecycle_ordinal=(
                    struct.unpack_from("<H", source_body, 0x76)[0]
                    if kind == "tiling" else None
                ),
                queue_namespace=(
                    struct.unpack_from("<H", source_body, 0x7e)[0]
                    if kind == "tiling" else None
                ),
                u16_overrides={
                    offset: struct.unpack_from("<H", source_body, offset)[0]
                    for offset in (0x46, 0x56)
                },
            )
            body = g17p_build.build_optional_item(kind, **pointer_args)
            offset = source - source_page
            payload[offset:offset + len(body)] = body

        mapping = map_built_page(
            manifest,
            table_pages,
            source_page,
            bytes(payload),
            "built-first-optional-items",
        )
        virtual_page_overrides[mapping["dva"]] = mapping["relocated_pa"]
        initdata_relocations.append(mapping)
        built_optional_items = {
            kind: mapping["dva"] + (source - source_page)
            for kind, source in source_items.items()
        }
        print(
            "Built first optional items on page DVA %#x: TA %#x, 3D %#x"
            % (
                mapping["dva"],
                built_optional_items["tiling"],
                built_optional_items["fragment"],
            )
        )
        # Everything the backend needs is in scope here: the captured optional-item
        # pointers, which hardware proved belong to context initialization rather than to
        # a work item, and the register programs. Give it those and let it build the rest
        # at addresses of its own choosing, which is what a driver would do.
        if args.backend_build_submission:
            backend_module = load_backend_package()
            direct_space = CapturedAddressSpace(
                manifest, page_relocations, virtual_page_overrides
            )
            queue_pair = int(args.first_work_channel_pair)
            fixed_allocations = None
            if args.backend_publish_fresh_item and queue_pair == 2:
                source_event_items = {}
                for channel_index, kind in enumerate(("tiling", "fragment")):
                    entry_array = first_work_entry_array_dva(
                        manifest, ram, init_message, channel_index
                    )
                    source_event_items[kind] = read_snapshot_dva_u64(
                        manifest, ram, entry_array + 16
                    )
                fixed_allocations = {
                    "fragment_optional_item": [
                        None,
                        *[
                            source_items["fragment"]
                            + 2 * item_index * g17p_build.OPTIONAL_ITEM_SIZE
                            for item_index in range(
                                1, args.backend_fresh_item_count + 1
                            )
                        ],
                    ],
                    "tiling_optional_item": [
                        None,
                        *[
                            source_items["tiling"]
                            + 2 * item_index * g17p_build.OPTIONAL_ITEM_SIZE
                            for item_index in range(
                                1, args.backend_fresh_item_count + 1
                            )
                        ],
                    ],
                    "fragment_event_item": [
                        None,
                        *[
                            source_event_items["fragment"]
                            + 2 * item_index * g17p_build.EVENT_RECORD_SIZE
                            for item_index in range(
                                1, args.backend_fresh_item_count + 1
                            )
                        ],
                    ],
                    "tiling_event_item": [
                        None,
                        *[
                            source_event_items["tiling"]
                            + 2 * item_index * g17p_build.EVENT_RECORD_SIZE
                            for item_index in range(
                                1, args.backend_fresh_item_count + 1
                            )
                        ],
                    ],
                }
                for item_index in range(1, args.backend_fresh_item_count + 1):
                    fixed_allocations["work_descriptor_%d" % item_index] = [
                        captured_ta_dva
                        + item_index
                        * backend_module.G17PWorkBuilder.BODY_STRIDE["tiling"],
                        captured_fragment_dva
                        + item_index
                        * backend_module.G17PWorkBuilder.BODY_STRIDE["fragment"],
                    ]
            allocator = BackendAllocator(
                manifest, table_pages, source_page, initdata_relocations,
                direct_space=direct_space,
                fixed_allocations=fixed_allocations,
            )
            if args.backend_reserve_pages:
                allocator.reserve(args.backend_reserve_pages)
                print("Backend reserved %d heap pages before the restore"
                      % args.backend_reserve_pages)
            builder = backend_module.G17PPairedWorkBuilder(
                allocator.alloc, allocator.write, queue_pair=queue_pair)
            runtime_control = struct.unpack_from("<Q", captured_ta, 0x0934)[0]
            fragment_runtime_control = struct.unpack_from(
                "<Q", captured_fragment, 0x21CE
            )[0]
            if runtime_control != fragment_runtime_control:
                raise RuntimeError(
                    "captured TA/3D runtime-control bindings disagree: "
                    "%#x != %#x"
                    % (runtime_control, fragment_runtime_control)
                )
            builder.bind_runtime_control_page(runtime_control)
            print(
                "Backend descriptor pair binds captured runtime control %#x"
                % runtime_control
            )
            if args.backend_reuse_pools:
                # Firmware refuses a submission naming different parameter-buffer state
                # from the one it has bound, and says so. So point the builder at the
                # pools and shared objects already bound and let it build only the
                # descriptors, optional items and event records.
                _, bound_objects, _, _ = captured_work_model("TA_0", "tiling")
                # Firmware names the parameter-buffer state but not which of the item's four
                # pointer-block objects carries it. Taking one group fresh while the rest stay
                # bound is what separates them, so each half can be swapped independently.
                want_fresh = (args.backend_fresh_pools or args.backend_fresh_shared
                              or args.backend_fresh_shared_packed
                              or args.backend_fresh_shared_zero)
                fresh = builder.build_submission_graph() if want_fresh else None
                pool_a, pool_b = bound_objects[0], bound_objects[2]
                shared_pair = [bound_objects[1], bound_objects[3]]
                if args.backend_fresh_pools:
                    pool_a, pool_b = fresh["pools"]["pool_a"], fresh["pools"]["pool_b"]
                if args.backend_fresh_shared or args.backend_fresh_shared_packed:
                    shared_pair[0] = fresh["shared"][0]
                if args.backend_fresh_shared or args.backend_fresh_shared_zero:
                    shared_pair[1] = fresh["shared"][1]
                if args.backend_clone_shared_packed:
                    # The fresh packed object differed from the bound one in both its address and
                    # its contents, so the refusal does not say which firmware compares. A byte
                    # identical copy at a fresh address changes only the address.
                    size = g17p_build.SHARED_OBJECT_SIZE
                    body = b"".join(
                        struct.pack("<Q", read_snapshot_dva_u64(
                            manifest, ram, bound_objects[1] + offset))
                        for offset in range(0, size, 8))
                    clone = builder.alloc(len(body), "cloned_shared_object")
                    builder.write(clone, body)
                    print("Cloned the bound packed shared object %#x to %#x, %d bytes identical"
                          % (bound_objects[1], clone, len(body)))
                    shared_pair[0] = clone
                shared_pair = tuple(shared_pair)
                builder.tiling.use_pools(pool_a, pool_b)
                builder.fragment.use_pools(pool_a, pool_b)
                builder.shared = shared_pair
                if args.backend_recycle_submission_graph:
                    if want_fresh:
                        raise RuntimeError(
                            "bound-graph recycling cannot be combined with "
                            "partially fresh graph objects"
                        )
                    nested = [
                        read_snapshot_dva_u64(
                            manifest, ram, shared_pair[0] + offset
                        )
                        for offset in g17p_build.SHARED_OBJECT_POINTER_OFFSETS
                    ]
                    pool_a_slot = read_snapshot_dva_u64(
                        manifest, ram, pool_a
                    )
                    pool_b_slot = read_snapshot_dva_u64(
                        manifest,
                        ram,
                        pool_b + g17p_build.ARRAY_B_SLOT_OFFSET,
                    )
                    builder.leaf_pages = {
                        "primary_index": nested[0],
                        "secondary_index": nested[1],
                        "pool_a_slots": (
                            pool_a_slot - g17p_build.POOL_A_SLOT_OFFSET
                        ),
                        "pool_b_slots": (
                            pool_b_slot - g17p_build.POOL_B_SLOT_OFFSET
                        ),
                        "shared_slots": nested[2],
                        "flag": nested[3],
                    }
                    builder.index_group_ranges = None
                    builder.shared_count = 0x20
                    print(
                        "Backend bound the captured graph for finite in-place "
                        "generation recycling: %s"
                        % {
                            name: "%#x" % address
                            for name, address in builder.leaf_pages.items()
                        }
                    )
                graph = {
                    "reused": ["%#x" % value for value in bound_objects],
                    "pools": ["%#x" % pool_a, "%#x" % pool_b],
                    "shared": ["%#x" % value for value in shared_pair],
                    "fresh_pools": bool(args.backend_fresh_pools),
                    "fresh_shared": bool(args.backend_fresh_shared),
                }
                print("Backend pools %s (%s), shared packed %s (%s), shared zero %s (%s)"
                      % (graph["pools"],
                         "fresh" if args.backend_fresh_pools else "bound",
                         graph["shared"][0],
                         "fresh" if (args.backend_fresh_shared
                                     or args.backend_fresh_shared_packed) else "bound",
                         graph["shared"][1],
                         "fresh" if (args.backend_fresh_shared
                                     or args.backend_fresh_shared_zero) else "bound"))
            else:
                graph = builder.build_submission_graph()

            optional_pointers = {}
            for kind, source in source_items.items():
                optional_pointers[kind] = {
                    name: read_snapshot_dva_u64(manifest, ram, source + offset)
                    for name, offset in
                    g17p_build.OPTIONAL_ITEM_POINTER_OFFSETS.items()
                    if name != "tiling_shared_object"
                }
                source_body = read_snapshot_dva_bytes(
                    manifest, ram, source, g17p_build.OPTIONAL_ITEM_SIZE)
                optional_pointers[kind].update(
                    context_id=struct.unpack_from(
                        "<H", source_body, 0x32)[0],
                    uuid=struct.unpack_from("<H", source_body, 0x5A)[0],
                    scheduler_class=struct.unpack_from(
                        "<H", source_body, 0x5E)[0],
                    submission_ordinal_base=struct.unpack_from(
                        "<H", source_body, 0x3E)[0],
                    queue_context_index_base=struct.unpack_from(
                        "<H", source_body, 0x2A)[0],
                    queue_context_phase_base=struct.unpack_from(
                        "<H", source_body, 0x2E)[0],
                    lifecycle_ordinal_base=(
                        struct.unpack_from("<H", source_body, 0x76)[0]
                        if kind == "tiling" else None
                    ),
                    queue_namespace=struct.unpack_from(
                        "<H", source_body, 0x7E)[0]
                        if kind == "tiling" else None,
                    u16_overrides={
                        0x46: struct.unpack_from(
                            "<H", source_body, 0x46)[0],
                        0x56: struct.unpack_from(
                            "<H", source_body, 0x56)[0],
                    },
                )

            tiling_registers = built_render_registers["tiling"]
            fragment_registers = built_render_registers["fragment"]
            if args.backend_submit_cmdbuf:
                # Drive the front end's own translation rather than handing the builder
                # register programs. The command buffer carries what a driver would know:
                # the render size, the objects it has allocated, and the shader-binding
                # programs, which are compiled code this project does not produce and which
                # are therefore taken from the captured render context.
                shim_module = sys.modules["g17pbackend.g17p_shim"]
                encoder_module = sys.modules["g17pbackend.g17p_encoder"]
                encoder_bytes = read_snapshot_bytes(
                    manifest, ram, render_parameters.encoder,
                    encoder_module.ENCODER_SIZE)

                class CommandBuffer:
                    pass

                cmdbuf = CommandBuffer()
                cmdbuf.width = render_parameters.width
                cmdbuf.height = render_parameters.height
                for name in ("store_pipeline", "store_pipeline_bind",
                             "load_pipeline", "load_pipeline_bind",
                             "deflake_1", "deflake_2", "deflake_3",
                             "scissor_array", "aux_fb"):
                    setattr(cmdbuf, name, getattr(render_parameters, name))
                cmdbuf.encoder = encoder_module.parse_encoder(
                    encoder_bytes, render_parameters.context_base)
                if args.backend_encoder_opcode is not None:
                    cmdbuf.encoder = dataclasses.replace(
                        cmdbuf.encoder,
                        opcode=args.backend_encoder_opcode,
                    )
                if args.backend_encoder_index_count is not None:
                    cmdbuf.encoder = dataclasses.replace(
                        cmdbuf.encoder,
                        index_count=args.backend_encoder_index_count,
                    )
                if args.backend_encoder_field:
                    overrides = parse_encoder_fields(
                        args.backend_encoder_field, cmdbuf.encoder)
                    ENCODER_FIELD_BEFORE[0] = {
                        name: getattr(cmdbuf.encoder, name)
                        for name in overrides
                    }
                    cmdbuf.encoder = dataclasses.replace(
                        cmdbuf.encoder, **overrides)
                cmdbuf.shared = None
                cmdbuf.pools = None
                cmdbuf.heapmeta = (
                    render_parameters.heapmeta
                    if args.backend_reuse_context_heapmeta
                    else 0
                )
                cmdbuf.tiling_optional = optional_pointers["tiling"]
                cmdbuf.fragment_optional = optional_pointers["fragment"]

                fixed_render_dvas = {}
                if args.backend_reuse_render_dvas:
                    fixed_render_dvas = {
                        "g17p_tilemap": render_parameters.tilemap,
                        "g17p_tile_parameter_cache": render_parameters.tpc,
                        "g17p_heapmeta": render_parameters.heapmeta,
                        "g17p_ta_status": render_parameters.ta_status,
                        "g17p_fragment_status": (
                            render_parameters.fragment_status
                        ),
                        "g17p_depth_bias_array": (
                            render_parameters.depth_bias_array
                        ),
                        "g17p_encoder": render_parameters.encoder,
                    }
                else:
                    if args.backend_reuse_heapmeta_dva:
                        fixed_render_dvas[
                            "g17p_heapmeta"
                        ] = render_parameters.heapmeta
                    if args.backend_reuse_encoder_dva:
                        fixed_render_dvas[
                            "g17p_encoder"
                        ] = render_parameters.encoder
                render_source_dvas = {
                    "g17p_tilemap": render_parameters.tilemap,
                    "g17p_tile_parameter_cache": render_parameters.tpc,
                    "g17p_heapmeta": render_parameters.heapmeta,
                    "g17p_ta_status": render_parameters.ta_status,
                    "g17p_fragment_status": render_parameters.fragment_status,
                    "g17p_depth_bias_array": render_parameters.depth_bias_array,
                    "g17p_encoder": render_parameters.encoder,
                }
                render_allocator = BackendRenderAllocator(
                    manifest,
                    table_pages,
                    render_parameters.encoder,
                    initdata_relocations,
                    fixed_render_dvas,
                    render_source_dvas,
                    # Fresh zero pages under the render objects are right for a world where the
                    # workload has not started, and wrong for one captured mid-stream, where those
                    # objects hold state the tiler has been accumulating. Aliasing keeps the
                    # captured pages, so a published submission inherits that state instead of
                    # being handed blank objects.
                    (set(render_source_dvas)
                     if args.backend_alias_render_backing
                     else {"g17p_heapmeta"}
                     if args.backend_alias_heapmeta_backing
                     else None),
                )
                translator = object.__new__(shim_module.G17PShimBackend)
                translator.ctx = BackendRenderContext(
                    render_allocator, render_parameters.context_base)
                built = translator.build_submission(cmdbuf)
                tiling_registers = built["tiling_registers"]
                fragment_registers = built["fragment_registers"]
                for (
                    kind,
                    captured,
                    tail_offset,
                    render_name,
                ) in (
                    (
                        "tiling",
                        captured_ta,
                        0x945,
                        "g17p_ta_status",
                    ),
                    (
                        "fragment",
                        captured_fragment,
                        0x21DF,
                        "g17p_fragment_status",
                    ),
                ):
                    source_alias = struct.unpack_from(
                        "<Q", captured, tail_offset
                    )[0]
                    render_page = render_allocator.page_named(render_name)
                    if args.backend_reuse_render_dvas:
                        alias = replace_context_page(
                            manifest,
                            table_pages,
                            source_alias,
                            b"",
                            "backend-%s-status-alias" % kind,
                            64,
                            1,
                            target_pa=render_page["pa"],
                        )
                    else:
                        alias = map_built_context_page(
                            manifest,
                            table_pages,
                            source_alias,
                            b"",
                            "backend-%s-status-alias" % kind,
                            64,
                            1,
                            target_pa=render_page["pa"],
                        )
                    initdata_relocations.append(alias)
                    descriptor_status_aliases[kind] = {
                        "tail_offset": tail_offset,
                        "source_alias": source_alias,
                        "alias": int(alias["dva"]),
                        "render_dva": render_page["dva"],
                        "pa": render_page["pa"],
                    }
                    print(
                        "Mapped %s status aliases %#x and %#x to page %#x"
                        % (
                            kind,
                            render_page["dva"],
                            int(alias["dva"]),
                            render_page["pa"],
                        )
                    )
                if args.mirror_backend_global_descriptors:
                    patch_address_space = CapturedAddressSpace(
                        manifest, page_relocations, virtual_page_overrides
                    )
                    for (
                        kind,
                        descriptor_dva,
                        captured_registers,
                        translated_registers,
                    ) in (
                        (
                            "tiling",
                            captured_ta_dva,
                            captured_ta_registers,
                            tiling_registers,
                        ),
                        (
                            "fragment",
                            captured_fragment_dva,
                            captured_fragment_registers,
                            fragment_registers,
                        ),
                    ):
                        if [
                            number for number, _value in captured_registers
                        ] != [
                            number for number, _value in translated_registers
                        ]:
                            raise RuntimeError(
                                "%s translated register order differs from the "
                                "context-global record" % kind
                            )
                        layout = g17p_build.DESCRIPTOR_LAYOUT[kind]
                        changed = 0
                        for index, (
                            (_number, before),
                            (_translated_number, after),
                        ) in enumerate(
                            zip(captured_registers, translated_registers)
                        ):
                            if before == after:
                                continue
                            value_dva = (
                                descriptor_dva
                                + layout["registers"]
                                + index * g17p_build.REGISTER_ENTRY_SIZE
                                + 4
                            )
                            write_dva_u64(patch_address_space, value_dva, after)
                            backend_global_descriptor_patches.append(
                                {
                                    "kind": kind,
                                    "dva": value_dva,
                                    "before": before,
                                    "after": after,
                                }
                            )
                            changed += 1
                        alias = descriptor_status_aliases[kind]
                        alias_dva = descriptor_dva + alias["tail_offset"]
                        write_dva_u64(
                            patch_address_space, alias_dva, alias["alias"]
                        )
                        backend_global_descriptor_patches.append(
                            {
                                "kind": kind,
                                "dva": alias_dva,
                                "before": alias["source_alias"],
                                "after": alias["alias"],
                                "status_alias": True,
                            }
                        )
                        print(
                            "Mirrored %d translated %s registers and its "
                            "status alias into the context-global record"
                            % (changed, kind)
                        )
                # Feed the translation into the generated queue records. The
                # context-global path either points at these full-size copies or keeps
                # the native full records mirrored above; both views must agree.
                built_render_registers = {
                    "tiling": tiling_registers,
                    "fragment": fragment_registers,
                }
                render_parameters = built["parameters"]
                RENDER_PARAMETERS[0] = render_parameters
                for dva, _pa, _name, _size in render_allocator.pages:
                    if dva not in args.watch_render_dva:
                        args.watch_render_dva.append(dva)
                print("Front end translated a %dx%d command buffer into %d and %d "
                      "register writes, allocating %d objects and a tiler stream at %#x"
                      % (cmdbuf.width, cmdbuf.height, len(tiling_registers),
                         len(fragment_registers), len(built["allocated"]),
                         built["encoder"]))
                attempt_manifest["backend_submit_cmdbuf"] = {
                    "width": cmdbuf.width, "height": cmdbuf.height,
                    "tiling_registers": len(tiling_registers),
                    "fragment_registers": len(fragment_registers),
                    "allocated": {name: "%#x" % value
                                  for name, value in built["allocated"].items()},
                    "encoder": "%#x" % built["encoder"],
                    "encoder_opcode": cmdbuf.encoder.opcode,
                    "encoder_index_count": cmdbuf.encoder.index_count,
                    "encoder_field_overrides": {
                        name: {"before": before,
                               "after": getattr(cmdbuf.encoder, name)}
                        for name, before in (ENCODER_FIELD_BEFORE[0] or {}).items()
                    },
                    "reused_render_dvas": bool(
                        args.backend_reuse_render_dvas
                    ),
                    "reused_heapmeta_dva": bool(
                        args.backend_reuse_heapmeta_dva
                    ),
                    "reused_encoder_dva": bool(
                        args.backend_reuse_encoder_dva
                    ),
                    "reused_context_heapmeta": bool(
                        args.backend_reuse_context_heapmeta
                    ),
                    "aliased_heapmeta_backing": bool(
                        args.backend_alias_heapmeta_backing
                    ),
                    "status_aliases": descriptor_status_aliases,
                    "global_descriptor_patches": (
                        backend_global_descriptor_patches
                    ),
                    "render_allocator": render_allocator.summary(),
                }

            descriptor_context_id = struct.unpack_from(
                "<I", captured_ta, g17p_build.CONTEXT_ID_OFFSET)[0]
            descriptor_sequences = {
                "tiling": struct.unpack_from("<Q", captured_ta, 0x04)[0],
                "fragment": struct.unpack_from(
                    "<Q", captured_fragment, 0x04
                )[0],
            }
            pair = builder.item(
                0,
                None,
                tiling_registers,
                fragment_registers,
                optional_pointers["tiling"],
                optional_pointers["fragment"],
                descriptor_context_id,
                submission_ordinal=0,
                submit_sequences=descriptor_sequences,
                queue_pair=queue_pair,
                queue_grid_pair=queue_pair,
                parameters=render_parameters,
            )
            # A published group has so far reused the descriptors that became the first work, so
            # firmware was being handed an item it had already executed and whose completion
            # records were already written. Build a second, distinct item now, while its pages can
            # still be mapped, and publish that one instead.
            publish_pair = None
            publish_pairs = []
            publish_graph_item_indices = []
            publish_descriptor_pairs = []
            if args.backend_publish_fresh_item:
                for item_index in range(
                    1, args.backend_fresh_item_count + 1
                ):
                    recycle_generation = (
                        args.backend_recycle_submission_graph
                        and item_index >= 2
                    )
                    graph_item_index = 0 if recycle_generation else item_index
                    descriptor_pair = (
                        int(args.backend_recycle_descriptor_pair)
                        if (recycle_generation
                            and args.backend_recycle_descriptor_pair is not None)
                        else queue_pair
                    )
                    item_optional_pointers = {
                        kind: dict(values)
                        for kind, values in optional_pointers.items()
                    }
                    if recycle_generation:
                        # Queue-local state restarts at item zero, while the
                        # optional record's global ordinals continue across
                        # graph generations.  This is the exact split in the
                        # late native partial capture.
                        for kind in ("tiling", "fragment"):
                            item_optional_pointers[kind][
                                "submission_ordinal_base"
                            ] = (
                                int(optional_pointers[kind][
                                    "submission_ordinal_base"])
                                + item_index
                            )
                        lifecycle_base = optional_pointers["tiling"].get(
                            "lifecycle_ordinal_base"
                        )
                        if lifecycle_base is not None:
                            item_optional_pointers["tiling"][
                                "lifecycle_ordinal_base"
                            ] = int(lifecycle_base) + item_index
                        item_optional_pointers["tiling"][
                            "queue_namespace"
                        ] = descriptor_pair
                    if args.backend_create_queue is None:
                        queue_grids = queue_pair
                    else:
                        tiling_grid = (
                            int(args.backend_create_queue)
                            + (item_index - 1)
                            * int(args.backend_created_queue_grid_step)
                        )
                        queue_grids = (tiling_grid, tiling_grid + 1)
                    if fixed_allocations is not None:
                        builder.tiling.low_alias = {
                            "tiling": 0x7000018FC0
                            + item_index
                            * backend_module.G17PWorkBuilder.BODY_STRIDE["tiling"]
                        }
                        builder.fragment.low_alias = {
                            "fragment": 0x70000EFC40
                            + item_index
                            * backend_module.G17PWorkBuilder.BODY_STRIDE["fragment"]
                        }
                    if descriptor_pair != queue_pair:
                        # The exact later pair's high status pages are not in
                        # the earlier replay snapshot. Retain the already
                        # coherent pair-2 high/low alias while varying the
                        # descriptor and graph generation independently.
                        builder.tiling.status_base = (
                            backend_module.G17PWorkBuilder.PAIR_STATUS_BASES[
                                "tiling"
                            ][queue_pair]
                        )
                        builder.fragment.status_base = (
                            backend_module.G17PWorkBuilder.PAIR_STATUS_BASES[
                                "fragment"
                            ][queue_pair]
                        )
                    publish_pair = builder.item(
                        graph_item_index,
                        None,
                        tiling_registers,
                        fragment_registers,
                        item_optional_pointers["tiling"],
                        item_optional_pointers["fragment"],
                        descriptor_context_id,
                        submission_ordinal=(
                            0 if recycle_generation else item_index
                        ),
                        submit_sequences={
                            kind: (
                                sequence
                                if recycle_generation
                                else sequence + 2 * item_index
                            )
                            for kind, sequence in descriptor_sequences.items()
                        },
                        record_indices=(
                            (2 * (item_index // 2), item_index)
                            if (args.backend_render_pool_cadence
                                and not recycle_generation)
                            else None
                        ),
                        queue_pair=descriptor_pair,
                        queue_grid_pair=queue_grids,
                        parameters=render_parameters,
                        allocation_index=item_index,
                    )
                    publish_pairs.append(publish_pair)
                    publish_graph_item_indices.append(graph_item_index)
                    publish_descriptor_pairs.append(descriptor_pair)
                    print(
                        "Backend built fresh item %d (graph-local %d, pair %d, "
                        "grids %s) "
                        "for publication: TA %s, 3D %s"
                        % (
                            item_index,
                            graph_item_index,
                            descriptor_pair,
                            queue_grids,
                            ["%#x" % value for value in publish_pair["tiling"]],
                            ["%#x" % value for value in publish_pair["fragment"]],
                        )
                    )

                if args.backend_render_pool_cadence:
                    restored_records = set()
                    for item_pair in publish_pairs:
                        descriptor = item_pair["tiling"][0]
                        record_a = struct.unpack_from(
                            "<Q", direct_space.read(descriptor + 0x10, 8)
                        )[0]
                        if record_a in restored_records:
                            continue
                        baseline = read_snapshot_dva_bytes(
                            manifest, ram, record_a + 0x08, 0x0c
                        )
                        direct_space.write(record_a + 0x08, baseline)
                        restored_records.add(record_a)
                    print(
                        "Restored %d render Pool-A record(s) to captured "
                        "pre-start state for A0,A0,A2,A2 cadence"
                        % len(restored_records)
                    )

            deferred_item_payloads = []
            if publish_pairs and args.backend_defer_future_items:
                # Native constructs a work group only after the preceding
                # queue prefix completes.  Fixed native-array addresses must
                # be mapped before this replay starts, so retain the generated
                # bytes off-device and leave future slots in their captured
                # all-zero state until backend_publish() reaches them.
                for item_index, item_pair in enumerate(publish_pairs, 1):
                    materialization = []
                    if item_index >= 2:
                        for kind in ("tiling", "fragment"):
                            descriptor, optional, event = item_pair[kind]
                            for address, size in (
                                (
                                    descriptor,
                                    backend_module.G17PWorkBuilder.BODY_STRIDE[
                                        kind
                                    ],
                                ),
                                (optional, g17p_build.OPTIONAL_ITEM_SIZE),
                                (event, g17p_build.EVENT_RECORD_SIZE),
                            ):
                                payload = direct_space.read(address, size)
                                materialization.append((address, payload))
                                direct_space.write(address, bytes(size))

                        # G17PPairedWorkBuilder prepares this host-owned Pool-A
                        # record while building the descriptor.  Remove those
                        # two future-only fields as well; the normal
                        # pre-publication lifecycle writes them back after the
                        # preceding fence.
                        tiling_descriptor = item_pair["tiling"][0]
                        descriptor_body = materialization[0][1]
                        record_a = struct.unpack_from(
                            "<Q", descriptor_body, 0x10
                        )[0]
                        direct_space.write(record_a + 0x08, bytes(4))
                        direct_space.write(record_a + 0x10, bytes(4))
                        print(
                            "Deferred fresh item %d until publication: "
                            "%d spans, Pool-A %#x host fields cleared"
                            % (item_index, len(materialization), record_a)
                        )
                    deferred_item_payloads.append(materialization)

            fresh_queue_contexts = []
            if publish_pairs and fixed_allocations is not None:
                for item_index, (
                    item_pair, graph_item_index, descriptor_pair
                ) in enumerate(
                    zip(
                        publish_pairs,
                        publish_graph_item_indices,
                        publish_descriptor_pairs,
                    ),
                    1,
                ):
                    fresh_queue_contexts.append(
                        {
                            kind: {
                                "scratch": optional_pointers[kind][
                                    "firmware_scratch"
                                ],
                                "descriptor": item_pair[kind][0],
                                "item_index": graph_item_index,
                                "context_id": descriptor_context_id,
                                "pair": descriptor_pair,
                            }
                            for kind in ("tiling", "fragment")
                        }
                    )

            BACKEND_BUILT[0] = {
                "pair": pair,
                "publish_pair": publish_pair,
                "publish_pairs": publish_pairs,
                "graph": graph,
                "allocator": allocator.summary(),
                # Kept live, not just summarised, so a publication can carve a new queue's pointer
                # block and item ring out of the pages this allocator already had mapped.
                "allocator_object": allocator,
                "builder_object": builder,
                "fresh_queue_context": (
                    fresh_queue_contexts[-1]
                    if fresh_queue_contexts
                    else None
                ),
                "fresh_queue_contexts": fresh_queue_contexts,
                "deferred_item_payloads": deferred_item_payloads,
                "bound_addresses": list(bound_objects) if args.backend_reuse_pools else [],
            }
            for page in allocator.pages:
                virtual_page_overrides[page[0]] = page[1]
            # Reserved-but-unused pages are mapped by the restore just like the used ones, but a
            # publication that allocates out of them writes through this address space, which only
            # knows the pages registered here. Without them a per-submission allocation lands on a
            # page the write path cannot reach.
            for page in allocator.reserved:
                virtual_page_overrides[page[0]] = page[1]
            print("Backend built a paired group in %d of its own pages: "
                  "TA %s, 3D %s"
                  % (len(allocator.pages),
                     ["%#x" % value for value in pair["tiling"]],
                     ["%#x" % value for value in pair["fragment"]]))
            attempt_manifest["backend_built_submission"] = {
                "tiling": ["%#x" % value for value in pair["tiling"]],
                "fragment": ["%#x" % value for value in pair["fragment"]],
                "pages": len(allocator.pages),
            }

        attempt_manifest["built_first_optional_items"] = {
            "page_dva": mapping["dva"],
            "page_pa": mapping["relocated_pa"],
            "body_bytes": len(payload),
            "tiling_dva": built_optional_items["tiling"],
            "fragment_dva": built_optional_items["fragment"],
        }

    if args.build_first_event_items:
        source_items = {}
        for channel_index, (channel_name, kind) in enumerate(
            (("TA_0", "tiling"), ("3D_0", "fragment"))
        ):
            entry_array = first_work_entry_array_dva(
                manifest, ram, init_message, channel_index)
            source_items[kind] = read_snapshot_dva_u64(
                manifest, ram, entry_array + 16)

        source_pages = {
            address & ~(PAGE_SIZE - 1) for address in source_items.values()
        }
        if len(source_pages) != 1:
            raise RuntimeError(
                "first event items do not share one page: %r"
                % sorted(source_pages)
            )
        source_page = source_pages.pop()
        payload_size = max(
            (address - source_page) + g17p_build.EVENT_RECORD_SIZE
            for address in source_items.values()
        )
        payload = bytearray(payload_size)
        for kind, source in source_items.items():
            selector_subtype = read_snapshot_dva_u64(manifest, ram, source)
            counter_word = read_snapshot_dva_u64(
                manifest, ram, source + 8) & 0xffffffff
            unk_10 = read_snapshot_dva_u64(
                manifest, ram, source + 0x10) & 0xffffffff
            body = g17p_build.build_event_record(
                counter_word >> g17p_build.EVENT_COUNTER_SHIFT,
                selector_subtype >> 32,
                unk_10,
            )
            offset = source - source_page
            payload[offset:offset + len(body)] = body

        mapping = map_built_page(
            manifest,
            table_pages,
            source_page,
            bytes(payload),
            "built-first-event-items",
        )
        virtual_page_overrides[mapping["dva"]] = mapping["relocated_pa"]
        initdata_relocations.append(mapping)
        built_event_items = {
            kind: mapping["dva"] + (source - source_page)
            for kind, source in source_items.items()
        }
        print(
            "Built first event items on page DVA %#x: TA %#x, 3D %#x"
            % (
                mapping["dva"],
                built_event_items["tiling"],
                built_event_items["fragment"],
            )
        )
        attempt_manifest["built_first_event_items"] = {
            "page_dva": mapping["dva"],
            "page_pa": mapping["relocated_pa"],
            "body_bytes": len(payload),
            "tiling_dva": built_event_items["tiling"],
            "fragment_dva": built_event_items["fragment"],
        }

    if args.build_ta_descriptor:
        # Put a descriptor firmware has never seen in front of it. It contains only
        # the modeled common header, pointer block, register list, and derived mirror
        # fields; all remaining kind-specific header scalars are zero.
        source_dva, objects, registers, captured = captured_work_model(
            "TA_0", "tiling")
        if built_render_registers is not None:
            registers = built_render_registers["tiling"]

        if args.build_ta_pools:
            # Build the two record pools as well, and point the descriptor at them, so
            # the bulk of the item's memory is generated rather than captured. The
            # generator has been checked byte for byte against the capture offline; this
            # is the first time it runs on hardware. The slot bases come from the
            # captured pools' own first records, since those are firmware-context
            # addresses this harness does not otherwise allocate.
            # Read from the captured image rather than through the device address
            # space, which does not exist yet at this point in the flow.
            def captured_u64(dva):
                page = int(dva) & ~(PAGE_SIZE - 1)
                for mapping in manifest["mappings"]:
                    if int(mapping["va"]) != page:
                        continue
                    if mapping.get("blob_index") is None:
                        break
                    base = int(mapping["blob_index"]) * PAGE_SIZE
                    offset = base + (int(dva) & (PAGE_SIZE - 1))
                    return struct.unpack_from("<Q", ram, offset)[0]
                raise RuntimeError("no captured contents for DVA %#x" % dva)

            record_a = captured_u64(objects[0])
            record_b_slot = captured_u64(objects[2] + g17p_build.ARRAY_B_SLOT_OFFSET)
            record_b_shared = captured_u64(
                objects[2] + g17p_build.ARRAY_B_SHARED_OFFSET)
            if built_leaf_pages is not None:
                record_a = (
                    built_leaf_pages["pool_a_slots"]
                    + g17p_build.POOL_A_SLOT_OFFSET
                )
                record_b_slot = (
                    built_leaf_pages["pool_b_slots"]
                    + g17p_build.POOL_B_SLOT_OFFSET
                )
                record_b_shared = (
                    built_leaf_pages["shared_slots"]
                    + g17p_build.SHARED_SLOT_OFFSET
                )
            pool_a_body = g17p_build.build_record_array_a(record_a)
            pool_b_body = g17p_build.build_record_array_b(record_b_slot,
                                                          record_b_shared)
            pool_a = map_built_page(manifest, table_pages, objects[0],
                                    pool_a_body, "built-pool-a")
            pool_b = map_built_page(manifest, table_pages, objects[2],
                                    pool_b_body, "built-pool-b")
            for record in (pool_a, pool_b):
                virtual_page_overrides[record["dva"]] = record["relocated_pa"]
                initdata_relocations.append(record)
            print("Built pool A at DVA %#x (%#x bytes) and pool B at %#x (%#x bytes)"
                  % (pool_a["dva"], len(pool_a_body),
                     pool_b["dva"], len(pool_b_body)))
            attempt_manifest["built_ta_pools"] = {
                "pool_a_dva": pool_a["dva"], "pool_a_bytes": len(pool_a_body),
                "pool_b_dva": pool_b["dva"], "pool_b_bytes": len(pool_b_body),
                "slot_base_a": record_a, "slot_base_b": record_b_slot,
                "shared_slot": record_b_shared}
            # A pool is larger than a page, so only its first page is remapped here.
            # The descriptor's item zero uses record zero, which is in that page.
            objects[0] = pool_a["dva"]
            objects[2] = pool_b["dva"]

        if built_shared_objects is not None:
            objects[1], objects[3] = built_shared_objects
        built_submission_objects = list(objects)
        body = bytearray(
            g17p_build.build_descriptor(
                "tiling", objects, registers,
                submit_sequence=struct.unpack_from("<Q", captured, 0x04)[0],
                context_id=struct.unpack_from("<I", captured, 0x0c)[0])
        )
        model_bytes = len(body)
        report_model_against_capture("TA_0", body, captured, model_bytes)
        copy_captured_words("TA_0", body, captured, model_bytes)
        if args.build_ta_captured_tail:
            record_bytes = item_record_size(0x00)
            if len(captured) < record_bytes:
                raise RuntimeError(
                    "captured tiling item is only %#x bytes, need %#x"
                    % (len(captured), record_bytes)
                )
            body.extend(captured[model_bytes:record_bytes])
        if args.build_structural_tails or args.build_ta_structural_tail:
            body = build_backend_structural_record(
                "tiling",
                body,
                captured,
                model_bytes,
                registers,
                render_parameters,
            )
        if "tiling" in descriptor_status_aliases:
            status_alias = descriptor_status_aliases["tiling"]
            struct.pack_into(
                "<Q",
                body,
                status_alias["tail_offset"],
                status_alias["alias"],
            )
        (attempt_dir / "built_ta_descriptor.bin").write_bytes(body)
        built = map_built_page(
            manifest,
            table_pages,
            source_dva,
            body,
            "built-TA_0-descriptor",
            preserve_source_offset=(
                (source_dva & (PAGE_SIZE - 1)) + len(body) <= PAGE_SIZE
            ),
        )
        virtual_page_overrides[built["dva"]] = built["relocated_pa"]
        initdata_relocations.append(built)
        print("Built a TA_0 descriptor at DVA %#x (%d registers, %#x bytes), "
              "page %#x" % (built["dva"], len(registers), len(body),
                            built["relocated_pa"]))
        attempt_manifest["built_ta_descriptor"] = {
            "dva": built["dva"], "register_count": len(registers),
            "body_bytes": len(body), "model_bytes": model_bytes,
            "captured_tail": bool(args.build_ta_captured_tail),
            "source_dva": source_dva}
        # Route it through the existing redirect, which points queue entry zero at a
        # replacement descriptor. That path was written for a copied descriptor and does
        # not care that this one is built.
        new_ta_descriptor = built

    if args.build_3d_descriptor:
        source_dva, objects, registers, captured = captured_work_model(
            "3D_0", "fragment"
        )
        if built_render_registers is not None:
            registers = built_render_registers["fragment"]
        if built_submission_objects is not None:
            # The pointer block is shared by the TA and 3D halves. If TA construction
            # replaced either record pool, the built 3D half must name the same pair.
            objects = list(built_submission_objects)
        body = bytearray(
            g17p_build.build_descriptor(
                "fragment", objects, registers,
                submit_sequence=struct.unpack_from("<Q", captured, 0x04)[0],
                context_id=struct.unpack_from("<I", captured, 0x0c)[0])
        )
        model_bytes = len(body)
        report_model_against_capture("3D_0", body, captured, model_bytes)
        copy_captured_words("3D_0", body, captured, model_bytes)
        layout = g17p_build.DESCRIPTOR_LAYOUT["fragment"]
        pointer_end = (
            layout["pointers"] + 8 + layout["pointer_gap"] + 3 * 8
        )
        if args.build_3d_captured_header:
            # This is a diagnostic overlay, not part of the clean-room builder.
            # Preserve the model's pointer block because it can name generated
            # pools, while restoring every other captured pre-register byte.
            built_pointer_block = bytes(body[layout["pointers"]:pointer_end])
            body[:layout["registers"]] = captured[:layout["registers"]]
            body[layout["pointers"]:pointer_end] = built_pointer_block
        if args.build_3d_captured_tail:
            record_bytes = item_record_size(0x01)
            if len(captured) < record_bytes:
                raise RuntimeError(
                    "captured fragment item is only %#x bytes, need %#x"
                    % (len(captured), record_bytes)
                )
            body.extend(captured[model_bytes:record_bytes])
        if args.build_structural_tails or args.build_3d_structural_tail:
            body = build_backend_structural_record(
                "fragment",
                body,
                captured,
                model_bytes,
                registers,
                render_parameters,
            )
        if "fragment" in descriptor_status_aliases:
            status_alias = descriptor_status_aliases["fragment"]
            struct.pack_into(
                "<Q",
                body,
                status_alias["tail_offset"],
                status_alias["alias"],
            )
        (attempt_dir / "built_3d_descriptor.bin").write_bytes(body)
        built = map_built_page(
            manifest,
            table_pages,
            source_dva,
            bytes(body),
            "built-3D_0-descriptor",
            preserve_source_offset=(
                (source_dva & (PAGE_SIZE - 1)) + len(body) <= PAGE_SIZE
            ),
        )
        virtual_page_overrides[built["dva"]] = built["relocated_pa"]
        initdata_relocations.append(built)
        print(
            "Built a 3D_0 descriptor at DVA %#x (%d registers, %#x bytes), "
            "page %#x"
            % (built["dva"], len(registers), len(body), built["relocated_pa"])
        )
        attempt_manifest["built_3d_descriptor"] = {
            "dva": built["dva"],
            "register_count": len(registers),
            "body_bytes": len(body),
            "model_bytes": model_bytes,
            "captured_header": bool(args.build_3d_captured_header),
            "captured_tail": bool(args.build_3d_captured_tail),
            "source_dva": source_dva,
        }
        new_3d_descriptor = built

    if args.new_first_ta_descriptor_dva:
        new_ta_descriptor = map_new_ta_descriptor_dva(
            manifest, ram, table_pages, init_message
        )
        virtual_page_overrides[new_ta_descriptor["dva"]] = new_ta_descriptor[
            "relocated_pa"
        ]
        initdata_relocations.append(new_ta_descriptor)
        print(
            "Mapped %s DVA %#x from source DVA %#x: %#x -> %#x"
            % (
                new_ta_descriptor["label"],
                new_ta_descriptor["dva"],
                new_ta_descriptor["source_dva"],
                new_ta_descriptor["original_pa"],
                new_ta_descriptor["relocated_pa"],
            )
        )
    if args.new_first_3d_descriptor_dva:
        new_3d_descriptor = map_new_3d_descriptor_dva(
            manifest, ram, table_pages, init_message
        )
        virtual_page_overrides[new_3d_descriptor["dva"]] = new_3d_descriptor[
            "relocated_pa"
        ]
        initdata_relocations.append(new_3d_descriptor)
        print(
            "Mapped %s DVA %#x from source DVA %#x: %#x -> %#x"
            % (
                new_3d_descriptor["label"],
                new_3d_descriptor["dva"],
                new_3d_descriptor["source_dva"],
                new_3d_descriptor["original_pa"],
                new_3d_descriptor["relocated_pa"],
            )
        )
    if args.new_first_work_support_item_dvas:
        for name, mapping in first_work_support_item_mappings(
            manifest, ram, init_message
        ):
            relocation = map_new_selected_dva(
                manifest,
                ram,
                table_pages,
                mapping,
                name + "-new-dva",
            )
            virtual_page_overrides[relocation["dva"]] = relocation[
                "relocated_pa"
            ]
            new_support_item_dvas[relocation["source_dva"]] = relocation
            initdata_relocations.append(relocation)
            print(
                "Mapped %s DVA %#x from source DVA %#x: %#x -> %#x"
                % (
                    relocation["label"],
                    relocation["dva"],
                    relocation["source_dva"],
                    relocation["original_pa"],
                    relocation["relocated_pa"],
                )
            )
    if initdata_relocations:
        attempt_manifest["initdata_relocations"] = initdata_relocations
        if len(initdata_relocations) == 1:
            attempt_manifest["initdata_relocation"] = initdata_relocations[0]
        attempt_manifest_path.write_text(
            json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
        )

    if args.control_timeline is not None:
        timeline_replay = ExactControlTimelineReplay(
            manifest,
            table_pages,
            virtual_page_overrides,
            args.control_timeline,
            args.control_producer,
        )
        CONTROL_TIMELINE_REPLAY[0] = timeline_replay
        attempt_manifest["control_timeline_replay"] = timeline_replay.summary(
            args.control_timeline
        )
        attempt_manifest_path.write_text(
            json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
        )
        print(
            "Prepared exact control timeline: %d records, %d direct pages, "
            "%d table pages, %d resource spans, %d leaf attribute patches"
            % (
                len(timeline_replay.records),
                timeline_replay.new_direct_pages,
                timeline_replay.new_table_pages,
                len(timeline_replay.resource_spans),
                timeline_replay.attr_patches,
            )
        )

    mailbox_path = attempt_dir / "mailbox_trace.txt"
    with mailbox_path.open("w", buffering=1) as mailbox_trace:
        mailbox_trace.write(
            "# t_ns asc op endpoint/message, plus explicitly replayed SGX RMWs\n"
        )
        address_space = CapturedAddressSpace(
            manifest, page_relocations, virtual_page_overrides
        )
        work_state = None
        if args.replay_first_work:
            work_state = prepare_first_work(
                address_space,
                init_message,
                require_work=(
                    not args.control_only
                    and args.graft_submission is None
                    and args.post_control_overlay is None
                ),
                reset_control=not args.resume_post_control,
                control_producer_at_init=(
                    args.control_producer if args.prestage_control else 1
                ),
                reset_work_producers=not args.resume_post_control,
                disabled_channels=args.disable_work_channel,
                deferred_channels=args.defer_work_channel,
                queue_state_40=args.queue_state_40,
                cleared_work_items_before_control=args.clear_work_item_before_control,
            )
            if args.rebuild_compute_work:
                attempt_manifest["rebuilt_compute_work"] = (
                    rebuild_pending_compute_work(address_space, work_state)
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if args.rebuild_compute_client:
                attempt_manifest["rebuilt_compute_client"] = (
                    rebuild_pending_compute_client(address_space, work_state)
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if args.rebuild_compute_registration:
                attempt_manifest["rebuilt_compute_registration"] = (
                    rebuild_pending_compute_registration(
                        address_space, work_state
                    )
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if args.zero_transitive_extra_firmware_pages is not None:
                rebuilt = attempt_manifest.get("rebuilt_compute_work")
                if rebuilt is None:
                    raise RuntimeError(
                        "--zero-transitive-extra-firmware-pages requires "
                        "--rebuild-compute-work"
                    )
                attempt_manifest["zeroed_transitive_extra_firmware_pages"] = (
                    zero_transitive_extra_firmware_pages(
                        manifest,
                        ram,
                        init_message,
                        rebuilt,
                        args.zero_transitive_extra_firmware_pages,
                    )
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            source_config_dvas = list(args.graft_source_config_page)
            if args.graft_all_modeled_source_config_pages:
                source_config_dvas.extend(
                    modeled_initdata_dvas(manifest, ram, init_message)
                )
            source_config_dvas = sorted(set(source_config_dvas))
            if source_config_dvas:
                rebuilt = attempt_manifest.get("rebuilt_compute_work")
                if rebuilt is None:
                    raise RuntimeError(
                        "source-config grafting requires "
                        "--rebuild-compute-work"
                    )
                if args.source_config_snapshot is None:
                    raise RuntimeError(
                        "source-config grafting requires "
                        "--source-config-snapshot"
                    )
                attempt_manifest["graft_source_config_pages"] = (
                    source_config_dvas
                )
                attempt_manifest["grafted_source_config_pages"] = (
                    graft_source_config_pages(
                        manifest,
                        args.source_config_snapshot,
                        source_config_dvas,
                        rebuilt,
                        address_space,
                        work_state,
                    )
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if args.graft_submission is not None:
                root = pathlib.Path(args.graft_submission)
                # A capture holds one subdirectory per channel; older ones hold the
                # files directly. Graft every half present, tiling before fragment so
                # the order matches the order a host publishes them.
                if (root / "pages.json").exists():
                    halves = [root]
                else:
                    halves = sorted(
                        child for child in root.iterdir()
                        if (child / "pages.json").exists()
                    )
                    halves.sort(key=lambda d: 0 if d.name.startswith("TA") else 1)
                if not halves:
                    raise SystemExit("no capture with pages.json under %s" % root)
                grafts = {}
                for half in halves:
                    grafted = graft_submission_closure(
                        address_space, work_state, half, manifest, table_pages,
                        inner_head=args.graft_inner_head,
                        objects_only=args.graft_objects_only)
                    grafts[half.name] = grafted
                    print("Grafted %d pages (%d newly mapped) from %s/%s, inner head %d"
                          % (grafted["pages_written"],
                             len(grafted["pages_created"]),
                             root.name, half.name,
                             grafted["inner_head"]))
                    print("  pending entries [%d,%d): %s"
                          % (grafted["pending_span"][0],
                             grafted["pending_span"][1],
                             ["%#x(selector %#x, %#x bytes)"
                              % (record["dva"], record["selector"], record["length"])
                              for record in grafted["pending_records"]]))
                    if grafted.get("pages_skipped"):
                        print("  %d captured pages left untouched, holding no object of "
                              "this submission" % len(grafted["pages_skipped"]))
                    if grafted["unresolved"]:
                        print("  %d closure pages could not be resolved here"
                              % len(grafted["unresolved"]))
                attempt_manifest["grafted_submission"] = (
                    grafts[halves[0].name] if len(halves) == 1 else grafts
                )
                extra_poison = []
                for dva in (args.poison_render_dva or ()):
                    page = int(dva) & ~(PAGE_SIZE - 1)
                    try:
                        mapping = render_context_mapping(manifest, page)
                        pa = int(mapping["pa"])
                        via = "existing render mapping"
                    except RuntimeError:
                        entry = map_at_exact_dva(
                            manifest, table_pages, page, b"\xa5" * PAGE_SIZE,
                            root_pa=render_root_pa(manifest))
                        pa = int(entry["pa"])
                        via = "created in render context"
                    # The snapshot manifest is immutable, so watches installed
                    # later in this run need the live mapping explicitly when
                    # --poison-render-dva created a leaf that was not captured.
                    RENDER_MAPPING_OVERRIDES[page] = pa
                    iface.writemem(pa, b"\xa5" * PAGE_SIZE)
                    p.dc_civac(pa, PAGE_SIZE)
                    extra_poison.append({"half": "by-dva", "dva": page, "pa": pa, "via": via})
                    print("Poisoned render page %#x at %#x (%s)" % (page, pa, via))
                if extra_poison:
                    u.inst("dsb sy")
                    attempt_manifest.setdefault("poisoned_render_pages", []).extend(extra_poison)

                if args.poison_grafted_render:
                    poisoned = []
                    for name, grafted in grafts.items():
                        for entry in grafted.get("render_pages") or ():
                            pa = entry.get("pa")
                            if pa is None:
                                continue
                            iface.writemem(int(pa), b"\xa5" * PAGE_SIZE)
                            p.dc_civac(int(pa), PAGE_SIZE)
                            poisoned.append({"half": name, "dva": entry["dva"], "pa": int(pa)})
                    u.inst("dsb sy")
                    attempt_manifest.setdefault("poisoned_render_pages", []).extend(poisoned)
                    print("Poisoned %d grafted render pages with 0xa5" % len(poisoned))
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )

            # The only submission this part has been seen to render is the first one,
            # which firmware processes as it starts. Publishing afterwards completes and
            # carries nothing. So to ask whether the backend's own construction renders,
            # its group has to become the first work rather than a later one.
            if BACKEND_BUILT[0] is not None and args.backend_first_work:
                pair = BACKEND_BUILT[0]["pair"]
                redirects = []
                # Only the descriptor and the optional record. The event record is written
                # by the submitter's staging path, which this route bypasses, and a first
                # submission's event carries a different subtype from a later one's, so the
                # harness's own first-work event is left in place rather than a zeroed one.
                for channel, kind in (("TA_0", "tiling"), ("3D_0", "fragment")):
                    for index, address in enumerate(pair[kind][:2]):
                        redirects.append(deferred_redirect(redirect_first_work_item_at_index,
                            address_space, work_state, channel, index, address))
                attempt_manifest["backend_first_work_redirects"] = redirects
                print("Redirected the first work to the backend's own group: "
                      "TA %s, 3D %s"
                      % (["%#x" % value for value in pair["tiling"]],
                         ["%#x" % value for value in pair["fragment"]]))

            if new_ta_descriptor is not None:
                attempt_manifest["first_work_item_redirect"] = (
                    deferred_redirect(redirect_first_work_item,
                        address_space,
                        work_state,
                        "TA_0",
                        new_ta_descriptor["dva"],
                    )
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if new_3d_descriptor is not None:
                attempt_manifest["first_work_3d_item_redirect"] = (
                    deferred_redirect(redirect_first_work_item,
                        address_space,
                        work_state,
                        "3D_0",
                        new_3d_descriptor["dva"],
                    )
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if built_optional_items is not None:
                redirects = [
                    deferred_redirect(redirect_first_work_item_at_index,
                        address_space,
                        work_state,
                        "TA_0",
                        1,
                        built_optional_items["tiling"],
                    ),
                    deferred_redirect(redirect_first_work_item_at_index,
                        address_space,
                        work_state,
                        "3D_0",
                        1,
                        built_optional_items["fragment"],
                    ),
                ]
                attempt_manifest["first_work_optional_item_redirects"] = redirects
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if built_event_items is not None:
                redirects = [
                    deferred_redirect(redirect_first_work_item_at_index,
                        address_space,
                        work_state,
                        "TA_0",
                        2,
                        built_event_items["tiling"],
                    ),
                    deferred_redirect(redirect_first_work_item_at_index,
                        address_space,
                        work_state,
                        "3D_0",
                        2,
                        built_event_items["fragment"],
                    ),
                ]
                attempt_manifest["first_work_event_item_redirects"] = redirects
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if new_support_item_dvas:
                redirects = []
                for canonical_name in ("TA_0", "3D_0"):
                    channel_name = selected_first_work_name(canonical_name)
                    channel = next(
                        channel
                        for channel in work_state["channels"]
                        if channel["name"] == channel_name
                    )
                    queue_dva = read_dva_u64(
                        address_space, channel["ring_addr"] + 8
                    )
                    entry_array_dva = read_dva_u64(
                        address_space, queue_dva + 8
                    )
                    for item_index in (1, 2):
                        original_dva = read_dva_u64(
                            address_space,
                            entry_array_dva + item_index * 8,
                        )
                        source_page = (
                            address_space.normalize(original_dva)
                            & ~(PAGE_SIZE - 1)
                        )
                        relocation = new_support_item_dvas.get(source_page)
                        if relocation is None:
                            raise RuntimeError(
                                "no new-DVA mapping for %s queue entry %d "
                                "at %#x" % (channel_name, item_index, original_dva)
                            )
                        replacement_dva = relocation["dva"] + (
                            address_space.normalize(original_dva)
                            & (PAGE_SIZE - 1)
                        )
                        redirects.append(
                            deferred_redirect(redirect_first_work_item_at_index,
                                address_space,
                                work_state,
                                channel_name,
                                item_index,
                                replacement_dva,
                            )
                        )
                attempt_manifest["first_work_support_item_redirects"] = redirects
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if args.omit_first_optional_item:
                omissions = [
                    omit_first_optional_item(address_space, work_state, channel_name)
                    for channel_name in ("TA_0", "3D_0")
                ]
                attempt_manifest["omitted_first_optional_items"] = omissions
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if ta_descriptor_backreference is not None:
                backref_dva = ta_descriptor_backreference["source_dva"]
                original = read_dva_u64(address_space, backref_dva)
                write_dva_u64(address_space, backref_dva, new_ta_descriptor["dva"])
                attempt_manifest["first_work_backreference_redirect"] = {
                    "source_dva": backref_dva,
                    "original_descriptor_dva": original,
                    "replacement_descriptor_dva": new_ta_descriptor["dva"],
                }
                print(
                    "Redirected TA descriptor back-reference %#x: %#x -> %#x"
                    % (backref_dva, original, new_ta_descriptor["dva"])
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if three_d_descriptor_backreference is not None:
                backref_dva = three_d_descriptor_backreference["source_dva"]
                original = read_dva_u64(address_space, backref_dva)
                write_dva_u64(address_space, backref_dva, new_3d_descriptor["dva"])
                attempt_manifest["first_work_3d_backreference_redirect"] = {
                    "source_dva": backref_dva,
                    "original_descriptor_dva": original,
                    "replacement_descriptor_dva": new_3d_descriptor["dva"],
                }
                print(
                    "Redirected 3D descriptor back-reference %#x: %#x -> %#x"
                    % (backref_dva, original, new_3d_descriptor["dva"])
                )
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if global_descriptor_status_patches:
                applied = []
                for patch in global_descriptor_status_patches:
                    original = read_dva_u64(address_space, patch["dva"])
                    write_dva_u64(
                        address_space,
                        patch["dva"],
                        patch["replacement"],
                    )
                    record = dict(patch)
                    record["original"] = original
                    applied.append(record)
                    print(
                        "Mirrored %s status register %#x at %#x: %#x -> %#x"
                        % (
                            patch["kind"],
                            patch["register"],
                            patch["dva"],
                            original,
                            patch["replacement"],
                        )
                    )
                attempt_manifest[
                    "applied_global_descriptor_status_patches"
                ] = applied
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True)
                    + "\n"
                )
            # Arbitrary device addresses, not just the descriptor page. The record
            # arrays a descriptor points at are the interesting target now, and each
            # array is one template repeated, so a perturbation of the template reaches
            # every record. That makes a single boot test a range of template bytes
            # rather than one field, which matters when the alternative is one fact per
            # boot against a 0x100-byte structure.
            dva_patch_records = []
            for dva, value in (args.patch_dva_u32 or ()):
                before = read_dva_u32(address_space, dva)
                write_dva_u32(address_space, dva, value)
                update_grafted_expected(dva, struct.pack("<I", value))
                dva_patch_records.append({"dva": dva, "width": 4, "before": before,
                                          "after": value})
            for dva, value in (args.patch_dva_u64 or ()):
                before = read_dva_u64(address_space, dva)
                write_dva_u64(address_space, dva, value)
                update_grafted_expected(dva, struct.pack("<Q", value))
                dva_patch_records.append({"dva": dva, "width": 8, "before": before,
                                          "after": value})
            # A firmware resumed from a completed control state consumes no further control
            # entries, while one that starts with entries outstanding consumes every one. The
            # difference between those two worlds might be nothing more than whether anything was
            # outstanding when firmware started, so leave a harmless 0x2e entry pending here,
            # before it does, rather than publishing one afterwards.
            if args.prestage_control_tick:
                backend_module = load_backend_package()
                prestage_initdata = canonicalize(
                    int(init_message) & ((1 << 44) - 1),
                    int(manifest["vaddr_shift"]))
                prestage_channels = backend_module.G17PChannels(
                    lambda addr, size: address_space.read(addr, size),
                    prestage_initdata)
                prestage_control = prestage_channels.entries[12]
                prestage_counters = prestage_channels.counters(prestage_control)
                prestage_producer = prestage_counters[2]
                # Copying an existing entry rather than building a 0x2e lets a run leave the
                # opcode a host uses to open the phase outstanding instead. A firmware that
                # executes one of those in its own boot is the only one seen to keep servicing the
                # channel afterwards, and this is what separates that from merely having had
                # something outstanding.
                copy_from = args.prestage_control_copy
                for tick in range(args.prestage_control_tick):
                    if copy_from is not None:
                        # Successive entries, so a run can leave a complete opening sequence
                        # outstanding rather than one entry repeated. Three 0x16 and then the 0x20
                        # is what a host performs, and a partial one may not arm anything.
                        body = bytearray(address_space.read(
                            prestage_control["ring_addr"]
                            + (copy_from + tick) * 0x40, 0x40))
                    elif args.prestage_control_entry_hex:
                        # A 0x20 published after the opening crashes the coprocessor, but firmware
                        # accepts one during the opening. Leaving a host's second 0x20 outstanding
                        # before firmware starts is the only way to have it processed while 0x20 is
                        # still legal, which is what a host does before its later work.
                        body = bytearray(bytes.fromhex(
                            args.prestage_control_entry_hex.replace(" ", "")))
                        if len(body) != 0x40:
                            raise SystemExit(
                                "a device-control entry is 0x40 bytes, got %#x" % len(body))
                    else:
                        body = bytearray(0x40)
                        struct.pack_into("<II", body, 0, 0x2e, tick)
                    address_space.write(
                        prestage_control["ring_addr"]
                        + (prestage_producer + tick) * 0x40, bytes(body))
                address_space.write(
                    prestage_control["state_addrs"][2],
                    struct.pack("<I", prestage_producer + args.prestage_control_tick))
                print("Prestaged %d control ticks at ring %#x index %d, counters %s, "
                      "state addrs %s"
                      % (args.prestage_control_tick, prestage_control["ring_addr"],
                         prestage_producer, prestage_counters,
                         ["%#x" % addr for addr in prestage_control["state_addrs"]]))
                attempt_manifest["prestaged_control_ticks"] = {
                    "count": args.prestage_control_tick,
                    "first_index": prestage_producer,
                    "counters_before": prestage_counters,
                }

            # A device-control 0x20 names a slot in the operand page's table, and every populated
            # slot there is a buffer that exists. So publishing one of this host's own means
            # allocating and mapping a buffer first, appending it to the table, and only then
            # naming it. The buffer's address is what the table carries, so it does not have to
            # continue the guest's spacing; it only has to be mapped.
            for slot in (args.map_operand_slot or ()):
                table_at = OPERAND_TABLE_BASE + slot * OPERAND_TABLE_STRIDE
                # The operand page belongs to the render context, so it is reached through its
                # captured mapping rather than through the firmware address space.
                operand_mapping = render_context_mapping(manifest, OPERAND_PAGE)
                operand_pa = int(operand_mapping["pa"])
                previous = struct.unpack("<Q", iface.readmem(
                    operand_pa + table_at - OPERAND_TABLE_STRIDE, 8))[0]
                if not previous:
                    raise SystemExit(
                        "operand slot %d has no populated slot before it to copy a buffer's "
                        "attributes from" % slot)
                source_dva = previous & ~(1 << 60)
                # The populated buffers lie on a fixed stride from the first, and the slot firmware
                # reads for this entry is that address and no other. An earlier attempt let the
                # allocator pack the buffer in directly after its source, which put it two pages
                # low, and the table entry then named an address the stride does not land on.
                target_dva = source_dva + OPERAND_BUFFER_STRIDE
                mappings = map_built_context_pages(
                    manifest, table_pages, source_dva,
                    args.map_operand_pages, "operand-buffer", 1, 0,
                    alias_source_pages=args.alias_operand_buffer,
                    target_dva=target_dva)
                initdata_relocations.extend(mappings)
                buffer_dva = int(mappings[0]["dva"])
                packed = buffer_dva | (1 << 60)
                iface.writemem(operand_pa + table_at, struct.pack("<Q", packed))
                p.dc_civac(operand_pa, PAGE_SIZE)
                print("Mapped %d pages for operand slot %d at %#x (source %#x), "
                      "table entry %#x -> %#018x"
                      % (args.map_operand_pages, slot, buffer_dva, source_dva,
                         OPERAND_PAGE + table_at, packed))
                attempt_manifest.setdefault("operand_slots", []).append({
                    "slot": slot,
                    "buffer_dva": buffer_dva,
                    "pages": args.map_operand_pages,
                    "packed": packed,
                })

            # The render context is a separate root, so these go through its captured
            # mapping to a physical address rather than through the firmware address
            # space. Read-modify-write of the containing word keeps the rest of the
            # structure exactly as captured, so a run changes one field and no more.
            for dva, value in (args.patch_render_u32 or ()):
                mapping = render_context_mapping(manifest, dva)
                pa = int(mapping["pa"]) + (int(dva) & (PAGE_SIZE - 1))
                before = struct.unpack("<I", iface.readmem(pa, 4))[0]
                iface.writemem(pa, struct.pack("<I", int(value)))
                p.dc_civac(pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
                dva_patch_records.append({"dva": dva, "width": 4, "before": before,
                                          "after": value, "via": "render context",
                                          "pa": pa})
            # Writing a generated stream over an identical captured one would prove nothing,
            # so the page is destroyed first. Hardware has already shown that a page filled
            # with this marker renders nothing at all, which makes any render afterwards
            # attributable to the generated bytes rather than to what was there before.
            if args.build_encoder:
                params = RENDER_PARAMETERS[0]
                if params is None:
                    raise RuntimeError(
                        "--build-encoder needs --build-render-register-recipe, which is "
                        "where the encoder's address is derived")
                encoder_dva = params.encoder
                mapping = render_context_mapping(manifest, encoder_dva)
                page_pa = int(mapping["pa"])
                offset = encoder_dva & (PAGE_SIZE - 1)
                captured = iface.readmem(
                    page_pa + offset, g17p_encoder.ENCODER_SIZE)
                model = g17p_encoder.parse_encoder(
                    captured, params.context_base)
                generated = g17p_encoder.build_encoder(model)
                if generated != captured:
                    differing = [index for index in range(len(generated))
                                 if generated[index] != captured[index]]
                    raise RuntimeError(
                        "generated encoder differs from the captured one at %s"
                        % ["%#x" % index for index in differing[:12]])
                iface.writemem(page_pa, b"\xa5" * PAGE_SIZE)
                iface.writemem(page_pa + offset, generated)
                p.dc_civac(page_pa, PAGE_SIZE)
                print("Built the tiler encoder at DVA %#014x (%d bytes) over a "
                      "destroyed page" % (encoder_dva, len(generated)))
                attempt_manifest["built_encoder"] = {
                    "dva": encoder_dva,
                    "pa": page_pa,
                    "bytes": len(generated),
                    "index_count": model.index_count,
                    "primitive": model.primitive,
                    "opcode": model.opcode,
                }

            # Bring firmware up with nothing queued, so that a host publication is the
            # first thing to use the parameter buffer. Every other way of suppressing the
            # first work either does not suppress it or removes the path that publishes.
            # The write pointer is moved back to the done pointer rather than to zero,
            # since a write pointer behind the done pointer is a state no host produces.
            if args.empty_queues_before_start:
                emptied = []
                for channel in work_state["channels"]:
                    if channel.get("disabled") or "captured_producer" not in channel:
                        continue
                    queue_dva = channel.get("constructed_queue_dva")
                    if queue_dva is None:
                        queue_dva = read_dva_u64(
                            address_space, channel["ring_addr"] + 8)
                    if not queue_dva:
                        continue
                    pointer_state = read_dva_u64(address_space, queue_dva)
                    done = read_dva_u32(address_space, pointer_state + 0x00)
                    write = read_dva_u32(
                        address_space, pointer_state + g17p_build.QUEUE_PTR_WRITE
                        if hasattr(g17p_build, "QUEUE_PTR_WRITE") else pointer_state + 0x40)
                    write_dva_u32(address_space, pointer_state + 0x40, done)
                    # The queue's write pointer alone does not suppress the startup work:
                    # emptying it and leaving the ring slot alone still renders. Firmware
                    # takes what the slot announces, so the announced head has to go too.
                    slot_head = channel["ring_addr"] + 0x14
                    head_was = read_dva_u32(address_space, slot_head)
                    write_dva_u32(address_space, slot_head, head_was & ~0xffff)
                    emptied.append({"channel": channel["name"],
                                    "pointer_state": pointer_state,
                                    "done": done, "write_was": write,
                                    "slot_head_was": head_was})
                    print("  %s queue emptied: write %d -> %d (done), slot head %#x -> %#x"
                          % (channel["name"], write, done, head_was,
                             head_was & ~0xffff))
                if emptied:
                    attempt_manifest["emptied_queues"] = emptied

            if dva_patch_records:
                print("Patched %d device addresses before start"
                      % len(dva_patch_records))
                for record in dva_patch_records:
                    print("  %#014x  %#010x -> %#010x%s"
                          % (record["dva"], record["before"], record["after"],
                             "  (render context)" if record.get("via") else ""))
                attempt_manifest["applied_dva_patches"] = dva_patch_records

            patch_records = patch_first_work_values(
                address_space, work_state, args.patch_first_work_u32, 4
            ) + patch_first_work_values(
                address_space, work_state, args.patch_first_work_u64, 8
            )
            for record in patch_records:
                update_grafted_expected(
                    record["descriptor_dva"] + record["offset"],
                    int(record["replacement"]).to_bytes(
                        record["size"], "little"
                    ),
                )
            if patch_records:
                attempt_manifest["applied_first_work_patches"] = patch_records
                attempt_manifest_path.write_text(
                    json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
                )
            if args.coproc_maint:
                replay_coproc_maint(manifest, address_space, work_state)

        initial_render_watch = None
        if args.watch_render_from_start:
            initial_render_watch = snapshot_context_watch_pages(
                manifest, args.watch_render_dva, args.watch_context
            )

        # The scan across the first work takes its baseline after firmware has settled, which on a
        # world whose captured work is already pending means the work has run before the baseline
        # exists. Taken here, before firmware starts, the difference covers the startup work too.
        if args.scan_render_from_start and SCAN_RENDER_PREFIX[0]:
            INITIAL_SCAN_BASELINE[0] = scan_render_baseline(
                manifest, SCAN_RENDER_PREFIX[0])
            print("Render-context scan baseline taken before firmware starts")

        power_on_gpu(mailbox_trace)

        primary_base = int(u.adt["/arm-io/gfx-asc"].get_reg(0)[0])
        secondary_base = int(u.adt["/arm-io/gfx1-asc"].get_reg(0)[0])
        primary = ReplayASC(
            u, primary_base, "gfx-asc", address_space, mailbox_trace
        )
        secondary = ReplayASC(
            u, secondary_base, "gfx1-asc", address_space, mailbox_trace
        )
        asces = [primary, secondary]

        print("Starting primary ASC management")
        primary.start()
        primary.start_ep(0x20)
        primary.start_ep(0x21)

        print("Starting secondary ASC management")
        secondary.start()
        secondary.start_ep(0x20)
        secondary.start_ep(0x21)

        apply_pre_init_sgx_write(mailbox_trace)
        if args.graft_firmware_pages is not None and args.graft_after_boot:
            # The convergence run put the cold boot's content in place before the coprocessors
            # started, which is not the cold path's situation: it builds its world about a minute
            # after firmware is already running. Applying the same content after the boot separates
            # the content from when it arrives.
            print("Grafting after the coprocessors started")
            _do_graft()

        if args.pre_initdata_delay:
            # The cold-boot path starts the coprocessors and then spends a long time mapping
            # 56 MiB of render extent and 500 firmware pages before it sends initdata, where this
            # path sends it promptly. If firmware degrades over that window, lengthening it here
            # should stop this world rendering. Testing the theory on the world that works is
            # cheaper and sounder than fixing the cold path's deferred start to test it there.
            print("Waiting %.1fs between coprocessor start and initdata"
                  % args.pre_initdata_delay)
            time.sleep(args.pre_initdata_delay)
            for asc in (primary, secondary):
                try:
                    asc.work_pending()
                except Exception as exc:
                    print("  %s during the wait: %s" % (type(exc).__name__, exc))

        primary_msg = init_message
        secondary_msg = (primary_msg & ~((1 << 44) - 1)) | (
            (primary_msg + 0x8000) & ((1 << 44) - 1)
        )
        print("Sending primary initdata message %#x" % primary_msg)
        primary.send(primary_msg, ASCMessage1(EP=0x20))
        if args.no_secondary_initdata:
            # The record describes the second instance as a power instance, its faulting task
            # being the power one, and an accelerator that is never clocked is exactly what this
            # path's symptom looks like. So ask whether the render depends on it at all: if it does
            # not, the second instance is out of scope for the cold path's blocker, and if it does,
            # the cold path's own second instance becomes the suspect.
            print("Not sending the secondary's initdata message")
        else:
            print("Sending secondary initdata message %#x" % secondary_msg)
            secondary.send(secondary_msg, ASCMessage1(EP=0x20))

        acknowledged = wait_init_ack(
            asces[:1] if args.no_secondary_initdata else asces, args.timeout)
        if not acknowledged:
            raise TimeoutError(
                "init ACK timeout: primary=%s secondary=%s"
                % (primary.fw.init_ack, secondary.fw.init_ack)
            )

        print("Both AGX firmware instances acknowledged initdata")

        if args.dump_post_ack:
            # Every post-acknowledgement comparison so far has been this path's fresh firmware
            # against the **capture**, which is macOS's firmware's output rather than a fresh
            # firmware's. That is not the right comparison: it cannot distinguish "this firmware
            # behaves differently" from "this firmware has not done what a long-running one did".
            # This dumps what a fresh firmware writes in the world that renders, so the two fresh
            # firmwares can be diffed against each other.
            out = pathlib.Path(args.dump_post_ack)
            out.mkdir(parents=True, exist_ok=True)
            root_dva = canonicalize(int(init_message) & ((1 << 44) - 1),
                                    int(manifest["vaddr_shift"]))
            root_pa, _, _ = snapshot_dva_pa(manifest, root_dva)
            descriptor = bytes(iface.readmem(root_pa, 0x100))
            saved = {}
            targets = [("root", root_dva, 0x100)]
            for name, offset, size in (("main_config", 0x18, 0x600),
                                       ("data_region", 0x20, 0x1000),
                                       ("status_a", 0xa8, 0x400),
                                       ("status_b", 0xb0, 0x400)):
                dva = struct.unpack_from("<Q", descriptor, offset)[0]
                if dva:
                    targets.append((name, dva, size))
            targets.append(("shared_control", 0xfffffc20c0830000, 0x80))
            targets.append(("operand_table", 0x0000007000208000, 0x800))
            for name, dva, size in targets:
                try:
                    pa, _, _ = snapshot_dva_pa(manifest, dva)
                except Exception as exc:
                    print("  %s at %#x not resolvable: %s" % (name, dva, exc))
                    continue
                p.dc_civac(pa & ~(PAGE_SIZE - 1), PAGE_SIZE)
                body = bytes(iface.readmem(pa, size))
                (out / (name + ".bin")).write_bytes(body)
                saved[name] = {"dva": "%#x" % dva, "pa": "%#x" % pa,
                               "nonzero": sum(b != 0 for b in body)}
                print("  saved %-14s %#x bytes, %d non-zero"
                      % (name, size, saved[name]["nonzero"]))
            # Deliberately no accelerator register probe here. Reading the window at the
            # accelerator's register base from this world raises an SError and then storms,
            # thousands of them, taking the run down before it reports anything. The cold path
            # reads the same sixteen registers without complaint. That difference is itself a
            # measurement, and it is recorded in the log, but it cannot be taken this way: the
            # probe destroys the run it is trying to observe.
            (out / "manifest.json").write_text(
                json.dumps(saved, indent=2, sort_keys=True) + "\n")
            print("Saved this world's post-acknowledgement state -> %s" % out)
        if work_state is not None:
            control_addrs = work_state["control_state_addrs"]
            print(
                "Device-control counters before initial 0x89: %s"
                % [
                    read_dva_u32(address_space, address)
                    for address in control_addrs
                ]
            )
            # A resumed checkpoint has already completed device control. Its
            # wrapped ring no longer promises that historical entry three is
            # the opening opcode-0x20 record, and no control entry is replayed
            # on this path, so inspecting that stale slot is neither valid nor
            # relevant to the startup-work replay.
            control_operand_before = (
                None
                if args.resume_post_control
                else snapshot_control_operand_state(
                    manifest, address_space, work_state
                )
            )
        else:
            control_operand_before = None
        if not args.init_only:
            for asc in asces:
                asc.send(0x0089000000000000, ASCMessage1(EP=0x21))

        if args.init_only:
            print("Observing after initdata ACK without a doorbell")
            attempt_manifest["result"] = "passed-init-only"
        elif work_state is None and args.backend_control_tick:
            # The pre-control snapshot has no pending work, so the work path never runs. Whether
            # firmware takes device-control entries is answerable without any, and this is the only
            # world in which firmware performs the control phase itself.
            attempt_manifest["control_tick_counters"] = control_channel_tick(
                asces, address_space, manifest, init_message,
                args.backend_control_tick, args.backend_control_tick_start)
            attempt_manifest["result"] = "passed-control-tick"
        elif work_state is not None:
            attempt_manifest["result"] = submit_first_work(
                asces,
                address_space,
                manifest,
                work_state,
                args.timeout,
                args.control_producer,
                args.control_only,
                args.resume_post_control,
                args.prestage_control,
                args.dump_pre_control_state,
                args.clear_work_item_after_control,
                init_message,
                control_operand_before,
                post_control_overlay,
                args.watch_render_dva,
                args.copy_dva_range,
                args.watch_context,
                initial_render_watch,
                snapshot,
                restore_ram,
                args.reapply_snapshot_after_control,
            )
            if args.replay_second_outer_message:
                if args.clear_watched_render_before_extra_submissions:
                    attempt_manifest["inter_submission_render_clear"] = (
                        clear_render_watch_pages(initial_render_watch)
                    )
                # Repeatable rather than a single extra message. Two submissions
                # completing says the ring advances once; a stream is the claim worth
                # testing, and the function requires the queue drained on entry and
                # waits for completion, so calling it again is safe.
                rounds = []
                for round_index in range(args.extra_submissions):
                    rounds.append(
                        replay_second_outer_message(
                            asces,
                            address_space,
                            work_state,
                            args.timeout,
                            args.second_outer_clear_first_submit,
                            args.append_second_inner_batch,
                            args.second_outer_patch_u32,
                            args.construct_queue,
                            manifest,
                            ram,
                            table_pages,
                        )
                    )
                    print("completed extra submission %d of %d"
                          % (round_index + 1, args.extra_submissions))
                attempt_manifest["second_outer_message"] = rounds
                attempt_manifest["extra_submissions"] = args.extra_submissions
                if args.clear_watched_render_before_extra_submissions:
                    post_extra_changed = report_render_watch_pages(
                        initial_render_watch, "post_extra"
                    )
                    attempt_manifest["post_extra_render_changed_bytes"] = (
                        post_extra_changed
                    )
                    if post_extra_changed == 0:
                        raise RuntimeError(
                            "extra submissions retired without repopulating any "
                            "cleared watched output-page byte"
                        )
                    print(
                        "POST-EXTRA PHYSICAL OUTPUT PASS: %d watched output-page "
                        "bytes changed" % post_extra_changed
                    )
                attempt_manifest["result"] = (
                    "passed-%d-extra-submissions" % args.extra_submissions)
        else:
            attempt_manifest["result"] = "passed-init-ack"

        # Never call work_pending() here.  It drains to empty, but event 0x42
        # can be continuously asserted in an otherwise healthy world and
        # would deadlock this diagnostic epilogue.  A bounded observation is
        # sufficient to record late faults and completion activity.
        empty_rounds = 0
        for _round in range(16):
            moved = False
            for asc in asces:
                if asc.has_messages():
                    asc.work()
                    moved = True
            if moved:
                empty_rounds = 0
            else:
                empty_rounds += 1
                if empty_rounds >= 2:
                    break
            time.sleep(0.001)

        dump_state(
            attempt_dir / "post_init_state.json",
            asces,
            manifest,
            init_message,
            work_state,
        )
        attempt_manifest["primary_ack"] = bool(primary.fw.init_ack)
        attempt_manifest["secondary_ack"] = bool(secondary.fw.init_ack)
        attempt_manifest["primary_events"] = int(primary.fw.events)
        attempt_manifest["secondary_events"] = int(secondary.fw.events)

    attempt_manifest["backend_firmware_grafts"] = BACKEND_FIRMWARE_GRAFTS
    attempt_manifest["finished_utc"] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    attempt_manifest_path.write_text(
        json.dumps(attempt_manifest, indent=2, sort_keys=True) + "\n"
    )
    return 0


try:
    status = run()
except BaseException as exc:
    print("Replay failed: %s: %s" % (type(exc).__name__, exc))
    traceback.print_exc()
    attempt_path = attempt_dir / "attempt.json"
    if attempt_path.exists():
        attempt = json.loads(attempt_path.read_text())
    else:
        attempt = {}
    attempt["result"] = "failed"
    attempt["error_type"] = type(exc).__name__
    attempt["error"] = str(exc)
    attempt["backend_firmware_grafts"] = BACKEND_FIRMWARE_GRAFTS
    attempt["finished_utc"] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    attempt_path.write_text(json.dumps(attempt, indent=2, sort_keys=True) + "\n")
    status = 1

print("Replay result directory: %s" % attempt_dir)
raise SystemExit(status)
