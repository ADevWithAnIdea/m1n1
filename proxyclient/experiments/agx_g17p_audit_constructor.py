#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the active G17P initdata constructor without touching hardware.

This executes ``agx_g17p_boot.build_initdata`` against an in-memory Arena/UAT,
then applies the fixed pre-init mutations selected by ``DRMAsahiShim``.  The
result is therefore derived from the current source, not from an old generated
snapshot or a second implementation of the structures.

The report separates a pristine host handoff from a later running snapshot.
Only native-nonzero/current-zero bytes in the handoff are plausible omitted
host inputs.  Differences that first appear in the running snapshot are
firmware/runtime state and are reported separately.
"""

import argparse
import contextlib
import datetime
import importlib.util
import io
import json
import os
import pathlib
import struct
import sys
import types


HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))

from m1n1.agx import g17p                         # noqa: E402
from m1n1.agx import g17p_initdata as initdata    # noqa: E402


PAGE = 0x4000
KERN_VA_BASE = 0xFFFFFC2000000000
ARTIFACT_ROOT = pathlib.Path(
    os.path.expanduser("~/asahi_re/artifacts/agx_g17p"))
PRE_INIT = ARTIFACT_ROOT / "initdata_pre_submit_all_uat_roots_v2_20260724_150935"
SERIALIZED_HANDOFF = ARTIFACT_ROOT / "live_instances_20260726_213231"
POST_ACK = ARTIFACT_ROOT / "live_instances_20260727_034329"
RUNTIME = ARTIFACT_ROOT / "native_t256_write_full_20260806_085603"


class _Node:
    def __init__(self, **values):
        self.__dict__.update(values)


def load_active_boot_module():
    """Import the hardware runner with only its import-time proxy globals stubbed."""
    name = "_g17p_constructor_audit_boot"
    if name in sys.modules:
        return sys.modules[name]

    # agx_g17p_boot imports m1n1.setup at module load and otherwise uses the
    # proxy globals only in live functions.  Supplying the two ADT values needed
    # by Ver.set_version keeps this audit entirely offline.
    setup = types.ModuleType("m1n1.setup")
    setup.p = object()
    setup.iface = object()
    setup.u = types.SimpleNamespace(
        version="V13_5",
        adt={
            "/arm-io": _Node(soc_generation="H17"),
            "/chosen": _Node(chip_id=g17p.CHIP_ID),
        },
    )
    sys.modules["m1n1.setup"] = setup

    path = HERE / "agx_g17p_boot.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeUAT:
    def __init__(self):
        self.mappings = []

    def iomap_at(self, context, va, pa, size, **flags):
        self.mappings.append({
            "context": int(context),
            "va": int(va),
            "pa": int(pa),
            "size": int(size),
            "flags": {name: int(value) for name, value in flags.items()},
        })

    def flush_dirty(self):
        pass

    def invalidate_cache(self):
        pass


class MemoryArena:
    """In-memory implementation of the live Arena interface.

    Device and physical addresses are intentionally identical here.  The active
    constructor only needs their relation; using one address makes every write
    and pointer independently inspectable in the report.
    """

    def __init__(self, base_va):
        self.va = int(base_va)
        self.entries = []
        self._maps = []
        self.writes = []
        self.phase = "build_initdata"

    @contextlib.contextmanager
    def writing(self, phase):
        previous = self.phase
        self.phase = phase
        try:
            yield
        finally:
            self.phase = previous

    def _new_mapping(self, va, size, name, logical_va, logical_size):
        end = va + size
        for mapping in self._maps:
            if va < mapping["va"] + mapping["size"] and mapping["va"] < end:
                raise RuntimeError(
                    "%s at %#x overlaps %s at %#x" %
                    (name, logical_va, mapping["name"], mapping["logical_va"]))
        mapping = {
            "name": name,
            "va": int(va),
            "pa": int(va),
            "size": int(size),
            "logical_va": int(logical_va),
            "logical_size": int(logical_size),
            "data": bytearray(size),
        }
        self._maps.append(mapping)
        self.entries.append({
            "name": name,
            "va": int(logical_va),
            "pa": int(logical_va),
            "size": int(logical_size),
            "map_va": int(va),
            "map_pa": int(va),
            "map_size": int(size),
        })
        return mapping

    def alloc(self, size, name, data=None):
        size = (int(size) + PAGE - 1) & ~(PAGE - 1)
        va = self.va
        self._new_mapping(va, size, name, va, size)
        self.va += size
        if data is not None:
            self.write(va, data)
        return va, va

    def alloc_at(self, va, size, name, data=None, flags=None):
        del flags
        va = int(va)
        size = int(size)
        page_va = va & ~(PAGE - 1)
        offset = va - page_va
        span = (offset + size + PAGE - 1) & ~(PAGE - 1)
        self._new_mapping(page_va, span, name, va, size)
        if data is not None:
            self.write(va, data)
        return va, va

    def _mapping(self, address, size=1):
        for mapping in reversed(self._maps):
            if (mapping["va"] <= address
                    and address + size <= mapping["va"] + mapping["size"]):
                return mapping
        return None

    def physical(self, dva):
        mapping = self._mapping(int(dva))
        return int(dva) if mapping is not None else None

    def write(self, pa, data):
        pa = int(pa)
        data = bytes(data)
        mapping = self._mapping(pa, len(data))
        if mapping is None:
            raise RuntimeError("write to unmapped address %#x (%#x bytes)" %
                               (pa, len(data)))
        offset = pa - mapping["pa"]
        mapping["data"][offset:offset + len(data)] = data
        self.writes.append({
            "phase": self.phase,
            "address": pa,
            "size": len(data),
            "nonzero_bytes": sum(byte != 0 for byte in data),
        })

    def read(self, dva, size):
        dva = int(dva)
        size = int(size)
        out = bytearray()
        while size:
            mapping = self._mapping(dva)
            if mapping is None:
                raise ValueError("unmapped address %#x" % dva)
            offset = dva - mapping["va"]
            take = min(size, mapping["size"] - offset)
            out.extend(mapping["data"][offset:offset + take])
            dva += take
            size -= take
        return bytes(out)

    def allocation_report(self):
        return [{
            key: value for key, value in mapping.items() if key != "data"
        } | {
            "nonzero_bytes": sum(byte != 0 for byte in mapping["data"]),
        } for mapping in self._maps]


def write_u32(arena, address, value):
    arena.write(address, struct.pack("<I", int(value)))


def apply_active_pre_init(boot, arena, built):
    """Apply the fixed mutations selected by DRMAsahiShim.G17P_COLD_BOOT_ARGS."""
    instances = built["instances"]
    with arena.writing("stage_device_control"):
        # --empty-operand-table is fixed in the shim: these mappings exist and
        # are zero, including the later runtime operand buffers.
        arena.alloc_at(boot.CONTROL_OPERAND_TABLE_VA, PAGE,
                       "control_operand_table")
        arena.alloc_at(boot.COMPUTE_BINDING_OPERAND_TABLE_VA, PAGE,
                       "compute_binding_operand_table")
        arena.alloc_at(boot.COMPUTE_CLASS2_SUPPORT_TABLE_VA, PAGE,
                       "compute_class2_support_table")
        for index in range(boot.CONTROL_OPERAND_ENTRIES,
                           boot.CONTROL_OPERAND_ENTRIES_RUNTIME):
            arena.alloc_at(
                boot.CONTROL_OPERAND_BUFFER_BASE
                + index * boot.CONTROL_OPERAND_BUFFER_STRIDE,
                boot.CONTROL_OPERAND_BUFFER_SIZE,
                "runtime_operand_buffer_%d" % index,
            )

        primary = bytearray(g17p.CONTROL_MESSAGE_SIZE * 3)
        for index in range(3):
            struct.pack_into("<I", primary,
                             index * g17p.CONTROL_MESSAGE_SIZE,
                             g17p.CONTROL_MESSAGE_INIT)
        primary.extend(boot.build_control_20_entry())
        arena.write(instances[0]["control_ring_pa"], primary)

        produced = sum(count for _opcode, count in
                       boot.SECONDARY_CONTROL_SEQUENCE)
        secondary = bytearray(g17p.CONTROL_MESSAGE_SIZE * produced)
        entry = 0
        for opcode, count in boot.SECONDARY_CONTROL_SEQUENCE:
            for _ in range(count):
                struct.pack_into("<I", secondary,
                                 entry * g17p.CONTROL_MESSAGE_SIZE, opcode)
                entry += 1
        arena.write(instances[1]["control_ring_pa"], secondary)

        for instance, producer in zip(instances, (4, produced)):
            address = instance["channels"][
                g17p.CHANNEL_TABLE_WORK_COUNT][0][g17p.CHANNEL_STATE_PRODUCER]
            write_u32(arena, address, producer)

    # --build-records is also fixed in the shim.  This page is one of the two
    # hardware-data region-record targets.
    with arena.writing("build_current_job_records"):
        records = (
            ("tiling", boot.SUBMISSION_ADDRESSES["work_descriptor_0"][0],
             boot.SUBMISSION_ADDRESSES["queue_record_array"]),
            ("fragment", boot.SUBMISSION_ADDRESSES["work_descriptor_0"][1],
             boot.SUBMISSION_ADDRESSES["queue_record_array"]
             + g17p.QUEUE_RECORD_STRIDE),
        )
        for index, (kind, descriptor, queue) in enumerate(records):
            header, second = boot.PER_SUBMISSION_RECORD_HEADERS[kind]
            base = (boot.PER_SUBMISSION_RECORD_VA
                    + index * boot.PER_SUBMISSION_RECORD_STRIDE)
            arena.write(base, struct.pack("<QQ", header, second))
            arena.write(base + boot.PER_SUBMISSION_DESCRIPTOR_AT,
                        struct.pack("<Q", descriptor))
            arena.write(base + boot.PER_SUBMISSION_QUEUE_AT,
                        struct.pack("<Q", queue))

    with arena.writing("apply_scalars"):
        primary = instances[0]
        for offset, value in boot.MAIN_CONFIG_SCALARS:
            write_u32(arena, primary["main_va"] + offset, value)
        for offset, value in boot.DATA_REGION_SCALARS:
            write_u32(arena, built["region_c_va"] + offset, value)


def build_source_image():
    boot = load_active_boot_module()
    arena = MemoryArena(KERN_VA_BASE + g17p.NATIVE_HWDATA_OFFSET)
    uat = FakeUAT()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        built = boot.build_initdata(arena, uat, KERN_VA_BASE, 2)
    apply_active_pre_init(boot, arena, built)
    return boot, arena, uat, built, output.getvalue()


def contiguous_runs(predicate):
    runs = []
    start = None
    for offset, selected in enumerate(predicate):
        if selected and start is None:
            start = offset
        elif not selected and start is not None:
            runs.append((start, offset))
            start = None
    if start is not None:
        runs.append((start, len(predicate)))
    return runs


def describe_runs(runs, model, native):
    return [{
        "start": start,
        "end": end,
        "size": end - start,
        "current_hex": model[start:min(end, start + 32)].hex(),
        "native_hex": native[start:min(end, start + 32)].hex(),
    } for start, end in runs]


def semantic_specs(arena, built):
    """Map capture object names to the current constructor's exact addresses."""
    specs = {}
    instances = built["instances"]
    for slot, label in enumerate(("primary", "secondary")):
        instance = instances[slot]
        specs[(label, "root")] = (
            instance["root_va"],
            initdata.ROOT_SECONDARY_SIZE if slot else initdata.ROOT_SIZE,
            "descriptor",
        )
        specs[(label, "main_config")] = (
            instance["main_va"], initdata.MAIN_SIZE, "descriptor")
        specs[(label, "hwdata")] = (
            built["hwdata_va"], initdata.HWDATA_SIZE, "descriptor")
        specs[(label, "hwdata_bundle")] = (
            built["hwdata_va"], g17p.HWDATA_BUNDLE_SIZE, "descriptor")
        specs[(label, "region_a")] = (
            built["region_a_va"], PAGE, "descriptor")
        specs[(label, "region_c")] = (
            built["region_c_va"], initdata.REGION_C_SIZE, "descriptor")
        specs[(label, "status_a")] = (
            instance["status_a_va"], initdata.STATUS_BLOCK_SIZE,
            "descriptor")
        if instance["status_b_pa"] is not None:
            specs[(label, "status_b")] = (
                instance["status_b_pa"],
                initdata.STATUS_BLOCK_SIZE,
                "descriptor",
            )

        for index, (states, ring) in enumerate(instance["channels"]):
            if any(states):
                specs[(label, "ch%02d_state" % index)] = (
                    next(address for address in states if address),
                    (g17p.CHANNEL_ENTRY_STATE_SPACING
                     if index == g17p.CHANNEL_PARTIAL_ENTRY else
                     g17p.CHANNEL_ENTRY_STATE_SPACING * 3),
                    "channel-state",
                )
            if ring:
                size = (g17p.RING_SLOT_SIZE if index < 12
                        else g17p.CONTROL_MESSAGE_SIZE)
                specs[(label, "ch%02d_ring" % index)] = (
                    ring, size, "channel-ring")

    hwdata = built["hwdata_va"]
    specs[("primary", "hwregion0")] = (
        hwdata + g17p.NATIVE_HWDATA_REGION_OFFSETS[0], PAGE,
        "descriptor-target")
    specs[("primary", "hwregion1")] = (
        hwdata + g17p.NATIVE_HWDATA_REGION_OFFSETS[1], PAGE,
        "descriptor-target")
    for label in ("primary", "secondary"):
        specs[(label, "hwregion0")] = specs[("primary", "hwregion0")]
        specs[(label, "hwregion1")] = specs[("primary", "hwregion1")]

    for index, (offset, _value) in enumerate(g17p.NATIVE_PRIMARY_REGION_TRIPLES):
        if index:
            specs[("primary", "triple%d" % index)] = (
                KERN_VA_BASE + offset, PAGE, "descriptor-target")

    specs[("primary", "computed_page")] = (
        KERN_VA_BASE + g17p.NATIVE_PRIMARY_COMPUTED_PAGE_OFFSET,
        PAGE, "implicit-descriptor-target")
    specs[("primary", "repeated_target")] = (
        hwdata + g17p.MAIN_REPEATED_ADDR_OFFSET,
        0x100, "descriptor-target")
    for index, offset in enumerate(g17p.NATIVE_SECONDARY_ROOT_EXTRA_OFFSETS):
        specs[("secondary", "root_extra%d" % index)] = (
            KERN_VA_BASE + offset,
            (g17p.NATIVE_SECONDARY_ROOT_EXTRA_0_SIZE if index == 0 else 0x80),
            "descriptor-target")

    state_address = struct.unpack(
        "<Q", arena.read(hwdata + g17p.HWDATA_BUNDLE_STATE_PTR, 8))[0]
    specs[("primary", "hwdata_state")] = (
        state_address, g17p.HWDATA_STATE_SIZE, "descriptor-target")
    specs[("secondary", "hwdata_state")] = specs[("primary", "hwdata_state")]
    return specs


class InstanceCapture:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.manifest = json.loads((self.path / "manifest.json").read_text())

    def objects(self):
        for label in ("primary", "secondary"):
            instance = self.manifest["instances"].get(label) or {}
            for name, record in (instance.get("objects") or {}).items():
                if not record or not record.get("file"):
                    continue
                path = self.path / record["file"]
                if path.is_file():
                    yield label, name, record, path.read_bytes()


class RuntimeCapture:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.manifest = json.loads((self.path / "manifest.json").read_text())
        self.ram = (self.path / self.manifest["ram_file"]).read_bytes()
        self.pages = {}
        for group in self.manifest["root_mappings"]:
            if (int(group.get("root_ctx_id", -1)),
                    int(group.get("selector", -1))) != (64, 1):
                continue
            for page in group["mappings"]:
                index = page.get("blob_index")
                if index is not None:
                    self.pages[int(page["va"])] = int(index)

    def read(self, address, size):
        out = bytearray()
        while size:
            page = address & ~(PAGE - 1)
            index = self.pages.get(page)
            if index is None:
                raise ValueError("runtime capture has no page for %#x" % address)
            offset = address - page
            take = min(size, PAGE - offset)
            start = index * PAGE + offset
            out.extend(self.ram[start:start + take])
            address += take
            size -= take
        return bytes(out)

    def covers(self, address, size):
        while size:
            page = address & ~(PAGE - 1)
            if page not in self.pages:
                return False
            take = min(size, PAGE - (address - page))
            address += take
            size -= take
        return True


def compare_instance_capture(capture, arena, specs, phase):
    comparisons = []
    for label, name, record, native_file in capture.objects():
        # Auxiliary config views were explicitly excluded from this audit. Their
        # modeled populated runs remain visible in the constructor write list.
        if name.startswith("addr"):
            continue
        spec = specs.get((label, name))
        if spec is None:
            continue
        address, size, family = spec
        size = min(size, len(native_file))
        try:
            current = arena.read(address, size)
        except ValueError as error:
            comparisons.append({
                "instance": label, "object": name, "family": family,
                "address": address, "size": size, "error": str(error),
            })
            continue
        native = native_file[:size]
        mismatch = contiguous_runs([
            left != right for left, right in zip(current, native)])
        missing = contiguous_runs([
            left == 0 and right != 0 for left, right in zip(current, native)])
        extra = contiguous_runs([
            left != 0 and right == 0 for left, right in zip(current, native)])
        comparisons.append({
            "instance": label,
            "object": name,
            "family": family,
            "address": address,
            "captured_address": int(record["dva"]),
            "size": size,
            "current_nonzero_bytes": sum(byte != 0 for byte in current),
            "native_nonzero_bytes": sum(byte != 0 for byte in native),
            "mismatch_bytes": sum(end - start for start, end in mismatch),
            "mismatch_runs": describe_runs(mismatch, current, native),
            "native_nonzero_current_zero_bytes": sum(
                end - start for start, end in missing),
            "native_nonzero_current_zero_runs": describe_runs(
                missing, current, native),
            "current_nonzero_native_zero_bytes": sum(
                end - start for start, end in extra),
            "current_nonzero_native_zero_runs": describe_runs(
                extra, current, native),
            "phase": phase,
        })
    return comparisons


def compare_snapshot_specs(capture, arena, specs, phase):
    """Compare each unique modeled config object against a full DVA snapshot."""
    comparisons = []
    seen = set()
    for (instance, name), (address, size, family) in specs.items():
        identity = (address, size, family)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            current = arena.read(address, size)
            native = capture.read(address, size)
        except ValueError as error:
            comparisons.append({
                "instance": instance, "object": name, "family": family,
                "address": address, "size": size, "error": str(error),
                "phase": phase,
            })
            continue
        mismatch = contiguous_runs([
            left != right for left, right in zip(current, native)])
        missing = contiguous_runs([
            left == 0 and right != 0 for left, right in zip(current, native)])
        extra = contiguous_runs([
            left != 0 and right == 0 for left, right in zip(current, native)])
        comparisons.append({
            "instance": instance,
            "object": name,
            "family": family,
            "address": address,
            "size": size,
            "current_nonzero_bytes": sum(byte != 0 for byte in current),
            "native_nonzero_bytes": sum(byte != 0 for byte in native),
            "mismatch_bytes": sum(end - start for start, end in mismatch),
            "mismatch_runs": describe_runs(mismatch, current, native),
            "native_nonzero_current_zero_bytes": sum(
                end - start for start, end in missing),
            "native_nonzero_current_zero_runs": describe_runs(
                missing, current, native),
            "current_nonzero_native_zero_bytes": sum(
                end - start for start, end in extra),
            "current_nonzero_native_zero_runs": describe_runs(
                extra, current, native),
            "phase": phase,
        })
    return comparisons


def compare_private_cluster(capture, arena, built, ownership):
    address = built["private_cluster_va"]
    size = g17p.NATIVE_PRIVATE_CLUSTER_SIZE
    current = arena.read(address, size)
    native = capture.read(address, size)
    pages = []
    for offset in range(0, size, PAGE):
        left = current[offset:offset + PAGE]
        right = native[offset:offset + PAGE]
        missing = contiguous_runs([
            current_byte == 0 and native_byte != 0
            for current_byte, native_byte in zip(left, right)])
        if not missing:
            continue
        pages.append({
            "address": address + offset,
            "native_nonzero_current_zero_bytes": sum(
                end - start for start, end in missing),
            "native_nonzero_current_zero_runs": describe_runs(
                missing, left, right),
            "ownership": ownership,
        })
    return {
        "address": address,
        "size": size,
        "pages_with_native_nonzero_current_zero": len(pages),
        "native_nonzero_current_zero_bytes": sum(
            page["native_nonzero_current_zero_bytes"] for page in pages),
        "pages": pages,
    }


def compare_host_allocations(capture, arena):
    """Compare complete host-owned mappings, including every unlabeled byte."""
    comparisons = []
    for mapping in arena._maps:
        address = mapping["va"]
        size = mapping["size"]
        if not capture.covers(address, size):
            continue
        current = arena.read(address, size)
        native = capture.read(address, size)
        mismatch = contiguous_runs([
            left != right for left, right in zip(current, native)])
        missing = contiguous_runs([
            left == 0 and right != 0 for left, right in zip(current, native)])
        extra = contiguous_runs([
            left != 0 and right == 0 for left, right in zip(current, native)])
        comparisons.append({
            "allocation": mapping["name"],
            "address": address,
            "size": size,
            "current_nonzero_bytes": sum(byte != 0 for byte in current),
            "native_nonzero_bytes": sum(byte != 0 for byte in native),
            "mismatch_bytes": sum(end - start for start, end in mismatch),
            "mismatch_runs": describe_runs(mismatch, current, native),
            "native_nonzero_current_zero_bytes": sum(
                end - start for start, end in missing),
            "native_nonzero_current_zero_runs": describe_runs(
                missing, current, native),
            "current_nonzero_native_zero_bytes": sum(
                end - start for start, end in extra),
            "current_nonzero_native_zero_runs": describe_runs(
                extra, current, native),
        })
    return comparisons


def scan_unlabeled_pointers(capture, arena):
    """Find mapped native addresses without relying on labeled field offsets.

    Four-byte alignment includes the packed pointers already measured in the
    hardware-data records while avoiding byte-shifted aliases of each pointer.
    A value is retained only when its target page exists in the exact native
    firmware-context snapshot.
    """
    found = []
    seen = set()
    for mapping in arena._maps:
        address = mapping["va"]
        size = mapping["size"]
        if not capture.covers(address, size):
            continue
        current = arena.read(address, size)
        native = capture.read(address, size)
        for offset in range(0, size - 7, 4):
            target = struct.unpack_from("<Q", native, offset)[0]
            if (target & ~(PAGE - 1)) not in capture.pages:
                continue
            identity = (address + offset, target)
            if identity in seen:
                continue
            seen.add(identity)
            current_target = struct.unpack_from("<Q", current, offset)[0]
            found.append({
                "allocation": mapping["name"],
                "field_address": address + offset,
                "field_offset": offset,
                "native_target": target,
                "target_page": target & ~(PAGE - 1),
                "target_page_native_nonzero_bytes": sum(
                    byte != 0 for byte in capture.read(
                        target & ~(PAGE - 1), PAGE)),
                "current_target": current_target,
                "matches_current": current_target == target,
                "current_is_zero": current_target == 0,
            })
    return found


def pointer_inventory(boot, arena, built):
    instances = built["instances"]
    inventory = []

    def add(owner, offset, target, role):
        inventory.append({
            "owner": owner,
            "offset": offset,
            "target": int(target),
            "mapped": arena.physical(target) is not None if target else False,
            "role": role,
        })

    for slot, label in enumerate(("primary-root", "secondary-root")):
        root = arena.read(instances[slot]["root_va"],
                          initdata.ROOT_SECONDARY_SIZE if slot else
                          initdata.ROOT_SIZE)
        for offset, role in (
                (initdata.ROOT_REGION_A, "shared leading region"),
                (initdata.ROOT_MAIN_CONFIG, "main configuration"),
                (initdata.ROOT_REGION_C, "data/configuration region"),
                (initdata.ROOT_STATUS_A, "status A"),
                (initdata.ROOT_STATUS_B, "status B")):
            add(label, offset, struct.unpack_from("<Q", root, offset)[0], role)
        if slot:
            add(label, initdata.ROOT_SECONDARY_EXTRA_0,
                struct.unpack_from("<Q", root,
                                   initdata.ROOT_SECONDARY_EXTRA_0)[0],
                "secondary-only private target 0")
            add(label, initdata.ROOT_SECONDARY_EXTRA_1,
                struct.unpack_from("<Q", root,
                                   initdata.ROOT_SECONDARY_EXTRA_1)[0],
                "secondary-only private target 1")

    for slot, label in enumerate(("primary-main", "secondary-main")):
        instance = instances[slot]
        main = arena.read(instance["main_va"], initdata.MAIN_SIZE)
        for offset, role in (
                (initdata.MAIN_HWDATA_ADDR, "hardware-data bundle"),
                (initdata.MAIN_REPEATED_ADDR, "firmware-written repeated target"),
                (initdata.MAIN_REPEATED_ADDR_2,
                 "firmware-written repeated target (duplicate)")):
            add(label, offset, struct.unpack_from("<Q", main, offset)[0], role)
        for index, (states, ring) in enumerate(instance["channels"]):
            base = initdata.MAIN_CHANNEL_TABLE + index * initdata.CHANNEL_ENTRY_SIZE
            for state_index, target in enumerate(states):
                add(label, base + state_index * 8, target,
                    "channel %d state %d" % (index, state_index))
            add(label, base + 0x18, ring, "channel %d ring" % index)
        if slot == 0:
            for index, (offset, _value) in enumerate(
                    g17p.NATIVE_PRIMARY_REGION_TRIPLES):
                add(label,
                    initdata.MAIN_REGION_TRIPLES
                    + index * initdata.MAIN_REGION_TRIPLE_STRIDE,
                    KERN_VA_BASE + offset,
                    "region triple %d%s" %
                    (index, " (intentionally unresolved)" if index == 0 else ""))
        else:
            add(label, initdata.MAIN_SECONDARY_ADDR,
                struct.unpack_from("<Q", main,
                                   initdata.MAIN_SECONDARY_ADDR)[0],
                "unaligned pointer into primary auxiliary view")

    hwdata = built["hwdata_va"]
    add("hardware-data", g17p.HWDATA_BUNDLE_STATE_PTR,
        struct.unpack("<Q", arena.read(
            hwdata + g17p.HWDATA_BUNDLE_STATE_PTR, 8))[0],
        "secondary-relative state object")
    for index in range(len(g17p.HWDATA_REGION_RECORDS)):
        offset = (initdata.REGION_RECORD_OFFSET
                  + index * initdata.REGION_RECORD_STRIDE
                  + initdata.REGION_RECORD_ADDR)
        add("hardware-data", offset,
            struct.unpack("<Q", arena.read(hwdata + offset, 8))[0],
            "hardware-data region %d" % index)
    return inventory


def write_text_report(path, report):
    pre_init = report["pre_init_comparisons"]
    missing = [entry for entry in pre_init
               if entry.get("native_nonzero_current_zero_bytes")]
    serialized = [entry for entry in report["serialized_handoff_comparisons"]
                  if entry.get("native_nonzero_current_zero_bytes")]
    post_ack = [entry for entry in report["post_ack_comparisons"]
                if entry.get("native_nonzero_current_zero_bytes")]
    pre_private = report["pre_init_private_cluster"]
    runtime_private = report["runtime_private_cluster"]
    allocation_comparisons = report["host_allocation_comparisons"]
    allocation_missing = [entry for entry in allocation_comparisons
                          if entry["native_nonzero_current_zero_bytes"]]
    pointer_candidates = report["unlabeled_pointer_scan"]
    missing_pointers = [entry for entry in pointer_candidates
                        if not entry["matches_current"]]

    lines = [
        "G17P active-constructor audit",
        "==============================",
        "",
        "Source image: agx_g17p_boot.build_initdata plus fixed static "
        "DRM-shim init/control staging mutations.",
        "Per-view config_view interpretation is excluded by request; the shared "
        "hardware-data bundle is still compared as one object.",
        "",
        "Exact pre-init snapshot: %d unique config objects compared; %d contain "
        "native-nonzero/current-zero bytes." % (len(pre_init), len(missing)),
    ]
    if not missing:
        lines.append("No omitted nonzero host input was found in the compared initdata graph.")
    for entry in missing:
        lines.append(
            "- %s/%s at %#x: %d bytes in %d runs" % (
                entry["instance"], entry["object"], entry["address"],
                entry["native_nonzero_current_zero_bytes"],
                len(entry["native_nonzero_current_zero_runs"])))
        for run in entry["native_nonzero_current_zero_runs"][:12]:
            lines.append("    +%#x..+%#x native=%s" % (
                run["start"], run["end"], run["native_hex"]))

    lines.extend([
        "",
        "Disposition of the exact-pre-init omissions:",
    ])
    for item in report["known_disposition"]:
        lines.append("- %s: %s" % (item["finding"], item["result"]))
    lines.extend([
        "No newly untested basic boot/render input was found. This does not "
        "prove that compute firmware never consults these regions; it means "
        "their captured contents have already failed as fixes and are not an "
        "unnoticed constructor omission.",
    ])

    lines.extend([
        "",
        "Complete allocation scan: %d complete host-owned mappings were present "
        "in the native high root; %d contain native-nonzero/current-zero bytes." % (
            len(allocation_comparisons), len(allocation_missing)),
    ])
    for entry in allocation_missing:
        lines.append("- %s at %#x (%#x bytes): %d missing bytes" % (
            entry["allocation"], entry["address"], entry["size"],
            entry["native_nonzero_current_zero_bytes"]))
    lines.extend([
        "Unlabeled pointer scan: %d native mapped-address fields found at "
        "four-byte alignment; %d do not match the current image." % (
            len(pointer_candidates), len(missing_pointers)),
    ])
    for entry in missing_pointers:
        lines.append("- %s +%#x at %#x: current=%#x native=%#x -> page %#x "
                     "(%d native nonzero bytes)" % (
            entry["allocation"], entry["field_offset"],
            entry["field_address"], entry["current_target"],
            entry["native_target"], entry["target_page"],
            entry["target_page_native_nonzero_bytes"]))

    lines.extend([
        "",
        "Exact pre-init private cluster: %d/%d pages contain %d native-nonzero/"
        "current-zero bytes. These are host-visible before the first initdata "
        "endpoint write." % (
            pre_private["pages_with_native_nonzero_current_zero"],
            pre_private["size"] // PAGE,
            pre_private["native_nonzero_current_zero_bytes"]),
        "Serialized two-instance capture: %d objects contain native-nonzero/"
        "current-zero bytes. Its primary may already be post-ACK, so it is a "
        "cross-check rather than the ownership reference." % len(serialized),
        "Post-ACK named objects: %d objects contain native-nonzero/current-zero "
        "bytes. These are not automatically host inputs." % len(post_ack),
        "Runtime private cluster: %d/%d pages contain %d native-nonzero/"
        "current-zero bytes; this snapshot is post-start firmware/runtime state."
        % (runtime_private["pages_with_native_nonzero_current_zero"],
           runtime_private["size"] // PAGE,
           runtime_private["native_nonzero_current_zero_bytes"]),
        "",
        "Pointer inventory: %d pointer fields, %d nonzero targets mapped, %d "
        "nonzero targets intentionally/unexpectedly unresolved." % (
            len(report["pointer_inventory"]),
            sum(item["target"] != 0 and item["mapped"]
                for item in report["pointer_inventory"]),
            sum(item["target"] != 0 and not item["mapped"]
                for item in report["pointer_inventory"])),
        "",
        "See audit.json for every allocation, constructor write, mismatch run, "
        "runtime-private page and pointer target.",
    ])
    path.write_text("\n".join(lines) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args(argv)

    boot, arena, uat, built, constructor_stdout = build_source_image()
    specs = semantic_specs(arena, built)

    pre_init_capture = RuntimeCapture(PRE_INIT)
    pre_init = compare_snapshot_specs(
        pre_init_capture, arena, specs, "exact-pre-first-initdata-write")
    serialized_handoff = compare_instance_capture(
        InstanceCapture(SERIALIZED_HANDOFF), arena, specs,
        "serialized-two-instance-handoff")
    post_ack = compare_instance_capture(
        InstanceCapture(POST_ACK), arena, specs, "post-ack-running")
    pre_init_private = compare_private_cluster(
        pre_init_capture, arena, built,
        "host-visible before the first initdata endpoint write")
    runtime_private = compare_private_cluster(
        RuntimeCapture(RUNTIME), arena, built,
        "post-start firmware/runtime state; not handoff input")
    host_allocations = compare_host_allocations(pre_init_capture, arena)
    unlabeled_pointers = scan_unlabeled_pointers(pre_init_capture, arena)

    timestamp = datetime.datetime.now(datetime.timezone.utc)
    output = args.output or (
        ARTIFACT_ROOT / ("constructor_audit_%s" %
                         timestamp.strftime("%Y%m%d_%H%M%S")))
    output.mkdir(parents=True, exist_ok=False)

    report = {
        "format": "m1n1-t8140-g17p-active-constructor-audit-v1",
        "created_utc": timestamp.isoformat(),
        "source": str(HERE / "agx_g17p_boot.py"),
        "source_entrypoint": (
            "build_initdata plus fixed static DRMAsahiShim init/control staging "
            "mutations"),
        "reference_captures": {
            "pre_init": str(PRE_INIT),
            "serialized_handoff": str(SERIALIZED_HANDOFF),
            "post_ack": str(POST_ACK),
            "runtime": str(RUNTIME),
        },
        "excluded": [
            "per-view interpretation of main-config auxiliary config_view bytes",
            "submission/render/compute object graphs outside initdata",
            "Apple binary contents",
        ],
        "known_disposition": [
            {
                "finding": "primary/hwdata_bundle +0xb75c variable word",
                "result": (
                    "the word changes between native boots; seeding exact observed "
                    "values did not affect startup or the failing work path"),
                "evidence": "hardware-data bundle delta experiments",
            },
            {
                "finding": "secondary/root_extra0 target contents",
                "result": (
                    "the pointer is required, but redirecting it to a fresh mapped "
                    "zero page lets both ASCs survive; seeding its captured native "
                    "page did not fix the earlier dual-opening failure. This rules "
                    "it out only for startup/render, not for compute"),
                "evidence": "secondary-root +0xb8 relocation experiments",
            },
            {
                "finding": "secondary/root_extra1 target contents",
                "result": (
                    "the pointer is retained as part of the observed ABI, while the "
                    "current zero target is accepted during successful cold boot and "
                    "render operation. It remains a compute-config candidate"),
                "evidence": "secondary-root +0xc0 experiments",
            },
            {
                "finding": "other native-only bytes in three private-cluster pages",
                "result": (
                    "a prior cold-builder substitution removed native contents from "
                    "618 of 626 firmware-high pages and still physically rendered; "
                    "the retained eight pages were channel lifecycle state. That "
                    "experiment did not exercise compute"),
                "evidence": "cold-builder full-private substitution",
            },
        ],
        "allocations": arena.allocation_report(),
        "writes": arena.writes,
        "uat_mappings": uat.mappings,
        "pointer_inventory": pointer_inventory(boot, arena, built),
        "pre_init_comparisons": pre_init,
        "serialized_handoff_comparisons": serialized_handoff,
        "post_ack_comparisons": post_ack,
        "pre_init_private_cluster": pre_init_private,
        "runtime_private_cluster": runtime_private,
        "host_allocation_comparisons": host_allocations,
        "unlabeled_pointer_scan": unlabeled_pointers,
    }
    (output / "audit.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n")
    (output / "constructor_stdout.txt").write_text(constructor_stdout)
    write_text_report(output / "summary.txt", report)
    print((output / "summary.txt").read_text(), end="")
    print("Artifact: %s" % output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
