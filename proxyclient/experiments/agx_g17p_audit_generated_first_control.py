#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture source-built state at the native pre-first-control boundary."""

import datetime
import hashlib
import json
import pathlib
import struct
import tempfile

from agx_g17p_compute_relocated_control import install_relocated_boot_module


PAGE = 0x4000
ARTIFACTS = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")
REFERENCE = ARTIFACTS / "native_first_control_preconsume_20260812_022644"
OUTPUT_PREFIX = "generated_first_control_audit"
BOUNDARY = "after both initdata acknowledgements, before control-start 0x89"
ROOTS = (
    ((0, 0), 0, "context-0-low"),
    ((1, 0), 1, "context-1-low"),
    ((64, 1), 1, "firmware-high"),
)
PTE_ATTRIBUTE_MASK = (
    (1 << 0) | (1 << 1) | (0x7 << 2) | (0x3 << 6) |
    (0x3 << 8) | (1 << 10) | (1 << 11) |
    (1 << 53) | (1 << 54) | (1 << 55)
)
FIXED_REGION_NAMES = {
    "gpu-region",
    "gfx-shared-region",
    "gfx-shared-l2-region",
    "gfx-handoff",
}


class AuditComplete(RuntimeError):
    pass


def _difference_runs(current, native):
    runs = []
    start = None
    for offset, (ours, theirs) in enumerate(zip(current, native)):
        different = ours != theirs
        if different and start is None:
            start = offset
        elif not different and start is not None:
            runs.append([start, offset - start])
            start = None
    if start is not None:
        runs.append([start, len(current) - start])
    return runs


def _names_for_page(arena, address):
    names = []
    page_end = address + PAGE
    for record in arena.entries:
        start = int(record["va"])
        end = start + int(record["size"])
        if start < page_end and address < end and record["name"] not in names:
            names.append(record["name"])
    return names


def _read_current_pages(module, rows):
    mapped = [row for row in rows if row["current_pa"] is not None]
    index = 0
    while index < len(mapped):
        run = [mapped[index]]
        while index + len(run) < len(mapped):
            previous = run[-1]
            candidate = mapped[index + len(run)]
            if candidate["root"] != previous["root"]:
                break
            if candidate["address"] != previous["address"] + PAGE:
                break
            if candidate["current_pa"] != previous["current_pa"] + PAGE:
                break
            if len(run) >= 0x100000 // PAGE:
                break
            run.append(candidate)
        base = run[0]["current_pa"]
        size = len(run) * PAGE
        module.p.dc_civac(base, size)
        body = bytes(module.iface.readmem(base, size))
        for page_index, row in enumerate(run):
            row["current_body"] = body[page_index * PAGE:(page_index + 1) * PAGE]
        index += len(run)


def _mapping_inventory(uat, slot):
    pages = {}

    def visit(start, end, _index, pte, _level, sparse=False):
        del sparse
        address = start & ~(PAGE - 1)
        physical = int(pte.offset())
        while address <= end:
            pages[address] = (physical, int(pte))
            address += PAGE
            physical += PAGE

    uat.foreach_page(slot, visit)
    return pages


def _capture_fixed_regions(module, native, output):
    records = []
    for reference in native.manifest["fixed_regions"]:
        name = reference["name"]
        if name not in FIXED_REGION_NAMES:
            continue
        pa = int(reference["pa"])
        size = int(reference["size"])
        native_body = (native.path / reference["file"]).read_bytes()
        if len(native_body) != size:
            raise RuntimeError("short native fixed region %s" % name)
        module.p.dc_civac(pa, size)
        current = bytes(module.iface.readmem(pa, size))
        filename = "current_fixed_%s.bin" % name.replace("-", "_")
        (output / filename).write_bytes(current)
        records.append({
            "name": name,
            "pa": pa,
            "size": size,
            "current_file": filename,
            "native_file": reference["file"],
            "current_sha256": hashlib.sha256(current).hexdigest(),
            "native_sha256": hashlib.sha256(native_body).hexdigest(),
            "current_nonzero": sum(byte != 0 for byte in current),
            "native_nonzero": sum(byte != 0 for byte in native_body),
            "changed_bytes": sum(a != b for a, b in zip(current, native_body)),
            "native_nonzero_current_zero": sum(
                theirs != 0 and ours == 0
                for ours, theirs in zip(current, native_body)),
            "current_nonzero_native_zero": sum(
                ours != 0 and theirs == 0
                for ours, theirs in zip(current, native_body)),
            "different_nonzero": sum(
                ours != 0 and theirs != 0 and ours != theirs
                for ours, theirs in zip(current, native_body)),
            "runs": _difference_runs(current, native_body),
        })
    return records


def capture_boundary(module, state):
    from agx_g17p_audit_native_compute_graph import Snapshot

    native = Snapshot(REFERENCE)
    uat = state["uat"]
    arena = state["arena"]
    uat.invalidate_cache()

    mappings = {
        slot: _mapping_inventory(uat, slot)
        for slot in sorted({slot for _root, slot, _label in ROOTS})
    }
    rows = []
    for root, slot, label in ROOTS:
        for address, mapping in sorted(native.roots[root].items()):
            current_mapping = mappings[slot].get(int(address))
            current_pa = (None if current_mapping is None
                          else current_mapping[0])
            current_pte = (None if current_mapping is None
                           else current_mapping[1])
            rows.append({
                "root": "%d:%d" % root,
                "root_context": root[0],
                "root_selector": root[1],
                "root_label": label,
                "slot": slot,
                "address": int(address),
                "native_pa": int(mapping["pa"]),
                "native_pte": int(mapping["pte"]),
                "native_blob": int(mapping["blob_index"]),
                "current_pa": current_pa,
                "current_pte": current_pte,
                "names": _names_for_page(arena, int(address)),
            })

    _read_current_pages(module, rows)
    current_blob = bytearray()
    differences = []
    exact = missing_mapping = attribute_mismatch = 0
    for blob_index, row in enumerate(rows):
        current = row.pop("current_body", bytes(PAGE))
        native_offset = row["native_blob"] * PAGE
        native_body = native.ram[native_offset:native_offset + PAGE]
        row["current_blob"] = blob_index
        row["current_sha256"] = hashlib.sha256(current).hexdigest()
        row["native_sha256"] = hashlib.sha256(native_body).hexdigest()
        current_blob.extend(current)

        if row["current_pa"] is None:
            missing_mapping += 1
        elif ((row["current_pte"] ^ row["native_pte"])
              & PTE_ATTRIBUTE_MASK):
            attribute_mismatch += 1

        changed = sum(a != b for a, b in zip(current, native_body))
        if not changed and row["current_pa"] is not None:
            exact += 1
        if changed or row["current_pa"] is None or (
                row["current_pte"] is not None and
                ((row["current_pte"] ^ row["native_pte"])
                 & PTE_ATTRIBUTE_MASK)):
            differences.append({
                "root": row["root"],
                "root_label": row["root_label"],
                "address": row["address"],
                "names": row["names"],
                "missing_mapping": row["current_pa"] is None,
                "current_pa": row["current_pa"],
                "native_pa": row["native_pa"],
                "current_attributes": (
                    None if row["current_pte"] is None else
                    row["current_pte"] & PTE_ATTRIBUTE_MASK),
                "native_attributes": row["native_pte"] & PTE_ATTRIBUTE_MASK,
                "changed_bytes": changed,
                "native_nonzero_current_zero": sum(
                    theirs != 0 and ours == 0
                    for ours, theirs in zip(current, native_body)),
                "current_nonzero_native_zero": sum(
                    ours != 0 and theirs == 0
                    for ours, theirs in zip(current, native_body)),
                "different_nonzero": sum(
                    ours != 0 and theirs != 0 and ours != theirs
                    for ours, theirs in zip(current, native_body)),
                "runs": _difference_runs(current, native_body),
            })

    native_aliases = {}
    current_aliases = {}
    for row in rows:
        identity = [row["root"], row["address"]]
        native_aliases.setdefault(row["native_pa"], []).append(identity)
        if row["current_pa"] is not None:
            current_aliases.setdefault(row["current_pa"], []).append(identity)

    native_alias_mismatches = []
    for native_pa, identities in native_aliases.items():
        if len(identities) < 2:
            continue
        selected = [row for row in rows
                    if [row["root"], row["address"]] in identities]
        current_pas = sorted({row["current_pa"] for row in selected
                              if row["current_pa"] is not None})
        missing = any(row["current_pa"] is None for row in selected)
        if len(current_pas) != 1 or missing:
            native_alias_mismatches.append({
                "native_pa": native_pa,
                "members": identities,
                "current_pas": current_pas,
                "missing_current_mapping": missing,
            })

    current_overaliases = []
    for current_pa, identities in current_aliases.items():
        if len(identities) < 2:
            continue
        selected = [row for row in rows
                    if [row["root"], row["address"]] in identities]
        native_pas = sorted({row["native_pa"] for row in selected})
        if len(native_pas) != 1:
            current_overaliases.append({
                "current_pa": current_pa,
                "members": identities,
                "native_pas": native_pas,
            })

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output = ARTIFACTS / ("%s_%s" % (OUTPUT_PREFIX, stamp))
    output.mkdir(parents=True)
    (output / "current_pages.bin").write_bytes(current_blob)
    fixed_regions = _capture_fixed_regions(module, native, output)
    summary = {
        "format": "m1n1-g17p-generated-boundary-audit-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "boundary": BOUNDARY,
        "reference": str(REFERENCE),
        "page_size": PAGE,
        "page_count": len(rows),
        "exact_content_pages": exact,
        "missing_current_mappings": missing_mapping,
        "attribute_mismatch_pages": attribute_mismatch,
        "different_pages": len(differences),
        "native_alias_mismatches": native_alias_mismatches,
        "current_overaliases": current_overaliases,
        "fixed_regions": fixed_regions,
        "pages": rows,
    }
    (output / "manifest.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output / "differences.json").write_text(json.dumps({
        "format": "m1n1-g17p-generated-boundary-differences-v1",
        "reference": str(REFERENCE),
        "current_manifest": str(output / "manifest.json"),
        "pages": sorted(
            differences,
            key=lambda item: (
                -item["native_nonzero_current_zero"],
                -item["changed_bytes"],
                item["root"], item["address"])),
    }, indent=2, sort_keys=True) + "\n")

    print("GENERATED PRE-CONTROL AUDIT: %s" % output, flush=True)
    print(
        "  %d pages: %d exact, %d different, %d missing mappings, "
        "%d attribute mismatches" % (
            len(rows), exact, len(differences), missing_mapping,
            attribute_mismatch),
        flush=True,
    )
    print(
        "  alias differences: %d native aliases split, %d extra current aliases" % (
            len(native_alias_mismatches), len(current_overaliases)),
        flush=True,
    )
    print("  fixed carveouts:", flush=True)
    for record in fixed_regions:
        print(
            "    %-22s changed=%-6d missing-nz=%-6d current-nz=%-6d native-nz=%-6d" % (
                record["name"], record["changed_bytes"],
                record["native_nonzero_current_zero"],
                record["current_nonzero"], record["native_nonzero"]),
            flush=True,
        )
    for item in sorted(
            differences,
            key=lambda value: (
                -value["native_nonzero_current_zero"],
                -value["changed_bytes"]))[:24]:
        print(
            "  %-14s %#014x missing-nz=%-5d changed=%-5d names=%s" % (
                item["root_label"], item["address"],
                item["native_nonzero_current_zero"], item["changed_bytes"],
                ",".join(item["names"]) or "-"),
            flush=True,
        )
    raise AuditComplete(str(output))


def main():
    module = install_relocated_boot_module()

    def audit_root(label, uat):
        entries = [int(module.p.read64(uat.ttbr1_base + 8 * index))
                   for index in range(3)]
        print(
            "PRE-INIT ROOT %s: %s" % (
                label, ", ".join("[%d]=%#x" % pair
                                 for pair in enumerate(entries))),
            flush=True,
        )

    module.FINAL_26_6_PRE_INIT_REGISTER_AUDIT = audit_root
    module.FINAL_26_6_PRE_CONTROL_AUDIT = (
        lambda state: capture_boundary(module, state))

    from m1n1.agx.shim import DRMAsahiShim

    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        try:
            front.init()
        except AuditComplete as result:
            print("AUDIT COMPLETE: %s" % result, flush=True)
            return 0
    raise RuntimeError("pre-control audit callback was not reached")


if __name__ == "__main__":
    raise SystemExit(main())
