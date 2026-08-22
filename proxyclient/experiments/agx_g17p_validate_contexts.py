#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the per-context facts this record depends on, against a capture, without hardware.

Four findings cost this project a great deal to establish and are easy to regress, because each looks
like an ordinary aliasing assumption until it is measured:

  * an address mapped in several contexts need not name the same object
  * each work descriptor's low alias is the descriptor itself in context 0 and something unrelated
    in the render context, and the same holds for the two context and queue pages
  * intermediate translation descriptors carry VALID and TYPE only, so a host that writes just those
    is correct and the extra bits belong to leaves
  * a host fills the operand table completely, twenty-two entries on a regular stride, where a
    pre-work snapshot shows it empty

Run with a snapshot directory, or with none to take the newest `pre_work_*`.
"""

import json
import pathlib
import struct
import sys

PAGE = 0x4000
CAPTURES = pathlib.Path("/Users/user/asahi_re/artifacts/agx_g17p")

# The values agx_g17p_boot.py builds from. Kept here as literals deliberately: a gate that imports
# them from the path it is checking cannot catch a change to them.
DESCRIPTORS = {"tiling": (0xfffffc20c0018000, 0x7000000000),
               "fragment": (0xfffffc20c00b0000, 0x7000098000)}
CONTEXT_QUEUE = {"tiling": (0xfffffc20001d8000, 0x7000438000),
                 "fragment": (0xfffffc2000200000, 0x7000460000)}
OPERAND_TABLE = 0x7000208000
OPERAND_BASE = 0x7000220000
OPERAND_STRIDE = 0x108000
OPERAND_COUNT = 22
OPERAND_ENTRY_STRIDE = 0x40
CONTEXT_ZERO = 0
PRIVATE_ZERO_PAGE = 0x2ffffff8000
RENDER_ROOTS = (7, 8, 9, 10)
ADDR_MASK = 0x0000FFFFFFFFC000


def load(snapshot):
    manifest = json.loads((snapshot / "manifest.json").read_text())
    ram = (snapshot / manifest["ram_file"]).read_bytes()
    per_root = {}
    for group in manifest["root_mappings"]:
        index = int(group["root_index"])
        for mapping in group["mappings"]:
            if mapping.get("blob_index") is None:
                continue
            per_root.setdefault(index, {})[int(mapping["va"])] = (
                int(mapping["blob_index"]), int(mapping["pa"]) & ~(PAGE - 1))
    return manifest, ram, per_root


def check_aliases(label, pairs, per_root, failures):
    """Each low alias is its firmware counterpart in context 0 and not in the render context."""
    for kind, (high, low) in pairs.items():
        owner = next((table for index, table in per_root.items() if high in table), None)
        if owner is None:
            failures.append("%s %s: no captured page at %#x" % (label, kind, high))
            continue
        want = owner[high][1]
        zero = per_root.get(CONTEXT_ZERO, {}).get(low)
        if zero is None:
            failures.append("%s %s: context 0 does not map %#x" % (label, kind, low))
        elif zero[1] != want:
            failures.append(
                "%s %s: context 0's %#x is pa %#x, not the object's %#x"
                % (label, kind, low, zero[1], want))
        else:
            print("  %-9s %-8s context 0's %#x is the same page as %#x"
                  % (label, kind, low, high))
        for index in RENDER_ROOTS:
            other = per_root.get(index, {}).get(low)
            if other is None:
                continue
            if other[1] == want:
                failures.append(
                    "%s %s: root %d's %#x is the same page as %#x, so the contexts do "
                    "not differ there and this check has lost its meaning"
                    % (label, kind, index, low, high))
            else:
                print("  %-9s %-8s root %-2d's %#x is a different page, as expected"
                      % (label, kind, index, low))


def check_table_descriptors(manifest, snapshot, per_root, failures):
    """Every intermediate descriptor carries VALID and TYPE and nothing else."""
    tables = (snapshot / manifest["tables_file"]).read_bytes()
    by_pa = {int(pa): i for i, pa in enumerate(manifest["table_pages"])}
    levels = ((36, 8), (25, 2048))
    checked = 0
    for group in manifest["root_mappings"]:
        root_pa = int(group.get("root_pa") or 0)
        index = int(group["root_index"])
        mapped = sorted(int(mp["va"]) for mp in group["mappings"]
                        if mp.get("blob_index") is not None)
        if not root_pa or not mapped:
            continue
        table = root_pa
        for shift, count in levels:
            page = by_pa.get(table & ~(PAGE - 1))
            if page is None:
                break
            body = tables[page * PAGE:(page + 1) * PAGE]
            entry = struct.unpack_from(
                "<Q", body, ((mapped[0] >> shift) & (count - 1)) * 8)[0]
            if not entry & 1:
                break
            extra = entry & ~ADDR_MASK & ~0x3
            if extra:
                failures.append(
                    "root %d level shift %d: descriptor %#x carries %#x beyond VALID and TYPE"
                    % (index, shift, entry, extra))
            checked += 1
            table = entry & ADDR_MASK
    print("  %d intermediate descriptors carry VALID and TYPE only" % checked)


def check_operand_table(ram, per_root, failures):
    """A pre-work snapshot has the table empty; the entries a host writes are regular."""
    entry = next((table.get(OPERAND_TABLE) for table in per_root.values()
                  if OPERAND_TABLE in table), None)
    if entry is None:
        failures.append("no captured page for the operand table at %#x" % OPERAND_TABLE)
        return
    body = ram[entry[0] * PAGE:(entry[0] + 1) * PAGE]
    if any(body):
        failures.append(
            "the operand table is not empty in this snapshot, so it is not a pre-work "
            "capture and the reading that a host fills it needs rechecking")
    else:
        print("  the operand table is empty before first work, as expected")
    # The buffers a host names must be inside the low alias region the render context carries.
    render = per_root.get(7, {})
    missing = [OPERAND_BASE + i * OPERAND_STRIDE for i in range(OPERAND_COUNT)
               if (OPERAND_BASE + i * OPERAND_STRIDE) not in render]
    if missing:
        failures.append(
            "%d of the %d operand buffers a host names are not mapped in the render "
            "context, first %#x" % (len(missing), OPERAND_COUNT, missing[0]))
    else:
        print("  all %d operand buffers a host names are mapped in the render context"
              % OPERAND_COUNT)


def check_render_aliases(per_root, failures):
    """Roots 8, 9 and 10 alias root 7's pages, except the private zero page.

    A host builds these by pointing them at the same physical pages the render context uses, and the
    only page that is its own per root is the private zero page. If that ever stops being true they
    are distinct objects and building them as aliases silently supplies the wrong memory, which is
    the fault this record has already hit four times at other addresses.
    """
    render = per_root.get(7)
    if not render:
        failures.append("no render context in this snapshot")
        return
    for index in (8, 9, 10):
        table = per_root.get(index)
        if not table:
            continue
        shared = [va for va in table if va in render]
        differing = [va for va in shared if table[va][1] != render[va][1]]
        missing = [va for va in table if va not in render]
        if missing:
            failures.append("root %d maps %d pages the render context does not, first %#x"
                            % (index, len(missing), missing[0]))
        unexpected = [va for va in differing if va != PRIVATE_ZERO_PAGE]
        if unexpected:
            failures.append(
                "root %d has %d pages at a different physical page from the render "
                "context beyond the private zero page, first %#x; they are distinct "
                "objects and cannot be built as aliases"
                % (index, len(unexpected), unexpected[0]))
        elif PRIVATE_ZERO_PAGE in differing:
            print("  root %-2d aliases the render context in %d pages, with its own zero page"
                  % (index, len(shared) - 1))


def main():
    if len(sys.argv) > 1:
        snapshot = pathlib.Path(sys.argv[1])
    else:
        matches = sorted(CAPTURES.glob("pre_work_*"))
        if not matches:
            print("no pre_work_* snapshot on disk, nothing to check")
            return 0
        snapshot = matches[-1]
    print("checking against %s" % snapshot.name)
    manifest, ram, per_root = load(snapshot)

    failures = []
    check_aliases("descriptor", DESCRIPTORS, per_root, failures)
    check_aliases("ctx/queue", CONTEXT_QUEUE, per_root, failures)
    check_table_descriptors(manifest, snapshot, per_root, failures)
    check_render_aliases(per_root, failures)
    check_operand_table(ram, per_root, failures)

    if failures:
        print("\n%d failures:" % len(failures))
        for line in failures:
            print("  %s" % line)
        return 1
    print("\nall per-context checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
