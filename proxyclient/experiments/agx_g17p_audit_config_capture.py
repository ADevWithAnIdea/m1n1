#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture source G17P config at the output-positive native CL2 boundary."""

import datetime
import json
import os
import pathlib
import struct
import sys
import tempfile
from collections import deque


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

os.environ["M1N1DEVICE"] = "/dev/m1n1-neo"
os.environ["M1N1HEAP_RESERVE"] = "1"
os.environ["AGX_GPU"] = "G17"

from m1n1.agx.shim import DRMAsahiShim  # noqa: E402

from agx_g17p_source_lifecycle import advance_source_lifecycle  # noqa: E402


PAGE = 0x4000
NATIVE = pathlib.Path(
    "/Users/user/asahi_re/artifacts/agx_g17p/"
    "native_add3_full_positive_20260811_230235"
)

FIRMWARE_ROOT = (64, 1)
CONTEXT0_ROOT = (0, 0)
PRIMARY_ROOT = 0xFFFFFC20001A8000
SECONDARY_ROOT = 0xFFFFFC20001B0000
CONFIG_RANGES = (
    # Complete hardware-data/main-config bundle, including unlabeled bytes.
    (FIRMWARE_ROOT, 0xFFFFFC20C0788000, 0x28000),
    # Complete private config/state cluster reached by both initdata roots.
    (FIRMWARE_ROOT, 0xFFFFFC2000020000, 0x178000),
    (FIRMWARE_ROOT, PRIMARY_ROOT, PAGE),
    (FIRMWARE_ROOT, SECONDARY_ROOT, PAGE),
)


def reference_pages():
    manifest = json.loads((NATIVE / "manifest.json").read_text())
    roots = {}
    for group in manifest["root_mappings"]:
        context = int(group.get("root_ctx_id", -1))
        selector = int(group.get("selector", -1))
        root = (context, selector)
        if root not in (FIRMWARE_ROOT, CONTEXT0_ROOT):
            continue
        roots[root] = {}
        for mapping in group["mappings"]:
            if mapping.get("blob_index") is None:
                continue
            roots[root][int(mapping["va"])] = mapping

    ram = (NATIVE / manifest["ram_file"]).read_bytes()

    def native_page(root, address):
        mapping = roots[root][address]
        offset = int(mapping["blob_index"]) * PAGE
        body = ram[offset:offset + PAGE]
        if len(body) != PAGE:
            raise RuntimeError("short native page %#x" % address)
        return body

    selected = set()
    for root, address, size in CONFIG_RANGES:
        for page in range(address, address + size, PAGE):
            if page in roots[root]:
                selected.add((root, page))

    queue = deque(((FIRMWARE_ROOT, PRIMARY_ROOT),
                   (FIRMWARE_ROOT, SECONDARY_ROOT)))
    depth = {(FIRMWARE_ROOT, PRIMARY_ROOT): 0,
             (FIRMWARE_ROOT, SECONDARY_ROOT): 0}
    while queue:
        root, page = queue.popleft()
        if page not in roots.get(root, {}):
            continue
        selected.add((root, page))
        if depth[(root, page)] >= 6:
            continue
        body = native_page(root, page)
        for offset in range(0, PAGE - 7, 4):
            value = struct.unpack_from("<Q", body, offset)[0]
            target_page = value & ~(PAGE - 1)
            if value >= 0xFFFF000000000000:
                target_root = FIRMWARE_ROOT
            else:
                target_root = CONTEXT0_ROOT
            target = (target_root, target_page)
            if target_page not in roots.get(target_root, {}):
                continue
            selected.add(target)
            if target not in depth:
                depth[target] = depth[(root, page)] + 1
                queue.append(target)

    pages = {}
    for root, address in selected:
        translation = (
            "firmware-high" if root == FIRMWARE_ROOT else "context-0")
        pages[(translation, address)] = roots[root][address]
    return manifest, pages


def translate_page(backend, translation, address):
    if translation == "firmware-high":
        root = backend.firmware_high_root
    else:
        root = backend.space.uat.ttbr0_base
    ranges = backend.space.uat.iotranslate_root(root, address, PAGE)
    if not ranges or ranges[0][0] is None:
        raise RuntimeError("unmapped")
    if sum(length for pa, length in ranges if pa is not None) < PAGE:
        raise RuntimeError("short mapping")
    return int(ranges[0][0])


def physical_read(backend, pa, size):
    if not (0x10000000000 <= pa < 0x20000000000):
        raise RuntimeError("non-DRAM translation %#x" % pa)
    backend.u.proxy.dc_ivac(pa, size)
    return bytes(backend.u.iface.readmem(pa, size))


def capture(backend):
    manifest, references = reference_pages()
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output = pathlib.Path(os.path.expanduser(
        "~/asahi_re/artifacts/agx_g17p/generated_config_pre_cl2_%s" % stamp))
    output.mkdir(parents=True, exist_ok=False)

    translated = []
    missing = []
    for (translation, address), native in sorted(
            references.items(), key=lambda item: (item[0][0], item[0][1])):
        try:
            pa = translate_page(backend, translation, address)
            if not (0x10000000000 <= pa < 0x20000000000):
                raise RuntimeError("non-DRAM translation %#x" % pa)
        except Exception as error:
            missing.append({
                "dva": address,
                "translation": translation,
                "error": str(error),
            })
            continue
        translated.append((translation, address, native, pa))

    physical_pages = {}
    pending = sorted({pa for _translation, _address, _native, pa
                      in translated})
    while pending:
        start = pending.pop(0)
        count = 1
        while (pending and pending[0] == start + count * PAGE and
               count * PAGE < 0x100000):
            pending.pop(0)
            count += 1
        body = physical_read(backend, start, count * PAGE)
        for index in range(count):
            physical_pages[start + index * PAGE] = (
                body[index * PAGE:(index + 1) * PAGE])

    raw = bytearray()
    pages = []
    for translation, address, native, pa in translated:
        body = physical_pages[pa]
        pages.append({
            "dva": address,
            "pa": pa,
            "capture_offset": len(raw),
            "translation": translation,
            "native_blob_index": native.get("blob_index"),
            "native_pte": native.get("pte"),
        })
        raw.extend(body)

    (output / "pages.bin").write_bytes(bytes(raw))
    (output / "pages.json").write_text(json.dumps({
        "format": "m1n1-t8140-g17p-source-config-pre-cl2-v2",
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "phase": (
            "source-built world at primary control 67 after output-positive "
            "renders and before any CL2 client or firmware object"
        ),
        "page_size": PAGE,
        "initdata_addr": int(backend.initdata_addr),
        "native_reference": str(NATIVE),
        "native_capture_label": manifest.get("capture_label"),
        "native_trigger_type": manifest.get("trigger_type"),
        "pages": pages,
        "missing": missing,
    }, indent=2, sort_keys=True) + "\n")
    print(
        "CONFIG AUDIT snapshot=%s pages=%d missing=%d" %
        (output, len(pages), len(missing)),
        flush=True,
    )
    return output


def main():
    if len(sys.argv) != 1:
        raise SystemExit("agx_g17p_audit_config_capture.py accepts no arguments")
    with tempfile.TemporaryFile() as memfd:
        front = DRMAsahiShim(memfd.fileno())
        front.init()
        backend = front.g17p
        if backend is None:
            raise RuntimeError("G17P backend did not initialize")
        advance_source_lifecycle(front, backend)
        capture(backend)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
