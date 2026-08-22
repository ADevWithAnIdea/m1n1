# SPDX-License-Identifier: MIT
"""Common state capture for T8140/G17P native/direct phase comparisons."""

import datetime
import hashlib
import json
import pathlib


TRANSFER_CHUNK = 0x400000
REGIONS = (
    ("gpu-region", "gpu-region-base", "gpu-region-size"),
    ("gfx-shared-region", "gfx-shared-region-base", "gfx-shared-region-size"),
    ("gfx-shared-l2-region", "gfx-shared-l2-region-base",
     "gfx-shared-l2-region-size"),
    ("gfx-handoff", "gfx-handoff-base", "gfx-handoff-size"),
)
ASC_NODES = (
    ("primary", "/arm-io/gfx-asc"),
    ("secondary", "/arm-io/gfx1-asc"),
)


def _readmem(iface, address, size):
    chunks = []
    for offset in range(0, size, TRANSFER_CHUNK):
        chunks.append(bytes(iface.readmem(
            address + offset, min(TRANSFER_CHUNK, size - offset)
        )))
    return b"".join(chunks)


def save_phase_state(iface, proxy, adt, output, phase, trigger=None):
    """Persist host UAT/handoff regions and safe hardware registers."""
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=False)
    sgx = adt["/arm-io/sgx"]
    records = []

    for name, base_prop, size_prop in REGIONS:
        base = int(sgx._properties.get(base_prop, 0))
        size = int(sgx._properties.get(size_prop, 0))
        if not base or not size:
            continue
        data = _readmem(iface, base, size)
        filename = name + ".bin"
        (output / filename).write_bytes(data)
        records.append({
            "name": name,
            "pa": base,
            "size": size,
            "file": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    ascs = []
    for name, path in ASC_NODES:
        base = int(adt[path].get_reg(0)[0])
        ascs.append({
            "name": name,
            "base": base,
            "cpu_control": int(proxy.read32(base + 0x0044)),
            "cpu_status": int(proxy.read32(base + 0x0048)),
            "inbox_control": int(proxy.read32(base + 0x8110)),
            "outbox_control": int(proxy.read32(base + 0x8114)),
        })

    sgx_base = int(sgx.get_reg(0)[0])
    report = {
        "format": "m1n1-t8140-g17p-phase-state-v1",
        "captured_utc": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "phase": phase,
        "trigger": trigger,
        "chip_id": int(adt["/chosen"].chip_id),
        "sgx_base": sgx_base,
        "sgx_registers": {
            "axi_transition_0": int(proxy.read32(sgx_base + 0x1000104)),
            "axi_transition_1": int(proxy.read32(sgx_base + 0x1000108)),
            "pre_init": int(proxy.read32(sgx_base + 0xd06030)),
        },
        "asces": ascs,
        "regions": records,
    }
    manifest = output / "phase_state.json"
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return manifest
