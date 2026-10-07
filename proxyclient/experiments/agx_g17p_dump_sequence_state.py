#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read only captured sequence data after a failed direct replay, before reset."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("profile", type=Path)
    parser.add_argument("attempt", type=Path)
    args = parser.parse_args()
    if not os.environ.get("M1N1DEVICE", "").startswith("/dev/ttys"):
        parser.error("use only the exact raw PTY from this workflow's live RID 1 relay")
    manifest = json.loads((args.snapshot / "manifest.json").read_text())
    profile = json.loads(args.profile.read_text())
    if manifest["ram_sha256"] != profile["snapshot_ram_sha256"]:
        parser.error("profile/checkpoint identity mismatch")
    from agx_g17p_replay_independent_sequence import output_pages
    owned = {int(row["original_pa"]) for row in manifest["blob_pages"]}
    pages = {int(row["pa"]) for row in profile["records"]}
    for root in manifest["root_mappings"]:
        if root["root_ctx_id"] == 1:
            pages.update(int(row["pa"]) for row in root["mappings"]
                         if row["va"] in output_pages(3))
    if not pages <= owned:
        parser.error("diagnostic page is not captured owned RAM")
    from m1n1.setup import iface, p, u
    if u.adt["/chosen"].chip_id != 0x8140:
        raise RuntimeError("not the authorized T8140 target")
    out = args.attempt / "failure_data"
    out.mkdir(exist_ok=False)
    records = []

    def save(pa, size, name):
        p.dc_ivac(pa, size)
        body = bytes(iface.readmem(pa, size))
        (out / name).write_bytes(body)
        records.append(dict(pa=pa, size=size, file=name,
                            sha256=hashlib.sha256(body).hexdigest()))

    for pa in sorted(pages):
        save(pa, 0x4000, "ram_%x.bin" % pa)
    for pa in manifest["table_pages"]:
        save(int(pa), 0x4000, "table_%x.bin" % int(pa))
    allowed = {"gpu-region", "gfx-shared-region", "gfx-shared-l2-region", "gfx-handoff"}
    for row in manifest["fixed_regions"]:
        if row["name"] in allowed:
            save(int(row["pa"]), int(row["size"]), "fixed_%s.bin" % row["name"])
    (out / "manifest.json").write_text(json.dumps(dict(snapshot=str(args.snapshot.resolve()),
        profile=str(args.profile.resolve()), records=records), indent=2) + "\n")
    print("Saved %d owned data regions: %s" % (len(records), out))


if __name__ == "__main__":
    main()
