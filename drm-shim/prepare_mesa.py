#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Package a clean, pinned Mesa tree with the local G17G interposer.

The input checkout is read only: archive the specified commit, apply the
reviewable local patch in temporary storage, and write a new source archive.
Build that archive on a Linux filesystem supporting shared writable mmap.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

REVISION = "6546c2f14b6795e8c0645b805161fc1883a43bc8"
UAPI_SHA256 = "69fe416b7294dfec4794217bd11379effd53caff4e86010bb803f1b34bdf5e89"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mesa-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new .tar source archive")
    args = parser.parse_args()
    if args.output.exists() or args.output.with_suffix(".json").exists():
        parser.error("refusing to replace an existing source archive or manifest")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    local = Path(__file__).resolve().parent
    inputs = ("mesa.patch", "mesa_g17g.c", "g17g_bridge.c", "g17g_bridge.h")
    manifest = dict(mesa_revision=REVISION, uapi_sha256=UAPI_SHA256,
                    inputs={name: hashlib.sha256((local / name).read_bytes()).hexdigest()
                            for name in inputs})
    with tempfile.TemporaryDirectory(prefix="g17g-mesa-") as temporary:
        temporary = Path(temporary)
        archive = temporary / "mesa.tar"
        subprocess.run(["git", "-C", str(args.mesa_source.resolve()), "archive",
                        "--format=tar", "--output=" + str(archive), REVISION], check=True)
        tree = temporary / "source"
        tree.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(tree, filter="data")
        header = tree / "include/drm-uapi/asahi_drm.h"
        if hashlib.sha256(header.read_bytes()).hexdigest() != UAPI_SHA256:
            raise RuntimeError("archived Mesa Asahi UAPI differs from the pinned header")
        subprocess.run(["git", "apply", "--check", str(local / "mesa.patch")],
                       cwd=tree, check=True)
        subprocess.run(["git", "apply", str(local / "mesa.patch")], cwd=tree, check=True)
        for name in inputs[1:]:
            shutil.copyfile(local / name, tree / "src/drm-shim" / name)
        with tarfile.open(args.output, "x") as output:
            output.add(tree, arcname=".")
    with args.output.open("rb") as output:
        manifest["archive_sha256"] = hashlib.file_digest(output, "sha256").hexdigest()
    args.output.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(args.output)
    print(manifest["archive_sha256"])


if __name__ == "__main__":
    main()
