#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the native C dispatcher with the current Python's embedding ABI."""
from pathlib import Path
import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import sysconfig

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fixture-uapi-dir", type=Path,
                    help="compile caller fixture against this pinned header directory")
parser.add_argument("--libc-fixture", action="store_true",
                    help="also build the Linux fixture using real ioctl/mmap calls")
args = parser.parse_args()
if args.libc_fixture and (sys.platform != "linux" or args.fixture_uapi_dir is None):
    parser.error("--libc-fixture requires Linux and --fixture-uapi-dir")
output = root / "build" / ("libg17g_drm_shim.dylib" if sys.platform == "darwin"
                            else "libg17g_drm_shim.so")
output.parent.mkdir(exist_ok=True)
library = sysconfig.get_config_var("LDLIBRARY")
name = library.removeprefix("lib").split(".so")[0].removesuffix(".dylib")
command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC",
           "-dynamiclib" if sys.platform == "darwin" else "-shared",
           "-I" + sysconfig.get_path("include"),
           "-DG17G_PYTHON_EXECUTABLE=" + json.dumps(sys.executable),
           str(root / "drm-shim/g17g_bridge.c"), "-o", str(output), "-lpthread"]
if sysconfig.get_config_var("PYTHONFRAMEWORK"):
    command.append(str(Path(sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX")) / library))
else:
    command += ["-L" + sysconfig.get_config_var("LIBDIR"), "-l" + name]
command += shlex.split(sysconfig.get_config_var("LIBS") or "")
command += shlex.split(sysconfig.get_config_var("SYSLIBS") or "")
subprocess.run(command, check=True)
print(output)
if args.fixture_uapi_dir is not None:
    header = args.fixture_uapi_dir / "asahi_drm.h"
    expected = "69fe416b7294dfec4794217bd11379effd53caff4e86010bb803f1b34bdf5e89"
    if hashlib.sha256(header.read_bytes()).hexdigest() != expected:
        raise SystemExit("caller header differs from pinned Asahi UAPI commit 030248d39b401c94695c9f7df2fed630d35120cd")
    fixture = output.with_name(output.name.replace("drm_shim", "compute_fixture"))
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC",
        "-dynamiclib" if sys.platform == "darwin" else "-shared",
        "-I" + str(args.fixture_uapi_dir), str(root / "drm-shim/compute_fixture.c"),
        str(output), "-o", str(fixture)], check=True)
    print(fixture)
    if args.libc_fixture:
        libc_fixture = output.with_name("libg17g_compute_fixture_libc.so")
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
            "-DG17G_FIXTURE_LIBC", "-I" + str(args.fixture_uapi_dir),
            str(root / "drm-shim/compute_fixture.c"), "-o", str(libc_fixture)], check=True)
        print(libc_fixture)
