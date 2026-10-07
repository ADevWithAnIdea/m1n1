#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
xcrun -sdk macosx clang -arch arm64 -fobjc-arc \
    "$root/proxyclient/experiments/g17p_native_barriers.m" \
    -framework Foundation -framework Metal \
    -o "$root/build/g17p_native_barriers"
codesign -f -s - "$root/build/g17p_native_barriers"
shasum -a 256 "$root/build/g17p_native_barriers" \
    "$root/proxyclient/experiments/g17p_native_barriers.metal"
