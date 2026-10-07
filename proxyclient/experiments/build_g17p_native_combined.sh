#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
xcrun -sdk macosx clang -arch arm64 -fobjc-arc -Wall -Wextra -Werror \
    "$root/proxyclient/experiments/g17p_native_combined.m" \
    -framework Foundation -framework Metal -o "$root/build/g17pcombined"
codesign -f -s - "$root/build/g17pcombined"
codesign --verify --strict "$root/build/g17pcombined"
shasum -a 256 "$root/build/g17pcombined"
