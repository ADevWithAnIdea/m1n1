#!/bin/sh
# SPDX-License-Identifier: MIT

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
xcrun clang -arch arm64 -dynamiclib \
    "$root/proxyclient/experiments/g17p_partial_iotrace.c" \
    -framework IOKit -framework CoreFoundation \
    -o "$root/build/g17p_partial_iotrace.dylib"
codesign -f -s - "$root/build/g17p_partial_iotrace.dylib"
shasum -a 256 "$root/build/g17p_partial_iotrace.dylib"
