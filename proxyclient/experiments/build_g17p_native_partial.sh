#!/bin/sh
# SPDX-License-Identifier: MIT

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
air="$root/build/g17p_native_partial.air"
metallib="$root/build/g17ppartial.metallib"
executable="$root/build/g17ppartial"

xcrun -sdk macosx metal -c \
    "$root/proxyclient/experiments/g17p_native_partial.metal" -o "$air"
xcrun -sdk macosx metallib "$air" -o "$metallib"
xcrun -sdk macosx clang -arch arm64 -fobjc-arc -Wall -Wextra -Werror \
    "$root/proxyclient/experiments/g17p_native_partial.m" \
    -framework Foundation -framework Metal -o "$executable"
codesign -f -s - "$executable"
shasum -a 256 "$executable" "$metallib"
