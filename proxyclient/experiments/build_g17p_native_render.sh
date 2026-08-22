#!/bin/sh
# SPDX-License-Identifier: MIT

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
air="$root/build/g17p_native_render.air"
metallib="$root/build/g17p_native_render.metallib"
executable="$root/build/g17p_native_render"

xcrun -sdk macosx metal -c \
    "$root/proxyclient/experiments/g17p_native_render.metal" -o "$air"
xcrun -sdk macosx metallib "$air" -o "$metallib"
xcrun -sdk macosx clang -arch arm64 -fobjc-arc \
    "$root/proxyclient/experiments/g17p_native_render.m" \
    -framework Foundation -framework Metal -o "$executable"
codesign -f -s - "$executable"
shasum -a 256 "$executable" "$metallib"
