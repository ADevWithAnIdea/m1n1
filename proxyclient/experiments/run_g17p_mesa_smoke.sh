#!/bin/sh
# SPDX-License-Identifier: MIT
# Build and run the source-built first-partial integration through real Mesa.
#
# This launcher intentionally accepts no arguments.  The optional directory
# variables below describe the Linux build-host installation, not GPU behavior;
# the actual workload runs under env -i so no experiment knob can affect it.

set -eu

if [ "$#" -ne 0 ]; then
    echo "run_g17p_mesa_smoke.sh accepts no arguments" >&2
    exit 2
fi

m1n1_root=${M1N1_ROOT:-/home/user.guest/m1n1-g17p}
mesa_root=${MESA_ROOT:-/Users/user/asahi_re/gpu/mesa}
mesa_build=${MESA_BUILD:-/home/user.guest/mesa-build}
mesa_destdir=${MESA_DESTDIR:-/home/user.guest/mesa-install}
mesa_lib=${MESA_LIB:-$mesa_destdir/usr/local/lib/aarch64-linux-gnu}
proxy_device=${M1N1_PROXY_DEVICE:-socket://host.lima.internal:33331}
expected_uapi_sha256=69fe416b7294dfec4794217bd11379effd53caff4e86010bb803f1b34bdf5e89

source_file=$m1n1_root/proxyclient/experiments/g17p_mesa_smoke.c
smoke_binary=$mesa_build/g17p_mesa_smoke
shim_library=$mesa_build/src/asahi/drm-shim/libasahi_noop_drm_shim.so
gbm_library=$mesa_lib/libgbm.so
dri_directory=$mesa_lib/dri
venv_python=$m1n1_root/.venv/bin/python3
uapi_header=$mesa_root/include/drm-uapi/asahi_drm.h

for required_path in "$source_file" "$venv_python" "$uapi_header" \
                     "$mesa_build/build.ninja"; do
    if [ ! -e "$required_path" ]; then
        echo "missing integration prerequisite: $required_path" >&2
        exit 1
    fi
done

uapi_sha256=$(sha256sum "$uapi_header" | awk '{print $1}')
if [ "$uapi_sha256" != "$expected_uapi_sha256" ]; then
    echo "Mesa asahi_drm.h is not the audited upstream UAPI: $uapi_sha256" >&2
    exit 1
fi

ninja -C "$mesa_build"
DESTDIR="$mesa_destdir" ninja -C "$mesa_build" install

for required_path in "$shim_library" "$gbm_library" \
                     "$dri_directory/asahi_dri.so"; do
    if [ ! -e "$required_path" ]; then
        echo "Mesa build did not produce: $required_path" >&2
        exit 1
    fi
done

python_site=$(
    "$venv_python" -c \
        'import sysconfig; print(sysconfig.get_paths()["purelib"])'
)
proof_state=$(mktemp -d "${TMPDIR:-/tmp}/g17p-mesa-proof.XXXXXX")
cleanup_proof_state()
{
    case "$proof_state" in
        */g17p-mesa-proof.*)
            [ ! -e "$proof_state" ] || rm -r -- "$proof_state"
            ;;
    esac
}
trap cleanup_proof_state EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ ! -x "$smoke_binary" ] || [ "$source_file" -nt "$smoke_binary" ]; then
    cc -std=c11 -O2 -Wall -Wextra -Werror \
        -I"$mesa_root/include" \
        -I"$mesa_destdir/usr/local/include" \
        -I/usr/include/libdrm \
        -L"$mesa_lib" -Wl,-rpath,"$mesa_lib" \
        "$source_file" -o "$smoke_binary" -lEGL -lGLESv2 -lgbm
fi

echo "G17P_MESA_PROOF uapi_sha256=$uapi_sha256 environment=clean workload=source-built-first-partial"
env -i \
    HOME="$HOME" \
    USER="${USER:-lab}" \
    LANG="${LANG:-C.UTF-8}" \
    PATH=/usr/local/bin:/usr/bin:/bin \
    XDG_CACHE_HOME="$proof_state/cache" \
    XDG_CONFIG_HOME="$proof_state/config" \
    XDG_DATA_HOME="$proof_state/data" \
    LD_LIBRARY_PATH="$mesa_lib" \
    LD_PRELOAD="$shim_library" \
    GBM_BACKENDS_PATH="$mesa_lib/gbm" \
    LIBGL_DRIVERS_PATH="$dri_directory" \
    MESA_SHADER_CACHE_DISABLE=true \
    PYTHONPATH="$m1n1_root/proxyclient:$python_site" \
    PYTHONUNBUFFERED=1 \
    M1N1DEVICE="$proxy_device" \
    M1N1TIMEOUT=30 \
    "$smoke_binary"
