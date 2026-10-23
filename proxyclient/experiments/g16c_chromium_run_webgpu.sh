#!/bin/sh
set -eu
mkdir -p /dev/shm /tmp/chromium-runtime /tmp/chromium-webgpu-profile-v1
chmod 700 /tmp/chromium-runtime
if ! grep -q ' /dev/shm ' /proc/mounts; then mount -t tmpfs -o size=256m tmpfs /dev/shm; fi
unset LD_PRELOAD ASAHI_MESA_DEBUG MESA_LOADER_DRIVER_OVERRIDE VK_ICD_FILENAMES
export LD_LIBRARY_PATH=/opt/mesa-vulkan-apple9/lib:/opt/chromium/lib
export VK_DRIVER_FILES=/opt/mesa-vulkan-apple9/icd.json
export MESA_SHADER_CACHE_DISABLE=true
export XDG_RUNTIME_DIR=/tmp/chromium-runtime
export FONTCONFIG_FILE=/opt/chromium/fonts.conf
set +e
/opt/chromium/webgpu-cdp
rc=$?
set -e
cat /tmp/chromium-webgpu-browser.log
exit "$rc"
