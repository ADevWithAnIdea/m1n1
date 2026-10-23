#!/bin/sh
set -eu
mkdir -p /dev/shm /tmp/chromium-runtime /tmp/chromium-profile-v1 /root
chmod 700 /tmp/chromium-runtime
if ! grep -q ' /dev/shm ' /proc/mounts; then mount -t tmpfs -o size=256m tmpfs /dev/shm; fi
unset LD_PRELOAD ASAHI_MESA_DEBUG MESA_LOADER_DRIVER_OVERRIDE VK_ICD_FILENAMES
export LD_LIBRARY_PATH=/opt/mesa-vulkan-apple9/lib:/opt/chromium/lib
export VK_DRIVER_FILES=/opt/mesa-vulkan-apple9/icd.json
export MESA_SHADER_CACHE_DISABLE=true
export XDG_RUNTIME_DIR=/tmp/chromium-runtime
export FONTCONFIG_FILE=/opt/chromium/fonts.conf
exec /bin/busybox timeout -k 5 35 /opt/chromium/chromium \
 --headless=new --ozone-platform=headless --enable-gpu --use-gl=angle --use-angle=vulkan \
 --disable-software-rasterizer --ignore-gpu-blocklist --no-sandbox \
 --no-first-run --no-default-browser-check --disable-background-networking \
 --disable-component-update --disable-sync --user-data-dir=/tmp/chromium-profile-v1 \
 --enable-logging=stderr --log-level=0 --dump-dom file:///opt/chromium/probe.html
