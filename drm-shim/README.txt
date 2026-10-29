SPDX-License-Identifier: GPL-2.0-only

M5 DRM shim and firmware backend
===============================

This branch contains the firmware-facing T8142/G17G shim, extracted from the
recovered M5 worktree. It starts at GravityLinux/bootloader main f02d4a52.
It includes the Asahi UAPI dispatcher, native bridge, cold boot, ASC mailbox
transport, host-built initialization/command objects, compute and render
submission, resident queues/VMs, timestamp/sync lifetimes, TVB growth and
attributed fault handling. It does not require a running macOS guest.

Firmware is supplied by the platform boot environment. No Apple firmware,
kernelcache, capture checkpoint or firmware executable code is distributed.
The backend is the saved macOS 27 beta-5 T8142 protocol implementation. This
does not establish support for other firmware versions or GPU families.

Where the firmware-facing code lives
-----------------------------------

proxyclient/m1n1/g17g_shim_entry.py
  Lazy native entrypoint, proxy connection and the real hardware adapter.

proxyclient/m1n1/drm_shim/g17g_boot.py
  Powers the GPU ASCs, builds fresh initdata and sends MSG_INITDATA; waits
  for both firmware acknowledgments through StandardASC endpoints.

proxyclient/m1n1/drm_shim/g17g_adapter.py
  Turns validated UAPI work into hardware submissions and completion fences.

proxyclient/m1n1/drm_shim/g17g_runtime.py, g17g_compute_queue.py,
g17g_submit.py, g17g_render_runtime.py, g17g_render_submit.py,
g17g_partial_runtime.py, g17g_mixed_runtime.py, g17g_mixed_submit.py,
g17g_resident_queue.py and g17g_tvb_runtime.py
  Own firmware queue/control messages, work publication and completion,
  repeated mixed compute/render work, resident VM state and growth replies.

proxyclient/m1n1/drm_shim/g17g_backend.py, g17g_compute.py,
g17g_render.py, g17g_initdata.py and g17g_postcontrol.py
  Build the firmware ABI data structures explicitly from source.

proxyclient/m1n1/drm_shim/g17g_stream.py and g17g_transfer.py
  Publish driver-owned data and service reports, with target-side batching.

proxyclient/m1n1/drm_shim/g17g_mapping_client.py and g17g_uat.py
  Use unchanged upstream UAT APIs for driver mapping policy. g17g_uat.py is
  retained as the mapping-policy module name; it contains no state-object,
  management-table image, PTE encoder or page-table walker. See AUDIT.txt.

Build and native use
--------------------

Use a Python environment with the repository requirements installed:

  python3 drm-shim/build_bridge.py
  PYTHONPATH=proxyclient python3 -m unittest discover \
    -s tests/python/test_proxyclient/test_m1n1 -p 'test_agx_g17g*.py'

The bridge embeds that interpreter's ABI. Output is build/libg17g_drm_shim.so
on Linux or build/libg17g_drm_shim.dylib on macOS. g17g_drm_init(backing_fd)
creates the real lazy shim. The first operation requiring a device connects
through M1N1DEVICE and runs G17GBootRuntime before submitting to firmware.

Set M1N1DEVICE to a working M5 proxy transport, PYTHONPATH to proxyclient,
and G17G_CRASH_DIRECTORY to an existing writable directory. The boot runtime
checks chip-id 0x8142 before GPU allocation or power changes. It never reboots
or chainloads a target automatically. Start from a freshly reset target with
the required firmware resident. G17G_BOOT_PROFILE defaults to compute; mixed
is also retained. G17G_TVB_MAX_BLOCKS selects the retained reactive-growth cap.

The native embedding route can instead attach an explicitly created
G17GIoctlShim using g17g_drm_attach while holding the Python GIL. Tests exercise
the compiled C dispatcher and real shared-file BO/usercopy/sync boundaries.

Mesa integration
----------------

mesa_g17g.c and mesa.patch connect the dispatcher to Mesa's drm-shim libc
entrypoints. prepare_mesa.py packages a separate, pinned Mesa source checkout
without modifying that input tree:

  python3 drm-shim/prepare_mesa.py --mesa-source /path/to/mesa \
    --output /path/to/new/mesa-g17g.tar

The helper checks the original public Asahi UAPI header hash. This branch does
not include a Mesa compiler port. compute_fixture.c and the native discovery/
lifetime callers are retained for that integration; the normal bridge build
does not need a Mesa checkout. GPU compiler products in the optional reference
fixtures are the original experiment's own Metal caller products, not firmware.

Qualification
-------------

The extracted backend was hardware-qualified in the saved research checkout
for the bounded operations recorded there. This branch removes its private
UAT extensions and uses the existing UAT as a client instead. That adaptation
has offline integration tests against the actual unchanged UAT, including
full 608-page initialization preparation, 42-bit mappings, resident roots,
unmap isolation, TVB allocation/overlap/OOM and scratch-resource cleanup.

All 411 extraction tests pass on macOS and Linux. These are not a fresh M5
hardware qualification of the mapping adaptation. No target was accessed for
this extraction. Async submission, comprehensive hardware coverage, arbitrary
USC-base relocation and recovery after a fatal GPU crash remain unsupported
or unqualified. A fatal crash retains reachable backing and requires reset.

AUDIT.txt describes the provenance boundary and excluded implementation code;
provenance.json records source and extracted file hashes.
