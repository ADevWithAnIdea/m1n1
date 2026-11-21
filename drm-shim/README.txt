SPDX-License-Identifier: GPL-2.0-only

M5 DRM shim and firmware backend
===============================

For LLMs

This branch contains the firmware-facing T8142/G17G shim. The original
extraction started at GravityLinux/bootloader main f02d4a52. This snapshot
brings the 27.3 shim worktree onto GravityLinux/bootloader main ac17c97f.
It includes the Asahi UAPI dispatcher, native bridge, cold boot, ASC mailbox
transport, host-built initialization/command objects, compute and render
submission, resident queues/VMs, timestamp/sync lifetimes, TVB growth and
attributed fault handling. It does not require a running macOS guest.

Firmware is supplied by the platform boot environment. No Apple firmware,
kernelcache, capture checkpoint or firmware executable code is distributed.
The backend includes the original macOS 27.0 beta-5 T8142 protocol and the
macOS 27.3 beta protocol identified by mBoot-20457.60.65.0.1 (26C5035r).

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

Use Python 3.12 or newer and a C compiler. Build the bridge with the
same interpreter that will run the shim:

  python3 -m venv .venv
  . .venv/bin/activate
  python3 -m pip install -r requirements.txt
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
or chainloads a target automatically. The USC execution base is fixed at 1 TiB.
Queue creation ignores the caller's base field and checks the full 4 GiB window
against the VM's kernel reservation. Start from a freshly reset target with
the required firmware resident. G17G_BOOT_PROFILE defaults to compute; mixed
is also retained. G17G_TVB_MAX_BLOCKS selects the retained reactive-growth cap.

Run the hardware smoke test from the repository root with the M5 stopped
at its proxy and the supported firmware resident:

  mkdir -p build/g17g-crashes
  export M1N1DEVICE=/dev/path-to-m5-proxy
  export G17G_CRASH_DIRECTORY="$PWD/build/g17g-crashes"
  export PYTHONPATH="$PWD/proxyclient"
  python3 drm-shim/smoke.py

The smoke test uses the native C ioctl and mmap entrypoints. It checks a
complete 16 KiB compute output page, including its guard, followed by
eight render attachments in a separate VM. It uses the included owned
caller fixtures and needs no Mesa checkout.

The native embedding route can instead attach an explicitly created
G17GIoctlShim using g17g_drm_attach while holding the Python GIL. Tests exercise
the compiled C dispatcher and real shared-file BO/usercopy/sync boundaries.
Pass GEM_MMAP_OFFSET's value to g17g_drm_mmap_fd to obtain a duplicate of the
BO's backing file. Map it at offset zero and close the duplicate after mmap.
The kernel preserves the caller's mapping through GEM and DRM file close.

Mesa integration
----------------

mesa_g17g.c and mesa.patch connect the dispatcher to Mesa's drm-shim libc
entrypoints. prepare_mesa.py packages a separate, pinned Mesa source checkout
without modifying that input tree:

  python3 drm-shim/prepare_mesa.py --mesa-source /path/to/mesa \
    --output /path/to/new/mesa-g17g.tar

On Linux, unpack the archive and build the interposer and Mesa driver
with the Mesa build dependencies and a Python embedding development
package providing the python3-embed pkg-config entry:

  mkdir mesa-source
  tar -xf /path/to/new/mesa-g17g.tar -C mesa-source
  meson setup mesa-build mesa-source --buildtype=release \
    -Dplatforms= -Dgallium-drivers= -Dvulkan-drivers=asahi -Dtools=drm-shim \
    -Dglx=disabled -Degl=disabled -Dgles1=disabled -Dgles2=disabled -Dllvm=enabled
  meson compile -C mesa-build asahi_g17g_drm_shim vulkan_asahi

For a caller with suitable M5 GPU programs, preload
mesa-build/src/drm-shim/libasahi_g17g_drm_shim.so with the same proxy and
PYTHONPATH environment used above.

The helper checks the original public Asahi UAPI header hash. This branch does
not include a Mesa compiler port. compute_fixture.c and the native discovery/
lifetime callers are retained for that integration; the normal bridge build
does not need a Mesa checkout. GPU compiler products in the optional reference
fixtures are the original experiment's own Metal caller products, not firmware.

On the Mesa interposer, GEM_WRITEBACK uses the host's normal cached shared
mapping for CPU read and write access. Other BOs receive MADV_SEQUENTIAL as
a streaming hint. Regular file mmap cannot request the native driver's
write-combining page attribute. Either mode publishes CPU writes at submit
and makes GPU writes available when the synchronous submission completes.

At the pinned Mesa revision, Honeykrisp creates per-queue timeline syncobjs
and uses transfers for submits containing only synchronization. Those calls
are handled by the shim. External memory in hk_device_memory.c goes through
the PRIME handle and FD operations in agx_device.c. External synchronization
in util/u_sync_provider.c uses both opaque syncobj FDs and sync-files. The WSI
display path imports the dma-buf on the display device. These sharing paths
require native Linux DRM objects. The pinned tree has no syncobj eventfd call.
The G17G interposer selects an unused render minor and exposes the native
DRM nodes alongside it. This lets libdrm enumerate the shim alongside the
separate render and display devices used for Linux sharing tests.

On Linux, setting G17G_NATIVE_DRM_DEVICE to a native DRM primary node
with linear dumb-buffer and syncobj support enables PRIME, opaque syncobj FD
and sync-file exchange. The node supplies shareable GEM backing. The shim wraps
proxy uploads and readback in dma-buf CPU synchronization. Its other
BOs keep their per-object backing files.

Linux tests ran Honeykrisp external-memory, sync-file semaphore and opaque
timeline semaphore round-trips with the software GPU endpoint. An independent
native DRM file updated the imported timeline after the Vulkan exporter was
destroyed. A separate M5 test through the Linux bridge verified two complete
16 KiB compute pages in exported dma-bufs and imported them into the native
display device as framebuffers.

Imported sync-files preserve the kernel fence and its status. Work completed
successfully through the synchronous proxy publishes a native syncobj signal
at retirement. Local submission errors remain available on the shim side and
return their errno from sync-file export. The native backing device can
publish successful completions and import existing kernel fences. A native
opaque peer sees no new signal for a local error. An explicit reset can
reinitialize a timeline that contains an unexportable local error.

Attachment updates validate writable VM coverage as they are parsed. On the
observed G17G command ABI, render targets come from the render state and
caller programs. The shim retains attachment lists as UAPI metadata. It
reads back every writable VM mapping, including outputs omitted from the
attachment lists.

Sampler heap admission checks the whole logical range at eight bytes per
entry. T8142 completed a 27.3 compute submission with the maximum firmware
count of 4,294,967,294 (the adjacent 32-bit count-plus-one field remains
representable) and a render submission with the maximum UAPI count of
65,535. These measurements cover descriptor admission and correct output
with the heaps bound.

Separate single-user macOS 27.3 captures sampled zero-based index 2,047 in
both compute and fragment shaders. Cold replay verified all 16 KiB of
each output page. Replaying again with source-built sampler records
changed the selected filter and produced the exact alternate output on
both engines.

Source-built UAPI submissions then exercised both filters through the
shim on T8142. Compute selected hardware sampler ID 131,071 and matched
all 16 KiB of its guarded output. Fragment selected ID 65,534 with the
maximum advertised render count of 65,535 and matched all eight 64 KiB
attachments. In both cases the shader launch referenced the same sampler
allocation supplied to the UAPI. The GPU returned 0.5 for linear filtering
and 1.0 for nearest. The native compute descriptor had zero sampler fields
at 0xf2c. The caller's launch supplied the sampler root.

Qualification
-------------

The extracted backend was hardware-qualified in the saved research checkout
for the bounded operations recorded there. This branch removes its private
UAT extensions and uses the existing UAT as a client instead. That adaptation
has offline integration tests against the actual unchanged UAT, including
full 608-page initialization preparation, 42-bit mappings, resident roots,
unmap isolation, TVB allocation/overlap/OOM and scratch-resource cleanup.

The 27.3 snapshot passed 442 shim tests and native C process
initialization from an exported checkout on macOS. From that checkout,
the two-workload hardware smoke test passed the full 16 KiB compute
page and all eight 64 KiB render attachments on the M5 Air. The pinned
Mesa archive was generated and its digest verified.

The supported submission model is synchronous, with a fixed 1 TiB USC
execution base. The Mesa compiler port for G17G is separate work.
The included smoke workloads exercise the bridge and firmware transport.
A fatal GPU crash retains reachable backing and requires a target reset.

The synchronous submit ioctl reports an already-terminal job failure as
errno. An output syncobj still signals terminal completion and retains the
error for dependent submits. The pinned Honeykrisp integration reports
device loss on a failed submit instead of aborting the caller process.
The Linux Vulkan test used the pinned Honeykrisp build, the libc interposer
and an injected ENOMEM completion at the hardware endpoint. Both vkQueueSubmit
and vkQueueWaitIdle returned VK_ERROR_DEVICE_LOST, and device close succeeded.
A separate M5 run reached a real TVB allocation limit, preserved ENOMEM on the
failed fence and its dependent submit, then returned eight exact attachments
on independent work before closing the same DRM file.

AUDIT.txt describes the provenance boundary and excluded implementation code;
provenance.json records source and extracted file hashes.
