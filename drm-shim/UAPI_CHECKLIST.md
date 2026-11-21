<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# M5 DRM shim UAPI checklist

Modify this checklist only at the operator’s request. Checking and unchecking
existing boxes is allowed without a request.

The reference is the T6041/G16C M4 Max Linux driver at `582beabe96db`.
The shim uses synchronous submission.

- [x] **VM binds.** Accept identical rebinds as no-ops. Replace overlapping
  mappings while preserving unaffected prefixes and suffixes, including
  single-page mappings. Require a bind stride of at least 32 bytes.
- [x] **Timestamps.** Support 8-byte-aligned object offsets and ranges while
  mapping the backing at page granularity. Reject unaligned command timestamp
  offsets and nonzero offsets with a zero handle. Check that compute, vertex,
  and fragment timestamps land in the requested BO ranges.
- [x] **Render state.** Preserve the caller’s `isp_bgobjvals` bits wherever the
  M5 firmware supports them. Reject unsupported values explicitly. Handle
  valid `vdm_ctrl_stream_base` placements outside the shim’s current resource
  window, including the low addresses accepted by Max.
- [x] **Compute and render sampler heaps.** Determine the M5 limit and support
  valid mapped heaps above the current 1,024-entry cap. Validate the count and
  the entire mapped heap range before submission.
- [x] **Queues and barriers.** Check that the entire 4 GiB USC window lies
  outside the VM’s kernel reservation at queue creation. Support the
  fragment-stage VDM barrier flag accepted by Max while preserving synchronous
  submission.
- [x] **Attachments and BOs.** Validate every attachment update as it is
  parsed, including updates with no following job. Carry attachment hints to
  firmware where supported and retain readback of all writable mappings.
  Give `GEM_WRITEBACK` defined CPU mapping semantics on the host rather than
  silently treating both flag values alike.

## Queue and memory lifetimes

- [x] **Reuse retired firmware queue slots.** The adapter retains every
  allocated queue owner and only marks it destroyed. After 10 firmware
  queue groups have been used, another queue requiring one returns
  `ENOSPC`, even with zero live queues. Reclaim slots, queue storage and
  counters after retirement. Run create, submit, close and reopen cycles
  beyond that limit across files and VMs. Verify output after reuse and
  check that a retired queue's completions cannot affect its successor.
  [Queue ownership](../proxyclient/m1n1/drm_shim/g17g_adapter.py#L76)
- [x] **Recycle work rings and publication state indefinitely.** Mixed mode
  stops at a cumulative 130 compute jobs or 860 render jobs. The dedicated
  paths also contain finite item-ring or ordinal checks. Exercise exhaustion
  and wraparound on the compute-only, render-only and mixed paths, including
  multiple live queues and VMs. Check results beyond the current cumulative
  ceilings. Keep the advertised 64-command per-ioctl limit and any finite
  limit on resources that are simultaneously live.
  [Mixed admission](../proxyclient/m1n1/drm_shim/g17g_adapter.py#L106),
  [Resident rings](../proxyclient/m1n1/drm_shim/g17g_resident_queue.py),
  [Render ordinals](../proxyclient/m1n1/drm_shim/g17g_render_runtime.py#L426)
- [x] **Bound memory and object ownership under churn.** VM slots are
  eligible for reuse, and the shim has paths to release physical BO backing.
  The host ioctl backing-file offsets grow monotonically. Exercise repeated
  VM, GEM, timestamp-object and mapping teardown, including handle close
  with a live CPU mapping and references held until work retires. Check
  that device backing, page tables and retained owner state stay bounded
  and that surviving mappings remain valid. Check partial VM-bind failure
  and retry against the reference driver's observable behavior.
  [VM and GEM ownership](../proxyclient/m1n1/drm_shim/g17g_modern.py),
  [Host allocation](../proxyclient/m1n1/drm_shim/g17g_ioctl.py#L209)

## Command execution

- [x] **Run mixed compute and render in one submit.** Both orders have
  produced correct results across separate submits, and two renders with
  a fragment-stage barrier have passed in one submit. Use nonoverlapping
  command and support allocations to prove both engine orders in a single
  ioctl. Check independent commands, a producer/consumer dependency in
  both directions, and the final output fence.
  [Command planning](../proxyclient/m1n1/drm_shim/g17g_adapter.py#L106)
- [ ] **Resolve the compiler scratch contract.** The shim rejects nonzero
  `binary`, `cfg` and `data` for the compute, vertex and fragment helper
  fields. The reference G16C path also rejects them, but the local Mesa
  Honeykrisp code can populate them when a shader needs scratch. Support
  the helper ABI or demonstrate the intended M5 compiler's helper-free
  scratch handling. Run main-shader and preamble cases with real spills
  for all three stages. The existing vertex scratch flag does not prove
  these paths.
  [Compute helper](../proxyclient/m1n1/drm_shim/g17g_modern.py#L761),
  [Render helpers](../proxyclient/m1n1/drm_shim/g17g_modern.py#L942)
- [x] **Prove wide sampler heaps with actual sampling.** The shim validates
  the complete mapped range and the firmware has completed work with the
  maximum representable counts. Show compute and fragment shaders selecting
  entries above 1,024, including the upper usable entries where addressable,
  and returning distinct expected values for different filters.
  [Current sampler evidence](README.txt)

## DRM userspace contract

- [x] **Round-trip the required fences and shared buffers.** In-process
  binary and timeline syncobj operations exist. PRIME/dma-buf sharing,
  syncobj and sync-file FD import/export, and syncobj eventfd are absent
  from the shim. Identify which the userspace bring-up path actually calls
  and exercise those paths end to end. Include the display or external
  sharing path when testing WSI. Use native DRM support for these APIs in
  Linux.
  [DRM dispatcher](../proxyclient/m1n1/drm_shim/g17g_ioctl.py#L169)
- [x] **Deliver failures to userspace through the normal contract.**
  Published jobs retain an attributed internal fence status, and a
  quiescent TVB allocation failure has a recoverable path. Exercise the
  intended userspace's observation of a failed job or lost device. Check
  that an errored completion never becomes a successful result, dependent
  work sees the failure, and closing after failure preserves the working
  lifetime rules. Prove that work can resume after a recoverable failure.
  [Failure attribution](../proxyclient/m1n1/drm_shim/g17g_adapter.py),
  [Submit and sync ioctls](../proxyclient/m1n1/drm_shim/g17g_ioctl.py#L235)
