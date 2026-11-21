<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# M5 and Neo GPU submission flow

The M5 Air (T8142/G17G) accepted Neo's first-compute item order and
first-render publication flow on macOS 27.3 beta firmware (26C5035r).
The experiments used source-built workloads and the M5 firmware objects
and mappings supplied by this shim.

## Queue lifetime

Firmware initdata and per-client work queues have separate lifetimes.
Initdata brings up the firmware and its shared channel rings. A DRM
`QUEUE_CREATE` gives userspace a queue handle associated with a VM and
priority. The first real `SUBMIT` provides the command stream and
introduces the queue to firmware through a work-channel entry.

This follows the M1/M2 Asahi model. Asahi allocates the per-client queues
at `QUEUE_CREATE` and posts `RunWorkQueue` with `is_new` when it first
publishes a real job. Its tiling queue can carry an `InitBuffer` command
ahead of that job to bind the tile buffer.
[Asahi queue creation](https://github.com/AsahiLinux/linux/blob/asahi/drivers/gpu/drm/asahi/file.rs#L930-L984) ·
[Asahi queue publication](https://github.com/AsahiLinux/linux/blob/asahi/drivers/gpu/drm/asahi/workqueue.rs#L506-L535) ·
[Asahi tile-buffer binding](https://github.com/AsahiLinux/linux/blob/asahi/drivers/gpu/drm/asahi/queue/render.rs#L940-L968)

## Compute

| Submission | Neo | M5 |
| --- | --- | --- |
| First compute | Descriptor → setup → event | The shim emits setup → descriptor → event. Hardware also passed with Neo's order. |
| Retained queue | The independent-queue path emits descriptor → event when setup is unnecessary. The default compute-only path still emits setup. | The tested same-queue continuation emits descriptor → event. |

The item selectors are `0x03` for the compute descriptor, `0x0f` for
setup, and `0x0e` for the event. The publisher advances the inner ring by
the actual item count, writes the outer channel slot with that work
limit, exposes the producer indices, and sends compute doorbell
`0x008300000000000a` on endpoint `0x21`. The setup item and the
first-use flag in the outer slot are separate inputs.

The cold M5 A/B test swapped only the first two item-ring pointers.
Readback before the kick confirmed each order. Both orders retired all
three entries, signaled the fence, and produced the exact 16 KiB output
page. Submissions two and three on the same queue also passed with the
existing two-item continuation. This test covered the cold first job
and its continuation on the same queue.
[M5 first compute](../proxyclient/m1n1/drm_shim/g17g_submit.py) ·
[M5 compute continuation](../proxyclient/m1n1/drm_shim/g17g_compute_queue.py)

## First render

Neo stages the first real draw, arms completion tracking, releases the
fragment and tiling work producers, and sends `0x0083000000000008`.
The tested M5 variant used that same firmware-visible flow after M5's
normal startup.

1. Keep the M5 render mappings, support objects, queue records, and
   descriptors. Fill the tiling and fragment item rings with the real draw
   and stage the corresponding outer work-channel entries.
2. Snapshot completion state and expose the work on channels 6 and 7.
3. Leave the service ring at its startup cursor of 1. Skip the stock
   first-render service sequence of six `0x1a` records and one `0x20`
   address-table registration, their seven `0x0084000000000011` kicks,
   and the wait for a type-13 receipt.
4. Send one render kick `0x0083000000000008` on endpoint `0x21`.
   If firmware asks for tile vertex buffer (TVB) growth, service the
   requests through the normal service-ring path. Its `0x0084000000000011`
   reply kicks come after the render kick.
5. Validate execution completion and both queue retirements before
   signaling the fence.

The stock M5 protocol exposes the draw before issuing its registration
kicks. Small draws have completed during that sequence, before the
explicit render kick. A separate experiment kept the seven registration
records but withheld both work producers. The service records retired,
the type-13 receipt stayed absent, and releasing and kicking the draw
afterward still timed out. Skipping the registration sequence entirely
was the successful variant.
[Stock M5 first render](../proxyclient/m1n1/drm_shim/g17g_mixed_runtime.py) ·
[M5 TVB service](../proxyclient/m1n1/drm_shim/g17g_tvb_runtime.py)

| Cold M5 test | Result |
| --- | --- |
| Direct 2× MSAA clear, two cold boots | The first render kick retired both queues and signaled the fence. The five color, depth, stencil, and guard pages matched byte for byte. |
| Direct eight-target draw, two cold boots | Firmware issued 12 TVB growth requests after the render kick. The pool grew from 3 to 123 blocks, both queues retired, and the fence signaled. All 512 KiB across eight render targets matched the expected digests. |
| Stock eight-target control | The registration receipt arrived. The workload completed with the same growth and exact output. |

The direct MSAA runs used the fixture's clear resource and compiler
support mappings. An earlier trial without them faulted at a missing
mapping. The stock MSAA control filled the expected output pages but
also reported a firmware crash before signaling the fence.

## Driver implications

Share the queue lifetime, publication ordering, and render doorbell
flow. Supply the M5 firmware mappings, queue and item encoders, TVB
reply handling, and completion checks through the firmware backend.
Neo's render item order and M5 queue re-registration were outside these
tests. The published shim still implements its stock sequence. The
direct variants were exercised in a lab harness on real hardware.
