# T8140/G17P Firmware ABI Specification

## Scope

This document describes the clean-room firmware ABI required to start and drive
the T8140 G17P GPU. It is an implementation reference, not a history of the
experiments used to establish the ABI.

Every statement below has been exercised on hardware unless it is explicitly
marked **unknown**. An unknown scalar may be carried as an opaque platform
constant. An unknown pointer, size, ownership transition, or publication gate is
not considered harmless and is called out separately.

The notation is:

- All integers are little-endian.
- Offsets and addresses are hexadecimal.
- `DVA` means a GPU device virtual address.
- `FW DVA` means an address in the sign-extended firmware-high address space.
- `client DVA` means an address in a client UAT context.
- Unless stated otherwise, objects are initially zero outside listed fields.
- A field described as firmware-owned must not be reset while firmware can still
  reference its containing object.

The current implementation model is in:

- `proxyclient/m1n1/agx/g17p.py`
- `proxyclient/m1n1/agx/g17p_initdata.py`
- `proxyclient/m1n1/agx/g17p_submission.py`
- `proxyclient/m1n1/agx/g17p_compute.py`
- `proxyclient/m1n1/agx/g17p_render.py`
- `proxyclient/m1n1/agx/g17p_encoder.py`
- `proxyclient/m1n1/agx/g17p_source_topology.py`

Those files are useful executable serializers. This document defines the object
graph and lifecycle that those serializers implement.

### Source-only cold-boot boundary

The production proof path does not open a trace closure, snapshot metadata, or
captured page image at runtime.  `g17p_source_topology.py` is the executable
description of the address-only topology required by the first partial render.
It contains DVA runs, PTE attribute bits, root context tags, prescribed physical
addresses, and intentional physical aliases.  It contains no page bodies or
firmware objects.  Every destination page is freshly allocated or cleared and
then filled by the object serializers in this specification.

The strict first-partial topology has only these initial hardware root slots:

| Slot | Context tag | Leaf inventory | Role |
|---:|---:|---:|---|
| 0 | 0 | 299 pages | context-0 low aliases |
| 1 | 64 | 626 pages | firmware-high bootstrap graph |
| 2 | 1 | 2,241 pages | client/render graph for the first partial command |

The prescribed tree roots are context 0 at physical `0x10034bcc000`, render
low at `0x10057ba0000`, and firmware high at `0x10021598000`.  Seventeen table
locations are native placement requirements: three for context 0, nine for
render low, and five for firmware high.  Four additional firmware-high tables
needed by the live source graph are allocated and linked by the driver.  The
source inventory also describes 661 firmware-high DVA leaves and their native
physical placement, including one intentional physical alias.  A Linux driver
may encode the same runs in generation data rather than copying the Python
tables, but it must preserve every address, attribute, context tag, alias, and
publication transition.

The first-work transition is temporal, not merely a static mapping.  Initdata
and the opening control use the source firmware-high tree.  Before publishing
the first TA/fragment producers, hardware context slot 0 receives the empty
high root at physical `0x10034bc8000` and slot 1 receives the empty high root at
`0x10057b9c000`; the bootstrap firmware root remains live off-table for
firmware-owned references.  The one-record primary scheduler page is published
before the ordered fragment-then-TA work producers.  Cache cleans and barriers
around each transition follow the rules in *Memory Ordering And Cache Rules*.

The known first-partial workload separately supplies 43 explicit 16 KiB
caller/compiler payload pages.  They are checksummed shader, resource, and
command input for this one userspace recipe, not firmware state and not a
substitute for a G17 userspace compiler.  They are classified as caller payload
by the zero-capture audit.  All initdata, queue, descriptor, scheduler, control,
translation, and completion objects remain source constructed.

## Architecture

G17P has two firmware instances:

| Instance | ASC node | Role |
|---|---|---|
| Primary | `/arm-io/gfx-asc` | Work scheduler, device control, TA, fragment, and compute queues |
| Secondary | `/arm-io/gfx1-asc` | Control-only peer required for the primary to operate |

The secondary is not a second GPU. It participates in bring-up and control. The
primary and secondary roots are separated by `0x8000`; their private shared
regions are separated by `0x40000`. Firmware-high mappings above top-level entry
2 must be installed in both instances' translation roots.

The host must start the secondary/control-only instance first, then the primary.
Both must remain healthy. Artificially advancing secondary counters is not a
replacement for the work performed by that firmware.

### Address spaces

The firmware uses 16 KiB UAT pages and three levels below the root:

| Level | Index shift | Entries | Table size |
|---|---:|---:|---:|
| 1 | 36 | 64 | `0x4000` |
| 2 | 25 | 2048 | `0x4000` |
| 3 | 14 | 2048 | `0x4000` |

Firmware addresses use 43 significant VA bits. A firmware-high address is sign
extended from bit 42. `0xffffffffffffffff` is a sentinel, not an address.

Objects fall into three categories:

1. Firmware-high objects, read by the schedulers and usually mapped Shared,
   writable, and visible through both firmware roots where required.
2. Client-context objects, including shaders, resources, render targets, CDM or
   VDM streams, and render-context state.
3. Aliased objects, where one physical page has both a client DVA and an FW DVA.
   The two main-config region-view pairs, queue-context pages, descriptor register
   views, and several support objects require this relationship.

Do not synthesize a high address by combining the high bits of one pointer with
the low bits of another. Several packed fields contain an unaligned full FW DVA
beside a low 32-bit client address; they are different encodings.

## Startup Sequence

Starting from a powered-off GPU:

1. Read register windows, carveouts, performance ladders, and platform constants
   from the ADT. Do not replace ADT-defined sizes or addresses with inferred ones.
2. Power the required GPU blocks and map all register windows declared to
   firmware. Host software must not directly read windows that are unsafe for the
   CPU.
3. Create 16 KiB UAT roots. Install client mappings, shared FW mappings, and all
   required low/high aliases. Mirror shared FW mappings into both firmware roots.
4. Allocate and initialize the complete initdata graph below.
5. Write zero to SGX register offset `0xd06030`.
6. Stage one opening device-control record before publishing initdata.
7. Boot the secondary firmware and send its endpoint `0x20` initdata message.
8. Wait for secondary acknowledgement and peer progress.
9. Boot the primary firmware and send its endpoint `0x20` initdata message.
10. Send the control-start notification only after the descriptor handoff is
    acknowledged. The start notification has a zero low payload.
11. Service report/control traffic and publish work through endpoint `0x21`.

Cache-clean every host-written object before making it reachable. Publish a
producer only after its payload and slot are visible.

## Mailbox ABI

A mailbox word is:

```text
63             56 55             48 47                         0
+----------------+-----------------+-----------------------------+
|     unused     | message type    | address or message payload  |
+----------------+-----------------+-----------------------------+
```

The type is bits 48..55, not 56..63.

| Endpoint | Type | Meaning |
|---:|---:|---|
| `0x20` | `0x81` | Initdata handoff; low 48 bits are root FW DVA |
| `0x20` | `0x89` | Start device-control service; low payload is zero |
| `0x20` | `0x84` | Control completion/acknowledgement |
| `0x21` | `0x83` | Work doorbell; inspect published work rings |
| `0x23` | peer traffic | Firmware-to-firmware control traffic |

One primary `0x83` doorbell is sufficient after a correctly ordered publication.
The low payload may carry observed message state, but no second wake-up doorbell
is required.

## Initdata Object Graph

### Initdata root

Primary size is `0xb8`; secondary size is `0xc8`.

| Offset | Type | Ownership | Meaning |
|---:|---|---|---|
| `0x00` | `u16[4]` | host | Version tuple; T8140 value `{0x04c0,0x0396,0xa322,0x0c8a}` |
| `0x08` | `u64` | host | FW DVA of shared 16 KiB region A |
| `0x10` | `u64` | host | Zero at handoff; semantics unknown |
| `0x18` | `u64` | host | FW DVA of main configuration |
| `0x20` | `u64` | host | FW DVA of region C |
| `0x28` | `u32` | host | Instance kind: 0 primary, 1 secondary |
| `0x2c` | `u32` | host | Constant 1 |
| `0x30` | `u16` | host | Page size, `0x4000` |
| `0x32` | `u8` | host | Page bits, 14 |
| `0x33` | `u8` | host | Level count, 3 |
| `0x34` | level descriptor[3] | host | UAT geometry |
| `0xa8` | `u64` | host | Status A FW DVA |
| `0xb0` | `u64` | host | Status B FW DVA |
| `0xb8` | `u64` | host | Secondary-only extra object 0 |
| `0xc0` | `u64` | host | Secondary-only extra object 1 |

### UAT level descriptor

Size `0x20`.

| Offset | Type | Value |
|---:|---|---|
| `0x00` | `u8` | 8 |
| `0x01` | `u8` | 14 |
| `0x02` | `u8` | 14 |
| `0x03` | `u8` | index shift |
| `0x04` | `u16` | entry count |
| `0x06` | `u16` | `0x4000` |
| `0x08` | `u64` | 1 |
| `0x10` | `u64` | physical mask `0x000003ffffffc000` |
| `0x18` | `u64` | `(entry_count - 1) << index_shift` |

### Main configuration

Size `0x600`. Offsets are relative to the object, which need not be page aligned.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | Hardware-data object FW DVA |
| `0x08` | `u64` | Writable repeated-region FW DVA |
| `0x10` | `u64` | Same repeated-region FW DVA |
| `0x20` | channel entry[17] | Channel table |
| `0x254` | unaligned `u64[5]` | Five views into the hardware-data bundle |
| `0x2d0` | `u64[6]` | Region views: high-only sentinel, two low/high physical-alias pairs, null |
| `0x300` | `u32` | Secondary only: 4 |
| `0x3e0` | `u32` | Primary only: `0xff` |
| `0x471` | unaligned `u64` | Secondary-only pointer into view 2 |
| `0x4c0` | `u32` | Primary `0x16`; secondary `0x2a` |

The primary populates all work channels. The secondary leaves channel entries
0..11 empty and receives only control/report channels. The five bare addresses
are views into one contiguous allocation; they are not independent blank pages.
The allocation is at least `0x10000`, although its principal bundle is `0xc000`.
The repeated writable region is at bundle base + `0xc500`.

The six qwords at `0x2d0` must retain their alias relationships. The first is a
high-only blank sentinel; qwords 1/2 and 3/4 are low/high aliases of two physical
pages; qword 5 is zero.

The five bundle views have logical extents `0x18c0`, `0x0c80`, `0x3c00`,
`0x3380`, and `0x3300`. They contain sparse platform data but no pointers. Their
exact nonzero runs are the `MAIN_ADDR_OBJECTS` table in `g17p.py`. They must be
views of the common bundle at offsets `0x2740`, `0x3380`, `0x4400`, `0xbc80`,
and `0xbd00`; allocating five unrelated objects breaks the overlap and offset
relations used by firmware.

### Channel table entry

Size `0x20`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | State counter address 0 |
| `0x08` | `u64` | State counter address 1 |
| `0x10` | `u64` | State counter address 2 |
| `0x18` | `u64` | Ring base |

Entries 0..11 are ordered `TA_0`, `3D_0`, `CL_0`, `TA_1`, `3D_1`,
`CL_1`, through `TA_3`, `3D_3`, `CL_3`. Entry 12 continues the compact
control-state grid. Entries
13 and 14 are report channels with split state objects. Entry 15 is partial and
contains only its first state address. Entry 16 is empty.

For a work channel, state 0 is the consumer and state 2 is the producer. The
three addresses are separate 32-bit counters at `0x10` spacing; do not collapse
them into one state object.

### Hardware-data object

Size `0x3db4`. This object combines register mappings, ADT-derived performance
data, channel configuration, region records, and opaque platform constants.

#### Register mapping entry

Array starts at `0x640`, contains 53 entries, and has stride `0x28`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | Physical register-window base |
| `0x08` | `u64` | Firmware device VA |
| `0x10` | `u32` | Window size |
| `0x14` | `u32` | Duplicate window size |
| `0x18` | `u64` | Opaque scalar, normally zero |
| `0x20` | `u32` | Mapping/declaration flag |

Declared-but-unmapped slots carry only the flag. Register windows come from the
ADT. The current FW DVA register aperture is `0xfffffc2180000000` through
`0xfffffc2190000000`.

#### Performance tables

Each ladder has 11 `u32` entries.

| Offset | Layout |
|---:|---|
| `0xfc8` | Frequency ladder A and first per-state block group |
| `0x1008` | Core-voltage column, block stride `0x40`, value repeated 16 times |
| `0x1408` | Memory-voltage column, same block layout |
| `0x1808` | Frequency ladder B |
| `0x1848` | Scale ladder B |
| `0x18c8` | Relative ladder A |
| `0x1908` | Relative ladder B |
| `0x19c8` | Index map A |
| `0x1a08` | Index map B |
| `0x1cdc` | Frequency ladder B copy and second per-state block group |
| `0x1d1c` | Core-voltage column, one value per block |
| `0x211c` | Memory-voltage column, one value per block |

`u32` chip ID is at `0xe90`.

#### Required channel block

| Offset | Type | Value |
|---:|---|---|
| `0x258e` | `u16` | Work-channel count, 12 |
| `0x2590` | `u32[4]` | `{0,1,1,1}` |
| `0x25a0` | `u32[4]` | `{0,1,1,1}` |
| `0x25b4` | `u32[12]` | All `0xffffffff` before assignment |
| `0x25f4` | `u32` | 1 |
| `0x2600` | `u32` | 1 |
| `0x2608` | `u32` | 1 |

#### Hardware region record

Records begin at `0x2610`, stride `0x40`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u32` | Record-specific lead |
| `0x04` | `u32` | Region value |
| `0x08` | `u32` | Constant `0x70` |
| `0x0c` | unaligned `u64` | Region FW DVA |
| `0x14` | `u32` | `0x800` |
| `0x18` | `u32` | `0x40` |
| `0x1c` | `u32` | Record-specific trail |

T8140 uses two records, each naming a 16 KiB region. Their
`(lead, value, trail)` values are `(0x100,0x1848000,0)` and
`(0,0x1870000,2)`.

The remaining 269 nonzero bytes are opaque T8140 platform constants. They are
not addresses, sizes, or live counters. Their exact sparse runs are the
`HWDATA_CONSTANTS` table in `g17p_initdata.py`; the host must supply those values
until their ADT derivation is established. Offset `0x2630` is firmware state and
must start zero.

### Region C

Size `0x1000`. Region C is a sparse platform-tuning object. Its 180 nonzero
bytes are the exact `REGION_C_CONSTANTS` runs in `g17p_initdata.py`; all other
bytes start zero. Offset `0xe50` must contain `0x00000100` before the first
compact class-1 registration. Leaving it zero causes an asynchronous primary
firmware SError while processing device-control opcode `0x20`.

### Status block

Size `0x80`.

| Offset | Type | Pre-init | Post-ack |
|---:|---|---:|---:|
| `0x04` | `u32` | 1 | 1 |
| `0x10` | `u32` | 0 | 1 |
| `0x14` | `u32` | 0 | 1 |

The primary status-B pointer names a larger status/config object, not merely this
prefix. It contains FW-control state/ring pointers at `0x48e0` and `0x48e8`, a
three-word pre-init lifecycle header at `0xe434`, and sparse configuration from
`0xe440`. The configuration is firmware-visible platform state and must remain
valid for the firmware lifetime.

### Primary compute-dispatch record

The second `0x20`-byte record in the primary dispatch-record page is required
for compute execution. It contains five `u32` values at offsets `0x00..0x10`:

```text
e0000000 08000000 00000000 00002a00 00001500
```

The remaining `0x0c` bytes are zero. The scalar meanings are unknown, but none
is an address. Queue retirement without this record does not establish compute
execution.

## Device-Control ABI

A device-control ring contains 256 records of `0x40` bytes. The leading `u32`
is the opcode; fields not defined for an opcode are zero. The opening ring is
staged before initdata publication and contains one record:

| Instance | Opening opcode |
|---|---:|
| Primary | `0x16` |
| Secondary | `0x2a` |

The opening producer is 1. Notify firmware once with type `0x89` and low payload
zero. Regular operation uses the observed `0x2e` control cadence and compact
opcode `0x20` registrations for compute resource classes. A compact `0x20`
registration is one-shot; do not resubmit the same registration object as if it
were an idempotent command.

## Work Transport

### Work-channel ring slot

Each of 12 work channels owns 256 slots. Slot size is `0x18`; ring size is
`0x1800`. Producer and consumer are 8-bit wrapping values held in 32-bit words.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | Zero |
| `0x08` | `u64` | Command queue FW DVA |
| `0x10` | `u32` | Kind: 0 TA, 1 fragment, 2 compute |
| `0x14` | `u32` | Packed head/grid/first-submit field |

The packed field is:

- bits 0..15: queue write head;
- bits 16..23: queue-grid index;
- bit 24: first submission on this queue;
- bits 25..31: zero.

Queue grid index is `(pair << 2) | kind`, where kind 0 is TA, 1 is fragment,
and 2 is compute. The ring slot index and queue item index are separate wrapping
namespaces.

### Command queue record

Allocation stride and size are `0xc0`; fields through `0xab` are meaningful.

| Offset | Type | Ownership | Meaning |
|---:|---|---|---|
| `0x00` | `u64` | host | Queue pointer block |
| `0x08` | `u64` | host | Item-pointer ring |
| `0x10` | `u64` | host | Intrusive job-list head |
| `0x18` | `u32` | firmware | Read pointer 1, initially 0 |
| `0x1c` | `u32` | firmware | Read pointer 2; mirrors done |
| `0x20` | `u32` | firmware | Read pointer 3, initially 0 |
| `0x24` | `s32` | host | Event ID, initially -1 |
| `0x28` | `u32` | host | Priority profile field 0 |
| `0x2c` | `u32` | host | Priority profile field 1 |
| `0x30` | `u64` | host | Priority mask/sentinel |
| `0x38` | `u32` | host | Priority profile field 3 |
| `0x3c` | `u32` | host | Zero |
| `0x40` | `u32` | host | Priority profile field 4 |
| `0x44` | `s32` | host | -1 |
| `0x48` | `u32` | host | Queue UUID |
| `0x4c` | `u32` | mixed | Opaque |
| `0x50` | `u64` | mixed | Opaque |
| `0x58` | `u32` | firmware | Busy state |
| `0x78` | `u32` | mixed | Opaque |
| `0x7c` | `u32` | host/firmware | `has_commands`; not required as a gate |
| `0x90` | `u32` | firmware | Inflight count/state |
| `0x94` | `u32` | mixed | Per-queue counter |
| `0x98` | `u32` | host | Version-gated zero on T8140 |
| `0x9c` | unaligned `u64` | host | Per-queue context FW DVA |

`has_commands` may remain zero: firmware consumes a correctly published group
without a clear-to-set transition. It is not proof of work execution.

The five priority-dependent fields form one indivisible profile inherited from
the older `CommandQueueInfo::set_prio()` layout, shifted eight bytes earlier by
G17P's removed `gpu_buf_addr`.  The Linux UAPI profiles proven by exact output
on both TA and fragment queues are:

| Linux priority | `+0x28` | `+0x2c` | `+0x30` | `+0x38` | `+0x40` |
|---|---:|---:|---:|---:|---:|
| LOW (0) | 0 | 0 | `0xffffffffffff0000` | 1 | 1 |
| MEDIUM (1) | 1 | 1 | `0xffffffff00000000` | 0 | 0 |

Program all five fields while the transport queue is idle, before publishing
the next item.  Changing only `+0x28` does not construct a valid priority.

### Queue pointer block

Nominal size `0x60`, normally allocated at least `0x80`.

| Offset | Type | Ownership | Meaning |
|---:|---|---|---|
| `0x00` | `u32` | firmware | Done index |
| `0x10` | `u32` | firmware | Opaque |
| `0x20` | `u32` | firmware | Opaque |
| `0x30` | `u32` | firmware | Read index |
| `0x40` | `u32` | host | Write index |
| `0x50` | `u32` | host | Ring-size value, `0xffffffff` |
| `0x60` | `u32` | host | Created queues use `0x500`; outside nominal prefix |

Indices are monotonically increasing logical positions. Physical item-ring
access wraps by capacity. A fence captures the immutable logical prefix after a
command's entries; it must not follow the queue's moving write pointer.

### Item ring

The item ring is an array of `u64` FW DVA pointers. A submission group contains:

- work descriptor, optional selector `0x0f`, event selector `0x0e`; or
- work descriptor, event selector `0x0e`.

The event terminates the group. Compute and current render paths use three items.
An inner batch representation is therefore three consecutive `u64` FW DVAs:
descriptor, optional item, and event item. Its size is `0x18` per work item.

### Intrusive job-list head

Size `0x18`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | First job or zero |
| `0x08` | `u64` | Last/link; points to this head when empty |
| `0x10` | `u64` | Opaque |

### Event item

Allocate `0x400`; records are `0x40`. The host writes only the first record and
firmware appends state.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u32` | Selector `0x0e` |
| `0x04` | `u32` | `0x00010000 | queue_grid_index` |
| `0x08` | `u32` | Group number shifted left 8 |
| `0x10` | `u32` | 0 TA, `0x100` fragment, `0x200` compute |

### Common publication order

For one submission:

1. Construct all work descriptors, command streams, resources, support objects,
   event record, and queue-context record.
2. Write the three item FW DVAs into consecutive item-ring entries beginning at
   the current logical write index.
3. Update host-owned queue and context fields without overwriting retained
   firmware state.
4. Clean every payload and item-ring cache line.
5. Execute a completion barrier.
6. Advance the queue write index to the immutable post-group prefix; clean it.
7. Fill the next channel-ring slot with queue DVA, kind, head, grid index, and
   first-submit bit; clean it.
8. Execute a completion barrier.
9. Advance channel state 2 producer last, wrapping modulo 256; clean it.
10. Execute a completion barrier.
11. Send one primary endpoint `0x21`, type `0x83` work doorbell.

The consumer reaching the producer and queue pointers advancing prove parsing or
retirement, not shader execution. Only expected target bytes prove execution.

## Common Work-Item Structures

### Register entry

Register programs are ordered arrays of `0x0c` records. Duplicate register IDs
are legal and order is significant.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u32` | Register number |
| `0x04` | `u64` | Register value |

Capacity is 128 records in each known descriptor register region.

### Render pool A

35 records, stride `0x100`.

| Offset | Type | Value |
|---:|---|---|
| `0x00` | `u64` | `slot_base + record_index * 4` |
| `0x10` | `u32` | First record only: `0x50` |

### Render pool B

79 records, stride `0x80`.

| Offset | Type | Value |
|---:|---|---|
| `0x00` | `u32` | `0x80004 + pair*0x140 + record*4` |
| `0x04` | `u32` | `0x10` |
| `0x08` | `u64` | `slot_base + pair*0x140 + record*4` |
| `0x28` | `u32` | 36-entry cycle from `0x178020`, step `0x20`, wrap value `0x178000`, plus pair `*0x5e0000` |
| `0x40` | `u64` | Shared-object FW DVA |
| `0x4c` | `u32` | First record only: 1 |

Pool indices wrap independently by their capacities.

### Packed shared object

Size `0x88`.

| Offset | Type | Meaning/value |
|---:|---|---|
| `0x0c` | `u32` | Pair or context index |
| `0x20` | `u64` | Leaf pointer 0 |
| `0x28` | `u32` | `0x00190000 + (pair*0x5e << 16)` |
| `0x2c` | `u32` | `0x10` |
| `0x30` | `u32` | `0x10000` |
| `0x34` | `u32` | Group count * 4 |
| `0x38` | `u32` | `0x0c18` |
| `0x3c` | `u32` | Group count |
| `0x44` | unaligned `u64` | Leaf pointer 1 |
| `0x4c` | unaligned `u64` | Leaf pointer 2 |
| `0x54` | `u32` | Group count * 4 - 1 |
| `0x58` | `u32` | `0x20000` |
| `0x64` | unaligned `u64` | Leaf pointer 3 |
| `0x7c` | `u32` | `0x3060` |
| `0x80` | `u32` | `0x1020` |
| `0x84` | `u32` | `0x00180000 + (pair*0x5e << 16)` |

The fourth descriptor object is an all-zero `0x100`-byte object.

### Submission leaf pages

Six 16 KiB pages are directly named by the pools/shared object:

| Page | Host initialization |
|---|---|
| Primary index | Four consecutive `u32` values for each of 32 index groups |
| Secondary index | One `u64` group base per group |
| Pool-A slots | `u32 2` at `0x04` |
| Pool-B slots | Zero |
| Shared slots | group count at `0x00` and `0x04`; `u32 1` at `0x60` |
| Flag | `u32 1` at `0x00` |

Default group ranges are six groups from `0x11` and 26 from `0x4a`, each group
advancing by five; each pair adds `0xbc`. Context 2 uses six groups from `0x11`
and two from `0x3c`.

## Render ABI

A render command is a paired TA and fragment submission. The host may serialize
engines for correctness, but each stage has its own queue, channel, descriptor,
event, and completion prefix.

### TA descriptor

Selector 0; allocation/record size `0x9c0`, with host-defined content through
at least `0x94d`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u32` | Selector 0 |
| `0x04` | unaligned `u64` | Submit sequence; TA values are odd |
| `0x0c` | `u32` | Context identity |
| `0x10` | `u64` | Pool-A record |
| `0x20` | `u64` | Packed shared object |
| `0x28` | `u64` | Pool-B record |
| `0x30` | `u64` | Zero shared object |
| `0x18`, `0x304` | `u32` | Queue-pair index |
| `0x48` | `u32` | Work ordinal |
| `0x60` | register entry[] | Ordered TA register program |
| `0x370`,`0x37c`,`0x388` | `u32` | `0x100 + work_ordinal` |

`work_ordinal = submission_ordinal + floor(submission_ordinal / 2)`. TA submit
sequence is `1 + 2*item_index`.

The TA structural tail also contains the following host-written fields. `self`
is the low alias of this descriptor; `pair_slot` advances eight bytes per queue
pair; `status` advances `0x40` per pair-local record.

| Offset | Type | Meaning/value |
|---:|---|---|
| `0x760` | `u64` | Low self alias |
| `0x768` | `u32` | `0x036c0049` |
| `0x780` | `u64` | `0x1000240000` |
| `0x789` | `u8` | `0x78` |
| `0x7d6` | `u32` | Low 32 bits of deflake address |
| `0x876` | `u32` | `0xffffffff` |
| `0x892` | `u8` | 1 |
| `0x8a6` | unaligned `u64` | Dispatch pair-slot A |
| `0x8ae` | unaligned `u64` | Dispatch pair-slot B |
| `0x8ba` | scalar | TA grid field |
| `0x8fe` | `u64` | Shared status address |
| `0x932` | `u8` | `0x44` |
| `0x934` | `u64` | Shared control address |
| `0x93c` | `u8` | 1 |
| `0x945` | unaligned `u64` | Pair-local status record |
| `0x94d` | `u8` | 1 |

### Fragment descriptor

Selector 1; allocation/record size `0x2240`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u32` | Selector 1 |
| `0x04` | unaligned `u64` | Submit sequence; fragment values are even |
| `0x0c` | `u32` | Context identity |
| `0x20` | `u64` | Pool-A record |
| `0x28` | `u64` | Packed shared object |
| `0x30` | `u64` | Pool-B record |
| `0x38` | `u64` | Zero shared object |
| `0x40` | `u64` | Mirrors tile-map register `0x16429` |
| `0x48` | `u64` | Mirrors multisample register `0x10019` |
| `0x54` | `u32` | Mirrors macro-tile dimensions register `0x100b1` |
| `0x68` | `u32` | Mirrors merge-X register `0x15131` |
| `0x6c` | `u32` | Mirrors merge-Y register `0x15139` |
| `0x78` | `u64` | Total tile count |
| `0xa0` | register entry[] | Ordered fragment register program |
| `0x458` | `u32` | Queue-pair index |
| `0x470`,`0x47c` | `u32` | `0x100 + work_ordinal` |

Fragment submit sequence is `2*item_index`.

The fragment structural tail contains four repeated subrecords based at
`0x7a0`, `0xec0`, `0x15e0`, and `0x1d00`. Each writes a record-specific first
word at `base+0x08`, `0x16020` at `base+0x20`, `0x16068` at `base+0x2c`, and
`u8 4` at `base+0x32`. It also carries:

| Offset | Type | Meaning/value |
|---:|---|---|
| `0x7a0`,`0xec0`,`0x15e0`,`0x1d00` | `u64` | Low self aliases to four internal regions |
| `0x1d20` | `u64` | Depth-bias array |
| `0x1d30` | `u64` | Scissor array |
| `0x1e78` | `u64` | Load-pipeline bind |
| `0x1e80` | `u64` | Load pipeline |
| `0x1ea8` | `u64` | Partial-render load-pipeline bind |
| `0x1eb0` | `u64` | Partial-render load pipeline |
| `0x1ec0` | `u32` | `0x04040404` |
| `0x1f38` | `u64` | TIB block count |
| `0x1f40` | `u64` | Auxiliary-framebuffer flags |
| `0x1f48`,`0x1f4c` | `u32` | Width, height |
| `0x1f50` | `u64` | Auxiliary-framebuffer page count |
| `0x1f58` | `u64` | Tile config |
| `0x1f7c` | `u64` | Store pipeline |
| `0x1f9c` | `u64` | Partial-render store pipeline |
| `0x1fa8` | `u32` | Depth clear value bits |
| `0x2140`,`0x2148` | `u64` | Dispatch pair-slots A/B |
| `0x2198`,`0x21a0` | `u64` | Shared status A/B |
| `0x21ce` | unaligned `u64` | Shared control address |
| `0x21df` | unaligned `u64` | Pair-local status record |

The remaining one-byte flags and body constants are fixed by `BODY_FIELDS` and
`_write_structural_tail()` in `g17p_backend.py`. They are opaque scalars, not
hidden pointers.

The ordered register programs carry dimensions, tile geometry, VDM stream,
tilemap and heap addresses, pipeline program/bind addresses, scissor/depth-bias
arrays, depth/stencil and auxiliary buffers, status addresses, and lifecycle
stamps. They are serialized exactly by `build_tiling_registers()` and
`build_fragment_registers()` in `g17p_render.py`. Register arrays must remain
ordered and retain duplicates.

### Uncompressed depth/stencil load and store

The following `ZLS_CTRL` bits are functionally established on G17P:

| Bit | Meaning |
|---:|---|
| 2 | Depth load uses compression metadata |
| 4 | Stencil load uses compression metadata |
| 6 | Depth store produces compression metadata |
| 8 | Stencil store produces compression metadata |
| 14 | Load stencil at tile start |
| 15 | Load depth at tile start |
| 18 | Store stencil at tile end |
| 19 | Store depth at tile end |

The depth and stencil base registers accept ordinary caller-owned GPU virtual
addresses. `ISP_ZLS_PIXELS` packs the surface dimensions as
`(width - 1) | ((height - 1) << 15)`. `ISP_BGOBJDEPTH` carries the raw 32-bit
depth clear value in the selected depth format. The low eight bits of
`ISP_BGOBJVALS` carry the stencil clear value.

With a 64x64 float-depth surface and an 8-bit stencil surface, setting only the
two store bits wrote exact uniform clear images to both caller buffers. Setting
all four load/store bits preserved independently initialized depth and stencil
images exactly. This establishes real ZLS memory access; command retirement is
not used as its witness.

Compression metadata bases are independent caller-owned GPU virtual addresses.
A compressed store of uniform float depth and 8-bit stencil changed both main
buffers and 128 bytes in each metadata page. Loading that representation with
the compressed-load bits and storing it without the compressed-store bits
expanded it to the exact expected ordinary depth and stencil images. The driver
does not interpret the compression codec; it retains and maps the main and
metadata allocations and forwards their addresses and control bits.

Depth and stencil mappings are writable command resources. The UAPI attachment
array is only an optional scheduling hint and is not a complete write set, so a
synchronous prototype must copy back every writable binding rather than only
listed color attachments.

The main depth/stencil layer stride is packed as
`((stride_in_16KiB_pages - 1) << 14) | 1`. Compression metadata uses
`(stride_in_128B_cache_lines - 1) << 14`; consequently, a metadata stride value
of zero encodes one cache line rather than an absent stride. Three-layer
rendering with independently initialized pages produced exact color, depth, and
stencil output in every layer.

`sample_size_B * samples * utile_width_px * utile_height_px` is the tilebuffer
allocation for one utile and must not exceed 32768 bytes. The firmware-visible
utile configuration is `(utile_width_px / 16) << 12 |
(utile_height_px / 16) << 14 | log2(samples)`. The standard multisample-control
patterns are `0x88` for one sample, `0x44cc` for two samples, and `0xeaa26e26`
for four samples. Exact two-sample output was observed with a 32x32 utile and
exact four-sample output with a 32x16 utile, both using an 8-byte per-sample
tilebuffer stride. A full 32768-byte tilebuffer is valid when the partial
store/reload programs and state described below are present.

### Forced partial-render pause and resume

G17P uses three additional ordered fragment register programs embedded in the
four repeated fragment-descriptor subrecords:

- the 16-write program at descriptor offset `0x07c0` stores color through
  `partial_eot` and stores the configured depth/stencil state;
- the 23-write program at `0x0ee0` supplies both `partial_eot` and `partial_bg`
  while restoring depth/stencil state for a resumed tile;
- the 10-write program at `0x1600` reloads color through `partial_bg` and
  restores depth/stencil state.

Their encoded headers are at `0x0ec8`, `0x15e8`, and `0x1d08`. The partial
program pointers are distinct UAPI inputs, are based at the queue's
`usc_exec_base`, and must name readable caller mappings. They must not silently
fall back to the ordinary background/end-of-tile programs.

The exact threshold for the established 128x128, eight-R32F, eight-varying,
single-tile accumulation workload is 48,217 triangles: 48,216 does not enter
the partial path, while 48,217 does. Replacing only the partial-background
reload resource block with the command's valid clear block leaves the command
fault-free but reduces the result from approximately `1..8` to only the final
segment. This is the semantic negative proving that the reload program is
reached.

A cold first command built entirely from the public render command, generated
encoder/register programs/submission objects, and its own compiler payload
produced the complete `1..8` accumulation in all eight independent physical
attachments. The strict live audit copied zero captured bytes or prebuilt
firmware objects. TA/fragment status and timestamps changed as secondary
witnesses, but only the complete framebuffer result is treated as execution
proof.

The eight values are intentionally floating-point results, not integer bit
patterns.  Repeated shader additions and the normalization constant produce
stable IEEE-754 rounding such as `1.0001`, `4.9975`, and `8.0008`.  The semantic
oracle requires every attachment's finite result to be within `0.02` of its
caller-selected target and rejects any finite companion outside that interval;
these bounded round-off terms are therefore expected output, not evidence of a
lost store/reload.  The reload-to-clear negative is orders of magnitude smaller
and cannot pass this oracle.

The partial state is bounded and recycled in place. At 2x, 4x, and 8x the
minimum workload, successful controlled replays changed only the same compact
records in tilemap page `0x10001b0000` and TPC page `0x10001d8000`; no
per-pause page stream was consumed. This establishes repeated pause/resume
within one render command. Reusing or replacing complete command queues is a
separate queue-lifecycle problem and must not be inferred from work-item
retirement alone.

### Render optional item

Size `0xc0`, selector `0x0f`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x08` | `u64` | Client-context scratch |
| `0x10` | `u64` | Firmware-context scratch |
| `0x18` | `u16` | Queue-grid index |
| `0x1a` | `u16` | First-submit flag; cleared on later items |
| `0x1e` | `u16` | Context ID when required |
| `0x2a` | `u16` | Later-item index |
| `0x2e` | `u16` | Later-item index shifted left 8 |
| `0x32` | `u16` | Context ID |
| `0x36` | unaligned `u64` | Shared control |
| `0x3e` | `u16` | Global submission ordinal |
| `0x4a` | unaligned `u64` | Channel control |
| `0x52` | `u16` | First-submit flag |
| `0x56` | `u16` | Context ID |
| `0x5a` | `u16` | Queue UUID, default `0xa6` |
| `0x5e` | `u16` | Context ID |
| `0x62` | `u16` | First-submit flag |
| `0x66` | `u16` | Constant 1 |
| `0x6e` | unaligned `u64` | TA only: packed shared object |
| `0x76..0x85` | bytes | Fragment: 16 bytes of `0xff` |

The TA form also carries ordinal/pair/grid scalars at `0x76`, `0x7e`, and
`0x82`. Initial TA constants are `1` at `0x1a`, `0x26`, `0x32`, `0x52`,
`0x5e`, `0x62`, `0x66`, and `0x82`, with UUID `0xa6` at `0x5a`. Initial
fragment constants are `1` at `0x18`, `0x1a`, `0x22`, `0x26`, `0x32`,
`0x52`, `0x5e`, `0x62`, and `0x66`, with UUID `0xa6` at `0x5a`.

### Render queue-context item

Items have a `0x200` logical stride; the host-written body is `0x180` bytes
beginning at page offset `0x200`. Descriptor and queue pointers are at item
offsets `0x10` and `0x18` (page offsets `0x210` and `0x218`). Other qwords at
item offsets `0x00`, `0x08`, `0x20`, `0x28`, `0x30`, `0x150..0x168`, and
`0x178` encode stage, grid, item index, and descriptor locators. They are
constructed from stage, pair, item index, context ID, descriptor DVA, and queue
DVA; they are not reusable page templates.

For pair zero, the page-relative qword values before dynamic pointer insertion
are:

| Page offset | TA | Fragment |
|---:|---:|---:|
| `0x200` | `0x0000000000000004` | `0x0400040000000004` |
| `0x208` | 0 | `0x004000e000130d40` |
| `0x220` | `0xffff0c0000000001` | `0xffff180000000003` |
| `0x228` | 0 | 1 |
| `0x230` | 0 | `0x0000010000000000` |
| `0x350` | `0x0002380380000003` | `0x0002b00380004c05` |
| `0x358` | 0 | `0x0000100380004c3e` |
| `0x360` | 0 | `0x0000100380004c77` |
| `0x368` | 0 | `0x0000100380004cb0` |
| `0x378` | `0x003fffffffffffff` | `0x003fffffffffffff` |

Successive item indices add stage-specific increments to these fields. In TA,
`0x200` adds 4, `0x228` adds 1, and `0x350` adds `0x9c`. In fragment,
`0x200` adds 4, `0x208` adds `0x8900`, `0x228` and `0x230` add 1, and
`0x350` through `0x368` each add `0x224`.

On reuse, update only host-owned qwords and retain firmware-owned state. The low
and FW-high queue-context addresses must alias the same physical pages.

### Tiler encoder stream

Size `0x8c`. All bound addresses are 32-bit offsets from the render context base.

| Offset | Size | Meaning |
|---:|---:|---|
| `0x00` | `0x20` | Header: flags, mode, state, class, control |
| `0x20` | `0x40` | Eight `{u32 address_offset, u32 control}` bind pairs |
| `0x60` | `0x2c` | Indexed draw record |

Header defaults are flags `0x4000002e`, mode `0x01000000`, state `0x00066000`,
class `0x00000606`, and control `0x00000500`.

Indexed draw record:

| Record offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u32` | Index-buffer context offset |
| `0x04` | `u32` | Draw config, default `0x40000001` |
| `0x08` | `u32` | Restart comparand, default `0xffff` |
| `0x0d` | `u8` | Primitive, triangle is 6 |
| `0x0e` | `u16` | Draw opcode; direct indexed16 `0x61f2`, indirect `0x6432` |
| `0x10` | `u32` | Index config, default `0x01bc0200` |
| `0x14` | direct `u32` | Index count |
| `0x18` | direct `u32` | Instance count |
| `0x1c` | direct `s32` | Base vertex |
| `0x14` | indirect `u32[2]` | Argument DVA, high word then low word |
| `0x1c` | indirect `u32` | Index extent |

The opcode at stream offset `0x6e` gates drawing. A retiring submission with a
zero opcode performs no framebuffer writes.

Indexed-indirect arguments are the public 20-byte structure:

```c
struct indexed_indirect_args {
    uint32_t index_count;
    uint32_t instance_count;
    uint32_t index_start;
    int32_t  base_vertex;
    uint32_t base_instance;
};
```

### Render-context helper pages

All are 16 KiB objects:

- Bind0: seven records, stride `0x80`; each has `u32 0x80` at `+0x00` and
  `u32 0x10040000` at `+0x40`, plus established constants at absolute offsets
  `0x2c8`, `0x344`, `0x348`, and `0x380`.
- Bind group: 23 sparse `u32` constants in the first `0x74` bytes.
- Viewport: header at `0x900`, floating-point half-width/half-height transform at
  `0x910`, and depth 1.0 at `0x924`.
- Index buffer: `u32 0x100` at `0x00` for the established indexed path.
- Auxiliary framebuffer: `{0x60000000,0x35b}` at `0x480`.

### Parameter-buffer blocks

The render parameter allocation contains eight blocks of `0x5200` bytes. Each
live render group owns one block. Firmware writes the selected block; it cannot
be rebound while live. Reuse is allowed only after semantic command completion,
then the host resets the block to its initial zero state and cleans it before
publication. If all eight blocks are live, the host must apply backpressure.

## Compute ABI

Compute uses queue kind 2 and selector 3. Direct and indirect CDM submissions
have executed repeatedly on one persistent queue, including item-ring and outer
channel-ring wrap.

### Compute descriptor

Allocate one 16 KiB page. The descriptor contains two ordered register arrays
and a packed structural tail.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u32` | Selector 3 |
| `0x04` | unaligned `u64` | Submit sequence |
| `0x0c` | `u32` | Context ID |
| `0x10` | `u64` | Scheduler record FW DVA |
| `0x18` | `u16[4]` | `{0x22,0x23,0x23,0x24}` |
| `0x40` | register entry[128] | Primary register program |
| `0x740` | `u64` | Low alias + `0x40` |
| `0x748` | `u32` | Packed primary count: `(count * 12) << 16 | count` |
| `0x760` | register entry[128] | Four-entry secondary mirror program |
| `0xe60` | `u64` | Low alias + `0x760` |
| `0xe68` | `u32` | `0x00300004`: four records and byte length |
| `0xed8` | `u64` | Resource DVA from register `0x1a510` |
| `0xee0` | `u64` | DVA of the CDM terminating word |
| `0xf08` | `u64` | Register-derived value `0x1a440` occurrence 0 |
| `0xf20` | `u32` | High 32 bits of dispatch identity `0x1a540` |
| `0xf28` | `u32` | `0xffffffff` |
| `0xf2c` | unaligned `u64` | Sampler-heap DVA, or zero |
| `0xf34` | `u32` | Sampler count, or zero |
| `0xf38` | `u32` | Sampler maximum: `count + 1`, or zero for an empty heap |
| `0xf40` | `u64` | Dispatch-state pointer A |
| `0xf48` | `u64` | Dispatch-state pointer B |
| `0xf50` | `u32` | Queue submission number shifted left 8 |
| `0xf54` | `u32` | Queue-grid index |
| `0xf58` | `u32` | Queue-local ordinal |
| `0xf60` | `u32` | Positive global submission index |
| `0xf68` | `u64` | Low 32 bits of dispatch identity |
| `0xf70` | `u32` | Work ordinal |
| `0xf7c` | unaligned `u64` | Internal 24 MHz timestamp destination A |
| `0xf84` | unaligned `u64` | Internal 24 MHz timestamp destination B |
| `0xf8c` | unaligned `u64` | Caller 1 GHz timestamp start destination |
| `0xf94` | unaligned `u64` | Caller 1 GHz timestamp end destination |
| `0xfb0` | `u16` | `0x1a` |
| `0xfb2` | unaligned `u64` | Shared-control FW DVA |
| `0xfba` | `u32` | Support control, default `0x21000001` |
| `0xfbe` | `u32` | Support flags, default 1 |
| `0xfc5` | `u8` | `0x9f` |
| `0xfc8` | `u32` | `(work_ordinal & 3) << 30` |
| `0xfcb` | unaligned `u64` | Zero-page FW DVA |
| `0xfd3` | `u8` | 1 |

The secondary register program mirrors four scratch values from the primary:

| Destination register | Source register |
|---:|---:|
| `0x10099` | `0x0a5c1` |
| `0x10091` | `0x0a5c9` |
| `0x0a5c1` | `0x10099` |
| `0x0a5c9` | `0x10091` |

Firmware consumes the primary-register count encoded at `0x748`, so the native
`0x01b00024` value describes 36 entries and is not an immutable descriptor
constant. A controlled compatibility experiment established these additional
register writes:

| Register | Meaning |
|---:|---|
| `0x10071` | Queue `usc_exec_base`, aligned to 4 GiB |
| `0x11841` | Legacy-shaped helper program value |
| `0x11849` | Legacy-shaped helper argument/data value |
| `0x11f81` | Legacy-shaped helper configuration value |

`0x10071` populated from the queue has executed on startup and post-start work.
The three helper-shaped writes are accepted when inserted after `0x1a4e8`, but
acceptance is not helper invocation. Native G17P descriptors do not emit any of
the four writes: a corpus of 61 decodable native compute items, including an
exactly executed 1024-float private-array workload, contained no `0x10071`,
`0x11841`, `0x11849`, or `0x11f81` entries. No nonzero helper execution is
therefore established for this generation. A production G17P translator uses
the proven queue-base write with zero helper values and rejects any nonzero
helper tuple before publication.

The sampler fields belong to the descriptor's encoder-parameter block, which
begins at `0xf14`. A nonempty heap must be 8-byte aligned and mapped read-only
or read/write in the command VM for at least `count * 8` bytes. The established
nonempty encoding is `{array, count, count + 1}` at `0xf2c`; an empty heap uses
three zero values. A command carrying one caller-mapped default sampler through
these fields executed and produced its exact caller-selected output.

Compute attachments are optional write-region hints, not shader arguments or
output declarations. On current G17P, no per-command firmware encoding has been
observed for them. A native add3 command with an explicit write-use declaration
executed with exact output while its resource table, CDM stream, shader/code
pages, operand-page lists, and operand table remained byte-for-byte identical
to the same command without that declaration. The descriptor's two reserved
regions at `0x640..0x73f` and `0xd60..0xe5f` remained entirely zero in both
cases. The remaining descriptor differences were context-local IDs, ordinals,
and pointers.

The host must still consume every UAPI attachment: validate that the complete
range is writable in the command VM, keep all covered bindings and BO backing
alive through terminal completion, and perform any required post-completion
cache maintenance or copyback over the hinted ranges. Omitting hints cannot
change execution because the shader and its resource graph define the actual
memory accesses. In particular, attachment zero is not implicitly the output.

`0xee0` points to the `0x40000000` terminator itself, not one byte past the CDM
stream. A malformed end pointer can retire without executing client code.

### Compute optional item

Size `0xc0`, selector `0x0f`. Its packed pointer and ordinal fields match the
render optional layout where shared. Compute-specific defaults are:

| Offset | Type | Value/meaning |
|---:|---|---|
| `0x08` | `u64` | Low/client queue-context alias |
| `0x10` | `u64` | FW-high queue-context alias |
| `0x18` | `u16` | Grid index, normally 2 |
| `0x1a` | `u16` | First-submit flag |
| `0x22` | `u16` | 2 |
| `0x2a` | `u16` | Later-item index |
| `0x2e` | `u16` | Later-item index shifted left 8 |
| `0x32` | `u16` | Context field, default 1 |
| `0x36` | unaligned `u64` | Shared control |
| `0x3e` | `u16` | Submission ordinal |
| `0x46` | `u16` | 2 |
| `0x4a` | unaligned `u64` | Channel control |
| `0x52` | `u16` | First-submit flag |
| `0x56` | `u16` | 1 |
| `0x5a` | `u16` | UUID, default `0xa6` |
| `0x5e` | `u16` | 1 |
| `0x62` | `u16` | First-submit flag |
| `0x66` | `u16` | 1 |
| `0x76..0x85` | bytes | `0xff` sentinel |

### Compute event item

Allocate `0x400`; first `0x40` bytes are host-owned initially.

| Offset | Type | Value |
|---:|---|---|
| `0x00` | `u32` | `0x0e` |
| `0x04` | `u32` | `0x00010000 | grid_index` |
| `0x08` | `u32` | `(group_number << 8) | low_counter` |
| `0x10` | `u32` | `0x200` |

### Compute queue-context record

Logical record size `0x200`; current allocation reserves eight 16 KiB pages.
Physical record offset for monotonic item `i` is
`((i + 1) % record_count) * 0x200`.

| Record offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | Flags, grid encoding, and `(item+1)*4` |
| `0x10` | `u64` | Compute descriptor FW DVA |
| `0x18` | `u64` | Queue FW DVA |
| `0x20` | `u64` | Stage/context constant, default `0xffff080100000001` |
| `0x28` | `u64` | Grid and item index |
| `0x130` | `u64` | Opaque host scalar, default 2 |
| `0x138` | `u64` | Opaque host scalar, default 0 |
| `0x150` | `u64` | Locator, default `0x000110038001a002` |
| `0x158` | `u64` | Locator, default `0x000020038001a03b` |
| `0x178` | `u64` | `0x003fffffffffffff` |

On slot reuse, replace only these host-owned qwords. Preserve every other byte
written by firmware.

### Compute scheduler record

Size `0x100`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | Scheduler-slot FW DVA |
| `0x08` | `u32` | Work ID, normally zero for host seed |
| `0x0c` | `u32` | Phase, normally zero for host seed |
| `0x10` | `u32` | `0x50` |
| `0x24` | `u32` | 1 only when phase is nonzero |
| `0xa0` | `u64` | Optional job-list DVA |
| `0xa8` | `u64` | Optional high node ID |
| `0xb0` | `u64` | Optional preceding low node ID |
| `0xc0` | `u64` | Optional active marker 1 |

The scheduler slot is `0x40`. A live seed entry is `(2 << 32) | value`; the
first established value is `0x35`.

### Compute shared-state page

Size `0x4000`. The host seed writes one `u32` active value, normally 1, at
`0x00`; the remainder begins zero and is firmware-owned after registration.

### Shared-support object

Size one 16 KiB page. The common form is:

| Offset | Type | Meaning/default |
|---:|---|---|
| `0x00` | `u64` | Header, 3 |
| `0x08` | `u64` | 2 |
| `0x10` | `u64` | `0x0200800000000001` |
| `0x18` | `u64` | `0x0004000000000070` |
| `0x20` | `u64` | Resource class shifted left 40 |
| `0x28` | `u64` | Same resource-class encoding |
| `0x30` | `u64` | Client state or operand table |
| `0x40` | `u64`/`u32` | 4 |
| `0x48` | `u32` | Cursor |
| `0x4c` | unaligned `u64` | Firmware-state FW DVA |
| `0x54` | `u32` | Opaque scalar |
| `0x5c` | `u32` | Opaque scalar |
| `0x60` | `u32` | Final kind |

Compact class-1/2 control support replaces the leading fields with:

- `u32 control_class` at `0x00` and `0x10`;
- `u32 active` at `0x08`;
- low 32 bits of an operand-buffer DVA at `0x14`;
- operand-table DVA at `0x30`.

Class 1 defaults to resource class `0x13`, cursor `0x98`, final kind 2. Class 2
defaults to resource class `0x17`, cursor `0xb8`, final kind 3.

### Operand table and page lists

The operand table has 21 records, stride `0x40`. Each record begins with:

```text
(buffer_dva | 0x1000000000000000)
```

The established allocation gives each operand a `0x100000`-byte tranche and a
`0x108000` stride. Page-list objects enumerate every 4 KiB page DVA. One 16 KiB
page holds eight one-MiB tranches; 21 operands use three page-list pages.

A simple buffer-only resource table is one page with consecutive `u64` buffer
DVAs beginning at `0x14a0`. Unused table entries are zero.

### Class-2 pool record

80 records, stride `0x80`, in one page.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | Low slot alias + `0x280 + index*4` |
| `0x08` | `u64` | FW-high slot alias + same offset |
| `0x10` | `u64` | Firmware/runtime state |
| `0x28` | `u64` | `0x808000 + (index % 36)*0x20` |
| `0x40` | `u64` | Shared-state DVA + `0x40` |
| `0x48` | `u32[2]` | Firmware/runtime state and active marker |

The shared-state page has `{limit, limit}` at `0x00` and active count at `0x40`.
The established defaults are limit 8 and active 5.

### Class-2 predecessor record

36 records, stride `0x100`.

| Offset | Type | Meaning |
|---:|---|---|
| `0x00` | `u64` | Slot DVA + `index*4` |
| `0x08` | `u32[2]` | Firmware scheduler state |
| `0x10` | `u64` | `0x50` in active records |
| `0x20` | `u32[2]` | Firmware scheduler state |
| `0xa0` | `u64` | Resource job-list head |
| `0xa8` | `u64` | High identity |
| `0xb0` | `u64` | Low identity |
| `0xc0` | `u64` | Active marker |

The host registration seed writes only the slot DVA at `0x00` in each record.
Firmware populates scheduler state. Do not initialize the seed with a later
post-registration image.

The associated predecessor-slot page is a `u32` array. Its registration seed is
zero; the established post-registration forms begin `{0,1,1}` for the minimal
path or `{0,2,2,2}` for the larger path. Those are firmware lifecycle states,
not universal host initialization constants.

### Direct CDM record

Size `0x2c`.

| Offset | Type | Meaning/default |
|---:|---|---|
| `0x00` | `u32` | Config, `0x00080000` |
| `0x04` | `u32` | Constant, `0x01000000` |
| `0x08` | `u64` | Encoded shader pointer |
| `0x10` | `u32[3]` | Global grid dimensions |
| `0x1c` | `u32[3]` | Threadgroup dimensions |
| `0x28` | `u32` | Tail, `0x60000160` |

The shader DVA must be 64-byte aligned. Encoding is:

```text
low     = (shader_dva >> 6) & 0xffffffff
control = 0x40000000 | (shader_dva >> 40)
encoded = low | (control << 32)
```

A direct stream is one or more `0x2c` records followed by `u32 0x40000000`.

### Indirect compute structures

The indirect helper record is `0x1c`:

| Offset | Type | Meaning/default |
|---:|---|---|
| `0x00` | `u32` | Config, `0x10080000` |
| `0x04` | `u32` | Constant, `0x01000000` |
| `0x08` | `u64` | Encoded helper shader pointer |
| `0x10` | `u32` | Generated-geometry DVA high word |
| `0x14` | `u32` | Generated-geometry DVA low word |
| `0x18` | `u32` | Tail, `0x60000160` |

The stream is a normal `0x2c` main dispatch, then this helper record, then the
terminator.

The resource page contains:

| Offset | Content |
|---:|---|
| `0x14a0` | Helper argument DVA table |
| `0x14c0` | Six generated `u32`: global dimensions then local dimensions |
| `0x14e0` | Main shader argument DVA table |

The helper binding object is at least `0x68`. It begins with the public indirect
argument DVA and generated-geometry DVA at `0x00` and `0x08`; the remaining
established packed state is serialized by `build_indirect_helper_binding()`.
The helper constant object is an array of `{u32 reciprocal, u32 shift}` entries
used for unsigned division by the entry index plus one.

## Completion, Fences, And Timestamps

### Queue completion

A queue command is transport-complete when the queue's logical done/read state
has reached the immutable post-command prefix and the channel consumer has
reached the producer that published it. For a render command, both TA and
fragment prefixes must complete. For a compute command, the compute prefix must
complete.

This completion is a valid resource-lifetime fence. It is not proof that shader
code ran. Exact expected output bytes are the execution proof.

Commands on one persistent compute queue are ordered and coherent. Cross-engine
render/compute dependencies have produced exact expected bytes in both
directions. A correctness-first implementation may host-serialize the engine
queues while preserving userspace dependency semantics.

### Terminal states and attribution

Record ownership when a hardware command is published.  The host record names
the DRM file, logical VM, hardware context, logical queue, command-buffer index
and type, physical queue pair, and firmware submission ordinal.  Render child
fences additionally name their TA and fragment queue prefixes.  A command index
counts the complete parsed command buffer, including attachment-setting and
other software state records before the hardware command.

The established terminal classes are:

| case | publication | fence terminal state | queue/device consequence |
|---|---|---|---|
| invalid handle, binding, field, or dependency | none | no new fence; synchronous rejection record | queue remains usable |
| ordinary completion | published | completed, error 0 | queue remains usable |
| shader soft fault | published | completed, error 0 | queue and VM remain usable |
| logical queue destruction with pending work | already published | stays pending until its ordinary or fatal terminal point | handle disappears immediately; physical state is retained |
| fatal RTKit crash | published work may remain pending | failed, `-ENODEV`, reason `device-lost` | device cannot be reused before reboot |

Rejection must be transactional: record the exact file/VM/queue/command and
original validation error, but create no fence and do not change any producer,
group number, descriptor, or output sync point.

An endpoint-1 fatal notification carries the crash-buffer DVA and size, not a
VM or queue ID.  Preserve that buffer and its mailbox history first.  Then use
the host publication table to fail every still-outstanding command fence.
Propagate the child error to the submit fence and any binary/timeline output
points.  Never change a fence that had already completed successfully.

A deliberate primary-RTKit hard crash with one real render producer published
but its work doorbell suppressed proved this ordering.  The pending target page
remained completely zero, both TA and fragment prefixes remained normally
unsignaled, exactly one command fence became `-ENODEV`, and a previously
completed render fence remained successful.  Logical queue destruction then
treated both fences as terminal.  The 4 KiB crash payload and mailbox histories
were preserved before fence signaling.

### Timestamp destinations

G17P has distinct internal and caller-visible timestamp mechanisms.

The compute descriptor carries two unaligned 64-bit destination-pointer pairs:

| purpose | start/A pointer | end/B pointer | timebase |
|---|---:|---:|---:|
| internal completion/status | `+0xf7c` | `+0xf84` | 24 MHz |
| caller-visible command time | `+0xf8c` | `+0xf94` | 1 GHz |

The internal pair may name independent host-owned ordinary firmware memory.
For every ordinary post-start command, firmware writes a full 64-bit value to A
and then a larger full 64-bit value to B. No bytes outside either selected
eight-byte destination are changed. These values use a monotonically increasing
24 MHz command-time counter. On a system whose `CNTFRQ_EL0` is 1 GHz,
multiplying `CNTPCT_EL0` by `24,000,000 / 1,000,000,000` brackets the observed
values. Three exact compute commands measured 314--324 ticks from A to B. The
exact internal events represented by A and B have not yet been isolated.

A compute command staged before firmware startup follows a different internal
lifecycle: it writes internal A but leaves internal B untouched. Its separate
caller-visible start/end pair is complete and forward ordered. Do not expose
the internal startup asymmetry through the UAPI.

The render descriptors carry one internal 24 MHz destination per stage and a
separate caller-visible start/end pair:

| stage | internal pointer | caller start pointer | caller end pointer |
|---|---:|---:|---:|
| vertex/TA | `+0x8fe` | `+0x90e` | `+0x916` |
| fragment | `+0x2198` | `+0x21a8` | `+0x21b0` |

The render and compute caller pairs are accepted only when their destinations lie in the special
timestamp aperture. Hardware-data qword `+0x28` supplies its base,
`0xfffffc2181400000` on the measured final-26.6 G17P system. Mapping the same
physical page at an arbitrary firmware VA does not produce caller timestamps.

Each caller pointer selects one eight-byte destination. Firmware writes a full
64-bit architectural timestamp in the 1 GHz `CNTPCT_EL0` domain. Within a
render the order is vertex start, vertex end, fragment start, fragment end.
This ordering held across three successive exact renders on alternating queue
pairs. Firmware consumes and clears each start pointer in the work descriptor;
the end pointers remain. Do not reuse or inspect the descriptor as immutable
input after publication.

The Linux special-object model maps a page-aligned GEM range into this aperture
and returns a file-private object handle. A command's timestamp offset is
relative to that special mapping, not to the GEM as a whole and not a GPU VA.
Resolve it as `special_mapping_base + offset`, require
`offset + 8 <= mapped_range_size`, and retain the mapping through the terminal
command fence. One hardware-proven binding spanned two 16 KiB pages, with
vertex timestamps in the first page and fragment timestamps in the second.
After the fence terminates, object unbind may invalidate the aperture PTEs.

The UAPI `command_timestamp_frequency_hz` for G17P is therefore
`1,000,000,000`. The 24 MHz internal command values are not exposed through
that UAPI field.

The following timestamp details remain **unknown**:

- the precise command lifecycle events represented by compute A and B;
- wrap behavior of the 64-bit 24 MHz counter;
- the maximum hardware-supported timestamp-aperture extent beyond the proven
  two-page mapping.

Do not infer shader execution from a timestamp write alone.

## Memory Ordering And Cache Rules

### Host-to-firmware publication

For CPU-written memory:

1. Write the complete object graph.
2. Clean all modified data cache lines to the point visible to the GPU.
3. Execute `dsb sy` before publishing any pointer or producer that makes the
   object reachable.
4. Publish the pointer/producer last, clean it, and execute another `dsb sy`.
5. Ring the mailbox doorbell.

### UAT changes

For map, unmap, permission change, partial unbind, or physical-page reuse:

1. Ensure no pending firmware reference can reach the old mapping.
2. Update page tables.
3. Clean modified page-table lines.
4. Execute `dsb sy`.
5. Invalidate the affected ASID/context; the current bring-up path uses
   `tlbi vmalle1os` when a narrower operation is unavailable.
6. Execute `dsb sy` before publishing work or reusing physical memory.

Client mappings used by both firmware and shader cores are mapped Shared. A
single-page binding repeats one physical page over the requested DVA range.
An attachment may name a page-sized subrange of a larger binding; preserve the
attachment's pointer and size rather than replacing them with the covering
binding's base and extent.

### Multiple logical VMs

Firmware admits one render descriptor identity on this path.  A raw work-item
context number does not select an arbitrary UAT root.  Multiple isolated VMs
are implemented by serializing submissions, replacing every valid hardware
root-table entry tagged with the admitted ASID with the selected VM's low root,
cleaning the table entries, executing `dsb sy`, invalidating the admitted ASID,
and executing another `dsb sy`.  Work descriptors retain the admitted context
identity.

Two live VMs may map the same DVA to independent physical pages.  Exact A/B/A
renders through root switches write only the selected VM's page.  A
non-primary VM may be destroyed after its queues and mappings are gone: restore
the primary root if necessary, invalidate both private roots and its ASID, and
reject the stale VM handle.  The surviving VM continues to execute without
changing the released VM's old physical page.

A partial unbind removes the original hardware mapping and creates logical
left/right survivors with the correct BO offsets.  Reinstall those survivors
and any replacement mapping before the next publication, then perform the UAT
ordering above.  A command naming the hole is rejected transactionally before
any descriptor, producer, or doorbell is published.  After terminal completion
the same DVA may be rebound to fresh physical backing; later work reaches only
the replacement PA.

### Backpressure

Never overwrite a live ring slot, item pointer, queue-context record, parameter
block, event item, descriptor, or resource object. If capacity is exhausted,
poll completion/report channels and defer publication. Allocation failure before
publication leaves prior queue state untouched and returns an error to userspace.

## Faults And Recovery

Unmapped shader loads use soft-fault semantics and return zero. Unmapped shader
stores are discarded. The command may retire normally, and later valid work can
execute. This behavior is command-local and does not permit the driver to ignore
invalid mappings at submission time. Firmware exposes no fence error or separate
host-visible terminal class for this shader event; the injected command is
attributed by its ordinary publication identity and completes successfully.

A firmware exception, non-soft translation fault, or fatal coprocessor crash is
not recoverable in place. Endpoint 1 reports the crash-buffer DVA and size.
Preserve the raw report and mailbox history, attribute every outstanding fence
from the host publication table, signal it with `-ENODEV`, and then reboot the
device. Do not attempt to restart only the firmware.

## Teardown And Reuse

Logical destruction and physical release are separate:

1. Stop accepting new work on the queue or VM.
2. Retain every queue record, descriptor, event, support object, BO, UAT mapping,
   and timestamp object reachable by an outstanding fence.
3. Wait for semantic terminal completion or explicitly terminate the fence after
   a fatal device loss.
4. Require queue done/read/write equality and channel idleness before normal
   physical teardown.
5. Clear item-ring slots, current-job links, intrusive job lists, queue records,
   pointer blocks, and work-ring slots.
6. Clean those writes and invalidate every low/high alias and affected UAT ASID.
7. Only then release physical pages or reuse DVAs.

Queue transport identities may be reused after teardown. Retained work ordinals
must continue monotonically where firmware-visible state survives; resetting an
ordinal while retaining related firmware state creates an inconsistent object
graph.

## Known Gaps

Opaque platform constants in hardware-data and region C are accepted debt. They
are neither hidden replay pages nor unknown pointer graphs: their exact bytes are
constructed explicitly. Major pointers, lengths, counters, and ownership gates
must not remain opaque in a production driver.

## Structure Index

| Structure | Size/stride | Section |
|---|---:|---|
| Initdata root | `0xb8` / `0xc8` | Initdata root |
| UAT level descriptor | `0x20` | UAT level descriptor |
| Main configuration | `0x600` | Main configuration |
| Channel table entry | `0x20` | Channel table entry |
| Hardware-data object | `0x3db4` | Hardware-data object |
| Register mapping entry | `0x28` | Register mapping entry |
| Hardware region record | `0x40` | Hardware region record |
| Region C | `0x1000` | Region C |
| Status block | `0x80` | Status block |
| Primary compute-dispatch record | `0x20` | Primary compute-dispatch record |
| Device-control record | `0x40` | Device-Control ABI |
| Work-ring slot | `0x18` | Work-channel ring slot |
| Queue record | `0xc0` | Command queue record |
| Queue pointer block | `0x60` minimum | Queue pointer block |
| Item-ring entry | `0x08` | Item ring |
| Inner work batch | `0x18` per item | Item ring |
| Job-list head | `0x18` | Intrusive job-list head |
| Event item/record | `0x400` / `0x40` | Event item |
| Register entry | `0x0c` | Register entry |
| Render pool A record | `0x100` | Render pool A |
| Render pool B record | `0x80` | Render pool B |
| Packed shared object | `0x88` | Packed shared object |
| Zero shared object | `0x100` | Packed shared object |
| Render optional item | `0xc0` | Render optional item |
| Render queue-context record | `0x200` | Render queue-context item |
| TA descriptor | `0x9c0` | TA descriptor |
| Fragment descriptor | `0x2240` | Fragment descriptor |
| Tiler encoder | `0x8c` | Tiler encoder stream |
| Indexed indirect arguments | `0x14` | Tiler encoder stream |
| Render parameter block | `0x5200` | Parameter-buffer blocks |
| Compute descriptor | `0x4000` | Compute descriptor |
| Compute optional item | `0xc0` | Compute optional item |
| Compute event item | `0x400` | Compute event item |
| Compute queue-context record | `0x200` | Compute queue-context record |
| Compute scheduler record | `0x100` | Compute scheduler record |
| Compute scheduler slot | `0x40` | Compute scheduler record |
| Compute shared-state page | `0x4000` | Compute shared-state page |
| Shared-support object | `0x4000` | Shared-support object |
| Operand table record | `0x40` | Operand table and page lists |
| Class-2 pool record | `0x80` | Class-2 pool record |
| Class-2 predecessor record | `0x100` | Class-2 predecessor record |
| Direct CDM record | `0x2c` | Direct CDM record |
| Indirect CDM helper record | `0x1c` | Indirect compute structures |
| Indirect helper binding | `0x68` body | Indirect compute structures |
| Buffer resource table | `u64[]` at `0x14a0` | Operand table and page lists |
