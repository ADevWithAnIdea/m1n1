# SPDX-License-Identifier: GPL-2.0-only
"""Host-built T8142/G17G compute graph shared by experiments and drm_shim.

This module is deliberately transport-free.  It turns caller values into the
complete byte products for the accepted one-dispatch compute submission and
states which source-built post-control pages the live firmware world must
already provide.  Allocation, UAT publication, cache maintenance and mailbox
transport stay in the runtime adapter.
"""

import dataclasses
import hashlib
import struct

from . import g17g
from . import g17g_compute
from . import g17g_compute_predecessor_assets
from . import g17g_direct_pair_assets
from . import g17g_encoder
from . import g17g_initdata
from . import g17g_mixed_partial_assets
from . import g17g_mixed_partial_native_tail
from . import g17g_mixed_render_assets
from . import g17g_postcontrol
from . import g17g_render
from . import g17g_render_compiler
from . import g17g_partial_assets
from . import g17g_partial_repeat_assets


PAGE_SIZE = g17g_compute.PAGE_SIZE

COMPUTE_CHANNEL = 8
COMPUTE_GRID_INDEX = 10

# Stable firmware-context addresses from the accepted beta-5 first-compute
# topology.  Fresh backing is installed for submission-owned objects; global
# objects are supplied by the source post-control package named below.
COMPUTE_SHARED_BASE = 0xFFFFFC2000800000
COMPUTE_DESCRIPTOR_LOW = 0x7200340000
# The captured low-alias allocation lives in the tail of the address-list run
# and ends at 0x7200400000. Command 190 is the first 0x1000-byte descriptor
# that would cross that boundary; continuing linearly then overwrites the live
# client-state and operand page-list mappings. Continue in fresh caller space.
COMPUTE_DESCRIPTOR_LOW_RELOCATED_BASE = 0x7202000000
COMPUTE_DESCRIPTOR_LOW_RELOCATION_ORDINAL = 190
# The native high descriptor allocation is 61 16-KiB pages.  With a 0x1040
# stride it contains 241 legal descriptor starts: command 241 begins at
# +0xf3c00 and straddles the final boundary, while the base for command 242
# would lie beyond the allocation.  Descriptors are retired before this pool
# wraps, so reuse it cyclically instead of extending an allocator-owned DVA.
COMPUTE_DESCRIPTOR_HIGH_RECORD_COUNT = 241
COMPUTE_QUEUE_CONTEXT_LOW = 0x7200438000
COMPUTE_ADDRESS_LIST = 0x7200000000
COMPUTE_ADDRESS_LIST_SIZE = 0x400000
COMPUTE_CLIENT_STATE = 0x7200408000
COMPUTE_PAGE_LIST = 0x720040C000
COMPUTE_SCRATCH = 0x7200420000
COMPUTE_OPERAND_BASE = 0x7200448000
COMPUTE_SHADER = 0x100000A8000
COMPUTE_RESOURCE = 0x100000F8000
COMPUTE_CDM = 0x100000C8000
COMPUTE_BUFFER_OUT = 0x10000040000
COMPUTE_BUFFER_A = 0x10000030000
COMPUTE_BUFFER_B = 0x10000038000
# Native's earliest compute-before-render command buffer keeps its three
# caller pages outside the partial renderer's live compiler pages.  These are
# caller addresses, not firmware-owned ABI addresses, and let the source path
# retain one context-1 root across the dependent-render publication.
COMPUTE_TO_RENDER_BUFFERS = (
    0x10000060000,
    0x10000064000,
    0x10000068000,
)
COMPUTE_ROBUSTNESS = 0x1000018000

# Caller-chosen scratch VA range for additional direct dispatches carried by
# one selector-3 descriptor.  These are ordinary context-1 buffers, not ABI
# fixed addresses; keeping them outside the captured allocation families
# lets the runtime add them without repurposing render or compiler pages.
COMPUTE_DIRECT_BUFFER_BASE = 0x10010000000
COMPUTE_DIRECT_BUFFER_DISPATCH_STRIDE = 3 * PAGE_SIZE
# Native keeps at least four encoders in one selector-3 descriptor.  The
# clean-room split resource-selector encoding and the one-page arenas support
# up to 64 direct dispatches in that same graph.
COMPUTE_INITIAL_GRAPH_DISPATCH_LIMIT = (
    g17g_compute.G17G_ADD_MAX_DIRECT_DISPATCHES
)
COMPUTE_INITIAL_CDM_GROUP_STRIDE = 0x1000

COMPUTE_RESOURCE_SIZE = PAGE_SIZE
COMPUTE_RESOURCE_MAPPING_SIZE = 3 * PAGE_SIZE
COMPUTE_SHADER_MAPPING_SIZE = 2 * PAGE_SIZE
COMPUTE_CDM_MAPPING_SIZE = 2 * PAGE_SIZE

COMPUTE_GLOBAL_SCHEDULER = 0xFFFFFC20C08A8100
COMPUTE_GLOBAL_SCHEDULER_SLOT = 0xFFFFFC2001600000
COMPUTE_GLOBAL_SUPPORT = 0xFFFFFC20C08B0000
COMPUTE_GLOBAL_STATE = 0xFFFFFC2001608000
COMPUTE_GLOBAL_DISPATCH_A = 0xFFFFFC20001C8000
COMPUTE_GLOBAL_DISPATCH_B = 0xFFFFFC20C07D8000
COMPUTE_GLOBAL_STATUS_A = 0xFFFFFC2000024E48
COMPUTE_GLOBAL_STATUS_B = 0xFFFFFC2000024E50
COMPUTE_GLOBAL_ZERO = 0xFFFFFC2001610000
COMPUTE_CHANNEL_STATE_PAGE = 0xFFFFFC2000020000
COMPUTE_CHANNEL_RING_PAGE = 0xFFFFFC20C07A0000
COMPUTE_POINTER_PAGE = 0xFFFFFC2000010000
COMPUTE_QUEUE_PAGE = 0xFFFFFC20C0000000
COMPUTE_ITEM_RING_PAGE = 0xFFFFFC20C0008000
COMPUTE_DESCRIPTOR_PAGE = 0xFFFFFC20C0358000
COMPUTE_OPTIONAL_PAGE = 0xFFFFFC20C0600000
COMPUTE_EVENT_PAGE = 0xFFFFFC20C05E8000
COMPUTE_QUEUE_CONTEXT_PAGE = 0xFFFFFC20001D8000
COMPUTE_JOB_LIST_PAGE = 0xFFFFFC2000000000
COMPUTE_QUEUE_AUX_PAGE = 0xFFFFFC20C07C0000

# Queue indexes are local to each firmware channel.  The earliest coherent
# ch6/ch7/ch8 capture therefore encodes compute as queue 0 on channel 8 even
# though TA is logical queue 1 on channel 6.  Caller space is not a translated
# standalone-compute allocation: the paired pre-kick boundary instead reuses
# render scratch at 0x7200000000 and has independent address-list,
# operand-buffer, and client-state allocations below.
COMPUTE_MIXED_QUEUE_INDEX = 0
COMPUTE_MIXED_QUEUE_GENERATION = 0x10E
# The channel-local queue index is not the physical transport-record ordinal.
# The earliest coherent native publication places compute in physical record
# zero, TA in record one, and fragment in record two.  All three channels keep
# their own logical queue indices (compute remains zero).  The pointer blocks
# and item-ring records follow the same physical ordering.
COMPUTE_MIXED_POINTER = COMPUTE_POINTER_PAGE
COMPUTE_MIXED_QUEUE = COMPUTE_QUEUE_PAGE
COMPUTE_MIXED_ITEM_RING = COMPUTE_ITEM_RING_PAGE
COMPUTE_MIXED_OPTIONAL = COMPUTE_OPTIONAL_PAGE
COMPUTE_MIXED_EVENT = COMPUTE_EVENT_PAGE
# The earliest coherent compute publication still consumes the first compute
# channel's low scratch record.  0x7200488000 belongs to the later serialized
# post-render lifecycle and silently leaves this first compute work pending.
COMPUTE_MIXED_QUEUE_CONTEXT_LOW = COMPUTE_QUEUE_CONTEXT_LOW
COMPUTE_MIXED_QUEUE_CONTEXT_HIGH = COMPUTE_QUEUE_CONTEXT_PAGE
COMPUTE_MIXED_SCHEDULER = 0xFFFFFC20C08B0100
COMPUTE_MIXED_SCHEDULER_SLOT = 0xFFFFFC2001608000
COMPUTE_MIXED_SHARED_SUPPORT = 0xFFFFFC20C08C0000
COMPUTE_MIXED_SHARED_STATE = 0xFFFFFC2001620000

# Exact context-64 leaf exchange around the earliest compute-first mixed
# type-0x84.  Native keeps the ten ``before`` leaves visible while channel-12
# slot 3 is pending, then atomically replaces them with the 23 ``after``
# leaves when that record retires.  These are address-topology facts only;
# every backing page and byte remains source-built.
COMPUTE_MIXED_FIRST_TYPE84_BEFORE_GLOBAL_PAGES = (
    0xFFFFFC20C0808000,
    0xFFFFFC20C080C000,
    0xFFFFFC20C0830000,
    0xFFFFFC20C0834000,
    0xFFFFFC20C0858000,
    0xFFFFFC20C085C000,
    0xFFFFFC20C0868000,
    0xFFFFFC20C086C000,
    0xFFFFFC20C0890000,
    0xFFFFFC20C0894000,
)
COMPUTE_MIXED_FIRST_TYPE84_AFTER_GLOBAL_PAGES = (
    0xFFFFFC2001620000,
    0xFFFFFC2001630000,
    0xFFFFFC2001638000,
    0xFFFFFC2001640000,
    0xFFFFFC20C07F0000,
    0xFFFFFC20C07F4000,
    0xFFFFFC20C0800000,
    0xFFFFFC20C0804000,
    0xFFFFFC20C0828000,
    0xFFFFFC20C082C000,
    0xFFFFFC20C0850000,
    0xFFFFFC20C0854000,
    0xFFFFFC20C0878000,
    0xFFFFFC20C087C000,
    0xFFFFFC20C08C0000,
    0xFFFFFC20C08C8000,
    0xFFFFFC20C08CC000,
    0xFFFFFC20C08D0000,
    0xFFFFFC20C08D4000,
    0xFFFFFC20C08D8000,
    0xFFFFFC20C08DC000,
    0xFFFFFC20C08E8000,
    0xFFFFFC20C08F8000,
)
COMPUTE_MIXED_ZERO = 0xFFFFFC2001628000
COMPUTE_MIXED_JOB_LIST = COMPUTE_JOB_LIST_PAGE + 0x18
COMPUTE_MIXED_QUEUE_AUX = COMPUTE_QUEUE_AUX_PAGE + 0x40
COMPUTE_MIXED_STATUS_A = COMPUTE_GLOBAL_STATUS_A + 0x10
COMPUTE_MIXED_STATUS_B = COMPUTE_GLOBAL_STATUS_B + 0x10
COMPUTE_MIXED_SCRATCH = 0x7200840000
COMPUTE_MIXED_OPERAND_BASE = 0x7200868000
COMPUTE_MIXED_ADDRESS_LIST = 0x7200420000
COMPUTE_MIXED_CLIENT_STATE = 0x7200828000
COMPUTE_MIXED_PAGE_LIST = 0x720082C000
COMPUTE_MIXED_SHADER = 0x100003D0000
COMPUTE_MIXED_SHADER_RELOCATION_TARGET = COMPUTE_MIXED_SHADER
COMPUTE_MIXED_CDM = 0x100003F0000
COMPUTE_MIXED_RESOURCE = 0x10000420000
COMPUTE_MIXED_ROBUSTNESS = 0x1000080000
# The earliest two-publication witness allocates a private eight-page scratch
# span for queue one rather than reusing queue zero's span.  Keep subsequent
# experimental publications in the same otherwise-unused caller run.
COMPUTE_MIXED_FRESH_SCRATCH_BASE = 0x7201EC0000
COMPUTE_MIXED_FRESH_SCRATCH_STRIDE = 8 * PAGE_SIZE
# The established one-compute source render already owns the native second-
# publication holes.  These collision-free source addresses preserve that
# working render graph while retaining one independent transport/context set
# per additional compute publication.
COMPUTE_MIXED_FRESH_POINTER_STRIDE = 3 * 0x2870
COMPUTE_MIXED_FRESH_QUEUE_STRIDE = 3 * g17g.QUEUE_RECORD_STRIDE
COMPUTE_MIXED_FRESH_OPTIONAL_STRIDE = 3 * g17g_compute.COMPUTE_OPTIONAL_SIZE
COMPUTE_MIXED_FRESH_EVENT_STRIDE = 3 * g17g_compute.COMPUTE_EVENT_SIZE
COMPUTE_MIXED_FRESH_QUEUE_CONTEXT_STRIDE = 0x78000
COMPUTE_MIXED_FRESH_ZERO_BASE = 0xFFFFFC2001650000
# Exact source-reencoded object addresses from the earliest native capture in
# which two independent compute queues are pending with one render.  Unlike
# the collision-free diagnostic layout above, this is a complete allocation
# family: caller programs, lifecycle objects, and every transport pool move
# together and are byte-comparable with the known-good replay.
COMPUTE_MIXED_TWO_QUEUE_GENERATION = 0x107
COMPUTE_MIXED_TWO_POINTERS = (
    0xFFFFFC2000010000, 0xFFFFFC20000150E0,
)
COMPUTE_MIXED_TWO_ITEM_RINGS = (
    0xFFFFFC20C0008000, 0xFFFFFC20C000D0E0,
)
COMPUTE_MIXED_TWO_QUEUES = (
    0xFFFFFC20C0000000, 0xFFFFFC20C0000100,
)
COMPUTE_MIXED_TWO_OPTIONALS = (
    0xFFFFFC20C0600000, 0xFFFFFC20C06000C0,
)
COMPUTE_MIXED_TWO_EVENTS = (
    0xFFFFFC20C05E8000, 0xFFFFFC20C05E8040,
)
COMPUTE_MIXED_TWO_QUEUE_CONTEXT_LOW = (0x7200438000, 0x7200460000)
COMPUTE_MIXED_TWO_QUEUE_CONTEXT_HIGH = (
    0xFFFFFC20001D8000, 0xFFFFFC2000200000,
)
COMPUTE_MIXED_TWO_ZEROS = (
    0xFFFFFC2001618000, 0xFFFFFC2001630000,
)
COMPUTE_MIXED_TWO_STATUS_A = (
    0xFFFFFC2000024E48, 0xFFFFFC2000024E68,
)
COMPUTE_MIXED_TWO_STATUS_B = (
    0xFFFFFC2000024E50, 0xFFFFFC2000024E70,
)
COMPUTE_MIXED_TWO_SCRATCH = (0x7200420000, 0x7201EC0000)
COMPUTE_MIXED_TWO_ROBUSTNESS = (0x1000078000, 0x1000088000)
COMPUTE_MIXED_TWO_SHADER = (0x100003D0000, 0x10000458000)
COMPUTE_MIXED_TWO_CDM = (0x100003F0000, 0x10000478000)
COMPUTE_MIXED_TWO_RESOURCE = (0x10000420000, 0x100004A8000)
COMPUTE_MIXED_TWO_BUFFERS = (
    (0x10000030000, 0x10000038000, 0x10000040000),
    (0x10000430000, 0x10000438000, 0x10000440000),
)
COMPUTE_MIXED_TWO_DISPATCH_IDENTITIES = (
    0x000000CB010000EF, 0x000000CD01000107,
)
COMPUTE_MIXED_TWO_SHARED_SUPPORT = 0xFFFFFC20C08B8000
COMPUTE_MIXED_TWO_SHARED_STATE = 0xFFFFFC2001610000
COMPUTE_MIXED_TWO_CLIENT_STATE = 0x7200408000
COMPUTE_MIXED_TWO_OPERAND_BASE = 0x7200448000
# The two-publication transport was first decoded behind a pending render.
# These are the seven render-owned pages that its compute objects actually
# reference and that therefore have to be source-built when the same graph is
# the first work firmware sees.  In particular, the offset job list at +0x18
# and channel-control record at +0x40 are distinct objects; leaving their
# self/link fields zero makes first admission dereference NULL+8.
COMPUTE_MIXED_TWO_FIRST_WORK_GLOBAL_PAGES = (
    0xFFFFFC2000000000,
    0xFFFFFC2000024000,
    0xFFFFFC20001C8000,
    0xFFFFFC2001608000,
    0xFFFFFC20C07C0000,
    0xFFFFFC20C07D8000,
    0xFFFFFC20C08B0000,
)
# The earliest mixed caller keeps one otherwise empty selector-zero leaf
# between its low render state runs.  Its captured image is all zero and its
# PTE uses the ordinary caller read-only/UXN class.  Omitting the leaf prevents
# firmware from admitting either prequeued compute publication even though no
# decoded object points into it directly.
RENDER_MIXED_COMPUTE_ADMISSION_ZERO_DVA = 0x1000230000
# The earliest source graph writes the low identity ``0x010000f1`` into the
# shared scheduler record.  That value is also the native resource-allocation
# watermark for eight direct encoders.  A clean native four-versus-nine
# comparison changes only this mirrored descriptor identity (apart from the
# CDM terminator), from low byte ``e5`` to ``f4``: exactly three identities per
# added encoder, matching its A/B/output buffers.  Preserve the proven
# overprovisioned watermark for one through eight encoders, then advance it by
# three for each additional eight-encoder capacity block.
COMPUTE_MIXED_DISPATCH_IDENTITY = 0x000000CB010000F1
COMPUTE_MIXED_DISPATCH_IDENTITY_CAPACITY = 8
COMPUTE_MIXED_DISPATCH_IDENTITY_STRIDE = 3
# A same-queue compute command separated from its predecessor by the coherent
# first render advances the shared dispatch namespace by an additional 0x1a.
# The earliest native mixed-repeat witness is therefore ...0039 rather than
# the compute-only ...001f transition.
COMPUTE_MIXED_REPEAT_DISPATCH_IDENTITY_STRIDE = 0x0000000200000039

# Exact selector-zero topology at the earliest render-then-compute pre-kick
# boundary.  The boolean is the measured GPU read-only/executable class.  The
# table records addresses and permissions only; every nonzero page below is
# still constructed from decoded objects.
COMPUTE_MIXED_CONTEXT1_RUNS = (
    (0x1000000000, 4, True),
    (0x1000018000, 2, True),
    (0x1000028000, 2, True),
    (0x1000038000, 2, True),
    (0x1000048000, 2, True),
    (0x1000058000, 2, False),
    (0x1000068000, 3, False),
    (0x1000078000, 1, False),
    (0x1000080000, 1, False),
    (0x1000088000, 32, False),
    (0x1000110000, 32, False),
    (0x1000198000, 32, False),
    (0x1000220000, 1, False),
    (0x1000228000, 2, False),
    (0x1000238000, 6, False),
    (0x1000258000, 1, False),
    (0x1000260000, 9, False),
    (0x1000288000, 1, False),
    (0x7200000000, 256, False),
    (0x7200408000, 4, False),
    (0x7200420000, 1818, False),
    (0x7202090000, 128, False),
    (0x10000000000, 4, True),
    (0x10000018000, 1, False),
    (0x10000030000, 1, False),
    (0x10000038000, 1, False),
    (0x10000040000, 1, False),
    (0x10000048000, 4, True),
    (0x10000060000, 8, False),
    (0x10000088000, 28, True),
    (0x100000FC000, 3, True),
    (0x1000010C000, 3, True),
    (0x10000120000, 2, False),
    (0x10000130000, 2, False),
    (0x10000140000, 64, False),
    (0x10000248000, 2, False),
    (0x10000258000, 2, True),
    (0x10000268000, 2, True),
    (0x10000278000, 2, True),
    (0x10000288000, 2, True),
    (0x10000298000, 48, True),
    (0x100003D0000, 2, True),
    (0x100003F0000, 2, False),
    (0x10000420000, 3, False),
    (0x2FFFFFF8000, 1, False),
)
COMPUTE_MIXED_CONTEXT1_PAGE_COUNT = 2529
COMPUTE_MIXED_CONTEXT1_READ_ONLY_PAGE_COUNT = 112
COMPUTE_MIXED_CONTEXT1_DVA_SHA256 = (
    "a0106144b16d651caa11bf3c8114da46"
    "dc9930609786d321a7d64f2f4106dd08"
)
COMPUTE_MIXED_CONTEXT1_READ_ONLY_DVA_SHA256 = (
    "c67dcb468099e3060bf7e678562cc986"
    "c884056dc80de8ff2c872440bdbee078"
)

# The coherent first-compute allocation retains two compiler/resource pages
# at addresses outside the first-clear placement run.  Their byte products
# are already decoded and hash-gated in the partial-render caller bundle; the
# mixed transition only relocates those caller-owned bytes to the two native
# executable leaves.  No captured pre-work image is involved.
COMPUTE_MIXED_RELOCATED_CALLER_PAGES = {
    0x100000FC000: (
        0x1000019C000,
        "0fa41d5bab4fb10165159d9e77055e81916ee2ca85436fb1a44bbee93e880b1c",
    ),
    0x1000010C000: (
        0x100001AC000,
        "46d45e3cf7376b8d2143e5d3524b8712544b064dd8c3fafe20946f3f6f251007",
    ),
}
COMPUTE_MIXED_TWO_RETAINED_CALLER_PAGE = 0x1000010C000

# The coherent render allocation places this complete, contiguous compiler
# product 0xa0000 bytes below the already hash-gated partial-render copy.
# These are caller assets, not captured firmware state; only their placement
# changes.  Page deletion proved that the entire later compiler closure must
# stay coherent, including the page at 0x100000f8000 that was absent from the
# old mixed topology.
RENDER_MIXED_RELOCATED_CALLER_PAGE_COUNT = 26
RENDER_MIXED_RELOCATED_CALLER_PAGES = {
    0x100000A0000 + index * PAGE_SIZE: (
        0x10000140000 + index * PAGE_SIZE,
        g17g_partial_assets.PARTIAL_CONTEXT_PAGE_SHA256[
            0x10000140000 + index * PAGE_SIZE
        ],
    )
    for index in range(RENDER_MIXED_RELOCATED_CALLER_PAGE_COUNT)
}
RENDER_MIXED_RELOCATED_CALLER_EDGE_PAGES = {
    address: RENDER_MIXED_RELOCATED_CALLER_PAGES[address]
    for address in (0x100000A0000, 0x10000104000)
}

COMPUTE_DISPATCH_IDENTITY = 0x000000C8010000D1
COMPUTE_SUBMISSION_ARENA_STRIDE = 0x70000
COMPUTE_DISPATCH_IDENTITY_STRIDE = 0x000000020000001F
# The earliest possible second native MTLCommandQueue advances the same
# dispatch namespace by a slightly different amount.  This is a queue-create
# transition, not an ordinary same-queue command allocation.
COMPUTE_NEW_QUEUE_DISPATCH_IDENTITY_STRIDE = 0x0000000200000015
COMPUTE_NEW_QUEUE_GENERATION_STRIDE = 0x25
COMPUTE_BATCH_BUFFER_BASE = 0x11000000000
COMPUTE_BATCH_BUFFER_STRIDE = 0x10000
# Scheduler records form a 64-entry cyclic pool. This is independent of the
# queue transport lifetime: hardware has executed records 1..64 and then a
# second 63-command wave through wrapped records 1..63 exactly.
COMPUTE_SCHEDULER_RECORD_COUNT = 64
# Queue zero's captured scheduler arena is a 64-record cyclic pool.  A
# materialized later queue accepts at most 20 scheduler records in one work
# kick.  This is a drained scheduler-wave limit, not the queue transport's
# lifetime: reset and reuse these 20 records between kicks.
COMPUTE_RECREATED_SCHEDULER_RECORD_COUNT = 20
COMPUTE_QUEUE_COMMAND_CAPACITY = 127
COMPUTE_RECREATED_QUEUE_COMMAND_CAPACITY = 127
COMPUTE_RECREATED_QUEUE_NORMAL_BASE = 0xFFFFFC20C1000000
COMPUTE_RECREATED_QUEUE_SHARED_BASE = 0xFFFFFC2001800000
COMPUTE_RECREATED_QUEUE_EPOCH_STRIDE = 0x20000
# Keep a bounded address pool for later explicit queue teardown/recreation.
COMPUTE_RECREATED_QUEUE_POOL_SIZE = 5
COMPUTE_CHANNEL_RING_SLOT_COUNT = 0x100
COMPUTE_CHANNEL_COUNTER_MASK = COMPUTE_CHANNEL_RING_SLOT_COUNT - 1
COMPUTE_STREAM_SUBMISSION_LIMIT = (1 << 16) - 1


def compute_submission_addresses(ordinal):
    """Return the caller/global object addresses for one compute command."""
    ordinal = int(ordinal)
    if not 1 <= ordinal < (1 << 16):
        raise ValueError("compute submission ordinal must fit positive u16")
    index = ordinal - 1
    scheduler_index = index % COMPUTE_SCHEDULER_RECORD_COUNT
    descriptor_index = index % COMPUTE_DESCRIPTOR_HIGH_RECORD_COUNT
    arena_delta = index * COMPUTE_SUBMISSION_ARENA_STRIDE
    descriptor_low = (
        COMPUTE_DESCRIPTOR_LOW + index * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE
        if ordinal < COMPUTE_DESCRIPTOR_LOW_RELOCATION_ORDINAL else
        COMPUTE_DESCRIPTOR_LOW_RELOCATED_BASE
        + (ordinal - COMPUTE_DESCRIPTOR_LOW_RELOCATION_ORDINAL)
        * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE
    )
    return {
        "shader": COMPUTE_SHADER + arena_delta,
        "resource": COMPUTE_RESOURCE + arena_delta,
        "cdm": COMPUTE_CDM + arena_delta,
        "robustness": COMPUTE_ROBUSTNESS + index * 0x40,
        "descriptor": (
            COMPUTE_DESCRIPTOR_PAGE
            + descriptor_index * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE
        ),
        "descriptor_low": descriptor_low,
        "scheduler": COMPUTE_GLOBAL_SCHEDULER + scheduler_index * 0x100,
        "scheduler_slot": (
            COMPUTE_GLOBAL_SCHEDULER_SLOT + scheduler_index * 4
        ),
        "status_a": COMPUTE_GLOBAL_STATUS_A + index * 0x10,
        "status_b": COMPUTE_GLOBAL_STATUS_B + index * 0x10,
        "zero_page": COMPUTE_GLOBAL_ZERO + index * 0x40,
        "event": (
            COMPUTE_EVENT_PAGE
            + index * g17g_compute.COMPUTE_EVENT_SIZE
        ),
        "dispatch_identity": (
            COMPUTE_DISPATCH_IDENTITY
            + index * COMPUTE_DISPATCH_IDENTITY_STRIDE
        ),
    }


def compute_scheduler_slot_index(ordinal):
    """Return the one-based ready-word index in the 64-record pool."""
    ordinal = int(ordinal)
    if not 1 <= ordinal < (1 << 16):
        raise ValueError("compute submission ordinal must fit positive u16")
    return (ordinal - 1) % COMPUTE_SCHEDULER_RECORD_COUNT + 1


def compute_dispatch_identity(ordinal, queue_epoch=0):
    """Return the native dispatch identity across queue-create boundaries.

    Ordinary commands advance by ``...001f``.  The first command on a newly
    materialized queue instead advances from the preceding command by
    ``...0015``.  ``queue_epoch`` is the number of such transitions before
    ``ordinal``; it is explicit because callers may choose a shorter queue
    lifetime than the 127-command transport capacity.
    """
    ordinal = int(ordinal)
    queue_epoch = int(queue_epoch)
    if not 1 <= ordinal < (1 << 16):
        raise ValueError("compute submission ordinal must fit positive u16")
    if not 0 <= queue_epoch < ordinal:
        raise ValueError("compute queue epoch is out of range")
    return (
        COMPUTE_DISPATCH_IDENTITY
        + (ordinal - 1) * COMPUTE_DISPATCH_IDENTITY_STRIDE
        - queue_epoch * (
            COMPUTE_DISPATCH_IDENTITY_STRIDE
            - COMPUTE_NEW_QUEUE_DISPATCH_IDENTITY_STRIDE
        )
    )


def compute_queue_generation(queue_epoch=0):
    """Return the selector-15/queue-record token for one queue epoch."""
    queue_epoch = int(queue_epoch)
    if not 0 <= queue_epoch < (1 << 16):
        raise ValueError("compute queue epoch must fit nonnegative u16")
    return (
        g17g_compute.COMPUTE_QUEUE_GENERATION
        + queue_epoch * COMPUTE_NEW_QUEUE_GENERATION_STRIDE
    )


def compute_queue_epoch(ordinal):
    """Return the bounded transport epoch containing ``ordinal``.

    Native pointer blocks advertise room for 639 commands. Queue zero is
    recreated when its odd item producer reaches 255 after 127 commands. A
    recreated queue drains 20-record scheduler waves and is recreated only
    when its own odd item producer reaches 255 after 127 commands.
    """
    ordinal = int(ordinal)
    if not 1 <= ordinal < (1 << 16):
        raise ValueError("compute submission ordinal must fit positive u16")
    if ordinal <= COMPUTE_QUEUE_COMMAND_CAPACITY:
        return 0
    return 1 + (
        ordinal - COMPUTE_QUEUE_COMMAND_CAPACITY - 1
    ) // COMPUTE_RECREATED_QUEUE_COMMAND_CAPACITY


def compute_channel_counter(ordinal):
    """Return channel 8's observed eight-bit producer/consumer value."""
    ordinal = int(ordinal)
    if ordinal < 0:
        raise ValueError("compute channel ordinal must be nonnegative")
    return ordinal & COMPUTE_CHANNEL_COUNTER_MASK


def compute_channel_slot_index(ordinal):
    """Return the physical outer-ring slot for a positive work ordinal."""
    ordinal = int(ordinal)
    if ordinal < 1:
        raise ValueError("compute channel slots require a positive ordinal")
    return (ordinal - 1) % COMPUTE_CHANNEL_RING_SLOT_COUNT


def build_mixed_compute_pointer_release(completed_limit, producer_limit):
    """Rearm the persistent compute queue after its mixed service idle.

    Native clears all three live pointer cursors while servicing compute one,
    then the host republishes the retired inner consumer pair together with
    compute two's new producer.  This is distinct from the compute-only path,
    where the consumer pair remains live across adjacent submissions.
    """
    completed_limit = int(completed_limit)
    producer_limit = int(producer_limit)
    if not 0 <= completed_limit < producer_limit < (1 << 32):
        raise ValueError("invalid mixed compute pointer limits")
    return g17g.build_pointer_block(
        field_00=completed_limit,
        field_30=completed_limit,
        field_40=producer_limit,
    )


def compute_queue_start_ordinal(queue_epoch):
    """Return the first global command ordinal in a transport epoch."""
    queue_epoch = int(queue_epoch)
    if not 0 <= queue_epoch < (1 << 16):
        raise ValueError("compute queue epoch must fit nonnegative u16")
    ordinal = (
        1 if queue_epoch == 0 else
        1
        + COMPUTE_QUEUE_COMMAND_CAPACITY
        + (queue_epoch - 1) * COMPUTE_RECREATED_QUEUE_COMMAND_CAPACITY
    )
    if ordinal >= (1 << 16):
        raise ValueError("compute queue epoch starts outside the u16 range")
    return ordinal


def compute_queue_command_capacity(queue_epoch):
    """Return the proven command count for one transport epoch."""
    queue_epoch = int(queue_epoch)
    if queue_epoch < 0:
        raise ValueError("compute queue epoch must be nonnegative")
    return (
        COMPUTE_QUEUE_COMMAND_CAPACITY if queue_epoch == 0 else
        COMPUTE_RECREATED_QUEUE_COMMAND_CAPACITY
    )


def compute_client_submission_addresses(ordinal):
    """Return the reusable caller arena for a logical compute ordinal."""
    ordinal = int(ordinal)
    if not 1 <= ordinal < (1 << 16):
        raise ValueError("compute submission ordinal must fit positive u16")
    arena_ordinal = (
        (ordinal - 1) % COMPUTE_SCHEDULER_RECORD_COUNT + 1
    )
    addresses = compute_submission_addresses(arena_ordinal)
    return {
        name: addresses[name]
        for name in ("shader", "resource", "cdm")
    }


def compute_recreated_queue_addresses(epoch=1):
    """Return the bounded transport slot for a post-capacity queue epoch."""
    epoch = int(epoch)
    if not 1 <= epoch < (1 << 16):
        raise ValueError("compute queue epoch must fit positive u16")
    slot = (epoch - 1) % COMPUTE_RECREATED_QUEUE_POOL_SIZE
    delta = slot * COMPUTE_RECREATED_QUEUE_EPOCH_STRIDE
    normal = COMPUTE_RECREATED_QUEUE_NORMAL_BASE + delta
    shared = COMPUTE_RECREATED_QUEUE_SHARED_BASE + delta
    return {
        "queue": normal,
        "item_ring": normal + PAGE_SIZE,
        "optional": normal + 2 * PAGE_SIZE,
        "queue_aux": normal + 3 * PAGE_SIZE,
        "scheduler": normal + 4 * PAGE_SIZE,
        # Twenty one-based 0x100-byte work records fit in the first page.  A
        # second page remains reserved so the allocation shape stays stable.
        "queue_support": normal + 6 * PAGE_SIZE,
        "pointers": shared,
        "job_list": shared + PAGE_SIZE,
        "scheduler_slot": shared + 2 * PAGE_SIZE,
    }


def compute_batch_buffer_addresses(ordinal):
    """Return three independent caller buffers for one queued command."""
    ordinal = int(ordinal)
    if not 2 <= ordinal < (1 << 16):
        raise ValueError("batched compute ordinal must be at least two")
    base = (
        COMPUTE_BATCH_BUFFER_BASE
        + (ordinal - 2) * COMPUTE_BATCH_BUFFER_STRIDE
    )
    return {
        "a": base,
        "b": base + PAGE_SIZE,
        "out": base + 2 * PAGE_SIZE,
    }

RENDER_CHANNELS = (6, 7)
RENDER_STATE_PAGE = 0xFFFFFC2000020000
RENDER_STATE_OFFSETS = (0x40, 0x140)
RENDER_CHANNEL_RING_PAGES = (0xFFFFFC20C0794000, 0xFFFFFC20C079C000)
RENDER_CHANNEL_RING_SLOT_OFFSETS = (0x2640, 0x640)
RENDER_CHANNEL_RING_SLOT_COUNT = 0x100
RENDER_INNER_RING_ITEM_COUNT = 0x500
RENDER_INNER_RING_ITEMS_PER_SUBMISSION = 3
RENDER_UNWRAPPED_STREAM_SUBMISSION_LIMIT = (
    RENDER_INNER_RING_ITEM_COUNT // RENDER_INNER_RING_ITEMS_PER_SUBMISSION
)
RENDER_STREAM_SUBMISSION_LIMIT = (1 << 16) - 1
RENDER_SERVICE_RING_SLOT_COUNT = 0x100
# Channel 12 reserves the final three ring positions for a fresh
# registration/admission pair followed by one ordinary admission.  The pair
# starts here and retires the service state from 253 to 255.
RENDER_SERVICE_REREGISTRATION_SLOT = 253
RENDER_CHANNEL_COUNTER_MASK = 0xFF
RENDER_TILING_DESCRIPTOR_PAGE = 0xFFFFFC20C0018000
RENDER_FRAGMENT_DESCRIPTOR_PAGE = 0xFFFFFC20C00B0000
# The 37-page native tiling arena ends four kilobytes into descriptor 242.
# Supply the immediately following page in both firmware-high and caller-low
# views when that descriptor is requested.
RENDER_TILING_DESCRIPTOR_EXTENSION_PAGE = 0xFFFFFC20C00AC000
RENDER_TILING_DESCRIPTOR_EXTENSION_LOW_ALIAS = 0x7200094000
# Native context zero resumes the fragment descriptor alias relation on the
# following page, but leaves this single intervening page unmapped in both
# views. Descriptor 241 straddles it. A host that requests that fresh identity
# must allocate the hole and map both aliases to the same physical page.
RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_PAGE = 0xFFFFFC20C02B4000
RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_LOW_ALIAS = 0x720029C000
# Native maps eight fragment queue-context pages (items 0..254); item 255
# begins the immediately following page, which a 256-submission host must add.
RENDER_FRAGMENT_QUEUE_CONTEXT_NATIVE_PAGE_COUNT = 8
RENDER_OPTIONAL_PAGE = 0xFFFFFC20C0600000
RENDER_EVENT_PAGE = 0xFFFFFC20C05E8000
RENDER_DEFAULT_TOKEN = 0x146
# The earliest simultaneous render+compute publication allocates transport
# records globally even though the three firmware channels retain their local
# queue identities.  Compute occupies physical record zero, TA record one,
# and fragment record two.  Pointer blocks and inner-ring records use the same
# 0x2870-byte physical stride.
RENDER_MIXED_TILING_PHYSICAL_QUEUE_INDEX = 1
RENDER_MIXED_TILING_POINTER = (
    g17g_postcontrol.QUEUE_POINTER_PAGE + 0x2870
)
RENDER_MIXED_TILING_ITEM_RING = (
    g17g_postcontrol.QUEUE_ITEM_RING_PAGE + 0x2870
)
RENDER_MIXED_FRAGMENT_PHYSICAL_QUEUE_INDEX = 2
RENDER_MIXED_FRAGMENT_POINTER = (
    g17g_postcontrol.QUEUE_POINTER_PAGE + 2 * 0x2870
)
RENDER_MIXED_FRAGMENT_ITEM_RING = (
    g17g_postcontrol.QUEUE_ITEM_RING_PAGE + 2 * 0x2870
)
RENDER_MIXED_FRAGMENT_OPTIONAL = RENDER_OPTIONAL_PAGE + 0xC0
RENDER_MIXED_TILING_OPTIONAL = RENDER_OPTIONAL_PAGE + 0x180
RENDER_MIXED_FRAGMENT_EVENT = RENDER_EVENT_PAGE + 0x40
RENDER_MIXED_TILING_EVENT = RENDER_EVENT_PAGE + 0x80
RENDER_MIXED_QUEUE_INDICES = (1, 2)
RENDER_MIXED_CONTEXT_ID = 1
RENDER_MIXED_TILING_CONTEXT_SCRATCH = 0x7200460000
RENDER_MIXED_TILING_FIRMWARE_SCRATCH = 0xFFFFFC2000200000
RENDER_MIXED_FRAGMENT_CONTEXT_SCRATCH = 0x7200488000
RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH = 0xFFFFFC2000228000
RENDER_MIXED_SCRATCH_PAGE_COUNT = 8
RENDER_MIXED_SHARED_CONTROL = 0xFFFFFC20C08B8000
RENDER_MIXED_DESCRIPTOR_OBJECTS = (
    0xFFFFFC20C08A8100,
    0xFFFFFC20C08F8000,
    0xFFFFFC20C08C8080,
    0xFFFFFC20C08CA800,
)
RENDER_MIXED_TILING_STATUS = 0xFFFFFC2001618000
RENDER_MIXED_FRAGMENT_STATUS = 0xFFFFFC2001648000
RENDER_MIXED_TILING_REGISTER_STATUS = 0x1000078000
RENDER_MIXED_FRAGMENT_REGISTER_STATUS = 0x1000260000
RENDER_MIXED_RESOURCE_ADDRESS_OFFSET = 0x8000
# A render allocated after standalone compute is not the render-first family
# above with a different token.  The earliest linked native boundary retains
# compute's physical transport record zero and adds this complete render
# allocation family without removing or replacing any context-64 leaf.
COMPUTE_PREDECESSOR_RENDER_TOKEN = 0x16
COMPUTE_PREDECESSOR_RENDER_LIFECYCLE = 0xD00100010C
COMPUTE_PREDECESSOR_RENDER_DESCRIPTOR_OBJECTS = (
    0xFFFFFC20C08A8100,
    0xFFFFFC20C08F0000,
    0xFFFFFC20C08C0080,
    0xFFFFFC20C08C2800,
)
COMPUTE_PREDECESSOR_RENDER_TILING_STATUS = 0xFFFFFC2001620000
COMPUTE_PREDECESSOR_RENDER_FRAGMENT_STATUS = 0xFFFFFC2001640000
COMPUTE_PREDECESSOR_RENDER_TILING_REGISTER_STATUS = 0x1000080000
COMPUTE_PREDECESSOR_RENDER_FRAGMENT_REGISTER_STATUS = 0x1000260000
COMPUTE_PREDECESSOR_RENDER_SHARED_CONTROL = 0xFFFFFC20C08B8000
COMPUTE_PREDECESSOR_RENDER_OPTIONAL_CONTEXT_ID = 1
COMPUTE_PREDECESSOR_PARTIAL_STORE_PIPELINE = 0x10000298400
COMPUTE_PREDECESSOR_PARTIAL_LOAD_PIPELINE = 0x10000298200
COMPUTE_PREDECESSOR_PARTIAL_RELOAD_PIPELINE = 0x10000298000
COMPUTE_PREDECESSOR_PARTIAL_VERTEX_PIPELINE = 0x10000298700
COMPUTE_PREDECESSOR_PARTIAL_AUXILIARY_OBJECT = 0x100003B0000
COMPUTE_PREDECESSOR_PARTIAL_SCISSOR_ARRAY = 0x100002A8000
COMPUTE_PREDECESSOR_PARTIAL_DEPTH_BIAS_ARRAY = 0x100003F0000
COMPUTE_PREDECESSOR_PARTIAL_COMPILER_SOURCE_BASE = 0x10000140000
COMPUTE_PREDECESSOR_PARTIAL_COMPILER_PAGE_COUNT = 27
COMPUTE_PREDECESSOR_PARTIAL_COMPILER_RELOCATION = 0x88000
COMPUTE_PREDECESSOR_PARTIAL_ZERO_COMPILER_PAGES = (
    0x100000A0000,
    0x100000A8000,
    0x100000F4000,
    0x10000104000,
)
COMPUTE_PREDECESSOR_PARTIAL_ALLOCATION_INDEX_SHA256 = (
    "595dd63b75b088d39c9ebbea242356f640cbbd91eedbc2093de020ac9a955d01"
)
COMPUTE_PREDECESSOR_PARTIAL_ADDRESS_LIST_BASE = 0x7201AA0000
COMPUTE_PREDECESSOR_PARTIAL_OPERAND_TABLE = 0x7201EA8000
COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE = 0x7201EC0000
COMPUTE_PREDECESSOR_PARTIAL_OPERAND_RUNS = tuple(
    (
        COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE
        + index * g17g_render.RENDER_OPERAND_STRIDE,
        g17g_render.RENDER_OPERAND_SIZE // PAGE_SIZE,
        False,
    )
    for index in range(g17g_render.PARTIAL_RENDER_OPERAND_COUNT)
)
# Native reserves these otherwise empty leaves before the first render after
# compute. Their contents are all zero; presence and permission class are the
# only observable ABI state.
COMPUTE_PREDECESSOR_PARTIAL_ZERO_RESERVATION_RUNS = (
    (0x1000108000, 2, False),
    (0x1000190000, 2, False),
    (0x1000218000, 2, False),
    (0x1000234000, 1, False),
    (0x1000250000, 2, False),
    (0x1000284000, 1, False),
    (0x1000290000, 1, False),
    (0x7201C78000, 2, False),
    (0x7201E80000, 2, False),
    (0x1000003C000, 1, False),
    (0x100001C0000, 1, False),
    (0x100002F8000, 2, False),
    (0x10000308000, 2, False),
    (0x10000318000, 2, False),
    (0x10000328000, 2, False),
    (0x10000338000, 2, False),
    (0x10000348000, 2, False),
    (0x10000410000, 40, True),
)
COMPUTE_PREDECESSOR_PARTIAL_RETAINED_CONTEXT1_RUNS = (
    (0x10000138000, 2, False),
)
# Native's first compute admission before a dependent partial render uses a
# smaller caller allocation than standalone compute.  The removed and added
# leaves below are all topology-only facts: every removed leaf is zero-backed,
# and the only nonzero added leaves are the source-built CDM/resource pages at
# their native caller-selected addresses.  Keep the delta compact so arbitrary
# extra direct-dispatch buffers can compose with the same base allocation.
COMPUTE_PREDECESSOR_PARTIAL_FIRST_DISPATCH_BUFFERS = (
    0x10000058000,
    0x10000060000,
    0x10000068000,
)
COMPUTE_PREDECESSOR_PARTIAL_SHADER = 0x10000168000
COMPUTE_PREDECESSOR_PARTIAL_CDM = 0x10000188000
COMPUTE_PREDECESSOR_PARTIAL_RESOURCE = 0x100001B8000
COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS = 0x1000078000
COMPUTE_PREDECESSOR_PARTIAL_ADDITIONAL_SHADER_OFFSET = 0x240
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_REMOVED_RUNS = (
    (0x1000018000, 1),
    (0x10000050000, 2),
    (0x1000005C000, 1),
    (0x10000064000, 1),
    (0x10000070000, 8),
    (0x10000098000, 2),
    (0x100000A8000, 2),
    (0x100000B8000, 2),
    (0x100000C8000, 2),
    (0x100000D8000, 2),
    (0x100000E8000, 2),
    (0x100000F8000, 3),
    (0x10000108000, 2),
    (0x10000118000, 2),
    (0x10000128000, 2),
    (0x10000170000, 1),
)
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_ADDED_RUNS = (
    (0x1000078000, 1),
    (0x10000034000, 1),
    (0x1000003C000, 1),
    (0x10000044000, 1),
    (0x10000130000, 2),
    (0x10000140000, 2),
    (0x10000178000, 2),
    (0x10000188000, 2),
    (0x10000198000, 2),
    (0x100001A8000, 2),
    (0x100001B8000, 3),
)
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_REMOVED_RUNS = (
    (0x10000098000, 2),
    (0x100000B8000, 2),
    (0x100000C8000, 2),
    (0x100000D8000, 2),
    (0x100000E8000, 2),
    (0x10000108000, 2),
    (0x10000128000, 2),
    (0x10000138000, 2),
    (0x10000148000, 2),
)
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_ADDED_RUNS = (
    (0x10000178000, 2),
    (0x10000188000, 2),
    (0x10000198000, 2),
    (0x100001A8000, 2),
)
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_SOURCE_PAGE_COUNT = 1740
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_SOURCE_RO_PAGE_COUNT = 32
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_PAGE_COUNT = 1724
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_PAGE_COUNT = 22
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_DVA_SHA256 = (
    "2edb01fec665b54516f8f7c164b081fd4e1de729ad2da0b35034a5354cb35e06"
)
COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_DVA_SHA256 = (
    "ea72821d4aa1af61db4f8f4e22548c6e40128e7722198dcf9c538f9853a52e73"
)
# The first render allocated after compute shares four caller-visible status
# leaves with the corresponding fresh firmware-high objects.  Equal zero
# contents are not enough: firmware updates the high name while the work graph
# consumes the low name, so both DVAs must resolve to the same physical page.
COMPUTE_PREDECESSOR_PARTIAL_CONTEXT1_ALIASES = {
    0x1000088000: 0xFFFFFC2001630000,
    0x1000250000: 0xFFFFFC20C08E0000,
    0x1000254000: 0xFFFFFC20C08E4000,
    0x1000260000: 0xFFFFFC2001640000,
}
# The boolean selects executable versus UXN leaf flags. These common mappings
# already have byte-identical source/native contents; only that class changes.
COMPUTE_PREDECESSOR_PARTIAL_PERMISSION_RUNS = (
    (0x10000018000, 4, True),
    (0x10000040000, 4, False),
    (0x10000138000, 6, False),
    (0x10000168000, 2, False),
    (0x100001B8000, 2, False),
    (0x100001D0000, 26, True),
    (0x10000240000, 16, True),
    (0x10000288000, 2, True),
    (0x10000310000, 2, False),
    (0x10000320000, 2, False),
    (0x10000330000, 2, False),
    (0x10000340000, 2, False),
    (0x10000350000, 22, False),
    (0x100003B0000, 2, False),
)

# Standalone compute and standalone partial rendering overprovision these
# allocations. The native compute-to-partial boundary has retired all of them.
COMPUTE_PREDECESSOR_PARTIAL_RETIRED_CONTEXT1_RUNS = (
    (0x100008C000, 1),
    (0x1000110000, 2),
    (0x1000198000, 2),
    (0x1000220000, 1),
    (0x100022C000, 1),
    (0x1000238000, 2),
    (0x1000258000, 1),
    (0x1000264000, 1),
    (0x7201EA0000, 2),
    (0x7201EB8000, 2),
    (0x10000028000, 2),
    (0x10000050000, 2),
    (0x1000005C000, 1),
    (0x10000064000, 1),
    (0x10000080000, 2),
    (0x10000098000, 2),
    (0x100000C8000, 2),
    (0x100000E4000, 1),
    (0x100000F8000, 2),
    (0x10000128000, 2),
    (0x10000150000, 2),
    (0x10000160000, 2),
    (0x10000170000, 2),
    (0x10000180000, 2),
    (0x10000190000, 2),
    (0x100001A0000, 2),
    (0x10000238000, 2),
    (0x10000280000, 2),
    (0x10000290000, 2),
    (0x100002A0000, 2),
    (0x100003A8000, 2),
    (0x100003B8000, 2),
    (0x100003C8000, 2),
    (0x100003D8000, 2),
    (0x100003E8000, 2),
) + tuple(
    (0x7200440000 + index * 0x208000, 2)
    for index in range(12)
) + tuple(
    (0x72020C0000 + index * 0x208000, 2)
    for index in range(4)
)

COMPUTE_PREDECESSOR_RENDER_RETIRED_GLOBAL_PAGES = tuple(
    list(range(0xFFFFFC20C0800000, 0xFFFFFC20C0808000, PAGE_SIZE))
    + list(range(0xFFFFFC20C0828000, 0xFFFFFC20C0830000, PAGE_SIZE))
    + list(range(0xFFFFFC20C0850000, 0xFFFFFC20C0858000, PAGE_SIZE))
)
COMPUTE_PREDECESSOR_RENDER_INHERITED_GLOBAL_PAGES = tuple(
    list(range(0xFFFFFC20C0818000, 0xFFFFFC20C0820000, PAGE_SIZE))
    + list(range(0xFFFFFC20C0840000, 0xFFFFFC20C0848000, PAGE_SIZE))
)
COMPUTE_TO_PARTIAL_RENDER_NEW_GLOBAL_PAGES = tuple(
    list(range(0xFFFFFC2000200000, 0xFFFFFC2000220000, PAGE_SIZE))
    + list(range(0xFFFFFC2000228000, 0xFFFFFC2000248000, PAGE_SIZE))
    + list(COMPUTE_PREDECESSOR_RENDER_INHERITED_GLOBAL_PAGES)
    + [
        0xFFFFFC2001618000,
        0xFFFFFC2001620000,
        0xFFFFFC2001628000,
        0xFFFFFC2001630000,
        0xFFFFFC2001638000,
        0xFFFFFC2001640000,
        0xFFFFFC20C08B8000,
        0xFFFFFC20C08C0000,
        0xFFFFFC20C08C8000,
        0xFFFFFC20C08D0000,
        0xFFFFFC20C08D4000,
        0xFFFFFC20C08D8000,
        0xFFFFFC20C08DC000,
        0xFFFFFC20C08E0000,
        0xFFFFFC20C08E4000,
        0xFFFFFC20C08F0000,
    ]
)
# The minimal native two-compute/one-render capture uses a second allocation
# family.  Its physical transport records are interleaved in allocation order
# (compute 0, TA, compute 1, fragment), while optional/event/context pools use
# their own independently observed order.  Keep this explicit: applying one
# synthetic stride to every pool is what made the relocated publication-two
# discriminator malformed.
RENDER_MIXED_TWO_TOKEN = 0x107
RENDER_MIXED_TWO_TILING_PHYSICAL_QUEUE_INDEX = 1
RENDER_MIXED_TWO_FRAGMENT_PHYSICAL_QUEUE_INDEX = 3
RENDER_MIXED_TWO_TILING_POINTER = (
    g17g_postcontrol.QUEUE_POINTER_PAGE + 0x2870
)
RENDER_MIXED_TWO_TILING_ITEM_RING = (
    g17g_postcontrol.QUEUE_ITEM_RING_PAGE + 0x2870
)
RENDER_MIXED_TWO_FRAGMENT_POINTER = 0xFFFFFC2001658000
RENDER_MIXED_TWO_FRAGMENT_ITEM_RING = 0xFFFFFC20C0900000
RENDER_MIXED_TWO_FRAGMENT_OPTIONAL = RENDER_OPTIONAL_PAGE + 0x180
RENDER_MIXED_TWO_TILING_OPTIONAL = RENDER_OPTIONAL_PAGE + 0x240
RENDER_MIXED_TWO_FRAGMENT_EVENT = RENDER_EVENT_PAGE + 0x80
RENDER_MIXED_TWO_TILING_EVENT = RENDER_EVENT_PAGE + 0xC0
RENDER_MIXED_TWO_QUEUE_INDICES = (2, 3)
RENDER_MIXED_TWO_TILING_CONTEXT_SCRATCH = 0x7200488000
RENDER_MIXED_TWO_TILING_FIRMWARE_SCRATCH = 0xFFFFFC2000228000
RENDER_MIXED_TWO_FRAGMENT_CONTEXT_SCRATCH = 0x72004B0000
RENDER_MIXED_TWO_FRAGMENT_FIRMWARE_SCRATCH = 0xFFFFFC2000250000
RENDER_MIXED_TWO_SHARED_CONTROL = 0xFFFFFC20C08C0000
RENDER_MIXED_TWO_TAGGED_ADDRESS = 0x7201EA8000
RENDER_MIXED_TWO_TILING_STATUS = 0xFFFFFC2001628000
RENDER_MIXED_TWO_FRAGMENT_STATUS = 0xFFFFFC2001650000
RENDER_MIXED_TWO_TILING_REGISTER_STATUS = 0x1000080000
RENDER_MIXED_TWO_FRAGMENT_REGISTER_STATUS = 0x1000268000
RENDER_MIXED_TWO_RESOURCE_ADDRESS_OFFSET = 0x10000
RENDER_MIXED_TWO_LIFECYCLE = 0xC901000120
RENDER_MIXED_TWO_WORK_INDEX = 1
# The earliest render-then-compute capture is a distinct allocation instance
# from the older standalone-clear witness.  These values are ordinary host
# allocation/lifecycle identities: rebuilding the clear with them makes every
# firmware work object byte-exact at that boundary.
EARLIEST_MIXED_RENDER_TOKEN = COMPUTE_MIXED_QUEUE_GENERATION
EARLIEST_MIXED_RENDER_LIFECYCLE = 0xC90100010E
RENDER_ZLS_DEPTH_DVA = 0x10000380000
RENDER_ZLS_STENCIL_DVA = 0x10000384000
RENDER_ZLS_STENCIL_ARRAY_DVA = 0x10000480000
RENDER_ZLS_DEPTH_AUX_DVA = 0x10000388000
RENDER_ZLS_STENCIL_AUX_DVA = 0x1000038C000
PARTIAL_RENDER_TOKEN = 0x103
PARTIAL_RENDER_ATTACHMENT_BASE = 0x10000058000
PARTIAL_RENDER_ATTACHMENT_SIZE = 0x10000
PARTIAL_RENDER_ATTACHMENT_STRIDE = 0x18000
PARTIAL_RENDER_ATTACHMENT_COUNT = 8
# The earliest native compute predecessor owns 0x10000068000, then places the
# eight partial attachments in the next 0x18000-stride allocation family.
MIXED_PARTIAL_RENDER_ATTACHMENT_BASE = 0x10000070000
# Every validated direct render writes the first attachment's scalar result at
# this qword.  Fresh output backing is zero, making it a real execution and
# ownership witness without relying on descriptor bookkeeping fields that can
# remain zero after a completed work item.
PARTIAL_RENDER_OUTPUT_WITNESS_OFFSET = 0x7EF8
PARTIAL_RENDER_FRESH_ZERO_RESOURCE_PAGES = (
    0x100001F8000,
    0x10000300000,
)
# The earliest native ordinal-two partial-render boundary has a caller-owned
# virtual reservation that is absent from the compact source graph.  Exact
# delta-debugging reduced it to 117 equal allocations: each maps 32 16-KiB
# pages and is followed by a two-page guard hole.  Every mapped byte is zero
# before and after the render, so this is address-space shape, not captured
# object content.  Keep the generator hash-gated while its ultimate allocator
# role is characterized.
RENDER_REPEAT_ZERO_RESERVATION_BASE = 0x1000290000
RENDER_REPEAT_ZERO_RESERVATION_RUN_COUNT = 117
RENDER_REPEAT_ZERO_RESERVATION_PAGES_PER_RUN = 32
RENDER_REPEAT_ZERO_RESERVATION_RUN_STRIDE = 0x88000
RENDER_REPEAT_ZERO_RESERVATION_DVA_SHA256 = (
    "aec42f79407d9be2179588a9f8ad4e662ed90f9512250575d75e243cc45b6dba"
)
RENDER_REPEAT_ZERO_RESERVATION_PTE_FLAGS = {
    "VALID": 1,
    "TYPE": 1,
    "AttrIndex": 2,
    "AP": 2,
    "SH": 0,
    "AF": 1,
    "nG": 1,
    "PXN": 0,
    "UXN": 1,
    "OS": 1,
}
# The reservation is accompanied by one caller-visible page of 4,096 u32
# allocation indices.  The high firmware alias and low caller alias share the
# same backing.  Its native ordinal-two image is fully generated below; the
# hash is evidence that no captured bytes have leaked into the implementation.
RENDER_REPEAT_RESERVATION_INDEX_LOW = 0x1000238000
RENDER_REPEAT_RESERVATION_INDEX_HIGH = 0xFFFFFC20C08C8000
RENDER_REPEAT_RESERVATION_INDEX_SHA256 = (
    "eb70190c0cbaa3d34fee09abf4ffca41db90040fd239ea07846681ef5f332488"
)
# After occurrence-two service, the compact source lifecycle leaves this
# paired allocation count at 0x10/0x10.  The native host clears it before the
# second work release.  Byte bisection proved the adjacent first qword is not
# required, so keep this as one guarded host field rather than a page image.
RENDER_REPEAT_PREWORK_QWORD_TRANSITIONS = {
    0xFFFFFC20015E8000: (
        (0x008, 0x0000001000000010, 0x0),
    ),
    # Fragment descriptor page containing the retired group-one tail and the
    # admitted group-two head.  Live completion endpoints at +0x2114..+0x2202
    # are intentionally absent: retaining the source-firmware values is an
    # exact-output positive.  The remaining fields are deterministic resource
    # cursor, generation, and flag transitions.
    RENDER_FRAGMENT_DESCRIPTOR_PAGE: (
        (0x20F0, 0x0000003900000000, 0x0000003800000000),
        (0x2308, 0x00000100001E8400, 0x00000100001E8540),
        (0x2320, 0x00000100001E8400, 0x00000100001E8540),
        (0x2328, 0x0000004000015369, 0x0000012000015369),
        (0x2670, 0x0100010A000160E0, 0x01000109000160E0),
        (0x2680, 0x000000D00100010A, 0x000000D001000109),
        (0x2688, 0x0100010A0000A341, 0x010001090000A341),
        (0x2A10, 0x00000100001E8400, 0x00000100001E8540),
        (0x2A28, 0x00000100001E8400, 0x00000100001E8540),
        (0x3130, 0x00000100001E8400, 0x00000100001E8540),
        (0x3148, 0x00000100001E8400, 0x00000100001E8540),
        (0x3150, 0x0000004000015369, 0x0000000000015369),
        (0x3840, 0x0000004000015369, 0x0000000000015369),
        (0x3880, 0x00000100001E8400, 0x00000100001E8540),
    ),
    # The occurrence-two service publication below materializes these
    # admission records.  Native host state retires them again before the work
    # release; the reverse transition is deterministic and contains no live
    # timestamp or captured pointer.
    g17g_postcontrol.ADDRESS_TABLE_PAGE: (
        (0x208, 0x0000000200000001, 0x0000000000000001),
        (0x220, 0x0000000100000000, 0x0),
        (0x2A0, 0xFFFFFC2000000000, 0x0),
        (0x2A8, 0x00000000010000FF, 0x0),
        (0x2B0, 0x00000000010000FE, 0x0),
        (0x2C0, 0x0000000000000001, 0x0),
    ),
    # The packed VDM vertex-pipeline word advances from USC offset +0x1e8700
    # to +0x1e8740 between these partial groups.  The low u32 is static state.
    0x1000058000: (
        (0x130, 0x00007A1C01000000, 0x00007A1D01000000),
    ),
}
# The earliest direct pair needs only the caller-side packed vertex-pipeline
# transition.  Its second command buffer uses USC offset +0x1e8d40, unlike the
# older partial lifecycle's adjacent +0x1e8700 -> +0x1e8740 transition above.
# Page deletion bisection proved every other changed context-1 page irrelevant.
RENDER_DIRECT_PAIR_PREWORK_QWORD_TRANSITIONS = {
    0x1000058000: (
        (0x130, 0x00007A1C01000000, 0x00007A3501000000),
    ),
}
# The second direct draw changes only these three admission fields in the
# live fragment descriptor.  Byte-level deletion bisection proved that the
# other 39 native byte changes on this page (timestamps, flags, generation
# records, and duplicated late records) are not required for execution.
RENDER_DIRECT_PAIR_FRAGMENT_QWORD_TRANSITIONS = {
    RENDER_FRAGMENT_DESCRIPTOR_PAGE: (
        (0x2308, 0x00000100001E8400, 0x00000100001E8540),
        (0x2320, 0x00000100001E8400, 0x00000100001E8540),
        (0x2328, 0x0000004000015369, 0x0000012000015369),
    ),
}
RENDER_DIRECT_PAIR_ORDINAL_PAGE_SHA256 = (
    "102af223ed1ffbed78d3d12e97c43ed5884dac13ff756ee80e307c5a18e3551e"
)
RENDER_REPEAT_PRISTINE_CONTEXT1_PAGE_SHA256 = {
    0x100001B8000: (
        "2fdd53dea11d7ddc17c97157e0a055ac8bc41ec81f6313fb0371cef3c5b3e957"
    ),
}
PARTIAL_RENDER_POSTCONTROL_ALIAS_DVA = 0x1000238000
PARTIAL_RENDER_POSTCONTROL_ALIAS_HIGH = 0xFFFFFC20C08C8000
PARTIAL_RENDER_EXPECTED_ATTACHMENT_SHA256 = (
    "46519eb0b0d9050d8356bfa9007c6e5bdc0aabc0aed84df569e07d79e7c22b6a",
    "4f2073413b84092cf1bfb2d59f3306e3185479aeeb90a2402de23a9303afa183",
    "77b4ccc174c9ec49d925bdab26cb847605b269ab900882db880424c059b16dc9",
    "4610ee9129a1fabc147e542508130dca829d74ca4d0a86b70e4fd091ed1f9a70",
    "fcb2da1474c1b1618a1574e6969b00e27c7b22bde67fab7ff8bb387e060b07bc",
    "36fe66cbab7b0f4c27b597cab7d65e3633f50f205095717800b64f0e09d36b19",
    "16dede1fae2d5d0a154f610d1f6d4a472e3301143a0e4897203f7465ef35050c",
    "ccbdba562a7e0ff88e94ef4a552fb6079d903f262b4fbf675a3343ca059669c6",
)
PARTIAL_RENDER_THREE_VERTEX_ATTACHMENT_SHA256 = (
    "70de9c2c43be398c4430a6f4022a17b39dc26a13d39c1f8cd9cec50f36f37c83",
    "2caa96f979d5e9fc40dde7d841957c03196560502481093e51387b738e99a054",
    "6b8e6323ae4fd5bba831461bfaffc5a7efc3b1b7337cb47df7fa03493988b12c",
    "4c401ca65a2926469d7b41fc800cc7ef39e0360534870ec1d8c672981920b47b",
    "433d9f3115623a73c148fb6aaa785b18228b3a55551f3f7eaa63515eee94106e",
    "52c8358ce0ae5e0778190ad8b1294c2d009f7746ba21db3083178f4d2dc94967",
    "2a215d697fb5b7d45216ab730443051eb09040d241f3069e39d78baf1284cc0b",
    "95a8dc86bd2d5cff197860e1431644a29b87efd47861ca966d1192f1c6a880ae",
)
# Own-source 500,000-triangle draw, one instance, default 128x128 viewport.
# Expected output only, never firmware input. Pinned source growth-off control
# 2026-09-09 02:07 and independent growth/refusal runs match all eight buffers.
PARTIAL_RENDER_500K_TRIANGLE_ATTACHMENT_SHA256 = (
    "3ae45eb30f6ed010145f9c1af0579d65929b9f701a33636694375b5be8910051",
    "e200811f59e3ed4a313d2f890cfa0e8e32423300463a8bb9c1283bb589281521",
    "6068d754efb867f20d5f103e0f4de77d62a58ac639fa6cf71f777400643f0a7b",
    "f625cd3c7399e971b34c34db7e37a62bb2c24885bd04a8eb703cc945513883f2",
    "469b876dcc185a9c5679cc0599b32db71af052f79974024412fa0536f488d288",
    "9713abfaf5ed0b6431e1a14e529a44a1ef9ad6c9a47efb8a71636d741498e1f3",
    "bcc337165cf04806e5d2a442d1dc1327e39fd9adcc1e8c866d59e97a9b17cf6a",
    "50447b67e818a5729f01f30826784f0951392d7dfa0205e15a603a3542dc7239",
)
# Three vertices under a zero-origin 64x64 explicit scissor.  Two independent
# cold starts reproduced these one-pixel images exactly.  The full-surface
# three-vertex profile above produces two pixels with the same per-attachment
# maxima, so this is a semantic clipping proof rather than retirement alone.
PARTIAL_RENDER_SCISSOR_64X64_THREE_VERTEX_ATTACHMENT_SHA256 = (
    "a4c6827bd284390892a6b5c70aa3e3ccc201afac73a22aa84d85333d8f23af7f",
    "eb2b753fae3fa2d763716a669d8fe4961c800de8a8841f810b9c809f4ddb82ef",
    "d6b1d8c191cd3084d761f8432bcd8ee1a3195f2d7cdb00e8a52ced0a3fdd874d",
    "baacd79b4f0c8b03ea1cf22361868062f7d9c2170f8a9b17723c3007bb07841e",
    "a1f9613376132f5325ee00360c006be0f5bf383d6a9a3a3b917f2e7259e76f2d",
    "fa32c58771b5edd3f267be6cfcfa3263377e4ac145a584e48b148aacc13db9c9",
    "6257f3b73d81210b68fb36c13d9015d50d489f014c885f7058d0e1319930a1d1",
    "f822d79ba508f0a783af3e52e100430c69f16a66bed3b776b45d0bc3496075b6",
)
# Three vertices under the source-built scissor (64, 0, 64, 128).  The native
# discriminator used a different shader that writes 1.0..8.0; these hashes
# instead retain this graph's established compiler assets and prove that its
# exact right-hand pixel moved from (63, 63) to (64, 63).
PARTIAL_RENDER_SCISSOR_X64_THREE_VERTEX_ATTACHMENT_SHA256 = (
    "3f192e3697ce47b15a5bf768767f35c63536fc2da8232610f97643666840d79d",
    "dc4a96aa523401555e2f3c3a4ece52890d9b260974fa5315045bfeae12cf0230",
    "33aabe256cef3f0e07bffbacb2aeb8116ce829149d2504d335da28e02d7bf3fc",
    "f721ff3e74ff0dff2130fa63f0c08e39a4d46daada422785de482732fa60a79e",
    "74c546e0aa2b41489bef131c83151b18be85311b31f24753930246d3942d6355",
    "9dc61321b23d77c5122e811e5dad03804e5a770e1286d8ad845c4c1e3edccafe",
    "642b20b92f202ab219d599a130b460cf7556a4674c122184222510cb1cdf0a76",
    "2e04391d69b65923427d5a7e8f21ce80e77c75a51ea30ed1087a29a37716f252",
)
# Three vertices with the independently selected 130x128 VDM viewport.  Two
# fresh-start executions reproduced these exact two-pixel images.  Keep this
# profile separate from the native 128x128 viewport so a viewport regression
# cannot pass merely because some output changed.
PARTIAL_RENDER_VIEWPORT_130X128_ATTACHMENT_SHA256 = (
    "e5c85f180502fa3dfd958796e4538eb1757924c8dc204d698b40802c733383bc",
    "c4185943934eda818554c6c70b24c49f8b388bd1e1ceb2bf484f86e967e6c701",
    "14a984180eab459ef5d490d95e4c7800c228466f3206bf10e9584651d8d82963",
    "19a2c43ddccc1c5315c483cf77afaf933220a6bbb85d3f55c90789f8f4acc287",
    "3c37928d8116f4403eeb19a03c098998906972a9fc9907caa3bea5db9b35adc6",
    "2cd1d4b97a4b808d43758746cf768a38db8eb50aea762453beaf21722fe3f199",
    "e6ac89bfb74b74830663d832fa04983868df599fea4ff9ab03350c64151a84f0",
    "af9678cfefcada8297b3fc94becaed207752be89ec3c87e4903974d0b3906ff7",
)
# Sixty-four three-vertex Index List records under one opening state packet.
# Two independent cold starts reproduced these hashes exactly.
PARTIAL_RENDER_64_DIRECT_ATTACHMENT_SHA256 = (
    "da2dc9437ee2c4401d3284206b8409ab319df14dceb2c0a8d9af5e3f08d954fe",
    "4aee47520f24aff03455c682b52c9dd547191bef2df6c21712b8d8b1ccba8a36",
    "1ae22598d0f48c88e83369763cbfb58d062f08c44a20381694a2667985c5912a",
    "70eb572554a164049a76feafa3875f57b130268b001bde6e0b68d480677e8e13",
    "c805fd9639d1df884ae36d02a929f1bc66193e33f6dac10f9b8f6b99a0610569",
    "ea0c767d8ac4ca4094a7f00f9711b9fa9e91eee4132614736d447565643f8a45",
    "de752a18b65ba7593786043a50bc5ca18874d1de6f5d3e403c4bd86e1514f927",
    "11cb9deadee68dc240d350159f580acd2cc26daa1e99a21dc0bfc3281430f45e",
)
# The minimal native direct-pair witness also submits three vertices, but its
# caller resource normalizes one triangle to 1.0 instead of retaining the
# original 3,085,888-triangle divisor embedded in the source baseline above.
# Keep this separate from the source three-vertex profile: matching it proves
# that an imported native work graph executed with its own caller resources.
PARTIAL_RENDER_ONE_TRIANGLE_ATTACHMENT_SHA256 = (
    "4db69d93f43172f7b638150a75dd5308ef298c47574f143be145fb6651c711e3",
    "33c9e3d15170338c9dfbf30326444d7858e2f16388a459f38aea0f6fc57327a0",
    "ebee8ba0de12deb4c50d8ec701675a211d7037d3ec93c51ee73410639f56b15f",
    "8880a686c5c8f025333efd5412f77cb460279af8124dd973a398ea20b53a7c1b",
    "11183890ebaf6c6d9d73c6860762a3a9e87142b4fd0385ea45a391b9be1936e4",
    "ebb501185516d34b802743d47144359da2c7620d97b06c3b96fd62b29c32ff04",
    "d119e7221cba62fd6d1ef6b15ce89503e3b1d504f85c088ec2f0aa7e91a4bb73",
    "82d4f06555730c07e2c483ce89d80a6bd6e119ba40030b2ac5de51869673945b",
)
PARTIAL_RENDER_SIX_VERTEX_ATTACHMENT_SHA256 = (
    "2caa96f979d5e9fc40dde7d841957c03196560502481093e51387b738e99a054",
    "4c401ca65a2926469d7b41fc800cc7ef39e0360534870ec1d8c672981920b47b",
    "52c8358ce0ae5e0778190ad8b1294c2d009f7746ba21db3083178f4d2dc94967",
    "95a8dc86bd2d5cff197860e1431644a29b87efd47861ca966d1192f1c6a880ae",
    "5071cb3017bcc0d5ec5ec72d078b0239186816b349016b740d35864830694107",
    "42af80ed6e412bda55b111a20d98818d73e8d6f489817f6ff7c9e40e0d458dfd",
    "97f4d38da648d3a54d7c493912fc3c4e8fb4012bd3eb3d36e7325d11216217c3",
    "a05a0414f938088f3cfe027390f94924c4118d00c7be33f1849942d8b3f6c098",
)
# One aligned cache line in the second 16-KiB page of attachment zero.  Its
# final four bytes contain the first nonzero native result at page offset
# 0x3efc, unlike the attachment's all-zero first page.  Intermediate
# long-stream tests remap that complete page but read this exact changing line;
# the final generation retains the full eight-attachment check.  The hash is
# evidence only; no output bytes are fed back to firmware.
PARTIAL_RENDER_PROBE_PAGE_INDEX = 1
PARTIAL_RENDER_PROBE_OFFSET = 0x3E80
PARTIAL_RENDER_PROBE_SIZE = 0x80
PARTIAL_RENDER_EXPECTED_PROBE_SHA256 = (
    "4006e9c271746d5c15d877cc21c4a8b8788e58d36855a1930043dcda5bad5ccb"
)
# Capture-specific queue identity from one native boot.  This is retained only
# for byte-comparison fixtures; same-boot render-1 -> render-2 evidence proves
# that the live queue identity does not advance between submissions.
RENDER_SECOND_TOKEN = 0xEE
RENDER_FIRST_SERVICE_HISTORY_PAGE = 0xFFFFFC20C07F8000
RENDER_SECOND_SERVICE_HISTORY_PAGE = 0xFFFFFC20C0808000
COMPUTE_TO_RENDER_HISTORY_CONTEXT_LOW = 0x7201848000
RENDER_SERVICE_HISTORY_RECORD_SIZE = 0x40
# Also emitted before the continuation records of a successful partial draw;
# this header is not an error/ENOMEM classification.
RENDER_PARTIAL_FRAGMENT_HISTORY_HEADER = 0x0101000000000263
RENDER_LIVE_ADMISSION_PAGE = 0xFFFFFC20C0790000
RENDER_LIVE_ADMISSION_QWORD_OFFSET = 0x78
RENDER_LIVE_ADMISSION_LOW32 = 0x1F40
RENDER_MIXED_LIVE_ADMISSION = 0x0000002A00001F40

# Native render->compute changes this one-byte engine discriminator before it
# publishes the batched compute service interval.  The preceding render leaves
# the byte at 1 (fragment); compute admission requires 2.  Keep the transition
# separate from the final compute graph so callers can publish it at the native
# pre-service boundary rather than too late beside the type-0x83 work kick.
COMPUTE_MIXED_PRESERVICE_ENGINE_PAGE = 0xFFFFFC20001A0000
COMPUTE_MIXED_PRESERVICE_ENGINE_OFFSET = 0x84
COMPUTE_MIXED_PRESERVICE_ENGINE_KIND = 2


def build_render_stream_ring_slot(
        queue_index, inner_head, queue_address=None, first_submit=True, engine_kind=None):
    """Build one reusable persistent-render outer-ring publication.

    The inner TA/fragment queue remains at the already retired six-entry head;
    only the outer channel slot and producer advance for stream generations
    three and later.  This is the same persistent-queue rule established on
    G17P, expressed with G17G's queue addresses and queue-index bit.
    """
    queue_index = int(queue_index)
    inner_head = int(inner_head)
    if not 0 <= queue_index < (1 << 8):
        raise ValueError("render queue index is out of range")
    if not 0 <= inner_head <= g17g.RING_SLOT_LIMIT_MASK:
        raise ValueError("render inner head does not fit in the ring slot")
    word_14 = (
        (0x01000000 if first_submit else 0)
        | (queue_index << g17g.RING_SLOT_QUEUE_INDEX_SHIFT)
        | inner_head
    )
    if queue_address is None:
        queue_address = (
            g17g_postcontrol.QUEUE_PAGE
            + queue_index * g17g.QUEUE_RECORD_STRIDE
        )
    # +0x10 is the engine kind, not the queue's grid index.  Pair zero made
    # the two values look identical (TA grid 0, fragment grid 1); a later
    # queue pair must retain kind 0/1 while word_14 carries its grid 2/3.
    kind = queue_index & 1 if engine_kind is None else int(engine_kind)
    if kind not in (0, 1):
        raise ValueError('render engine kind must be TA0 or fragment1')
    return g17g.build_ring_slot(queue_address, kind, word_14)


def render_channel_counter(value):
    """Return the observed eight-bit work-channel counter.

    The generation-256 discriminator filled outer slot 255 but left both
    channel consumers at 255 when the host published producer 256.  The work
    channels therefore use the same 256-slot counter namespace as channel 12.
    """
    value = int(value)
    if value < 0:
        raise ValueError("render channel counter source must be nonnegative")
    return value & RENDER_CHANNEL_COUNTER_MASK


def render_inner_ring_group_bounds(
        ordinal, transport_start_ordinal, initial_head=0):
    """Return the non-wrapping inner-ring interval for one render group."""
    ordinal = int(ordinal)
    transport_start_ordinal = int(transport_start_ordinal)
    initial_head = int(initial_head)
    if ordinal < transport_start_ordinal:
        raise ValueError("render ordinal precedes its transport generation")
    if not 0 <= initial_head <= RENDER_INNER_RING_ITEM_COUNT:
        raise ValueError("render transport initial head is out of range")
    start = (
        initial_head
        + (ordinal - transport_start_ordinal)
        * RENDER_INNER_RING_ITEMS_PER_SUBMISSION
    )
    return start, start + RENDER_INNER_RING_ITEMS_PER_SUBMISSION


def render_inner_ring_needs_recreation(
        ordinal, transport_start_ordinal, initial_head=0):
    """Whether the next group would cross the finite inner item ring."""
    _start, end = render_inner_ring_group_bounds(
        ordinal, transport_start_ordinal, initial_head
    )
    return end > RENDER_INNER_RING_ITEM_COUNT


def render_service_counter(value):
    """Return channel 12's observed eight-bit circular-ring counter.

    Native channel 12 inserts a registration/admission pair at slot 253, then
    uses slot 255 for the following admission before wrapping to zero.
    """
    value = int(value)
    if value < 0:
        raise ValueError("render service counter source must be nonnegative")
    return value % RENDER_SERVICE_RING_SLOT_COUNT


def render_counter_between(start, current, target):
    """Whether ``current`` lies on the short modular path to ``target``."""
    start = render_channel_counter(start)
    current = render_channel_counter(current)
    target = render_channel_counter(target)
    return (
        (current - start) & RENDER_CHANNEL_COUNTER_MASK
    ) <= (
        (target - start) & RENDER_CHANNEL_COUNTER_MASK
    )


def build_render_generation_service_record(submission_ordinal):
    """Build the opcode-0x2e admission record for render N.

    Earliest native occurrences two and three establish values one and two in
    service-ring slots four and five.  This value is a monotonic submission
    sequence; unlike the ring position, it does not wrap at 256.
    """
    submission_ordinal = int(submission_ordinal)
    if not 2 <= submission_ordinal < (1 << 32):
        raise ValueError(
            "render service ordinal must fit in u32 and be at least 2"
        )
    return g17g.build_service_opcode2e_record(submission_ordinal - 1)


def build_render_generation_service_records(
        submission_ordinal, starting_slot, *, position_registration=True):
    """Build the complete channel-12 publication for one render.

    The hash-pinned native work-257 pair establishes one topology's circular-
    ring grammar.  When ``position_registration`` is true and the next record
    occupies slot 253, macOS first republishes opcode 0x20 with the same
    sequence as the following opcode 0x2e.  Both records retire together to
    state 255.  The sequence is the source stream's own monotonic service
    lifecycle value; the native capture's absolute value is not portable
    across histories.

    The independently proven direct-draw topology has seven extra warm-up
    records and accepts an ordinary opcode 0x2e at its physical slot 253.  It
    therefore passes ``position_registration=False``: physical position alone
    is not a topology-independent registration trigger.
    """
    submission_ordinal = int(submission_ordinal)
    admission = build_render_generation_service_record(submission_ordinal)
    if (
        not position_registration
        or render_service_counter(starting_slot) != (
            RENDER_SERVICE_REREGISTRATION_SLOT
        )
    ):
        return (admission,)
    sequence = submission_ordinal - 1
    return (
        g17g.build_service_opcode20_record(
            g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS,
            g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
            sequence=sequence,
            count=16,
        ),
        g17g.build_service_opcode2e_record(sequence),
    )

# The beta-5 first-retired -> second-published native boundary changes these
# three qwords outside the queue-owned item records and channel-12 service
# state.  The three former state transitions at +0x300/+0x310/+0x320 are now
# reproduced by the independently acknowledged service-ring lifecycle below,
# rather than written as unexplained publication fields.
RENDER_SECOND_PUBLICATION_TRANSITIONS = {
    g17g_postcontrol.ADDRESS_TABLE_PAGE: (
        (0x208, 0x0, 0x1),
        (0x210, 0x0, 0x50),
    ),
    g17g_postcontrol.TARGET_RECORD_ARRAY_PAGE: (
        (0x148, 0x0, 0x100000000),
    ),
}

# Exact source-before/native-before-work closure at the early allocation-path
# ordinal-two boundary.  The source firmware accepts the asynchronous slot-4
# notification but does not consume it, so these compact host-visible
# generation fields remain at their post-first-work values.  Three independent
# native ordinal-two captures agree on the one-byte advances at ...1628000 and
# the cleared high-u32 sentinel at ...c08e8000; the same-topology capture pins
# the remaining paired generation qwords below.  Keep this distinct from the
# retained-resource post-service recipe, whose scheduler/allocator values are
# different.
RENDER_SECOND_ALLOCATION_POSTSERVICE_TRANSITIONS = {
    # These after-values come from the hash-pinned same-boot transition from
    # first-render retirement to the immediately following second-render
    # pre-kick.  Earlier values in this table mixed two boots and therefore
    # confused boot/queue identity with submission generation.
    0xFFFFFC200002C000: (
        (0x3120, 0x0000000000000002, 0x0002000000000200),
        (0x31C0, 0x0000000000000001, 0x0000000000000003),
        (0x33C0, 0x0000000000000000, 0x0000000000000037),
    ),
    g17g_initdata.REGION_20_ADDRESS: (
        (0x080, 0x0000000100000000, 0x0000000200000001),
    ),
    0xFFFFFC20015E0000: (
        (0x000, 0x00000000000000FF, 0x0000000000000400),
        (0x008, 0x00000000000000FF, 0x0000000000000400),
        (0x400, 0x0000000100000001, 0x0000000200000002),
        (0x600, 0x0000000000000002, 0x0000000000000004),
        (0xE00, 0x0000000000000002, 0x0000000000000003),
        (0xE20, 0x0000000000000001, 0x0000000000000002),
        (0xE28, 0x0000000000000001, 0x0000000000000002),
    ),
    COMPUTE_GLOBAL_SCHEDULER_SLOT: (
        (0x008, 0x0000000000000000, 0x0000000000000002),
    ),
    0xFFFFFC2001618000: (
        (0x060, 0x0000000000000000, 0x0000000000000001),
    ),
    0xFFFFFC2001628000: (
        (0x000, 0x0000000000000001, 0x0000000000000002),
    ),
    0xFFFFFC20C08E8000: (
        (0x008, 0xFFFFFFFF00000001, 0x0000000000000001),
    ),
    # The allocation-path scheduler's four history/resource cursors form one
    # fixed-stride window.  Native ordinal two selects the generation rooted
    # at ...c07e8000; source's post-first closure points each entry two pages
    # later even though both generations remain mapped.
    0xFFFFFC20C0788000: (
        (0x2738, 0xC080800000000072, 0xC07E800000000072),
        (0x2758, 0xC083000000000072, 0xC081000000000072),
        (0x2778, 0xC085800000000072, 0xC083800000000072),
        (0x2798, 0xC088000000000072, 0xC086000000000072),
    ),
    # This small admission value is the sole stable low-valued field lost
    # after source work one while remaining nonzero at both native ordinal-two
    # boundaries (1 and 3 respectively).  Successful source work one uses 1;
    # restore that source-built value rather than importing a native live page.
    RENDER_LIVE_ADMISSION_PAGE: (
        (0x098, 0x0000000000000000, 0x0000000000000001),
    ),
}


def build_relocated_first_render_service_history(
        first_record, include_fragment=False):
    """Build the occurrence-2 page from the live first-render record.

    Three source boots establish that firmware writes exactly one 0x40-byte
    record at ``...c07f8000`` while retiring the first clear.  Two independent
    early native occurrence-2 captures establish the same record layout at
    ``...c0808000``.  Its four timestamps are live firmware output, so retain
    the source values and validate only the stable numeric ABI fields.

    The native page also contains a fragment record at +0x40.  Source firmware
    emits only the tiling record, so derive a distinct monotonic fragment
    interval from that same-boot record.  Two independent earliest native
    boundaries put fragment start about 0x60 ticks after tiling completion and
    make its completion interval about four times the tiling interval.  The
    absolute values remain entirely source-live; only this numeric relation is
    synthesized.
    """
    first_record = bytes(first_record)
    if len(first_record) != RENDER_SERVICE_HISTORY_RECORD_SIZE:
        raise ValueError("first-render service history record size changed")
    qwords = struct.unpack("<8Q", first_record)
    if qwords[:2] != (0x0001000000000013, 0x20):
        raise ValueError(
            "first-render service history header changed: %#x/%#x"
            % qwords[:2]
        )
    if qwords[6:] != (
        RENDER_TILING_DESCRIPTOR_PAGE,
        0xFFFFFC20C0000000,
    ):
        raise ValueError("first-render service history targets changed")
    if not (0 < qwords[2] < qwords[3] < qwords[4] < qwords[5]):
        raise ValueError("first-render service history timestamps changed")
    page = bytearray(PAGE_SIZE)
    page[:len(first_record)] = first_record
    if include_fragment:
        tiling_duration = qwords[5] - qwords[4]
        fragment_start = qwords[5] + 0x60
        fragment_times = (
            fragment_start,
            fragment_start + 0x10,
            fragment_start + 0x18,
            fragment_start + 0x18 + 4 * tiling_duration,
        )
        fragment_record = struct.pack(
            "<8Q",
            0x0001000000000223,
            0x20,
            *fragment_times,
            RENDER_FRAGMENT_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000080,
        )
        page[
            RENDER_SERVICE_HISTORY_RECORD_SIZE:
            2 * RENDER_SERVICE_HISTORY_RECORD_SIZE
        ] = fragment_record
    return bytes(page)


def build_mixed_compute_first_type84_service_history(source_page):
    """Move the live compute record into native's one-shot service page.

    Source firmware records the completed tiling, compute, and fragment
    intervals consecutively at ``RENDER_FIRST_SERVICE_HISTORY_PAGE``.  At the
    earliest native compute-first type-0x84, only the completed compute record
    remains visible, at ``RENDER_SECOND_SERVICE_HISTORY_PAGE``.  Preserve its
    same-boot timestamps while normalizing the two stable lifecycle fields;
    no captured bytes enter the result.
    """
    source_page = bytes(source_page)
    if len(source_page) != PAGE_SIZE:
        raise ValueError("mixed compute service-history page is short")
    record_size = RENDER_SERVICE_HISTORY_RECORD_SIZE
    if any(source_page[3 * record_size:]):
        raise ValueError("mixed compute service-history tail changed")
    source_record = source_page[record_size:2 * record_size]
    qwords = struct.unpack("<8Q", source_record)
    if qwords[:2] != (0x0101000000000033, 0x20):
        raise ValueError("mixed compute service-history header changed")
    if not (0 < qwords[2] < qwords[3] < qwords[4] < qwords[5]):
        raise ValueError("mixed compute service-history timestamps changed")
    if (
        qwords[6] != COMPUTE_DESCRIPTOR_PAGE
        or qwords[7] not in (
            0xFFFFFC20C0000000,
            0xFFFFFC20C0000080,
        )
    ):
        raise ValueError(
            "mixed compute service-history targets changed: %#x/%#x"
            % qwords[6:]
        )
    target_page = bytearray(PAGE_SIZE)
    struct.pack_into(
        "<8Q",
        target_page,
        0,
        0x0001000000000033,
        0x20,
        *qwords[2:6],
        COMPUTE_DESCRIPTOR_PAGE,
        0xFFFFFC20C0000000,
    )
    return {
        RENDER_FIRST_SERVICE_HISTORY_PAGE: bytes(PAGE_SIZE),
        RENDER_SECOND_SERVICE_HISTORY_PAGE: bytes(target_page),
    }


def build_compute_to_render_service_history(source_page):
    """Relocate a retired standalone-compute record for dependent render.

    The source standalone-compute path leaves one firmware-written record at
    offset zero of ``RENDER_FIRST_SERVICE_HISTORY_PAGE``.  The earliest native
    compute-then-partial-render boundary retains the same record, including
    its same-boot timestamps, at ``RENDER_SECOND_SERVICE_HISTORY_PAGE`` and
    leaves the original page zero.  This builder validates every stable ABI
    field and moves the complete live record without importing captured data.
    """
    source_page = bytes(source_page)
    if len(source_page) != PAGE_SIZE:
        raise ValueError("standalone compute service-history page is short")
    record_size = RENDER_SERVICE_HISTORY_RECORD_SIZE
    if any(source_page[record_size:]):
        raise ValueError("standalone compute service-history tail changed")
    record = source_page[:record_size]
    qwords = struct.unpack("<8Q", record)
    if qwords[:2] != (0x0001000000000033, 0x20):
        raise ValueError("standalone compute service-history header changed")
    if not (0 < qwords[2] < qwords[3] < qwords[4] < qwords[5]):
        raise ValueError("standalone compute service-history timestamps changed")
    if qwords[6:] != (
        COMPUTE_DESCRIPTOR_PAGE,
        0xFFFFFC20C0000000,
    ):
        raise ValueError(
            "standalone compute service-history targets changed: %#x/%#x"
            % qwords[6:]
        )
    target_page = bytearray(PAGE_SIZE)
    target_page[:record_size] = record
    return {
        RENDER_FIRST_SERVICE_HISTORY_PAGE: bytes(PAGE_SIZE),
        RENDER_SECOND_SERVICE_HISTORY_PAGE: bytes(target_page),
    }


def build_second_direct_render_service_history(first_history_page, *, failed_fragment=False):
    """Relocate live work-one history into the direct-pair allocation.

    Native allocates the initially zero ``...c0808000`` page only after work
    one has completed.  Its two records therefore have to be carried forward
    from the live ``...c07f8000`` page.  Keep every firmware timestamp; if
    firmware emitted only the tiling record, synthesize the already validated
    source-live fragment interval.
    """
    first_history_page = bytes(first_history_page)
    if len(first_history_page) != PAGE_SIZE:
        raise ValueError("first-direct service history page is short")
    if failed_fragment:
        return preserve_partial_render_service_history(first_history_page, failed_fragment=True)
    tail = 2 * RENDER_SERVICE_HISTORY_RECORD_SIZE
    if any(first_history_page[tail:]):
        return preserve_partial_render_service_history(first_history_page)
    first_record = first_history_page[:RENDER_SERVICE_HISTORY_RECORD_SIZE]
    first_qwords = struct.unpack("<8Q", first_record)
    if first_qwords[:2] == (
        RENDER_PARTIAL_FRAGMENT_HISTORY_HEADER,
        0x20,
    ):
        if first_qwords[6:] != (
            RENDER_FRAGMENT_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000080,
        ):
            raise ValueError(
                "exhausted first-direct history targets changed"
            )
        if not (
            0 < first_qwords[2] < first_qwords[3]
            < first_qwords[4] < first_qwords[5]
        ):
            raise ValueError(
                "exhausted first-direct history timestamps changed"
            )
        if any(first_history_page[RENDER_SERVICE_HISTORY_RECORD_SIZE:tail]):
            raise ValueError(
                "exhausted first-direct history has an extra record"
            )
        result = bytearray(PAGE_SIZE)
        result[:RENDER_SERVICE_HISTORY_RECORD_SIZE] = first_record
        return bytes(result)
    build_relocated_first_render_service_history(first_record)
    fragment_record = first_history_page[
        RENDER_SERVICE_HISTORY_RECORD_SIZE:tail
    ]
    if fragment_record == bytes(RENDER_SERVICE_HISTORY_RECORD_SIZE):
        return build_relocated_first_render_service_history(
            first_record, include_fragment=True
        )
    fragment_qwords = struct.unpack("<8Q", fragment_record)
    if fragment_qwords[:2] not in (
        (0x0001000000000223, 0x20),
        (0x0101000000000223, 0x20),
    ):
        raise ValueError("first-direct fragment history header changed")
    if fragment_qwords[6:] != (
        RENDER_FRAGMENT_DESCRIPTOR_PAGE,
        0xFFFFFC20C0000080,
    ):
        raise ValueError("first-direct fragment history targets changed")
    if not (
        0 < fragment_qwords[2] < fragment_qwords[3]
        < fragment_qwords[4] < fragment_qwords[5]
    ):
        raise ValueError("first-direct fragment history timestamps changed")
    result = bytearray(PAGE_SIZE)
    result[:tail] = first_history_page[:tail]
    return bytes(result)


def preserve_partial_render_service_history(page, *, failed_fragment=False):
    """Validate and carry the complete live history of one partial draw.

    A successful source 500k-triangle draw emits an opening fragment record,
    repeated fragment continuations, then tiling and final fragment records.
    These are firmware-written same-boot records, not captured input. Keep
    every timestamp and record; do not truncate the page to the tiny-draw pair.
    Only this observed grammar is accepted here, not arbitrary record types.
    The opt-in failed form is the three-record live source history after a
    validated memory-limit type7/type9 termination; both fragment descriptor
    references carry low bit one. Preserve that tag and all timestamps,
    without assigning the tag a meaning or inventing successful completion.
    """
    if not isinstance(failed_fragment, bool):
        raise ValueError("failed fragment history selection must be boolean")
    page = bytes(page)
    if len(page) != PAGE_SIZE:
        raise ValueError("partial render service history page is short")
    records = []
    ended = False
    for offset in range(0, PAGE_SIZE, RENDER_SERVICE_HISTORY_RECORD_SIZE):
        words = struct.unpack_from("<8Q", page, offset)
        if not any(words):
            ended = True
            continue
        if ended:
            raise ValueError("partial render service history has a hole")
        records.append(words)
    if len(records) < 3:
        raise ValueError("partial render service history is incomplete")
    if failed_fragment and len(records) != 3:
        raise ValueError("qualified memory-limit history must contain exactly three records")
    headers = ([RENDER_PARTIAL_FRAGMENT_HISTORY_HEADER]
               + [0x01010000000002A3] * (len(records) - 3)
               + [0x0001000000000013, 0x00010000000002E3])
    for words, header in zip(records, headers):
        tiling = header == 0x0001000000000013
        targets = (RENDER_TILING_DESCRIPTOR_PAGE, 0xFFFFFC20C0000000) if tiling else (
            RENDER_FRAGMENT_DESCRIPTOR_PAGE | int(failed_fragment), 0xFFFFFC20C0000080)
        allowed_headers = (header, 0x01010000000002E3) if header == 0x00010000000002E3 else (header,)
        if words[0] not in allowed_headers or words[1] != 0x20 or words[6:] != targets:
            raise ValueError("partial render service history header/targets changed")
        if not 0 < words[2] < words[3] < words[4] < words[5]:
            raise ValueError("partial render service history timestamps changed")
    return page


def build_first_render_fragment_completion_qwords(
        first_record, fragment_record=None):
    """Build the missing fragment half of the first completion closure.

    At the matched occurrence-2 boundary, the native fragment queue
    accumulator equals the difference between its two descriptor completion
    timestamps.  Source firmware exposes the same invariant for tiling, but
    leaves the fragment accumulator, descriptor endpoints, shared completion
    endpoint, and generation byte zero.  Use the synthetic same-boot fragment
    record above to construct a coherent non-captured completion discriminator.
    """
    first_record = bytes(first_record)
    build_relocated_first_render_service_history(first_record)
    if len(first_record) != RENDER_SERVICE_HISTORY_RECORD_SIZE:
        raise ValueError("first-render service history record size changed")
    qwords = struct.unpack("<8Q", first_record)
    if qwords[:2] != (0x0001000000000013, 0x20):
        raise ValueError("first-render service history header changed")
    if fragment_record is None:
        synthetic = build_relocated_first_render_service_history(
            first_record, include_fragment=True
        )
        fragment_record = synthetic[
            RENDER_SERVICE_HISTORY_RECORD_SIZE:
            2 * RENDER_SERVICE_HISTORY_RECORD_SIZE
        ]
        fragment_qwords = struct.unpack("<8Q", fragment_record)
        start, end = fragment_qwords[4:6]
    else:
        fragment_record = bytes(fragment_record)
        if len(fragment_record) != RENDER_SERVICE_HISTORY_RECORD_SIZE:
            raise ValueError("first-render fragment history size changed")
        fragment_qwords = struct.unpack("<8Q", fragment_record)
        if fragment_qwords[:2] != (0x0001000000000223, 0x20):
            raise ValueError("first-render fragment history header changed")
        if fragment_qwords[6:] != (
            RENDER_FRAGMENT_DESCRIPTOR_PAGE,
            0xFFFFFC20C0000080,
        ):
            raise ValueError("first-render fragment history targets changed")
        if not (
            0 < fragment_qwords[2] < fragment_qwords[3]
            < fragment_qwords[4] < fragment_qwords[5]
        ):
            raise ValueError("first-render fragment history timestamps changed")
        start, end = fragment_qwords[4:6]
    if not 0 < start < end:
        raise ValueError("first-render completion endpoints changed")
    duration = end - start
    if duration >= 1 << 32:
        raise ValueError("first-render completion duration changed")
    return {
        g17g_postcontrol.QUEUE_PAGE: (
            (g17g.QUEUE_RECORD_STRIDE + g17g.QUEUE_ACCUMULATOR_OFFSET,
             0, duration),
        ),
        RENDER_FRAGMENT_DESCRIPTOR_PAGE: (
            (0x2114, 0, start),
            (0x211C, 0, end),
        ),
        g17g_render.STATUS_A & ~(PAGE_SIZE - 1): (
            (g17g_render.STATUS_A - (g17g_render.STATUS_A & ~(PAGE_SIZE - 1))
              - 8, 0, 1),
            (g17g_render.STATUS_B - (g17g_render.STATUS_B & ~(PAGE_SIZE - 1)),
             0, end),
        ),
    }

# Stable state already present before native first work, after the first
# channel-12 service interval.  Source firmware consumes that interval but
# does not materialize these small updates; leaving them at their earlier
# values changes the first work kick's completion routing from one primary plus
# eight secondary events to primary-only events.  The byte at 0x...2c000
# +0x3122 is especially phase-specific: it is zero on both sides of native
# service consumption, then the host sets it to 2 before the work kick.
RENDER_FIRST_WORK_LIFECYCLE_TRANSITIONS = {
    0xFFFFFC200002C000: (
        (0x3120, 0x0, 0x0000000000020000),
    ),
    0xFFFFFC20015E0000: (
        (0x000, 0x0, 0x400),
        (0x008, 0x0, 0x400),
        (0x400, 0x0, 0x0000000100000001),
        (0x600, 0x0, 0x2),
        (0x800, 0x0, 0xFFFFFC20C07C0000),
        (0xC00, 0x0, 0x2000),
        (0xE00, 0x0, 0x2),
        (0xE20, 0x0, 0x1),
        (0xE28, 0x0, 0x1),
    ),
    0xFFFFFC20015F0000: (
        (0x008, 0x00001A0000000000, 0x00001E0000000000),
        (0x010, 0x0008000000001A00, 0x0008000000001E00),
    ),
    COMPUTE_GLOBAL_SCHEDULER_SLOT: (
        (0x000, 0x0000000100000000, 0x0000000200000000),
    ),
    COMPUTE_GLOBAL_STATE: (
        (0x000, 0x1, 0x2),
    ),
    0xFFFFFC2001628000: (
        (0x000, 0x0, 0x1),
    ),
    g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS: (
        (0x048, 0x0160800000000068, 0x0160800000000078),
    ),
    0xFFFFFC20C07A8000: (
        (0x3800, 0x0, 0x2A),
        (0x3840, 0x0, 0x2A),
    ),
}

# Stable numeric first-retired state present in two independent native boots
# before the next service interval.  The source first clear executes, but its
# firmware does not materialize these host-lifecycle updates.  Keep this as a
# sparse exact-before transition rather than importing any native page.
RENDER_POST_FIRST_LIFECYCLE_TRANSITIONS = {
    # The pre-init scheduler page carries a two-byte-stride phase counter and
    # a three-byte engine-state ring.  Source firmware advances the counter
    # while leaving the first-work byte in lane 2.  Native host state before
    # occurrence 2 holds the counter at 4, rotates value 2 into lane 0, and
    # publishes service generation 1.  The next service advances these to
    # counter 6, lanes 0/1 populated, and generation 2.
    0xFFFFFC200002C000: (
        (0x3118, 0x0000000600000000, 0x0000000400000000),
        (0x3120, 0x0000000000020000, 0x0000000000000002),
        (0x31C0, 0x0, 0x1),
        (0x2BC0, 0x0, 0x3000001D00000000),
        (0x3180, 0x0000000100000000, 0x0000000100000205),
        (0x3420, 0x1, 0x0),
        (0x3488, 0x4, 0x0000000300000001),
        (0x3490, 0x0000000100000000, 0x0),
        (0x34A0, 0x0, 0x1),
        (0x34A8, 0x0, 0xFFFFFC20C07D8004),
        (0x34B0, 0x0, 0x10000EA),
        (0x34B8, 0x0, 0x100),
        (0x34C0, 0x0, 0x1),
        (0x34C8, 0x0, 0x1),
        # Source firmware publishes the first render's tiling-stage identity
        # at +0x33c0 but leaves the paired fragment lane zero.  At the exact
        # native occurrence-2 admission boundary both lanes are 0x2d.
        (0x33E0, 0x0, 0x2D),
    ),
    # The same static scheduler control word is mirrored in a second pre-init
    # page.  Source work sets the adjacent high u32; native host state clears
    # it before the next service interval.
    0xFFFFFC20000E0000: (
        (0x3440, 0x0000000100000000, 0x0000000100000205),
        (0x3458, 0x1, 0x0),
    ),
    # Native clears the low byte of root +0x20's first control qword only
    # after the first render retires.  This was the sole differing byte on
    # the otherwise-exact small context-64 page at the matched occurrence-2
    # admission boundary.
    g17g_initdata.REGION_20_ADDRESS: (
        (0x080, 0x0000000100000001, 0x0000000100000000),
    ),
    0xFFFFFC20001C8000: (
        (0x000, 0x0, 0x0000010000000100),
    ),
    0xFFFFFC20015E0000: (
        (0x000, 0x400, 0xFF),
        (0x008, 0x400, 0xFF),
    ),
    0xFFFFFC20015E8000: (
        (0x008, 0x0, 0x0000000800000008),
    ),
    0xFFFFFC2001618000: (
        (0x060, 0x1, 0x0),
    ),
    # The source first clear materializes its tiling-status companion but
    # leaves the fragment-status page zero.  Use the values paired with the
    # source workload's observed tiling status in the earlier native boot.
    g17g_render.FRAGMENT_STATUS: (
        (0x000, 0x0, 0x000000D2000006F7),
        (0x010, 0x0, 0x000000D2000006F7),
    ),
    g17g_postcontrol.ADDRESS_TABLE_PAGE: (
        (0x108, 0x0000000100000000, 0x0000000200000000),
        (0x1B0, 0x0, 0x10000EA),
        (0x1C0, 0x0, 0x1),
    ),
    g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS: (
        # Source firmware sets byte +0x44 while retiring the first work.
        # Native host state clears it before occurrence-2 service admission.
        # It is the only differing byte in this descriptor at that boundary.
        (0x040, 0x0000000100000000, 0x0),
        (0x050, 0x00000001FFFFFC20, 0x00000002FFFFFC20),
    ),
    0xFFFFFC20C08E8000: (
        (0x000, 0x0, 0x0000000100000001),
        # This high u32 is transient: zero immediately after first-render
        # retirement, all ones immediately before occurrence-2 type-0x84,
        # then zero again after firmware consumes slot 4.
        (0x008, 0x0000000000000001, 0xFFFFFFFF00000001),
    ),
    0xFFFFFC20C0788000: (
        (0x2738, 0xC07F800000000072, 0xC080800000000072),
        (0x2750, 0x0187000000000001, 0x0187000000000002),
        (0x2758, 0xC082000000000072, 0xC083000000000072),
        (0x2778, 0xC084800000000072, 0xC085800000000072),
    ),
    # Firmware materializes four of the six queue-control qwords after work;
    # these two host-owned words complete the exact native service-2 view.
    g17g_postcontrol.QUEUE_ADDRESS_70_PAGE: (
        (0x020, 0x0002000000000000, 0xA802000000000000),
        (0x028, 0x0, 0x0000000670000001),
    ),
    # Source firmware advances these three primary-main counters after the
    # first clear, but both matched native boots retain zero through the
    # occurrence-2 admission/consumption boundary.
    0xFFFFFC20C07A4000: (
        (0x3160, 0x0000000200000001, 0x0),
        (0x3168, 0x0000000100000003, 0x0000000100000000),
    ),
    0xFFFFFC20C0790000: (
        (0x280, 0x60000, 0x10000),
        (0x328, 0x0, 0x200),
    ),
    # Both native occurrence-2 allocation policies retire the first render's
    # job-list links and compact (record-count, token) companion before slot
    # 4 becomes visible.
    COMPUTE_JOB_LIST_PAGE: (
        (0x000, 0xFFFFFC20C08A8100, 0x0),
        (0x008, 0xFFFFFC20C08A8198, 0xFFFFFC2000000000),
    ),
    0xFFFFFC20000DC000: (
        (0x2C40, 0x16, 0x0),
        (0x2C48, RENDER_DEFAULT_TOKEN, 0x0),
    ),
}

RENDER_POST_FIRST_ALLOCATOR_PAGE = 0xFFFFFC20015F0000
RENDER_POST_FIRST_ALLOCATOR_OFFSETS = (0x008, 0x010, 0x018)
RENDER_POST_FIRST_ALLOCATOR_RESOURCE_BEFORE = 0x00001E0000000000
RENDER_POST_FIRST_ALLOCATOR_RESOURCE_AFTER = 0x00001F3000000130
RENDER_POST_FIRST_ALLOCATOR_CURSOR_BEFORE = 0x0008000000001E00
RENDER_POST_FIRST_ALLOCATOR_CURSOR_AFTER = 0x0008000000001E00
RENDER_POST_FIRST_ALLOCATOR_RELEASED_BEFORE = 0x0
RENDER_POST_FIRST_ALLOCATOR_RELEASED_AFTER = 0x0

# Exact stable numeric state changed across the retained-generation native
# occurrence-2 service transaction.  Queue consumer/ack fields and live
# timestamps are deliberately excluded: those remain firmware output.  The
# tiling stage byte at +0x33c0 remains 0x2d while the fragment byte advances
# to 0x50, and the paired resource-generation records advance coherently.
RENDER_SECOND_MINIMAL_POSTSERVICE_TRANSITIONS = {
    0xFFFFFC2000024000: (
        (0x0E40, 0x1, 0x2),
    ),
    0xFFFFFC200002C000: (
        (0x3118, 0x0000000600000000, 0x0000000800000000),
        (0x3120, 0x0000000000000002, 0x0200000000000002),
        (0x31E0, 0x2, 0x3),
        (0x33E0, 0x2D, 0x50),
        (0x34D0, 0x0, 0x0000000300000001),
        (0x34E8, 0x0, 0x1),
        (0x34F0, 0x0, 0xFFFFFC20C07D8004),
        (0x34F8, 0x0, 0x00000000010000FE),
        (0x3500, 0x0, 0x200),
        (0x3508, 0x0, 0x1),
        (0x3510, 0x0, 0x1),
    ),
    g17g_initdata.REGION_20_ADDRESS: (
        (0x080, 0x0000000100000000, 0x0000000200000000),
    ),
    0xFFFFFC20001C8000: (
        (0x000, 0x0000010000000100, 0x0000020000000200),
    ),
    0xFFFFFC20015E0000: (
        (0x000, 0xFF, 0x400),
        (0x400, 0x0000000100000001, 0x0000000200000002),
        (0x600, 0x2, 0x4),
        (0xE00, 0x2, 0x4),
        (0xE20, 0x1, 0x2),
        (0xE28, 0x1, 0x2),
    ),
    RENDER_POST_FIRST_ALLOCATOR_PAGE: (
        (0x008, 0x00001F3800000138, 0x00001FB0000001B0),
    ),
    0xFFFFFC20015E8000: (
        (0x008, 0x0000000800000008, 0x0000001000000010),
    ),
    COMPUTE_GLOBAL_SCHEDULER_SLOT: (
        (0x008, 0x0, 0x2),
    ),
    COMPUTE_GLOBAL_STATE: (
        (0x000, 0x2, 0x4),
    ),
    g17g_render.TILING_STATUS: (
        (0x040, 0x0, 0x000000480000059D),
        (0x050, 0x0, 0x000000480000059D),
    ),
    0xFFFFFC2001628000: (
        (0x000, 0x1, 0x2),
    ),
    g17g_render.FRAGMENT_STATUS: (
        (0x040, 0x0, 0x00000030000006F7),
        (0x050, 0x0, 0x00000030000006F7),
    ),
    g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS: (
        (0x050, 0x00000002FFFFFC20, 0x00000004FFFFFC20),
    ),
    0xFFFFFC20C08E8000: (
        (0x000, 0x0000000100000001, 0x0000000200000002),
        (0x008, 0xFFFFFFFF00000001, 0x0000000000000001),
        (0x010, 0x0000000100000000, 0x0000000200000000),
    ),
    # Exact same-boot occurrence-2 service response on the channel-control
    # object referenced by both selector-15 records.  Source matches all
    # three pre-service values but its firmware does not materialize this
    # response; leaving the object in generation one lets tiling retire while
    # fragment is silently skipped.
    g17g_postcontrol.QUEUE_ADDRESS_70_PAGE: (
        (0x008, 0x001C00005DC00000, 0x000000005DC00000),
        (0x020, 0xA802000000000000, 0x5202000000000000),
        (0x028, 0x0000000648000001, 0x000000087A000003),
    ),
    # Native occurrence-2 type-0x84 changes the relocated live history from
    # group one to group two.  Byte +0x47 is the fragment-stage discriminator:
    # tiling remains stage 0 while fragment advances to stage 1.  The two
    # descriptor pointers advance by their exact per-group object strides.
    RENDER_SECOND_SERVICE_HISTORY_PAGE: (
        (0x000, 0x0001000000000013, 0x0002000000000013),
        (
            0x030,
            RENDER_TILING_DESCRIPTOR_PAGE,
            RENDER_TILING_DESCRIPTOR_PAGE
            + g17g_render.TILING_DESCRIPTOR_SIZE,
        ),
        (0x040, 0x0001000000000223, 0x0102000000000223),
        (
            0x070,
            RENDER_FRAGMENT_DESCRIPTOR_PAGE,
            RENDER_FRAGMENT_DESCRIPTOR_PAGE
            + g17g_render.FRAGMENT_DESCRIPTOR_SIZE,
        ),
    ),
}

# After the common second-publication qword installs address-table record two
# with count one, the retained native path publishes the remainder of that
# record and its resource-list tail.  The high stage/generation u32 at +0x20c
# is the only changed byte in the first qword, but native publishes the six
# qwords as one coherent work-admission record.  Keep this separate so the
# allocation-heavy repeat recipe remains unchanged.
RENDER_SECOND_MINIMAL_WORK_TRANSITIONS = {
    g17g_postcontrol.ADDRESS_TABLE_PAGE: (
        (0x208, 0x0000000000000001, 0x0000000200000001),
        (0x220, 0x0000000000000000, 0x0000000100000000),
        (0x2A0, 0x0000000000000000, 0xFFFFFC2000000000),
        (0x2A8, 0x0000000000000000, 0x00000000010000FF),
        (0x2B0, 0x0000000000000000, 0x00000000010000FE),
        (0x2C0, 0x0000000000000000, 0x0000000000000001),
    ),
}


def is_post_first_render_allocator_resource(value):
    """Validate the compact live resource/cursor pair after first work.

    The qword stores the same allocation advance twice: the upper 16-bit
    field starts at 0x1e00 and the low field starts at zero.  Native early
    snapshots show 0x120 after both render engines retire, while the
    compiler-closure diagnostic reached the adjacent 0x118 state.  Accept
    only aligned, bounded values that retain that exact relation.
    """
    value = int(value)
    upper = (value >> 32) & 0xffff
    lower = value & 0xffff
    return (
        value == (upper << 32) | lower
        and lower < 0x2000
        and lower & 7 == 0
        and upper == 0x1e00 + lower
    )


def is_post_first_render_lifecycle_source_value(
        address, offset, value, exemplar):
    """Accept an exact or structurally bounded live source-before value."""
    address = int(address)
    offset = int(offset)
    value = int(value)
    exemplar = int(exemplar)
    if value == exemplar:
        return True
    if (
        address == 0xFFFFFC200002C000
        and 0x34A0 <= offset <= 0x34C8
        and offset & 7 == 0
    ):
        # Before the host publishes the post-retirement records, firmware's
        # live two-engine path leaves the RTKit stack sentinel in all six
        # qwords.  Native snapshots taken after the host reaction already
        # contain the destination records and therefore do not expose this
        # intermediate state.
        return value == int.from_bytes(b"RTKSTACK", "little")
    if (
        address == g17g_render.FRAGMENT_STATUS
        and offset in (0x000, 0x010)
    ):
        return (
            value & 0xffffffff in (0x427, 0x6f7)
            and value >> 32 <= 0x1ff
        )
    if (
        address == g17g_postcontrol.QUEUE_ADDRESS_70_PAGE
        and offset == 0x020
    ):
        high = value >> 48
        return value & 0x0000ffffffffffff == 0 and high & 0xff == 0x02
    if (
        address == g17g_postcontrol.QUEUE_ADDRESS_70_PAGE
        and offset == 0x028
    ):
        return value & 0xffffff == 1
    if (address, offset) == (0xFFFFFC20C0790000, 0x280):
        return value & 0xFFFF == 0 and 2 <= value >> 16 <= 0xFFFF
    if (
        (address, offset)
        == (g17g_postcontrol.ADDRESS_TABLE_PAGE, 0x190)
    ):
        return value in (0x1, 0x0000000100000000)
    return False

RENDER_SECOND_SERVICE_STATE = 0xFFFFFC2001638000
RENDER_SECOND_SERVICE_OBJECT = 0xFFFFFC20C08F0000
RENDER_SECOND_ADDRESS_LIST_BASE = 0x7202298000
RENDER_SECOND_OPERAND_TABLE = 0x72026A0000
# The early post-clear service object refers back to the already-established
# first-render operand runs.  A later capture happened to contain a separate
# allocation at 0x72026b8000; that allocation is not present at the actual
# occurrence-2 admission boundary.
RENDER_SECOND_OPERAND_BASE = 0x7200000000
RENDER_SECOND_RETIRED_CONTEXT1_RUNS = (
    (0x7200200000, 2, False),
    (0x7200408000, 2, False),
    (0x7200610000, 2, False),
    (0x7200818000, 2, False),
    (0x7200A20000, 2, False),
    (0x7200C28000, 2, False),
    (0x7200E30000, 2, False),
    (0x7201038000, 2, False),
    (0x7201240000, 2, False),
    (0x7201448000, 2, False),
    (0x7201650000, 2, False),
    (0x7201858000, 2, False),
    (0x7201A60000, 2, False),
    (0x7201C68000, 2, False),
    (0x7201E70000, 4, False),
    (0x7201E88000, 128, False),
    (0x7202090000, 128, False),
)
RENDER_SECOND_CONTEXT1_RUNS = (
    (0x7200400000, 2, False),
    (0x7200418000, 2, False),
    (0x7200620000, 2, False),
    (0x7200828000, 2, False),
    (0x7200A30000, 2, False),
    (0x7200C38000, 2, False),
    (0x7200E40000, 2, False),
    (0x7201048000, 2, False),
    (0x7201250000, 2, False),
    (0x7201458000, 2, False),
    (0x7201660000, 2, False),
    (0x7201868000, 2, False),
    (0x7201A70000, 2, False),
    (0x7201C78000, 2, False),
    (RENDER_SECOND_ADDRESS_LIST_BASE, 256, False),
    (RENDER_SECOND_OPERAND_TABLE, 4, False),
)
RENDER_SECOND_CONTEXT1_PAGE_COUNT = 288
RENDER_SECOND_CONTEXT1_DVA_SHA256 = (
    "fb01b0007edc453a7d52fd1077df09bf46f971d7dc641e2919c4b7ec9524c03b"
)
RENDER_SECOND_RETIRED_CONTEXT1_DVA_SHA256 = (
    "e8238d483ba3fc30b67edcc28365ce2fd90c39cd81a757c20d9dcef3c150f5dc"
)


def expand_render_repeat_zero_reservation_dvas():
    """Return the reduced native allocation reservation in DVA order."""
    dvas = tuple(
        RENDER_REPEAT_ZERO_RESERVATION_BASE
        + run * RENDER_REPEAT_ZERO_RESERVATION_RUN_STRIDE
        + page * PAGE_SIZE
        for run in range(RENDER_REPEAT_ZERO_RESERVATION_RUN_COUNT)
        for page in range(RENDER_REPEAT_ZERO_RESERVATION_PAGES_PER_RUN)
    )
    expected_count = (
        RENDER_REPEAT_ZERO_RESERVATION_RUN_COUNT
        * RENDER_REPEAT_ZERO_RESERVATION_PAGES_PER_RUN
    )
    if len(dvas) != expected_count or dvas != tuple(sorted(set(dvas))):
        raise ValueError("repeat-render zero reservation shape changed")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if (
        hashlib.sha256(encoded).hexdigest()
        != RENDER_REPEAT_ZERO_RESERVATION_DVA_SHA256
    ):
        raise ValueError("repeat-render zero reservation DVA hash changed")
    return dvas


def build_render_repeat_reservation_index_page():
    """Build the exact ordinal-two reservation-index page from ABI rules."""
    values = []
    for start in (0x11, 0x22, 0x33):
        values.extend(range(start, start + 0x10))
    value = 0x52
    while len(values) < PAGE_SIZE // 4:
        if value % 0x11 != 0xD:
            values.append(value)
        value += 1
    body = struct.pack("<%dI" % len(values), *values)
    if len(body) != PAGE_SIZE or values[-1] != 0x111D:
        raise ValueError("repeat-render reservation-index shape changed")
    if hashlib.sha256(body).hexdigest() != (
        RENDER_REPEAT_RESERVATION_INDEX_SHA256
    ):
        raise ValueError("repeat-render reservation-index hash changed")
    return body


def apply_render_repeat_prework_qword_transitions(
        page_images, transition_recipe=None):
    """Apply guarded ordinal-two host fields to live source page images."""
    if transition_recipe is None:
        transition_recipe = RENDER_REPEAT_PREWORK_QWORD_TRANSITIONS
    result = {int(address): bytearray(body)
              for address, body in page_images.items()}
    if set(result) != set(transition_recipe):
        raise ValueError("repeat-render prework transition page set changed")
    for address, entries in transition_recipe.items():
        body = result[address]
        if len(body) != PAGE_SIZE:
            raise ValueError("repeat-render prework transition page is short")
        for offset, expected_before, after_value in entries:
            before_value = struct.unpack_from("<Q", body, offset)[0]
            if before_value not in (expected_before, after_value):
                raise ValueError(
                    "repeat-render prework source mismatch at %#x: "
                    "expected source %#x or target %#x, found %#x"
                    % (
                        address + offset,
                        expected_before,
                        after_value,
                        before_value,
                    )
                )
            if before_value == expected_before:
                struct.pack_into("<Q", body, offset, after_value)
    return {address: bytes(body) for address, body in result.items()}


def build_render_repeat_pristine_context1_pages():
    """Return compiler pages that ordinal two resets to pristine host assets."""
    assets = g17g_partial_assets.build_partial_context_pages()
    result = {}
    for address, expected_digest in (
        RENDER_REPEAT_PRISTINE_CONTEXT1_PAGE_SHA256.items()
    ):
        body = assets.get(address)
        if body is None or len(body) != PAGE_SIZE:
            raise ValueError("repeat-render pristine page is absent")
        if hashlib.sha256(body).hexdigest() != expected_digest:
            raise ValueError("repeat-render pristine page hash changed")
        result[address] = body
    return result


def build_render_repeat_context1_pages():
    """Build every characterized caller page required before generation two."""
    result = build_render_repeat_pristine_context1_pages()
    repeat_products = (
        g17g_partial_repeat_assets.build_partial_repeat_context_pages()
    )
    overlap = set(result) & set(repeat_products)
    if overlap:
        raise ValueError(
            "repeat caller products overlap pristine page %#x" % min(overlap)
        )
    result.update(repeat_products)
    return dict(sorted(result.items()))


def build_second_direct_render_caller_pages():
    """Build the immutable Metal caller bundle used by direct work two."""
    result = g17g_direct_pair_assets.build_direct_pair_context_pages()
    ordinal_address = next(iter(
        RENDER_DIRECT_PAIR_PREWORK_QWORD_TRANSITIONS
    ))
    source = g17g_encoder.build_partial_bound_state_pages()[ordinal_address]
    ordinal_page = apply_render_repeat_prework_qword_transitions(
        {ordinal_address: source},
        RENDER_DIRECT_PAIR_PREWORK_QWORD_TRANSITIONS,
    )[ordinal_address]
    if hashlib.sha256(ordinal_page).hexdigest() != (
            RENDER_DIRECT_PAIR_ORDINAL_PAGE_SHA256):
        raise ValueError("G17G direct-pair ordinal page changed")
    result[ordinal_address] = ordinal_page
    return dict(sorted(result.items()))


def build_direct_pair_accumulation_outputs(triangles):
    """Exact test oracle for the existing 128x128 unit-scale caller bundle.

    Own partial_vertex uses dimensions=(128,128,3,1), unlike work one's
    divisor 3085888. Each centered triangle covers pixels (63,63), (64,63)
    and adds attachment_index+1 to R32Float from zero. Bound the count so all
    additions, including attachment eight, stay exactly representable.
    This constructs expected output only, never submission input.
    """
    if type(triangles) is not int or not 1 <= triangles <= (1 << 21):
        raise ValueError("unit-scale oracle requires 1..2097152 triangles")
    outputs = []
    for attachment in range(8):
        output = bytearray(128 * 128 * 4)
        for x in (63, 64):
            struct.pack_into("<f", output, (63 * 128 + x) * 4,
                             triangles * (attachment + 1))
        outputs.append(bytes(output))
    return tuple(outputs)


def build_first_render_service_records():
    """Build native channel-12 slots 1..3 before the first render kick."""
    return (
        g17g.build_service_opcode15_record(),
        g17g.build_service_opcode15_record(),
        g17g.build_service_opcode20_record(
            g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS,
            g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
            sequence=1,
            count=16,
        ),
    )


def build_first_mixed_clear_service_records(compute_publication_count=1):
    """Build the pending records in the earliest clear-then-compute trace.

    Firmware has already produced the first opcode-0x15 in slot zero by this
    boundary.  The minimized native mixed trace contains two more opcode-0x15
    records and the clear's opcode-0x20 in host-published slots one through
    three.  Together with slot zero, this leaves channel 12 retired at four
    before the compute engine-transition record is published in slot four.

    The two-compute/one-render capture uses the next allocation family for
    the opcode-0x20 object and tagged-address table.  The record grammar and
    sequence stay unchanged; select those two addresses explicitly instead
    of reusing the one-publication service record.
    """
    compute_publication_count = int(compute_publication_count)
    layout = _mixed_render_layout(compute_publication_count)
    tagged_address = (
        RENDER_MIXED_TWO_TAGGED_ADDRESS
        if compute_publication_count == 2
        else g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS
    )
    return (
        g17g.build_service_opcode15_record(),
        g17g.build_service_opcode15_record(),
        g17g.build_service_opcode20_record(
            layout["shared_control"],
            tagged_address,
            sequence=2,
            count=16,
            word_30=1,
        ),
    )


def build_mixed_render_compute_service_records():
    """Build the sole record between the first clear and compute kick.

    At the earliest same-command-buffer render-then-compute boundary, slots
    zero through three retain ``15,15,15,20`` and XNU publishes only an
    opcode-0x2e engine transition in slot four.  Producer 4 advances to 5 and
    one type-0x84 retires that single record.  The six opcode-0x1a records
    belong to the standalone first-compute opening and were a late-state
    contamination in the old mixed recipe.
    """
    return (g17g.build_service_opcode2e_record(1),)


def build_mixed_compute_first_opening_service_records():
    """Build native compute-first mixed slots 1..3.

    The first three slots are ordered by the first engine publication.  When
    compute wins the render/compute race, the two remaining opcode-0x15
    opening records are followed by opcode-0x2e(1).  The render opcode-0x20
    registration is then published alone in slot four after compute one.
    """
    return (
        g17g.build_service_opcode15_record(),
        g17g.build_service_opcode15_record(),
        g17g.build_service_opcode2e_record(1),
    )


def build_mixed_repeat_pre_render_service_records():
    """Build the native compute-first slot 4 before the intervening render.

    Native mixed execution has no standalone-compute six-record registration
    prefix.  Slots zero through three are ``15,15,15,2e(1)``; after compute
    one retires, the render opcode-0x20 registration is the sole next record.
    """
    return (
        g17g.build_service_opcode20_record(
            RENDER_MIXED_SHARED_CONTROL,
            g17g_render.RENDER_OPERAND_TABLE_DVA,
            sequence=2,
            count=16,
            word_30=1,
        ),
    )


def build_mixed_repeat_post_render_service_records():
    """Build native mixed slot 5 between render and compute two."""
    return (g17g.build_service_opcode2e_record(2, word_0c=1),)


def build_first_direct_render_service_records():
    """Build the two pending slots consumed by the first direct handoffs."""
    return (
        g17g.build_service_opcode15_record(),
        g17g.build_service_opcode15_record(),
    )


def build_partial_render_growth_service_records():
    """Build the first observed slot-three resource registration.

    This is the same opcode-0x20 shape native uses in slot three of the
    earliest clear lifecycle.  Keeping the candidate in a separate builder
    avoids assigning growth semantics until hardware proves that use.
    """
    return (build_first_render_service_records()[2],)


def build_compute_to_partial_render_service_records():
    """Build native slots 1..7 between dependent compute and partial work.

    The clean first-work command-buffer capture exposes this exact ordering
    after compute retires and before the dependent TA/3D kick.  It is distinct
    from both standalone compute registration and the later direct-render
    repeat interval: the engine transition splits the six registration
    records after their third member.
    """
    return (
        g17g.build_type84_prefix_record(0, 1),
        g17g.build_type84_prefix_record(0, 2),
        g17g.build_type84_prefix_record(1, 1),
        g17g.build_service_opcode2e_record(1),
        g17g.build_type84_prefix_record(1, 2),
        g17g.build_type84_prefix_record(2, 1),
        g17g.build_type84_prefix_record(2, 2),
    )


def build_first_render_service_input_pages():
    """Build the exact mutable input page before the first render type-0x84.

    The matching beta-5 transition pair proves that the existing state page
    remains at generation one across this service event.  The named object is
    already at generation two before the event, while its cursor remains at
    0x68; firmware advances only that cursor to 0x78 while acknowledging the
    service-ring interval.
    """
    return {
        g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS:
            g17g.build_opcode20_first_object(
                0x7200000000,
                g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
                COMPUTE_GLOBAL_STATE,
                word_10=2,
                word_60=3,
            ),
    }


def build_first_mixed_render_service_input_pages():
    """Build the relocated mixed control object before its service event.

    The earliest coherent mixed capture allocates the channel-12 object at
    ``RENDER_MIXED_SHARED_CONTROL`` because the preceding page is now the
    scheduler-record pool.  Its host-published pre-service cursor is 0x68;
    the matching pre-work image advances only that cursor to 0x78.
    """
    return {
        RENDER_MIXED_SHARED_CONTROL: g17g.build_opcode20_first_object(
            0x7200000000,
            g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
            0xFFFFFC2001610000,
            cursor=0x68,
            resource_units=0x1A,
            word_08=1,
            word_10=2,
            word_60=3,
        ),
    }


def build_mixed_compute_first_service_control():
    """Build the control object visible at both early mixed type-0x84s."""
    control = bytearray(g17g.build_opcode20_first_object(
        0x7200000000,
        g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
        0xFFFFFC2001610000,
        cursor=0x58,
        resource_units=0x16,
        word_08=0,
        word_10=2,
        word_54=1,
        word_60=2,
    ))
    # The early service allocation retains the complete first record, not
    # merely its 0x16-unit high endpoint.  This qword is stable across both
    # adjacent native type-0x84 snapshots.
    struct.pack_into("<Q", control, 0x20, 0x0000166000000060)
    struct.pack_into("<I", control, 0x5C, 1)
    return bytes(control)


def build_mixed_compute_first_preservice_state_pages():
    """Build exact sparse compute-one -> render-admission publications.

    A same-boot capture at two adjacent primary type-0x84 sends proves this is
    not a seven-page state replacement.  It is a compact host publication
    which closes compute's completion words, opens one allocator record, and
    installs the fragment admission record.  Dynamic work bytes are supplied
    later, after the second notification.
    """
    allocator_before = bytes.fromhex(
        "000000e4000000006000000060160000001600000000080000"
        "0000000000000000"
    ) + bytes(0x20)
    allocator_after = bytearray(allocator_before)
    allocator_identity = COMPUTE_MIXED_QUEUE_GENERATION
    struct.pack_into(
        "<Q", allocator_after, 0x20,
        0x00000000E4000000 | (allocator_identity << 8),
    )
    struct.pack_into("<Q", allocator_after, 0x28, 0x00001A0000000000)
    struct.pack_into("<Q", allocator_after, 0x30, 0x0008000000001A00)
    fragment_optional = g17g_render.build_optional_item(
        "fragment",
        RENDER_MIXED_FRAGMENT_CONTEXT_SCRATCH,
        RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH,
        COMPUTE_MIXED_SHARED_SUPPORT,
        g17g_render.CHANNEL_CONTROL,
        COMPUTE_MIXED_QUEUE_GENERATION,
        submission_ordinal=2,
        queue_index=RENDER_MIXED_QUEUE_INDICES[1],
        queue_context_index=0,
        first_record=True,
        context_id=RENDER_MIXED_CONTEXT_ID,
        lifecycle_ordinal=0,
    )
    fragment_admission = bytearray(0x2240)
    fragment_admission[0] = 1
    fragment_admission[0x0C] = 1
    fragment_admission[0x21D6] = 1
    fragment_admission[0x21D9] = 0x77
    fragment_admission[0x21E7] = 2
    fragment_admission[0x21EE] = 4
    service_control = build_mixed_compute_first_service_control()
    completion_idle_pages = {
        # Both compute aliases name native physical queue record zero.
        COMPUTE_QUEUE_CONTEXT_PAGE: ((
            g17g_compute.compute_queue_context_item_offset(0) + 0x18,
            struct.pack("<Q", COMPUTE_QUEUE_PAGE),
        ),),
        COMPUTE_CHANNEL_RING_PAGE: ((
            g17g_compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET
            + g17g.RING_SLOT_QUEUE_ADDRESS_OFFSET,
            struct.pack("<Q", COMPUTE_QUEUE_PAGE),
        ),),
        # Native has admitted only dispatch lane zero at this boundary.  The
        # two completion/producer words are still clear until work
        # publication restores the live compute graph.
        COMPUTE_GLOBAL_DISPATCH_A: ((0x004, bytes(8)),),
        # Both adjacent native snapshots agree on these scheduler records.
        # The first record has consumed one unit but has no later render
        # identity yet; the compute record has returned to work ID zero while
        # retaining its firmware-owned ready word and early identity.
        _page(COMPUTE_GLOBAL_SCHEDULER): (
            (0x108, struct.pack("<Q", 1)),
            (0x120, bytes(8)),
            (0x1A0, bytes(0x28)),
        ),
        COMPUTE_GLOBAL_SUPPORT: (
            (0x108, struct.pack("<Q", 0x0000000100000000)),
            (0x1B8, struct.pack("<Q", 0x00000000010000E5)),
        ),
        # The service state and tiling-status companions exchange ownership
        # before the first type-0x84.  Native leaves the former at generation
        # one and publishes the same paired status qwords in both adjacent
        # snapshots.
        COMPUTE_GLOBAL_ZERO: (
            (0x000, struct.pack("<Q", 1)),
            (0x010, bytes(8)),
        ),
        RENDER_MIXED_TILING_STATUS: (
            (0x000, struct.pack("<Q", 0x000000600000082D)),
            (0x010, struct.pack("<Q", 0x000000600000082D)),
        ),
        COMPUTE_QUEUE_PAGE: (
            # At the first service boundary native temporarily exchanges the
            # TA/compute intrusive-list and auxiliary links.  Compute and
            # fragment are idle (limit zero); TA remains retired at three.
            (0x010, struct.pack("<Q", COMPUTE_JOB_LIST_PAGE + 0x18)),
            (0x070, struct.pack("<Q", COMPUTE_QUEUE_AUX_PAGE + 0x40)),
            (
                g17g.QUEUE_RECORD_STRIDE + 0x010,
                struct.pack("<Q", COMPUTE_JOB_LIST_PAGE),
            ),
            (g17g.QUEUE_RECORD_STRIDE + 0x018, bytes(8)),
            (
                g17g.QUEUE_RECORD_STRIDE + 0x070,
                struct.pack("<Q", COMPUTE_QUEUE_AUX_PAGE),
            ),
            (2 * g17g.QUEUE_RECORD_STRIDE + 0x018, bytes(8)),
        ),
        COMPUTE_ITEM_RING_PAGE: (
            (
                0x000,
                struct.pack(
                    "<3Q",
                    COMPUTE_MIXED_OPTIONAL,
                    COMPUTE_DESCRIPTOR_PAGE,
                    COMPUTE_EVENT_PAGE,
                ),
            ),
        ),
        0xFFFFFC2000020000: tuple(
            (offset, bytes(8))
            for offset in (0x040, 0x050, 0x060, 0x140, 0x150, 0x160)
        ),
        0xFFFFFC2000024000: (
            (0x0DE8, bytes(8)),
            (0x0E10, bytes(8)),
            (0x0E20, bytes(8)),
            (0x0E40, struct.pack("<Q", 1)),
            (0x0E58, bytes(0x10)),
        ),
        COMPUTE_EVENT_PAGE: (
            (0x040, bytes(0x18)),
            (0x080, bytes(0x10)),
        ),
        RENDER_MIXED_TILING_FIRMWARE_SCRATCH:
            ((0x000, bytes(PAGE_SIZE)),),
        RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH:
            ((0x000, bytes(PAGE_SIZE)),),
        RENDER_MIXED_SHARED_CONTROL:
            ((0x000, service_control),),
    }
    before = {
        **completion_idle_pages,
        RENDER_LIVE_ADMISSION_PAGE: ((
            RENDER_LIVE_ADMISSION_QWORD_OFFSET,
            struct.pack("<Q", RENDER_MIXED_LIVE_ADMISSION),
        ),),
        0xFFFFFC2000014000: (
            (0x10E0, bytes(8)),
            (0x1110, bytes(8)),
            (0x1120, b"\0"),
        ),
        0xFFFFFC20001A0000: ((0x0E75, b"\0"),),
        0xFFFFFC20015E0000: ((0x0000, b"\0\x04"),),
        0xFFFFFC20015E8000: ((0x0000, bytes(0x10)),),
        0xFFFFFC20015F0000: ((0x0000, allocator_before),),
        COMPUTE_GLOBAL_SCHEDULER_SLOT: ((0x0004, bytes(4)),),
        0xFFFFFC20C000C000: ((0x10E0, bytes(0x18)),),
        RENDER_FRAGMENT_DESCRIPTOR_PAGE:
            ((0x0000, bytes(0x2240)),),
        RENDER_OPTIONAL_PAGE: ((0x00C0, bytes(0x180)),),
    }
    after = {
        **completion_idle_pages,
        RENDER_LIVE_ADMISSION_PAGE: ((
            RENDER_LIVE_ADMISSION_QWORD_OFFSET,
            struct.pack("<Q", RENDER_MIXED_LIVE_ADMISSION),
        ),),
        0xFFFFFC2000014000: (
            (0x10E0, bytes(8)),
            (0x1110, bytes(8)),
            (0x1120, b"\x01"),
        ),
        0xFFFFFC2000024000: completion_idle_pages[
            0xFFFFFC2000024000
        ] + (
            (0x0E48, bytes(4)),
            (0x0E50, bytes(4)),
        ),
        0xFFFFFC20001A0000: ((0x0E75, b"\x01"),),
        0xFFFFFC20015E0000: ((0x0000, b"\xff\0"),),
        0xFFFFFC20015E8000: (
            (0x0000, struct.pack("<Q", 0x0000003000024000)),
            (0x0008, bytes(8)),
        ),
        0xFFFFFC20015F0000: ((0x0000, bytes(allocator_after)),),
        COMPUTE_GLOBAL_SCHEDULER_SLOT: (
            (0x0004, struct.pack("<I", 1)),
        ),
        0xFFFFFC20C000C000: ((
            0x10E0,
            struct.pack("<Q", RENDER_MIXED_FRAGMENT_OPTIONAL)
            + bytes(0x10),
        ),),
        RENDER_FRAGMENT_DESCRIPTOR_PAGE:
            ((0x0000, bytes(fragment_admission)),),
        RENDER_OPTIONAL_PAGE: ((
            0x00C0,
            fragment_optional + bytes(0xC0),
        ),),
    }
    return {
        "before": before,
        "after": after,
    }


def build_second_render_service_records():
    """Build native early channel-12 slots 4..11 through occurrence nine."""
    return (
        g17g.build_service_opcode2e_record(1),
        g17g.build_service_opcode2e_record(2),
        g17g.build_type84_prefix_record(0, 1),
        g17g.build_type84_prefix_record(0, 2),
        g17g.build_type84_prefix_record(1, 1),
        g17g.build_type84_prefix_record(1, 2),
        g17g.build_type84_prefix_record(2, 1),
        g17g.build_type84_prefix_record(2, 2),
    )


def build_second_direct_render_service_records():
    """Build the seven records between the first two native tiny draws.

    The corrected beta-5 direct-pair capture has channel-12 producer three
    after draw one.  Slots 3..9 are one opcode-0x2e admission followed by the
    six type-0x84 prefix records, and each record receives one notification
    before draw two.  This is deliberately separate from the eight-record
    clear lifecycle above: that later capture also contains opcode-0x2e(2).
    """
    return (
        g17g.build_service_opcode2e_record(1),
        g17g.build_type84_prefix_record(0, 1),
        g17g.build_type84_prefix_record(0, 2),
        g17g.build_type84_prefix_record(1, 1),
        g17g.build_type84_prefix_record(1, 2),
        g17g.build_type84_prefix_record(2, 1),
        g17g.build_type84_prefix_record(2, 2),
    )


def build_second_render_service_pages():
    """Build both fresh context-64 pages named by service generation two."""
    state = bytearray(PAGE_SIZE)
    struct.pack_into("<Q", state, 0, 2)
    return {
        RENDER_SECOND_SERVICE_STATE: bytes(state),
        RENDER_SECOND_SERVICE_OBJECT: g17g.build_opcode20_first_object(
            RENDER_SECOND_ADDRESS_LIST_BASE,
            RENDER_SECOND_OPERAND_TABLE,
            RENDER_SECOND_SERVICE_STATE,
            cursor=0x78,
            word_10=2,
            word_60=3,
        ),
    }


def expand_second_render_context1_dvas():
    """Expand and hash-gate the early generation-two service topology."""
    dvas = tuple(
        base + index * PAGE_SIZE
        for base, page_count, _read_only in RENDER_SECOND_CONTEXT1_RUNS
        for index in range(page_count)
    )
    if len(dvas) != RENDER_SECOND_CONTEXT1_PAGE_COUNT:
        raise ValueError("second-render context-1 page count changed")
    if dvas != tuple(sorted(set(dvas))):
        raise ValueError("second-render context-1 runs overlap or are unordered")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if hashlib.sha256(encoded).hexdigest() != RENDER_SECOND_CONTEXT1_DVA_SHA256:
        raise ValueError("second-render context-1 DVA hash changed")
    return dvas


def expand_second_render_retired_context1_dvas():
    """Return the equally sized generation-one runs replaced for service."""
    dvas = tuple(
        base + index * PAGE_SIZE
        for base, page_count, _read_only in
        RENDER_SECOND_RETIRED_CONTEXT1_RUNS
        for index in range(page_count)
    )
    if len(dvas) != RENDER_SECOND_CONTEXT1_PAGE_COUNT:
        raise ValueError("second-render retired context-1 page count changed")
    if dvas != tuple(sorted(set(dvas))):
        raise ValueError("second-render retired context-1 runs overlap")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if (
        hashlib.sha256(encoded).hexdigest()
        != RENDER_SECOND_RETIRED_CONTEXT1_DVA_SHA256
    ):
        raise ValueError("second-render retired context-1 DVA hash changed")
    return dvas


def second_render_context1_page_images():
    """Build the five nonzero pages in the early service topology."""
    pages = g17g_render.build_render_address_list_pages(
        buffer_base=RENDER_SECOND_OPERAND_BASE,
        address_list_base=RENDER_SECOND_ADDRESS_LIST_BASE,
    )
    pages[RENDER_SECOND_OPERAND_TABLE] = (
        g17g_render.build_render_operand_table(RENDER_SECOND_OPERAND_BASE)
    )
    if not set(pages) <= set(expand_second_render_context1_dvas()):
        raise ValueError("second-render page image escaped its topology")
    return dict(sorted(pages.items()))


# The corrected earliest direct-pair capture allocates the same kind of
# generation-two service object as the older clear witness above, but its
# caller address-list arena is six pages larger and contains all eighteen
# partial-render operands.  These are address-space facts, not captured
# contents: 297/306 newly visible pages are zero and the remaining nine pages
# are fully generated below or are the already source-built live history.
RENDER_SECOND_DIRECT_ADDRESS_LIST_BASE = 0x72028B0000
RENDER_SECOND_DIRECT_OPERAND_TABLE = 0x7202CB8000
RENDER_SECOND_DIRECT_CONTEXT1_RUNS = (
    (0x7200400000, 2, False),
    (0x7200418000, 2, False),
    (0x7200620000, 2, False),
    (0x7200828000, 2, False),
    (0x7200A30000, 2, False),
    (0x7200C38000, 2, False),
    (0x7200E40000, 2, False),
    (0x7201048000, 2, False),
    (0x7201250000, 2, False),
    (0x7201458000, 2, False),
    (0x7201660000, 2, False),
    (0x7201868000, 2, False),
    (0x7201A70000, 2, False),
    (0x7201C78000, 2, False),
    (0x7201E80000, 2, False),
    (0x7202088000, 2, False),
    (0x7202290000, 2, False),
    (RENDER_SECOND_DIRECT_ADDRESS_LIST_BASE, 256, False),
    (RENDER_SECOND_DIRECT_OPERAND_TABLE, 4, False),
)
RENDER_SECOND_DIRECT_CONTEXT1_PAGE_COUNT = 294
RENDER_SECOND_DIRECT_CONTEXT1_DVA_SHA256 = (
    "285e9f8373f56d57d62f715d40f00db03831051bb1187c2de3cbe08f4064684f"
)
# Source work one owns this disjoint 294-page allocation family.  Native
# retires it after registering the direct work-two family above and before
# releasing the second work item.
RENDER_SECOND_DIRECT_RETIRED_CONTEXT1_RUNS = (
    (0x7200200000, 2),
    (0x7200408000, 2),
    (0x7200610000, 2),
    (0x7200818000, 2),
    (0x7200A20000, 2),
    (0x7200C28000, 2),
    (0x7200E30000, 2),
    (0x7201038000, 2),
    (0x7201240000, 2),
    (0x7201448000, 2),
    (0x7201650000, 2),
    (0x7201858000, 2),
    (0x7201A60000, 2),
    (0x7201C68000, 2),
    (0x7201E70000, 2),
    (0x7202078000, 2),
    (0x7202280000, 2),
    (0x7202488000, 4),
    (0x72024A0000, 128),
    (0x72026A8000, 128),
)
RENDER_SECOND_DIRECT_RETIRED_CONTEXT1_DVA_SHA256 = (
    "1528c5b68cc081f50dad7ae921a1a255d4c426a8743b008b234b440950279035"
)
RENDER_SECOND_DIRECT_HIGH_DVAS = (
    RENDER_SECOND_SERVICE_STATE,
    RENDER_SECOND_SERVICE_HISTORY_PAGE,
    0xFFFFFC20C080C000,
    0xFFFFFC20C0830000,
    0xFFFFFC20C0834000,
    0xFFFFFC20C0858000,
    0xFFFFFC20C085C000,
    0xFFFFFC20C0868000,
    0xFFFFFC20C086C000,
    0xFFFFFC20C0890000,
    0xFFFFFC20C0894000,
    RENDER_SECOND_SERVICE_OBJECT,
)
RENDER_SECOND_DIRECT_HIGH_DVA_SHA256 = (
    "eb15152f829246648aaeb4fd380c4c103f3a0f2a24c80555ce676f13b461bc86"
)


def expand_second_direct_render_context1_dvas():
    """Expand the native-only caller leaves created before direct work two."""
    dvas = tuple(
        base + index * PAGE_SIZE
        for base, page_count, _read_only in
        RENDER_SECOND_DIRECT_CONTEXT1_RUNS
        for index in range(page_count)
    )
    if (
        len(dvas) != RENDER_SECOND_DIRECT_CONTEXT1_PAGE_COUNT
        or dvas != tuple(sorted(set(dvas)))
    ):
        raise ValueError("second-direct caller topology changed")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if hashlib.sha256(encoded).hexdigest() != (
        RENDER_SECOND_DIRECT_CONTEXT1_DVA_SHA256
    ):
        raise ValueError("second-direct caller DVA hash changed")
    return dvas


def expand_second_direct_retired_context1_dvas():
    """Return the source work-one leaves retired before direct work two."""
    dvas = tuple(
        base + index * PAGE_SIZE
        for base, page_count in RENDER_SECOND_DIRECT_RETIRED_CONTEXT1_RUNS
        for index in range(page_count)
    )
    if (
        len(dvas) != RENDER_SECOND_DIRECT_CONTEXT1_PAGE_COUNT
        or dvas != tuple(sorted(set(dvas)))
    ):
        raise ValueError("second-direct retired caller topology changed")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if hashlib.sha256(encoded).hexdigest() != (
        RENDER_SECOND_DIRECT_RETIRED_CONTEXT1_DVA_SHA256
    ):
        raise ValueError("second-direct retired caller DVA hash changed")
    return dvas


def second_direct_render_leaf_flags(space, dva):
    """Return characterized native leaf attributes for host work-two pages."""
    dva = int(dva)
    if space == "context1-selector0":
        if dva not in set(expand_second_direct_render_context1_dvas()):
            raise ValueError("unknown second-direct caller leaf")
        return {
            "VALID": 1, "TYPE": 1, "AttrIndex": 2, "AP": 2,
            "SH": 0, "AF": 1, "nG": 1, "PXN": 0, "UXN": 1,
            "OS": 1,
        }
    if space == "context64-selector1":
        if dva not in set(expand_second_direct_render_high_dvas()):
            raise ValueError("unknown second-direct firmware leaf")
        return {
            "VALID": 1, "TYPE": 1,
            "AttrIndex": 2 if dva == RENDER_SECOND_SERVICE_STATE else 0,
            "AP": 1, "SH": 0, "AF": 1, "nG": 0, "PXN": 0,
            "UXN": 1, "OS": 1,
        }
    raise ValueError("unknown second-direct address space")


def second_direct_render_context1_page_images():
    """Build all six nonzero pages in the direct-pair caller allocation."""
    pages = g17g_render.build_render_address_list_pages(
        buffer_base=RENDER_SECOND_OPERAND_BASE,
        address_list_base=RENDER_SECOND_DIRECT_ADDRESS_LIST_BASE,
        operand_count=g17g_render.PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT,
    )
    pages[RENDER_SECOND_DIRECT_OPERAND_TABLE] = (
        g17g_render.build_render_operand_table(
            RENDER_SECOND_OPERAND_BASE,
            operand_count=(
                g17g_render.PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT
            ),
        )
    )
    if not set(pages) <= set(expand_second_direct_render_context1_dvas()):
        raise ValueError("second-direct page image escaped its topology")
    return dict(sorted(pages.items()))


def expand_second_direct_render_high_dvas():
    """Return and hash-gate the twelve direct-pair firmware-high leaves."""
    dvas = tuple(RENDER_SECOND_DIRECT_HIGH_DVAS)
    if dvas != tuple(sorted(set(dvas))):
        raise ValueError("second-direct high topology changed")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if hashlib.sha256(encoded).hexdigest() != (
        RENDER_SECOND_DIRECT_HIGH_DVA_SHA256
    ):
        raise ValueError("second-direct high DVA hash changed")
    return dvas


def build_second_direct_render_service_pages(service_history_page, *, failed_fragment=False):
    """Build the three nonzero high pages visible before direct services."""
    service_history_page = bytes(service_history_page)
    if len(service_history_page) != PAGE_SIZE:
        raise ValueError("second-direct service history page is short")
    if any(service_history_page[2 * RENDER_SERVICE_HISTORY_RECORD_SIZE:]):
        preserve_partial_render_service_history(service_history_page, failed_fragment=failed_fragment)
    state = bytearray(PAGE_SIZE)
    struct.pack_into("<Q", state, 0, 2)
    pages = {
        RENDER_SECOND_SERVICE_STATE: bytes(state),
        RENDER_SECOND_SERVICE_HISTORY_PAGE: service_history_page,
        RENDER_SECOND_SERVICE_OBJECT: g17g.build_opcode20_first_object(
            RENDER_SECOND_DIRECT_ADDRESS_LIST_BASE,
            RENDER_SECOND_DIRECT_OPERAND_TABLE,
            RENDER_SECOND_SERVICE_STATE,
            cursor=0x90,
            resource_units=0x24,
            word_10=2,
            word_60=3,
        ),
    }
    if not set(pages) <= set(expand_second_direct_render_high_dvas()):
        raise ValueError("second-direct service page escaped its topology")
    return dict(sorted(pages.items()))


# The earliest three-direct-draw capture establishes the recurrent allocator
# transition after the allocation-heavy second draw.  The third draw reuses
# slot A's two firmware-high leaves and allocates only a fresh 256-page address
# list plus four operand-table leaves.  All six nonzero caller pages and both
# high pages are byte-exact products of the existing builders; the remaining
# 254 caller leaves are zero.  The second draw's address-list/operand arena and
# a 28-page transient compiler allocation disappear at the same boundary.
RENDER_THIRD_DIRECT_ADDRESS_LIST_BASE = 0x7202490000
RENDER_THIRD_DIRECT_OPERAND_TABLE = 0x7202898000
RENDER_THIRD_DIRECT_SERVICE_STATE = COMPUTE_GLOBAL_STATE
RENDER_THIRD_DIRECT_SERVICE_OBJECT = COMPUTE_GLOBAL_SUPPORT
RENDER_THIRD_DIRECT_CONTEXT1_RUNS = (
    (RENDER_THIRD_DIRECT_ADDRESS_LIST_BASE, 256),
    (RENDER_THIRD_DIRECT_OPERAND_TABLE, 4),
)
RENDER_THIRD_DIRECT_CONTEXT1_PAGE_COUNT = 260
RENDER_THIRD_DIRECT_CONTEXT1_DVA_SHA256 = (
    "a63b2ef92a49203f6c25c998f45ac06f144d4c14758db5d56a923e7a2bc2347b"
)
RENDER_THIRD_DIRECT_RETIRED_CONTEXT1_RUNS = (
    (RENDER_SECOND_DIRECT_ADDRESS_LIST_BASE, 256),
    (RENDER_SECOND_DIRECT_OPERAND_TABLE, 4),
    (0x10000140000, 28),
)
RENDER_THIRD_DIRECT_RETIRED_CONTEXT1_PAGE_COUNT = 288
RENDER_THIRD_DIRECT_RETIRED_CONTEXT1_DVA_SHA256 = (
    "c87f2711e71307d6ad84ccbb31607dce272c68dd56c753b739677c58b81e0971"
)
RENDER_THIRD_DIRECT_HIGH_DVAS = (
    RENDER_THIRD_DIRECT_SERVICE_STATE,
    RENDER_THIRD_DIRECT_SERVICE_OBJECT,
)
RENDER_THIRD_DIRECT_HIGH_DVA_SHA256 = (
    "ab910ced707e052438d135cedc1161804e0d02337fa79ea40efe91ec38321f23"
)
RENDER_THIRD_DIRECT_RETIRED_HIGH_DVAS = (
    RENDER_SECOND_SERVICE_STATE,
    RENDER_SECOND_SERVICE_OBJECT,
)


def _expand_direct_render_runs(runs, expected_count, expected_sha256, label):
    dvas = tuple(
        base + index * PAGE_SIZE
        for base, page_count in runs
        for index in range(page_count)
    )
    if len(dvas) != expected_count or dvas != tuple(sorted(set(dvas))):
        raise ValueError("%s topology changed" % label)
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if hashlib.sha256(encoded).hexdigest() != expected_sha256:
        raise ValueError("%s DVA hash changed" % label)
    return dvas


def expand_third_direct_render_context1_dvas():
    """Return the native caller leaves allocated before direct work three."""
    return _expand_direct_render_runs(
        RENDER_THIRD_DIRECT_CONTEXT1_RUNS,
        RENDER_THIRD_DIRECT_CONTEXT1_PAGE_COUNT,
        RENDER_THIRD_DIRECT_CONTEXT1_DVA_SHA256,
        "third-direct caller",
    )


def expand_third_direct_retired_context1_dvas():
    """Return work-two caller leaves retired before direct work three."""
    return _expand_direct_render_runs(
        RENDER_THIRD_DIRECT_RETIRED_CONTEXT1_RUNS,
        RENDER_THIRD_DIRECT_RETIRED_CONTEXT1_PAGE_COUNT,
        RENDER_THIRD_DIRECT_RETIRED_CONTEXT1_DVA_SHA256,
        "third-direct retired caller",
    )


def expand_third_direct_render_high_dvas():
    """Return and hash-gate the two recycled slot-A firmware leaves."""
    dvas = tuple(RENDER_THIRD_DIRECT_HIGH_DVAS)
    if dvas != tuple(sorted(set(dvas))):
        raise ValueError("third-direct high topology changed")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if hashlib.sha256(encoded).hexdigest() != (
            RENDER_THIRD_DIRECT_HIGH_DVA_SHA256):
        raise ValueError("third-direct high DVA hash changed")
    return dvas


def third_direct_render_leaf_flags(space, dva):
    """Return native leaf attributes for the work-three allocation."""
    dva = int(dva)
    if space == "context1-selector0":
        if dva not in set(expand_third_direct_render_context1_dvas()):
            raise ValueError("unknown third-direct caller leaf")
        return {
            "VALID": 1, "TYPE": 1, "AttrIndex": 2, "AP": 2,
            "SH": 0, "AF": 1, "nG": 1, "PXN": 0, "UXN": 1,
            "OS": 1,
        }
    if space == "context64-selector1":
        if dva not in set(expand_third_direct_render_high_dvas()):
            raise ValueError("unknown third-direct firmware leaf")
        return {
            "VALID": 1, "TYPE": 1,
            "AttrIndex": (
                2 if dva == RENDER_THIRD_DIRECT_SERVICE_STATE else 0
            ),
            "AP": 1, "SH": 0, "AF": 1, "nG": 0, "PXN": 0,
            "UXN": 1, "OS": 1,
        }
    raise ValueError("unknown third-direct address space")


def third_direct_render_context1_page_images():
    """Build all six nonzero pages in direct work three's caller arena."""
    pages = g17g_render.build_render_address_list_pages(
        buffer_base=RENDER_SECOND_OPERAND_BASE,
        address_list_base=RENDER_THIRD_DIRECT_ADDRESS_LIST_BASE,
        operand_count=g17g_render.PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT,
    )
    pages[RENDER_THIRD_DIRECT_OPERAND_TABLE] = (
        g17g_render.build_render_operand_table(
            RENDER_SECOND_OPERAND_BASE,
            operand_count=(
                g17g_render.PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT
            ),
        )
    )
    if not set(pages) <= set(expand_third_direct_render_context1_dvas()):
        raise ValueError("third-direct page image escaped its topology")
    return dict(sorted(pages.items()))


def build_third_direct_render_service_pages():
    """Build the byte-exact recycled slot-A state and service object."""
    state = bytearray(PAGE_SIZE)
    struct.pack_into("<Q", state, 0, 2)
    pages = {
        RENDER_THIRD_DIRECT_SERVICE_STATE: bytes(state),
        RENDER_THIRD_DIRECT_SERVICE_OBJECT:
            g17g.build_opcode20_first_object(
                RENDER_THIRD_DIRECT_ADDRESS_LIST_BASE,
                RENDER_THIRD_DIRECT_OPERAND_TABLE,
                RENDER_THIRD_DIRECT_SERVICE_STATE,
                cursor=0x90,
                resource_units=0x24,
                word_10=2,
                word_60=3,
            ),
    }
    if set(pages) != set(expand_third_direct_render_high_dvas()):
        raise ValueError("third-direct service page set changed")
    return dict(sorted(pages.items()))


# The earliest four-direct-draw capture closes the two-slot allocator cycle.
# Work four republishes exactly the 260-page B address-list/operand arena that
# work two used, together with its state/object leaves, after work three
# retired them.  The six nonzero caller pages and both high pages are byte-for-
# byte identical to their work-two images.  At the same boundary the complete
# 260-page A arena and its two high leaves disappear.  No captured contents are
# needed to express either side of this transition.
RENDER_FOURTH_DIRECT_ADDRESS_LIST_BASE = RENDER_SECOND_DIRECT_ADDRESS_LIST_BASE
RENDER_FOURTH_DIRECT_OPERAND_TABLE = RENDER_SECOND_DIRECT_OPERAND_TABLE
RENDER_FOURTH_DIRECT_SERVICE_STATE = RENDER_SECOND_SERVICE_STATE
RENDER_FOURTH_DIRECT_SERVICE_OBJECT = RENDER_SECOND_SERVICE_OBJECT
RENDER_FOURTH_DIRECT_CONTEXT1_RUNS = (
    (RENDER_FOURTH_DIRECT_ADDRESS_LIST_BASE, 256),
    (RENDER_FOURTH_DIRECT_OPERAND_TABLE, 4),
)
RENDER_FOURTH_DIRECT_CONTEXT1_PAGE_COUNT = 260
RENDER_FOURTH_DIRECT_CONTEXT1_DVA_SHA256 = (
    "903581197d3972bb807ce245d8fbf9259ddbac0a2914825e1c653579f409d722"
)
RENDER_FOURTH_DIRECT_RETIRED_CONTEXT1_RUNS = (
    (RENDER_THIRD_DIRECT_ADDRESS_LIST_BASE, 256),
    (RENDER_THIRD_DIRECT_OPERAND_TABLE, 4),
)
RENDER_FOURTH_DIRECT_RETIRED_CONTEXT1_PAGE_COUNT = 260
RENDER_FOURTH_DIRECT_RETIRED_CONTEXT1_DVA_SHA256 = (
    "a63b2ef92a49203f6c25c998f45ac06f144d4c14758db5d56a923e7a2bc2347b"
)
RENDER_FOURTH_DIRECT_HIGH_DVAS = (
    RENDER_FOURTH_DIRECT_SERVICE_STATE,
    RENDER_FOURTH_DIRECT_SERVICE_OBJECT,
)
RENDER_FOURTH_DIRECT_HIGH_DVA_SHA256 = (
    "150d9bab44d2a2f59da0c84c112f7e052b50e74f7ad8e73dae01714e655463ef"
)
RENDER_FOURTH_DIRECT_RETIRED_HIGH_DVAS = RENDER_THIRD_DIRECT_HIGH_DVAS

# These values were read from the five descriptors in the minimal native
# direct workload.  Keep them explicit until a later earliest-state capture
# proves the recurrence beyond work five; the ordinary partial-render cadence
# is different and must not be substituted here.
RENDER_DIRECT_TILING_LIFECYCLES = (
    0xCE010000F3,
    0xD00100010E,
    0xD201000127,
    0xD401000140,
    0xD601000159,
)


def direct_render_tiling_lifecycle(submission_ordinal):
    """Return the earliest direct-draw lifecycle, including its warm-up.

    Works one through five are capture-pinned.  Work six exactly rejoins the
    independently decoded persistent partial-render recurrence: generation
    two's base transition is ``(2 << 32) + 0x17`` and every later generation
    adds ``(2 << 32) + 3``.
    """
    submission_ordinal = int(submission_ordinal)
    if not 1 <= submission_ordinal < (1 << 16):
        raise ValueError("direct render lifecycle ordinal must fit positive u16")
    if submission_ordinal <= len(RENDER_DIRECT_TILING_LIFECYCLES):
        return RENDER_DIRECT_TILING_LIFECYCLES[submission_ordinal - 1]
    return (
        RENDER_DIRECT_TILING_LIFECYCLES[0]
        + (2 << 32) + 0x17
        + (submission_ordinal - 2) * ((2 << 32) + 3)
    )


def direct_render_service_object(submission_ordinal):
    """Return the direct-draw service object across warm-up and recurrence."""
    submission_ordinal = int(submission_ordinal)
    if not 1 <= submission_ordinal < (1 << 16):
        raise ValueError(
            "direct render service-object ordinal must fit positive u16"
        )
    # Captured warm-up is A/B/A/B/A. Work six retains A and enters the
    # ordinary persistent-render regime, so no later allocation-slot switch
    # is needed.
    return (
        RENDER_FOURTH_DIRECT_SERVICE_OBJECT
        if submission_ordinal in (2, 4)
        else RENDER_THIRD_DIRECT_SERVICE_OBJECT
    )


def expand_fourth_direct_render_context1_dvas():
    """Return the B-side caller leaves republished before direct work four."""
    return _expand_direct_render_runs(
        RENDER_FOURTH_DIRECT_CONTEXT1_RUNS,
        RENDER_FOURTH_DIRECT_CONTEXT1_PAGE_COUNT,
        RENDER_FOURTH_DIRECT_CONTEXT1_DVA_SHA256,
        "fourth-direct caller",
    )


def expand_fourth_direct_retired_context1_dvas():
    """Return the A-side caller leaves retired before direct work four."""
    return _expand_direct_render_runs(
        RENDER_FOURTH_DIRECT_RETIRED_CONTEXT1_RUNS,
        RENDER_FOURTH_DIRECT_RETIRED_CONTEXT1_PAGE_COUNT,
        RENDER_FOURTH_DIRECT_RETIRED_CONTEXT1_DVA_SHA256,
        "fourth-direct retired caller",
    )


def expand_fourth_direct_render_high_dvas():
    """Return and hash-gate the two republished slot-B firmware leaves."""
    dvas = tuple(RENDER_FOURTH_DIRECT_HIGH_DVAS)
    if dvas != tuple(sorted(set(dvas))):
        raise ValueError("fourth-direct high topology changed")
    encoded = b"".join(struct.pack("<Q", address) for address in dvas)
    if hashlib.sha256(encoded).hexdigest() != (
            RENDER_FOURTH_DIRECT_HIGH_DVA_SHA256):
        raise ValueError("fourth-direct high DVA hash changed")
    return dvas


def fourth_direct_render_leaf_flags(space, dva):
    """Return native leaf attributes for the work-four B allocation."""
    dva = int(dva)
    if space == "context1-selector0":
        if dva not in set(expand_fourth_direct_render_context1_dvas()):
            raise ValueError("unknown fourth-direct caller leaf")
        return {
            "VALID": 1, "TYPE": 1, "AttrIndex": 2, "AP": 2,
            "SH": 0, "AF": 1, "nG": 1, "PXN": 0, "UXN": 1,
            "OS": 1,
        }
    if space == "context64-selector1":
        if dva not in set(expand_fourth_direct_render_high_dvas()):
            raise ValueError("unknown fourth-direct firmware leaf")
        return {
            "VALID": 1, "TYPE": 1,
            "AttrIndex": (
                2 if dva == RENDER_FOURTH_DIRECT_SERVICE_STATE else 0
            ),
            "AP": 1, "SH": 0, "AF": 1, "nG": 0, "PXN": 0,
            "UXN": 1, "OS": 1,
        }
    raise ValueError("unknown fourth-direct address space")


def fourth_direct_render_context1_page_images():
    """Build all six nonzero pages in direct work four's B-side arena."""
    pages = g17g_render.build_render_address_list_pages(
        buffer_base=RENDER_SECOND_OPERAND_BASE,
        address_list_base=RENDER_FOURTH_DIRECT_ADDRESS_LIST_BASE,
        operand_count=g17g_render.PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT,
    )
    pages[RENDER_FOURTH_DIRECT_OPERAND_TABLE] = (
        g17g_render.build_render_operand_table(
            RENDER_SECOND_OPERAND_BASE,
            operand_count=(
                g17g_render.PARTIAL_RENDER_SERVICE_INPUT_OPERAND_COUNT
            ),
        )
    )
    if not set(pages) <= set(expand_fourth_direct_render_context1_dvas()):
        raise ValueError("fourth-direct page image escaped its topology")
    return dict(sorted(pages.items()))


def build_fourth_direct_render_service_pages():
    """Build the byte-exact republished slot-B state and service object."""
    state = bytearray(PAGE_SIZE)
    struct.pack_into("<Q", state, 0, 2)
    pages = {
        RENDER_FOURTH_DIRECT_SERVICE_STATE: bytes(state),
        RENDER_FOURTH_DIRECT_SERVICE_OBJECT:
            g17g.build_opcode20_first_object(
                RENDER_FOURTH_DIRECT_ADDRESS_LIST_BASE,
                RENDER_FOURTH_DIRECT_OPERAND_TABLE,
                RENDER_FOURTH_DIRECT_SERVICE_STATE,
                cursor=0x90,
                resource_units=0x24,
                word_10=2,
                word_60=3,
            ),
    }
    if set(pages) != set(expand_fourth_direct_render_high_dvas()):
        raise ValueError("fourth-direct service page set changed")
    return dict(sorted(pages.items()))

# Four cold-boot mappings are absent at the native first type-0x84 boundary,
# then return before the first work kick.  The service boundary also contains
# only four of the ten fresh zero pages used by the first-clear work graph; the
# other six appear after service.  Keeping these phases distinct makes the
# source service input match the native 651 captured-RAM context-64 leaves
# while preserving the already validated first-work topology.
RENDER_PRE_SERVICE_RETIRED_GLOBAL_PAGES = (
    0xFFFFFC20C0828000,
    0xFFFFFC20C082C000,
    0xFFFFFC20C0850000,
    0xFFFFFC20C0854000,
)
RENDER_PRE_SERVICE_NEW_ZERO_GLOBAL_PAGES = (
    0xFFFFFC20C0840000,
    0xFFFFFC20C0844000,
    0xFFFFFC20C0868000,
    0xFFFFFC20C086C000,
)
RENDER_POST_SERVICE_NEW_ZERO_GLOBAL_PAGES = (
    0xFFFFFC20C07F0000,
    0xFFFFFC20C07F4000,
    0xFFFFFC20C0818000,
    0xFFFFFC20C081C000,
    0xFFFFFC20C0878000,
    0xFFFFFC20C087C000,
)

# Before the first work kick, ten earlier-lifecycle mappings are replaced by
# the complete ten-page fresh set.  This is address topology only; no captured
# physical placement or contents are part of the backend product.
RENDER_SOURCE_RETIRED_GLOBAL_PAGES = (
    0xFFFFFC20C0808000,
    0xFFFFFC20C080C000,
    0xFFFFFC20C0830000,
    0xFFFFFC20C0834000,
    0xFFFFFC20C0858000,
    0xFFFFFC20C085C000,
    0xFFFFFC20C0880000,
    0xFFFFFC20C0884000,
    0xFFFFFC20C0890000,
    0xFFFFFC20C0894000,
)
RENDER_SOURCE_NEW_ZERO_GLOBAL_PAGES = tuple(sorted(
    RENDER_PRE_SERVICE_NEW_ZERO_GLOBAL_PAGES
    + RENDER_POST_SERVICE_NEW_ZERO_GLOBAL_PAGES
))

# The native occurrence-2 before-image swaps these ten currently mapped pages
# for RENDER_SOURCE_RETIRED_GLOBAL_PAGES.  Four are first-render fresh pages;
# six are older lifecycle mappings.  This exact set, rather than all ten fresh
# pages, keeps the symmetric source capture at 651 context-64 leaves.
RENDER_SECOND_PRESERVICE_RETIRED_GLOBAL_PAGES = (
    0xFFFFFC20C07F0000,
    0xFFFFFC20C07F4000,
    0xFFFFFC20C0800000,
    0xFFFFFC20C0804000,
    0xFFFFFC20C0828000,
    0xFFFFFC20C082C000,
    0xFFFFFC20C0850000,
    0xFFFFFC20C0854000,
    0xFFFFFC20C0878000,
    0xFFFFFC20C087C000,
)


def _page_image(body, name):
    """Return one zero-padded firmware page for a bounded object body."""
    body = bytes(body)
    if len(body) > PAGE_SIZE:
        raise ValueError("%s exceeds one G17G page" % name)
    return body + bytes(PAGE_SIZE - len(body))

def compute_addresses(mixed_after_render=False):
    """Return all firmware-context addresses used by one compute graph."""
    addresses = {
        "state": COMPUTE_CHANNEL_STATE_PAGE,
        "pointers": COMPUTE_POINTER_PAGE,
        "scheduler": COMPUTE_GLOBAL_SCHEDULER,
        "scheduler_slot": COMPUTE_GLOBAL_SCHEDULER_SLOT,
        "shared_support": COMPUTE_GLOBAL_SUPPORT,
        "shared_state": COMPUTE_GLOBAL_STATE,
        "dispatch_a": COMPUTE_GLOBAL_DISPATCH_A,
        "dispatch_b": COMPUTE_GLOBAL_DISPATCH_B,
        "status_a": COMPUTE_GLOBAL_STATUS_A,
        "status_b": COMPUTE_GLOBAL_STATUS_B,
        "zero_page": COMPUTE_GLOBAL_ZERO,
        "class2_support": COMPUTE_SHARED_BASE + 0x30000,
        "class2_state": COMPUTE_SHARED_BASE + 0x34000,
        "channel_ring": COMPUTE_CHANNEL_RING_PAGE,
        "queue": COMPUTE_QUEUE_PAGE,
        "item_ring": COMPUTE_ITEM_RING_PAGE,
        "descriptor": COMPUTE_DESCRIPTOR_PAGE,
        "optional": COMPUTE_OPTIONAL_PAGE,
        "event": COMPUTE_EVENT_PAGE,
        "queue_context": COMPUTE_QUEUE_CONTEXT_PAGE,
        "job_list": COMPUTE_JOB_LIST_PAGE,
        "queue_aux": COMPUTE_QUEUE_AUX_PAGE,
    }
    if mixed_after_render:
        addresses.update({
            "pointers": COMPUTE_MIXED_POINTER,
            "scheduler": COMPUTE_MIXED_SCHEDULER,
            "scheduler_slot": COMPUTE_MIXED_SCHEDULER_SLOT,
            "shared_support": COMPUTE_MIXED_SHARED_SUPPORT,
            "shared_state": COMPUTE_MIXED_SHARED_STATE,
            "status_a": COMPUTE_MIXED_STATUS_A,
            "status_b": COMPUTE_MIXED_STATUS_B,
            "zero_page": COMPUTE_MIXED_ZERO,
            "queue": COMPUTE_MIXED_QUEUE,
            "item_ring": COMPUTE_MIXED_ITEM_RING,
            "optional": COMPUTE_MIXED_OPTIONAL,
            "event": COMPUTE_MIXED_EVENT,
            "queue_context": COMPUTE_MIXED_QUEUE_CONTEXT_HIGH,
            "job_list": COMPUTE_MIXED_JOB_LIST,
            "queue_aux": COMPUTE_MIXED_QUEUE_AUX,
        })
        # These standalone service objects are not mapped at the native
        # post-render compute boundary and are not referenced by its graph.
        del addresses["class2_support"]
        del addresses["class2_state"]
    return addresses


def mixed_compute_context1_dvas():
    """Expand and hash-gate the earliest mixed selector-zero topology."""
    dvas = tuple(
        base + index * PAGE_SIZE
        for base, page_count, _read_only in COMPUTE_MIXED_CONTEXT1_RUNS
        for index in range(page_count)
    )
    if len(dvas) != COMPUTE_MIXED_CONTEXT1_PAGE_COUNT:
        raise ValueError("G17G mixed compute context topology changed")
    if dvas != tuple(sorted(set(dvas))):
        raise ValueError("G17G mixed compute context runs overlap")
    encoded = b"".join(struct.pack("<Q", dva) for dva in dvas)
    if hashlib.sha256(encoded).hexdigest() != (
        COMPUTE_MIXED_CONTEXT1_DVA_SHA256
    ):
        raise ValueError("G17G mixed compute DVA hash changed")
    return dvas


def mixed_compute_context1_read_only_dvas():
    """Expand and hash-gate the mixed GPU read-only permission subset."""
    dvas = tuple(
        base + index * PAGE_SIZE
        for base, page_count, read_only in COMPUTE_MIXED_CONTEXT1_RUNS
        if read_only
        for index in range(page_count)
    )
    if len(dvas) != COMPUTE_MIXED_CONTEXT1_READ_ONLY_PAGE_COUNT:
        raise ValueError("G17G mixed compute read-only topology changed")
    if not set(dvas) <= set(mixed_compute_context1_dvas()):
        raise ValueError("G17G mixed compute read-only DVA is absent")
    encoded = b"".join(struct.pack("<Q", dva) for dva in dvas)
    if hashlib.sha256(encoded).hexdigest() != (
        COMPUTE_MIXED_CONTEXT1_READ_ONLY_DVA_SHA256
    ):
        raise ValueError("G17G mixed compute read-only DVA hash changed")
    return dvas


# The in-place transition starts from the canonical first-clear root.  Retire
# every leaf absent from the exact mixed boundary and rewrite permissions only
# where a retained leaf changes class.
COMPUTE_MIXED_CONTEXT1_RETIRED_DVAS = tuple(sorted(
    set(g17g_render.expand_render_context1_dvas())
    - set(mixed_compute_context1_dvas())
))
COMPUTE_MIXED_CONTEXT1_REPERMISSION_DVAS = tuple(sorted(
    (
        set(g17g_render.expand_render_context1_dvas())
        & set(mixed_compute_context1_dvas())
    ) & (
        set(g17g_render.expand_render_context1_read_only_dvas())
        ^ set(mixed_compute_context1_read_only_dvas())
    )
))


def _page(address):
    return int(address) & ~(PAGE_SIZE - 1)


def build_second_render_publication_qwords():
    """Return the exact source-before/value-after qwords for render group 2."""
    result = {}
    for address, entries in RENDER_SECOND_PUBLICATION_TRANSITIONS.items():
        if address & (PAGE_SIZE - 1):
            raise ValueError("second-render publication page is unaligned")
        checked = []
        for offset, before, after in entries:
            if offset & 7 or not 0 <= offset <= PAGE_SIZE - 8:
                raise ValueError("second-render publication qword is unaligned")
            if not 0 <= before < (1 << 64) or not 0 <= after < (1 << 64):
                raise ValueError("second-render publication value does not fit u64")
            checked.append((offset, before, after))
        if len({offset for offset, _before, _after in checked}) != len(checked):
            raise ValueError("second-render publication qword is duplicated")
        result[address] = tuple(checked)
    return result


def build_second_render_allocation_postservice_qwords():
    """Return the matched early ordinal-two queue/stage generation closure."""
    result = {}
    for address, entries in (
        RENDER_SECOND_ALLOCATION_POSTSERVICE_TRANSITIONS.items()
    ):
        if address & (PAGE_SIZE - 1):
            raise ValueError("second-render post-service page is unaligned")
        checked = []
        for offset, before, after in entries:
            if offset & 7 or not 0 <= offset <= PAGE_SIZE - 8:
                raise ValueError(
                    "second-render post-service qword is unaligned"
                )
            if not 0 <= before < (1 << 64) or not 0 <= after < (1 << 64):
                raise ValueError(
                    "second-render post-service value does not fit u64"
                )
            checked.append((offset, before, after))
        if len({offset for offset, _before, _after in checked}) != len(checked):
            raise ValueError("second-render post-service qword is duplicated")
        result[address] = tuple(checked)
    return result


def build_second_render_token_qwords():
    """Return the ordinal-two queue-identity transition (there is none).

    Native same-boot captures retain the queue word-40 identity and optional
    item UUID across both render submissions.  The old 0x146 -> 0xee recipe
    compared different boots and is intentionally no longer executable.
    """
    return {}


def build_first_render_work_lifecycle_qwords():
    """Return exact after-service state required before first render work."""
    result = {}
    for address, entries in RENDER_FIRST_WORK_LIFECYCLE_TRANSITIONS.items():
        if address & (PAGE_SIZE - 1):
            raise ValueError("first-render work lifecycle page is unaligned")
        checked = []
        for offset, before, after in entries:
            if offset & 7 or not 0 <= offset <= PAGE_SIZE - 8:
                raise ValueError("first-render work lifecycle qword is unaligned")
            if not 0 <= before < (1 << 64) or not 0 <= after < (1 << 64):
                raise ValueError(
                    "first-render work lifecycle value does not fit u64"
                )
            checked.append((offset, before, after))
        if len({offset for offset, _before, _after in checked}) != len(checked):
            raise ValueError("first-render work lifecycle qword is duplicated")
        result[address] = tuple(checked)
    return result


def build_first_mixed_render_work_lifecycle_qwords():
    """Return mixed host transitions after channel-12 publication."""
    before = g17g.build_opcode20_first_object(
        0x7200000000,
        g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
        0xFFFFFC2001610000,
        cursor=0x68,
        resource_units=0x1A,
        word_08=1,
        word_10=2,
        word_60=3,
    )
    after = g17g.build_opcode20_first_object(
        0x7200000000,
        g17g_postcontrol.CHANNEL12_TAGGED_ADDRESS,
        0xFFFFFC2001610000,
        cursor=0x78,
        resource_units=0x1A,
        word_08=1,
        word_10=2,
        word_60=3,
    )
    return {
        # The adjacent type-0x84 pair admits generation one.  The actual render
        # work publication advances it to generation two only after the second
        # notification.
        COMPUTE_GLOBAL_SCHEDULER_SLOT: ((
            0x00,
            0x0000000100000000,
            0x0000000200000000,
        ),),
        # Admission has already closed the first record at 0x16 units and
        # opened the fragment record at 0x1a.  Work publication adds the
        # source-owned identity to record zero and expands record one to the
        # complete 0x1e-unit work allocation.
        0xFFFFFC20015F0000: ((
            0x00,
            0x00000000E4000000,
            0x00000000E4008400,
        ), (
            0x08,
            0x0000166000000060,
            0x0000166000000060,
        ), (
            0x10,
            0x0008000000001600,
            0x0008000000001600,
        ), (
            0x20,
            0x00000000E4000000
            | (COMPUTE_MIXED_QUEUE_GENERATION << 8),
            0x00000000E4000000,
        ), (
            0x28,
            0x00001A0000000000,
            0x00001E0000000000,
        ), (
            0x30,
            0x0008000000001A00,
            0x0008000000001E00,
        )),
        RENDER_MIXED_SHARED_CONTROL: ((
            0x40,
            0x0000000100000000,
            0,
        ), (
            0x48,
            struct.unpack_from("<Q", before, 0x48)[0],
            struct.unpack_from("<Q", after, 0x48)[0],
        ),),
        RENDER_LIVE_ADMISSION_PAGE: ((
            RENDER_LIVE_ADMISSION_QWORD_OFFSET,
            0,
            RENDER_MIXED_LIVE_ADMISSION,
        ),),
    }


def build_first_mixed_partial_render_work_lifecycle_qwords():
    """Return the source partial variant of mixed work publication.

    The dependent native partial graph retains its allocation identity at
    ``+0x20`` through the render-pre boundary.  Source uses its own queue
    generation, so retain the corresponding source-built identity rather
    than copying the native token.  The remaining allocation endpoints stay
    those of the already validated source partial graph.
    """
    transitions = build_first_mixed_render_work_lifecycle_qwords()
    allocator_address = 0xFFFFFC20015F0000
    allocator = []
    for offset, before, after in transitions[allocator_address]:
        if offset == 0x20:
            after = before
        allocator.append((offset, before, after))
    transitions[allocator_address] = tuple(allocator)
    return transitions


def build_compute_predecessor_partial_render_work_lifecycle_qwords():
    """Build the exact work boundary after standalone compute retires.

    Unlike the render-first family, this allocation grows additively from the
    completed compute record.  The retained compute queue, optional record,
    allocation record, and channel-12 support object change from the standalone
    compute token cohort to the dependent-render cohort at the same boundary
    that publishes the freshly mapped 32-page render family.
    """
    return {
        g17g_postcontrol.QUEUE_PAGE: ((
            0x040,
            0x00000119FFFFFFFF,
            0x00000016FFFFFFFF,
        ),),
        RENDER_OPTIONAL_PAGE: ((
            0x058,
            0x0002000001190000,
            0x0002000000160000,
        ),),
        0xFFFFFC200002C000: (
            (0x3120, 0, 0x0002000000010000),
            (0x31C0, 0, 1),
        ),
        g17g_initdata.REGION_20_ADDRESS: ((
            0x080,
            0x0000000100000001,
            0x0000000200000001,
        ),),
        0xFFFFFC20015E0000: (
            (0x000, 0, 0xFF),
            (0x008, 0, 0x400),
            (0x010, 0, 0x400),
            (0x400, 0, 0x0000000100000001),
            (0x408, 0, 1),
            (0x600, 0, 3),
            (0xE00, 0, 3),
            (0xE20, 0, 1),
            (0xE28, 0, 1),
        ),
        0xFFFFFC20015E8000: ((
            0x000,
            0x0000003000024000,
            0x0000003000024000,
        ),),
        0xFFFFFC20015F0000: (
            (
                0x08,
                0x00001A6000000060,
                0x0000166000000060,
            ),
            (
                0x10,
                0x0008000000001600,
                0x0008000000001600,
            ),
            (0x20, 0, 0x00000000E4035400),
            (0x28, 0, 0x0000240000000000),
            (0x30, 0, 0x0008000000002400),
        ),
        COMPUTE_GLOBAL_SCHEDULER_SLOT: ((
            0x000,
            0x0000000100000000,
            0x0000000300000000,
        ),),
        g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS: (
            (
                0x020,
                0x00001A0000000000,
                0x0000166000000060,
            ),
            (
                0x028,
                0x00001A0000000000,
                0x0000160000000000,
            ),
        ),
        RENDER_LIVE_ADMISSION_PAGE: ((
            RENDER_LIVE_ADMISSION_QWORD_OFFSET,
            0,
            0x0000002A00001746,
        ),),
    }


def build_post_first_render_lifecycle_qwords(allocator_qwords=None):
    """Return sparse source-before/native-after first-render state.

    Delaying first-work publication until after the first service makes the
    source allocator state deterministic.  The early native occurrence-2
    before-image gives the exact next resource and service-object references.
    Supplying the three live source qwords adds that exact guarded transition
    to the otherwise fully numeric result.
    """
    transitions = dict(RENDER_POST_FIRST_LIFECYCLE_TRANSITIONS)
    if allocator_qwords is not None:
        if len(allocator_qwords) != 3:
            raise ValueError("post-first-render allocator needs three qwords")
        resource, cursor, released = map(int, allocator_qwords)
        if not is_post_first_render_allocator_resource(resource):
            raise ValueError(
                "post-first-render allocator resource shape changed: "
                "resource=%#018x cursor=%#018x released=%#018x"
                % (resource, cursor, released)
            )
        if cursor != RENDER_POST_FIRST_ALLOCATOR_CURSOR_BEFORE:
            raise ValueError(
                "post-first-render allocator cursor shape changed: "
                "resource=%#018x cursor=%#018x released=%#018x"
                % (resource, cursor, released)
            )
        if released != RENDER_POST_FIRST_ALLOCATOR_RELEASED_BEFORE:
            raise ValueError(
                "post-first-render allocator release state changed: "
                "resource=%#018x cursor=%#018x released=%#018x"
                % (resource, cursor, released)
            )
        transitions[RENDER_POST_FIRST_ALLOCATOR_PAGE] = (
            (
                0x008,
                resource,
                RENDER_POST_FIRST_ALLOCATOR_RESOURCE_AFTER,
            ),
            (0x010, cursor, RENDER_POST_FIRST_ALLOCATOR_CURSOR_AFTER),
            (0x018, released, RENDER_POST_FIRST_ALLOCATOR_RELEASED_AFTER),
        )
    transitions[g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS] += (
            (
                0x020,
                0x00001A0000000000,
                RENDER_POST_FIRST_ALLOCATOR_RESOURCE_AFTER,
            ),
            (
                0x028,
                0x00001A0000000000,
            (RENDER_POST_FIRST_ALLOCATOR_CURSOR_AFTER & 0xFFFF) << 32,
        ),
    )
    # The first work's transient address-table entry is absent at the exact
    # native admission boundary for both retained and allocation-heavy paths.
    transitions[g17g_postcontrol.ADDRESS_TABLE_PAGE] += (
        (0x110, 0x0000000100000050, 0x0000000000000050),
        (0x128, 0xC00188A600000001, 0x0),
        (0x130, 0x00000000FFFFFC20, 0x0),
        (0x190, 0x1, 0x0),
    )

    result = {}
    for address, entries in transitions.items():
        if address & (PAGE_SIZE - 1):
            raise ValueError("post-first-render lifecycle page is unaligned")
        checked = []
        for offset, before, after in entries:
            if offset & 7 or not 0 <= offset <= PAGE_SIZE - 8:
                raise ValueError(
                    "post-first-render lifecycle qword is unaligned"
                )
            if not 0 <= before < (1 << 64) or not 0 <= after < (1 << 64):
                raise ValueError(
                    "post-first-render lifecycle value does not fit u64"
                )
            checked.append((offset, before, after))
        if len({offset for offset, _before, _after in checked}) != len(checked):
            raise ValueError(
                "post-first-render lifecycle qword is duplicated"
            )
        result[address] = tuple(checked)
    return result


def build_post_first_render_minimal_lifecycle_qwords(allocator_qwords=None):
    """Return the retained-generation-one occurrence-2 transition.

    The allocation-heavy native occurrence-2 path rolls the scheduler phase
    counter back to four and changes both allocator limit qwords.  A clean
    beta-5 boot that reused its first-render resources instead retained phase
    six and the second 0x400 limit, while advancing the one-byte service
    generation from zero to two.
    """
    transitions = build_post_first_render_lifecycle_qwords(allocator_qwords)
    transitions[0xFFFFFC200002C000] = tuple(
        (offset, before, 2 if offset == 0x31C0 else after)
        for offset, before, after in transitions[0xFFFFFC200002C000]
        if offset != 0x3118
    )
    transitions[0xFFFFFC20015E0000] = tuple(
        entry for entry in transitions[0xFFFFFC20015E0000]
        if entry[0] != 0x008
    )
    # The retained-resource native path also publishes the first render's
    # tiling stage identity.  The paired fragment lane is common to both
    # allocation policies above; both lanes advance to 0x50 after service.
    transitions[0xFFFFFC200002C000] += (
        (0x33C0, 0x0, 0x2D),
    )
    if allocator_qwords is not None:
        retained_resource = 0x00001F3800000138
        transitions[RENDER_POST_FIRST_ALLOCATOR_PAGE] = tuple(
            (
                offset,
                before,
                retained_resource if offset == 0x008 else after,
            )
            for offset, before, after in
            transitions[RENDER_POST_FIRST_ALLOCATOR_PAGE]
        )
        transitions[g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS] = tuple(
            (
                offset,
                before,
                retained_resource if offset == 0x020 else after,
            )
            for offset, before, after in
            transitions[g17g_postcontrol.CHANNEL12_DESCRIPTOR_ADDRESS]
        )
    transitions[g17g_postcontrol.QUEUE_ADDRESS_70_PAGE] = tuple(
        (
            offset,
            before,
            0x0000000648000001 if offset == 0x028 else after,
        )
        for offset, before, after in
        transitions[g17g_postcontrol.QUEUE_ADDRESS_70_PAGE]
    )
    return transitions


def build_second_render_minimal_postservice_qwords():
    """Return the retained-path stage transition after service slot four."""
    return {
        address: tuple(entries)
        for address, entries in
        RENDER_SECOND_MINIMAL_POSTSERVICE_TRANSITIONS.items()
    }


def build_second_render_minimal_work_qwords():
    """Return the retained-path one-byte stage marker for work group two."""
    return {
        address: tuple(entries)
        for address, entries in RENDER_SECOND_MINIMAL_WORK_TRANSITIONS.items()
    }


def find_active_render_service_counter_pairs(page):
    """Locate live ``(tagged count, count)`` records without placement data."""
    page = bytes(page)
    if len(page) != PAGE_SIZE:
        raise ValueError("render service-counter scan needs one page")
    result = []
    for offset in range(0, PAGE_SIZE - 8, 8):
        tagged, count = struct.unpack_from("<QQ", page, offset)
        if 0 < count < (1 << 32) and tagged == (1 << 32) | count:
            result.append((offset, count))
    return tuple(result)


# These descriptor targets are fresh runtime scratch/status pages in the
# source world.  They are absent from the 43-page post-control package because
# their initial representation is simply a zero page.
COMPUTE_SOURCE_ZERO_GLOBAL_PAGES = (
    _page(COMPUTE_GLOBAL_DISPATCH_A),
    _page(COMPUTE_GLOBAL_DISPATCH_B),
    _page(COMPUTE_GLOBAL_STATUS_A),
)

# The accepted beta-5 pre-first-work root adds these four normal/UXN leaves
# after the earlier pre-type-0x84 package.  All four captured pages are
# completely zero.  They are not named by the bounded submission graph, so
# keep their role numeric while making the late topology explicit.
COMPUTE_SOURCE_NEW_ZERO_GLOBAL_PAGES = (
    0xFFFFFC20C07F0000,
    0xFFFFFC20C07F4000,
    0xFFFFFC20C0878000,
    0xFFFFFC20C087C000,
)

# A completed first render retires these four all-zero high-context leaves,
# while the earliest compute pre-work topology retains them.  They therefore
# have to be restored when a quiescent render graph is replaced by compute.
# Symmetric pre-kick snapshots confirm that all four page images are zero.
COMPUTE_AFTER_RENDER_RESTORE_ZERO_GLOBAL_PAGES = (
    0xFFFFFC20C0830000,
    0xFFFFFC20C0834000,
    0xFFFFFC20C0858000,
    0xFFFFFC20C085C000,
)

# Standalone compute retires the wider 25-page service allocation below, but
# the earliest render-then-compute boundary retains 23 of those pages.  Only
# these two leaves are absent in both source render and native mixed compute.
COMPUTE_MIXED_RETIRED_GLOBAL_PAGES = (
    0xFFFFFC20C0890000,
    0xFFFFFC20C0894000,
)

# Render has retired these two all-zero service leaves by the time its clear
# completes, while the immediately following native compute restores them.
COMPUTE_MIXED_RESTORE_ZERO_GLOBAL_PAGES = (
    0xFFFFFC20C0808000,
    0xFFFFFC20C080C000,
)

# Queue index two's high queue-context allocation is a full eight-page span.
# The first page contains its source-built item; the remaining native pages
# are mapped shared/UXN and completely zero at the pre-kick boundary.
COMPUTE_MIXED_QUEUE_CONTEXT_TAIL_PAGES = tuple(
    COMPUTE_MIXED_QUEUE_CONTEXT_HIGH + index * PAGE_SIZE
    for index in range(1, 8)
)


def build_compute_status_global_page():
    """Build the complete shared page containing the two zero status words.

    ``COMPUTE_GLOBAL_STATUS_A/B`` occupy only two qwords in a pre-init
    auxiliary page.  Treating their containing page as scratch erased the
    established interface pointers and post-control state elsewhere in it.
    Rebuild the source-owned page and apply the already-characterized
    post-control fields; the status words themselves remain zero.
    """
    page_address = _page(COMPUTE_GLOBAL_STATUS_A)
    pages = g17g_initdata.build_preinit_auxiliary_pages(0)
    page = bytearray(pages[page_address])
    for offset, value in (
        g17g_postcontrol.build_existing_postcontrol_qwords()[page_address]
    ):
        struct.pack_into("<Q", page, offset, value)
    for address in (COMPUTE_GLOBAL_STATUS_A, COMPUTE_GLOBAL_STATUS_B):
        if any(page[address - page_address:address - page_address + 8]):
            raise ValueError("compute status word is not initially zero")
    return bytes(page)

# Conversely, these 25 earlier-lifecycle pages are absent from the accepted
# beta-5 pre-first-work root. Twenty-one belong to the 43-page pre-type-0x84
# package and four to the wider pre-init region topology. The source coldboot
# adapter keeps them through the six service notifications and then removes
# their high-half leaves before publishing first work. Context-0 aliases are a
# separate mapping surface and are not included here.
COMPUTE_SOURCE_RETIRED_GLOBAL_PAGES = (
    0xFFFFFC2000200000,
    0xFFFFFC2000204000,
    0xFFFFFC2000208000,
    0xFFFFFC200020C000,
    0xFFFFFC2000210000,
    0xFFFFFC2000214000,
    0xFFFFFC2000218000,
    0xFFFFFC200021C000,
    0xFFFFFC2001618000,
    0xFFFFFC2001620000,
    0xFFFFFC2001628000,
    0xFFFFFC2001630000,
    0xFFFFFC20C0808000,
    0xFFFFFC20C080C000,
    0xFFFFFC20C0890000,
    0xFFFFFC20C0894000,
    0xFFFFFC20C08B8000,
    0xFFFFFC20C08C0000,
    0xFFFFFC20C08C8000,
    0xFFFFFC20C08CC000,
    0xFFFFFC20C08D0000,
    0xFFFFFC20C08D4000,
    0xFFFFFC20C08D8000,
    0xFFFFFC20C08DC000,
    0xFFFFFC20C08E8000,
)


def source_global_pages(queue_generation=g17g_compute.COMPUTE_QUEUE_GENERATION):
    """Return source post-control pages required by the compute descriptor.

    These are global lifecycle objects, not submission-owned allocations.  A
    cold-boot runtime must publish them before installing the compute graph.
    """
    package = g17g_postcontrol.build_postcontrol_pages(queue_generation)
    addresses = compute_addresses()
    required = {
        _page(addresses[name])
        for name in (
            "pointers", "scheduler", "scheduler_slot", "shared_support",
            "shared_state", "queue", "item_ring", "job_list", "queue_aux",
            "zero_page",
        )
    }
    missing = required - set(package)
    if missing:
        raise ValueError(
            "source post-control package lacks compute globals: %s"
            % ", ".join("%#x" % address for address in sorted(missing))
        )
    result = {address: package[address] for address in sorted(required)}
    for address in COMPUTE_SOURCE_ZERO_GLOBAL_PAGES:
        if address in result:
            raise ValueError("compute zero global duplicates post-control page")
        result[address] = (
            build_compute_status_global_page()
            if address == _page(COMPUTE_GLOBAL_STATUS_A)
            else bytes(PAGE_SIZE)
        )
    for address in COMPUTE_SOURCE_NEW_ZERO_GLOBAL_PAGES:
        if address in result:
            raise ValueError("compute late-zero global duplicates prior page")
        result[address] = bytes(PAGE_SIZE)
    return dict(sorted(result.items()))


def context1_page_images(graph):
    """Expand the graph's bounded client writes into complete source pages.

    The runtime allocates every DVA in ``expand_compute_context1_dvas()`` with
    fresh zero backing.  This function supplies the nonzero/caller-owned page
    images, including writes such as the three-page operand list.
    """
    allowed = set(graph.get(
        "context1_dvas", g17g_compute.expand_compute_context1_dvas()
    ))
    result = {}
    for address, body in sorted(graph["context1_writes"].items()):
        if int(address) & (PAGE_SIZE - 1):
            raise ValueError("context-1 write is not page aligned: %#x" % address)
        body = bytes(body)
        if not body:
            raise ValueError("context-1 write is empty at %#x" % address)
        for offset in range(0, len(body), PAGE_SIZE):
            page_address = int(address) + offset
            if page_address not in allowed:
                raise ValueError(
                    "context-1 write reaches unmapped page %#x" % page_address
                )
            if page_address in result:
                raise ValueError(
                    "overlapping context-1 page image at %#x" % page_address
                )
            result[page_address] = _page_image(
                body[offset:offset + PAGE_SIZE],
                "context-1 write at %#x" % page_address,
            )
    return dict(sorted(result.items()))


def context1_mapping_runs(graph=None):
    """Return maximal DVA runs with one established UAT permission class."""
    graph = {} if graph is None else graph
    dvas = tuple(graph.get(
        "context1_dvas", g17g_compute.expand_compute_context1_dvas()
    ))
    executable = set(graph.get(
        "context1_read_only_dvas",
        g17g_compute.expand_compute_context1_read_only_dvas(),
    ))
    runs = []
    run_address = None
    run_count = 0
    run_executable = None
    for address in dvas:
        page_executable = address in executable
        if (
            run_address is not None
            and address == run_address + run_count * PAGE_SIZE
            and page_executable == run_executable
        ):
            run_count += 1
            continue
        if run_address is not None:
            runs.append((run_address, run_count, run_executable))
        run_address = address
        run_count = 1
        run_executable = page_executable
    if run_address is not None:
        runs.append((run_address, run_count, run_executable))
    return tuple(runs)


def firmware_page_images(graph):
    """Return complete source pages for every submission firmware object."""
    addresses = graph["addresses"]
    result = {}
    for name, body in graph["firmware_objects"].items():
        address = int(addresses[name])
        if address & (PAGE_SIZE - 1):
            raise ValueError("firmware object %s is not page aligned" % name)
        if address in result:
            raise ValueError("firmware object page overlaps at %#x" % address)
        result[address] = _page_image(body, "firmware object %s" % name)
    return dict(sorted(result.items()))


def build_mixed_compute_pipeline_support(compute_publication_count=2):
    """Return the retained dual-engine compiler support program."""
    return build_earliest_mixed_render_caller_pages(
        compute_publication_count
    )[
        g17g_compute.COMPUTE_PIPELINE_SUPPORT_DVA
    ]


def build_earliest_mixed_render_caller_pages(compute_publication_count=2):
    """Build the four mixed-only caller compiler/resource pages."""
    compute_publication_count = int(compute_publication_count)
    if compute_publication_count not in (1, 2):
        raise ValueError(
            "G17G mixed caller variant requires one or two publications"
        )
    result = g17g_mixed_render_assets.build_mixed_render_context_pages(
        compute_publication_count
    )
    assets = g17g_partial_assets.build_partial_context_pages()
    relocated_pages = (
        RENDER_MIXED_RELOCATED_CALLER_PAGES
        if compute_publication_count == 2 else
        RENDER_MIXED_RELOCATED_CALLER_EDGE_PAGES
    )
    for target, (source, expected_digest) in (
            relocated_pages.items()):
        body = assets.get(source)
        if (
            body is None
            or len(body) != PAGE_SIZE
            or hashlib.sha256(body).hexdigest() != expected_digest
        ):
            raise ValueError(
                "G17G mixed-render relocated asset changed at %#x" % source
            )
        if target in result:
            raise ValueError("G17G mixed-render caller placement overlaps")
        result[target] = body
    return dict(sorted(result.items()))


def build_mixed_compute_relocated_caller_pages():
    """Build the two retained caller assets at their coherent mixed DVAs."""
    assets = g17g_partial_assets.build_partial_context_pages()
    result = {}
    for target, (source, expected_digest) in (
            COMPUTE_MIXED_RELOCATED_CALLER_PAGES.items()):
        body = assets.get(source)
        if (
            body is None
            or len(body) != PAGE_SIZE
            or hashlib.sha256(body).hexdigest() != expected_digest
        ):
            raise ValueError(
                "G17G mixed relocated caller asset changed at %#x" % source
            )
        result[target] = body
    return dict(sorted(result.items()))


def build_add_compute_graph(
        values_a=None, values_b=None, mixed_after_render=False,
        additional_dispatch_values=(),
        direct_dispatch_group_capacity=None,
        direct_buffer_base=COMPUTE_DIRECT_BUFFER_BASE,
        direct_buffer_page_stride=PAGE_SIZE,
        first_dispatch_buffers=None,
        allow_direct_buffer_topology_overlap=False,
        alias_final_dispatch_buffers=False,
        alias_final_dispatch_shader=False,
        truncate_final_dispatch_extent=False,
        dispatch_identity=None, queue_generation=None,
        trailing_zero_page_count=0, trailing_zero_page_base=None,
        fresh_queue_per_group=False,
        native_two_publication_layout=False,
        caller_shader_address=None, caller_cdm_address=None,
        caller_resource_address=None, caller_robustness_address=None,
        additional_shader_record_offset=None):
    """Build one selector-3 ``g17g_add`` graph from caller data.

    ``additional_dispatch_values`` is a sequence of ``(A, B)`` value pairs.
    Each pair becomes another direct-CDM record with independent caller-owned
    A/B/output pages.  Up to 64 records share one selector-3 descriptor and
    one first-work firmware kick.
    """
    if values_a is None:
        values_a = tuple(1000.0 + index for index in range(64))
    else:
        values_a = tuple(float(value) for value in values_a)
    if values_b is None:
        values_b = (0.5,) * 64
    else:
        values_b = tuple(float(value) for value in values_b)
    if len(values_a) != 64 or len(values_b) != 64:
        raise ValueError("g17g_add requires exactly 64 values per input")
    if first_dispatch_buffers is None:
        first_dispatch_buffers = (
            COMPUTE_BUFFER_A, COMPUTE_BUFFER_B, COMPUTE_BUFFER_OUT
        )
        custom_first_dispatch_buffers = False
    else:
        first_dispatch_buffers = tuple(map(int, first_dispatch_buffers))
        custom_first_dispatch_buffers = True
        if len(first_dispatch_buffers) != 3:
            raise ValueError("first compute dispatch requires A/B/output pages")
        if (
            len(set(first_dispatch_buffers)) != 3
            or any(address & (PAGE_SIZE - 1)
                   for address in first_dispatch_buffers)
        ):
            raise ValueError(
                "first compute dispatch pages must be distinct and aligned"
            )

    dispatch_values = [(values_a, values_b)]
    for index, pair in enumerate(additional_dispatch_values, 1):
        try:
            extra_a, extra_b = pair
        except (TypeError, ValueError) as error:
            raise ValueError(
                "additional compute dispatch %d requires an (A, B) pair"
                % index
            ) from error
        extra_a = tuple(float(value) for value in extra_a)
        extra_b = tuple(float(value) for value in extra_b)
        if len(extra_a) != 64 or len(extra_b) != 64:
            raise ValueError(
                "additional compute dispatch %d requires 64 values per input"
                % index
            )
        dispatch_values.append((extra_a, extra_b))
    if len(dispatch_values) > COMPUTE_INITIAL_GRAPH_DISPATCH_LIMIT:
        raise ValueError(
            "initial compute graph supports at most %d dispatches"
            % COMPUTE_INITIAL_GRAPH_DISPATCH_LIMIT
        )
    if direct_dispatch_group_capacity is None:
        direct_dispatch_group_capacity = (
            g17g_compute.G17G_ADD_MAX_DIRECT_DISPATCHES
        )
    direct_dispatch_group_capacity = int(direct_dispatch_group_capacity)
    if not (
        1 <= direct_dispatch_group_capacity
        <= g17g_compute.G17G_ADD_MAX_DIRECT_DISPATCHES
    ):
        raise ValueError(
            "direct compute group capacity must be 1 through %d"
            % g17g_compute.G17G_ADD_MAX_DIRECT_DISPATCHES
        )
    if alias_final_dispatch_shader and len(dispatch_values) < 2:
        raise ValueError("final compute shader alias requires two dispatches")
    if truncate_final_dispatch_extent and len(dispatch_values) < 2:
        raise ValueError("truncated compute extent requires two dispatches")
    direct_buffer_base = int(direct_buffer_base)
    if direct_buffer_base & (PAGE_SIZE - 1):
        raise ValueError("direct compute buffer base is not page aligned")
    direct_buffer_page_stride = int(direct_buffer_page_stride)
    if (
        direct_buffer_page_stride < PAGE_SIZE
        or direct_buffer_page_stride & (PAGE_SIZE - 1)
    ):
        raise ValueError(
            "direct compute buffer page stride is not a positive page multiple"
        )
    trailing_zero_page_count = int(trailing_zero_page_count)
    if not 0 <= trailing_zero_page_count <= 64:
        raise ValueError("trailing compute zero-page count is out of range")
    if trailing_zero_page_base is not None:
        trailing_zero_page_base = int(trailing_zero_page_base)
        if trailing_zero_page_base & (PAGE_SIZE - 1):
            raise ValueError("trailing compute zero-page base is not page aligned")
    mixed_after_render = bool(mixed_after_render)
    fresh_queue_per_group = bool(fresh_queue_per_group)
    native_two_publication_layout = bool(native_two_publication_layout)
    if fresh_queue_per_group and not mixed_after_render:
        raise ValueError(
            "fresh per-group compute queues require the coherent mixed layout"
        )
    if native_two_publication_layout and not (
        mixed_after_render
        and fresh_queue_per_group
        and len(dispatch_values) == 2 * direct_dispatch_group_capacity
    ):
        raise ValueError(
            "native two-publication layout requires two equal-sized fresh "
            "mixed queues"
        )
    if (
        not mixed_after_render
        and len(dispatch_values) > g17g_compute.G17G_ADD_MAX_DIRECT_DISPATCHES
    ):
        raise ValueError(
            "multi-descriptor first-work compute currently requires the "
            "coherent mixed layout"
        )
    addresses = compute_addresses(mixed_after_render=mixed_after_render)
    if native_two_publication_layout:
        addresses.update({
            "shared_support": COMPUTE_MIXED_TWO_SHARED_SUPPORT,
            "shared_state": COMPUTE_MIXED_TWO_SHARED_STATE,
            "status_a": COMPUTE_MIXED_TWO_STATUS_A[0],
            "status_b": COMPUTE_MIXED_TWO_STATUS_B[0],
            "zero_page": COMPUTE_MIXED_TWO_ZEROS[0],
        })
    queue_index = (
        COMPUTE_MIXED_QUEUE_INDEX if mixed_after_render else 0
    )
    if queue_generation is None:
        queue_generation = (
            COMPUTE_MIXED_TWO_QUEUE_GENERATION
            if native_two_publication_layout else
            COMPUTE_MIXED_QUEUE_GENERATION
            if mixed_after_render else
            g17g_compute.COMPUTE_QUEUE_GENERATION
        )
    else:
        queue_generation = int(queue_generation)
        if not 0 <= queue_generation < (1 << 32):
            raise ValueError("compute queue generation does not fit in u32")
    address_list_address = (
        COMPUTE_MIXED_ADDRESS_LIST
        if mixed_after_render else COMPUTE_ADDRESS_LIST
    )
    client_state_address = (
        COMPUTE_MIXED_TWO_CLIENT_STATE
        if native_two_publication_layout else
        COMPUTE_MIXED_CLIENT_STATE
        if mixed_after_render else COMPUTE_CLIENT_STATE
    )
    page_list_address = (
        COMPUTE_MIXED_PAGE_LIST
        if mixed_after_render else COMPUTE_PAGE_LIST
    )
    operand_base = (
        COMPUTE_MIXED_TWO_OPERAND_BASE
        if native_two_publication_layout else
        COMPUTE_MIXED_OPERAND_BASE
        if mixed_after_render else COMPUTE_OPERAND_BASE
    )
    scratch_address = (
        COMPUTE_MIXED_SCRATCH if mixed_after_render else COMPUTE_SCRATCH
    )
    shader_address = (
        int(caller_shader_address) if caller_shader_address is not None else
        COMPUTE_MIXED_SHADER if mixed_after_render else COMPUTE_SHADER
    )
    shader_relocation_target = (
        COMPUTE_MIXED_SHADER_RELOCATION_TARGET
        if mixed_after_render and caller_shader_address is None else
        shader_address
    )
    if additional_shader_record_offset is not None:
        additional_shader_record_offset = int(
            additional_shader_record_offset
        )
        if (
            additional_shader_record_offset
            < g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
            or additional_shader_record_offset & 0x3F
            or additional_shader_record_offset
            + max(0, len(dispatch_values) - 1)
            * g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
            > PAGE_SIZE
        ):
            raise ValueError(
                "additional caller shader record range is invalid"
            )
        if (
            len(dispatch_values) > 1
            and len(dispatch_values) > direct_dispatch_group_capacity
        ):
            raise ValueError(
                "sparse caller shader currently requires one compute descriptor"
            )
    cdm_address = (
        int(caller_cdm_address) if caller_cdm_address is not None else
        COMPUTE_MIXED_CDM if mixed_after_render else COMPUTE_CDM
    )
    resource_address = (
        int(caller_resource_address) if caller_resource_address is not None else
        COMPUTE_MIXED_RESOURCE if mixed_after_render else COMPUTE_RESOURCE
    )
    robustness_address = (
        int(caller_robustness_address)
        if caller_robustness_address is not None else
        COMPUTE_MIXED_ROBUSTNESS if mixed_after_render else COMPUTE_ROBUSTNESS
    )
    for name, address in (
        ("caller shader", shader_address),
        ("caller CDM", cdm_address),
        ("caller resource", resource_address),
        ("caller robustness", robustness_address),
    ):
        if address & (PAGE_SIZE - 1):
            raise ValueError("%s address is not page aligned" % name)
    if dispatch_identity is None:
        dispatch_identity = COMPUTE_DISPATCH_IDENTITY
        if mixed_after_render:
            dispatch_identity = (
                COMPUTE_MIXED_DISPATCH_IDENTITY
                + (
                    (len(dispatch_values) - 1)
                    // COMPUTE_MIXED_DISPATCH_IDENTITY_CAPACITY
                ) * COMPUTE_MIXED_DISPATCH_IDENTITY_STRIDE
            )
    else:
        dispatch_identity = int(dispatch_identity)
        if not 0 <= dispatch_identity < (1 << 64):
            raise ValueError("compute dispatch identity does not fit in u64")
    dispatch_buffers = []
    dispatch_outputs = []
    for index, (dispatch_a_values, dispatch_b_values) in enumerate(
        dispatch_values
    ):
        if alias_final_dispatch_buffers and index == len(dispatch_values) - 1:
            if index == 0:
                raise ValueError(
                    "final compute buffer alias requires two dispatches"
                )
            buffers = dispatch_buffers[-1]
            dispatch_a_values = dispatch_outputs[-1]["values_a"]
            dispatch_b_values = dispatch_outputs[-1]["values_b"]
        elif native_two_publication_layout:
            group_index = index // direct_dispatch_group_capacity
            local_index = index % direct_dispatch_group_capacity
            if local_index == 0:
                buffers = COMPUTE_MIXED_TWO_BUFFERS[group_index]
            else:
                base = (
                    direct_buffer_base
                    + index * 3 * direct_buffer_page_stride
                )
                buffers = (
                    base,
                    base + direct_buffer_page_stride,
                    base + 2 * direct_buffer_page_stride,
                )
        elif index == 0:
            buffers = first_dispatch_buffers
        else:
            base = (
                direct_buffer_base
                + (index - 1) * 3 * direct_buffer_page_stride
            )
            buffers = (
                base,
                base + direct_buffer_page_stride,
                base + 2 * direct_buffer_page_stride,
            )
        dispatch_buffers.append(buffers)
        dispatch_outputs.append({
            "index": index,
            "buffer_a": buffers[0],
            "buffer_b": buffers[1],
            "output": buffers[2],
            "values_a": dispatch_a_values,
            "values_b": dispatch_b_values,
            "expected_values": tuple(
                left + right
                for left, right in zip(
                    dispatch_a_values, dispatch_b_values
                )
            ),
        })
    dispatch_groups = tuple(
        tuple(dispatch_outputs[start:start +
                               direct_dispatch_group_capacity])
        for start in range(
            0, len(dispatch_outputs),
            direct_dispatch_group_capacity,
        )
    )
    group_specs = []
    cdm_image = bytearray(COMPUTE_CDM_MAPPING_SIZE)
    cdm_used_end = 0
    for group_index, group_dispatches in enumerate(dispatch_groups):
        group_cdm_address = (
            COMPUTE_MIXED_TWO_CDM[group_index]
            if native_two_publication_layout else
            cdm_address + group_index * COMPUTE_INITIAL_CDM_GROUP_STRIDE
        )
        group_resource_address = (
            COMPUTE_MIXED_TWO_RESOURCE[group_index]
            if native_two_publication_layout else
            resource_address + group_index * PAGE_SIZE
        )
        group_dispatch_identity = (
            COMPUTE_MIXED_TWO_DISPATCH_IDENTITIES[group_index]
            + (
                (len(group_dispatches) - 1)
                // COMPUTE_MIXED_DISPATCH_IDENTITY_CAPACITY
            ) * COMPUTE_MIXED_DISPATCH_IDENTITY_STRIDE
            if native_two_publication_layout else
            dispatch_identity
            + group_index * COMPUTE_DISPATCH_IDENTITY_STRIDE
        )
        group_shader_address = (
            COMPUTE_MIXED_TWO_SHADER[group_index]
            if native_two_publication_layout else shader_address
        )
        group_cdm = g17g_compute.build_cdm_stream(tuple(
            g17g_compute.build_direct_dispatch(
                (
                    group_shader_address
                    + additional_shader_record_offset
                    + (dispatch["index"] - 1)
                    * g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
                    if additional_shader_record_offset is not None
                    and dispatch["index"] > 0 else
                    group_shader_address
                    + (
                        local_index - 1
                        if alias_final_dispatch_shader
                        and dispatch["index"] == len(dispatch_outputs) - 1
                        else local_index
                    ) * g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
                ),
                grid=(64, 1, 1),
                threadgroup=(32, 1, 1),
            )
            for local_index, dispatch in enumerate(group_dispatches)
        ))
        if not native_two_publication_layout:
            cdm_offset = group_cdm_address - cdm_address
            if cdm_offset + len(group_cdm) > len(cdm_image):
                raise ValueError("initial compute CDM groups exceed their arena")
            cdm_image[cdm_offset:cdm_offset + len(group_cdm)] = group_cdm
            cdm_used_end = max(cdm_used_end, cdm_offset + len(group_cdm))
        group_specs.append({
            "index": group_index,
            "dispatches": group_dispatches,
            "cdm": group_cdm,
            "cdm_address": group_cdm_address,
            "shader_address": group_shader_address,
            "resource_address": group_resource_address,
            "robustness_address": (
                COMPUTE_MIXED_TWO_ROBUSTNESS[group_index]
                if native_two_publication_layout else
                robustness_address + group_index * 2 * PAGE_SIZE
                if fresh_queue_per_group else
                robustness_address + group_index * 0x40
            ),
            "scratch_address": (
                COMPUTE_MIXED_TWO_SCRATCH[group_index]
                if native_two_publication_layout else
                scratch_address
                if not fresh_queue_per_group or group_index == 0 else
                COMPUTE_MIXED_FRESH_SCRATCH_BASE
                + (group_index - 1) * COMPUTE_MIXED_FRESH_SCRATCH_STRIDE
            ),
            "dispatch_identity": group_dispatch_identity,
        })

    context1_writes = {
        g17g_compute.COMPUTE_PIPELINE_SUPPORT_DVA:
            (
                build_mixed_compute_pipeline_support(
                    2 if native_two_publication_layout else 1
                )
                if mixed_after_render else
                g17g_compute.build_compute_pipeline_support()
            ),
        client_state_address:
            g17g_compute.build_compute_operand_table(operand_base),
    }
    if native_two_publication_layout:
        for group in group_specs:
            context1_writes[group["shader_address"]] = (
                g17g_compute.build_add_shader_program(
                    COMPUTE_SHADER,
                    group["shader_address"],
                    dispatch_count=len(group["dispatches"]),
                )
            )
            context1_writes[group["cdm_address"]] = group["cdm"]
    else:
        shader_page = bytearray(g17g_compute.build_add_shader_program(
            COMPUTE_SHADER,
            shader_relocation_target,
            dispatch_count=(
                1 if additional_shader_record_offset is not None else
                max(len(group) for group in dispatch_groups)
            ),
        ))
        if (
            additional_shader_record_offset is not None
            and len(dispatch_values) > 1
        ):
            for dispatch_index in range(1, len(dispatch_values)):
                variant = g17g_compute.build_add_shader_program(
                    COMPUTE_SHADER,
                    shader_relocation_target,
                    dispatch_count=1,
                    dispatch_index_base=dispatch_index,
                )[:g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE]
                start = (
                    additional_shader_record_offset
                    + (dispatch_index - 1)
                    * g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
                )
                shader_page[
                    start:start + g17g_compute.G17G_ADD_SHADER_RECORD_STRIDE
                ] = variant
        context1_writes.update({
            shader_address: bytes(shader_page),
            page_list_address:
                g17g_compute.build_compute_operand_page_lists(),
            cdm_address: bytes(cdm_image[:cdm_used_end]),
        })
    for group in group_specs:
        context1_writes[group["resource_address"]] = (
            g17g_compute.build_buffer_resource_tables(
                tuple(
                    dispatch_buffers[dispatch["index"]]
                    for dispatch in group["dispatches"]
                ),
                size=COMPUTE_RESOURCE_SIZE,
            )
        )
    for dispatch in dispatch_outputs:
        context1_writes[dispatch["buffer_a"]] = struct.pack(
            "<64f", *dispatch["values_a"]
        )
        context1_writes[dispatch["buffer_b"]] = struct.pack(
            "<64f", *dispatch["values_b"]
        )
        context1_writes[dispatch["output"]] = bytes(PAGE_SIZE)
    if mixed_after_render:
        relocated_callers = build_mixed_compute_relocated_caller_pages()
        if native_two_publication_layout:
            # Page-level replay bisection against the earliest two-compute
            # witness isolates this retained compiler asset as necessary for
            # admission.  The neighboring relocated page belongs to the
            # one-compute allocation family and is deliberately not copied.
            context1_writes[COMPUTE_MIXED_TWO_RETAINED_CALLER_PAGE] = (
                relocated_callers[COMPUTE_MIXED_TWO_RETAINED_CALLER_PAGE]
            )
        else:
            # The earliest coherent compute scratch allocation is eight clean
            # pages between its client-state and operand-buffer arenas.
            context1_writes[COMPUTE_MIXED_SCRATCH] = bytes(8 * PAGE_SIZE)
            context1_writes.update(relocated_callers)
    if fresh_queue_per_group:
        for group in group_specs:
            context1_writes[group["robustness_address"]] = bytes(PAGE_SIZE)
            context1_writes[group["scratch_address"]] = bytes(
                8 * PAGE_SIZE
            )
    if not native_two_publication_layout:
        address_list_pages = g17g_compute.build_compute_address_list_pages(
            operand_base,
            address_list_base=address_list_address,
        )
        context1_writes.update(address_list_pages)

    firmware_objects = {}
    if not mixed_after_render:
        firmware_objects.update({
            "class2_state": g17g_compute.build_compute_shared_state(),
            "class2_support": g17g.build_opcode20_first_object(
                COMPUTE_OPERAND_BASE,
                COMPUTE_CLIENT_STATE,
                addresses["class2_state"],
            ),
        })
    queue_context_body = bytearray(PAGE_SIZE)
    item_ring_addresses = []
    group_firmware_objects = []
    for group in group_specs:
        group_index = group["index"]
        group_queue_index = (
            group_index if fresh_queue_per_group else queue_index
        )
        optional_name = (
            "optional" if group_index == 0 else
            "optional_%d" % group_index
        )
        descriptor_name = (
            "descriptor" if group_index == 0 else
            "descriptor_%d" % group_index
        )
        event_name = (
            "event" if group_index == 0 else "event_%d" % group_index
        )
        scheduler_name = (
            "scheduler" if group_index == 0 else
            "scheduler_%d" % group_index
        )
        pointers_name = (
            "pointers" if group_index == 0 else
            "pointers_%d" % group_index
        )
        item_ring_name = (
            "item_ring" if group_index == 0 else
            "item_ring_%d" % group_index
        )
        queue_name = (
            "queue" if group_index == 0 else "queue_%d" % group_index
        )
        queue_context_name = (
            "queue_context" if group_index == 0 else
            "queue_context_%d" % group_index
        )
        zero_name = (
            "zero_page" if group_index == 0 else
            "zero_page_%d" % group_index
        )
        descriptor_address = (
            addresses["descriptor"]
            + group_index * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE
        )
        event_address = (
            COMPUTE_MIXED_TWO_EVENTS[group_index]
            if native_two_publication_layout else
            addresses["event"]
            + group_index * (
                COMPUTE_MIXED_FRESH_EVENT_STRIDE
                if fresh_queue_per_group else
                g17g_compute.COMPUTE_EVENT_SIZE
            )
        )
        optional_address = (
            COMPUTE_MIXED_TWO_OPTIONALS[group_index]
            if native_two_publication_layout else
            addresses["optional"]
            + group_index * (
                COMPUTE_MIXED_FRESH_OPTIONAL_STRIDE
                if fresh_queue_per_group else
                g17g_compute.COMPUTE_OPTIONAL_SIZE
            )
        )
        scheduler_address = addresses["scheduler"] + group_index * 0x100
        pointer_address = (
            COMPUTE_MIXED_TWO_POINTERS[group_index]
            if native_two_publication_layout else
            addresses["pointers"]
            + group_index * COMPUTE_MIXED_FRESH_POINTER_STRIDE
            if fresh_queue_per_group else addresses["pointers"]
        )
        item_ring_address = (
            COMPUTE_MIXED_TWO_ITEM_RINGS[group_index]
            if native_two_publication_layout else
            addresses["item_ring"]
            + group_index * COMPUTE_MIXED_FRESH_POINTER_STRIDE
            if fresh_queue_per_group else addresses["item_ring"]
        )
        queue_address = (
            COMPUTE_MIXED_TWO_QUEUES[group_index]
            if native_two_publication_layout else
            addresses["queue"]
            + group_index * COMPUTE_MIXED_FRESH_QUEUE_STRIDE
            if fresh_queue_per_group else addresses["queue"]
        )
        queue_context_address = (
            COMPUTE_MIXED_TWO_QUEUE_CONTEXT_HIGH[group_index]
            if native_two_publication_layout else
            addresses["queue_context"]
            + group_index * COMPUTE_MIXED_FRESH_QUEUE_CONTEXT_STRIDE
            if fresh_queue_per_group else addresses["queue_context"]
        )
        queue_context_low = (
            COMPUTE_MIXED_TWO_QUEUE_CONTEXT_LOW[group_index]
            if native_two_publication_layout else
            COMPUTE_MIXED_QUEUE_CONTEXT_LOW
            + group_index * COMPUTE_MIXED_FRESH_QUEUE_CONTEXT_STRIDE
            if fresh_queue_per_group else
            COMPUTE_MIXED_QUEUE_CONTEXT_LOW
            if mixed_after_render else COMPUTE_QUEUE_CONTEXT_LOW
        )
        addresses[optional_name] = optional_address
        addresses[descriptor_name] = descriptor_address
        addresses[event_name] = event_address
        addresses[scheduler_name] = scheduler_address
        addresses[pointers_name] = pointer_address
        addresses[item_ring_name] = item_ring_address
        addresses[queue_name] = queue_address
        addresses[queue_context_name] = queue_context_address
        zero_address = (
            COMPUTE_MIXED_TWO_ZEROS[group_index]
            if native_two_publication_layout else
            addresses["zero_page"]
            if group_index == 0 else
            COMPUTE_MIXED_FRESH_ZERO_BASE
            + (group_index - 1) * PAGE_SIZE
            if fresh_queue_per_group else
            addresses["zero_page"] + group_index * 0x40
        )
        addresses[zero_name] = zero_address
        registers = g17g_compute.build_compute_registers(
            resource=group["resource_address"],
            cdm=group["cdm_address"],
            robustness=group["robustness_address"],
            scratch=group["scratch_address"],
            dispatch_identity=group["dispatch_identity"],
            work_ordinal=(
                2 * group_index
                if native_two_publication_layout else
                (1 if mixed_after_render else 0) + group_index
            ),
            register_14028=0,
        )
        descriptor = g17g_compute.build_compute_descriptor(
            registers=registers,
            scheduler_record=scheduler_address,
            low_alias=(
                COMPUTE_DESCRIPTOR_LOW
                + group_index * g17g_compute.COMPUTE_DESCRIPTOR_STRIDE
            ),
            cdm_terminator=(
                group["cdm_address"] + len(group["cdm"]) - 4
                - (
                    g17g_compute.CDM_RECORD_SIZE
                    if truncate_final_dispatch_extent
                    and group_index == len(group_specs) - 1
                    else 0
                )
            ),
            dispatch_identity=group["dispatch_identity"],
            context_id=1,
            descriptor_index=group_queue_index,
            submit_sequence=group_index,
            tail_submit_sequence=group_index,
            lifecycle_ordinal=(
                1 if fresh_queue_per_group else group_index + 1
            ),
            queue_submission=(
                1 if fresh_queue_per_group else group_index + 1
            ),
            dispatch_a=(
                addresses["dispatch_a"] + group_index * 4
            ),
            dispatch_b=(
                addresses["dispatch_b"] + group_index * 4
            ),
            status_a=(
                COMPUTE_MIXED_TWO_STATUS_A[group_index]
                if native_two_publication_layout else
                addresses["status_a"] + group_index * 0x10
            ),
            status_b=(
                COMPUTE_MIXED_TWO_STATUS_B[group_index]
                if native_two_publication_layout else
                addresses["status_b"] + group_index * 0x10
            ),
            shared_control=addresses["shared_support"],
            zero_page=zero_address,
        )[:g17g_compute.COMPUTE_DESCRIPTOR_OBJECT_SIZE]
        event = g17g_compute.build_compute_event(
            group_number=(
                1 if fresh_queue_per_group else group_index + 1
            ),
            queue_index=group_queue_index,
        )
        scheduler = None
        if mixed_after_render:
            scheduler = g17g_compute.build_compute_scheduler_record(
                addresses["scheduler_slot"],
                slot_index=group_index + 1,
                work_id=(
                    2 * group_index
                    if native_two_publication_layout else group_index + 1
                ),
            )
        optional = g17g_compute.build_compute_optional(
            queue_context_low,
            queue_context_address,
            shared_control=addresses["shared_support"],
            channel_control=addresses["queue_aux"],
            submission_ordinal=(
                1 if fresh_queue_per_group or group_index == 0 else
                3 * group_index
            ),
            token=queue_generation,
            first_queue=(fresh_queue_per_group or group_index == 0),
            queue_index=group_queue_index,
            byte_46=0,
        )
        group_firmware_objects.append((
            optional_name, optional, event_name, event,
            descriptor_name, descriptor,
            scheduler_name, scheduler,
        ))
        context_item_index = 0 if fresh_queue_per_group else group_index
        context_offset = g17g_compute.compute_queue_context_item_offset(
            context_item_index
        )
        context_item = g17g_compute.build_compute_queue_context_item(
            descriptor_address,
            queue_address,
            item_index=context_item_index,
            queue_index=group_queue_index,
        )
        if fresh_queue_per_group:
            context_body = bytearray(PAGE_SIZE)
            context_body[
                context_offset:context_offset + len(context_item)
            ] = context_item
            firmware_objects[queue_context_name] = bytes(context_body)
            if group_index:
                firmware_objects[zero_name] = bytes(PAGE_SIZE)
            scratch_start = group["scratch_address"]
            scratch_end = scratch_start + 8 * PAGE_SIZE
            if not scratch_start <= queue_context_low < scratch_end:
                context1_writes[queue_context_low] = bytes(PAGE_SIZE)
        else:
            queue_context_body[
                context_offset:context_offset + len(context_item)
            ] = context_item
        group_item_addresses = (
            optional_address, descriptor_address, event_address,
        )
        item_ring_addresses.extend(group_item_addresses)
        group["transport"] = {
            "pointers_name": pointers_name,
            "pointers": pointer_address,
            "item_ring_name": item_ring_name,
            "item_ring": item_ring_address,
            "queue_name": queue_name,
            "queue": queue_address,
            "item_addresses": group_item_addresses,
        }

    if not fresh_queue_per_group:
        firmware_objects["queue_context"] = bytes(queue_context_body)
    for (
        optional_name, optional, event_name, event,
        descriptor_name, descriptor,
        scheduler_name, scheduler,
    ) in group_firmware_objects:
        firmware_objects[optional_name] = optional
        firmware_objects[event_name] = event
        firmware_objects[descriptor_name] = descriptor
        if scheduler is not None:
            firmware_objects[scheduler_name] = scheduler

    postcontrol = g17g_postcontrol.build_postcontrol_pages(queue_generation)
    pointer_block = g17g.build_pointer_block(
        field_00=0, field_30=0, field_40=len(item_ring_addresses)
    )
    queue_record = g17g_compute.build_compute_queue_record(
        addresses["pointers"], addresses["item_ring"],
        addresses["job_list"], addresses["queue_aux"],
        queue_generation=queue_generation,
    )
    if mixed_after_render:
        # The render queues occupy the first two records in each arena.  Write
        # only compute's bounded third records so their live bytes survive.
        if fresh_queue_per_group:
            for group in group_specs:
                transport = group["transport"]
                firmware_objects[transport["pointers_name"]] = (
                    g17g.build_pointer_block(
                        field_00=0, field_30=0, field_40=3
                    )
                )
                firmware_objects[transport["item_ring_name"]] = struct.pack(
                    "<3Q", *transport["item_addresses"]
                )
                firmware_objects[transport["queue_name"]] = (
                    g17g_compute.build_compute_queue_record(
                        transport["pointers"], transport["item_ring"],
                        addresses["job_list"], addresses["queue_aux"],
                        queue_generation=queue_generation,
                    )
                )
        else:
            firmware_objects["pointers"] = pointer_block
            firmware_objects["item_ring"] = struct.pack(
                "<%dQ" % len(item_ring_addresses), *item_ring_addresses
            )
            firmware_objects["queue"] = queue_record
        if native_two_publication_layout:
            initial_active_groups = len(group_specs)
            firmware_objects["shared_support"] = (
                g17g_compute.build_compute_shared_support(
                    client_state_address,
                    addresses["shared_state"],
                    active=1,
                )
            )
            firmware_objects["shared_state"] = (
                g17g_compute.build_compute_shared_state(
                    active=initial_active_groups
                )
            )
        else:
            support = bytearray(g17g.build_opcode20_first_object(
                address_list_address,
                client_state_address,
                addresses["shared_state"],
                cursor=0x58,
                resource_units=0x16,
                word_08=0,
                word_10=2,
                word_60=2,
            ))
            initial_active_groups = (
                1 if fresh_queue_per_group else len(group_specs)
            )
            struct.pack_into("<I", support, 0x00, 1 + initial_active_groups)
            struct.pack_into("<I", support, 0x5C, initial_active_groups)
            firmware_objects["shared_support"] = bytes(support)
            firmware_objects["shared_state"] = (
                g17g_compute.build_compute_shared_state(
                    active=initial_active_groups
                )
            )
        firmware_objects["zero_page"] = bytes(PAGE_SIZE)
    else:
        firmware_objects["job_list"] = postcontrol[addresses["job_list"]]
        firmware_objects["queue_aux"] = postcontrol[addresses["queue_aux"]]
        pointer_page = bytearray(postcontrol[addresses["pointers"]])
        pointer_page[:len(pointer_block)] = pointer_block
        firmware_objects["pointers"] = bytes(pointer_page)
        item_ring = bytearray(postcontrol[addresses["item_ring"]])
        struct.pack_into(
            "<%dQ" % len(item_ring_addresses), item_ring, 0,
            *item_ring_addresses,
        )
        firmware_objects["item_ring"] = bytes(item_ring)
        queue_page = bytearray(postcontrol[addresses["queue"]])
        queue_page[:len(queue_record)] = queue_record
        firmware_objects["queue"] = bytes(queue_page)

    # Each descriptor is a complete selector-15/3/14 group.  The first outer
    # slot carries the one-time registration tag; later prequeued slots use
    # the observed complete-group grammar and cumulative 3-item limits.
    channel_patches = tuple(
        (
            g17g_compute.COMPUTE_CHANNEL_RING_SLOT_OFFSET
            + group_index * g17g.RING_SLOT_SIZE,
            (
                g17g_compute.build_compute_channel_slot(
                    group["transport"]["queue"],
                    queue_index=(group_index if fresh_queue_per_group else
                                 queue_index),
                )
                if fresh_queue_per_group or group_index == 0 else
                g17g_compute.build_compute_full_group_channel_slot(
                    addresses["queue"],
                    item_limit=3 * (group_index + 1),
                    queue_index=queue_index,
                )
            ),
        )
        for group_index, group in enumerate(group_specs)
    )
    firmware_patches = {
        "channel_ring": channel_patches,
        "state": ((
            g17g_compute.COMPUTE_CHANNEL_STATE_OFFSET,
            struct.pack(
                "<I12xI12xI", 0, 0, len(group_specs)
            ),
        ),),
    }

    fresh_firmware_page_flags = {}
    if mixed_after_render:
        fresh_firmware_page_flags.update({
            addresses["queue_context"]: "shared",
            addresses["shared_state"]: "shared",
            addresses["shared_support"]: "normal",
            # The paired native render->compute pre-kick snapshot changes
            # this reused render leaf to shared UXN.  Keeping the inherited
            # executable PTE is the sole common-DVA PTE-class mismatch.
            addresses["zero_page"]: "shared",
        })
        fresh_firmware_page_flags.update({
            address: "shared"
            for address in COMPUTE_MIXED_QUEUE_CONTEXT_TAIL_PAGES
        })
        if fresh_queue_per_group:
            fresh_firmware_page_flags.update({
                int(addresses[
                    "queue_context" if group["index"] == 0 else
                    "queue_context_%d" % group["index"]
                ]): "shared"
                for group in group_specs
            })
            fresh_firmware_page_flags.update({
                int(addresses["zero_page_%d" % group["index"]]): "shared"
                for group in group_specs[1:]
            })
    base_context1_dvas = (
        mixed_compute_context1_dvas()
        if mixed_after_render else
        g17g_compute.expand_compute_context1_dvas()
    )
    base_context1_read_only_dvas = (
        mixed_compute_context1_read_only_dvas()
        if mixed_after_render else
        g17g_compute.expand_compute_context1_read_only_dvas()
    )
    extra_resource_dvas = tuple(sorted(
        int(group["resource_address"])
        for group in group_specs[1:]
    ))
    native_context1_dvas = tuple(sorted({
        int(address) + offset
        for address, body in context1_writes.items()
        for offset in range(0, len(body), PAGE_SIZE)
    })) if native_two_publication_layout else ()
    requested_extra_context1_dvas = {
        int(dispatch[name])
        for dispatch in dispatch_outputs[1:]
        for name in ("buffer_a", "buffer_b", "output")
    }
    if custom_first_dispatch_buffers:
        requested_extra_context1_dvas.update(first_dispatch_buffers)
    reusable_zero_dvas = {
        base + index * PAGE_SIZE
        for base, page_count in g17g_compute.COMPUTE_CONTEXT1_ZERO_RUNS
        for index in range(page_count)
    }
    direct_buffer_topology_overlap = tuple(sorted(
        requested_extra_context1_dvas
        & set(base_context1_dvas)
        - (
            set(first_dispatch_buffers) & reusable_zero_dvas
            if custom_first_dispatch_buffers else set()
        )
    ))
    extra_context1_dvas = tuple(sorted(
        requested_extra_context1_dvas - set(base_context1_dvas)
    ))
    if trailing_zero_page_base is None:
        trailing_zero_page_base = (
            max(extra_context1_dvas) + PAGE_SIZE
            if extra_context1_dvas else direct_buffer_base
        )
    trailing_context1_dvas = tuple(
        trailing_zero_page_base + index * PAGE_SIZE
        for index in range(trailing_zero_page_count)
    )
    if direct_buffer_topology_overlap and not bool(
        allow_direct_buffer_topology_overlap
    ):
        raise ValueError("direct-dispatch caller buffers overlap base topology")
    if set(trailing_context1_dvas) & (
        set(base_context1_dvas) | set(extra_context1_dvas)
    ):
        raise ValueError("trailing compute pages overlap live topology")
    context1_dvas = tuple(sorted(
        set(base_context1_dvas)
        | set(extra_resource_dvas)
        | set(extra_context1_dvas)
        | set(trailing_context1_dvas)
        | set(native_context1_dvas)
    ))
    context1_read_only_dvas = tuple(sorted(
        set(base_context1_read_only_dvas)
        | (
            {group["shader_address"] for group in group_specs[1:]}
            if native_two_publication_layout else
            set(extra_resource_dvas)
        )
    ))
    return {
        "format": (
            "m1n1-t8142-g17g-host-mixed-compute-graph-v2"
            if mixed_after_render and len(dispatch_outputs) > 1 else
            "m1n1-t8142-g17g-host-compute-graph-v2"
            if len(dispatch_outputs) > 1 else
            "m1n1-t8142-g17g-host-mixed-compute-graph-v1"
            if mixed_after_render else
            "m1n1-t8142-g17g-host-compute-graph-v1"
        ),
        "channel": COMPUTE_CHANNEL,
        "grid_index": COMPUTE_GRID_INDEX,
        "addresses": addresses,
        "context1_writes": context1_writes,
        "firmware_objects": firmware_objects,
        "firmware_patches": firmware_patches,
        "source_global_pages": (
            {} if mixed_after_render else source_global_pages(queue_generation)
        ),
        "context1_dvas": context1_dvas,
        "context1_read_only_dvas": (
            context1_read_only_dvas
        ),
        "context1_retired_dvas": (
            COMPUTE_MIXED_CONTEXT1_RETIRED_DVAS
            if mixed_after_render else ()
        ),
        "context1_repermission_dvas": (
            COMPUTE_MIXED_CONTEXT1_REPERMISSION_DVAS
            if mixed_after_render else ()
        ),
        "queue_index": queue_index,
        "queue_generation": queue_generation,
        "scratch_address": scratch_address,
        "robustness_address": robustness_address,
        "dispatch_identity": dispatch_identity,
        "fresh_firmware_page_flags": fresh_firmware_page_flags,
        "values_a": values_a,
        "values_b": values_b,
        "expected_values": dispatch_outputs[0]["expected_values"],
        "dispatch_outputs": tuple(dispatch_outputs),
        "direct_dispatch_count": len(dispatch_outputs),
        "direct_dispatch_group_capacity": direct_dispatch_group_capacity,
        "additional_shader_record_offset": additional_shader_record_offset,
        "direct_buffer_base": direct_buffer_base,
        "direct_buffer_page_stride": direct_buffer_page_stride,
        "first_dispatch_buffers": first_dispatch_buffers,
        "direct_buffer_topology_overlap": direct_buffer_topology_overlap,
        "aliased_final_dispatch_buffers": bool(alias_final_dispatch_buffers),
        "aliased_final_dispatch_shader": bool(alias_final_dispatch_shader),
        "truncated_final_dispatch_extent": bool(
            truncate_final_dispatch_extent
        ),
        "trailing_zero_page_count": trailing_zero_page_count,
        "trailing_zero_page_base": trailing_zero_page_base,
        "compute_descriptor_count": len(group_specs),
        "cdm_addresses": tuple(
            group["cdm_address"] for group in group_specs
        ),
        "shader_addresses": tuple(
            group["shader_address"] for group in group_specs
        ),
        "resource_addresses": tuple(
            group["resource_address"] for group in group_specs
        ),
        "fresh_queue_per_group": fresh_queue_per_group,
        "native_two_publication_layout": native_two_publication_layout,
        "deferred_fresh_shared_activation": (
            fresh_queue_per_group and not native_two_publication_layout
        ),
        "cdm_size": sum(len(group["cdm"]) for group in group_specs),
        "cdm_group_sizes": tuple(
            len(group["cdm"]) for group in group_specs
        ),
        "shader_sha256": hashlib.sha256(
            g17g_compute.G17G_ADD_SHADER
        ).hexdigest(),
    }


def build_compute_predecessor_partial_compute_graph(
        include_first_admission_assets=True, **kwargs):
    """Build compute with the native first-admission caller topology.

    This remains completely source-built.  The topology recipe only moves the
    fixed caller program and removes/adds zero-backed allocation leaves; extra
    dispatch buffers requested by the caller remain present.
    """
    native_two_publication_layout = bool(
        kwargs.get("native_two_publication_layout", False)
    )
    fixed = {} if native_two_publication_layout else {
        "first_dispatch_buffers": (
            COMPUTE_PREDECESSOR_PARTIAL_FIRST_DISPATCH_BUFFERS
        ),
        "caller_shader_address": COMPUTE_PREDECESSOR_PARTIAL_SHADER,
        "caller_cdm_address": COMPUTE_PREDECESSOR_PARTIAL_CDM,
        "caller_resource_address": COMPUTE_PREDECESSOR_PARTIAL_RESOURCE,
        "caller_robustness_address": COMPUTE_PREDECESSOR_PARTIAL_ROBUSTNESS,
        "additional_shader_record_offset": (
            COMPUTE_PREDECESSOR_PARTIAL_ADDITIONAL_SHADER_OFFSET
        ),
    }
    conflicts = tuple(sorted(set(kwargs) & set(fixed)))
    if conflicts:
        raise ValueError(
            "compute-predecessor partial topology fixes caller placement: %s"
            % ", ".join(conflicts)
        )
    graph = build_add_compute_graph(**fixed, **kwargs)
    source_dvas = set(map(int, graph["context1_dvas"]))
    source_read_only = set(map(int, graph["context1_read_only_dvas"]))

    def expand(runs):
        return {
            base + index * PAGE_SIZE
            for base, page_count in runs
            for index in range(page_count)
        }

    asset_dvas = (
        set(g17g_compute_predecessor_assets
            .COMPUTE_PREDECESSOR_CALLER_PAGE_SHA256)
        | {COMPUTE_PREDECESSOR_PARTIAL_SHADER}
    )
    asset_read_only_dvas = {
        0x10000000000,
        0x10000004000,
        0x10000008000,
        0x1000000C000,
        0x10000158000,
    }
    if native_two_publication_layout:
        # The independently owned two-publication compute family already has
        # its own larger caller topology.  Preserve it and add only the
        # first-admission caller pages it lacks; applying the one-publication
        # removal recipe would incorrectly delete live queue-two resources.
        # The all-zero 0x1000230000 leaf is not directly referenced by a
        # decoded object, but the earlier native/source topology bisection
        # proved that its presence alone gates admission of both queues.
        removed = set()
        added = (
            asset_dvas | {RENDER_MIXED_COMPUTE_ADMISSION_ZERO_DVA}
        ) - source_dvas
        read_only_removed = set()
        read_only_added = asset_read_only_dvas - source_read_only
    else:
        removed = expand(COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_REMOVED_RUNS)
        added = expand(COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_ADDED_RUNS)
        read_only_removed = expand(
            COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_REMOVED_RUNS
        )
        read_only_added = expand(
            COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_ADDED_RUNS
        )
        if not removed <= source_dvas:
            raise ValueError("compute-predecessor source topology lost leaves")
    # Extended graphs can legitimately consume a leaf that the native
    # one-dispatch topology already contributed.  The first extra per-job
    # resource page is exactly such a case.  The union below is idempotent;
    # retain the overlap in the provenance record instead of rejecting an
    # otherwise source-built extension.
    preexisting_added = added & source_dvas
    if not read_only_removed <= source_read_only:
        raise ValueError("compute-predecessor source permission set changed")
    if not native_two_publication_layout and not read_only_added <= added:
        raise ValueError("compute-predecessor executable addition escaped")

    graph = dict(graph)
    if native_two_publication_layout:
        writes = dict(graph["context1_writes"])
        writes[RENDER_MIXED_COMPUTE_ADMISSION_ZERO_DVA] = bytes(PAGE_SIZE)
        graph["context1_writes"] = dict(sorted(writes.items()))
    first_work_global_pages = {}
    if native_two_publication_layout:
        # Ordinary mixed render publishes this exact global closure before it
        # makes the two compute queues visible.  A compute-predecessor partial
        # sequence has no preceding render publication, so carry only the
        # pages reached by compute's queue/descriptor/scheduler objects.  The
        # graph's bounded objects are written afterwards and replace records
        # one and two in the scheduler page as usual.
        render_globals = render_source_global_pages(
            graph["queue_generation"],
            mixed_compute_pending=True,
            compute_publication_count=2,
            compute_predecessor=False,
        )
        first_work_global_pages = {
            address: render_globals[address]
            for address in COMPUTE_MIXED_TWO_FIRST_WORK_GLOBAL_PAGES
        }
        graph["source_global_pages"] = dict(first_work_global_pages)
    graph["context1_dvas"] = tuple(sorted(source_dvas - removed | added))
    graph["context1_read_only_dvas"] = tuple(sorted(
        source_read_only - read_only_removed | read_only_added
    ))
    asset_record = {
        "captured_input": None,
        "included": bool(include_first_admission_assets),
        "source_manifest_sha256": (
            g17g_compute_predecessor_assets.SOURCE_MANIFEST_SHA256
        ),
    }
    if include_first_admission_assets:
        if (
            graph["compute_descriptor_count"] != 1
            and not graph["native_two_publication_layout"]
        ):
            raise ValueError(
                "compute-predecessor first-admission assets require one "
                "compute descriptor"
            )
        writes = dict(graph["context1_writes"])
        caller_pages = (
            g17g_compute_predecessor_assets
            .build_compute_predecessor_caller_pages()
        )
        if not set(caller_pages) <= set(graph["context1_dvas"]):
            raise ValueError("compute-predecessor caller asset escaped topology")
        merged_caller_pages = {}
        for address, asset_body in caller_pages.items():
            source_body = writes.get(address)
            if not native_two_publication_layout or source_body is None:
                writes[address] = asset_body
                continue
            if len(source_body) > PAGE_SIZE or len(asset_body) != PAGE_SIZE:
                raise ValueError("compute-predecessor caller page size changed")
            source_body = bytes(source_body).ljust(PAGE_SIZE, b"\0")
            merged = bytearray(source_body)
            added_byte_count = 0
            conflicting_byte_count = 0
            for offset, asset_byte in enumerate(asset_body):
                source_byte = source_body[offset]
                if asset_byte and not source_byte:
                    merged[offset] = asset_byte
                    added_byte_count += 1
                elif asset_byte and source_byte != asset_byte:
                    conflicting_byte_count += 1
            writes[address] = bytes(merged)
            merged_caller_pages[address] = {
                "source_sha256": hashlib.sha256(source_body).hexdigest(),
                "asset_sha256": hashlib.sha256(asset_body).hexdigest(),
                "merged_sha256": hashlib.sha256(merged).hexdigest(),
                "added_byte_count": added_byte_count,
                "source_precedence_conflicting_byte_count": (
                    conflicting_byte_count
                ),
            }
        shader_address = COMPUTE_PREDECESSOR_PARTIAL_SHADER
        shader_page = bytearray(writes.get(
            shader_address,
            g17g_compute.build_add_shader_program(
                COMPUTE_SHADER,
                shader_address,
                dispatch_count=1,
            ),
        ))
        tail_start = (
            g17g_compute_predecessor_assets
            .COMPUTE_PREDECESSOR_SHADER_TAIL_OFFSET
        )
        tail_end = (
            g17g_compute_predecessor_assets
            .COMPUTE_PREDECESSOR_SHADER_TAIL_END
        )
        if any(shader_page[tail_start:tail_end]):
            raise ValueError(
                "compute-predecessor shader tail overlaps source program"
            )
        shader_page[tail_start:tail_end] = (
            g17g_compute_predecessor_assets
            .compute_predecessor_shader_tail()
        )
        writes[shader_address] = bytes(shader_page)
        graph["context1_writes"] = dict(sorted(writes.items()))
        asset_record.update({
            "caller_page_count": len(caller_pages),
            "caller_page_sha256": dict(
                g17g_compute_predecessor_assets
                .COMPUTE_PREDECESSOR_CALLER_PAGE_SHA256
            ),
            "shader_tail_offset": tail_start,
            "shader_tail_end": tail_end,
            "shader_tail_sha256": (
                g17g_compute_predecessor_assets
                .COMPUTE_PREDECESSOR_SHADER_TAIL_SHA256
            ),
            "merged_caller_pages": merged_caller_pages,
        })
    images = context1_page_images(graph)
    if not set(images) <= set(graph["context1_dvas"]):
        raise ValueError("compute-predecessor page image escaped topology")

    standard_graph = (
        len(source_dvas)
        == COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_SOURCE_PAGE_COUNT
        and len(source_read_only)
        == COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_SOURCE_RO_PAGE_COUNT
    )
    if standard_graph:
        checks = (
            (
                graph["context1_dvas"],
                COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_PAGE_COUNT,
                COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_DVA_SHA256,
                "DVA",
            ),
            (
                graph["context1_read_only_dvas"],
                COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_PAGE_COUNT,
                COMPUTE_PREDECESSOR_PARTIAL_COMPUTE_RO_DVA_SHA256,
                "read-only DVA",
            ),
        )
        for values, expected_count, expected_sha256, label in checks:
            encoded = b"".join(
                struct.pack("<Q", address) for address in values
            )
            if (
                len(values) != expected_count
                or hashlib.sha256(encoded).hexdigest() != expected_sha256
            ):
                raise ValueError(
                    "compute-predecessor partial %s topology changed" % label
                )

    graph["compute_predecessor_partial_context1_topology"] = {
        "captured_input": None,
        "source_mapping_count": len(source_dvas),
        "mapping_count": len(graph["context1_dvas"]),
        "source_read_only_mapping_count": len(source_read_only),
        "read_only_mapping_count": len(graph["context1_read_only_dvas"]),
        "removed_mapping_count": len(removed),
        "added_mapping_count": len(added),
        "preexisting_added_mapping_count": len(preexisting_added),
        "native_two_publication_layout": native_two_publication_layout,
        "standard_graph": standard_graph,
    }
    graph["compute_predecessor_partial_context1_assets"] = asset_record
    graph["compute_predecessor_partial_first_work_globals"] = {
        "captured_input": None,
        "included": bool(first_work_global_pages),
        "page_count": len(first_work_global_pages),
        "pages": {
            address: hashlib.sha256(body).hexdigest()
            for address, body in sorted(first_work_global_pages.items())
        },
    }
    return graph


def _build_mixed_render_target_record_page(layout=None):
    """Build the shifted allocation-family target records for mixed work."""
    layout = _mixed_render_layout() if layout is None else dict(layout)
    family_delta = int(layout["resource_address_offset"]) - (
        RENDER_MIXED_RESOURCE_ADDRESS_OFFSET
    )
    if family_delta not in (0, PAGE_SIZE * 2):
        raise ValueError("unsupported mixed target-record allocation family")
    page = bytearray(PAGE_SIZE)
    for index in range(g17g_postcontrol.TARGET_RECORD_ARRAY_COUNT):
        record = g17g.build_target_record_80(
            0x1000088000 + family_delta + index * 0x40,
            0xFFFFFC2001638000 + family_delta + index * 0x40,
            0x228000 + family_delta + (index % 36) * 0x40,
            0xFFFFFC2001630040 + family_delta,
            word_48=(1 << 32) if index == 1 else 0,
        )
        offset = index * g17g.TARGET_RECORD_80_STRIDE
        page[offset:offset + len(record)] = record
    return bytes(page)


def _build_compute_predecessor_render_target_record_page():
    """Build the exact target-record family added after compute retires."""
    page = bytearray(PAGE_SIZE)
    for index in range(g17g_postcontrol.TARGET_RECORD_ARRAY_COUNT):
        record = g17g.build_target_record_80(
            0x1000088000 + index * 0x40,
            0xFFFFFC2001630000 + index * 0x40,
            0x228000 + (index % 36) * 0x40,
            0xFFFFFC2001628040,
            word_48=(1 << 32) if index == 1 else 0,
        )
        offset = index * g17g.TARGET_RECORD_80_STRIDE
        page[offset:offset + len(record)] = record
    return bytes(page)


def _build_mixed_render_trailing_descriptor_page(package):
    """Relocate the decoded trailing descriptor into allocation family 1."""
    page = bytearray(package[0xFFFFFC20C08E8000])
    for offset, value in (
        (0x20, 0xFFFFFC20C08D8000),
        (0x28, 0x1000240000),
        (0x44, 0xFFFFFC20C08D0000),
        (0x4C, 0xFFFFFC2001630000),
        (0x64, 0xFFFFFC2001640000),
    ):
        struct.pack_into("<Q", page, offset, value)
    struct.pack_into("<I", page, 0x84, 0x230000)
    return bytes(page)


def _build_compute_predecessor_render_trailing_descriptor_page(package):
    """Build the trailing descriptor in the compute-predecessor family."""
    page = bytearray(package[0xFFFFFC20C08E8000])
    for offset, value in (
        (0x20, 0xFFFFFC20C08D0000),
        (0x28, 0x1000240000),
        (0x44, 0xFFFFFC20C08C8000),
        (0x4C, 0xFFFFFC2001628000),
        (0x64, 0xFFFFFC2001638000),
    ):
        struct.pack_into("<Q", page, offset, value)
    struct.pack_into("<I", page, 0x84, 0x230000)
    return bytes(page)


def _mixed_render_layout(
        compute_publication_count=1, compute_predecessor=False):
    """Return the measured transport/scratch family for pending compute."""
    compute_publication_count = int(compute_publication_count)
    compute_predecessor = bool(compute_predecessor)
    if compute_predecessor:
        if compute_publication_count not in (1, 2):
            raise ValueError(
                "compute-predecessor render supports one or two retired "
                "publications"
            )
        return {
            "token": COMPUTE_PREDECESSOR_RENDER_TOKEN,
            "tiling_physical_queue_index": (
                RENDER_MIXED_TILING_PHYSICAL_QUEUE_INDEX
            ),
            "fragment_physical_queue_index": (
                RENDER_MIXED_FRAGMENT_PHYSICAL_QUEUE_INDEX
            ),
            "tiling_pointer": RENDER_MIXED_TILING_POINTER,
            "fragment_pointer": RENDER_MIXED_FRAGMENT_POINTER,
            "tiling_item_ring": RENDER_MIXED_TILING_ITEM_RING,
            "fragment_item_ring": RENDER_MIXED_FRAGMENT_ITEM_RING,
            "tiling_optional": RENDER_MIXED_TILING_OPTIONAL,
            "fragment_optional": RENDER_MIXED_FRAGMENT_OPTIONAL,
            "tiling_event": RENDER_MIXED_TILING_EVENT,
            "fragment_event": RENDER_MIXED_FRAGMENT_EVENT,
            "queue_indices": RENDER_MIXED_QUEUE_INDICES,
            "tiling_context_scratch": RENDER_MIXED_TILING_CONTEXT_SCRATCH,
            "tiling_firmware_scratch": (
                RENDER_MIXED_TILING_FIRMWARE_SCRATCH
            ),
            "fragment_context_scratch": (
                RENDER_MIXED_FRAGMENT_CONTEXT_SCRATCH
            ),
            "fragment_firmware_scratch": (
                RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH
            ),
            "shared_control": COMPUTE_PREDECESSOR_RENDER_SHARED_CONTROL,
            "tiling_status": COMPUTE_PREDECESSOR_RENDER_TILING_STATUS,
            "fragment_status": COMPUTE_PREDECESSOR_RENDER_FRAGMENT_STATUS,
            "tiling_register_status": (
                COMPUTE_PREDECESSOR_RENDER_TILING_REGISTER_STATUS
            ),
            "fragment_register_status": (
                COMPUTE_PREDECESSOR_RENDER_FRAGMENT_REGISTER_STATUS
            ),
            "resource_address_offset": RENDER_MIXED_RESOURCE_ADDRESS_OFFSET,
            "tiling_optional_pair_index": None,
            "tiling_work_index": None,
            "work_stamp_index": None,
            "optional_context_id": (
                COMPUTE_PREDECESSOR_RENDER_OPTIONAL_CONTEXT_ID
            ),
            "optional_secondary_context_id": 0,
            "scratch_context_id": 0,
            "descriptor_objects": (
                COMPUTE_PREDECESSOR_RENDER_DESCRIPTOR_OBJECTS
            ),
            "family": "compute_predecessor",
            "additive_global_pages": COMPUTE_TO_PARTIAL_RENDER_NEW_GLOBAL_PAGES,
        }
    if compute_publication_count == 1:
        return {
            "token": EARLIEST_MIXED_RENDER_TOKEN,
            "tiling_physical_queue_index": (
                RENDER_MIXED_TILING_PHYSICAL_QUEUE_INDEX
            ),
            "fragment_physical_queue_index": (
                RENDER_MIXED_FRAGMENT_PHYSICAL_QUEUE_INDEX
            ),
            "tiling_pointer": RENDER_MIXED_TILING_POINTER,
            "fragment_pointer": RENDER_MIXED_FRAGMENT_POINTER,
            "tiling_item_ring": RENDER_MIXED_TILING_ITEM_RING,
            "fragment_item_ring": RENDER_MIXED_FRAGMENT_ITEM_RING,
            "tiling_optional": RENDER_MIXED_TILING_OPTIONAL,
            "fragment_optional": RENDER_MIXED_FRAGMENT_OPTIONAL,
            "tiling_event": RENDER_MIXED_TILING_EVENT,
            "fragment_event": RENDER_MIXED_FRAGMENT_EVENT,
            "queue_indices": RENDER_MIXED_QUEUE_INDICES,
            "tiling_context_scratch": RENDER_MIXED_TILING_CONTEXT_SCRATCH,
            "tiling_firmware_scratch": RENDER_MIXED_TILING_FIRMWARE_SCRATCH,
            "fragment_context_scratch": (
                RENDER_MIXED_FRAGMENT_CONTEXT_SCRATCH
            ),
            "fragment_firmware_scratch": (
                RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH
            ),
            "shared_control": RENDER_MIXED_SHARED_CONTROL,
            "tiling_status": RENDER_MIXED_TILING_STATUS,
            "fragment_status": RENDER_MIXED_FRAGMENT_STATUS,
            "tiling_register_status": RENDER_MIXED_TILING_REGISTER_STATUS,
            "fragment_register_status": (
                RENDER_MIXED_FRAGMENT_REGISTER_STATUS
            ),
            "resource_address_offset": RENDER_MIXED_RESOURCE_ADDRESS_OFFSET,
            "tiling_optional_pair_index": None,
            "tiling_work_index": None,
            "work_stamp_index": None,
            "optional_context_id": RENDER_MIXED_CONTEXT_ID,
            "optional_secondary_context_id": None,
            "scratch_context_id": RENDER_MIXED_CONTEXT_ID,
            "descriptor_objects": RENDER_MIXED_DESCRIPTOR_OBJECTS,
            "family": "render_first",
            "additive_global_pages": (),
        }
    if compute_publication_count == 2:
        return {
            "token": RENDER_MIXED_TWO_TOKEN,
            "tiling_physical_queue_index": (
                RENDER_MIXED_TWO_TILING_PHYSICAL_QUEUE_INDEX
            ),
            "fragment_physical_queue_index": (
                RENDER_MIXED_TWO_FRAGMENT_PHYSICAL_QUEUE_INDEX
            ),
            "tiling_pointer": RENDER_MIXED_TWO_TILING_POINTER,
            "fragment_pointer": RENDER_MIXED_TWO_FRAGMENT_POINTER,
            "tiling_item_ring": RENDER_MIXED_TWO_TILING_ITEM_RING,
            "fragment_item_ring": RENDER_MIXED_TWO_FRAGMENT_ITEM_RING,
            "tiling_optional": RENDER_MIXED_TWO_TILING_OPTIONAL,
            "fragment_optional": RENDER_MIXED_TWO_FRAGMENT_OPTIONAL,
            "tiling_event": RENDER_MIXED_TWO_TILING_EVENT,
            "fragment_event": RENDER_MIXED_TWO_FRAGMENT_EVENT,
            "queue_indices": RENDER_MIXED_TWO_QUEUE_INDICES,
            "tiling_context_scratch": (
                RENDER_MIXED_TWO_TILING_CONTEXT_SCRATCH
            ),
            "tiling_firmware_scratch": (
                RENDER_MIXED_TWO_TILING_FIRMWARE_SCRATCH
            ),
            "fragment_context_scratch": (
                RENDER_MIXED_TWO_FRAGMENT_CONTEXT_SCRATCH
            ),
            "fragment_firmware_scratch": (
                RENDER_MIXED_TWO_FRAGMENT_FIRMWARE_SCRATCH
            ),
            "shared_control": RENDER_MIXED_TWO_SHARED_CONTROL,
            "tiling_status": RENDER_MIXED_TWO_TILING_STATUS,
            "fragment_status": RENDER_MIXED_TWO_FRAGMENT_STATUS,
            "tiling_register_status": (
                RENDER_MIXED_TWO_TILING_REGISTER_STATUS
            ),
            "fragment_register_status": (
                RENDER_MIXED_TWO_FRAGMENT_REGISTER_STATUS
            ),
            "resource_address_offset": (
                RENDER_MIXED_TWO_RESOURCE_ADDRESS_OFFSET
            ),
            "tiling_optional_pair_index": 0,
            "tiling_work_index": RENDER_MIXED_TWO_WORK_INDEX,
            "work_stamp_index": RENDER_MIXED_TWO_WORK_INDEX,
            "optional_context_id": RENDER_MIXED_CONTEXT_ID,
            "optional_secondary_context_id": None,
            "scratch_context_id": RENDER_MIXED_CONTEXT_ID,
            "descriptor_objects": RENDER_MIXED_DESCRIPTOR_OBJECTS,
            "family": "render_first_two_compute",
            "additive_global_pages": (),
        }
    raise ValueError(
        "coherent mixed render supports one or two compute publications"
    )


def _mixed_render_common_global_pages(package, layout=None):
    """Return mixed-render bodies for globals already present in the root."""
    layout = _mixed_render_layout() if layout is None else dict(layout)
    three_words = bytearray(package[0xFFFFFC20C08C0000])
    for offset in (0x00, 0x08, 0x10):
        value = struct.unpack_from("<I", three_words, offset)[0]
        struct.pack_into("<I", three_words, offset, value + 1)
    sequence = bytearray(package[0xFFFFFC20C08C8000])
    for offset in range(0, 0xC0, 4):
        value = struct.unpack_from("<I", sequence, offset)[0]
        struct.pack_into("<I", sequence, offset, value + 1)
    state = bytearray(PAGE_SIZE)
    state[0x00] = 3
    state[0x04] = 3
    state[0x60] = 1
    scheduler = bytearray(PAGE_SIZE)
    for index in range(g17g_postcontrol.ADDRESS_TABLE_COUNT):
        struct.pack_into(
            "<Q", scheduler, index * 0x100,
            COMPUTE_MIXED_SCHEDULER_SLOT + index * 4,
        )
    shared_zero = bytearray(PAGE_SIZE)
    struct.pack_into("<I", shared_zero, 0, 2)
    shared_control = g17g.build_opcode20_first_object(
        0x7200000000,
        0x7200408000,
        0xFFFFFC2001610000,
        cursor=0x78,
        resource_units=0x1A,
        word_08=1,
        word_10=2,
        word_60=3,
    )
    second_shared_control = None
    if layout["shared_control"] == RENDER_MIXED_TWO_SHARED_CONTROL:
        second_shared_control = g17g.build_opcode20_first_object(
            0x7201AA0000,
            0x7201EA8000,
            COMPUTE_MIXED_SHARED_STATE,
            word_00=2,
            cursor=0x78,
            resource_units=0x1A,
            word_08=1,
            word_10=2,
            word_60=3,
        )
    result = {
        COMPUTE_MIXED_SCHEDULER_SLOT:
            g17g_compute.build_compute_scheduler_slot(),
        0xFFFFFC2001610000: bytes(shared_zero),
        0xFFFFFC2001618000: bytes(PAGE_SIZE),
        0xFFFFFC2001630000: bytes(state),
        _page(COMPUTE_MIXED_SCHEDULER): bytes(scheduler),
        RENDER_MIXED_SHARED_CONTROL: shared_control,
        0xFFFFFC20C08C8000: _build_mixed_render_target_record_page(layout),
        0xFFFFFC20C08D0000: bytes(three_words),
        0xFFFFFC20C08D8000: bytes(sequence),
        0xFFFFFC20C08E8000: bytes(PAGE_SIZE),
    }
    if second_shared_control is not None:
        result[layout["shared_control"]] = second_shared_control
    return result


def _mixed_render_fresh_global_pages(package, layout=None):
    """Return the new high-half allocation pages in the coherent mixed root."""
    layout = _mixed_render_layout() if layout is None else dict(layout)
    if layout.get("family") == "compute_predecessor":
        three_words = bytearray(package[0xFFFFFC20C08C0000])
        for offset in (0x00, 0x08, 0x10):
            value = struct.unpack_from("<I", three_words, offset)[0]
            struct.pack_into("<I", three_words, offset, value + 1)
        sequence = bytearray(package[0xFFFFFC20C08C8000])
        for offset in range(0, 0xC0, 4):
            value = struct.unpack_from("<I", sequence, offset)[0]
            struct.pack_into("<I", sequence, offset, value + 1)
        small_state = bytearray(PAGE_SIZE)
        struct.pack_into("<Q", small_state, 0, 2)
        active_state = bytearray(PAGE_SIZE)
        struct.pack_into("<II", active_state, 0, 3, 3)
        struct.pack_into("<Q", active_state, 0x60, 1)
        pages = {
            address: bytes(PAGE_SIZE)
            for address in COMPUTE_TO_PARTIAL_RENDER_NEW_GLOBAL_PAGES
        }
        pages[0xFFFFFC2001618000] = bytes(small_state)
        pages[0xFFFFFC2001628000] = bytes(active_state)
        pages[0xFFFFFC2001638000] = b"\x01" + bytes(PAGE_SIZE - 1)
        pages[COMPUTE_PREDECESSOR_RENDER_SHARED_CONTROL] = (
            g17g.build_opcode20_first_object(
                0x7201AA0000,
                0x7201EA8000,
                0xFFFFFC2001618000,
                word_00=2,
                cursor=0x90,
                resource_units=0x24,
                word_08=1,
                word_10=2,
                word_60=3,
            )
        )
        pages[0xFFFFFC20C08C0000] = (
            _build_compute_predecessor_render_target_record_page()
        )
        pages[0xFFFFFC20C08C8000] = bytes(three_words)
        pages[0xFFFFFC20C08D0000] = bytes(sequence)
        if hashlib.sha256(pages[0xFFFFFC20C08D0000]).hexdigest() != (
                COMPUTE_PREDECESSOR_PARTIAL_ALLOCATION_INDEX_SHA256):
            raise ValueError("mixed partial allocation-index page changed")
        pages[COMPUTE_PREDECESSOR_RENDER_DESCRIPTOR_OBJECTS[1]] = (
            _build_compute_predecessor_render_trailing_descriptor_page(package)
        )
        if set(pages) != set(COMPUTE_TO_PARTIAL_RENDER_NEW_GLOBAL_PAGES):
            raise ValueError("compute-predecessor allocation family changed")
        return dict(sorted(pages.items()))
    scratch_bases = [layout["fragment_firmware_scratch"]]
    if layout["tiling_firmware_scratch"] != (
            RENDER_MIXED_TILING_FIRMWARE_SCRATCH):
        scratch_bases.append(layout["tiling_firmware_scratch"])
    pages = {
        base + index * PAGE_SIZE: bytes(PAGE_SIZE)
        for base in scratch_bases
        for index in range(RENDER_MIXED_SCRATCH_PAGE_COUNT)
    }
    pages.update({
        0xFFFFFC2001638000: bytes(PAGE_SIZE),
        0xFFFFFC2001640000: b"\x01" + bytes(PAGE_SIZE - 1),
        layout["fragment_status"]: bytes(PAGE_SIZE),
        RENDER_MIXED_DESCRIPTOR_OBJECTS[1]:
            _build_mixed_render_trailing_descriptor_page(package),
    })
    if layout["tiling_status"] != RENDER_MIXED_TILING_STATUS:
        pages[layout["tiling_status"]] = bytes(PAGE_SIZE)
    for address in (
            layout["fragment_pointer"], layout["fragment_item_ring"]):
        page = int(address) & ~(PAGE_SIZE - 1)
        if page not in (
                g17g_postcontrol.QUEUE_POINTER_PAGE,
                g17g_postcontrol.QUEUE_POINTER_PAGE + PAGE_SIZE,
                g17g_postcontrol.QUEUE_ITEM_RING_PAGE,
                g17g_postcontrol.QUEUE_ITEM_RING_PAGE + PAGE_SIZE):
            pages.setdefault(page, bytes(PAGE_SIZE))
    return dict(sorted(pages.items()))


def render_source_global_pages(
        token=RENDER_DEFAULT_TOKEN, mixed_compute_pending=False,
        compute_publication_count=1, compute_predecessor=False):
    """Build the already-decoded globals referenced by the first clear."""
    compute_publication_count = int(compute_publication_count)
    compute_predecessor = bool(compute_predecessor)
    if not mixed_compute_pending and compute_publication_count != 1:
        raise ValueError(
            "compute publication count requires a coherent mixed render"
        )
    layout = (
        _mixed_render_layout(compute_publication_count, compute_predecessor)
        if mixed_compute_pending else None
    )
    package = g17g_postcontrol.build_postcontrol_pages(int(token))
    required = {
        g17g_postcontrol.QUEUE_ADDRESS_10_PAGE,
        g17g_postcontrol.QUEUE_ADDRESS_70_PAGE,
        0xFFFFFC20001D8000,
        0xFFFFFC2000200000,
        0xFFFFFC2001610000,
        0xFFFFFC2001630000,
        0xFFFFFC20C08A8000,
        0xFFFFFC20C08B0000,
        0xFFFFFC20C08B8000,
        0xFFFFFC20C08E8000,
    }
    missing = required - set(package)
    if missing:
        raise ValueError(
            "source post-control package lacks render globals: %s"
            % ", ".join("%#x" % address for address in sorted(missing))
        )
    # The linked compute-post boundary already owns every common page.  Native
    # render admission adds a disjoint 32-page family and preserves those
    # live, firmware-mutated compute bodies byte-for-byte.
    if compute_predecessor:
        return {}
    result = {address: package[address] for address in sorted(required)}
    for address in COMPUTE_SOURCE_ZERO_GLOBAL_PAGES:
        result[address] = (
            build_compute_status_global_page()
            if address == _page(COMPUTE_GLOBAL_STATUS_A)
            else bytes(PAGE_SIZE)
        )
    if mixed_compute_pending:
        result.update(_mixed_render_common_global_pages(package, layout))
        job_list = bytearray(result[g17g_postcontrol.QUEUE_ADDRESS_10_PAGE])
        struct.pack_into("<Q", job_list, 0x20, COMPUTE_MIXED_JOB_LIST)
        result[g17g_postcontrol.QUEUE_ADDRESS_10_PAGE] = bytes(job_list)
        queue_aux = bytearray(result[g17g_postcontrol.QUEUE_ADDRESS_70_PAGE])
        for offset, value in (
            (0x40, 0x1000000FFFF),
            (0x60, 0x2000000000000),
            (0x70, 0xFF000000),
        ):
            struct.pack_into("<Q", queue_aux, offset, value)
        result[g17g_postcontrol.QUEUE_ADDRESS_70_PAGE] = bytes(queue_aux)
    return dict(sorted(result.items()))


def render_late_global_pages(
        mixed_compute_pending=False, compute_publication_count=1,
        compute_predecessor=False):
    """Build the two scratch pages required at the first-clear kick boundary."""
    if mixed_compute_pending:
        layout = _mixed_render_layout(
            compute_publication_count, compute_predecessor
        )
        return {
            layout["tiling_firmware_scratch"]:
                g17g_render.build_tiling_firmware_scratch_page(
                    queue_index=layout["queue_indices"][0],
                    queue_address=(
                        g17g_postcontrol.QUEUE_PAGE
                        + layout["tiling_physical_queue_index"]
                        * g17g.QUEUE_RECORD_STRIDE
                    ),
                    context_id=layout["scratch_context_id"],
                ),
            layout["fragment_firmware_scratch"]:
                g17g_render.build_fragment_firmware_scratch_page(
                    queue_index=layout["queue_indices"][1],
                    queue_address=(
                        g17g_postcontrol.QUEUE_PAGE
                        + layout["fragment_physical_queue_index"]
                        * g17g.QUEUE_RECORD_STRIDE
                    ),
                    context_id=layout["scratch_context_id"],
                ),
        }
    return {
        g17g_render.TILING_FIRMWARE_SCRATCH:
            g17g_render.build_tiling_firmware_scratch_page(),
        g17g_render.FRAGMENT_FIRMWARE_SCRATCH:
            g17g_render.build_fragment_firmware_scratch_page(),
    }


def _render_queue_pages(
        items, token, mixed_compute_pending=False,
        compute_publication_count=1, compute_predecessor=False):
    package = g17g_postcontrol.build_postcontrol_pages(int(token))

    if mixed_compute_pending:
        layout = _mixed_render_layout(
            compute_publication_count, compute_predecessor
        )
        queue = bytearray(PAGE_SIZE)
        for physical_index, pointers, item_ring in (
            (
                layout["tiling_physical_queue_index"],
                layout["tiling_pointer"],
                layout["tiling_item_ring"],
            ),
            (
                layout["fragment_physical_queue_index"],
                layout["fragment_pointer"],
                layout["fragment_item_ring"],
            ),
        ):
            record = g17g_compute.build_compute_queue_record(
                pointers,
                item_ring,
                g17g_postcontrol.QUEUE_ADDRESS_10_PAGE,
                g17g_postcontrol.QUEUE_ADDRESS_70_PAGE,
                int(token),
            )
            start = physical_index * g17g.QUEUE_RECORD_STRIDE
            queue[start:start + len(record)] = record

        if int(compute_publication_count) == 2 and not compute_predecessor:
            pointer_page = bytearray(PAGE_SIZE)
            pointer = g17g.build_pointer_block(field_40=3)
            tiling_pointer_offset = (
                layout["tiling_pointer"]
                - g17g_postcontrol.QUEUE_POINTER_PAGE
            )
            pointer_page[
                tiling_pointer_offset:tiling_pointer_offset + len(pointer)
            ] = pointer
            fragment_pointer = bytearray(PAGE_SIZE)
            fragment_pointer_offset = (
                layout["fragment_pointer"] & (PAGE_SIZE - 1)
            )
            fragment_pointer[
                fragment_pointer_offset:
                fragment_pointer_offset + len(pointer)
            ] = pointer

            item_ring_page = bytearray(PAGE_SIZE)
            tiling_item_offset = (
                layout["tiling_item_ring"]
                - g17g_postcontrol.QUEUE_ITEM_RING_PAGE
            )
            struct.pack_into(
                "<3Q", item_ring_page, tiling_item_offset,
                layout["tiling_optional"],
                RENDER_TILING_DESCRIPTOR_PAGE,
                layout["tiling_event"],
            )
            fragment_item_ring = bytearray(PAGE_SIZE)
            fragment_item_offset = (
                layout["fragment_item_ring"] & (PAGE_SIZE - 1)
            )
            struct.pack_into(
                "<3Q", fragment_item_ring, fragment_item_offset,
                layout["fragment_optional"],
                RENDER_FRAGMENT_DESCRIPTOR_PAGE,
                layout["fragment_event"],
            )

            optional = bytearray(PAGE_SIZE)
            for address, body in (
                (layout["fragment_optional"], items["fragment_optional"]),
                (layout["tiling_optional"], items["tiling_optional"]),
            ):
                offset = address - RENDER_OPTIONAL_PAGE
                optional[offset:offset + len(body)] = body
            event = bytearray(PAGE_SIZE)
            for address, body in (
                (layout["fragment_event"], items["fragment_event"]),
                (layout["tiling_event"], items["tiling_event"]),
            ):
                offset = address - RENDER_EVENT_PAGE
                event[offset:offset + len(body)] = body
            return {
                "queue": bytes(queue),
                "pointers": bytes(pointer_page),
                "fragment_pointers": bytes(fragment_pointer),
                "item_ring": bytes(item_ring_page),
                "fragment_item_ring": bytes(fragment_item_ring),
                "optional": bytes(optional),
                "event": bytes(event),
                "tiling_descriptor": _page_image(
                    items["tiling_descriptor"], "render tiling descriptor"
                ),
                "fragment_descriptor": _page_image(
                    items["fragment_descriptor"],
                    "render fragment descriptor",
                ),
            }

        pointer_span = bytearray(2 * PAGE_SIZE)
        pointer = g17g.build_pointer_block(field_40=3)
        tiling_pointer_offset = (
            RENDER_MIXED_TILING_POINTER
            - g17g_postcontrol.QUEUE_POINTER_PAGE
        )
        pointer_span[
            tiling_pointer_offset:tiling_pointer_offset + len(pointer)
        ] = pointer
        fragment_pointer_offset = (
            RENDER_MIXED_FRAGMENT_POINTER
            - g17g_postcontrol.QUEUE_POINTER_PAGE
        )
        pointer_span[
            fragment_pointer_offset:fragment_pointer_offset + len(pointer)
        ] = pointer

        item_ring_span = bytearray(2 * PAGE_SIZE)
        tiling_item_offset = (
            RENDER_MIXED_TILING_ITEM_RING
            - g17g_postcontrol.QUEUE_ITEM_RING_PAGE
        )
        struct.pack_into(
            "<3Q", item_ring_span, tiling_item_offset,
            RENDER_MIXED_TILING_OPTIONAL,
            RENDER_TILING_DESCRIPTOR_PAGE,
            RENDER_MIXED_TILING_EVENT,
        )
        fragment_item_offset = (
            RENDER_MIXED_FRAGMENT_ITEM_RING
            - g17g_postcontrol.QUEUE_ITEM_RING_PAGE
        )
        struct.pack_into(
            "<3Q", item_ring_span, fragment_item_offset,
            RENDER_MIXED_FRAGMENT_OPTIONAL,
            RENDER_FRAGMENT_DESCRIPTOR_PAGE,
            RENDER_MIXED_FRAGMENT_EVENT,
        )

        optional = bytearray(PAGE_SIZE)
        optional[0xC0:0xC0 + len(items["fragment_optional"])] = (
            items["fragment_optional"]
        )
        optional[0x180:0x180 + len(items["tiling_optional"])] = (
            items["tiling_optional"]
        )
        event = bytearray(PAGE_SIZE)
        event[0x40:0x40 + len(items["fragment_event"])] = (
            items["fragment_event"]
        )
        event[0x80:0x80 + len(items["tiling_event"])] = (
            items["tiling_event"]
        )
        return {
            "queue": bytes(queue),
            "pointers": bytes(pointer_span[:PAGE_SIZE]),
            "pointers_tail": bytes(pointer_span[PAGE_SIZE:]),
            "item_ring": bytes(item_ring_span[:PAGE_SIZE]),
            "item_ring_tail": bytes(item_ring_span[PAGE_SIZE:]),
            "optional": bytes(optional),
            "event": bytes(event),
            "tiling_descriptor": _page_image(
                items["tiling_descriptor"], "render tiling descriptor"
            ),
            "fragment_descriptor": _page_image(
                items["fragment_descriptor"], "render fragment descriptor"
            ),
        }

    queue = bytearray(package[g17g_postcontrol.QUEUE_PAGE])
    for index in range(2):
        record = g17g_compute.build_compute_queue_record(
            g17g_postcontrol.POINTER_BLOCK_ADDRESSES[index],
            g17g_postcontrol.ITEM_RING_ADDRESSES[index],
            g17g_postcontrol.QUEUE_ADDRESS_10_PAGE,
            g17g_postcontrol.QUEUE_ADDRESS_70_PAGE,
            int(token),
        )
        start = index * g17g.QUEUE_RECORD_STRIDE
        queue[start:start + len(record)] = record

    pointers = bytearray(package[g17g_postcontrol.QUEUE_POINTER_PAGE])
    pointer = g17g.build_pointer_block(field_40=3)
    pointers[:len(pointer)] = pointer
    pointers[0x2870:0x2870 + len(pointer)] = pointer

    item_ring = bytearray(package[g17g_postcontrol.QUEUE_ITEM_RING_PAGE])
    struct.pack_into(
        "<3Q", item_ring, 0,
        RENDER_OPTIONAL_PAGE + 0xC0,
        RENDER_TILING_DESCRIPTOR_PAGE,
        RENDER_EVENT_PAGE + 0x40,
    )
    struct.pack_into(
        "<3Q", item_ring, 0x2870,
        RENDER_OPTIONAL_PAGE,
        RENDER_FRAGMENT_DESCRIPTOR_PAGE,
        RENDER_EVENT_PAGE,
    )

    optional = bytearray(PAGE_SIZE)
    optional[0:len(items["fragment_optional"])] = items["fragment_optional"]
    optional[0xC0:0xC0 + len(items["tiling_optional"])] = (
        items["tiling_optional"]
    )
    event = bytearray(PAGE_SIZE)
    event[0:len(items["fragment_event"])] = items["fragment_event"]
    event[0x40:0x40 + len(items["tiling_event"])] = items["tiling_event"]

    return {
        "queue": bytes(queue),
        "pointers": bytes(pointers),
        "item_ring": bytes(item_ring),
        "optional": bytes(optional),
        "event": bytes(event),
        "tiling_descriptor": _page_image(
            items["tiling_descriptor"], "render tiling descriptor"
        ),
        "fragment_descriptor": _page_image(
            items["fragment_descriptor"], "render fragment descriptor"
        ),
    }


def _render_channel_patches(layout=None):
    """Build TA/fragment publication records without caller asset construction."""
    firmware_patches = {
        "channel_ring_6": ((
            RENDER_CHANNEL_RING_SLOT_OFFSETS[0],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[0], 0, 0x01000003
            ),
        ),),
        "channel_ring_7": ((
            RENDER_CHANNEL_RING_SLOT_OFFSETS[1],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[1], 1, 0x01010003
            ),
        ),),
        "state": tuple(
            (offset, struct.pack("<I12xI12xI", 0, 0, 1))
            for offset in RENDER_STATE_OFFSETS
        ),
    }
    if layout is not None:
        firmware_patches["channel_ring_6"] = ((
            RENDER_CHANNEL_RING_SLOT_OFFSETS[0],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_PAGE
                + layout["tiling_physical_queue_index"]
                * g17g.QUEUE_RECORD_STRIDE,
                0,
                0x01000003 | (layout["queue_indices"][0] << 16),
            ),
        ),)
        firmware_patches["channel_ring_7"] = ((
            RENDER_CHANNEL_RING_SLOT_OFFSETS[1],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_PAGE
                + layout["fragment_physical_queue_index"]
                * g17g.QUEUE_RECORD_STRIDE,
                1,
                0x01000003 | (layout["queue_indices"][1] << 16),
            ),
        ),)
    return firmware_patches


def build_render_transport(
        params, token=RENDER_DEFAULT_TOKEN, *, mixed_compute_pending=False,
        compute_publication_count=1, descriptor_sequence_bias=0,
        compute_predecessor=False):
    """Build only firmware transport for standalone or mixed TA/fragment work.

    Caller programs, resources, attachments and timestamp backing are opaque.
    The experiment fixture and the UAPI share this exact queue/descriptor and
    mixed allocation construction; neither path needs to create test assets
    to obtain firmware-owned state. Mapping and publication remain separate.
    """
    token = int(token)
    mixed_compute_pending = bool(mixed_compute_pending)
    compute_publication_count = int(compute_publication_count)
    compute_predecessor = bool(compute_predecessor)
    descriptor_sequence_bias = int(descriptor_sequence_bias)
    if not 0 <= descriptor_sequence_bias < (1 << 32):
        raise ValueError("render descriptor sequence bias must fit in uint32")
    if not mixed_compute_pending and compute_publication_count != 1:
        raise ValueError(
            "compute publication count requires a coherent mixed render"
        )
    layout = (
        _mixed_render_layout(compute_publication_count, compute_predecessor)
        if mixed_compute_pending else None
    )
    if mixed_compute_pending and token == RENDER_DEFAULT_TOKEN:
        token = layout["token"]
    if mixed_compute_pending and token != layout["token"]:
        raise ValueError(
            "coherent mixed render token must match the compute generation"
        )
    params.validate()
    if mixed_compute_pending:
        items = g17g_render.build_clear_work_items(
            params,
            token,
            submission_ordinal=1,
            optional_submission_ordinal=2,
            optional_first_record=True,
            optional_context_id=layout["optional_context_id"],
            optional_secondary_context_id=(
                layout["optional_secondary_context_id"]
            ),
            optional_lifecycle_ordinal=0,
            tiling_optional_pair_index=(
                layout["tiling_optional_pair_index"]
            ),
            tiling_work_index=layout["tiling_work_index"],
            work_stamp_index=layout["work_stamp_index"],
            queue_context_index=0,
            queue_indices=layout["queue_indices"],
            tiling_context_scratch=layout["tiling_context_scratch"],
            tiling_firmware_scratch=layout["tiling_firmware_scratch"],
            fragment_context_scratch=layout["fragment_context_scratch"],
            fragment_firmware_scratch=layout["fragment_firmware_scratch"],
            tiling_status_base=layout["tiling_status"],
            fragment_status_base=layout["fragment_status"],
            tiling_register_status_base=(
                layout["tiling_register_status"]
            ),
            fragment_register_status_base=(
                layout["fragment_register_status"]
            ),
            descriptor_objects=layout["descriptor_objects"],
            shared_control=layout["shared_control"],
            descriptor_resource_address_offset=(
                layout["resource_address_offset"]
            ),
            descriptor_context_id=RENDER_MIXED_CONTEXT_ID,
            descriptor_sequence_bias=descriptor_sequence_bias,
        )
    else:
        items = g17g_render.build_clear_work_items(
            params, token,
            descriptor_sequence_bias=descriptor_sequence_bias,
        )
    firmware_pages = _render_queue_pages(
        items, token, mixed_compute_pending=mixed_compute_pending,
        compute_publication_count=compute_publication_count,
        compute_predecessor=compute_predecessor,
    )
    firmware_addresses = {
        "queue": g17g_postcontrol.QUEUE_PAGE,
        "pointers": g17g_postcontrol.QUEUE_POINTER_PAGE,
        "item_ring": g17g_postcontrol.QUEUE_ITEM_RING_PAGE,
        "optional": RENDER_OPTIONAL_PAGE,
        "event": RENDER_EVENT_PAGE,
        "tiling_descriptor": RENDER_TILING_DESCRIPTOR_PAGE,
        "fragment_descriptor": RENDER_FRAGMENT_DESCRIPTOR_PAGE,
    }
    if mixed_compute_pending:
        if compute_publication_count == 1 or compute_predecessor:
            firmware_addresses.update({
                "pointers_tail": (
                    g17g_postcontrol.QUEUE_POINTER_PAGE + PAGE_SIZE
                ),
                "item_ring_tail": (
                    g17g_postcontrol.QUEUE_ITEM_RING_PAGE + PAGE_SIZE
                ),
            })
        else:
            firmware_addresses.update({
                "fragment_pointers": (
                    layout["fragment_pointer"] & ~(PAGE_SIZE - 1)
                ),
                "fragment_item_ring": (
                    layout["fragment_item_ring"] & ~(PAGE_SIZE - 1)
                ),
            })

    fresh_global_pages = {}
    fresh_global_page_flags = {}
    firmware_alias_extensions = {}
    if mixed_compute_pending:
        package = g17g_postcontrol.build_postcontrol_pages(token)
        fresh_global_pages.update(
            _mixed_render_fresh_global_pages(package, layout)
        )
        fresh_global_page_flags.update({
            address: "shared_uxn"
            for address in fresh_global_pages
            if address < g17g_postcontrol.QUEUE_PAGE
        })
        fresh_global_page_flags.update({
            address: "normal_uxn"
            for address in fresh_global_pages
            if address >= g17g_postcontrol.QUEUE_PAGE
        })
        if compute_predecessor:
            # The earliest native compute->partial boundary maps both stage
            # status leaves with the shared executable class.  Their bytes
            # already match; UXN is the only remaining PTE-class difference
            # in the complete 32-page additive family.
            for address in (
                layout["tiling_status"], layout["fragment_status"]
            ):
                if address not in fresh_global_pages:
                    raise ValueError(
                        "compute-predecessor status leaf is not fresh"
                    )
                fresh_global_page_flags[address] = "shared_executable"
        scratch_pairs = ((
            layout["fragment_context_scratch"],
            layout["fragment_firmware_scratch"],
        ),)
        if compute_predecessor or layout["tiling_firmware_scratch"] != (
                RENDER_MIXED_TILING_FIRMWARE_SCRATCH):
            scratch_pairs += ((
                layout["tiling_context_scratch"],
                layout["tiling_firmware_scratch"],
            ),)
        for low_base, high_base in scratch_pairs:
            for index in range(RENDER_MIXED_SCRATCH_PAGE_COUNT):
                firmware_alias_extensions[
                    low_base + index * PAGE_SIZE
                ] = high_base + index * PAGE_SIZE
    firmware_patches = _render_channel_patches(layout)
    return {
        "format": "m1n1-t8142-g17g-render-transport-v1",
        "submission_ready": True,
        "execution_validated": False,
        "captured_input": None,
        "channels": RENDER_CHANNELS,
        "token": token,
        "parameters": params,
        "items": items,
        "firmware_addresses": firmware_addresses,
        "firmware_pages": firmware_pages,
        "firmware_patch_addresses": {
            "channel_ring_6": RENDER_CHANNEL_RING_PAGES[0],
            "channel_ring_7": RENDER_CHANNEL_RING_PAGES[1],
            "state": RENDER_STATE_PAGE,
        },
        "firmware_patches": firmware_patches,
        "source_global_pages": render_source_global_pages(
            token,
            mixed_compute_pending=mixed_compute_pending,
            compute_publication_count=compute_publication_count,
            compute_predecessor=compute_predecessor,
        ),
        "late_global_pages": render_late_global_pages(
            mixed_compute_pending=mixed_compute_pending,
            compute_publication_count=compute_publication_count,
            compute_predecessor=compute_predecessor,
        ),
        "fresh_global_pages": dict(sorted(fresh_global_pages.items())),
        "fresh_global_page_flags": dict(
            sorted(fresh_global_page_flags.items())
        ),
        "firmware_alias_extensions": dict(
            sorted(firmware_alias_extensions.items())
        ),
        "compute_publication_count": compute_publication_count,
        "compute_predecessor_family": compute_predecessor,
        "firmware_live_preserve_ranges": (
            {
                "queue": ((0, g17g.QUEUE_RECORD_STRIDE),),
                "pointers": ((0, 0x2870),),
                "item_ring": ((0, 0x2870),),
                "optional": ((0, 0xC0),),
                "event": ((0, 0x40),),
            }
            if compute_predecessor else {}
        ),
        "missing_dependencies": {},
    }


def build_clear_render_products(
        params=None, token=RENDER_DEFAULT_TOKEN, zls_initial=None,
        mixed_compute_pending=False, compute_publication_count=1,
        descriptor_sequence_bias=0, compute_predecessor=False):
    """Add caller test assets to the independently built render transport."""
    if params is None:
        params = g17g_render.G17GClearRenderParameters(
            target_dva=0x10000018000,
            clear_state_page=0x10000110000,
            clear_rgba=(0x11, 0x22, 0x33, 0x44),
            store_pipeline=0x10000130400,
            load_pipeline=0x10000130200,
            auxiliary_object=0x10000248000,
            tiling_lifecycle=0xC6010000EB,
        )
    transport = build_render_transport(
        params, token, mixed_compute_pending=mixed_compute_pending,
        compute_publication_count=compute_publication_count,
        descriptor_sequence_bias=descriptor_sequence_bias,
        compute_predecessor=compute_predecessor)
    compute_publication_count = transport["compute_publication_count"]
    scissor = params.resolved_scissor_array()
    depth_bias = params.resolved_depth_bias_array()
    context1_writes = {
        g17g_render.RENDER_OPERAND_TABLE_DVA:
            g17g_render.build_render_operand_table(),
        g17g_render.RENDER_BASE10_SUPPORT_DVA:
            g17g_render.build_render_base10_support_page(),
        params.store_pipeline & ~(PAGE_SIZE - 1):
            g17g_render.build_clear_pipeline_page(
                params.store_pipeline & ~(PAGE_SIZE - 1),
                mixed_compute_publication_count=(
                    compute_publication_count
                ),
            ),
        params.target_dva & ~(PAGE_SIZE - 1): bytes(PAGE_SIZE),
        params.clear_state_page: g17g_render.build_clear_state_page(params),
        scissor: g17g_render.build_render_scissor_page(
            params.width, params.height
        ),
        depth_bias: bytes(PAGE_SIZE),
    }
    context1_writes.update(g17g_render.build_render_address_list_pages(
        operand_count=g17g_render.RENDER_SERVICE_INPUT_OPERAND_COUNT,
    ))
    context1_writes.update(g17g_render_compiler.build_clear_compiler_pages())
    if mixed_compute_pending:
        # Native's earliest dual-pending caller graph has already retired the
        # original placement-program leaf.  The render descriptors use the
        # relocated 0x10000148xxx program family, while compute admission
        # requires this retained writable leaf to be pristine.
        context1_writes[0x10000088000] = bytes(PAGE_SIZE)
        context1_writes[RENDER_MIXED_COMPUTE_ADMISSION_ZERO_DVA] = bytes(
            PAGE_SIZE
        )
        context1_writes.update(build_earliest_mixed_render_caller_pages(
            compute_publication_count
        ))
    for address in (
        0x100001C000,
        0x1000260000,
        0x1000288000,
        params.auxiliary_object,
    ):
        context1_writes.setdefault(address, bytes(PAGE_SIZE))

    if params.sampler_count:
        sampler_end = params.sampler_array + params.sampler_count * 8
        sampler_page = params.sampler_array & ~(PAGE_SIZE - 1)
        while sampler_page < sampler_end:
            if sampler_page in context1_writes:
                raise ValueError("G17G sampler heap overlaps render state")
            context1_writes[sampler_page] = bytes(PAGE_SIZE)
            sampler_page += PAGE_SIZE

    preserved_pages = []
    if params.occlusion_query_base:
        query_page = params.occlusion_query_base & ~(PAGE_SIZE - 1)
        if query_page in context1_writes:
            raise ValueError("G17G occlusion-query page overlaps render state")
        query_image = bytes((0xA5,)) * PAGE_SIZE
        context1_writes[query_page] = query_image
        preserved_pages.append({
            "name": "occlusion_query",
            "base": query_page,
            "size": PAGE_SIZE,
            "expected_sha256": hashlib.sha256(query_image).hexdigest(),
        })

    timestamp_outputs = []
    fresh_global_pages = dict(transport["fresh_global_pages"])
    for name, address in (
        ("tiling_start", params.tiling_user_timestamp_start),
        ("tiling_end", params.tiling_user_timestamp_end),
        ("fragment_start", params.fragment_user_timestamp_start),
        ("fragment_end", params.fragment_user_timestamp_end),
    ):
        address = int(address)
        if not address:
            continue
        page = address & ~(PAGE_SIZE - 1)
        if page != g17g_render.TIMESTAMP_APERTURE_BASE:
            raise ValueError(
                "G17G caller timestamps must use the hardware-data aperture"
            )
        fresh_global_pages.setdefault(page, bytes(PAGE_SIZE))
        timestamp_outputs.append({
            "name": name, "address": address, "space": "firmware",
        })

    zls_initial = {} if zls_initial is None else dict(zls_initial)
    unknown_zls_initial = set(zls_initial) - {"depth", "stencil"}
    if unknown_zls_initial:
        raise ValueError(
            "unknown G17G ZLS initial image(s): %s"
            % ", ".join(sorted(unknown_zls_initial))
        )
    zls_outputs = []
    pixel_count = params.width * params.height
    zls_plane_count = max(params.layers, params.samples)
    zls_size = PAGE_SIZE * zls_plane_count
    depth_clear = (
        struct.pack("<I", params.depth_clear_value_bits)
        * pixel_count * zls_plane_count
    )
    if params.layers > 1:
        stencil_plane = (
            bytes((params.stencil_clear_value,)) * pixel_count
            + bytes(PAGE_SIZE - pixel_count)
        )
        stencil_clear = stencil_plane * params.layers
    else:
        stencil_clear = (
            bytes((params.stencil_clear_value,))
            * pixel_count * params.samples
        )
    zls_specs = (
        (
            "depth", params.depth_buffer,
            g17g_render.ZLS_LOAD_DEPTH, g17g_render.ZLS_STORE_DEPTH,
            depth_clear,
        ),
        (
            "stencil", params.stencil_buffer,
            g17g_render.ZLS_LOAD_STENCIL, g17g_render.ZLS_STORE_STENCIL,
            stencil_clear,
        ),
    )
    for name, address, load_bit, store_bit, clear_prefix in zls_specs:
        if not address:
            if name in zls_initial:
                raise ValueError("G17G %s initial image has no buffer" % name)
            continue
        address = int(address)
        if address & (PAGE_SIZE - 1):
            raise ValueError("G17G %s buffer must be page aligned" % name)
        initial = bytes(zls_initial.get(name, bytes(zls_size)))
        if len(initial) != zls_size:
            raise ValueError(
                "G17G %s initial image must be %d bytes"
                % (name, zls_size)
            )
        if len(clear_prefix) > zls_size:
            raise ValueError("G17G %s image exceeds its ZLS extent" % name)
        for offset in range(0, zls_size, PAGE_SIZE):
            page = address + offset
            if page in context1_writes:
                raise ValueError("G17G %s buffer overlaps render state" % name)
            context1_writes[page] = initial[offset:offset + PAGE_SIZE]
        if params.depth_flags & store_bit:
            expected = (
                initial
                if params.depth_flags & load_bit else
                clear_prefix + bytes(zls_size - len(clear_prefix))
            )
            zls_outputs.append({
                "name": name,
                "base": address,
                "size": zls_size,
                "initial_sha256": hashlib.sha256(initial).hexdigest(),
                "expected_sha256": hashlib.sha256(expected).hexdigest(),
            })
    for name, address in (
        ("depth_aux", params.depth_aux_buffer),
        ("stencil_aux", params.stencil_aux_buffer),
    ):
        if not address:
            continue
        address = int(address)
        if address & (PAGE_SIZE - 1):
            raise ValueError("G17G %s buffer must be page aligned" % name)
        if address in context1_writes:
            raise ValueError("G17G %s buffer overlaps render state" % name)
        context1_writes[address] = bytes(PAGE_SIZE)

    return dict(transport,
        format="m1n1-t8142-g17g-host-clear-products-v1",
        context1_writes=dict(sorted(context1_writes.items())),
        fresh_global_pages=dict(sorted(fresh_global_pages.items())),
        timestamp_outputs=tuple(timestamp_outputs),
        zls_outputs=tuple(zls_outputs),
        preserved_pages=tuple(preserved_pages),
        expected_no_target_write=not params.process_empty_tiles)


def build_earliest_mixed_clear_render_products(
        target_dva=None, compute_dispatch_count=1,
        tiling_lifecycle=None, compute_publication_count=1):
    """Build the proven clear with the earliest mixed lifecycle identity."""
    compute_dispatch_count = int(compute_dispatch_count)
    compute_publication_count = int(compute_publication_count)
    _mixed_render_layout(compute_publication_count)
    if not 1 <= compute_dispatch_count <= COMPUTE_INITIAL_GRAPH_DISPATCH_LIMIT:
        raise ValueError("mixed compute dispatch count is out of range")
    baseline = build_clear_render_products()["parameters"]
    inferred_tiling_lifecycle = (
        RENDER_MIXED_TWO_LIFECYCLE
        if compute_publication_count == 2 else
        EARLIEST_MIXED_RENDER_LIFECYCLE
        + 3 * max(0, compute_dispatch_count - 9)
    )
    if tiling_lifecycle is None:
        tiling_lifecycle = inferred_tiling_lifecycle
    else:
        tiling_lifecycle = int(tiling_lifecycle)
        if not 0 <= tiling_lifecycle < (1 << 64):
            raise ValueError("mixed render lifecycle does not fit in u64")
    replacements = {
        "target_dva": (
            0x10000098000 if target_dva is None else int(target_dva)
        ),
        "clear_state_page": 0x10000128000,
        "store_pipeline": 0x10000148400,
        "load_pipeline": 0x10000148200,
        "auxiliary_object": 0x10000260000,
        # The source allocation family overprovisions its opening identity for
        # nine direct compute encoders.  Each later encoder allocates three
        # caller buffers before the render descriptor and therefore advances
        # the shared render lifecycle watermark by three.
        "tiling_lifecycle": tiling_lifecycle,
    }
    if compute_publication_count == 2:
        replacements.update({
            "tiling_timestamp_start": 0xFFFFFC2000024E58,
            "fragment_timestamp_start": 0xFFFFFC2000024E58,
            "fragment_timestamp_end": 0xFFFFFC2000024E60,
        })
    params = dataclasses.replace(baseline, **replacements)
    products = build_clear_render_products(
        params=params, mixed_compute_pending=True,
        compute_publication_count=compute_publication_count,
    )
    if int(params.target_dva) == 0x10000098000:
        # Earliest render-first mixed capture: the caller's retained
        # allocation moves the writable three-page state/target interval.
        # Keep this explicit instead of inferring permissions from content.
        products["context1_read_only_overrides"] = {
            0x10000018000: True,
            0x10000088000: False,
            0x1000008C000: False,
            0x10000098000: False,
            0x100000F8000: True,
        }
    products["format"] = (
        "m1n1-t8142-g17g-host-earliest-mixed-clear-products-v1"
    )
    return products


def build_partial_render_products(
        params=None, token=PARTIAL_RENDER_TOKEN, submission_count=1,
        direct_draw=None, direct_draws=None, operand_count=None,
        address_list_hole=False):
    """Build the earliest 128x128 eight-attachment partial-render graph.

    The six firmware work items and the address-list/operand topology are
    constructed field by field.  The remaining context pages are hash-gated
    caller-owned Metal compiler/resource products embedded in
    ``g17g_partial_assets``; no capture artifact is consulted at runtime.
    """
    token = int(token)
    submission_count = int(submission_count)
    if not 1 <= submission_count < (1 << 16):
        raise ValueError("G17G partial submission count must fit in positive u16")
    operand_count = (
        g17g_render.PARTIAL_RENDER_OPERAND_COUNT
        if operand_count is None else int(operand_count)
    )
    if not 0 <= operand_count <= g17g_render.PARTIAL_RENDER_OPERAND_COUNT:
        raise ValueError("G17G partial operand count is out of range")
    address_list_hole = bool(address_list_hole)
    if (
        address_list_hole
        and operand_count != g17g_render.PARTIAL_RENDER_OPERAND_COUNT
    ):
        raise ValueError(
            "G17G partial address-list hole requires the full operand pool"
        )
    if params is None:
        params = g17g_render.G17GClearRenderParameters(
            target_dva=PARTIAL_RENDER_ATTACHMENT_BASE,
            clear_state_page=0x100001B8000,
            clear_rgba=(0, 0, 0, 0),
            store_pipeline=0x100001E8400,
            load_pipeline=0x100001E8200,
            auxiliary_object=0x10000300000,
            tiling_lifecycle=0xCE010000F3,
            width=128,
            height=128,
            partial_load_pipeline=0x100001E8000,
            partial_store_pipeline=0x100001E8400,
            tib_bytes=32,
            aux_fb_flags=0x10C000,
            partial_mode=True,
        )
    params.validate()
    if not params.partial_mode:
        raise ValueError("G17G partial products require partial-mode parameters")
    if direct_draws is None:
        direct_draws = (
            g17g_encoder.G17GDirectDraw()
            if direct_draw is None else direct_draw,
        )
    else:
        if direct_draw is not None:
            raise ValueError("G17G partial direct draw inputs conflict")
        direct_draws = tuple(direct_draws)
    if not direct_draws:
        raise ValueError("G17G partial direct draw sequence is empty")
    for draw in direct_draws:
        if not isinstance(draw, g17g_encoder.G17GDirectDraw):
            raise TypeError("G17G partial direct draw parameters have wrong type")
        draw.validate()
    direct_draw = direct_draws[0]
    shared_state = (
        direct_draw.vertex_pipeline,
        direct_draw.viewport_width,
        direct_draw.viewport_height,
    )
    if any(
        (draw.vertex_pipeline, draw.viewport_width, draw.viewport_height)
        != shared_state for draw in direct_draws[1:]
    ):
        raise ValueError("G17G partial direct records must share bound state")
    full_render_area = (
        params.scissor_x == 0
        and params.scissor_y == 0
        and params.resolved_scissor_width() == params.width
        and params.resolved_scissor_height() == params.height
    )
    native_direct_draw = (
        len(direct_draws) == 1
        and full_render_area
        and direct_draw.vertex_start == 0
        and direct_draw.vertex_count
        == g17g_encoder.NATIVE_PARTIAL_VERTEX_COUNT
        and direct_draw.instance_count == 1
        and direct_draw.viewport_width == 128
        and direct_draw.viewport_height == 128
    )
    three_vertex_direct_draw = (
        len(direct_draws) == 1
        and full_render_area
        and direct_draw.vertex_start == 0
        and direct_draw.vertex_count == 3
        and direct_draw.instance_count == 1
        and direct_draw.viewport_width == 128
        and direct_draw.viewport_height == 128
    )
    five_hundred_thousand_triangle_draw = (
        len(direct_draws) == 1
        and full_render_area
        and direct_draw.vertex_start == 0
        and direct_draw.vertex_count == 1500000
        and direct_draw.instance_count == 1
        and direct_draw.viewport_width == 128
        and direct_draw.viewport_height == 128
    )
    scissor_64x64_three_vertex_direct_draw = (
        len(direct_draws) == 1
        and params.scissor_x == 0
        and params.scissor_y == 0
        and params.resolved_scissor_width() == 64
        and params.resolved_scissor_height() == 64
        and direct_draw.vertex_start == 0
        and direct_draw.vertex_count == 3
        and direct_draw.instance_count == 1
        and direct_draw.viewport_width == 128
        and direct_draw.viewport_height == 128
    )
    scissor_x64_three_vertex_direct_draw = (
        len(direct_draws) == 1
        and params.scissor_x == 64
        and params.scissor_y == 0
        and params.resolved_scissor_width() == 64
        and params.resolved_scissor_height() == 128
        and direct_draw.vertex_start == 0
        and direct_draw.vertex_count == 3
        and direct_draw.instance_count == 1
        and direct_draw.viewport_width == 128
        and direct_draw.viewport_height == 128
    )
    six_vertex_direct_draw = (
        len(direct_draws) == 1
        and full_render_area
        and direct_draw.vertex_start == 0
        and direct_draw.vertex_count * direct_draw.instance_count == 6
        and direct_draw.viewport_width == 128
        and direct_draw.viewport_height == 128
    )
    viewport_130x128_direct_draw = (
        len(direct_draws) == 1
        and full_render_area
        and direct_draw.vertex_start == 0
        and direct_draw.vertex_count == 3
        and direct_draw.instance_count == 1
        and direct_draw.viewport_width == 130
        and direct_draw.viewport_height == 128
    )
    two_three_vertex_direct_draws = (
        len(direct_draws) == 2
        and full_render_area
        and all(
            draw.vertex_start == 0
            and draw.vertex_count == 3
            and draw.instance_count == 1
            and draw.viewport_width == 128
            and draw.viewport_height == 128
            for draw in direct_draws
        )
    )
    sixty_four_three_vertex_direct_draws = (
        len(direct_draws) == 64
        and full_render_area
        and all(
            draw.vertex_start == 0
            and draw.vertex_count == 3
            and draw.instance_count == 1
            and draw.viewport_width == 128
            and draw.viewport_height == 128
            for draw in direct_draws
        )
    )
    if native_direct_draw:
        attachment_expectation = "exact-native"
        expected_attachment_hashes = PARTIAL_RENDER_EXPECTED_ATTACHMENT_SHA256
    elif three_vertex_direct_draw:
        attachment_expectation = "exact-direct"
        expected_attachment_hashes = (
            PARTIAL_RENDER_THREE_VERTEX_ATTACHMENT_SHA256
        )
    elif five_hundred_thousand_triangle_draw:
        attachment_expectation = "exact-direct"
        expected_attachment_hashes = PARTIAL_RENDER_500K_TRIANGLE_ATTACHMENT_SHA256
    elif scissor_64x64_three_vertex_direct_draw:
        attachment_expectation = "exact-direct"
        expected_attachment_hashes = (
            PARTIAL_RENDER_SCISSOR_64X64_THREE_VERTEX_ATTACHMENT_SHA256
        )
    elif scissor_x64_three_vertex_direct_draw:
        attachment_expectation = "exact-direct"
        expected_attachment_hashes = (
            PARTIAL_RENDER_SCISSOR_X64_THREE_VERTEX_ATTACHMENT_SHA256
        )
    elif six_vertex_direct_draw or two_three_vertex_direct_draws:
        attachment_expectation = "exact-direct"
        expected_attachment_hashes = (
            PARTIAL_RENDER_SIX_VERTEX_ATTACHMENT_SHA256
        )
    elif viewport_130x128_direct_draw:
        attachment_expectation = "exact-direct"
        expected_attachment_hashes = (
            PARTIAL_RENDER_VIEWPORT_130X128_ATTACHMENT_SHA256
        )
    elif sixty_four_three_vertex_direct_draws:
        attachment_expectation = "exact-direct"
        expected_attachment_hashes = (
            PARTIAL_RENDER_64_DIRECT_ATTACHMENT_SHA256
        )
    else:
        attachment_expectation = "changed"
        expected_attachment_hashes = None
    items = g17g_render.build_clear_work_items(params, token)
    firmware_pages = _render_queue_pages(items, token)
    firmware_addresses = {
        "queue": g17g_postcontrol.QUEUE_PAGE,
        "pointers": g17g_postcontrol.QUEUE_POINTER_PAGE,
        "item_ring": g17g_postcontrol.QUEUE_ITEM_RING_PAGE,
        "optional": RENDER_OPTIONAL_PAGE,
        "event": RENDER_EVENT_PAGE,
        "tiling_descriptor": RENDER_TILING_DESCRIPTOR_PAGE,
        "fragment_descriptor": RENDER_FRAGMENT_DESCRIPTOR_PAGE,
    }
    context1_writes = g17g_partial_assets.build_partial_context_pages()
    native_program_base = 0x100001E8000
    program_bases = {
        int(address) & ~(PAGE_SIZE - 1)
        for address in (
            params.load_pipeline,
            params.store_pipeline,
            params.resolved_partial_load_pipeline(),
            params.resolved_partial_store_pipeline(),
            *(draw.vertex_pipeline for draw in direct_draws),
        )
    }
    program_page = context1_writes[native_program_base]
    for program_base in program_bases - {native_program_base}:
        if (
            program_base in context1_writes
            or program_base + PAGE_SIZE in context1_writes
        ):
            raise ValueError("relocated partial program page overlaps state")
        context1_writes[program_base] = program_page
        # Native gives this compiler product a two-page mapping even though
        # only the first page contains host bytes.  Preserve that address-space
        # contract when the program is caller-relocated.
        context1_writes[program_base + PAGE_SIZE] = bytes(PAGE_SIZE)
    if native_program_base not in program_bases:
        del context1_writes[native_program_base]
    # The compact command page is now encoded from fields.  The embedded
    # native page remains only as an exact oracle proving that the source
    # encoder captures every meaningful and reserved byte.
    captured_vdm = context1_writes.pop(g17g_encoder.VDM_STREAM_DVA)
    native_vdm = g17g_encoder.validate_native_direct_vdm_page()
    if captured_vdm != native_vdm:
        raise ValueError("partial native VDM oracle changed")
    vdm_stream = g17g_encoder.build_direct_vdm_page(draws=direct_draws)[
        :g17g_encoder.direct_vdm_stream_size(len(direct_draws))
    ]
    vdm_stream_start = int(params.vdm_ctrl_stream_base)
    vdm_stream_end = vdm_stream_start + len(vdm_stream)
    vdm_stream_pages = []
    for target_page in range(
            vdm_stream_start & ~(PAGE_SIZE - 1),
            (vdm_stream_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1),
            PAGE_SIZE):
        if target_page in context1_writes:
            raise ValueError("relocated G17G VDM stream overlaps render state")
        page = bytearray(PAGE_SIZE)
        copy_start = max(vdm_stream_start, target_page)
        copy_end = min(vdm_stream_end, target_page + PAGE_SIZE)
        source_start = copy_start - vdm_stream_start
        page[copy_start - target_page:copy_end - target_page] = (
            vdm_stream[source_start:source_start + copy_end - copy_start]
        )
        context1_writes[target_page] = bytes(page)
        vdm_stream_pages.append(target_page)
    # All ten VDM bindings land in four compact pages.  Replace their embedded
    # native oracle images with explicit sparse state records as well.
    native_bound_pages = g17g_encoder.build_partial_bound_state_pages()
    source_bound_pages = g17g_encoder.build_partial_bound_state_pages(
        vertex_pipeline=direct_draw.vertex_pipeline,
        render_x=params.scissor_x,
        render_y=params.scissor_y,
        render_width=params.resolved_scissor_width(),
        render_height=params.resolved_scissor_height(),
        viewport_width=direct_draw.viewport_width,
        viewport_height=direct_draw.viewport_height,
    )
    for address, source_page in source_bound_pages.items():
        captured_page = context1_writes.pop(address)
        if captured_page != native_bound_pages[address]:
            raise ValueError(
                "partial bound-state oracle changed at %#x" % address
            )
        context1_writes[address] = source_page
    # Native supplied nonzero contents at these two writable mappings, but a
    # fresh-device bisection proved those bytes irrelevant: explicit zero
    # pages produce the exact same eight outputs.  Retain the mappings needed
    # by descriptor pointers without carrying incidental captured state.
    for address in PARTIAL_RENDER_FRESH_ZERO_RESOURCE_PAGES:
        if address in context1_writes:
            raise ValueError("partial fresh-zero resource is embedded")
        context1_writes[address] = bytes(PAGE_SIZE)
    # This caller DVA is one of the nine context-1 aliases of the shared
    # post-control package.  The native caller image and the source-built
    # high-half page are byte-identical; validate that invariant and let the
    # runtime preserve the alias instead of allocating a conflicting leaf.
    aliased_body = context1_writes.pop(PARTIAL_RENDER_POSTCONTROL_ALIAS_DVA)
    # The embedded image is an oracle for the native first-partial allocation,
    # not a requirement that every source-built queue reuse that generation.
    # The live alias below is always supplied by the caller-selected package.
    postcontrol_body = g17g_postcontrol.build_postcontrol_pages(
        PARTIAL_RENDER_TOKEN
    )[
        PARTIAL_RENDER_POSTCONTROL_ALIAS_HIGH
    ]
    if aliased_body != postcontrol_body:
        raise ValueError("partial post-control alias contents changed")
    context1_writes[g17g_render.RENDER_OPERAND_TABLE_DVA] = (
        g17g_render.build_render_operand_table(
            operand_count=operand_count
        )
    )
    address_list_pages = g17g_render.build_render_address_list_pages(
        operand_count=operand_count,
    )
    context1_writes.update(address_list_pages)
    if address_list_hole:
        first_address_list = g17g_render.RENDER_ADDRESS_LIST_PAGE_DVAS[0]
        if not any(address_list_pages[first_address_list]):
            raise ValueError("G17G partial address-list hole is already zero")
        context1_writes[first_address_list] = bytes(PAGE_SIZE)
    attachment_pages = []
    for attachment_index in range(PARTIAL_RENDER_ATTACHMENT_COUNT):
        base = (
            PARTIAL_RENDER_ATTACHMENT_BASE
            + attachment_index * PARTIAL_RENDER_ATTACHMENT_STRIDE
        )
        for offset in range(0, PARTIAL_RENDER_ATTACHMENT_SIZE, PAGE_SIZE):
            address = base + offset
            if address in context1_writes:
                raise ValueError(
                    "partial output overlaps caller asset at %#x" % address
                )
            context1_writes[address] = bytes(PAGE_SIZE)
            attachment_pages.append(address)

    firmware_patches = {
        "channel_ring_6": ((
            RENDER_CHANNEL_RING_SLOT_OFFSETS[0],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[0], 0, 0x01000003
            ),
        ),),
        "channel_ring_7": ((
            RENDER_CHANNEL_RING_SLOT_OFFSETS[1],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[1], 1, 0x01010003
            ),
        ),),
        "state": tuple(
            (offset, struct.pack("<I12xI12xI", 0, 0, 1))
            for offset in RENDER_STATE_OFFSETS
        ),
    }
    source_global_pages = render_source_global_pages(token)
    fresh_global_pages = {}
    descriptor_alias_extensions = {}
    if submission_count > 241:
        fresh_global_pages[
            RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_PAGE
        ] = bytes(PAGE_SIZE)
        descriptor_alias_extensions[
            RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_LOW_ALIAS
        ] = RENDER_FRAGMENT_DESCRIPTOR_EXTENSION_PAGE
    if submission_count > 242:
        fresh_global_pages[
            RENDER_TILING_DESCRIPTOR_EXTENSION_PAGE
        ] = bytes(PAGE_SIZE)
        descriptor_alias_extensions[
            RENDER_TILING_DESCRIPTOR_EXTENSION_LOW_ALIAS
        ] = RENDER_TILING_DESCRIPTOR_EXTENSION_PAGE
    active_identity_count = min(
        submission_count, g17g_render.RENDER_QUEUE_CONTEXT_ITEM_COUNT
    )
    queue_context_pages = {
        g17g_render.render_queue_context_item_offset(item_index) // PAGE_SIZE
        for item_index in range(active_identity_count)
    }
    for page_index in sorted(queue_context_pages - {0}):
        fresh_global_pages[
            g17g_render.TILING_FIRMWARE_SCRATCH + page_index * PAGE_SIZE
        ] = bytes(PAGE_SIZE)
    for page_index in sorted(
            queue_context_pages
            - set(range(RENDER_FRAGMENT_QUEUE_CONTEXT_NATIVE_PAGE_COUNT))):
        fresh_global_pages[
            g17g_render.FRAGMENT_FIRMWARE_SCRATCH
            + page_index * PAGE_SIZE
        ] = bytes(PAGE_SIZE)
    # The ordinary stream reuses the finite 256-record status namespace.  Keep
    # one additional record available for the established monotonic-status
    # discriminator without making a long stream allocate linearly growing,
    # unused status backing.
    active_status_count = min(
        submission_count, g17g_render.RENDER_SUBMISSION_COUNTER_COUNT + 1
    )
    highest_status_page = (active_status_count - 1) * 0x40 // PAGE_SIZE
    for status_base in (
        g17g_render.TILING_STATUS,
        g17g_render.FRAGMENT_STATUS,
    ):
        for page_index in range(1, highest_status_page + 1):
            fresh_global_pages[
                status_base + page_index * PAGE_SIZE
            ] = bytes(PAGE_SIZE)
    for status_base in (
        g17g_render.TILING_REGISTER_STATUS,
        g17g_render.FRAGMENT_REGISTER_STATUS,
    ):
        for page_index in range(1, highest_status_page + 1):
            address = status_base + page_index * PAGE_SIZE
            if address in context1_writes:
                raise ValueError(
                    "partial register-status extension overlaps caller data"
                )
            context1_writes[address] = bytes(PAGE_SIZE)
    return {
        "format": "m1n1-t8142-g17g-host-partial-render-products-v1",
        "submission_ready": True,
        "execution_validated": False,
        "captured_input": None,
        "partial_render": True,
        "operand_count": operand_count,
        "address_list_hole": (
            g17g_render.RENDER_ADDRESS_LIST_PAGE_DVAS[0]
            if address_list_hole else None
        ),
        "program_pages": tuple(sorted(program_bases)),
        "direct_draw": dataclasses.asdict(direct_draw),
        "direct_draws": tuple(
            dataclasses.asdict(draw) for draw in direct_draws
        ),
        "vdm_stream_base": vdm_stream_start,
        "vdm_stream_pages": tuple(vdm_stream_pages),
        "attachment_expectation": attachment_expectation,
        "channels": RENDER_CHANNELS,
        "token": token,
        "parameters": params,
        "items": items,
        "firmware_addresses": firmware_addresses,
        "firmware_pages": firmware_pages,
        "firmware_patch_addresses": {
            "channel_ring_6": RENDER_CHANNEL_RING_PAGES[0],
            "channel_ring_7": RENDER_CHANNEL_RING_PAGES[1],
            "state": RENDER_STATE_PAGE,
        },
        "firmware_patches": firmware_patches,
        "source_global_pages": source_global_pages,
        "fresh_global_pages": dict(sorted(fresh_global_pages.items())),
        "descriptor_alias_extensions": dict(
            sorted(descriptor_alias_extensions.items())
        ),
        "submission_count": submission_count,
        "late_global_pages": render_late_global_pages(),
        "context1_writes": dict(sorted(context1_writes.items())),
        "attachments": tuple(
            {
                "index": index,
                "base": (
                    PARTIAL_RENDER_ATTACHMENT_BASE
                    + index * PARTIAL_RENDER_ATTACHMENT_STRIDE
                ),
                "size": PARTIAL_RENDER_ATTACHMENT_SIZE,
                "expected_sha256": (
                    expected_attachment_hashes[index]
                    if expected_attachment_hashes is not None else None
                ),
            }
            for index in range(PARTIAL_RENDER_ATTACHMENT_COUNT)
        ),
        "attachment_pages": tuple(attachment_pages),
        "missing_dependencies": {},
    }


def build_earliest_mixed_partial_render_products(
        params=None, compute_dispatch_count=1,
        compute_publication_count=1, direct_draw=None, direct_draws=None,
        mixed_context_page_mask=0, compute_predecessor=False):
    """Build one partial render at the proven coherent compute boundary.

    Partial rendering changes the TA/3D command grammar and caller resources;
    it does not create a second firmware transport.  Keep the independently
    validated partial command graph, then place it in the same queue, scratch,
    service, and publication topology as the earliest mixed clear.
    """
    compute_dispatch_count = int(compute_dispatch_count)
    compute_publication_count = int(compute_publication_count)
    mixed_context_page_mask = int(mixed_context_page_mask)
    compute_predecessor = bool(compute_predecessor)
    if not 0 <= mixed_context_page_mask <= 3:
        raise ValueError("mixed partial context-page mask must be 0 through 3")
    layout = _mixed_render_layout(
        compute_publication_count, compute_predecessor
    )
    if not 1 <= compute_dispatch_count <= COMPUTE_INITIAL_GRAPH_DISPATCH_LIMIT:
        raise ValueError("mixed compute dispatch count is out of range")

    if params is None:
        params = build_partial_render_products()["parameters"]
    inferred_tiling_lifecycle = (
        COMPUTE_PREDECESSOR_RENDER_LIFECYCLE
        if compute_predecessor else
        RENDER_MIXED_TWO_LIFECYCLE
        if compute_publication_count == 2 else
        EARLIEST_MIXED_RENDER_LIFECYCLE
        + 3 * max(0, compute_dispatch_count - 9)
    )
    parameter_replacements = {
        "target_dva": MIXED_PARTIAL_RENDER_ATTACHMENT_BASE,
        "tiling_lifecycle": inferred_tiling_lifecycle,
    }
    if compute_predecessor:
        parameter_replacements.update({
            "store_pipeline": COMPUTE_PREDECESSOR_PARTIAL_STORE_PIPELINE,
            "load_pipeline": COMPUTE_PREDECESSOR_PARTIAL_LOAD_PIPELINE,
            "partial_load_pipeline": (
                COMPUTE_PREDECESSOR_PARTIAL_RELOAD_PIPELINE
            ),
            "partial_store_pipeline": (
                COMPUTE_PREDECESSOR_PARTIAL_STORE_PIPELINE
            ),
            "auxiliary_object": (
                COMPUTE_PREDECESSOR_PARTIAL_AUXILIARY_OBJECT
            ),
            "scissor_array": COMPUTE_PREDECESSOR_PARTIAL_SCISSOR_ARRAY,
            "depth_bias_array": (
                COMPUTE_PREDECESSOR_PARTIAL_DEPTH_BIAS_ARRAY
            ),
        })
        if direct_draw is None and direct_draws is None:
            direct_draw = g17g_encoder.G17GDirectDraw(
                vertex_pipeline=(
                    COMPUTE_PREDECESSOR_PARTIAL_VERTEX_PIPELINE
                )
            )
        elif (
            direct_draw is not None
            and direct_draw.vertex_pipeline
            == g17g_encoder.NATIVE_PARTIAL_VERTEX_PIPELINE
        ):
            direct_draw = dataclasses.replace(
                direct_draw,
                vertex_pipeline=(
                    COMPUTE_PREDECESSOR_PARTIAL_VERTEX_PIPELINE
                ),
            )
        elif direct_draws is not None:
            direct_draws = tuple(
                dataclasses.replace(
                    draw,
                    vertex_pipeline=(
                        COMPUTE_PREDECESSOR_PARTIAL_VERTEX_PIPELINE
                    ),
                )
                if draw.vertex_pipeline
                == g17g_encoder.NATIVE_PARTIAL_VERTEX_PIPELINE else draw
                for draw in direct_draws
            )
    params = dataclasses.replace(params, **parameter_replacements)
    products = build_partial_render_products(
        params=params,
        token=layout["token"],
        direct_draw=direct_draw,
        direct_draws=direct_draws,
    )
    old_attachment_base = PARTIAL_RENDER_ATTACHMENT_BASE
    new_attachment_base = MIXED_PARTIAL_RENDER_ATTACHMENT_BASE
    attachment_arena_end = (
        old_attachment_base
        + (PARTIAL_RENDER_ATTACHMENT_COUNT - 1)
        * PARTIAL_RENDER_ATTACHMENT_STRIDE
        + PARTIAL_RENDER_ATTACHMENT_SIZE
    )
    relocated_context1 = dict(products["context1_writes"])
    relocated_attachment_pages = []
    relocated_attachments = []
    attachment_bodies = {}
    for attachment in products["attachments"]:
        old_base = int(attachment["base"])
        for offset in range(0, int(attachment["size"]), PAGE_SIZE):
            attachment_bodies[old_base + offset] = (
                relocated_context1.pop(old_base + offset)
            )
    for attachment in products["attachments"]:
        old_base = int(attachment["base"])
        new_base = new_attachment_base + old_base - old_attachment_base
        relocated = dict(attachment)
        relocated["base"] = new_base
        relocated_attachments.append(relocated)
        for offset in range(0, int(attachment["size"]), PAGE_SIZE):
            body = attachment_bodies[old_base + offset]
            new_address = new_base + offset
            if new_address in relocated_context1:
                raise ValueError("mixed partial attachment relocation overlaps")
            relocated_context1[new_address] = body
            relocated_attachment_pages.append(new_address)

    relocated_pointer_count = 0
    for address, original in tuple(relocated_context1.items()):
        body = bytearray(original)
        changed = False
        for offset in range(0, len(body) - 7):
            value = struct.unpack_from("<Q", body, offset)[0]
            if old_attachment_base <= value < attachment_arena_end:
                struct.pack_into(
                    "<Q", body, offset,
                    new_attachment_base + value - old_attachment_base,
                )
                relocated_pointer_count += 1
                changed = True
        if changed:
            relocated_context1[address] = bytes(body)
    if relocated_pointer_count != 1:
        raise ValueError(
            "mixed partial attachment pointer topology changed: %d"
            % relocated_pointer_count
        )
    products.update({
        "parameters": params,
        "context1_writes": dict(sorted(relocated_context1.items())),
        "attachments": tuple(relocated_attachments),
        "attachment_pages": tuple(relocated_attachment_pages),
        "attachment_relocation": {
            "source_base": old_attachment_base,
            "target_base": new_attachment_base,
            "pointer_rewrite_count": relocated_pointer_count,
            "captured_input": None,
        },
    })
    mixed_transport = build_clear_render_products(
        params=params,
        token=layout["token"],
        mixed_compute_pending=True,
        compute_publication_count=compute_publication_count,
        descriptor_sequence_bias=1 if compute_predecessor else 0,
        compute_predecessor=compute_predecessor,
    )

    for key in (
        "items", "firmware_addresses", "firmware_pages",
        "firmware_patches", "source_global_pages", "late_global_pages",
        "fresh_global_pages", "fresh_global_page_flags",
        "firmware_alias_extensions", "firmware_live_preserve_ranges",
        "compute_predecessor_family",
    ):
        products[key] = mixed_transport[key]

    context1_writes = dict(products["context1_writes"])
    for address, body in mixed_transport["context1_writes"].items():
        context1_writes.setdefault(address, body)
    # These relocated pages are the publication-count-specific compiler
    # closure established by the ordinary mixed oracle.  They do not contain
    # the two render-context records below, so they compose directly with the
    # partial compiler/resource family.
    mixed_caller_pages = build_earliest_mixed_render_caller_pages(
        compute_publication_count
    )
    mixed_context_pages = (0x10000000000, 0x10000018000)
    for address, body in mixed_caller_pages.items():
        if (
            address not in mixed_context_pages
            or mixed_context_page_mask
            & (1 << mixed_context_pages.index(address))
        ):
            context1_writes[address] = body
    context1_writes[0x10000088000] = bytes(PAGE_SIZE)
    context1_writes[RENDER_MIXED_COMPUTE_ADMISSION_ZERO_DVA] = bytes(
        PAGE_SIZE
    )
    context1_extra_runs = ()
    if compute_predecessor:
        # The first partial render allocated after compute uses a new caller
        # operand family.  Its high shared-control object names these
        # relocated lists directly, so retaining the standalone addresses
        # leaves the objects it actually consumes zero-filled.
        standalone_address_lists = g17g_render.build_render_address_list_pages(
            operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT
        )
        for address in standalone_address_lists:
            context1_writes.pop(address, None)
        context1_writes.pop(g17g_render.RENDER_OPERAND_TABLE_DVA, None)
        context1_writes.update(
            g17g_render.build_render_address_list_pages(
                buffer_base=COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE,
                address_list_base=(
                    COMPUTE_PREDECESSOR_PARTIAL_ADDRESS_LIST_BASE
                ),
                operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT,
            )
        )
        context1_writes[COMPUTE_PREDECESSOR_PARTIAL_OPERAND_TABLE] = (
            g17g_render.build_render_operand_table(
                buffer_base=COMPUTE_PREDECESSOR_PARTIAL_OPERAND_BASE,
                operand_count=g17g_render.PARTIAL_RENDER_OPERAND_COUNT,
            )
        )
        # Metal allocated the fixed caller program after the compute
        # predecessor's existing compiler range.  Twenty-seven pages retain
        # their exact program bytes and move by one allocation interval.
        compiler_sources = tuple(
            COMPUTE_PREDECESSOR_PARTIAL_COMPILER_SOURCE_BASE
            + index * PAGE_SIZE
            for index in range(
                COMPUTE_PREDECESSOR_PARTIAL_COMPILER_PAGE_COUNT
            )
        )
        compiler_pages = {
            address: context1_writes[address]
            for address in compiler_sources
        }
        for address in compiler_sources:
            del context1_writes[address]
        for address, body in compiler_pages.items():
            context1_writes[
                address
                + COMPUTE_PREDECESSOR_PARTIAL_COMPILER_RELOCATION
            ] = body

        # The compute-first allocation preserves four old compiler mappings,
        # but clears their contents instead of unmapping them.  Its compact
        # allocation-index page is already the generated high post-control
        # page at 0xfffffc20c08d0000; the runtime retargets the canonical
        # context-1 alias at 0x1000240000 to that fresh physical page.
        for address in COMPUTE_PREDECESSOR_PARTIAL_ZERO_COMPILER_PAGES:
            context1_writes[address] = bytes(PAGE_SIZE)

        # Four dense pages are the fixed shader/compiler product and six
        # sparse pages are its first-work state bindings.  Keep this bounded
        # program asset separate from firmware/runtime state; all transport,
        # descriptors, address lists, operand tables, and mappings remain
        # field-built above.
        context1_writes.update(
            g17g_mixed_partial_assets.build_mixed_partial_context_pages()
        )
        context1_extra_runs = (
            COMPUTE_PREDECESSOR_PARTIAL_OPERAND_RUNS
            + COMPUTE_PREDECESSOR_PARTIAL_ZERO_RESERVATION_RUNS
            + COMPUTE_PREDECESSOR_PARTIAL_RETAINED_CONTEXT1_RUNS
        )
        products["context1_read_only_overrides"] = {
            base + index * PAGE_SIZE: read_only
            for base, page_count, read_only in (
                COMPUTE_PREDECESSOR_PARTIAL_PERMISSION_RUNS
            )
            for index in range(page_count)
        }
        excluded_dvas = tuple(sorted(
            base + index * PAGE_SIZE
            for base, page_count in (
                COMPUTE_PREDECESSOR_PARTIAL_RETIRED_CONTEXT1_RUNS
            )
            for index in range(page_count)
        ))
        for address in excluded_dvas:
            context1_writes.pop(address, None)
        # These low leaves use the fresh high objects as their backing.  Do
        # not publish a second low-side body; the only overlapping generated
        # image is the same all-zero fragment-status page.
        for address in COMPUTE_PREDECESSOR_PARTIAL_CONTEXT1_ALIASES:
            context1_writes.pop(address, None)
        products["context1_excluded_dvas"] = excluded_dvas
        # The clean first-work compute->partial capture already exposes these
        # two caller pages when compute is admitted.  Replay bisection proved
        # that publishing either page only with the later render graph is too
        # late: firmware retires both render queues but suppresses attachment
        # writes.  This is caller/compiler state, not captured firmware state.
        # Keep the early-publication contract explicit so every runtime uses
        # the same source product at the first context admission boundary.
        products["precompute_context1_writes"] = {
            g17g_render.RENDER_BASE10_SUPPORT_DVA:
                context1_writes[g17g_render.RENDER_BASE10_SUPPORT_DVA],
            0x10000018000:
                g17g_mixed_partial_native_tail.full_page(),
        }
    else:
        products["precompute_context1_writes"] = {}
    products.update({
        "format": (
            "m1n1-t8142-g17g-host-earliest-mixed-partial-products-v1"
        ),
        "mixed_compute_pending": True,
        "compute_predecessor": compute_predecessor,
        "compute_publication_count": compute_publication_count,
        "mixed_context_page_mask": mixed_context_page_mask,
        "context1_aliases": (
            dict(COMPUTE_PREDECESSOR_PARTIAL_CONTEXT1_ALIASES)
            if compute_predecessor else {}
        ),
        "context1_extra_runs": context1_extra_runs,
        "context1_writes": dict(sorted(context1_writes.items())),
    })
    return products


def build_compute_predecessor_partial_render_inter_epoch_qwords():
    """Build the eight source-owned RAM qwords at the mixed work boundary.

    These are the only changed common RAM qwords in the minimized native
    compute-post to partial-render-pre delta which are not part of a complete
    source page image.  Four belong to the allocation lifecycle and four are
    the populated portions of the TA/3D channel-ring slots.
    """
    channel_patches = _render_channel_patches(
        _mixed_render_layout(compute_predecessor=True))
    lifecycle = build_compute_predecessor_partial_render_work_lifecycle_qwords()
    result = {}

    for address, offsets in (
        (0xFFFFFC20015E8000, (0x00,)),
        (0xFFFFFC20015F0000, (0x20, 0x28, 0x30)),
    ):
        entries = {
            int(offset): int(after)
            for offset, _before, after in lifecycle[address]
        }
        for offset in offsets:
            result.setdefault(address, []).append((
                offset, entries[offset], "allocation-lifecycle",
            ))

    for name, address in zip(("channel_ring_6", "channel_ring_7"),
                             RENDER_CHANNEL_RING_PAGES):
        patches = channel_patches[name]
        if len(patches) != 1:
            raise ValueError("mixed predecessor must publish one %s slot" % name)
        slot_offset, slot = patches[0]
        if len(slot) != g17g.RING_SLOT_SIZE:
            raise ValueError("mixed predecessor %s slot has wrong size" % name)
        for relative_offset in (0x08, 0x10):
            result.setdefault(address, []).append((
                int(slot_offset) + relative_offset,
                struct.unpack_from("<Q", slot, relative_offset)[0],
                name,
            ))

    checked = {}
    for address, entries in sorted(result.items()):
        if address & (PAGE_SIZE - 1):
            raise ValueError("mixed inter-epoch page is unaligned")
        offsets = [offset for offset, _value, _label in entries]
        if len(offsets) != len(set(offsets)):
            raise ValueError("mixed inter-epoch qword is duplicated")
        if any(offset & 7 or not 0 <= offset <= PAGE_SIZE - 8
               for offset in offsets):
            raise ValueError("mixed inter-epoch qword is unaligned")
        checked[address] = tuple(sorted(entries))
    if sum(map(len, checked.values())) != 8:
        raise ValueError("mixed inter-epoch source closure must have 8 qwords")
    return checked


def build_compute_predecessor_partial_render_context0_aliases():
    """Build the two eight-page scratch aliases added for partial render."""
    aliases = {}
    for low_base, high_base in (
        (
            RENDER_MIXED_TILING_CONTEXT_SCRATCH,
            RENDER_MIXED_TILING_FIRMWARE_SCRATCH,
        ),
        (
            RENDER_MIXED_FRAGMENT_CONTEXT_SCRATCH,
            RENDER_MIXED_FRAGMENT_FIRMWARE_SCRATCH,
        ),
    ):
        for index in range(RENDER_MIXED_SCRATCH_PAGE_COUNT):
            aliases[low_base + index * PAGE_SIZE] = (
                high_base + index * PAGE_SIZE
            )
    if len(aliases) != 16 or len(set(aliases.values())) != 16:
        raise ValueError("mixed partial scratch alias topology changed")
    return dict(sorted(aliases.items()))


def build_prequeued_two_partial_render_products(
        params=None, token=PARTIAL_RENDER_TOKEN):
    """Build the earliest two-group partial-render discriminator.

    Both groups are visible before the first work kick.  Group one selects
    the one-byte-different ordinary-load resource and therefore produces the
    already validated collapsed output; group two selects the proper partial
    reload resource.  Exact final attachment hashes can consequently only be
    produced if item positions 3..5 execute after positions 0..2, without any
    post-first host lifecycle transition.
    """
    products = build_partial_render_products(params=params, token=token)
    exact = products["parameters"]
    collapsed = dataclasses.replace(
        exact, partial_load_pipeline=0x100001E8200
    )
    second = dataclasses.replace(
        exact,
        tiling_lifecycle=exact.tiling_lifecycle + (2 << 32) + 0x14,
    )
    first_items = g17g_render.build_clear_work_items(
        collapsed, int(token), submission_ordinal=1, event_group=1
    )
    second_items = g17g_render.build_clear_work_items(
        second, int(token), submission_ordinal=1, event_group=2
    )
    pages = {
        name: bytearray(body)
        for name, body in _render_queue_pages(first_items, int(token)).items()
    }
    for block_offset in (0, 0x2870):
        struct.pack_into(
            "<I", pages["pointers"],
            block_offset + g17g.POINTER_FIELD_40, 6,
        )
    struct.pack_into(
        "<3Q", pages["item_ring"], 3 * 8,
        RENDER_OPTIONAL_PAGE + 0x240,
        RENDER_TILING_DESCRIPTOR_PAGE + g17g_render.TILING_DESCRIPTOR_SIZE,
        RENDER_EVENT_PAGE + 0xC0,
    )
    struct.pack_into(
        "<3Q", pages["item_ring"], 0x2870 + 3 * 8,
        RENDER_OPTIONAL_PAGE + 0x180,
        RENDER_FRAGMENT_DESCRIPTOR_PAGE + g17g_render.FRAGMENT_DESCRIPTOR_SIZE,
        RENDER_EVENT_PAGE + 0x80,
    )
    pages["optional"][0x180:0x240] = second_items["fragment_optional"]
    pages["optional"][0x240:0x300] = second_items["tiling_optional"]
    pages["event"][0x80:0xC0] = second_items["fragment_event"]
    pages["event"][0xC0:0x100] = second_items["tiling_event"]
    tiling_offset = g17g_render.TILING_DESCRIPTOR_SIZE
    fragment_offset = g17g_render.FRAGMENT_DESCRIPTOR_SIZE
    pages["tiling_descriptor"][
        tiling_offset:tiling_offset + g17g_render.TILING_DESCRIPTOR_SIZE
    ] = second_items["tiling_descriptor"]
    pages["fragment_descriptor"][
        fragment_offset:fragment_offset + g17g_render.FRAGMENT_DESCRIPTOR_SIZE
    ] = second_items["fragment_descriptor"]
    products["firmware_pages"] = {
        name: bytes(body) for name, body in pages.items()
    }

    patches = {
        name: tuple(entries)
        for name, entries in products["firmware_patches"].items()
    }
    for index, name in enumerate(("channel_ring_6", "channel_ring_7")):
        slot_offset = RENDER_CHANNEL_RING_SLOT_OFFSETS[index]
        patches[name] = (
            (
                slot_offset,
                g17g.build_ring_slot(
                    g17g_postcontrol.QUEUE_ADDRESSES[index],
                    index,
                    0x01000003 | (index << 16),
                ),
            ),
            (
                slot_offset + g17g.RING_SLOT_SIZE,
                g17g.build_ring_slot(
                    g17g_postcontrol.QUEUE_ADDRESSES[index],
                    index,
                    0x01000006 | (index << 16),
                ),
            ),
        )
    patches["state"] = tuple(
        (offset, struct.pack("<I12xI12xI", 0, 0, 2))
        for offset in RENDER_STATE_OFFSETS
    )
    products["firmware_patches"] = patches

    late_pages = {
        address: bytearray(body)
        for address, body in products["late_global_pages"].items()
    }
    queue_item_offset = (
        g17g_render.RENDER_QUEUE_CONTEXT_ITEM_BASE
        + g17g_render.RENDER_QUEUE_CONTEXT_ITEM_SIZE
    )
    for kind, address, descriptor in (
        (
            "tiling", g17g_render.TILING_FIRMWARE_SCRATCH,
            RENDER_TILING_DESCRIPTOR_PAGE + g17g_render.TILING_DESCRIPTOR_SIZE,
        ),
        (
            "fragment", g17g_render.FRAGMENT_FIRMWARE_SCRATCH,
            RENDER_FRAGMENT_DESCRIPTOR_PAGE
            + g17g_render.FRAGMENT_DESCRIPTOR_SIZE,
        ),
    ):
        item = g17g_render.build_render_queue_context_item(
            kind, descriptor, item_index=1
        )
        late_pages[address][
            queue_item_offset:queue_item_offset + len(item)
        ] = item
    products["late_global_pages"] = {
        address: bytes(body) for address, body in late_pages.items()
    }
    products["format"] = (
        "m1n1-t8142-g17g-host-two-partial-render-products-v1"
    )
    products["parameters"] = collapsed
    products["items"] = first_items
    products["prequeued_group_count"] = 2
    products["prequeued_item_limit"] = 6
    products["final_parameters"] = second
    products["second_items"] = second_items
    products["prequeued_partial_negative_then_positive"] = True
    return products


def build_prequeued_two_clear_render_products(
        params=None, token=RENDER_DEFAULT_TOKEN, second_params=None):
    """Build two first-generation clear groups visible at the first kick.

    This is a deliberately early-state discriminator.  Both groups use the
    already validated generation-one queue token and are present before the
    first work notification, so no post-first service or allocator state is
    involved.  They share the target but use distinct clear-state pages; the
    second color in the final target is therefore an execution witness for
    consumption of item indices 3..5, not merely the known-working first
    group.
    """
    products = build_clear_render_products(params=params, token=token)
    first = products["parameters"]
    second = (
        g17g_render.G17GClearRenderParameters(
            target_dva=first.target_dva,
            clear_state_page=first.clear_state_page + PAGE_SIZE,
            clear_rgba=(0x55, 0x66, 0x77, 0x88),
            store_pipeline=first.store_pipeline,
            load_pipeline=first.load_pipeline,
            auxiliary_object=first.auxiliary_object,
            tiling_lifecycle=first.tiling_lifecycle + (2 << 32) + 0x14,
            width=first.width,
            height=first.height,
        )
        if second_params is None else second_params
    )
    second.validate()
    if second.target_dva != first.target_dva:
        raise ValueError("prequeued clears must share one target DVA")
    if second.clear_state_page == first.clear_state_page:
        raise ValueError("prequeued clears require distinct clear-state pages")
    second_items = g17g_render.build_clear_work_items(
        second,
        int(token),
        submission_ordinal=1,
        event_group=2,
    )

    pages = {
        name: bytearray(body)
        for name, body in products["firmware_pages"].items()
    }
    for block_offset in (0, 0x2870):
        struct.pack_into(
            "<I", pages["pointers"],
            block_offset + g17g.POINTER_FIELD_40, 6,
        )
    struct.pack_into(
        "<3Q", pages["item_ring"], 3 * 8,
        RENDER_OPTIONAL_PAGE + 0x240,
        RENDER_TILING_DESCRIPTOR_PAGE + g17g_render.TILING_DESCRIPTOR_SIZE,
        RENDER_EVENT_PAGE + 0xC0,
    )
    struct.pack_into(
        "<3Q", pages["item_ring"], 0x2870 + 3 * 8,
        RENDER_OPTIONAL_PAGE + 0x180,
        RENDER_FRAGMENT_DESCRIPTOR_PAGE + g17g_render.FRAGMENT_DESCRIPTOR_SIZE,
        RENDER_EVENT_PAGE + 0x80,
    )
    pages["optional"][0x180:0x240] = second_items["fragment_optional"]
    pages["optional"][0x240:0x300] = second_items["tiling_optional"]
    pages["event"][0x80:0xC0] = second_items["fragment_event"]
    pages["event"][0xC0:0x100] = second_items["tiling_event"]
    tiling_offset = g17g_render.TILING_DESCRIPTOR_SIZE
    fragment_offset = g17g_render.FRAGMENT_DESCRIPTOR_SIZE
    pages["tiling_descriptor"][
        tiling_offset:tiling_offset + g17g_render.TILING_DESCRIPTOR_SIZE
    ] = second_items["tiling_descriptor"]
    pages["fragment_descriptor"][
        fragment_offset:fragment_offset + g17g_render.FRAGMENT_DESCRIPTOR_SIZE
    ] = second_items["fragment_descriptor"]
    products["firmware_pages"] = {
        name: bytes(body) for name, body in pages.items()
    }

    patches = {
        name: tuple(entries)
        for name, entries in products["firmware_patches"].items()
    }
    patches["channel_ring_6"] = (
        (
            RENDER_CHANNEL_RING_SLOT_OFFSETS[0],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[0], 0, 0x01000003
            ),
        ),
        (
            RENDER_CHANNEL_RING_SLOT_OFFSETS[0] + g17g.RING_SLOT_SIZE,
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[0], 0, 0x01000006
            ),
        ),
    )
    patches["channel_ring_7"] = (
        (
            RENDER_CHANNEL_RING_SLOT_OFFSETS[1],
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[1], 1, 0x01010003
            ),
        ),
        (
            RENDER_CHANNEL_RING_SLOT_OFFSETS[1] + g17g.RING_SLOT_SIZE,
            g17g.build_ring_slot(
                g17g_postcontrol.QUEUE_ADDRESSES[1], 1, 0x01010006
            ),
        ),
    )
    patches["state"] = tuple(
        (offset, struct.pack("<I12xI12xI", 0, 0, 2))
        for offset in RENDER_STATE_OFFSETS
    )
    products["firmware_patches"] = patches

    late_pages = {
        address: bytearray(body)
        for address, body in products["late_global_pages"].items()
    }
    for kind, address, descriptor in (
        (
            "tiling", g17g_render.TILING_FIRMWARE_SCRATCH,
            RENDER_TILING_DESCRIPTOR_PAGE + g17g_render.TILING_DESCRIPTOR_SIZE,
        ),
        (
            "fragment", g17g_render.FRAGMENT_FIRMWARE_SCRATCH,
            RENDER_FRAGMENT_DESCRIPTOR_PAGE
            + g17g_render.FRAGMENT_DESCRIPTOR_SIZE,
        ),
    ):
        offset = (
            g17g_render.RENDER_QUEUE_CONTEXT_ITEM_BASE
            + g17g_render.RENDER_QUEUE_CONTEXT_ITEM_SIZE
        )
        item = g17g_render.build_render_queue_context_item(
            kind, descriptor, item_index=1
        )
        late_pages[address][offset:offset + len(item)] = item
    products["late_global_pages"] = {
        address: bytes(body) for address, body in late_pages.items()
    }

    context1_writes = dict(products["context1_writes"])
    if second.clear_state_page in context1_writes:
        raise ValueError("prequeued second clear-state page is already occupied")
    context1_writes[second.clear_state_page] = (
        g17g_render.build_clear_state_page(second)
    )
    products["context1_writes"] = dict(sorted(context1_writes.items()))
    products["format"] = "m1n1-t8142-g17g-host-two-clear-products-v1"
    products["prequeued_group_count"] = 2
    products["prequeued_item_limit"] = 6
    products["final_parameters"] = second
    products["second_items"] = second_items
    return products


def build_prequeued_compressed_zls_roundtrip_products(
        token=RENDER_DEFAULT_TOKEN, decompress=True):
    """Build compressed-store then compressed-load/ordinary-store groups.

    Both groups are visible at the first work kick.  The final ordinary depth
    and stencil bytes are exact semantic witnesses for the compressed-load
    path, while both independent metadata pages must change from zero.
    """
    baseline = build_clear_render_products()["parameters"]
    dimensions = g17g_render.encode_zls_dimensions(
        baseline.width, baseline.height
    )
    depth_bits = struct.unpack("<I", struct.pack("<f", 0.25))[0]
    compressed_store = (
        g17g_render.ZLS_STORE_DEPTH
        | g17g_render.ZLS_STORE_STENCIL
        | g17g_render.ZLS_STORE_DEPTH_COMPRESSED
        | g17g_render.ZLS_STORE_STENCIL_COMPRESSED
    )
    decompress_flags = (
        g17g_render.ZLS_LOAD_DEPTH
        | g17g_render.ZLS_LOAD_STENCIL
        | g17g_render.ZLS_STORE_DEPTH
        | g17g_render.ZLS_STORE_STENCIL
        | g17g_render.ZLS_LOAD_DEPTH_COMPRESSED
        | g17g_render.ZLS_LOAD_STENCIL_COMPRESSED
    )
    first = dataclasses.replace(
        baseline,
        depth_buffer=RENDER_ZLS_DEPTH_DVA,
        stencil_buffer=RENDER_ZLS_STENCIL_DVA,
        depth_aux_buffer=RENDER_ZLS_DEPTH_AUX_DVA,
        stencil_aux_buffer=RENDER_ZLS_STENCIL_AUX_DVA,
        depth_clear_value_bits=depth_bits,
        stencil_clear_value=0x5A,
        depth_flags=compressed_store,
        depth_dimensions=dimensions,
    )
    second = dataclasses.replace(
        first,
        clear_state_page=first.clear_state_page + PAGE_SIZE,
        clear_rgba=(0x55, 0x66, 0x77, 0x88),
        tiling_lifecycle=first.tiling_lifecycle + (2 << 32) + 0x14,
        depth_clear_value_bits=struct.unpack(
            "<I", struct.pack("<f", 0.875)
        )[0],
        stencil_clear_value=0xE1,
        depth_flags=decompress_flags if decompress else 0,
        depth_buffer=(first.depth_buffer if decompress else 0),
        stencil_buffer=(first.stencil_buffer if decompress else 0),
        depth_aux_buffer=(first.depth_aux_buffer if decompress else 0),
        stencil_aux_buffer=(first.stencil_aux_buffer if decompress else 0),
        depth_dimensions=(first.depth_dimensions if decompress else 0),
    )
    products = build_prequeued_two_clear_render_products(
        params=first, token=token, second_params=second
    )
    zero_sha256 = hashlib.sha256(bytes(PAGE_SIZE)).hexdigest()
    pixel_count = first.width * first.height
    expected_depth = struct.pack("<I", depth_bits) * pixel_count
    expected_stencil = (
        bytes((0x5A,)) * pixel_count
        + bytes(PAGE_SIZE - pixel_count)
    )
    products["zls_outputs"] = (
        {
            "name": "depth",
            "base": RENDER_ZLS_DEPTH_DVA,
            "size": PAGE_SIZE,
            "initial_sha256": zero_sha256,
            "expected_sha256": (
                hashlib.sha256(expected_depth).hexdigest()
                if decompress else None
            ),
            "require_changed": True,
        },
        {
            "name": "stencil",
            "base": RENDER_ZLS_STENCIL_DVA,
            "size": PAGE_SIZE,
            "initial_sha256": zero_sha256,
            "expected_sha256": (
                hashlib.sha256(expected_stencil).hexdigest()
                if decompress else None
            ),
            "require_changed": True,
        },
        {
            "name": "depth_aux",
            "base": RENDER_ZLS_DEPTH_AUX_DVA,
            "size": PAGE_SIZE,
            "initial_sha256": zero_sha256,
            "expected_sha256": None,
            "require_changed": True,
        },
        {
            "name": "stencil_aux",
            "base": RENDER_ZLS_STENCIL_AUX_DVA,
            "size": PAGE_SIZE,
            "initial_sha256": zero_sha256,
            "expected_sha256": None,
            "require_changed": True,
        },
    )
    products["format"] = (
        "m1n1-t8142-g17g-host-compressed-zls-roundtrip-products-v1"
    )
    products["compressed_zls_roundtrip"] = {
        "compressed_store_flags": compressed_store,
        "decompress_flags": second.depth_flags,
        "decompress_enabled": bool(decompress),
    }
    return products


def build_sequential_compressed_zls_roundtrip_products(
        token=RENDER_DEFAULT_TOKEN, decompress=True):
    """Build compressed store and a later persistent-queue render group."""
    products = build_compressed_zls_store_products("both", token=token)
    first = products["parameters"]
    baseline = build_clear_render_products()["parameters"]
    decompress_flags = (
        g17g_render.ZLS_LOAD_DEPTH
        | g17g_render.ZLS_LOAD_STENCIL
        | g17g_render.ZLS_STORE_DEPTH
        | g17g_render.ZLS_STORE_STENCIL
        | g17g_render.ZLS_LOAD_DEPTH_COMPRESSED
        | g17g_render.ZLS_LOAD_STENCIL_COMPRESSED
    )
    if decompress:
        second = dataclasses.replace(
            first,
            clear_state_page=first.clear_state_page,
            clear_rgba=(0x55, 0x66, 0x77, 0x88),
            tiling_lifecycle=first.tiling_lifecycle + (2 << 32) + 0x18,
            depth_clear_value_bits=struct.unpack(
                "<I", struct.pack("<f", 0.875)
            )[0],
            stencil_clear_value=0xE1,
            depth_flags=decompress_flags,
        )
    else:
        second = g17g_render.G17GClearRenderParameters(
            target_dva=first.target_dva,
            clear_state_page=first.clear_state_page,
            clear_rgba=(0x55, 0x66, 0x77, 0x88),
            store_pipeline=baseline.store_pipeline,
            load_pipeline=baseline.load_pipeline,
            auxiliary_object=baseline.auxiliary_object,
            tiling_lifecycle=first.tiling_lifecycle + (2 << 32) + 0x18,
            width=first.width,
            height=first.height,
        )
    second.validate()
    context1_writes = dict(products["context1_writes"])
    if second.clear_state_page not in context1_writes:
        context1_writes[second.clear_state_page] = (
            g17g_render.build_clear_state_page(second)
        )
    products["context1_writes"] = dict(sorted(context1_writes.items()))
    if decompress:
        pixel_count = first.width * first.height
        expected = {
            "depth": hashlib.sha256(
                struct.pack("<I", first.depth_clear_value_bits) * pixel_count
            ).hexdigest(),
            "stencil": hashlib.sha256(
                bytes((first.stencil_clear_value,)) * pixel_count
                + bytes(PAGE_SIZE - pixel_count)
            ).hexdigest(),
        }
        products["zls_outputs"] = tuple(
            {
                **item,
                "expected_sha256": expected.get(item["name"]),
            }
            for item in products["zls_outputs"]
        )
    products["repeat_parameters"] = second
    products["snapshot_zls_before_repeat"] = True
    products["format"] = (
        "m1n1-t8142-g17g-host-sequential-compressed-zls-roundtrip-products-v2"
    )
    products["compressed_zls_roundtrip"] = {
        "compressed_store_flags": first.depth_flags,
        "decompress_flags": second.depth_flags,
        "decompress_enabled": bool(decompress),
        "ordering": "exact first retirement then persistent-queue group two",
        "clear_state_policy": "retain registered first object",
        "first_boundary_snapshot": True,
        "first_boundary_republication": False,
    }
    return products


def build_sequential_uncompressed_zls_repeat_products(
        token=RENDER_DEFAULT_TOKEN):
    """Build an uncompressed ZLS store followed by an ordinary clear."""
    baseline = build_clear_render_products()["parameters"]
    first = dataclasses.replace(
        baseline,
        depth_buffer=RENDER_ZLS_DEPTH_DVA,
        stencil_buffer=RENDER_ZLS_STENCIL_DVA,
        depth_clear_value_bits=struct.unpack(
            "<I", struct.pack("<f", 0.25)
        )[0],
        stencil_clear_value=0x5A,
        depth_flags=(
            g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL
        ),
        depth_dimensions=g17g_render.encode_zls_dimensions(
            baseline.width, baseline.height
        ),
    )
    products = build_clear_render_products(first, token)
    second = g17g_render.G17GClearRenderParameters(
        target_dva=first.target_dva,
        clear_state_page=first.clear_state_page,
        clear_rgba=(0x55, 0x66, 0x77, 0x88),
        store_pipeline=baseline.store_pipeline,
        load_pipeline=baseline.load_pipeline,
        auxiliary_object=baseline.auxiliary_object,
        tiling_lifecycle=first.tiling_lifecycle + (2 << 32) + 0x18,
        width=first.width,
        height=first.height,
    )
    second.validate()
    context1_writes = dict(products["context1_writes"])
    if second.clear_state_page not in context1_writes:
        context1_writes[second.clear_state_page] = (
            g17g_render.build_clear_state_page(second)
        )
    products["context1_writes"] = dict(sorted(context1_writes.items()))
    products["repeat_parameters"] = second
    products["snapshot_zls_before_repeat"] = True
    products["format"] = (
        "m1n1-t8142-g17g-host-sequential-uncompressed-zls-repeat-products-v2"
    )
    products["uncompressed_zls_repeat"] = {
        "store_flags": first.depth_flags,
        "second_flags": second.depth_flags,
        "ordering": "exact first retirement then persistent-queue group two",
        "clear_state_policy": "retain registered first object",
        "first_boundary_snapshot": True,
    }
    return products


def build_compressed_zls_store_products(
        component, token=RENDER_DEFAULT_TOKEN):
    """Build one single-component compressed-store discriminator."""
    if component not in ("depth", "stencil", "both"):
        raise ValueError(
            "compressed ZLS component must be depth, stencil, or both"
        )
    baseline = build_clear_render_products()["parameters"]
    common = {
        "depth_dimensions": g17g_render.encode_zls_dimensions(
            baseline.width, baseline.height
        ),
    }
    flags = 0
    outputs = []
    if component in ("depth", "both"):
        common.update({
            "depth_buffer": RENDER_ZLS_DEPTH_DVA,
            "depth_aux_buffer": RENDER_ZLS_DEPTH_AUX_DVA,
            "depth_clear_value_bits": struct.unpack(
                "<I", struct.pack("<f", 0.25)
            )[0],
        })
        flags |= (
            g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_DEPTH_COMPRESSED
        )
        outputs.extend((
            ("depth", RENDER_ZLS_DEPTH_DVA),
            ("depth_aux", RENDER_ZLS_DEPTH_AUX_DVA),
        ))
    if component in ("stencil", "both"):
        common.update({
            "stencil_buffer": RENDER_ZLS_STENCIL_DVA,
            "stencil_aux_buffer": RENDER_ZLS_STENCIL_AUX_DVA,
            "stencil_clear_value": 0x5A,
        })
        flags |= (
            g17g_render.ZLS_STORE_STENCIL
            | g17g_render.ZLS_STORE_STENCIL_COMPRESSED
        )
        outputs.extend((
            ("stencil", RENDER_ZLS_STENCIL_DVA),
            ("stencil_aux", RENDER_ZLS_STENCIL_AUX_DVA),
        ))
    common["depth_flags"] = flags
    params = dataclasses.replace(baseline, **common)
    products = build_clear_render_products(params=params, token=token)
    zero_sha256 = hashlib.sha256(bytes(PAGE_SIZE)).hexdigest()
    products["zls_outputs"] = tuple(
        {
            "name": name,
            "base": base,
            "size": PAGE_SIZE,
            "initial_sha256": zero_sha256,
            "expected_sha256": None,
            "require_changed": True,
        }
        for name, base in outputs
    )
    products["format"] = (
        "m1n1-t8142-g17g-host-compressed-%s-store-products-v1"
        % component
    )
    products["compressed_zls_store"] = {
        "component": component,
        "flags": params.depth_flags,
    }
    return products


def build_compressed_zls_load_replay_products(
        images, token=RENDER_DEFAULT_TOKEN):
    """Build a diagnostic compressed-load/ordinary-store submission."""
    images = {str(name): bytes(body) for name, body in dict(images).items()}
    expected_names = {"depth", "stencil", "depth_aux", "stencil_aux"}
    if set(images) != expected_names:
        raise ValueError("compressed ZLS replay requires all four images")
    if any(len(body) != PAGE_SIZE for body in images.values()):
        raise ValueError("compressed ZLS replay images must be one page")
    baseline = build_clear_render_products()["parameters"]
    depth_bits = struct.unpack("<I", struct.pack("<f", 0.25))[0]
    params = dataclasses.replace(
        baseline,
        depth_buffer=RENDER_ZLS_DEPTH_DVA,
        stencil_buffer=RENDER_ZLS_STENCIL_DVA,
        depth_aux_buffer=RENDER_ZLS_DEPTH_AUX_DVA,
        stencil_aux_buffer=RENDER_ZLS_STENCIL_AUX_DVA,
        depth_clear_value_bits=struct.unpack(
            "<I", struct.pack("<f", 0.875)
        )[0],
        stencil_clear_value=0xE1,
        depth_flags=(
            g17g_render.ZLS_LOAD_DEPTH
            | g17g_render.ZLS_LOAD_STENCIL
            | g17g_render.ZLS_STORE_DEPTH
            | g17g_render.ZLS_STORE_STENCIL
            | g17g_render.ZLS_LOAD_DEPTH_COMPRESSED
            | g17g_render.ZLS_LOAD_STENCIL_COMPRESSED
        ),
        depth_dimensions=g17g_render.encode_zls_dimensions(
            baseline.width, baseline.height
        ),
    )
    products = build_clear_render_products(params=params, token=token)
    addresses = {
        "depth": RENDER_ZLS_DEPTH_DVA,
        "stencil": RENDER_ZLS_STENCIL_DVA,
        "depth_aux": RENDER_ZLS_DEPTH_AUX_DVA,
        "stencil_aux": RENDER_ZLS_STENCIL_AUX_DVA,
    }
    context1_writes = dict(products["context1_writes"])
    for name, address in addresses.items():
        context1_writes[address] = images[name]
    products["context1_writes"] = dict(sorted(context1_writes.items()))
    pixel_count = params.width * params.height
    expected_depth = struct.pack("<I", depth_bits) * pixel_count
    expected_stencil = (
        bytes((0x5A,)) * pixel_count
        + bytes(PAGE_SIZE - pixel_count)
    )
    products["zls_outputs"] = (
        {
            "name": "depth",
            "base": RENDER_ZLS_DEPTH_DVA,
            "size": PAGE_SIZE,
            "initial_sha256": hashlib.sha256(images["depth"]).hexdigest(),
            "expected_sha256": hashlib.sha256(expected_depth).hexdigest(),
            "require_changed": True,
        },
        {
            "name": "stencil",
            "base": RENDER_ZLS_STENCIL_DVA,
            "size": PAGE_SIZE,
            "initial_sha256": hashlib.sha256(images["stencil"]).hexdigest(),
            "expected_sha256": hashlib.sha256(expected_stencil).hexdigest(),
            "require_changed": True,
        },
    )
    products["format"] = (
        "m1n1-t8142-g17g-diagnostic-compressed-zls-load-products-v1"
    )
    products["diagnostic_captured_input"] = {
        "kind": "same-device-earliest-compressed-store-pages",
        "page_sha256": {
            name: hashlib.sha256(body).hexdigest()
            for name, body in sorted(images.items())
        },
    }
    return products


def build_staged_two_clear_render_products(params=None,
                                            token=RENDER_DEFAULT_TOKEN):
    """Prebuild group two while exposing only group one to firmware.

    The payload objects, item-ring entries and next channel slots are inert
    until the pointer write index and channel producer advance.  Staging them
    before the first kick avoids rewriting hundreds of cache lines after
    firmware has dirtied the persistent queue state.
    """
    products = build_prequeued_two_clear_render_products(
        params=params, token=token
    )
    pages = {
        name: bytearray(body)
        for name, body in products["firmware_pages"].items()
    }
    for block_offset in (0, 0x2870):
        struct.pack_into(
            "<I", pages["pointers"],
            block_offset + g17g.POINTER_FIELD_40, 3,
        )
    products["firmware_pages"] = {
        name: bytes(body) for name, body in pages.items()
    }
    patches = {
        name: tuple(entries)
        for name, entries in products["firmware_patches"].items()
    }
    patches["state"] = tuple(
        (offset, struct.pack("<I12xI12xI", 0, 0, 1))
        for offset in RENDER_STATE_OFFSETS
    )
    products["firmware_patches"] = patches
    products["format"] = "m1n1-t8142-g17g-host-staged-two-clear-products-v1"
    products["staged_group_count"] = products.pop("prequeued_group_count")
    products["staged_item_limit"] = products.pop("prequeued_item_limit")
    products["staged_parameters"] = products.pop("final_parameters")
    products["staged_items"] = products.pop("second_items")
    return products


def render_context1_page_images(products):
    """Validate and page-pad the known render caller-owned writes."""
    allowed = set(render_context1_dvas(products))
    result = {}
    for address, body in sorted(products["context1_writes"].items()):
        address = int(address)
        body = bytes(body)
        if address & (PAGE_SIZE - 1):
            raise ValueError("render context-1 write is not page aligned")
        if not body:
            raise ValueError("render context-1 write is empty")
        for offset in range(0, len(body), PAGE_SIZE):
            page_address = address + offset
            if page_address not in allowed:
                raise ValueError(
                    "render context-1 write reaches unmapped page %#x"
                    % page_address
                )
            if page_address in result:
                raise ValueError(
                    "overlapping render context-1 page at %#x" % page_address
                )
            result[page_address] = _page_image(
                body[offset:offset + PAGE_SIZE],
                "render context-1 write at %#x" % page_address,
            )
    return dict(sorted(result.items()))


def render_context1_dvas(products=None):
    """Return the clear or partial context topology selected by products."""
    extra_dvas = {
        int(base) + index * PAGE_SIZE
        for base, page_count, _read_only in (
            () if products is None else products.get("context1_extra_runs", ())
        )
        for index in range(int(page_count))
    }
    excluded_dvas = {
        int(address) for address in (
            () if products is None else products.get(
                "context1_excluded_dvas", ()
            )
        )
    }
    if products is not None and products.get("partial_render"):
        base = g17g_render.expand_partial_render_context1_dvas()
        # A long-lived render context grows its writable 0x40-stride status
        # arrays beyond the single page present in the earliest native graph.
        return tuple(sorted(
            (set(base) - excluded_dvas)
            | extra_dvas
            | {int(address) for address in products["context1_writes"]}
        ))
    base = g17g_render.expand_render_context1_dvas()
    if products is None:
        return base
    return tuple(sorted(
        (set(base) - excluded_dvas)
        | extra_dvas
        | {int(address) for address in products["context1_writes"]}
    ))


def render_context1_mapping_runs(products=None):
    """Return maximal render DVA runs with one measured permission class."""
    dvas = render_context1_dvas(products)
    if products is not None and products.get("partial_render"):
        read_only = set(
            g17g_render.expand_partial_render_context1_read_only_dvas()
        )
    else:
        read_only = set(g17g_render.expand_render_context1_read_only_dvas())
    for base, page_count, extra_read_only in (
        () if products is None else products.get("context1_extra_runs", ())
    ):
        base = int(base)
        page_count = int(page_count)
        if base & (PAGE_SIZE - 1) or page_count <= 0:
            raise ValueError("invalid render context-1 extra mapping run")
        extra = {
            base + index * PAGE_SIZE for index in range(page_count)
        }
        if extra_read_only:
            read_only.update(extra)
        else:
            read_only.difference_update(extra)
    if products is not None and not products.get("partial_render"):
        target = int(products["parameters"].target_dva)
        read_only.discard(target & ~(PAGE_SIZE - 1))
    for address, value in (
        {} if products is None else products.get(
            "context1_read_only_overrides", {}
        )
    ).items():
        if value:
            read_only.add(int(address))
        else:
            read_only.discard(int(address))
    runs = []
    run_address = None
    run_count = 0
    run_read_only = None
    for address in dvas:
        page_read_only = address in read_only
        if (
            run_address is not None
            and address == run_address + run_count * PAGE_SIZE
            and page_read_only == run_read_only
        ):
            run_count += 1
            continue
        if run_address is not None:
            runs.append((run_address, run_count, run_read_only))
        run_address = address
        run_count = 1
        run_read_only = page_read_only
    if run_address is not None:
        runs.append((run_address, run_count, run_read_only))
    return tuple(runs)


def render_context1_permission_changes(
        current_dvas, current_read_only_dvas, products=None):
    """Return common render leaves that must change permission class.

    Context-one is additive across a compute-to-render dependency, but leaf
    permissions are not necessarily monotonic.  In particular, caller pages
    used as read-only compute inputs become writable render scratch.  Report
    both directions explicitly so an in-place publisher cannot silently keep
    the predecessor's class.
    """
    current = set(map(int, current_dvas))
    current_read_only = set(map(int, current_read_only_dvas))
    if not current_read_only <= current:
        raise ValueError("current read-only leaf is absent from context one")
    render = set(render_context1_dvas(products))
    render_read_only = {
        address + index * PAGE_SIZE
        for address, page_count, read_only in
        render_context1_mapping_runs(products)
        if read_only
        for index in range(page_count)
    }
    common = current & render
    return {
        "to_read_only": tuple(sorted(
            (render_read_only - current_read_only) & common
        )),
        "to_writable": tuple(sorted(
            (current_read_only - render_read_only) & common
        )),
    }
